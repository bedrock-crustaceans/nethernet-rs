pub mod error;
pub mod input;
pub mod output;

use crate::protocol::constants::{
    ADDRESS_TIMEOUT, BROADCAST_INTERVAL, ID_MESSAGE_PACKET, ID_REQUEST_PACKET, ID_RESPONSE_PACKET,
    LAN_DISCOVERY_PORT,
};
use crate::protocol::packet::discovery::{self, MessagePacket, RequestPacket, ResponsePacket, ServerData};
use crate::sans::Sans;
use crate::signaling::lan::error::LanSignalerError;
use crate::signaling::lan::input::LanSignalerInput;
use crate::signaling::lan::output::LanSignalerOutput;
use crate::signaling::signal::Signal;
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

/// Protocol-defined ping token used for keepalive/discovery messages.
/// This is the exact wire format expected by the protocol.
const PING_TOKEN: &str = "Ping";

struct AddressEntry {
    addr: SocketAddr,
    last_seen: Instant,
}

/// Sans-IO LAN-based signaling implementation for peer discovery and WebRTC negotiation.
///
/// This type performs no I/O itself: feed it received datagrams and periodic ticks via
/// [`Sans::handle`], drain the resulting datagrams-to-send and decoded signals via
/// [`Sans::poll`], and drive the actual UDP socket externally.
pub struct LanSignaler {
    network_id: u64,
    /// Whether to periodically broadcast discovery requests (client behavior). A pure
    /// server that only answers requests and never seeks other peers can leave this off.
    broadcast: bool,
    addresses: HashMap<u64, AddressEntry>,
    server_data: Option<ServerData>,
    discovered_servers: HashMap<u64, ServerData>,
    last_tick: Option<Instant>,
    output: VecDeque<LanSignalerOutput>,
}

impl LanSignaler {
    /// Creates a new LAN signaler for the given local network ID.
    ///
    /// If `broadcast` is `true`, a discovery [`RequestPacket`] is (re-)sent to the LAN
    /// broadcast address roughly every [`BROADCAST_INTERVAL`] while ticked.
    pub fn new(network_id: u64, broadcast: bool) -> Self {
        Self {
            network_id,
            broadcast,
            addresses: HashMap::new(),
            server_data: None,
            discovered_servers: HashMap::new(),
            last_tick: None,
            output: VecDeque::new(),
        }
    }

    /// Sets (or clears) the local server "pong" data advertised to discovery requests.
    pub fn set_server_data(&mut self, data: Option<ServerData>) {
        self.server_data = data;
    }

    /// Returns a snapshot of discovered servers keyed by their network ID.
    pub fn discovered(&self) -> &HashMap<u64, ServerData> {
        &self.discovered_servers
    }

    /// Returns the last-known socket address for the given network ID, if any.
    pub fn get_address(&self, network_id: u64) -> Option<SocketAddr> {
        self.addresses.get(&network_id).map(|entry| entry.addr)
    }

    fn broadcast_addr() -> SocketAddr {
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), LAN_DISCOVERY_PORT)
    }

    /// Handle an incoming discovery or message packet received over UDP.
    ///
    /// Updates the last-seen address for the packet's sender, ignores packets that originate
    /// from this node, and processes packets by type:
    /// - REQUEST: if local server data is configured, queue a discovery response to the requester.
    /// - RESPONSE: parse and store discovered `ServerData` into the discovered-servers map.
    /// - MESSAGE: ignore ping tokens; if the message is addressed to this node, parse it into
    ///   a [`Signal`] and queue it for the caller.
    fn handle_packet(
        &mut self,
        data: Vec<u8>,
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), LanSignalerError> {
        let (packet, sender_id) = match discovery::unmarshal(&data) {
            Ok(result) => result,
            // Malformed / not-our-protocol packet (likely from another service on the LAN).
            Err(_) => return Ok(()),
        };

        if sender_id == self.network_id {
            return Ok(());
        }

        self.addresses.insert(
            sender_id,
            AddressEntry {
                addr: from,
                last_seen: now,
            },
        );

        match packet.id() {
            ID_REQUEST_PACKET => {
                if let Some(data) = self.server_data.as_ref() {
                    let app_data = data.marshal()?;
                    let response = ResponsePacket::new(app_data);
                    let response_data = discovery::marshal(&response, self.network_id)?;
                    self.output
                        .push_back(LanSignalerOutput::Send(response_data, from));
                }
            }
            ID_RESPONSE_PACKET => {
                if let Some(response) = packet.as_any().downcast_ref::<ResponsePacket>()
                    && let Ok(server_info) = ServerData::unmarshal(&response.application_data)
                {
                    self.discovered_servers.insert(sender_id, server_info);
                }
            }
            ID_MESSAGE_PACKET => {
                if let Some(message) = packet.as_any().downcast_ref::<MessagePacket>() {
                    // Ignore Ping messages - these are not WebRTC negotiation signals.
                    if message.data == PING_TOKEN {
                        return Ok(());
                    }

                    if message.recipient_id == self.network_id
                        && let Ok(signal) = Signal::from_str(&message.data, sender_id)
                    {
                        self.output.push_back(LanSignalerOutput::Signal(signal));
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Sends a signaling message to the peer identified by the signal's `network_id`.
    ///
    /// Looks up the last-known socket address for the target network ID, serializes the signal
    /// into a `MessagePacket`, and queues it for transmission.
    fn handle_signal(&mut self, signal: Signal, _now: Instant) -> Result<(), LanSignalerError> {
        let addr = self
            .addresses
            .get(&signal.network_id)
            .map(|entry| entry.addr)
            .ok_or(LanSignalerError::UnknownNetworkId(signal.network_id))?;

        let message = MessagePacket::new(signal.network_id, signal.to_string());
        let data = discovery::marshal(&message, self.network_id)?;
        self.output.push_back(LanSignalerOutput::Send(data, addr));

        Ok(())
    }

    /// Periodic housekeeping: prunes stale peer addresses and, if enabled, re-broadcasts a
    /// discovery request. Runs at most once per [`BROADCAST_INTERVAL`], regardless of how
    /// often `Tick` is fed in.
    fn handle_tick(&mut self, now: Instant) -> Result<(), LanSignalerError> {
        let due = self
            .last_tick
            .is_none_or(|last| now.duration_since(last) >= BROADCAST_INTERVAL);

        if !due {
            return Ok(());
        }
        self.last_tick = Some(now);

        self.addresses
            .retain(|_, entry| now.duration_since(entry.last_seen) < ADDRESS_TIMEOUT);

        if self.broadcast {
            let request = RequestPacket;
            let data = discovery::marshal(&request, self.network_id)?;
            self.output
                .push_back(LanSignalerOutput::Send(data, Self::broadcast_addr()));
        }

        Ok(())
    }
}

impl Sans for LanSignaler {
    type Input = LanSignalerInput;
    type Output = LanSignalerOutput;
    type Error = LanSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            LanSignalerInput::Packet(data, from, now) => self.handle_packet(data, from, now),
            LanSignalerInput::Signal(signal, now) => self.handle_signal(signal, now),
            LanSignalerInput::Tick(now) => self.handle_tick(now),
        }
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    #[test]
    fn discovery_request_response() {
        let now = Instant::now();

        let mut client = LanSignaler::new(1, true);
        let mut server = LanSignaler::new(2, false);
        server.set_server_data(Some(ServerData::new(
            "host".to_string(),
            "world".to_string(),
        )));

        client.handle(LanSignalerInput::Tick(now)).unwrap();
        let LanSignalerOutput::Send(request, to) = client.poll().expect("request queued") else {
            panic!("expected Send output");
        };
        assert_eq!(to, LanSignaler::broadcast_addr());
        assert!(client.poll().is_none());

        server
            .handle(LanSignalerInput::Packet(request, addr(1), now))
            .unwrap();
        let LanSignalerOutput::Send(response, to) = server.poll().expect("response queued") else {
            panic!("expected Send output");
        };
        assert_eq!(to, addr(1));
        assert!(server.poll().is_none());

        client
            .handle(LanSignalerInput::Packet(response, addr(2), now))
            .unwrap();
        assert!(client.poll().is_none());

        let discovered = client.discovered().get(&2).expect("server discovered");
        assert_eq!(discovered.server_name, "host");
        assert_eq!(discovered.level_name, "world");
        assert_eq!(client.get_address(2), Some(addr(2)));
    }

    #[test]
    fn signal_relay_roundtrip() {
        let now = Instant::now();

        let mut a = LanSignaler::new(1, false);
        let mut b = LanSignaler::new(2, false);

        // Seed each side's address table as if a discovery exchange already happened.
        a.handle(LanSignalerInput::Packet(
            discovery::marshal(&RequestPacket, 2).unwrap(),
            addr(2),
            now,
        ))
        .unwrap();
        assert!(a.poll().is_none());
        b.handle(LanSignalerInput::Packet(
            discovery::marshal(&RequestPacket, 1).unwrap(),
            addr(1),
            now,
        ))
        .unwrap();
        assert!(b.poll().is_none());

        let offer = Signal::offer(42, "v=0...".to_string(), 2);
        a.handle(LanSignalerInput::Signal(offer, now)).unwrap();
        let LanSignalerOutput::Send(data, to) = a.poll().expect("signal queued") else {
            panic!("expected Send output");
        };
        assert_eq!(to, addr(2));

        b.handle(LanSignalerInput::Packet(data, addr(1), now))
            .unwrap();
        let LanSignalerOutput::Signal(signal) = b.poll().expect("signal decoded") else {
            panic!("expected Signal output");
        };
        assert_eq!(signal.signal_type, crate::signaling::signal::SignalType::Offer);
        assert_eq!(signal.connection_id, 42);
        assert_eq!(signal.data, "v=0...");
        assert_eq!(signal.network_id, 1);
    }

    #[test]
    fn unknown_recipient_errors() {
        let mut signaler = LanSignaler::new(1, false);
        let signal = Signal::offer(1, "data".to_string(), 99);
        let err = signaler
            .handle(LanSignalerInput::Signal(signal, Instant::now()))
            .unwrap_err();
        assert!(matches!(err, LanSignalerError::UnknownNetworkId(99)));
    }
}
