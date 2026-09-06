//! Establishing and driving a NetherNet peer-to-peer connection: async wrappers over
//! [`nethernet::connection::Connection`] for both signaling transports.

use crate::net::{self, UdpDriven, UdpDrivenOutput};
use crate::router::{SignalRouter, UnroutedSignal};
use bytes::Bytes;
use nethernet::connection::{Connection as SansConnection, IceMode};
use nethernet::protocol::error::ProtocolError;
use nethernet::session::{Channel, Session, SessionEvent, SessionOutput};
use nethernet::signaling::signal::{Signal, SignalType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long [`connect_via_lan`]/[`connect_via_http`] wait for an answer before giving
/// up. The guide doesn't mandate a value for LAN signaling; HTTP signaling's own single
/// round trip has no separate timeout concept (whatever the HTTP client's own request
/// timeout is applies there instead).
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("negotiation timed out")]
    Timeout,
    #[error("signaling channel closed before an answer arrived")]
    SignalingClosed,
    #[error("http signaling error: {0}")]
    Http(#[from] crate::http::client::ClientError),
}

/// Output produced by driving a [`Connection`].
pub enum ConnectionEvent {
    /// Both data channels are open; [`Connection::send`] and further
    /// [`ConnectionEvent::Message`]s are now meaningful.
    Ready,
    /// A complete message received on a data channel.
    Message(Channel, Vec<u8>),
}

enum Command {
    Send(Channel, Bytes),
    Signal(Signal),
}

struct Adapter(SansConnection);

impl UdpDriven for Adapter {
    type Output = ConnectionEvent;
    type Command = Command;
    type Error = ProtocolError;

    fn handle_packet(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), Self::Error> {
        self.0.handle_packet(data, from, now)
    }

    fn handle_command(&mut self, command: Command, _now: Instant) -> Result<(), Self::Error> {
        match command {
            Command::Send(channel, data) => self.0.send(channel, data),
            Command::Signal(signal) => self.0.handle_signal(&signal),
        }
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.0.handle_timeout(now)
    }

    fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        self.0.poll_timeout(now)
    }

    fn poll(&mut self) -> Option<UdpDrivenOutput<ConnectionEvent>> {
        match self.0.poll()? {
            SessionOutput::Send(data, to) => Some(UdpDrivenOutput::Send(data, to)),
            SessionOutput::Event(SessionEvent::Ready) => {
                Some(UdpDrivenOutput::Output(ConnectionEvent::Ready))
            }
            SessionOutput::Message(channel, data) => Some(UdpDrivenOutput::Output(
                ConnectionEvent::Message(channel, data),
            )),
        }
    }
}

/// An established (or establishing) NetherNet peer-to-peer connection, driving
/// [`nethernet::connection::Connection`] over a real UDP socket in the background.
///
/// Dropping this stops the background task.
pub struct Connection {
    local_addr: SocketAddr,
    command_tx: mpsc::UnboundedSender<Command>,
    event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
    task: JoinHandle<()>,
}

impl Connection {
    /// Spawns the background driver, returning the handle plus a clone of its command
    /// sender - so a caller (see [`connect_via_lan`]) can forward further input (e.g.
    /// a trickled candidate arriving after the answer) into it without holding a
    /// borrow of the returned `Connection` itself.
    fn spawn(
        socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
        connection: SansConnection,
    ) -> (Self, mpsc::UnboundedSender<Command>) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(net::run(socket, Adapter(connection), command_rx, event_tx));

        (
            Self {
                local_addr,
                command_tx: command_tx.clone(),
                event_rx,
                task,
            },
            command_tx,
        )
    }

    /// The address this connection's socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sends a complete application message on the given channel. Fire-and-forget:
    /// silently dropped if the background task has already stopped.
    pub fn send(&self, channel: Channel, data: Bytes) {
        let _ = self.command_tx.send(Command::Send(channel, data));
    }

    /// Receives the next event (readiness, or a received message). Returns `None`
    /// once the background task has stopped.
    pub async fn recv(&mut self) -> Option<ConnectionEvent> {
        self.event_rx.recv().await
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Connects to `remote_network_id` over LAN/UDP signaling (trickle ICE): binds a UDP
/// socket at `local_addr` for the data session, sends an offer through `router`,
/// awaits and applies the matching answer (and any trickled candidate), and returns
/// the resulting connection, already being driven in the background.
pub async fn connect_via_lan(
    router: &SignalRouter,
    local_addr: SocketAddr,
    connection_id: u64,
    remote_network_id: u64,
) -> Result<Connection, ConnectError> {
    let socket = Arc::new(UdpSocket::bind(local_addr).await?);
    let bound_addr = socket.local_addr()?;

    let (session, description) = Session::new(bound_addr, true)?;
    let (mut connection, signals) = SansConnection::connect(
        session,
        description,
        connection_id,
        remote_network_id,
        IceMode::Trickle,
    );

    let (mut answers, guard) = router.register(remote_network_id, connection_id);
    for signal in signals {
        router.send(signal);
    }

    // Under trickle ICE, the answer and its trailing candidate are two separate
    // signals that can arrive in either order, and `Session` only starts DTLS/SCTP
    // once *both* the remote description (from the answer) and a remote candidate
    // have been applied - so both are required here, not just the answer.
    await_required_signals(
        &mut answers,
        &mut connection,
        &[SignalType::Answer, SignalType::Candidate],
    )
    .await?;

    let (established, command_tx) = Connection::spawn(socket, bound_addr, connection);
    spawn_late_signal_forwarder(answers, guard, command_tx);

    Ok(established)
}

/// Accepts an offer received over LAN/UDP signaling (trickle ICE) - see
/// [`SignalRouter::recv_unrouted`] - binds a UDP socket at `local_addr` for the data
/// session, sends an answer through `router`, awaits and applies the offerer's trickled
/// candidate, and returns the resulting connection, already being driven in the
/// background.
///
/// Takes the whole [`UnroutedSignal`] (not just the offer inside it) because its
/// `route`/`guard` are already registered for this exact `(network_id, connection_id)`
/// from the instant the offer was received - registering a fresh route here instead
/// would reopen the gap that lets a fast-following trickled candidate be lost.
pub async fn accept_via_lan(
    router: &SignalRouter,
    local_addr: SocketAddr,
    unrouted: UnroutedSignal,
) -> Result<Connection, ConnectError> {
    let UnroutedSignal {
        signal: offer,
        route: mut candidates,
        guard,
    } = unrouted;
    let (remote_description, remote_candidates) = SansConnection::parse_offer(&offer)?;

    let socket = Arc::new(UdpSocket::bind(local_addr).await?);
    let bound_addr = socket.local_addr()?;

    let (session, description) = Session::new(bound_addr, false)?;
    let (mut connection, signals) = SansConnection::accept(
        session,
        description,
        &offer,
        remote_description,
        remote_candidates,
        IceMode::Trickle,
    )?;

    for signal in signals {
        router.send(signal);
    }

    // Same reasoning as connect_via_lan: the offerer's candidate is required before
    // transports can start, not merely optional trickle.
    await_required_signals(&mut candidates, &mut connection, &[SignalType::Candidate]).await?;

    let (established, command_tx) = Connection::spawn(socket, bound_addr, connection);
    spawn_late_signal_forwarder(candidates, guard, command_tx);

    Ok(established)
}

/// Keeps forwarding any further signals (e.g. a redundant retransmitted candidate, or
/// one that arrives even later than expected) into the now-running connection, until
/// either the router's route is exhausted or the connection is dropped - `guard`'s drop
/// unregisters the route once this task ends.
fn spawn_late_signal_forwarder(
    mut signals: mpsc::UnboundedReceiver<Signal>,
    guard: crate::router::RouteGuard,
    command_tx: mpsc::UnboundedSender<Command>,
) {
    tokio::spawn(async move {
        let _guard = guard;
        while let Some(signal) = signals.recv().await {
            if command_tx.send(Command::Signal(signal)).is_err() {
                break;
            }
        }
    });
}

/// Connects to the NetherNet HTTP signaling endpoint at `base_url` (full ICE, per the
/// guide's section 4): binds a UDP socket at `local_addr` for the data session, POSTs
/// an offer built from it, applies the answer from the single round trip, and returns
/// the resulting connection, already being driven in the background.
///
/// `network_id` is this client's own `NetworkID` (see the guide's section 9) - the
/// value the guide's `POST /v1/join/{networkId}` names, not a remote peer's.
pub async fn connect_via_http(
    client: &reqwest::Client,
    base_url: &url::Url,
    local_addr: SocketAddr,
    connection_id: u64,
    network_id: u64,
) -> Result<Connection, ConnectError> {
    let socket = Arc::new(UdpSocket::bind(local_addr).await?);
    let bound_addr = socket.local_addr()?;

    let (session, description) = Session::new(bound_addr, true)?;
    let (mut connection, signals) = SansConnection::connect(
        session,
        description,
        connection_id,
        network_id,
        IceMode::Full,
    );
    let offer_sdp = signals
        .into_iter()
        .next()
        .expect("Connection::connect always returns an offer signal first")
        .data;

    let answer_sdp = crate::http::client::join(client, base_url, network_id, offer_sdp).await?;
    connection.handle_signal(&Signal::answer(connection_id, answer_sdp, network_id))?;

    // Full ICE means every candidate is already in the SDP; no further signals are
    // expected for this connection, so no forwarding task is needed here (unlike
    // `connect_via_lan`).
    let (established, _command_tx) = Connection::spawn(socket, bound_addr, connection);
    Ok(established)
}

/// Waits for signals routed to one connection attempt, applying each as it arrives,
/// until every signal type in `required` has been seen at least once.
///
/// Signaling doesn't guarantee order between separately-sent signals (e.g. under
/// trickle ICE, an answer and its trailing candidate, or an offer and its candidate),
/// while `Session` only starts DTLS/SCTP once *both* the remote description and a
/// remote candidate have been applied - so callers must wait for every signal their
/// flow actually depends on, not just the first one that unblocks something.
async fn await_required_signals(
    signals: &mut mpsc::UnboundedReceiver<Signal>,
    connection: &mut SansConnection,
    required: &[SignalType],
) -> Result<(), ConnectError> {
    let deadline = tokio::time::Instant::now() + NEGOTIATION_TIMEOUT;
    let mut remaining: Vec<SignalType> = required.to_vec();

    while !remaining.is_empty() {
        let signal = tokio::time::timeout_at(deadline, signals.recv())
            .await
            .map_err(|_| ConnectError::Timeout)?
            .ok_or(ConnectError::SignalingClosed)?;

        remaining.retain(|t| *t != signal.signal_type);
        connection.handle_signal(&signal)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::LanSignaler;
    use nethernet::protocol::packet::discovery::ServerData;
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// A real connect-out (LAN signaling) and a real accept, driven entirely through
    /// the public async API, reach the full stack's `Ready` event and exchange a
    /// message - the same guarantee the sans-io `Connection`/`Session` tests already
    /// give, now exercised through real sockets and background tasks end to end.
    #[tokio::test]
    async fn connects_via_lan_and_exchanges_a_message() {
        let offerer_signaling = LanSignaler::bind(loopback(0), 1, true).await.unwrap();
        let answerer_signaling = LanSignaler::bind(loopback(0), 2, false).await.unwrap();
        answerer_signaling.set_server_data(Some(ServerData::new(
            "host".to_string(),
            "world".to_string(),
        )));

        // Seed each side's address table directly (see lan::tests for why: real
        // broadcast semantics on loopback are OS-dependent, so a deterministic direct
        // probe is used instead of relying on it here too).
        offerer_signaling.discover(answerer_signaling.local_addr());
        answerer_signaling.discover(offerer_signaling.local_addr());
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let offerer_router = SignalRouter::new(offerer_signaling);
        let answerer_router = SignalRouter::new(answerer_signaling);

        // The offerer's connect (which blocks awaiting an answer) and the answerer's
        // half of the exchange (receive the offer, build and send an answer) must run
        // concurrently - `join!` polls both within this same task, so neither router
        // needs to be moved into a separately spawned ('static) task.
        let (connect_result, accept_result) = tokio::join!(
            connect_via_lan(&offerer_router, loopback(0), 42, 2),
            async {
                let unrouted = tokio::time::timeout(
                    StdDuration::from_secs(5),
                    answerer_router.recv_unrouted(),
                )
                .await
                .expect("answerer never received the offer")
                .unwrap();
                accept_via_lan(&answerer_router, loopback(0), unrouted).await
            }
        );
        let mut offerer_connection = connect_result.unwrap();
        let mut answerer_connection = accept_result.unwrap();

        // Drive both to `Ready`. Real wall-clock time, not the simulated clock the
        // sans-io-level tests use, so give it a realistic budget rather than a fixed
        // iteration count.
        let drive_to_ready = async {
            let mut offerer_ready = false;
            let mut answerer_ready = false;
            while !(offerer_ready && answerer_ready) {
                tokio::select! {
                    Some(event) = offerer_connection.recv() => {
                        if matches!(event, ConnectionEvent::Ready) { offerer_ready = true; }
                    }
                    Some(event) = answerer_connection.recv() => {
                        if matches!(event, ConnectionEvent::Ready) { answerer_ready = true; }
                    }
                }
            }
        };
        tokio::time::timeout(StdDuration::from_secs(15), drive_to_ready)
            .await
            .expect("connection never became ready on both sides");

        offerer_connection.send(Channel::Reliable, Bytes::from_static(b"hello"));
        let message = tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                if let Some(ConnectionEvent::Message(channel, data)) =
                    answerer_connection.recv().await
                {
                    return (channel, data);
                }
            }
        })
        .await
        .expect("answerer never received the message");
        assert_eq!(message.0, Channel::Reliable);
        assert_eq!(message.1, b"hello");
    }
}
