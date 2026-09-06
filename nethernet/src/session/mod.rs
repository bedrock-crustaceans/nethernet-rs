//! Sans-IO WebRTC session: ICE, DTLS, SCTP and data channels, driven directly rather
//! than through a generic peer connection (see [`crate::protocol::webrtc`]).

mod dcep;
mod dtls;
mod ice;
mod sctp;

use crate::protocol::constants::SCTP_MAX_MESSAGE_SIZE;
use crate::protocol::error::{ProtocolError, Result};
use crate::protocol::message::{Message as Framing, MessageSegment};
use crate::protocol::webrtc::{Description, DtlsRole, certificate};
use dtls::EndpointEvent;
pub use dtls::ResolvedRole;
use ice::IceLayer;
use rtc::datachannel::message::Message as DcepMessage;
use rtc::ice::candidate::Candidate;
use rtc::sctp::{Event as SctpEvent, PayloadProtocolIdentifier, StreamId};
use sctp::SctpLayer;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

const RELIABLE_STREAM_ID: StreamId = 0;
const UNRELIABLE_STREAM_ID: StreamId = 1;

/// Which of NetherNet's two fixed data channels a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Reliable,
    Unreliable,
}

/// Events the driving application should react to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Both data channels are open; [`Session::send`] and [`Session::poll`]'s
    /// [`SessionOutput::Message`] are now meaningful.
    Ready,
}

/// Output produced by driving a [`Session`].
pub enum SessionOutput {
    /// A datagram the driver must send over the (single, shared) UDP socket.
    Send(Vec<u8>, SocketAddr),
    Event(SessionEvent),
    /// A complete, reassembled message received on a data channel.
    Message(Channel, Vec<u8>),
}

struct RemoteInfo {
    addr: SocketAddr,
}

#[derive(Default)]
struct Channels {
    reliable_open: bool,
    unreliable_open: bool,
    /// Reassembly state for the reliable channel's fragmentation (see
    /// [`crate::protocol::message`]); the unreliable channel never fragments.
    reassembly: Framing,
    ready_emitted: bool,
}

/// A single NetherNet peer-to-peer connection: ICE connectivity, a DTLS handshake, an
/// SCTP association, and the two data channels the HTTP signaling guide's section 6
/// mandates, wired together and driven explicitly rather than through a generic peer
/// connection.
///
/// This type performs no I/O itself: feed it datagrams and ticks via [`Self::handle_packet`]/
/// [`Self::handle_timeout`], drain the resulting datagrams-to-send/events/messages via
/// [`Self::poll`], and drive the actual UDP socket externally.
pub struct Session {
    is_controlling: bool,
    local_addr: SocketAddr,
    local_description: Description,
    ice: IceLayer,
    /// The certificate whose fingerprint was advertised in `local_description`; reused
    /// (not regenerated) when the DTLS layer is actually started, since the peer will
    /// reject a handshake with a certificate that doesn't match what we signaled.
    certificate: Option<rtc::dtls::crypto::Certificate>,

    /// Set once the remote description is known but no remote candidate has arrived
    /// yet (trickle ICE only): the role/fingerprint to use once one does.
    pending_role_fingerprint: Option<(ResolvedRole, (String, String))>,

    remote: Option<RemoteInfo>,
    dtls: Option<DtlsLayer>,
    sctp: Option<SctpLayer>,

    channels: Channels,
    output: VecDeque<SessionOutput>,
}

pub use dtls::DtlsLayer;

impl Session {
    /// Starts a session. `is_controlling` matches NetherNet's fixed offerer/answerer
    /// convention (see [`crate::protocol::webrtc::description`]): the offering
    /// (connecting) side controls ICE, announces the `actpass` DTLS role, and is the
    /// side that opens the two data channels once transports are up; the answering
    /// (accepting) side does the opposite of all three.
    ///
    /// Returns the session and the local [`Description`] to signal out as this side's
    /// offer or answer (its one gathered candidate is available via
    /// [`Self::local_candidate`], to embed directly under full ICE or signal
    /// separately under trickle ICE).
    pub fn new(local_addr: SocketAddr, is_controlling: bool) -> Result<(Self, Description)> {
        let ice = IceLayer::new(local_addr, is_controlling)?;
        let certificate = certificate::generate()?;
        let fingerprint = certificate::fingerprint(&certificate)?;

        let local_description = Description {
            ice: ice.local_credentials().clone(),
            dtls_role: if is_controlling {
                DtlsRole::Server
            } else {
                DtlsRole::Auto
            },
            fingerprint,
            sctp_max_message_size: SCTP_MAX_MESSAGE_SIZE,
            // Set by the caller (see `crate::connection::Connection`) if this
            // connection needs an `a=identity` assertion attached before encoding.
            identity: None,
        };

        let session = Self {
            is_controlling,
            local_addr,
            local_description: local_description.clone(),
            ice,
            certificate: Some(certificate),
            pending_role_fingerprint: None,
            remote: None,
            dtls: None,
            sctp: None,
            channels: Channels::default(),
            output: VecDeque::new(),
        };

        Ok((session, local_description))
    }

    /// This side's one gathered host candidate, to be signaled (embedded directly in a
    /// full-ICE SDP, or trickled separately as `CANDIDATEADD`).
    pub fn local_candidate(&self) -> &Candidate {
        self.ice.local_candidate()
    }

    /// The remote peer's address, once known: the ICE-selected pair's remote address
    /// once connectivity checks have picked one, or (since NetherNet only ever gathers
    /// one candidate per side) the address transports were started with, meanwhile.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.ice
            .selected_remote_addr()
            .or_else(|| self.remote.as_ref().map(|r| r.addr))
    }

    /// Applies the remote's description once known (for the offerer: once the answer
    /// arrives; for the answerer: immediately, from the offer that prompted creating
    /// this session), plus any candidates embedded in it (full ICE) or already
    /// trickled. DTLS/SCTP aren't started until at least one remote candidate is known
    /// (here, or via a later [`Self::add_remote_candidate`]).
    pub fn set_remote_description(
        &mut self,
        remote: &Description,
        candidates: Vec<Candidate>,
    ) -> Result<()> {
        self.ice
            .set_remote_credentials(remote.ice.ufrag.clone(), remote.ice.pwd.clone())?;

        let resolved_role = ResolvedRole::from_remote_announced(remote.dtls_role);
        let fingerprint = remote.fingerprint.clone();

        for candidate in &candidates {
            self.ice.add_remote_candidate(candidate.clone())?;
        }

        if let Some(candidate) = candidates.into_iter().next() {
            self.start_transports(candidate.addr(), resolved_role, fingerprint)?;
        } else {
            // Trickle ICE: remember the role/fingerprint for when a candidate arrives.
            self.pending_role_fingerprint = Some((resolved_role, fingerprint));
        }

        Ok(())
    }

    /// Adds a candidate trickled separately from the description (LAN/trickle-ICE
    /// signaling only).
    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<()> {
        let addr = candidate.addr();
        self.ice.add_remote_candidate(candidate)?;

        if self.remote.is_none()
            && let Some((resolved_role, fingerprint)) = self.pending_role_fingerprint.take()
        {
            self.start_transports(addr, resolved_role, fingerprint)?;
        }

        Ok(())
    }

    fn start_transports(
        &mut self,
        remote_addr: SocketAddr,
        resolved_role: ResolvedRole,
        remote_fingerprint: (String, String),
    ) -> Result<()> {
        let certificate = self
            .certificate
            .take()
            .ok_or_else(|| ProtocolError::Other("transports already started".to_string()))?;
        let dtls = DtlsLayer::new(
            self.local_addr,
            remote_addr,
            resolved_role,
            certificate,
            remote_fingerprint,
        )?;
        let sctp = SctpLayer::new(
            self.local_addr,
            remote_addr,
            resolved_role,
            self.local_description.sctp_max_message_size,
        )?;

        self.remote = Some(RemoteInfo { addr: remote_addr });
        self.dtls = Some(dtls);
        self.sctp = Some(sctp);

        Ok(())
    }

    /// Feeds an inbound datagram received on the local socket.
    pub fn handle_packet(&mut self, data: &[u8], from: SocketAddr, now: Instant) -> Result<()> {
        if self.ice.handle_read(data, from, now)? {
            self.pump(now)?;
            return Ok(());
        }

        if let Some(dtls) = &mut self.dtls {
            let events = dtls.handle_read(data, now)?;
            for event in events {
                self.handle_dtls_event(event, now);
            }
        }

        self.pump(now)?;
        Ok(())
    }

    fn handle_dtls_event(&mut self, event: EndpointEvent, now: Instant) {
        if let EndpointEvent::ApplicationData(data) = event
            && let Some(sctp) = &mut self.sctp
        {
            sctp.handle_read(&data, now);
        }
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ice.handle_timeout(now)?;
        if let Some(dtls) = &mut self.dtls {
            dtls.handle_timeout(now)?;
        }
        if let Some(sctp) = &mut self.sctp {
            sctp.handle_timeout(now);
        }
        self.pump(now)?;
        Ok(())
    }

    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        [
            self.ice.poll_timeout(),
            self.dtls.as_ref().and_then(|d| d.poll_timeout(now)),
            self.sctp.as_ref().and_then(|s| s.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Drains one queued output (a datagram to send, an event, or a received message).
    pub fn poll(&mut self) -> Option<SessionOutput> {
        self.output.pop_front()
    }

    /// Sends a complete application message on the given channel, fragmenting it (per
    /// [`crate::protocol::message`]) if it's too large for one SCTP message and this is
    /// the reliable channel; the unreliable channel never fragments and rejects
    /// anything too large instead.
    pub fn send(&mut self, channel: Channel, data: bytes::Bytes) -> Result<()> {
        let stream_id = match channel {
            Channel::Reliable => RELIABLE_STREAM_ID,
            Channel::Unreliable => UNRELIABLE_STREAM_ID,
        };

        let sctp = self
            .sctp
            .as_mut()
            .ok_or_else(|| ProtocolError::Other("transports not started".to_string()))?;
        let assoc = sctp
            .association_mut()
            .ok_or_else(|| ProtocolError::Other("association not established".to_string()))?;
        let mut stream = assoc
            .stream(stream_id)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        match channel {
            Channel::Reliable => {
                for segment in Framing::split_into_segments(data)? {
                    stream
                        .write_with_ppi(&segment.encode(), PayloadProtocolIdentifier::Binary)
                        .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                }
            }
            Channel::Unreliable => {
                let encoded = Framing::encode_unreliable(data)?;
                stream
                    .write_with_ppi(&encoded, PayloadProtocolIdentifier::Binary)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
            }
        }

        Ok(())
    }

    /// Pumps data between layers (SCTP -> DTLS -> wire) and advances the DCEP/channel
    /// state machine. Must run after any call that might have produced new outbound
    /// data or state transitions.
    fn pump(&mut self, now: Instant) -> Result<()> {
        while let Some((data, to)) = self.ice.poll_write() {
            self.output.push_back(SessionOutput::Send(data, to));
        }
        // Nothing currently reacts to ICE state-change/selected-pair events; drained
        // here purely so the agent's internal event queue doesn't grow unbounded.
        while self.ice.poll_event().is_some() {}

        if let (Some(sctp), Some(dtls)) = (&mut self.sctp, &mut self.dtls) {
            while let Some(event) = sctp.poll_event() {
                if let SctpEvent::Connected = event {
                    open_channels_if_controlling(self.is_controlling, sctp)?;
                }
            }

            drain_dcep_and_data(sctp, &mut self.channels, &mut self.output)?;

            while let Some(packet) = sctp.poll_transmit(now) {
                dtls.write(&packet)?;
            }

            while let Some((data, to)) = dtls.poll_transmit() {
                self.output.push_back(SessionOutput::Send(data, to));
            }
        }

        if self.channels.reliable_open
            && self.channels.unreliable_open
            && !self.channels.ready_emitted
        {
            self.channels.ready_emitted = true;
            self.output
                .push_back(SessionOutput::Event(SessionEvent::Ready));
        }

        Ok(())
    }
}

fn open_channels_if_controlling(is_controlling: bool, sctp: &mut SctpLayer) -> Result<()> {
    if !is_controlling {
        return Ok(());
    }
    let Some(assoc) = sctp.association_mut() else {
        return Ok(());
    };

    for (stream_id, open) in [
        (RELIABLE_STREAM_ID, dcep::reliable_open()),
        (UNRELIABLE_STREAM_ID, dcep::unreliable_open()),
    ] {
        let mut stream = assoc
            .open_stream(stream_id, PayloadProtocolIdentifier::Binary)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;
        let encoded = dcep::encode_open(open)?;
        stream
            .write_with_ppi(&encoded, dcep::PPI_DCEP)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;
    }

    Ok(())
}

/// Accepts newly opened streams (answerer), reads/acks DCEP control messages, and
/// delivers data messages (reassembling the reliable channel's fragments).
fn drain_dcep_and_data(
    sctp: &mut SctpLayer,
    channels: &mut Channels,
    output: &mut VecDeque<SessionOutput>,
) -> Result<()> {
    let Some(assoc) = sctp.association_mut() else {
        return Ok(());
    };

    while let Some(mut stream) = assoc.accept_stream() {
        if let Ok(Some(chunks)) = stream.read()
            && let Ok(data) = chunks.to_payload(4096)
            && let Ok(DcepMessage::DataChannelOpen(open)) = dcep::decode(&data)
        {
            let channel = if open.label == dcep::RELIABLE_CHANNEL_LABEL.as_bytes() {
                Some(Channel::Reliable)
            } else if open.label == dcep::UNRELIABLE_CHANNEL_LABEL.as_bytes() {
                Some(Channel::Unreliable)
            } else {
                None
            };
            if let Some(channel) = channel {
                let ack = dcep::encode_ack()?;
                stream
                    .write_with_ppi(&ack, dcep::PPI_DCEP)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                match channel {
                    Channel::Reliable => channels.reliable_open = true,
                    Channel::Unreliable => channels.unreliable_open = true,
                }
            }
        }
    }

    for (stream_id, channel) in [
        (RELIABLE_STREAM_ID, Channel::Reliable),
        (UNRELIABLE_STREAM_ID, Channel::Unreliable),
    ] {
        let Ok(mut stream) = assoc.stream(stream_id) else {
            continue;
        };
        while let Ok(Some(chunks)) = stream.read() {
            let is_dcep = matches!(chunks.ppi, PayloadProtocolIdentifier::Dcep);
            let Ok(data) = chunks.to_payload(1 << 20) else {
                continue;
            };

            if is_dcep {
                if let Ok(DcepMessage::DataChannelAck(_)) = dcep::decode(&data) {
                    match channel {
                        Channel::Reliable => channels.reliable_open = true,
                        Channel::Unreliable => channels.unreliable_open = true,
                    }
                }
                continue;
            }

            let Ok(segment) = MessageSegment::decode(data.freeze()) else {
                continue;
            };

            match channel {
                Channel::Reliable => {
                    if let Some(message) = channels.reassembly.add_segment(segment)? {
                        output
                            .push_back(SessionOutput::Message(Channel::Reliable, message.to_vec()));
                    }
                }
                Channel::Unreliable => {
                    if segment.remaining_segments == 0 {
                        output.push_back(SessionOutput::Message(
                            Channel::Unreliable,
                            segment.data.to_vec(),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// Drives an offerer and an answerer session, connected via full-ICE-style
    /// descriptions (candidates embedded up front, as HTTP signaling would deliver
    /// them), through the entire stack - ICE, DTLS, SCTP, DCEP - to both data channels
    /// opening, then exchanges messages in both directions on both channels.
    #[test]
    fn full_handshake_and_bidirectional_data_exchange() {
        let mut now = Instant::now();

        let (mut offerer, offer) = Session::new(addr(40100), true).unwrap();
        let (mut answerer, answer) = Session::new(addr(40101), false).unwrap();

        // Round-trip through the real SDP codec (full ICE, as HTTP signaling would
        // deliver it) rather than passing the structs directly, since DtlsRole::Auto
        // only ever normalizes to Client/Server by way of encode()+parse() - passing
        // the pre-encode struct would skip that and break role resolution.
        let offer_sdp = offer.encode_full(&[offerer.local_candidate().clone()]);
        let answer_sdp = answer.encode_full(&[answerer.local_candidate().clone()]);

        let (parsed_offer, offer_candidates) = Description::parse(&offer_sdp).unwrap();
        let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();

        answerer
            .set_remote_description(&parsed_offer, offer_candidates)
            .unwrap();
        offerer
            .set_remote_description(&parsed_answer, answer_candidates)
            .unwrap();

        let mut offerer_ready = false;
        let mut answerer_ready = false;

        for _ in 0..5000 {
            let mut progressed = false;

            let mut offerer_outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => offerer_outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => offerer_ready = true,
                    SessionOutput::Message(..) => panic!("unexpected message before Ready"),
                }
            }
            for (data, to) in offerer_outbox {
                assert_eq!(to, addr(40101));
                answerer.handle_packet(&data, addr(40100), now).unwrap();
            }

            let mut answerer_outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => answerer_outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => answerer_ready = true,
                    SessionOutput::Message(..) => panic!("unexpected message before Ready"),
                }
            }
            for (data, to) in answerer_outbox {
                assert_eq!(to, addr(40100));
                offerer.handle_packet(&data, addr(40101), now).unwrap();
            }

            if offerer_ready && answerer_ready {
                break;
            }

            if !progressed {
                let next = [offerer.poll_timeout(now), answerer.poll_timeout(now)]
                    .into_iter()
                    .flatten()
                    .min();
                now = next
                    .unwrap_or(now + Duration::from_millis(20))
                    .max(now + Duration::from_millis(1));
                offerer.handle_timeout(now).unwrap();
                answerer.handle_timeout(now).unwrap();
            }
        }

        assert!(offerer_ready, "offerer never became ready");
        assert!(answerer_ready, "answerer never became ready");
        assert_eq!(offerer.remote_addr(), Some(addr(40101)));
        assert_eq!(answerer.remote_addr(), Some(addr(40100)));

        // Exchange messages in both directions on both channels.
        offerer
            .send(
                Channel::Reliable,
                Bytes::from_static(b"hello from offerer (reliable)"),
            )
            .unwrap();
        offerer
            .send(
                Channel::Unreliable,
                Bytes::from_static(b"hello from offerer (unreliable)"),
            )
            .unwrap();
        answerer
            .send(
                Channel::Reliable,
                Bytes::from_static(b"hello from answerer (reliable)"),
            )
            .unwrap();
        answerer
            .send(
                Channel::Unreliable,
                Bytes::from_static(b"hello from answerer (unreliable)"),
            )
            .unwrap();

        let mut offerer_received = Vec::new();
        let mut answerer_received = Vec::new();

        for _ in 0..200 {
            let mut progressed = false;

            let mut offerer_outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => offerer_outbox.push((data, to)),
                    SessionOutput::Event(_) => {}
                    SessionOutput::Message(channel, data) => offerer_received.push((channel, data)),
                }
            }
            for (data, to) in offerer_outbox {
                answerer.handle_packet(&data, to, now).unwrap();
            }

            let mut answerer_outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => answerer_outbox.push((data, to)),
                    SessionOutput::Event(_) => {}
                    SessionOutput::Message(channel, data) => {
                        answerer_received.push((channel, data))
                    }
                }
            }
            for (data, to) in answerer_outbox {
                offerer.handle_packet(&data, to, now).unwrap();
            }

            if offerer_received.len() >= 2 && answerer_received.len() >= 2 {
                break;
            }

            if !progressed {
                now += Duration::from_millis(5);
                offerer.handle_timeout(now).unwrap();
                answerer.handle_timeout(now).unwrap();
            }
        }

        assert!(
            answerer_received
                .contains(&(Channel::Reliable, b"hello from offerer (reliable)".to_vec())),
            "answerer never received the reliable message: {answerer_received:?}"
        );
        assert!(
            answerer_received.contains(&(
                Channel::Unreliable,
                b"hello from offerer (unreliable)".to_vec()
            )),
            "answerer never received the unreliable message: {answerer_received:?}"
        );
        assert!(
            offerer_received.contains(&(
                Channel::Reliable,
                b"hello from answerer (reliable)".to_vec()
            )),
            "offerer never received the reliable message: {offerer_received:?}"
        );
        assert!(
            offerer_received.contains(&(
                Channel::Unreliable,
                b"hello from answerer (unreliable)".to_vec()
            )),
            "offerer never received the unreliable message: {offerer_received:?}"
        );
    }
}
