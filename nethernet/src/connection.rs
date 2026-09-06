//! Connection setup: the offer/answer/candidate [`Signal`] choreography around a
//! [`Session`], decoupled from any specific signaling transport.
//!
//! Both [`crate::signaling::lan::LanSignaler`] and
//! [`crate::signaling::http::HttpSignaler`] speak [`Signal`] as their common currency,
//! so this type only ever produces/consumes `Signal`s - the caller wires them to
//! whichever signaler is actually in use.

use crate::protocol::error::{ProtocolError, Result};
use crate::protocol::webrtc::Description;
use crate::protocol::webrtc::candidate::{format_ice_candidate, parse_ice_candidate};
use crate::session::{Channel, Session, SessionOutput};
use crate::signaling::signal::{Signal, SignalType};
use bytes::Bytes;
use rtc::ice::candidate::Candidate;
use std::net::SocketAddr;
use std::time::Instant;

/// Which ICE shape to use when encoding this side's offer/answer SDP, matching the
/// signaling transport that will carry it (see the NetherNet HTTP signaling guide,
/// sections 2 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceMode {
    /// Every candidate is embedded directly in the SDP, in one round trip
    /// (HTTP signaling).
    Full,
    /// No candidates are embedded in the SDP; a separate `CANDIDATEADD` signal follows
    /// immediately (LAN/UDP signaling).
    Trickle,
}

enum SignalKind {
    Offer,
    Answer,
}

/// A NetherNet connection attempt or established connection: the [`Signal`]
/// choreography (offer/answer/candidate) around a [`Session`].
///
/// This type performs no I/O and knows nothing about any specific signaling
/// transport: [`Self::connect`]/[`Self::accept`] return the [`Signal`]s to send, and
/// [`Self::handle_signal`] applies ones received - the caller is responsible for
/// actually moving them across whichever signaler is in use. Everything else
/// (datagrams, timeouts, application data) is a thin pass-through to the wrapped
/// [`Session`].
///
/// `connect`/`accept` take an already-created [`Session`] and its returned
/// [`Description`] (from [`Session::new`]) rather than constructing them internally:
/// attaching an `a=identity` assertion (guide section 5) means signing over the
/// session's actual certificate fingerprint, which only exists once `Session::new` has
/// run, so the caller needs a chance to set [`Description::identity`] in between.
pub struct Connection {
    session: Session,
    connection_id: u64,
    remote_network_id: u64,
    /// The remote's raw (unverified) `a=identity` value, if any - see
    /// [`Self::remote_identity`].
    remote_identity: Option<String>,
}

impl Connection {
    /// Starts an outgoing connection attempt (the offerer) from a session and
    /// description already created via `Session::new(local_addr, true)` - set
    /// `description.identity` first if this side needs to assert one (guide section
    /// 5.1). Returns the connection and the signal(s) to send: always an offer, plus -
    /// under [`IceMode::Trickle`] - a separate candidate signal.
    pub fn connect(
        session: Session,
        description: Description,
        connection_id: u64,
        remote_network_id: u64,
        ice_mode: IceMode,
    ) -> (Self, Vec<Signal>) {
        let signals = Self::describe(
            &session,
            &description,
            ice_mode,
            connection_id,
            remote_network_id,
            SignalKind::Offer,
        );

        (
            Self {
                session,
                connection_id,
                remote_network_id,
                remote_identity: None,
            },
            signals,
        )
    }

    /// Parses an incoming offer's SDP without any side effects, so the caller can
    /// inspect it - in particular, validate any `a=identity` assertion it carries
    /// (guide section 5.1) using its [`Description::fingerprint`] and `.identity` -
    /// before deciding whether to admit it at all via [`Self::accept`].
    pub fn parse_offer(offer: &Signal) -> Result<(Description, Vec<Candidate>)> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }
        Description::parse(&offer.data)
    }

    /// Answers an incoming offer (the answerer), given a session and description
    /// already created via `Session::new(local_addr, false)` (set
    /// `description.identity` first - the guide's section 5.2 requires one on every
    /// answer, regardless of signaling transport) and the offer's already-parsed
    /// remote description (see [`Self::parse_offer`] - typically called first to
    /// validate any identity assertion it carries). Returns the connection and the
    /// signal(s) to send back: always an answer, plus - under [`IceMode::Trickle`] - a
    /// separate candidate signal.
    pub fn accept(
        mut session: Session,
        description: Description,
        offer: &Signal,
        remote_description: Description,
        remote_candidates: Vec<Candidate>,
        ice_mode: IceMode,
    ) -> Result<(Self, Vec<Signal>)> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }

        let remote_identity = remote_description.identity.clone();
        session.set_remote_description(&remote_description, remote_candidates)?;

        let signals = Self::describe(
            &session,
            &description,
            ice_mode,
            offer.connection_id,
            offer.network_id,
            SignalKind::Answer,
        );

        Ok((
            Self {
                session,
                connection_id: offer.connection_id,
                remote_network_id: offer.network_id,
                remote_identity,
            },
            signals,
        ))
    }

    fn describe(
        session: &Session,
        description: &Description,
        ice_mode: IceMode,
        connection_id: u64,
        remote_network_id: u64,
        kind: SignalKind,
    ) -> Vec<Signal> {
        let sdp = match ice_mode {
            IceMode::Full => description.encode_full(&[session.local_candidate().clone()]),
            IceMode::Trickle => description.encode_trickle(),
        };

        let mut signals = vec![match kind {
            SignalKind::Offer => Signal::offer(connection_id, sdp, remote_network_id),
            SignalKind::Answer => Signal::answer(connection_id, sdp, remote_network_id),
        }];

        if ice_mode == IceMode::Trickle {
            signals.push(Signal::candidate(
                connection_id,
                format_ice_candidate(0, session.local_candidate(), &description.ice.ufrag),
                remote_network_id,
            ));
        }

        signals
    }

    /// Applies a signal received for this connection: for the offerer, the answer
    /// (and, under trickle ICE, the answerer's candidate); for the answerer, the
    /// offerer's trickled candidate (its description was already applied in
    /// [`Self::accept`]). Signals for a different connection or network are ignored.
    pub fn handle_signal(&mut self, signal: &Signal) -> Result<()> {
        if signal.connection_id != self.connection_id || signal.network_id != self.remote_network_id
        {
            return Ok(());
        }

        match signal.signal_type {
            SignalType::Answer => {
                let (description, candidates) = Description::parse(&signal.data)?;
                self.remote_identity = description.identity.clone();
                self.session
                    .set_remote_description(&description, candidates)?;
            }
            SignalType::Candidate => {
                let candidate = parse_ice_candidate(&signal.data)?;
                self.session.add_remote_candidate(candidate)?;
            }
            SignalType::Error => {
                return Err(ProtocolError::Other(format!(
                    "remote signaled a connection error: {}",
                    signal.data
                )));
            }
            SignalType::Offer => {}
        }

        Ok(())
    }

    /// The remote's raw, unverified `a=identity` attribute value, once known (from the
    /// offer, for the answerer; from the answer, for the offerer, once
    /// [`Self::handle_signal`] has applied it). `None` if the remote didn't send one.
    ///
    /// This is not verified by `Connection` itself - use
    /// [`crate::protocol::webrtc::identity::parse_identity`] and the verification
    /// functions in that module, checking the signed fingerprints against the remote
    /// description's `fingerprint` (from whichever of [`Self::parse_offer`] or the
    /// parsed answer you already have on hand).
    pub fn remote_identity(&self) -> Option<&str> {
        self.remote_identity.as_deref()
    }

    /// Feeds an inbound datagram received on the local socket.
    pub fn handle_packet(&mut self, data: &[u8], from: SocketAddr, now: Instant) -> Result<()> {
        self.session.handle_packet(data, from, now)
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.session.handle_timeout(now)
    }

    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        self.session.poll_timeout(now)
    }

    /// Drains one queued output (a datagram to send, an event, or a received message).
    pub fn poll(&mut self) -> Option<SessionOutput> {
        self.session.poll()
    }

    /// Sends a complete application message on the given channel.
    pub fn send(&mut self, channel: Channel, data: Bytes) -> Result<()> {
        self.session.send(channel, data)
    }

    /// The remote peer's address, once known.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.session.remote_addr()
    }

    /// The connection ID this attempt was signaled under.
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::webrtc::identity;
    use crate::session::SessionEvent;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// Drives a connect()/accept() pair through the Signal choreography and the full
    /// transport stack to both channels open, for a given `IceMode` - exercising the
    /// same underlying Session stack as the module-level test, but through the
    /// Connection/Signal API a real signaler would actually drive.
    fn assert_connects(ice_mode: IceMode) {
        let mut now = Instant::now();

        let (offer_session, offer_description) = Session::new(addr(40200), true).unwrap();
        let (mut offerer, offer_signals) =
            Connection::connect(offer_session, offer_description, 42, 7, ice_mode);
        let mut offer_iter = offer_signals.into_iter();
        let offer = offer_iter.next().unwrap();
        assert_eq!(offer.signal_type, SignalType::Offer);

        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        let (answer_session, answer_description) = Session::new(addr(40201), false).unwrap();
        let (mut answerer, answer_signals) = Connection::accept(
            answer_session,
            answer_description,
            &offer,
            remote_description,
            remote_candidates,
            ice_mode,
        )
        .unwrap();
        let mut answer_iter = answer_signals.into_iter();
        let answer = answer_iter.next().unwrap();
        assert_eq!(answer.signal_type, SignalType::Answer);

        offerer.handle_signal(&answer).unwrap();

        // Trickled candidates (if any) flow after the offer/answer.
        for signal in offer_iter {
            answerer.handle_signal(&signal).unwrap();
        }
        for signal in answer_iter {
            offerer.handle_signal(&signal).unwrap();
        }

        let mut offerer_ready = false;
        let mut answerer_ready = false;

        for _ in 0..5000 {
            let mut progressed = false;

            let mut outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => offerer_ready = true,
                    SessionOutput::Message(..) => {}
                }
            }
            for (data, to) in outbox {
                answerer.handle_packet(&data, to, now).unwrap();
            }

            let mut outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => answerer_ready = true,
                    SessionOutput::Message(..) => {}
                }
            }
            for (data, to) in outbox {
                offerer.handle_packet(&data, to, now).unwrap();
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

        assert!(offerer_ready, "offerer never became ready ({ice_mode:?})");
        assert!(answerer_ready, "answerer never became ready ({ice_mode:?})");
    }

    #[test]
    fn connects_with_full_ice() {
        assert_connects(IceMode::Full);
    }

    #[test]
    fn connects_with_trickle_ice() {
        assert_connects(IceMode::Trickle);
    }

    #[test]
    fn signals_for_a_different_connection_are_ignored() {
        let (session, description) = Session::new(addr(40210), true).unwrap();
        let (mut offerer, _) = Connection::connect(session, description, 1, 7, IceMode::Full);
        let unrelated = Signal::answer(999, "irrelevant".to_string(), 7);
        // Wrong connection_id: ignored, not an error.
        offerer.handle_signal(&unrelated).unwrap();
    }

    fn decode_cpk(claims: &serde_json::Value) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims["cpk"].as_str().unwrap())
            .unwrap()
    }

    /// An offerer attaches its own identity assertion, signed over its session's real
    /// certificate fingerprint; the answerer inspects and verifies it via
    /// `parse_offer` before deciding to `accept`, then attaches its own in the answer,
    /// which the offerer in turn verifies once `handle_signal` applies it.
    #[test]
    fn identity_assertions_flow_and_verify_in_both_directions() {
        let (offerer_keypair, _) = identity::generate_keypair().unwrap();
        let (answerer_keypair, _) = identity::generate_keypair().unwrap();

        let (offer_session, mut offer_description) = Session::new(addr(40220), true).unwrap();
        let offerer_token =
            identity::build_server_token(&offerer_keypair, serde_json::Map::new(), None).unwrap();
        offer_description.identity = Some(
            identity::build_identity(
                "offerer.example",
                &offerer_token,
                &[offer_description.fingerprint.clone()],
                &offerer_keypair,
            )
            .unwrap(),
        );

        let (mut offerer, offer_signals) =
            Connection::connect(offer_session, offer_description, 1, 7, IceMode::Full);
        let offer = offer_signals.into_iter().next().unwrap();

        // Answerer: pre-validate the offer's identity before accepting at all.
        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        let parsed =
            identity::parse_identity(remote_description.identity.as_ref().unwrap()).unwrap();
        assert_eq!(parsed.idp.domain, "offerer.example");
        let offerer_decoded = identity::verify_self_signed(&parsed.token).unwrap();
        parsed
            .verify_fingerprints(
                &decode_cpk(&offerer_decoded.claims),
                std::slice::from_ref(&remote_description.fingerprint),
            )
            .unwrap();

        let (answer_session, mut answer_description) = Session::new(addr(40221), false).unwrap();
        let answerer_token =
            identity::build_server_token(&answerer_keypair, serde_json::Map::new(), None).unwrap();
        answer_description.identity = Some(
            identity::build_identity(
                "answerer.example",
                &answerer_token,
                &[answer_description.fingerprint.clone()],
                &answerer_keypair,
            )
            .unwrap(),
        );

        let (_answerer, answer_signals) = Connection::accept(
            answer_session,
            answer_description,
            &offer,
            remote_description,
            remote_candidates,
            IceMode::Full,
        )
        .unwrap();
        let answer = answer_signals.into_iter().next().unwrap();

        offerer.handle_signal(&answer).unwrap();

        // Offerer: verify the answerer's identity after applying the answer.
        let (answer_description, _) = Description::parse(&answer.data).unwrap();
        let parsed = identity::parse_identity(offerer.remote_identity().unwrap()).unwrap();
        assert_eq!(parsed.idp.domain, "answerer.example");
        let answerer_decoded = identity::verify_self_signed(&parsed.token).unwrap();
        parsed
            .verify_fingerprints(
                &decode_cpk(&answerer_decoded.claims),
                &[answer_description.fingerprint],
            )
            .unwrap();
    }
}
