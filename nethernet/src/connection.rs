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
pub struct Connection {
    session: Session,
    connection_id: u64,
    remote_network_id: u64,
}

impl Connection {
    /// Starts an outgoing connection attempt (the offerer). Returns the connection and
    /// the signal(s) to send: always an offer, plus - under [`IceMode::Trickle`] - a
    /// separate candidate signal.
    pub fn connect(
        local_addr: SocketAddr,
        connection_id: u64,
        remote_network_id: u64,
        ice_mode: IceMode,
    ) -> Result<(Self, Vec<Signal>)> {
        let (session, description) = Session::new(local_addr, true)?;
        let signals = Self::describe(
            &session,
            &description,
            ice_mode,
            connection_id,
            remote_network_id,
            SignalKind::Offer,
        );

        Ok((
            Self {
                session,
                connection_id,
                remote_network_id,
            },
            signals,
        ))
    }

    /// Answers an incoming offer (the answerer). Returns the connection and the
    /// signal(s) to send back: always an answer, plus - under [`IceMode::Trickle`] - a
    /// separate candidate signal.
    pub fn accept(
        local_addr: SocketAddr,
        offer: &Signal,
        ice_mode: IceMode,
    ) -> Result<(Self, Vec<Signal>)> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }

        let (remote_description, remote_candidates) = Description::parse(&offer.data)?;
        let (mut session, description) = Session::new(local_addr, false)?;
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

        let (mut offerer, offer_signals) =
            Connection::connect(addr(40200), 42, 7, ice_mode).unwrap();
        let mut offer_iter = offer_signals.into_iter();
        let offer = offer_iter.next().unwrap();
        assert_eq!(offer.signal_type, SignalType::Offer);

        let (mut answerer, answer_signals) =
            Connection::accept(addr(40201), &offer, ice_mode).unwrap();
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
        let (mut offerer, _) = Connection::connect(addr(40210), 1, 7, IceMode::Full).unwrap();
        let unrelated = Signal::answer(999, "irrelevant".to_string(), 7);
        // Wrong connection_id: ignored, not an error.
        offerer.handle_signal(&unrelated).unwrap();
    }
}
