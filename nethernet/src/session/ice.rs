//! ICE connectivity, restricted to NetherNet's requirements: UDP-only, host candidates
//! only, no STUN/TURN (see the NetherNet HTTP signaling guide, section 6).

use crate::protocol::error::{ProtocolError, Result};
use bytes::BytesMut;
use rtc::ice::agent::agent_config::AgentConfig;
use rtc::ice::agent::{Agent, Credentials, Event};
use rtc::ice::candidate::candidate_host::CandidateHostConfig;
use rtc::ice::candidate::{Candidate, CandidateConfig, CandidateType};
use rtc::ice::network_type::NetworkType;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Wraps a single [`Agent`] bound to exactly one local host candidate. NetherNet never
/// gathers server-reflexive or relay candidates, so there is never more than one local
/// address to track.
pub struct IceLayer {
    agent: Agent,
    local_addr: SocketAddr,
}

impl IceLayer {
    /// Creates an ICE layer for the given locally bound address. `is_controlling`
    /// matches the WebRTC offerer/answerer split: the offering side controls.
    pub fn new(local_addr: SocketAddr, is_controlling: bool) -> Result<Self> {
        let config = AgentConfig {
            local_ufrag: rtc::ice::rand::generate_ufrag(),
            local_pwd: rtc::ice::rand::generate_pwd(),
            is_controlling,
            candidate_types: vec![CandidateType::Host],
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            ..Default::default()
        };

        let mut agent =
            Agent::new(Arc::new(config)).map_err(|e| ProtocolError::Other(format!("{e}")))?;

        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: local_addr.ip().to_string(),
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        agent
            .add_local_candidate(candidate)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        Ok(Self { agent, local_addr })
    }

    /// The local credentials (ufrag/pwd) to be signaled in this side's description.
    pub fn local_credentials(&self) -> &Credentials {
        self.agent.get_local_credentials()
    }

    /// This side's one gathered host candidate.
    pub fn local_candidate(&self) -> &Candidate {
        &self.agent.get_local_candidates()[0]
    }

    /// Applies the remote side's ICE credentials, signaled in its description.
    pub fn set_remote_credentials(&mut self, ufrag: String, pwd: String) -> Result<()> {
        self.agent
            .set_remote_credentials(ufrag, pwd)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    /// Adds a candidate signaled by the remote connection (embedded in a full-ICE SDP,
    /// or trickled separately via `CANDIDATEADD`).
    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<()> {
        self.agent
            .add_remote_candidate(candidate)
            .map(|_| ())
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    /// Feeds an inbound datagram addressed to this layer's local candidate. Returns
    /// `false` if `data` isn't a STUN packet destined for this layer (the caller should
    /// then try handing it to the next layer, e.g. DTLS).
    pub fn handle_read(&mut self, data: &[u8], from: SocketAddr, now: Instant) -> Result<bool> {
        if !is_stun_packet(data) {
            return Ok(false);
        }

        self.agent
            .handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr: from,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: BytesMut::from(data),
            })
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        Ok(true)
    }

    /// Returns the next outbound STUN datagram to send, if any.
    pub fn poll_write(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.agent
            .poll_write()
            .map(|msg| (msg.message.to_vec(), msg.transport.peer_addr))
    }

    /// Returns the next connection-state or selected-pair event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.agent.poll_event()
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.agent
            .handle_timeout(now)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.agent.poll_timeout()
    }

    /// The currently selected candidate pair's remote address, once connected.
    pub fn selected_remote_addr(&self) -> Option<SocketAddr> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(_, remote)| remote.addr())
    }
}

/// Distinguishes a STUN packet from everything else sharing the same 5-tuple (DTLS
/// records, in NetherNet's case).
fn is_stun_packet(data: &[u8]) -> bool {
    rtc::stun::message::is_stun_message(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::ice::state::ConnectionState;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// Drives two ICE agents to completion by relaying each side's outbound STUN
    /// datagrams into the other's `handle_read`, exactly as a real UDP socket would,
    /// advancing a simulated clock to whichever timeout either side next requests so
    /// retransmission/backoff timers actually progress.
    #[test]
    fn two_agents_connect_over_loopback() {
        let mut now = Instant::now();
        let mut a = IceLayer::new(addr(40000), true).unwrap();
        let mut b = IceLayer::new(addr(40001), false).unwrap();

        let a_creds = a.local_credentials().clone();
        let b_creds = b.local_credentials().clone();
        a.set_remote_credentials(b_creds.ufrag.clone(), b_creds.pwd.clone())
            .unwrap();
        b.set_remote_credentials(a_creds.ufrag.clone(), a_creds.pwd.clone())
            .unwrap();

        let a_candidate = a.local_candidate().clone();
        let b_candidate = b.local_candidate().clone();
        a.add_remote_candidate(b_candidate).unwrap();
        b.add_remote_candidate(a_candidate).unwrap();

        let mut a_connected = false;
        let mut b_connected = false;

        for _ in 0..2000 {
            let mut progressed = false;

            while let Some((data, to)) = a.poll_write() {
                progressed = true;
                assert_eq!(to, addr(40001));
                b.handle_read(&data, addr(40000), now).unwrap();
            }
            while let Some((data, to)) = b.poll_write() {
                progressed = true;
                assert_eq!(to, addr(40000));
                a.handle_read(&data, addr(40001), now).unwrap();
            }

            while let Some(event) = a.poll_event() {
                progressed = true;
                if let Event::ConnectionStateChange(ConnectionState::Connected) = event {
                    a_connected = true;
                }
            }
            while let Some(event) = b.poll_event() {
                progressed = true;
                if let Event::ConnectionStateChange(ConnectionState::Connected) = event {
                    b_connected = true;
                }
            }

            if a_connected && b_connected {
                break;
            }

            if !progressed {
                let next_timeout = [a.poll_timeout(), b.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                now = next_timeout
                    .unwrap_or(now + std::time::Duration::from_millis(20))
                    .max(now + std::time::Duration::from_millis(1));
                a.handle_timeout(now).unwrap();
                b.handle_timeout(now).unwrap();
            }
        }

        assert!(a_connected, "a never reached Connected");
        assert!(b_connected, "b never reached Connected");
        assert_eq!(a.selected_remote_addr(), Some(addr(40001)));
        assert_eq!(b.selected_remote_addr(), Some(addr(40000)));
    }

    #[test]
    fn stun_demux_rejects_non_stun_datagrams() {
        // DTLS records (handshake=22, application_data=23, ...) are far too short here
        // and lack STUN's magic cookie at bytes 4..8.
        assert!(!is_stun_packet(&[22, 0, 0]));
        assert!(!is_stun_packet(&[23, 0, 0]));

        // A real (if minimal) STUN header: type + length + magic cookie + transaction id.
        let mut stun_header = vec![0x00, 0x01, 0x00, 0x00];
        stun_header.extend_from_slice(&0x2112A442u32.to_be_bytes());
        stun_header.extend_from_slice(&[0u8; 12]);
        assert!(is_stun_packet(&stun_header));
    }
}
