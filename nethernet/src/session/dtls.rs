//! DTLS handshake and application-data transport for a single remote peer.
//!
//! NetherNet (like all of WebRTC) authenticates a peer by comparing its presented
//! certificate's fingerprint against the one signaled in SDP, not by validating a CA
//! chain, so normal certificate-chain verification is disabled in favor of a fingerprint
//! check.

use crate::protocol::error::{ProtocolError, Result};
use bytes::BytesMut;
use rtc::dtls::config::{ClientAuthType, ConfigBuilder};
use rtc::dtls::crypto::Certificate;
use rtc::dtls::endpoint::Endpoint;
pub use rtc::dtls::endpoint::EndpointEvent;
use rtc::shared::{TransportProtocol, error::Error as SharedError};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The role this side actually resolves to for the DTLS handshake, per RFC 5763 §5:
/// whichever side announced `active` in its own SDP acts as the client (it dials);
/// whichever side announced `actpass` resolves to acting as the client too, when it is
/// the side that must pick, so in NetherNet's fixed offerer/answerer convention the
/// offerer (which always announces `actpass`) ends up as the DTLS server, and the
/// answerer (which always announces `active`) ends up as the DTLS client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedRole {
    Client,
    Server,
}

impl ResolvedRole {
    /// Resolves the local role from the *remote*'s announced (parsed) DTLS role.
    pub fn from_remote_announced(remote: crate::protocol::webrtc::DtlsRole) -> Self {
        use crate::protocol::webrtc::DtlsRole;
        match remote {
            DtlsRole::Client => Self::Server,
            DtlsRole::Server | DtlsRole::Auto => Self::Client,
        }
    }
}

pub struct DtlsLayer {
    endpoint: Endpoint,
    remote_addr: SocketAddr,
}

impl DtlsLayer {
    /// Creates the DTLS layer for a single remote peer. `certificate` is this side's own
    /// (freshly generated) certificate; `remote_fingerprint` is the `(algorithm, value)`
    /// pair signaled in the remote's description, checked against whatever certificate
    /// the peer actually presents during the handshake.
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        role: ResolvedRole,
        certificate: Certificate,
        remote_fingerprint: (String, String),
    ) -> Result<Self> {
        let is_client = role == ResolvedRole::Client;

        let config = ConfigBuilder::default()
            .with_certificates(vec![certificate])
            .with_insecure_skip_verify(true)
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_verify_peer_certificate(Some(verify_fingerprint(remote_fingerprint)))
            .build(is_client, Some(remote_addr))
            .map_err(|e| ProtocolError::Other(format!("build DTLS config: {e}")))?;
        let config = Arc::new(config);

        let mut endpoint = Endpoint::new(
            local_addr,
            TransportProtocol::UDP,
            (!is_client).then(|| config.clone()),
        );

        if is_client {
            endpoint
                .connect(remote_addr, config, None)
                .map_err(|e| ProtocolError::Other(format!("start DTLS handshake: {e}")))?;
        }

        Ok(Self {
            endpoint,
            remote_addr,
        })
    }

    /// Feeds an inbound datagram addressed to this remote peer (already demultiplexed
    /// from STUN by the caller).
    pub fn handle_read(&mut self, data: &[u8], now: Instant) -> Result<Vec<EndpointEvent>> {
        self.endpoint
            .read(now, self.remote_addr, None, BytesMut::from(data))
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    /// Queues application data (an SCTP packet) to be DTLS-encrypted and sent.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.endpoint
            .write(self.remote_addr, data)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    /// Returns the next outbound DTLS record to send, if any.
    pub fn poll_transmit(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.endpoint
            .poll_transmit()
            .map(|msg| (msg.message.to_vec(), msg.transport.peer_addr))
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.endpoint
            .handle_timeout(self.remote_addr, now)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    /// The next time `handle_timeout` should be called, if a handshake retransmission
    /// is pending.
    pub fn poll_timeout(&self, now: Instant) -> Option<Instant> {
        let sentinel = now + Duration::from_secs(3600);
        let mut eto = sentinel;
        self.endpoint.poll_timeout(self.remote_addr, &mut eto).ok();
        (eto != sentinel).then_some(eto)
    }
}

/// Builds the SDP-fingerprint verification callback: WebRTC's actual trust mechanism,
/// replacing the CA-chain verification `with_insecure_skip_verify` disables.
fn verify_fingerprint(expected: (String, String)) -> rtc::dtls::config::VerifyPeerCertificateFn {
    Arc::new(move |presented_certs, _verified_chains| {
        let Some(cert) = presented_certs.first() else {
            return Err(SharedError::ErrFingerprintMismatch);
        };

        let digest = Sha256::digest(cert.as_slice());
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");

        if expected.0.eq_ignore_ascii_case("sha-256") && hex == expected.1 {
            Ok(())
        } else {
            Err(SharedError::ErrFingerprintMismatch)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::webrtc::certificate;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// Drives a client and a server DTLS layer to a completed handshake and an
    /// application-data exchange over a loopback relay, mirroring the ICE layer's test.
    #[test]
    fn client_and_server_handshake_and_exchange_data() {
        let mut now = Instant::now();

        let client_cert = certificate::generate().unwrap();
        let server_cert = certificate::generate().unwrap();
        let client_fp = certificate::fingerprint(&client_cert).unwrap();
        let server_fp = certificate::fingerprint(&server_cert).unwrap();

        let mut client = DtlsLayer::new(
            addr(40010),
            addr(40011),
            ResolvedRole::Client,
            client_cert,
            server_fp,
        )
        .unwrap();
        let mut server = DtlsLayer::new(
            addr(40011),
            addr(40010),
            ResolvedRole::Server,
            server_cert,
            client_fp,
        )
        .unwrap();

        let mut client_done = false;
        let mut server_done = false;

        for _ in 0..2000 {
            let mut progressed = false;

            while let Some((data, to)) = client.poll_transmit() {
                progressed = true;
                assert_eq!(to, addr(40011));
                for event in server.handle_read(&data, now).unwrap() {
                    if matches!(event, EndpointEvent::HandshakeComplete) {
                        server_done = true;
                    }
                }
            }
            while let Some((data, to)) = server.poll_transmit() {
                progressed = true;
                assert_eq!(to, addr(40010));
                for event in client.handle_read(&data, now).unwrap() {
                    if matches!(event, EndpointEvent::HandshakeComplete) {
                        client_done = true;
                    }
                }
            }

            if client_done && server_done {
                break;
            }

            if !progressed {
                let next = [client.poll_timeout(now), server.poll_timeout(now)]
                    .into_iter()
                    .flatten()
                    .min();
                now = next
                    .unwrap_or(now + Duration::from_millis(20))
                    .max(now + Duration::from_millis(1));
                client.handle_timeout(now).unwrap();
                server.handle_timeout(now).unwrap();
            }
        }

        assert!(client_done, "client handshake never completed");
        assert!(server_done, "server handshake never completed");

        client.write(b"hello from client").unwrap();
        let mut delivered = None;
        for _ in 0..10 {
            if let Some((data, _)) = client.poll_transmit() {
                for event in server.handle_read(&data, now).unwrap() {
                    if let EndpointEvent::ApplicationData(msg) = event {
                        delivered = Some(msg);
                    }
                }
            }
        }
        assert_eq!(delivered.as_deref(), Some(&b"hello from client"[..]));
    }
}
