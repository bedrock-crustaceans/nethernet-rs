//! Session descriptions exchanged in NetherNet's signaling.
//!
//! NetherNet expects a single `application` media description carrying the ICE, DTLS
//! and SCTP parameters of the remote transports. The description is built by hand
//! instead of through a peer connection, as vanilla clients reject the descriptions
//! produced by a generic WebRTC stack.
//!
//! Two shapes are produced depending on the signaling transport (see the NetherNet HTTP
//! signaling guide, sections 2 and 4): LAN/UDP signaling uses trickle ICE (no candidates
//! embedded, `a=ice-options:trickle`, candidates follow as separate `CANDIDATEADD`
//! signals), while HTTP signaling always uses full ICE (every candidate embedded
//! directly, terminated by `a=end-of-candidates`).

use crate::protocol::error::{ProtocolError, Result};
use crate::protocol::webrtc::candidate;
use rtc::ice::agent::Credentials;
use rtc::ice::candidate::Candidate;
use rtc::sdp::description::common::{Address, Attribute, ConnectionInformation};
use rtc::sdp::description::media::{MediaDescription, MediaName, RangedPort};
use rtc::sdp::description::session::{
    ATTR_KEY_CONNECTION_SETUP, ATTR_KEY_END_OF_CANDIDATES, ATTR_KEY_EXTMAP_ALLOW_MIXED,
    ATTR_KEY_GROUP, ATTR_KEY_IDENTITY, ATTR_KEY_MAX_MESSAGE_SIZE, ATTR_KEY_MID,
    ATTR_KEY_MSID_SEMANTIC, Origin, SessionDescription, TimeDescription,
};
use rtc::sdp::util::ConnectionRole;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

/// The SCTP port announced in session descriptions.
pub const SCTP_PORT: u16 = 5000;

/// The DTLS role the local connection announces in its own description. This is the
/// role announced, not necessarily the role the transport ends up acting as once the
/// remote description is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    Client,
    Server,
    Auto,
}

/// Parameters required to start the ICE, DTLS and SCTP transports of a connection.
#[derive(Clone)]
pub struct Description {
    pub ice: Credentials,
    pub dtls_role: DtlsRole,
    /// `(algorithm, value)`, e.g. `("sha-256", "AA:BB:...")`.
    pub fingerprint: (String, String),
    pub sctp_max_message_size: u32,
    /// The raw `a=identity` attribute value, if present (see
    /// [`crate::protocol::webrtc::identity`], and the NetherNet HTTP signaling guide,
    /// section 5). `Description` treats this as an opaque string - building and
    /// verifying its contents is the `identity` module's job.
    pub identity: Option<String>,
}

impl Description {
    /// Encodes the description for trickle ICE (NetherNet's LAN/UDP signaling): no
    /// candidates are embedded; `a=ice-options:trickle` tells the remote to expect them
    /// via separate `CANDIDATEADD` signals instead.
    pub fn encode_trickle(&self) -> String {
        let media = self
            .base_media()
            .with_value_attribute("ice-options".to_string(), "trickle".to_string());
        Self::session(media, self.identity.as_deref()).marshal()
    }

    /// Encodes the description for full ICE (NetherNet's HTTP signaling): every
    /// candidate already gathered is embedded directly, terminated by
    /// `a=end-of-candidates`.
    pub fn encode_full(&self, candidates: &[Candidate]) -> String {
        let mut media = self.base_media();
        for (index, c) in candidates.iter().enumerate() {
            media = media.with_candidate(candidate::attribute_value(index, c, &self.ice.ufrag));
        }
        media = media.with_value_attribute(ATTR_KEY_END_OF_CANDIDATES.to_string(), "".to_string());
        Self::session(media, self.identity.as_deref()).marshal()
    }

    /// Parses the SDP signaled by a remote connection, returning the description and
    /// any ICE candidates embedded directly in it (empty under trickle ICE).
    pub fn parse(sdp: &str) -> Result<(Self, Vec<Candidate>)> {
        let session = SessionDescription::unmarshal(&mut Cursor::new(sdp))
            .map_err(|e| ProtocolError::Other(format!("decode session description: {e}")))?;

        if session.media_descriptions.len() != 1 {
            return Err(ProtocolError::Other(format!(
                "unexpected number of media descriptions: {}, expected 1",
                session.media_descriptions.len()
            )));
        }
        let media = &session.media_descriptions[0];

        let ufrag = attribute(media, "ice-ufrag")?.to_string();
        let pwd = attribute(media, "ice-pwd")?.to_string();

        let fingerprint_attr = attribute(media, "fingerprint")?;
        let (algorithm, value) = fingerprint_attr.split_once(' ').ok_or_else(|| {
            ProtocolError::Other(format!("invalid fingerprint: {fingerprint_attr}"))
        })?;

        let setup = attribute(media, ATTR_KEY_CONNECTION_SETUP)?;
        let dtls_role = match setup {
            "active" => DtlsRole::Client,
            "actpass" => DtlsRole::Server,
            _ => {
                return Err(ProtocolError::Other(format!(
                    "invalid setup attribute: {setup}"
                )));
            }
        };

        let sctp_max_message_size = attribute(media, ATTR_KEY_MAX_MESSAGE_SIZE)?
            .parse::<u32>()
            .map_err(|e| ProtocolError::Other(format!("parse max-message-size attribute: {e}")))?;

        let mut candidates = Vec::new();
        for attr in &media.attributes {
            if attr.key == "candidate"
                && let Some(value) = &attr.value
                && let Ok(parsed) = candidate::parse_ice_candidate(value)
            {
                candidates.push(parsed);
            }
        }

        let identity = session.attribute(ATTR_KEY_IDENTITY).cloned();

        Ok((
            Self {
                ice: Credentials { ufrag, pwd },
                dtls_role,
                fingerprint: (algorithm.to_string(), value.to_string()),
                sctp_max_message_size,
                identity,
            },
            candidates,
        ))
    }

    /// Builds the session-level SDP wrapper around `media`. `identity`, if given, is
    /// the `a=identity` attribute value (see [`crate::protocol::webrtc::identity`]);
    /// per the guide's section 5, it is a session-level attribute that must come before
    /// the first `m=` line, which placing it among the other session attributes here
    /// satisfies regardless of the marshaled attribute order.
    fn session(media: MediaDescription, identity: Option<&str>) -> SessionDescription {
        let mut attributes = vec![
            Attribute {
                key: ATTR_KEY_GROUP.to_string(),
                value: Some("BUNDLE 0".to_string()),
            },
            Attribute {
                key: ATTR_KEY_EXTMAP_ALLOW_MIXED.to_string(),
                value: None,
            },
            Attribute {
                key: ATTR_KEY_MSID_SEMANTIC.to_string(),
                value: Some(" WMS".to_string()),
            },
        ];
        if let Some(identity) = identity {
            attributes.push(Attribute {
                key: ATTR_KEY_IDENTITY.to_string(),
                value: Some(identity.to_string()),
            });
        }

        SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: session_id(),
                session_version: 2,
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                unicast_address: "127.0.0.1".to_string(),
            },
            session_name: "-".to_string(),
            time_descriptions: vec![TimeDescription::default()],
            attributes,
            ..Default::default()
        }
        .with_media(media)
    }

    fn base_media(&self) -> MediaDescription {
        let media = MediaDescription {
            media_name: MediaName {
                media: "application".to_string(),
                port: RangedPort {
                    value: 9,
                    range: None,
                },
                protos: vec!["UDP".to_string(), "DTLS".to_string(), "SCTP".to_string()],
                formats: vec!["webrtc-datachannel".to_string()],
            },
            connection_information: Some(ConnectionInformation {
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                address: Some(Address {
                    address: "0.0.0.0".to_string(),
                    ttl: None,
                    range: None,
                }),
            }),
            ..Default::default()
        }
        .with_ice_credentials(self.ice.ufrag.clone(), self.ice.pwd.clone());

        let (algorithm, value) = &self.fingerprint;
        let media = media.with_fingerprint(algorithm.clone(), value.clone());

        media
            .with_value_attribute(
                ATTR_KEY_CONNECTION_SETUP.to_string(),
                connection_role(self.dtls_role).to_string(),
            )
            .with_value_attribute(ATTR_KEY_MID.to_string(), "0".to_string())
            .with_value_attribute("sctp-port".to_string(), SCTP_PORT.to_string())
            .with_value_attribute(
                ATTR_KEY_MAX_MESSAGE_SIZE.to_string(),
                self.sctp_max_message_size.to_string(),
            )
    }
}

/// Returns the value of a required media level attribute.
fn attribute<'a>(media: &'a MediaDescription, key: &str) -> Result<&'a str> {
    match media.attribute(key) {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(ProtocolError::Other(format!("empty {key} attribute"))),
        None => Err(ProtocolError::Other(format!("missing {key} attribute"))),
    }
}

/// Returns the connection role to be signaled for the local DTLS role.
fn connection_role(role: DtlsRole) -> ConnectionRole {
    match role {
        DtlsRole::Server => ConnectionRole::Actpass,
        _ => ConnectionRole::Active,
    }
}

/// A locally-unique-enough session id for the `o=` line; NetherNet does not rely on
/// this for anything beyond distinguishing SDP versions, so wall-clock time is enough.
fn session_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::ice::candidate::CandidateConfig;
    use rtc::ice::candidate::candidate_host::CandidateHostConfig;

    fn description(role: DtlsRole) -> Description {
        Description {
            ice: Credentials {
                ufrag: "abcd".to_string(),
                pwd: "0123456789abcdef01234567".to_string(),
            },
            dtls_role: role,
            fingerprint: ("sha-256".to_string(), "AB:CD:EF".to_string()),
            sctp_max_message_size: 65536,
            identity: None,
        }
    }

    fn host_candidate(address: &str, port: u16) -> Candidate {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: address.to_string(),
                port,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap()
    }

    #[test]
    fn trickle_roundtrip() {
        let encoded = description(DtlsRole::Server).encode_trickle();
        assert!(encoded.contains("a=setup:actpass"));
        assert!(encoded.contains("a=sctp-port:5000"));
        assert!(encoded.contains("a=max-message-size:65536"));
        assert!(encoded.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(encoded.contains("a=ice-options:trickle"));
        assert!(!encoded.contains("a=candidate:"));

        let (parsed, candidates) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.ice.ufrag, "abcd");
        assert_eq!(parsed.ice.pwd, "0123456789abcdef01234567");
        assert_eq!(parsed.dtls_role, DtlsRole::Server);
        assert_eq!(
            parsed.fingerprint,
            ("sha-256".to_string(), "AB:CD:EF".to_string())
        );
        assert_eq!(parsed.sctp_max_message_size, 65536);
        assert!(candidates.is_empty());
    }

    #[test]
    fn full_ice_embeds_candidates() {
        let candidates = vec![host_candidate("192.168.1.10", 54321)];
        let encoded = description(DtlsRole::Server).encode_full(&candidates);

        assert!(encoded.contains("a=candidate:"));
        assert!(encoded.contains("192.168.1.10"));
        assert!(encoded.contains("a=end-of-candidates"));
        assert!(!encoded.contains("a=ice-options:trickle"));

        let (_, parsed_candidates) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed_candidates.len(), 1);
        assert_eq!(parsed_candidates[0].address(), "192.168.1.10");
        assert_eq!(parsed_candidates[0].port(), 54321);
    }

    #[test]
    fn answer_is_parsed_as_client_role() {
        let encoded = description(DtlsRole::Auto).encode_trickle();
        assert!(encoded.contains("a=setup:active"));
        assert_eq!(
            Description::parse(&encoded).unwrap().0.dtls_role,
            DtlsRole::Client
        );
    }

    #[test]
    fn missing_attribute_is_rejected() {
        let encoded = description(DtlsRole::Server).encode_trickle();
        let without_fingerprint: String = encoded
            .lines()
            .filter(|line| !line.starts_with("a=fingerprint"))
            .map(|line| format!("{line}\r\n"))
            .collect();

        assert!(Description::parse(&without_fingerprint).is_err());
    }

    #[test]
    fn identity_attribute_is_session_level_and_roundtrips() {
        let mut with_identity = description(DtlsRole::Server);
        with_identity.identity = Some("opaque-identity-blob".to_string());

        let encoded = with_identity.encode_trickle();
        // Session-level: appears before the first `m=` line.
        let identity_pos = encoded.find("a=identity:opaque-identity-blob").unwrap();
        let media_pos = encoded.find("m=application").unwrap();
        assert!(identity_pos < media_pos);

        let (parsed, _) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.identity.as_deref(), Some("opaque-identity-blob"));
    }

    #[test]
    fn missing_identity_parses_as_none() {
        let encoded = description(DtlsRole::Server).encode_trickle();
        let (parsed, _) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.identity, None);
    }
}
