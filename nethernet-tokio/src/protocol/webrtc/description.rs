//! Session descriptions exchanged in `CONNECTREQUEST` and `CONNECTRESPONSE` signals.
//!
//! NetherNet expects a single `application` media description carrying the ICE,
//! DTLS and SCTP parameters of the remote transports. The description is built by
//! hand instead of through a peer connection, as vanilla clients reject the
//! descriptions produced by a generic WebRTC stack.

use crate::error::{NethernetError, Result};
use crate::protocol::constants::SCTP_PORT;
use crate::protocol::webrtc::{format_ice_candidate, parse_ice_candidate};
use rand::RngExt;
use std::io::Cursor;
use webrtc::dtls_transport::dtls_fingerprint::RTCDtlsFingerprint;
use webrtc::dtls_transport::dtls_parameters::DTLSParameters;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_parameters::RTCIceParameters;
use webrtc::sctp_transport::sctp_transport_capabilities::SCTPTransportCapabilities;
use webrtc::sdp::description::common::{Address, Attribute, ConnectionInformation};
use webrtc::sdp::description::media::{MediaDescription, MediaName, RangedPort};
use webrtc::sdp::description::session::{
    ATTR_KEY_CANDIDATE, ATTR_KEY_CONNECTION_SETUP, ATTR_KEY_EXTMAP_ALLOW_MIXED, ATTR_KEY_GROUP,
    ATTR_KEY_MID, ATTR_KEY_MSID_SEMANTIC, Origin, SessionDescription, TimeDescription,
};
use webrtc::sdp::util::ConnectionRole;

/// Parameters required to start the ICE, DTLS and SCTP transports of a connection.
#[derive(Debug, Clone)]
pub struct Description {
    pub ice: RTCIceParameters,
    pub dtls: DTLSParameters,
    pub sctp: SCTPTransportCapabilities,

    /// Candidates embedded in the description. Connections that do not support trickle
    /// ICE carry every local candidate in the description instead of signaling them.
    pub candidates: Vec<RTCIceCandidate>,
}

impl Description {
    /// Encodes the local parameters as the SDP carried by an offer or an answer.
    pub fn encode(&self) -> Result<String> {
        let session = SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: rand::rng().random(),
                session_version: 2,
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                unicast_address: "127.0.0.1".to_string(),
            },
            session_name: "-".to_string(),
            time_descriptions: vec![TimeDescription::default()],
            attributes: vec![
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
            ],
            ..Default::default()
        };

        let mut media = MediaDescription {
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
        };

        for (index, candidate) in self.candidates.iter().enumerate() {
            media = media.with_candidate(format_ice_candidate(
                index,
                candidate,
                &self.ice.username_fragment,
            ));
        }

        let media = media
            .with_ice_credentials(
                self.ice.username_fragment.clone(),
                self.ice.password.clone(),
            )
            .with_value_attribute("ice-options".to_string(), "trickle".to_string());

        let mut media = media;
        for fingerprint in &self.dtls.fingerprints {
            media =
                media.with_fingerprint(fingerprint.algorithm.clone(), fingerprint.value.clone());
        }

        let media = media
            .with_value_attribute(
                ATTR_KEY_CONNECTION_SETUP.to_string(),
                connection_role(self.dtls.role).to_string(),
            )
            .with_value_attribute(ATTR_KEY_MID.to_string(), "0".to_string())
            .with_value_attribute("sctp-port".to_string(), SCTP_PORT.to_string())
            .with_value_attribute(
                "max-message-size".to_string(),
                self.sctp.max_message_size.to_string(),
            );

        Ok(session.with_media(media).marshal())
    }

    /// Parses the SDP signaled by a remote connection.
    pub fn parse(sdp: &str) -> Result<Self> {
        let session = SessionDescription::unmarshal(&mut Cursor::new(sdp))
            .map_err(|e| NethernetError::Other(format!("decode session description: {}", e)))?;

        if session.media_descriptions.len() != 1 {
            return Err(NethernetError::Other(format!(
                "unexpected number of media descriptions: {}, expected 1",
                session.media_descriptions.len()
            )));
        }
        let media = &session.media_descriptions[0];

        let username_fragment = attribute(media, "ice-ufrag")?;
        let password = attribute(media, "ice-pwd")?;

        let fingerprint = attribute(media, "fingerprint")?;
        let (algorithm, value) = fingerprint.split_once(' ').ok_or_else(|| {
            NethernetError::Other(format!("invalid fingerprint: {}", fingerprint))
        })?;

        let setup = attribute(media, ATTR_KEY_CONNECTION_SETUP)?;
        let role = match setup {
            "active" => DTLSRole::Client,
            "actpass" => DTLSRole::Server,
            _ => {
                return Err(NethernetError::Other(format!(
                    "invalid setup attribute: {}",
                    setup
                )));
            }
        };

        let candidates = session
            .attributes
            .iter()
            .chain(media.attributes.iter())
            .filter(|attribute| attribute.key == ATTR_KEY_CANDIDATE)
            .filter_map(|attribute| attribute.value.as_deref())
            .map(parse_ice_candidate)
            .collect::<Result<Vec<_>>>()?;

        let max_message_size = attribute(media, "max-message-size")?
            .parse::<u32>()
            .map_err(|e| {
                NethernetError::Other(format!("parse max-message-size attribute: {}", e))
            })?;

        Ok(Self {
            ice: RTCIceParameters {
                username_fragment: username_fragment.to_string(),
                password: password.to_string(),
                ice_lite: false,
            },
            dtls: DTLSParameters {
                role,
                fingerprints: vec![RTCDtlsFingerprint {
                    algorithm: algorithm.to_string(),
                    value: value.to_string(),
                }],
            },
            sctp: SCTPTransportCapabilities { max_message_size },
            candidates,
        })
    }
}

/// Returns the value of a required media level attribute.
fn attribute<'a>(media: &'a MediaDescription, key: &str) -> Result<&'a str> {
    match media.attribute(key) {
        Some(Some(value)) => Ok(value),
        Some(None) => Err(NethernetError::Other(format!("empty {} attribute", key))),
        None => Err(NethernetError::Other(format!("missing {} attribute", key))),
    }
}

/// Returns the connection role to be signaled for the local DTLS role.
fn connection_role(role: DTLSRole) -> ConnectionRole {
    match role {
        DTLSRole::Server => ConnectionRole::Actpass,
        _ => ConnectionRole::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn description(role: DTLSRole) -> Description {
        Description {
            ice: RTCIceParameters {
                username_fragment: "abcd".to_string(),
                password: "0123456789abcdef01234567".to_string(),
                ice_lite: false,
            },
            dtls: DTLSParameters {
                role,
                fingerprints: vec![RTCDtlsFingerprint {
                    algorithm: "sha-256".to_string(),
                    value: "AB:CD:EF".to_string(),
                }],
            },
            sctp: SCTPTransportCapabilities {
                max_message_size: 65536,
            },
            candidates: Vec::new(),
        }
    }

    #[test]
    fn offer_roundtrip() {
        let encoded = description(DTLSRole::Server).encode().unwrap();
        assert!(encoded.contains("a=setup:actpass"));
        assert!(encoded.contains("a=sctp-port:5000"));
        assert!(encoded.contains("a=max-message-size:65536"));
        assert!(encoded.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));

        let parsed = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.ice.username_fragment, "abcd");
        assert_eq!(parsed.ice.password, "0123456789abcdef01234567");
        assert_eq!(parsed.dtls.role, DTLSRole::Server);
        assert_eq!(parsed.dtls.fingerprints[0].algorithm, "sha-256");
        assert_eq!(parsed.dtls.fingerprints[0].value, "AB:CD:EF");
        assert_eq!(parsed.sctp.max_message_size, 65536);
    }

    #[test]
    fn answer_is_parsed_as_client_role() {
        let encoded = description(DTLSRole::Auto).encode().unwrap();
        assert!(encoded.contains("a=setup:active"));
        assert_eq!(
            Description::parse(&encoded).unwrap().dtls.role,
            DTLSRole::Client
        );
    }

    #[test]
    fn missing_attribute_is_rejected() {
        let encoded = description(DTLSRole::Server).encode().unwrap();
        let without_fingerprint: String = encoded
            .lines()
            .filter(|line| !line.starts_with("a=fingerprint"))
            .map(|line| format!("{}\r\n", line))
            .collect();

        assert!(Description::parse(&without_fingerprint).is_err());
    }
}
