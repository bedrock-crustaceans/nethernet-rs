//! WebRTC negotiation messages.
//!
//! These messages are sent during WebRTC connection establishment.

use super::error::ConnectError;
use crate::error::{NethernetError, Result};
use std::fmt;

/// Message types used for WebRTC negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationMessage {
    /// CONNECTREQUEST - Contains SDP offer from client
    ConnectRequest {
        connection_id: u64,
        sdp_offer: String,
    },
    /// CONNECTRESPONSE - Contains SDP answer from server
    ConnectResponse {
        connection_id: u64,
        sdp_answer: String,
    },
    /// CANDIDATEADD - Contains ICE candidate
    CandidateAdd {
        connection_id: u64,
        candidate: String,
    },
    /// CONNECTERROR - Contains error code
    ConnectError {
        connection_id: u64,
        error: ConnectError,
    },
}

impl NegotiationMessage {
    /// Parse a negotiation message from its wire-format string.
    ///
    /// The expected wire format is:
    /// `MESSAGETYPE CONNECTIONID DATA`
    /// where `DATA` is the payload specific to the message type:
    /// - `CONNECTREQUEST` — SDP offer
    /// - `CONNECTRESPONSE` — SDP answer
    /// - `CANDIDATEADD` — ICE candidate
    /// - `CONNECTERROR` — numeric error code
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(NethernetError::Other("invalid message format".to_string()));
        }

        let message_type = parts[0];
        let connection_id = parts[1]
            .parse::<u64>()
            .map_err(|e| NethernetError::Other(format!("invalid connection ID: {}", e)))?;

        // Helper closure for validating payload (parts[2])
        let validate_payload = |error_msg: &str| -> Result<&str> {
            if parts.len() < 3 {
                return Err(NethernetError::Other(error_msg.to_string()));
            }
            if parts[2].trim().is_empty() {
                return Err(NethernetError::Other(error_msg.to_string()));
            }
            Ok(parts[2])
        };

        match message_type {
            "CONNECTREQUEST" => {
                let sdp_offer = validate_payload("missing SDP offer")?;
                Ok(Self::ConnectRequest {
                    connection_id,
                    sdp_offer: sdp_offer.to_string(),
                })
            }
            "CONNECTRESPONSE" => {
                let sdp_answer = validate_payload("missing SDP answer")?;
                Ok(Self::ConnectResponse {
                    connection_id,
                    sdp_answer: sdp_answer.to_string(),
                })
            }
            "CANDIDATEADD" => {
                let candidate = validate_payload("missing ICE candidate")?;
                Ok(Self::CandidateAdd {
                    connection_id,
                    candidate: candidate.to_string(),
                })
            }
            "CONNECTERROR" => {
                if parts.len() < 3 {
                    return Err(NethernetError::Other("missing error code".to_string()));
                }
                let error_code = parts[2]
                    .parse::<u8>()
                    .map_err(|e| NethernetError::Other(format!("invalid error code: {}", e)))?;
                let error = ConnectError::from_code(error_code).ok_or_else(|| {
                    NethernetError::Other(format!("unknown error code: {}", error_code))
                })?;
                Ok(Self::ConnectError {
                    connection_id,
                    error,
                })
            }
            _ => Err(NethernetError::Other(format!(
                "unknown message type: {}",
                message_type
            ))),
        }
    }

    /// Get the connection identifier associated with the message.
    pub fn connection_id(&self) -> u64 {
        match self {
            Self::ConnectRequest { connection_id, .. }
            | Self::ConnectResponse { connection_id, .. }
            | Self::CandidateAdd { connection_id, .. }
            | Self::ConnectError { connection_id, .. } => *connection_id,
        }
    }

    /// Return the canonical message type name for this negotiation message.
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::ConnectRequest { .. } => "CONNECTREQUEST",
            Self::ConnectResponse { .. } => "CONNECTRESPONSE",
            Self::CandidateAdd { .. } => "CANDIDATEADD",
            Self::ConnectError { .. } => "CONNECTERROR",
        }
    }
}

impl fmt::Display for NegotiationMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectRequest {
                connection_id,
                sdp_offer,
            } => {
                write!(f, "CONNECTREQUEST {} {}", connection_id, sdp_offer)
            }
            Self::ConnectResponse {
                connection_id,
                sdp_answer,
            } => {
                write!(f, "CONNECTRESPONSE {} {}", connection_id, sdp_answer)
            }
            Self::CandidateAdd {
                connection_id,
                candidate,
            } => {
                write!(f, "CANDIDATEADD {} {}", connection_id, candidate)
            }
            Self::ConnectError {
                connection_id,
                error,
            } => {
                write!(f, "CONNECTERROR {} {}", connection_id, error.code())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_request_roundtrip() {
        let msg = NegotiationMessage::ConnectRequest {
            connection_id: 12345,
            sdp_offer: "v=0\r\no=- 123456789 2 IN IP4 127.0.0.1".to_string(),
        };
        let s = msg.to_string();
        let parsed = NegotiationMessage::parse(&s).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_connect_response_roundtrip() {
        let msg = NegotiationMessage::ConnectResponse {
            connection_id: 67890,
            sdp_answer: "v=0\r\no=- 987654321 2 IN IP4 192.168.1.1".to_string(),
        };
        let s = msg.to_string();
        let parsed = NegotiationMessage::parse(&s).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_candidate_add_roundtrip() {
        let msg = NegotiationMessage::CandidateAdd {
            connection_id: 11111,
            candidate: "candidate:1234567890 1 udp 2130706431 192.168.1.100 54321 typ host"
                .to_string(),
        };
        let s = msg.to_string();
        let parsed = NegotiationMessage::parse(&s).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_connect_error_roundtrip() {
        let msg = NegotiationMessage::ConnectError {
            connection_id: 99999,
            error: ConnectError::NegotiationTimeout,
        };
        let s = msg.to_string();
        let parsed = NegotiationMessage::parse(&s).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_invalid_format() {
        assert!(NegotiationMessage::parse("INVALID").is_err());
        assert!(NegotiationMessage::parse("CONNECTREQUEST").is_err());
        assert!(NegotiationMessage::parse("CONNECTREQUEST abc").is_err());
    }
}
