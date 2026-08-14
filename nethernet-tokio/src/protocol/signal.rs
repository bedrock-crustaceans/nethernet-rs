use crate::error::{NethernetError, SignalErrorCode};
use std::fmt;
use std::str::FromStr;

/// Signal types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    /// CONNECTREQUEST - Connection request (offer)
    Offer,
    /// CONNECTRESPONSE - Connection response (answer)
    Answer,
    /// CANDIDATEADD - ICE candidate addition
    Candidate,
    /// CONNECTERROR - Connection error
    Error,
}

impl SignalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalType::Offer => "CONNECTREQUEST",
            SignalType::Answer => "CONNECTRESPONSE",
            SignalType::Candidate => "CANDIDATEADD",
            SignalType::Error => "CONNECTERROR",
        }
    }
}

impl FromStr for SignalType {
    type Err = NethernetError;

    /// Parses a signal type from its wire string representation.
    ///
    /// Recognizes the following exact strings: `"CONNECTREQUEST"`, `"CONNECTRESPONSE"`,
    /// `"CANDIDATEADD"`, and `"CONNECTERROR"`. For any other input, returns
    /// `NethernetError::Other` with an "Unknown signal type" message.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CONNECTREQUEST" => Ok(SignalType::Offer),
            "CONNECTRESPONSE" => Ok(SignalType::Answer),
            "CANDIDATEADD" => Ok(SignalType::Candidate),
            "CONNECTERROR" => Ok(SignalType::Error),
            _ => Err(NethernetError::Other(format!("Unknown signal type: {}", s))),
        }
    }
}

impl fmt::Display for SignalType {
    /// Formats the signal type as its canonical protocol string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// NetherNet signal message
#[derive(Debug, Clone)]
pub struct Signal {
    /// Signal type
    pub signal_type: SignalType,
    /// Connection ID
    pub connection_id: u64,
    /// Signal data (SDP, ICE candidate, etc.)
    pub data: String,
    /// Network ID (receiver/sender)
    pub network_id: String,
}

impl Signal {
    /// Constructs a Signal from its components.
    pub fn new(
        signal_type: SignalType,
        connection_id: u64,
        data: String,
        network_id: String,
    ) -> Self {
        Self {
            signal_type,
            connection_id,
            data,
            network_id,
        }
    }

    /// Constructs a Signal with type Offer (CONNECTREQUEST) using the given connection ID, SDP payload, and network ID.
    pub fn offer(connection_id: u64, sdp: String, network_id: String) -> Self {
        Self::new(SignalType::Offer, connection_id, sdp, network_id)
    }

    /// Creates a [`Signal`] with type [`SignalType::Answer`] for the specified connection, SDP payload, and network.
    pub fn answer(connection_id: u64, sdp: String, network_id: String) -> Self {
        Self::new(SignalType::Answer, connection_id, sdp, network_id)
    }

    /// Creates a [`Signal`] with type [`SignalType::Candidate`] for the given connection and network.
    pub fn candidate(connection_id: u64, candidate: String, network_id: String) -> Self {
        Self::new(SignalType::Candidate, connection_id, candidate, network_id)
    }

    /// Create a [`Signal`] representing a connection error.
    pub fn error(connection_id: u64, error_code: SignalErrorCode, network_id: String) -> Self {
        Self::new(
            SignalType::Error,
            connection_id,
            (error_code as u32).to_string(),
            network_id,
        )
    }

    /// Parses a Signal from a space-separated string and assigns the provided network ID.
    ///
    /// The input string must contain exactly three space-separated tokens in the form:
    /// `TYPE CONNECTION_ID DATA`
    /// - `TYPE` is the signal type token (e.g., `CONNECTREQUEST`, `CONNECTRESPONSE`, `CANDIDATEADD`, `CONNECTERROR`).
    /// - `CONNECTION_ID` is a base-10 unsigned integer.
    /// - `DATA` is the remaining token (signal payload such as SDP or ICE candidate).
    pub fn from_string(s: &str, network_id: String) -> Result<Self, NethernetError> {
        let parts: Vec<&str> = s.splitn(3, ' ').collect();
        if parts.len() != 3 {
            return Err(NethernetError::Other(format!(
                "Invalid signal format: expected 3 parts, got {}",
                parts.len()
            )));
        }

        let signal_type = SignalType::from_str(parts[0])?;
        let connection_id = parts[1]
            .parse::<u64>()
            .map_err(|e| NethernetError::Other(format!("Failed to parse connection ID: {}", e)))?;
        let data = parts[2].to_string();

        Ok(Self {
            signal_type,
            connection_id,
            data,
            network_id,
        })
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.signal_type.as_str(),
            self.connection_id,
            self.data
        )
    }
}
