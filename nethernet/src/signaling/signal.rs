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
    type Err = SignalParseError;

    /// Parses a signal type from its wire string representation.
    ///
    /// Recognizes the following exact strings: `"CONNECTREQUEST"`, `"CONNECTRESPONSE"`,
    /// `"CANDIDATEADD"`, and `"CONNECTERROR"`. For any other input, returns
    /// [`SignalParseError::UnknownSignalType`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CONNECTREQUEST" => Ok(SignalType::Offer),
            "CONNECTRESPONSE" => Ok(SignalType::Answer),
            "CANDIDATEADD" => Ok(SignalType::Candidate),
            "CONNECTERROR" => Ok(SignalType::Error),
            _ => Err(SignalParseError::UnknownSignalType(s.to_string())),
        }
    }
}

impl fmt::Display for SignalType {
    /// Formats the signal type as its canonical protocol string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Errors produced while parsing a [`Signal`] from its wire string representation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignalParseError {
    #[error("invalid signal format: expected 3 parts, got {0}")]
    InvalidFormat(usize),
    #[error("unknown signal type: {0}")]
    UnknownSignalType(String),
    #[error("failed to parse connection ID: {0}")]
    InvalidConnectionId(String),
}

/// Signal error codes (compatible with the Go implementation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SignalErrorCode {
    None = 0,
    DestinationNotLoggedIn = 1,
    NegotiationTimeout = 2,
    WrongTransportVersion = 3,
    FailedToCreatePeerConnection = 4,
    Ice = 5,
    ConnectRequest = 6,
    ConnectResponse = 7,
    CandidateAdd = 8,
    InactivityTimeout = 9,
    FailedToCreateOffer = 10,
    FailedToCreateAnswer = 11,
    FailedToSetLocalDescription = 12,
    FailedToSetRemoteDescription = 13,
    NegotiationTimeoutWaitingForResponse = 14,
    NegotiationTimeoutWaitingForAccept = 15,
    IncomingConnectionIgnored = 16,
    SignalingParsingFailure = 17,
    SignalingUnknownError = 18,
    SignalingUnicastMessageDeliveryFailed = 19,
    SignalingBroadcastDeliveryFailed = 20,
    SignalingMessageDeliveryFailed = 21,
    SignalingTurnAuthFailed = 22,
    SignalingFallbackToBestEffortDelivery = 23,
    NoSignalingChannel = 24,
    NotLoggedIn = 25,
    SignalingFailedToSend = 26,
}

impl From<u32> for SignalErrorCode {
    fn from(code: u32) -> Self {
        match code {
            0 => SignalErrorCode::None,
            1 => SignalErrorCode::DestinationNotLoggedIn,
            2 => SignalErrorCode::NegotiationTimeout,
            3 => SignalErrorCode::WrongTransportVersion,
            4 => SignalErrorCode::FailedToCreatePeerConnection,
            5 => SignalErrorCode::Ice,
            6 => SignalErrorCode::ConnectRequest,
            7 => SignalErrorCode::ConnectResponse,
            8 => SignalErrorCode::CandidateAdd,
            9 => SignalErrorCode::InactivityTimeout,
            10 => SignalErrorCode::FailedToCreateOffer,
            11 => SignalErrorCode::FailedToCreateAnswer,
            12 => SignalErrorCode::FailedToSetLocalDescription,
            13 => SignalErrorCode::FailedToSetRemoteDescription,
            14 => SignalErrorCode::NegotiationTimeoutWaitingForResponse,
            15 => SignalErrorCode::NegotiationTimeoutWaitingForAccept,
            16 => SignalErrorCode::IncomingConnectionIgnored,
            17 => SignalErrorCode::SignalingParsingFailure,
            18 => SignalErrorCode::SignalingUnknownError,
            19 => SignalErrorCode::SignalingUnicastMessageDeliveryFailed,
            20 => SignalErrorCode::SignalingBroadcastDeliveryFailed,
            21 => SignalErrorCode::SignalingMessageDeliveryFailed,
            22 => SignalErrorCode::SignalingTurnAuthFailed,
            23 => SignalErrorCode::SignalingFallbackToBestEffortDelivery,
            24 => SignalErrorCode::NoSignalingChannel,
            25 => SignalErrorCode::NotLoggedIn,
            26 => SignalErrorCode::SignalingFailedToSend,
            _ => SignalErrorCode::SignalingUnknownError,
        }
    }
}

impl From<SignalErrorCode> for u32 {
    fn from(code: SignalErrorCode) -> Self {
        code as u32
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
    pub network_id: u64,
}

impl Signal {
    /// Constructs a Signal from its components.
    pub fn new(signal_type: SignalType, connection_id: u64, data: String, network_id: u64) -> Self {
        Self {
            signal_type,
            connection_id,
            data,
            network_id,
        }
    }

    /// Constructs a Signal with type Offer (CONNECTREQUEST) using the given connection ID, SDP payload, and network ID.
    pub fn offer(connection_id: u64, sdp: String, network_id: u64) -> Self {
        Self::new(SignalType::Offer, connection_id, sdp, network_id)
    }

    /// Creates a [`Signal`] with type [`SignalType::Answer`] for the specified connection, SDP payload, and network.
    pub fn answer(connection_id: u64, sdp: String, network_id: u64) -> Self {
        Self::new(SignalType::Answer, connection_id, sdp, network_id)
    }

    /// Creates a [`Signal`] with type [`SignalType::Candidate`] for the given connection and network.
    pub fn candidate(connection_id: u64, candidate: String, network_id: u64) -> Self {
        Self::new(SignalType::Candidate, connection_id, candidate, network_id)
    }

    /// Create a [`Signal`] representing a connection error.
    pub fn error(connection_id: u64, error_code: SignalErrorCode, network_id: u64) -> Self {
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
    pub fn from_str(s: &str, network_id: u64) -> Result<Self, SignalParseError> {
        let parts: Vec<&str> = s.splitn(3, ' ').collect();
        if parts.len() != 3 {
            return Err(SignalParseError::InvalidFormat(parts.len()));
        }

        let signal_type = SignalType::from_str(parts[0])?;
        let connection_id = parts[1]
            .parse::<u64>()
            .map_err(|e| SignalParseError::InvalidConnectionId(e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let signal = Signal::offer(42, "v=0...".to_string(), 7);
        let s = signal.to_string();
        let parsed = Signal::from_str(&s, 7).unwrap();
        assert_eq!(parsed.signal_type, SignalType::Offer);
        assert_eq!(parsed.connection_id, 42);
        assert_eq!(parsed.data, "v=0...");
        assert_eq!(parsed.network_id, 7);
    }

    #[test]
    fn invalid_format() {
        assert!(Signal::from_str("CONNECTREQUEST 42", 0).is_err());
    }

    #[test]
    fn unknown_type() {
        assert!(Signal::from_str("FOO 42 data", 0).is_err());
    }
}
