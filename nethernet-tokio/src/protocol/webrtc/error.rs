//! WebRTC connection error codes.
//!
//! These error codes are sent in CONNECTERROR messages during WebRTC negotiation.
//!
//! Note: [`ConnectError`] and [`crate::error::SignalErrorCode`] represent the same logical
//! error conditions but use different wire formats (u8 vs u32) and have different discriminant
//! values. ConnectError has a gap at 0x14 in its discriminant sequence.

/// WebRTC connection error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(u8)]
pub enum ConnectError {
    #[error("no error")]
    None = 0x00,
    #[error("destination not logged in")]
    DestinationNotLoggedIn = 0x01,
    #[error("negotiation timeout")]
    NegotiationTimeout = 0x02,
    #[error("wrong transport version")]
    WrongTransportVersion = 0x03,
    #[error("failed to create peer connection")]
    FailedToCreatePeerConnection = 0x04,
    #[error("ICE error")]
    ICE = 0x05,
    #[error("connect request error")]
    ConnectRequest = 0x06,
    #[error("connect response error")]
    ConnectResponse = 0x07,
    #[error("candidate add error")]
    CandidateAdd = 0x08,
    #[error("inactivity timeout")]
    InactivityTimeout = 0x09,
    #[error("failed to create offer")]
    FailedToCreateOffer = 0x0a,
    #[error("failed to create answer")]
    FailedToCreateAnswer = 0x0b,
    #[error("failed to set local description")]
    FailedToSetLocalDescription = 0x0c,
    #[error("failed to set remote description")]
    FailedToSetRemoteDescription = 0x0d,
    #[error("negotiation timeout waiting for response")]
    NegotiationTimeoutWaitingForResponse = 0x0e,
    #[error("negotiation timeout waiting for accept")]
    NegotiationTimeoutWaitingForAccept = 0x0f,
    #[error("incoming connection ignored")]
    IncomingConnectionIgnored = 0x10,
    #[error("signaling parsing failure")]
    SignalingParsingFailure = 0x11,
    #[error("signaling unknown error")]
    SignalingUnknownError = 0x12,
    #[error("signaling unicast message delivery failed")]
    SignalingUnicastMessageDeliveryFailed = 0x13,
    #[error("signaling broadcast delivery failed")]
    SignalingBroadcastDeliveryFailed = 0x15,
    #[error("signaling message delivery failed")]
    SignalingMessageDeliveryFailed = 0x16,
    #[error("signaling TURN auth failed")]
    SignalingTurnAuthFailed = 0x17,
    #[error("signaling fallback to best effort delivery")]
    SignalingFallbackToBestEffortDelivery = 0x18,
    #[error("no signaling channel")]
    NoSignalingChannel = 0x19,
    #[error("not logged in")]
    NotLoggedIn = 0x1a,
    #[error("signaling failed to send")]
    SignalingFailedToSend = 0x1b,
}

impl ConnectError {
    /// Map a numeric wire code to the corresponding [`ConnectError`] variant.
    ///
    /// Returns [`Some`] when `code` matches a defined wire discriminant, [`None`] for unknown codes
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::None),
            0x01 => Some(Self::DestinationNotLoggedIn),
            0x02 => Some(Self::NegotiationTimeout),
            0x03 => Some(Self::WrongTransportVersion),
            0x04 => Some(Self::FailedToCreatePeerConnection),
            0x05 => Some(Self::ICE),
            0x06 => Some(Self::ConnectRequest),
            0x07 => Some(Self::ConnectResponse),
            0x08 => Some(Self::CandidateAdd),
            0x09 => Some(Self::InactivityTimeout),
            0x0a => Some(Self::FailedToCreateOffer),
            0x0b => Some(Self::FailedToCreateAnswer),
            0x0c => Some(Self::FailedToSetLocalDescription),
            0x0d => Some(Self::FailedToSetRemoteDescription),
            0x0e => Some(Self::NegotiationTimeoutWaitingForResponse),
            0x0f => Some(Self::NegotiationTimeoutWaitingForAccept),
            0x10 => Some(Self::IncomingConnectionIgnored),
            0x11 => Some(Self::SignalingParsingFailure),
            0x12 => Some(Self::SignalingUnknownError),
            0x13 => Some(Self::SignalingUnicastMessageDeliveryFailed),
            0x15 => Some(Self::SignalingBroadcastDeliveryFailed),
            0x16 => Some(Self::SignalingMessageDeliveryFailed),
            0x17 => Some(Self::SignalingTurnAuthFailed),
            0x18 => Some(Self::SignalingFallbackToBestEffortDelivery),
            0x19 => Some(Self::NoSignalingChannel),
            0x1a => Some(Self::NotLoggedIn),
            0x1b => Some(Self::SignalingFailedToSend),
            _ => None,
        }
    }

    /// Get the wire-format numeric code associated with this [`ConnectError`] variant.
    pub fn code(&self) -> u8 {
        *self as u8
    }
}

impl From<crate::error::SignalErrorCode> for ConnectError {
    /// Convert a [`crate::error::SignalErrorCode`] into the corresponding [`ConnectError`] variant.
    fn from(code: crate::error::SignalErrorCode) -> Self {
        use crate::error::SignalErrorCode as S;
        match code {
            S::None => Self::None,
            S::DestinationNotLoggedIn => Self::DestinationNotLoggedIn,
            S::NegotiationTimeout => Self::NegotiationTimeout,
            S::WrongTransportVersion => Self::WrongTransportVersion,
            S::FailedToCreatePeerConnection => Self::FailedToCreatePeerConnection,
            S::Ice => Self::ICE,
            S::ConnectRequest => Self::ConnectRequest,
            S::ConnectResponse => Self::ConnectResponse,
            S::CandidateAdd => Self::CandidateAdd,
            S::InactivityTimeout => Self::InactivityTimeout,
            S::FailedToCreateOffer => Self::FailedToCreateOffer,
            S::FailedToCreateAnswer => Self::FailedToCreateAnswer,
            S::FailedToSetLocalDescription => Self::FailedToSetLocalDescription,
            S::FailedToSetRemoteDescription => Self::FailedToSetRemoteDescription,
            S::NegotiationTimeoutWaitingForResponse => Self::NegotiationTimeoutWaitingForResponse,
            S::NegotiationTimeoutWaitingForAccept => Self::NegotiationTimeoutWaitingForAccept,
            S::IncomingConnectionIgnored => Self::IncomingConnectionIgnored,
            S::SignalingParsingFailure => Self::SignalingParsingFailure,
            S::SignalingUnknownError => Self::SignalingUnknownError,
            S::SignalingUnicastMessageDeliveryFailed => Self::SignalingUnicastMessageDeliveryFailed,
            S::SignalingBroadcastDeliveryFailed => Self::SignalingBroadcastDeliveryFailed,
            S::SignalingMessageDeliveryFailed => Self::SignalingMessageDeliveryFailed,
            S::SignalingTurnAuthFailed => Self::SignalingTurnAuthFailed,
            S::SignalingFallbackToBestEffortDelivery => Self::SignalingFallbackToBestEffortDelivery,
            S::NoSignalingChannel => Self::NoSignalingChannel,
            S::NotLoggedIn => Self::NotLoggedIn,
            S::SignalingFailedToSend => Self::SignalingFailedToSend,
        }
    }
}

impl From<ConnectError> for crate::error::SignalErrorCode {
    /// Convert a [`ConnectError`] into its corresponding [`crate::error::SignalErrorCode`].
    fn from(error: ConnectError) -> Self {
        use crate::error::SignalErrorCode as S;
        match error {
            ConnectError::None => S::None,
            ConnectError::DestinationNotLoggedIn => S::DestinationNotLoggedIn,
            ConnectError::NegotiationTimeout => S::NegotiationTimeout,
            ConnectError::WrongTransportVersion => S::WrongTransportVersion,
            ConnectError::FailedToCreatePeerConnection => S::FailedToCreatePeerConnection,
            ConnectError::ICE => S::Ice,
            ConnectError::ConnectRequest => S::ConnectRequest,
            ConnectError::ConnectResponse => S::ConnectResponse,
            ConnectError::CandidateAdd => S::CandidateAdd,
            ConnectError::InactivityTimeout => S::InactivityTimeout,
            ConnectError::FailedToCreateOffer => S::FailedToCreateOffer,
            ConnectError::FailedToCreateAnswer => S::FailedToCreateAnswer,
            ConnectError::FailedToSetLocalDescription => S::FailedToSetLocalDescription,
            ConnectError::FailedToSetRemoteDescription => S::FailedToSetRemoteDescription,
            ConnectError::NegotiationTimeoutWaitingForResponse => {
                S::NegotiationTimeoutWaitingForResponse
            }
            ConnectError::NegotiationTimeoutWaitingForAccept => {
                S::NegotiationTimeoutWaitingForAccept
            }
            ConnectError::IncomingConnectionIgnored => S::IncomingConnectionIgnored,
            ConnectError::SignalingParsingFailure => S::SignalingParsingFailure,
            ConnectError::SignalingUnknownError => S::SignalingUnknownError,
            ConnectError::SignalingUnicastMessageDeliveryFailed => {
                S::SignalingUnicastMessageDeliveryFailed
            }
            ConnectError::SignalingBroadcastDeliveryFailed => S::SignalingBroadcastDeliveryFailed,
            ConnectError::SignalingMessageDeliveryFailed => S::SignalingMessageDeliveryFailed,
            ConnectError::SignalingTurnAuthFailed => S::SignalingTurnAuthFailed,
            ConnectError::SignalingFallbackToBestEffortDelivery => {
                S::SignalingFallbackToBestEffortDelivery
            }
            ConnectError::NoSignalingChannel => S::NoSignalingChannel,
            ConnectError::NotLoggedIn => S::NotLoggedIn,
            ConnectError::SignalingFailedToSend => S::SignalingFailedToSend,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SignalErrorCode;

    #[test]
    fn test_connect_error_to_signal_error_code() {
        // Test all ConnectError variants convert to SignalErrorCode
        let variants = [
            ConnectError::None,
            ConnectError::DestinationNotLoggedIn,
            ConnectError::NegotiationTimeout,
            ConnectError::WrongTransportVersion,
            ConnectError::FailedToCreatePeerConnection,
            ConnectError::ICE,
            ConnectError::ConnectRequest,
            ConnectError::ConnectResponse,
            ConnectError::CandidateAdd,
            ConnectError::InactivityTimeout,
            ConnectError::FailedToCreateOffer,
            ConnectError::FailedToCreateAnswer,
            ConnectError::FailedToSetLocalDescription,
            ConnectError::FailedToSetRemoteDescription,
            ConnectError::NegotiationTimeoutWaitingForResponse,
            ConnectError::NegotiationTimeoutWaitingForAccept,
            ConnectError::IncomingConnectionIgnored,
            ConnectError::SignalingParsingFailure,
            ConnectError::SignalingUnknownError,
            ConnectError::SignalingUnicastMessageDeliveryFailed,
            ConnectError::SignalingBroadcastDeliveryFailed,
            ConnectError::SignalingMessageDeliveryFailed,
            ConnectError::SignalingTurnAuthFailed,
            ConnectError::SignalingFallbackToBestEffortDelivery,
            ConnectError::NoSignalingChannel,
            ConnectError::NotLoggedIn,
            ConnectError::SignalingFailedToSend,
        ];

        for variant in variants {
            let signal_code: SignalErrorCode = variant.into();
            let connect_code: ConnectError = signal_code.into();
            assert_eq!(variant, connect_code, "Round-trip failed for {:?}", variant);
        }
    }

    #[test]
    fn test_signal_error_code_to_connect_error() {
        // Test all SignalErrorCode variants convert to ConnectError
        let variants = [
            SignalErrorCode::None,
            SignalErrorCode::DestinationNotLoggedIn,
            SignalErrorCode::NegotiationTimeout,
            SignalErrorCode::WrongTransportVersion,
            SignalErrorCode::FailedToCreatePeerConnection,
            SignalErrorCode::Ice,
            SignalErrorCode::ConnectRequest,
            SignalErrorCode::ConnectResponse,
            SignalErrorCode::CandidateAdd,
            SignalErrorCode::InactivityTimeout,
            SignalErrorCode::FailedToCreateOffer,
            SignalErrorCode::FailedToCreateAnswer,
            SignalErrorCode::FailedToSetLocalDescription,
            SignalErrorCode::FailedToSetRemoteDescription,
            SignalErrorCode::NegotiationTimeoutWaitingForResponse,
            SignalErrorCode::NegotiationTimeoutWaitingForAccept,
            SignalErrorCode::IncomingConnectionIgnored,
            SignalErrorCode::SignalingParsingFailure,
            SignalErrorCode::SignalingUnknownError,
            SignalErrorCode::SignalingUnicastMessageDeliveryFailed,
            SignalErrorCode::SignalingBroadcastDeliveryFailed,
            SignalErrorCode::SignalingMessageDeliveryFailed,
            SignalErrorCode::SignalingTurnAuthFailed,
            SignalErrorCode::SignalingFallbackToBestEffortDelivery,
            SignalErrorCode::NoSignalingChannel,
            SignalErrorCode::NotLoggedIn,
            SignalErrorCode::SignalingFailedToSend,
        ];

        for variant in variants {
            let connect_code: ConnectError = variant.into();
            let signal_code: SignalErrorCode = connect_code.into();
            assert_eq!(variant, signal_code, "Round-trip failed for {:?}", variant);
        }
    }

    #[test]
    fn test_discriminant_gap_handling() {
        // Test that the 0x14 gap is handled correctly
        // SignalingBroadcastDeliveryFailed should be 0x15 in ConnectError
        let connect_error = ConnectError::SignalingBroadcastDeliveryFailed;
        assert_eq!(connect_error.code(), 0x15);

        // SignalingUnicastMessageDeliveryFailed should be 0x13 in ConnectError
        let connect_error = ConnectError::SignalingUnicastMessageDeliveryFailed;
        assert_eq!(connect_error.code(), 0x13);

        // Verify the gap: no variant at 0x14
        assert_eq!(ConnectError::from_code(0x14), None);
    }

    #[test]
    fn test_discriminant_values() {
        // Verify that ConnectError and SignalErrorCode map correctly despite different discriminants
        let signal_broadcast = SignalErrorCode::SignalingBroadcastDeliveryFailed;
        let connect_broadcast: ConnectError = signal_broadcast.into();

        // SignalErrorCode uses sequential values (20 for SignalingBroadcastDeliveryFailed)
        assert_eq!(signal_broadcast as u32, 20);
        // ConnectError has a gap and uses 0x15 (21)
        assert_eq!(connect_broadcast.code(), 0x15);

        // But they should still round-trip correctly
        let back_to_signal: SignalErrorCode = connect_broadcast.into();
        assert_eq!(signal_broadcast, back_to_signal);
    }
}
