//! DCEP ([RFC 8832]) data-channel open/ack, hand-rolled over a raw SCTP stream.
//!
//! `rtc::datachannel` provides only the message codec, not a channel-open driver (that
//! convenience lives inside `rtc`'s full `RTCPeerConnection`, which NetherNet bypasses),
//! so the small open/ack handshake is implemented directly here.
//!
//! [RFC 8832]: https://datatracker.ietf.org/doc/html/rfc8832

use crate::protocol::error::{ProtocolError, Result};
use rtc::datachannel::message::Message;
use rtc::datachannel::message::message_channel_ack::DataChannelAck;
use rtc::datachannel::message::message_channel_open::{
    CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
};
use rtc::sctp::PayloadProtocolIdentifier;
use rtc::shared::marshal::{Marshal, Unmarshal};

/// The channel names NetherNet always opens, per the HTTP signaling guide section 6.
pub const RELIABLE_CHANNEL_LABEL: &str = "ReliableDataChannel";
pub const UNRELIABLE_CHANNEL_LABEL: &str = "UnreliableDataChannel";

/// The SCTP payload protocol identifier for DCEP control messages (`DATA_CHANNEL_OPEN`/
/// `DATA_CHANNEL_ACK`), as opposed to `Binary`/`String` for the channel's own data.
pub const PPI_DCEP: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Dcep;

/// Builds the `DATA_CHANNEL_OPEN` message for the reliable, ordered channel (the SCTP
/// default reliability).
pub fn reliable_open() -> DataChannelOpen {
    DataChannelOpen {
        channel_type: ChannelType::Reliable,
        priority: CHANNEL_PRIORITY_NORMAL,
        reliability_parameter: 0,
        label: RELIABLE_CHANNEL_LABEL.as_bytes().to_vec(),
        protocol: Vec::new(),
    }
}

/// Builds the `DATA_CHANNEL_OPEN` message for the unreliable, unordered channel
/// (`maxRetransmits: 0`, i.e. no retransmission at all).
pub fn unreliable_open() -> DataChannelOpen {
    DataChannelOpen {
        channel_type: ChannelType::PartialReliableRexmitUnordered,
        priority: CHANNEL_PRIORITY_NORMAL,
        reliability_parameter: 0,
        label: UNRELIABLE_CHANNEL_LABEL.as_bytes().to_vec(),
        protocol: Vec::new(),
    }
}

/// Encodes a `DATA_CHANNEL_OPEN` message to bytes ready to write to an SCTP stream
/// (with [`PPI_DCEP`]).
pub fn encode_open(open: DataChannelOpen) -> Result<Vec<u8>> {
    Message::DataChannelOpen(open)
        .marshal()
        .map(|b| b.to_vec())
        .map_err(|e| ProtocolError::Other(format!("encode DATA_CHANNEL_OPEN: {e}")))
}

/// Encodes a `DATA_CHANNEL_ACK` message to bytes ready to write to an SCTP stream
/// (with [`PPI_DCEP`]).
pub fn encode_ack() -> Result<Vec<u8>> {
    Message::DataChannelAck(DataChannelAck)
        .marshal()
        .map(|b| b.to_vec())
        .map_err(|e| ProtocolError::Other(format!("encode DATA_CHANNEL_ACK: {e}")))
}

/// Decodes a DCEP control message read from a stream (PPI [`PPI_DCEP`]).
pub fn decode(mut data: &[u8]) -> Result<Message> {
    Message::unmarshal(&mut data).map_err(|e| ProtocolError::Other(format!("decode DCEP: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliable_open_roundtrip() {
        let encoded = encode_open(reliable_open()).unwrap();
        let Message::DataChannelOpen(open) = decode(&encoded).unwrap() else {
            panic!("expected DataChannelOpen");
        };
        assert_eq!(open.channel_type, ChannelType::Reliable);
        assert_eq!(open.label, RELIABLE_CHANNEL_LABEL.as_bytes());
    }

    #[test]
    fn unreliable_open_roundtrip() {
        let encoded = encode_open(unreliable_open()).unwrap();
        let Message::DataChannelOpen(open) = decode(&encoded).unwrap() else {
            panic!("expected DataChannelOpen");
        };
        assert_eq!(
            open.channel_type,
            ChannelType::PartialReliableRexmitUnordered
        );
        assert_eq!(open.reliability_parameter, 0);
        assert_eq!(open.label, UNRELIABLE_CHANNEL_LABEL.as_bytes());
    }

    #[test]
    fn ack_roundtrip() {
        let encoded = encode_ack().unwrap();
        assert!(matches!(
            decode(&encoded).unwrap(),
            Message::DataChannelAck(_)
        ));
    }
}
