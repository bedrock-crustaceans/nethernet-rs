//! Discovery message packet.
//!
//! Sent by both server and client to negotiate a NetherNet connection
//! and exchange ICE candidates.

use super::packet::Packet;
use crate::error::Result;
use crate::protocol::constants::ID_MESSAGE_PACKET;
use crate::protocol::types::{U64LE, read_bytes_u32, write_bytes_u32};
use std::io::{Read, Write};

/// MessagePacket is used for negotiating WebRTC connections.
/// It contains the recipient network ID and signaling data.
#[derive(Debug, Clone, Default)]
pub struct MessagePacket {
    /// Network ID of the recipient (not the connection ID)
    pub recipient_id: u64,
    /// Signaling data (string form of Signal)
    pub data: String,
}

impl MessagePacket {
    /// Create a MessagePacket for sending signaling data to a specific recipient.
    ///
    /// `recipient_id` is the recipient's network ID (not a connection ID).
    /// `data` is the signaling payload as a UTF-8 string (e.g., serialized Signal/ICE info).
    pub fn new(recipient_id: u64, data: String) -> Self {
        Self { recipient_id, data }
    }
}

impl Packet for MessagePacket {
    /// Packet identifier for a MessagePacket.
    fn id(&self) -> u16 {
        ID_MESSAGE_PACKET
    }

    /// Reads packet fields from a reader and populates `recipient_id` and `data`.
    ///
    /// Reads `recipient_id` as a little-endian 64-bit unsigned integer, then reads a
    /// 32-bit length-prefixed byte array and converts it to a UTF-8 `String`.
    /// I/O errors are propagated; invalid UTF-8 is returned as `NethernetError::Other`.
    fn read(&mut self, r: &mut dyn Read) -> Result<()> {
        self.recipient_id = U64LE::read(r)?.0;
        let data_bytes = read_bytes_u32(r)?;
        self.data = String::from_utf8(data_bytes)
            .map_err(|e| crate::error::NethernetError::Other(format!("invalid UTF-8: {}", e)))?;
        Ok(())
    }

    /// Serializes the packet into the wire format and writes it to the provided writer.
    ///
    /// The wire format is: recipient ID as little-endian u64 followed by the data as a
    /// 32-bit length-prefixed byte sequence.
    fn write(&self, w: &mut dyn Write) -> Result<()> {
        U64LE(self.recipient_id).write(w)?;
        write_bytes_u32(w, self.data.as_bytes())?;
        Ok(())
    }

    /// Provide a reference to the packet as a `dyn Any` for downcasting.
    ///
    /// This allows callers to attempt a runtime downcast to the concrete packet type.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
