//! Discovery response packet.
//!
//! Sent by servers in response to a RequestPacket from clients
//! to advertise the world/server information.
use super::packet::Packet;
use crate::error::Result;
use crate::protocol::constants::ID_RESPONSE_PACKET;
use crate::protocol::types::{U32LE, read_bytes_u32};
use std::io::{Read, Write};

/// ResponsePacket is sent by servers to respond to discovery requests.
/// It contains hex-encoded ServerData payload.
#[derive(Debug, Clone, Default)]
pub struct ResponsePacket {
    /// Application-specific data (typically ServerData in Minecraft: Bedrock Edition)
    pub application_data: Vec<u8>,
}

impl ResponsePacket {
    /// Create a ResponsePacket containing the provided application data.
    pub fn new(application_data: Vec<u8>) -> Self {
        Self { application_data }
    }
}

impl Packet for ResponsePacket {
    /// Provides the packet identifier for a discovery response packet.
    fn id(&self) -> u16 {
        ID_RESPONSE_PACKET
    }

    /// Read hex-encoded application data from `r` and store the decoded bytes in `self.application_data`.
    fn read(&mut self, r: &mut dyn Read) -> Result<()> {
        // Read hex-encoded data
        let hex_data = read_bytes_u32(r)?;

        // Decode from hex
        self.application_data = hex::decode(&hex_data)
            .map_err(|e| crate::error::NethernetError::Other(format!("hex decode error: {}", e)))?;

        Ok(())
    }

    /// Writes the packet's application_data as a hex-encoded byte sequence (prefixed with a 32-bit length) to the provided writer.
    fn write(&self, w: &mut dyn Write) -> Result<()> {
        // Encode to hex without intermediate allocation
        let len = self.application_data.len();
        let hex_len = len * 2;

        // Write length prefix (u32)
        // We cast to u32, assuming it fits (checked by MAX_BYTES elsewhere usually, but for discovery it's small)
        U32LE(hex_len as u32).write(w)?;

        // Write hex data in chunks to avoid large allocation
        let mut buf = [0u8; 2048]; // 512 bytes of input -> 1024 bytes of hex
        for chunk in self.application_data.chunks(512) {
            let encoded_len = chunk.len() * 2;
            hex::encode_to_slice(chunk, &mut buf[..encoded_len]).map_err(|e| {
                crate::error::NethernetError::Other(format!("hex encode error: {}", e))
            })?;
            w.write_all(&buf[..encoded_len])?;
        }
        Ok(())
    }

    /// Exposes the receiver as a `dyn Any` so callers can perform runtime downcasting.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
