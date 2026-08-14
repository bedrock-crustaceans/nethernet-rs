//! Discovery packet trait and marshaling/unmarshaling utilities.

use super::crypto::{compute_checksum, decrypt, encrypt, verify_checksum};
use super::{MessagePacket, RequestPacket, ResponsePacket};
use crate::error::{NethernetError, Result};
use crate::protocol::constants::{ID_MESSAGE_PACKET, ID_REQUEST_PACKET, ID_RESPONSE_PACKET};
use crate::protocol::types::{U16LE, U64LE};
use std::io::{Cursor, Read, Write};

/// Trait for discovery packets used in LAN discovery.
pub trait Packet: Send + Sync {
    /// Returns the unique ID of the packet.
    fn id(&self) -> u16;

    /// Reads/decodes the packet data from the reader.
    fn read(&mut self, r: &mut dyn Read) -> Result<()>;

    /// Writes the packet data into the writer.
    fn write(&self, w: &mut dyn Write) -> Result<()>;

    /// Allows downcasting to concrete packet types.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Header of a discovery packet.
#[derive(Debug, Clone)]
pub struct Header {
    /// Packet ID
    pub packet_id: u16,
    /// Sender network ID
    pub sender_id: u64,
}

impl Header {
    /// Reads a discovery packet header from the provided reader.
    ///
    /// This reads a 16-bit little-endian packet ID, a 64-bit little-endian sender ID,
    /// then consumes and discards 8 bytes of padding.
    pub fn read(r: &mut dyn Read) -> Result<Self> {
        let packet_id = U16LE::read(r)?.0;
        let sender_id = U64LE::read(r)?.0;

        // Discard 8-byte padding
        let mut padding = [0u8; 8];
        r.read_exact(&mut padding)?;

        Ok(Self {
            packet_id,
            sender_id,
        })
    }

    /// Serialize the header into the provided writer using little-endian encoding and fixed padding.
    pub fn write(&self, w: &mut dyn Write) -> Result<()> {
        U16LE(self.packet_id).write(w)?;
        U64LE(self.sender_id).write(w)?;
        // 8-byte padding
        w.write_all(&[0u8; 8])?;
        Ok(())
    }
}

/// Encodes a discovery packet together with a sender ID into the wire format.
///
/// The output is: a 32-byte HMAC-SHA256 checksum followed by the AES-ECB encrypted payload.
/// The encrypted payload contains a 16-bit length prefix, the packet header (packet ID and sender ID),
/// 8 bytes of padding, and the packet-specific data.
/// Returns an error if the encoded packet exceeds 65,535 bytes or if any underlying write/encryption step fails.
///
/// # Returns
///
/// A [`Vec<u8>`] containing the serialized packet: the 32-byte HMAC-SHA256 checksum followed by the AES-ECB encrypted payload.
pub fn marshal(packet: &dyn Packet, sender_id: u64) -> Result<Vec<u8>> {
    // Discovery packets are generally small (header 18 bytes + length 2 bytes + packet data)
    // We pre-allocate enough space for checksum (32), length (2), header (18), packet data, and potential padding (up to 16)
    let mut buf = Vec::with_capacity(32 + 2 + 18 + 64 + 16);

    // Placeholder for HMAC-SHA256 checksum (32 bytes)
    buf.extend_from_slice(&[0u8; 32]);

    // Placeholder for length (U16LE)
    buf.extend_from_slice(&[0u8; 2]);

    // Write header directly into buffer
    let header = Header {
        packet_id: packet.id(),
        sender_id,
    };
    header.write(&mut buf)?;

    // Write packet data directly into buffer
    packet.write(&mut buf)?;

    // Fill the actual length
    let total_len = buf.len();
    if total_len - 32 > u16::MAX as usize {
        return Err(NethernetError::MessageTooLarge(total_len - 32));
    }

    let data_len = (total_len - 32 - 2) as u16;
    buf[32..34].copy_from_slice(&data_len.to_le_bytes());

    // Compute HMAC-SHA256 checksum of the payload (everything after the 32-byte checksum placeholder)
    let checksum = compute_checksum(&buf[32..]);
    buf[..32].copy_from_slice(&checksum);

    // Encrypt the payload in-place
    // We need to extract the payload part to a temporary Vec or manage it carefully.
    // Since encrypt() now takes &mut Vec<u8>, we can't easily pass a slice of it.
    // However, we want to avoid double allocation.

    // Let's modify encrypt slightly to take a slice or just handle the Vec here.
    // Actually, the easiest way to achieve "zero copy" (or close to it) with the current API
    // is to split the buffer or use a temporary Vec for the payload part then join.
    // But the user asked for struct -> Vec -> encrypt -> Vec transition.

    let mut payload = buf.split_off(32);
    encrypt(&mut payload)?;

    buf.extend_from_slice(&payload);

    Ok(buf)
}

/// Decodes and verifies a discovery packet from raw bytes, returning the parsed packet and its sender ID.
///
/// The function expects the input to be a checksum (32 bytes) followed by an AES-ECB encrypted payload. It
/// decrypts the payload, verifies the HMAC-SHA256 checksum against the plaintext, reads the payload length and
/// header, instantiates the concrete packet type based on the header's packet ID, and delegates parsing of the
/// packet-specific fields to that packet's `read` implementation. Errors are returned for malformed data,
/// checksum mismatches, oversized/unknown packet IDs, or trailing bytes after parsing.
///
/// # Returns
///
/// A tuple containing the boxed concrete packet and the sender's 64-bit network ID.
pub fn unmarshal(data: &[u8]) -> Result<(Box<dyn Packet>, u64)> {
    if data.len() < 32 {
        return Err(NethernetError::Other("packet too short".to_string()));
    }

    // Extract checksum and encrypted payload
    let checksum: [u8; 32] = data[..32].try_into().unwrap();

    // Copy only the encrypted part into a Vec for in-place decryption
    let mut payload = data[32..].to_vec();
    decrypt(&mut payload)?;

    // Verify checksum against decrypted payload
    if !verify_checksum(&payload, &checksum) {
        return Err(NethernetError::Other("checksum mismatch".to_string()));
    }

    let mut cursor = Cursor::new(payload);

    // Read length (2 bytes)
    let _length = U16LE::read(&mut cursor)?;

    // Read header
    let header = Header::read(&mut cursor)?;

    // Create appropriate packet based on ID
    let mut packet: Box<dyn Packet> = match header.packet_id {
        ID_REQUEST_PACKET => Box::new(RequestPacket),
        ID_RESPONSE_PACKET => Box::new(ResponsePacket::default()),
        ID_MESSAGE_PACKET => Box::new(MessagePacket::default()),
        _ => {
            return Err(NethernetError::Other(format!(
                "unknown packet ID: {}",
                header.packet_id
            )));
        }
    };

    // Read packet data
    packet.read(&mut cursor)?;

    // Validate that cursor has been fully consumed
    let cursor_position = cursor.position() as usize;
    let payload_len = cursor.get_ref().len();
    if cursor_position < payload_len {
        let remaining = payload_len - cursor_position;
        return Err(NethernetError::Other(format!(
            "trailing data in packet: {} remaining bytes out of {} total payload bytes",
            remaining, payload_len
        )));
    }

    Ok((packet, header.sender_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header {
            packet_id: 0x01,
            sender_id: 0x1234567890abcdef,
        };

        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = Header::read(&mut cursor).unwrap();

        assert_eq!(header.packet_id, decoded.packet_id);
        assert_eq!(header.sender_id, decoded.sender_id);
    }
}
