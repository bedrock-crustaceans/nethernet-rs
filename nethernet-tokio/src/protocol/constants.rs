//! Constants for the NetherNet discovery protocol.

/// Default UDP port used for LAN discovery.
/// Servers should listen for RequestPackets on this port.
pub const LAN_DISCOVERY_PORT: u16 = 7551;

/// Packet IDs
pub const ID_REQUEST_PACKET: u16 = 0;
pub const ID_RESPONSE_PACKET: u16 = 1;
pub const ID_MESSAGE_PACKET: u16 = 2;

/// Maximum message size (in bytes)
pub const MAX_MESSAGE_SIZE: usize = 10000;

/// Maximum allowed size for general byte arrays to prevent OOM attacks.
/// 16 MB is a reasonable upper limit for most protocol use cases.
pub const MAX_BYTES: usize = 16 * 1024 * 1024; // 16 MB

/// Packet header size (in bytes)
/// PacketID (2) + SenderID (8) + Padding (8) = 18 bytes
pub const HEADER_SIZE: usize = 18;

pub const RELIABLE_CHANNEL: &str = "ReliableDataChannel";
pub const UNRELIABLE_CHANNEL: &str = "UnreliableDataChannel";

/// Default capacity for the bounded packet channel in sessions.
/// This prevents unbounded memory growth while allowing for bursts of incoming packets.
pub const DEFAULT_PACKET_CHANNEL_CAPACITY: usize = 1024;
