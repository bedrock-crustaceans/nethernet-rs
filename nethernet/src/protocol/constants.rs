//! Constants for the NetherNet discovery protocol.

/// Default UDP port used for LAN discovery.
/// Servers should listen for RequestPackets on this port.
pub const LAN_DISCOVERY_PORT: u16 = 7551;

/// Packet IDs
pub const ID_REQUEST_PACKET: u16 = 0;
pub const ID_RESPONSE_PACKET: u16 = 1;
pub const ID_MESSAGE_PACKET: u16 = 2;

/// Maximum allowed size for general byte arrays to prevent OOM attacks.
/// 16 MB is a reasonable upper limit for most protocol use cases.
pub const MAX_BYTES: usize = 16 * 1024 * 1024; // 16 MB

/// Maximum size of a single data-channel message fragment.
pub const MAX_MESSAGE_SIZE: usize = 10000;

/// Maximum SCTP message size announced in session descriptions.
pub const SCTP_MAX_MESSAGE_SIZE: u32 = 65536;

/// Interval on which discovery request broadcasts should be (re-)sent.
pub const BROADCAST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Duration after which a peer's last-known address is considered stale.
pub const ADDRESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
