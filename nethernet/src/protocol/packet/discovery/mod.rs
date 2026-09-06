//! LAN discovery module for NetherNet.
//!
//! This module provides encryption, packet handling, and server advertisement
//! for LAN discovery using UDP broadcast on port 7551.
//!
//! # Discovery Flow
//!
//! 1. Client broadcasts [`RequestPacket`] to network
//! 2. Server responds with [`ResponsePacket`] containing [`ServerData`]
//! 3. Both exchange [`MessagePacket`] for WebRTC negotiation
//!
//! All packets are encrypted with AES-ECB and authenticated with HMAC-SHA256.

mod crypto;
mod message;
mod packet;
mod request;
mod response;
mod server_data;

pub use message::MessagePacket;
pub use packet::{Header, Packet, marshal, unmarshal};
pub use request::RequestPacket;
pub use response::ResponsePacket;
pub use server_data::ServerData;
