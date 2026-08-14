//! Tokio-based NetherNet protocol implementation.
//!
//! This crate provides high-level types for creating NetherNet clients and servers using WebRTC:
//! - [`NethernetStream`] for client connections
//! - [`NethernetListener`] for server-side connection acceptance
//! - [`Session`] for WebRTC peer connection management
//! - [`Signaling`] trait and implementations (LAN discovery)

pub mod builders;
pub mod error;
pub mod protocol;
pub mod session;
pub mod signaling;
pub mod transport;

pub use builders::*;
pub use error::{NethernetError, Result};
pub use protocol::packet::discovery::{MessagePacket, RequestPacket, ResponsePacket, ServerData};
pub use protocol::{ConnectError, Message, MessageSegment, NegotiationMessage, Signal, SignalType};
pub use session::Session;
pub use signaling::{Notifier, Signaling};
pub use transport::{NethernetListener, NethernetStream};
