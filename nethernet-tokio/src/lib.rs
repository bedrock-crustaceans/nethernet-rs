//! Tokio driver for the sans-io [`nethernet`] crate: async wrappers over its
//! signaling and connection state machines, driven over real UDP/TCP sockets in
//! background tasks.
//!
//! - [`connection::connect_via_lan`]/[`connection::connect_via_http`] and
//!   [`listener::Listener`] establish and accept peer connections.
//! - [`lan::LanSignaler`] and [`http::server::HttpSignalingServer`]/[`http::client`]
//!   drive the two signaling transports the guide defines.
//! - [`router::SignalRouter`] fans one signaler's incoming signals out to whichever
//!   concurrent connection attempt they belong to.

pub mod connection;
pub mod http;
pub mod lan;
pub mod listener;
pub mod motd;
mod net;
pub mod router;

pub use motd::NethernetMotd;
