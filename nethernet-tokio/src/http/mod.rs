//! Async drivers for NetherNet's HTTP signaling (the NetherNet HTTP signaling guide),
//! for both sides of the exchange:
//!
//! - [`client`]: connecting *out* to a partner's NetherNet HTTP endpoint - what the
//!   Minecraft client does.
//! - [`server`]: *hosting* that endpoint, driving
//!   [`nethernet::signaling::http::HttpSignaler`] behind a real HTTP server - what a
//!   partner's server does.
//!
//! These are genuinely different roles over the same protocol, not two views of the
//! same thing - a process might implement either, both, or neither depending on
//! whether it connects out, hosts, or only uses LAN discovery.

pub mod client;
pub mod server;
