//! WebRTC negotiation protocol.
//!
//! This module provides the session descriptions, ICE candidate formats and error
//! codes used while negotiating a connection.

mod candidate;
mod description;
mod error;

pub use candidate::{format_ice_candidate, parse_ice_candidate};
pub use description::Description;
pub use error::ConnectError;
