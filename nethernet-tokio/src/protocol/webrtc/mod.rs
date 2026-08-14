//! WebRTC negotiation protocol.
//!
//! This module provides WebRTC connection negotiation messages and error handling.

mod candidate;
mod description;
mod error;
mod negotiation;

pub use candidate::{format_ice_candidate, parse_ice_candidate};
pub use description::Description;
pub use error::ConnectError;
pub use negotiation::NegotiationMessage;
