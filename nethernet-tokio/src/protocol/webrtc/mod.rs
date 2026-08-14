//! WebRTC negotiation protocol.
//!
//! This module provides WebRTC connection negotiation messages and error handling.

mod error;
mod negotiation;

pub use error::ConnectError;
pub use negotiation::NegotiationMessage;
