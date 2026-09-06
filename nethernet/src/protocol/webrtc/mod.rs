//! Hand-built WebRTC session descriptions and supporting types for NetherNet.
//!
//! NetherNet does not negotiate through a generic WebRTC peer connection: vanilla
//! clients reject the SDP a generic stack produces. These types build and parse the
//! exact minimal SDP shape NetherNet expects by hand, driving the underlying ICE, DTLS
//! and SCTP transports directly.

pub mod candidate;
pub mod certificate;
pub mod description;
pub mod identity;

pub use description::{Description, DtlsRole};
