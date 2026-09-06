//! Sans-IO WebRTC session: ICE, DTLS, SCTP and data channels, driven directly rather
//! than through a generic peer connection (see [`crate::protocol::webrtc`]).

mod dtls;
mod ice;
mod sctp;

pub use dtls::{DtlsLayer, ResolvedRole as DtlsResolvedRole};
pub use ice::IceLayer;
pub use sctp::SctpLayer;
