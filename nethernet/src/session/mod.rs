//! Sans-IO WebRTC session: ICE, DTLS, SCTP and data channels, driven directly rather
//! than through a generic peer connection (see [`crate::protocol::webrtc`]).

mod ice;

pub use ice::IceLayer;
