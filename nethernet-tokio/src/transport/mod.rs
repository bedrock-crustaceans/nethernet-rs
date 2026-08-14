pub mod listener;
pub mod stream;

pub use listener::NethernetListener;
pub use stream::NethernetStream;

use rand::Rng;

/// Generates the local ICE credentials up front so that gathered candidates can be
/// signaled with the username fragment they were gathered with.
pub(crate) fn generate_ice_credentials() -> (String, String) {
    let mut buf = [0u8; 20];
    rand::rng().fill_bytes(&mut buf);
    (hex::encode(&buf[..4]), hex::encode(&buf[4..]))
}
