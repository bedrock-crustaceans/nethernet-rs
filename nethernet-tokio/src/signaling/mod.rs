use crate::credentials::Credentials;
use crate::error::Result;
use crate::protocol::Signal;
use futures::Stream;
use std::pin::Pin;

pub mod http;
pub mod lan;

/// Signaling trait for WebRTC signaling
/// Abstract interface for WebRTC signaling
pub trait Signaling: Send + Sync {
    /// Sends a signal
    fn signal(&self, signal: Signal) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Returns the signal stream
    fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>>;

    /// Returns the local network ID
    fn network_id(&self) -> String;

    /// Reports whether candidates must be embedded in the session description instead
    /// of being signaled separately.
    ///
    /// Signaling implementations that cannot deliver candidates after the description,
    /// such as the HTTP endpoints of dedicated servers, return `true`.
    fn disable_trickle_ice(&self) -> bool {
        false
    }

    /// Returns the credentials of the ICE servers to gather candidates from.
    ///
    /// Signaling implementations that do not provide credentials, such as LAN discovery,
    /// return [`None`] and only gather host candidates.
    fn credentials(&self) -> impl std::future::Future<Output = Result<Option<Credentials>>> + Send {
        async { Ok(None) }
    }

    /// Sets the server data advertised to clients from a RakNet pong response.
    ///
    /// The pong is the `;` separated response Minecraft listeners send to unconnected
    /// pings, which is parsed into the server data of LAN discovery responses.
    fn set_pong_data(&self, data: &[u8]);
}
