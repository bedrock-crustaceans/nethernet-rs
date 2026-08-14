use crate::error::Result;
use crate::protocol::Signal;
use futures::Stream;
use std::pin::Pin;

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

    /// Sets pong data (for LAN discovery)
    fn set_pong_data(&self, data: Vec<u8>);
}

/// Notifier trait - for signal and error notifications
pub trait Notifier: Send + Sync {
    /// Notifies a new signal
    fn notify_signal(&self, signal: Signal);

    /// Notifies an error
    fn notify_error(&self, error: crate::error::NethernetError);
}
