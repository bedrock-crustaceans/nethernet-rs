use crate::signaling::signal::Signal;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub enum LanSignalerOutput {
    /// A datagram that the driver must send over the LAN discovery socket.
    Send(Vec<u8>, SocketAddr),
    /// A signal received from a remote peer, ready to be handed to the session layer.
    Signal(Signal),
}
