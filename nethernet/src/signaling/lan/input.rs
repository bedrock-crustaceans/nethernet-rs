use crate::signaling::signal::Signal;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Clone, Debug)]
pub enum LanSignalerInput {
    /// A datagram was received on the LAN discovery socket from `from` at time `now`.
    Packet(Vec<u8>, SocketAddr, Instant),
    /// Send `Signal` to its target network ID, using the last-known address for that peer.
    Signal(Signal, Instant),
    /// Periodic tick, used to drive discovery-request broadcasts and address-table cleanup.
    Tick(Instant),
}
