//! Async driver for [`nethernet::signaling::lan::LanSignaler`]: binds a UDP socket for
//! LAN discovery and drives the sans-io signaler over it in the background.

use crate::net::{self, UdpDriven, UdpDrivenOutput};
use nethernet::protocol::constants::BROADCAST_INTERVAL;
use nethernet::protocol::packet::discovery::{self, RequestPacket, ServerData};
use nethernet::sans::Sans;
use nethernet::signaling::lan::LanSignaler as SansLanSignaler;
use nethernet::signaling::lan::error::LanSignalerError;
use nethernet::signaling::lan::input::LanSignalerInput;
use nethernet::signaling::lan::output::LanSignalerOutput;
use nethernet::signaling::signal::Signal;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

enum Command {
    Signal(Signal),
    SetServerData(Option<ServerData>),
    Discover(SocketAddr),
    GetDiscovered(oneshot::Sender<HashMap<u64, ServerData>>),
}

struct Adapter {
    inner: SansLanSignaler,
    network_id: u64,
    /// Datagrams queued directly by this adapter (currently just `Command::Discover`
    /// probes) rather than by the wrapped sans-io signaler itself - checked by
    /// [`Adapter::poll`] before the signaler's own queue.
    extra_sends: VecDeque<(Vec<u8>, SocketAddr)>,
}

impl UdpDriven for Adapter {
    type Output = Signal;
    type Command = Command;
    type Error = LanSignalerError;

    fn handle_packet(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), Self::Error> {
        self.inner
            .handle(LanSignalerInput::Packet(data.to_vec(), from, now))
    }

    fn handle_command(&mut self, command: Command, now: Instant) -> Result<(), Self::Error> {
        match command {
            Command::Signal(signal) => self.inner.handle(LanSignalerInput::Signal(signal, now)),
            Command::SetServerData(data) => {
                self.inner.set_server_data(data);
                Ok(())
            }
            Command::Discover(addr) => {
                if let Ok(data) = discovery::marshal(&RequestPacket, self.network_id) {
                    self.extra_sends.push_back((data, addr));
                }
                Ok(())
            }
            Command::GetDiscovered(reply) => {
                let _ = reply.send(self.inner.discovered().clone());
                Ok(())
            }
        }
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.inner.handle(LanSignalerInput::Tick(now))
    }

    fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        // The sans-io signaler doesn't track its own wakeup time - it just no-ops a
        // `Tick` that arrives before `BROADCAST_INTERVAL` has elapsed - so ticking on a
        // fixed cadence is both correct and simple.
        Some(now + BROADCAST_INTERVAL)
    }

    fn poll(&mut self) -> Option<UdpDrivenOutput<Signal>> {
        if let Some((data, to)) = self.extra_sends.pop_front() {
            return Some(UdpDrivenOutput::Send(data, to));
        }

        match Sans::poll(&mut self.inner)? {
            LanSignalerOutput::Send(data, to) => Some(UdpDrivenOutput::Send(data, to)),
            LanSignalerOutput::Signal(signal) => Some(UdpDrivenOutput::Output(signal)),
        }
    }
}

/// A LAN discovery signaler bound to a real UDP socket, driving
/// [`nethernet::signaling::lan::LanSignaler`] in a background task.
///
/// Dropping this stops the background task. [`Self::send`]/[`Self::set_server_data`]/
/// [`Self::discover`] take `&self`, so a caller wanting to share one across tasks can
/// wrap it in an `Arc` (only [`Self::recv`] needs exclusive access).
pub struct LanSignaler {
    local_addr: SocketAddr,
    command_tx: mpsc::UnboundedSender<Command>,
    signal_rx: mpsc::UnboundedReceiver<Signal>,
    task: JoinHandle<()>,
}

impl LanSignaler {
    /// Binds a UDP socket at `bind_addr` (enabling broadcast) and starts driving LAN
    /// discovery signaling for `network_id` in the background. `broadcast` matches
    /// [`nethernet::signaling::lan::LanSignaler::new`]: whether to periodically
    /// broadcast discovery requests (client behavior) - a pure server that only
    /// answers requests can leave this off.
    pub async fn bind(
        bind_addr: SocketAddr,
        network_id: u64,
        broadcast: bool,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.set_broadcast(true)?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();

        let adapter = Adapter {
            inner: SansLanSignaler::new(network_id, broadcast),
            network_id,
            extra_sends: VecDeque::new(),
        };
        let task = tokio::spawn(net::run(socket, adapter, command_rx, signal_tx));

        Ok(Self {
            local_addr,
            command_tx,
            signal_rx,
            task,
        })
    }

    /// The address this signaler's socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Queues `signal` to be sent to whichever peer its `network_id` last signaled
    /// from (see the sans-io signaler's address table). Fire-and-forget: silently
    /// dropped if the background task has already stopped.
    pub fn send(&self, signal: Signal) {
        let _ = self.command_tx.send(Command::Signal(signal));
    }

    /// Sets (or clears) the local server "pong" data advertised to discovery requests.
    pub fn set_server_data(&self, data: Option<ServerData>) {
        let _ = self.command_tx.send(Command::SetServerData(data));
    }

    /// Sends a one-off discovery request directly to `addr`, rather than waiting for
    /// (or in addition to) the periodic subnet broadcast - useful when broadcast
    /// doesn't reach the target (a known IP behind NAT/routing that doesn't forward
    /// broadcast, containerized environments, etc.) or to probe a specific address
    /// without waiting for the next broadcast tick.
    pub fn discover(&self, addr: SocketAddr) {
        let _ = self.command_tx.send(Command::Discover(addr));
    }

    /// Returns a snapshot of every server discovered so far (i.e. that has responded to
    /// a discovery request with its own server data), keyed by network ID. Returns an
    /// empty map if the background task has already stopped.
    pub async fn discovered(&self) -> HashMap<u64, ServerData> {
        let (tx, rx) = oneshot::channel();
        if self.command_tx.send(Command::GetDiscovered(tx)).is_err() {
            return HashMap::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Receives the next signal from a remote peer. Returns `None` once the
    /// background task has stopped.
    pub async fn recv(&mut self) -> Option<Signal> {
        self.signal_rx.recv().await
    }
}

impl Drop for LanSignaler {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port)
    }

    /// Two signalers on loopback, seeded via a direct (non-broadcast) discovery probe,
    /// exchange a signal in both directions over real sockets and a real background
    /// task each.
    #[tokio::test]
    async fn signals_flow_between_two_bound_signalers() {
        let mut a = LanSignaler::bind(loopback(0), 1, false).await.unwrap();
        let mut b = LanSignaler::bind(loopback(0), 2, false).await.unwrap();

        // Seed each side's address table with the other's real bound address, without
        // depending on OS/network broadcast semantics: a direct discovery request/
        // response round trip in each direction achieves the same thing `Tick`-driven
        // broadcast would, deterministically.
        a.discover(b.local_addr());
        b.discover(a.local_addr());

        // Give the background tasks a moment to exchange the probes.
        tokio::time::sleep(Duration::from_millis(100)).await;

        a.send(Signal::offer(42, "offer-sdp".to_string(), 2));
        let received = tokio::time::timeout(Duration::from_secs(5), b.recv())
            .await
            .expect("b never received a's signal")
            .unwrap();
        assert_eq!(received.data, "offer-sdp");
        assert_eq!(received.network_id, 1);

        b.send(Signal::answer(42, "answer-sdp".to_string(), 1));
        let received = tokio::time::timeout(Duration::from_secs(5), a.recv())
            .await
            .expect("a never received b's signal")
            .unwrap();
        assert_eq!(received.data, "answer-sdp");
        assert_eq!(received.network_id, 2);
    }
}
