//! Dispatches signals from a shared signaler to whichever connection attempt they
//! belong to.
//!
//! [`crate::lan::LanSignaler`] and [`crate::http::server::HttpSignalingServer`] each
//! expose a single `recv(&mut self)`, so only one task can ever drain one - but many
//! connection attempts (each with its own `connection_id`) can be in flight over the
//! same signaler at once. [`SignalRouter`] moves the signaler into one background task
//! that owns its one `recv()` loop (and its `send()` calls, via a channel), and lets
//! each attempt register interest in just its own `(network_id, connection_id)`
//! signals, plus a catch-all for signals that don't match any registration (new
//! incoming offers, for a listener to pick up).

use nethernet::signaling::signal::Signal;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A `tokio::sync::Mutex` (not `std::sync::Mutex`) - held across `.recv().await` in
/// [`SignalRouter::recv_unrouted`], so it must not block the executor thread.
type UnroutedRx = tokio::sync::Mutex<mpsc::UnboundedReceiver<UnroutedSignal>>;

/// Anything that can send a [`Signal`] and, exclusively, receive the next one - the
/// shape both [`crate::lan::LanSignaler`] and
/// [`crate::http::server::HttpSignalingServer`] share.
pub trait Signaler: Send + 'static {
    fn send(&self, signal: Signal);
    fn recv(&mut self) -> impl Future<Output = Option<Signal>> + Send;
}

impl Signaler for crate::lan::LanSignaler {
    fn send(&self, signal: Signal) {
        crate::lan::LanSignaler::send(self, signal)
    }

    async fn recv(&mut self) -> Option<Signal> {
        crate::lan::LanSignaler::recv(self).await
    }
}

impl Signaler for crate::http::server::HttpSignalingServer {
    fn send(&self, signal: Signal) {
        crate::http::server::HttpSignalingServer::send(self, signal)
    }

    async fn recv(&mut self) -> Option<Signal> {
        crate::http::server::HttpSignalingServer::recv(self).await
    }
}

type Routes = Arc<Mutex<HashMap<(u64, u64), mpsc::UnboundedSender<Signal>>>>;

/// A signal with no matching route when it arrived: a route for its
/// `(network_id, connection_id)` is created for it atomically (see [`dispatch`]), so
/// nothing sent immediately after it for the same connection (e.g. a trickle-ICE
/// candidate right behind an offer) can slip through unrouted in the gap between
/// receiving this and explicitly registering interest in it.
pub struct UnroutedSignal {
    pub signal: Signal,
    pub route: mpsc::UnboundedReceiver<Signal>,
    pub guard: RouteGuard,
}

/// Owns a signaler's one `recv()`/`send()` pair in a background task and fans its
/// incoming signals out: registered `(network_id, connection_id)` pairs get their own
/// signals; everything else goes to the catch-all receiver.
///
/// Every method takes `&self` (the catch-all receiver is behind an async `Mutex`), so a
/// `SignalRouter` can be shared - typically via `Arc` - across as many concurrently
/// negotiating connection attempts as are in flight, plus (see [`crate::listener`]) a
/// single task looping on [`Self::recv_unrouted`] to pick up new ones.
pub struct SignalRouter {
    send_tx: mpsc::UnboundedSender<Signal>,
    routes: Routes,
    unrouted_rx: UnroutedRx,
    task: JoinHandle<()>,
}

impl SignalRouter {
    pub fn new<S: Signaler>(signaler: S) -> Self {
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let (unrouted_tx, unrouted_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        let task = tokio::spawn(dispatch(
            signaler,
            Arc::clone(&routes),
            send_rx,
            unrouted_tx,
        ));

        Self {
            send_tx,
            routes,
            unrouted_rx: tokio::sync::Mutex::new(unrouted_rx),
            task,
        }
    }

    /// Queues `signal` to be sent over the underlying signaler. Fire-and-forget:
    /// silently dropped if the dispatch task has already stopped.
    pub fn send(&self, signal: Signal) {
        let _ = self.send_tx.send(signal);
    }

    /// Registers interest in signals for `(network_id, connection_id)`, returning a
    /// receiver for them and a guard that removes the route when dropped - so a route
    /// can be handed off to (and outlive) whatever task ends up owning the connection,
    /// without the router itself needing to know when that's done.
    pub fn register(
        &self,
        network_id: u64,
        connection_id: u64,
    ) -> (mpsc::UnboundedReceiver<Signal>, RouteGuard) {
        let (tx, rx) = mpsc::unbounded_channel();
        self.routes
            .lock()
            .unwrap()
            .insert((network_id, connection_id), tx);
        let guard = RouteGuard {
            key: (network_id, connection_id),
            routes: Arc::clone(&self.routes),
        };
        (rx, guard)
    }

    /// Receives the next signal that didn't match any registered
    /// `(network_id, connection_id)` - in practice, a new incoming offer. A route for
    /// that same `(network_id, connection_id)` is created before the signal is handed
    /// back (see [`UnroutedSignal`]), so the caller can immediately start receiving any
    /// follow-up signals for the same connection (e.g. trickled candidates) without a
    /// gap in which they'd be misclassified as unrouted themselves.
    pub async fn recv_unrouted(&self) -> Option<UnroutedSignal> {
        self.unrouted_rx.lock().await.recv().await
    }
}

impl Drop for SignalRouter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Removes its route from the router when dropped. See [`SignalRouter::register`].
pub struct RouteGuard {
    key: (u64, u64),
    routes: Routes,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.routes.lock().unwrap().remove(&self.key);
    }
}

async fn dispatch<S: Signaler>(
    mut signaler: S,
    routes: Routes,
    mut send_rx: mpsc::UnboundedReceiver<Signal>,
    unrouted_tx: mpsc::UnboundedSender<UnroutedSignal>,
) {
    loop {
        tokio::select! {
            biased;

            signal = signaler.recv() => {
                let Some(signal) = signal else { return; };

                let key = (signal.network_id, signal.connection_id);
                let route = routes.lock().unwrap().get(&key).cloned();

                match route {
                    Some(tx) => {
                        let _ = tx.send(signal);
                    }
                    None => {
                        // No one has registered interest in this connection yet - make
                        // the route now, atomically, so a signal sent immediately after
                        // this one (e.g. a trickled candidate right behind an offer)
                        // has somewhere to land the instant it arrives, rather than a
                        // gap in which it too would be classified as unrouted and lost.
                        let (tx, rx) = mpsc::unbounded_channel();
                        routes.lock().unwrap().insert(key, tx);
                        let guard = RouteGuard {
                            key,
                            routes: Arc::clone(&routes),
                        };
                        if unrouted_tx
                            .send(UnroutedSignal { signal, route: rx, guard })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            to_send = send_rx.recv() => {
                match to_send {
                    Some(signal) => signaler.send(signal),
                    // All `SignalRouter` handles (and thus every sender) are gone.
                    None => return,
                }
            }
        }
    }
}
