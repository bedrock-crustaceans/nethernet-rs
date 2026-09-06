//! Continuously accepting incoming NetherNet peer connections signaled over LAN/UDP
//! discovery (trickle ICE).

use crate::connection::{ConnectError, Connection, accept_via_lan};
use crate::router::SignalRouter;
use nethernet::signaling::signal::SignalType;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Accepts a continuous stream of incoming NetherNet connections signaled over a
/// [`SignalRouter`] wrapping [`crate::lan::LanSignaler`] - the accept-side counterpart
/// to [`crate::connection::connect_via_lan`].
///
/// Every incoming offer is accepted concurrently as soon as it's seen (each on its own
/// freshly bound UDP socket at `bind_addr`), so a slow or stalled negotiation on one
/// connection attempt never blocks discovering, or completing, the next.
///
/// Dropping this stops accepting new connections; connections already handed back by
/// [`Self::accept`] are unaffected.
pub struct Listener {
    connection_rx: mpsc::UnboundedReceiver<Result<Connection, ConnectError>>,
    task: JoinHandle<()>,
}

impl Listener {
    /// Starts accepting connections signaled over `router`, binding a fresh UDP socket
    /// at `bind_addr` (typically an ephemeral port, i.e. port 0) for each one.
    pub fn new(router: SignalRouter, bind_addr: SocketAddr) -> Self {
        let router = Arc::new(router);
        let (connection_tx, connection_rx) = mpsc::unbounded_channel();

        let task = tokio::spawn(async move {
            loop {
                let Some(unrouted) = router.recv_unrouted().await else {
                    return;
                };
                if unrouted.signal.signal_type != SignalType::Offer {
                    // Anything else reaching the catch-all is a signal for a
                    // connection this listener already finished accepting (and thus
                    // dropped the route for) - nothing to do with it.
                    continue;
                }

                let router = Arc::clone(&router);
                let connection_tx = connection_tx.clone();
                tokio::spawn(async move {
                    let result = accept_via_lan(&router, bind_addr, unrouted).await;
                    let _ = connection_tx.send(result);
                });
            }
        });

        Self {
            connection_rx,
            task,
        }
    }

    /// Waits for the next incoming connection to finish negotiating (or fail to).
    /// Returns `None` once the underlying signaler has stopped.
    pub async fn accept(&mut self) -> Option<Result<Connection, ConnectError>> {
        self.connection_rx.recv().await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::LanSignaler;
    use bytes::Bytes;
    use nethernet::protocol::packet::discovery::ServerData;
    use nethernet::session::Channel;
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    async fn drive_to_ready(a: &mut Connection, b: &mut Connection) {
        let (mut a_ready, mut b_ready) = (false, false);
        while !(a_ready && b_ready) {
            tokio::select! {
                Some(event) = a.recv() => {
                    if matches!(event, crate::connection::ConnectionEvent::Ready) { a_ready = true; }
                }
                Some(event) = b.recv() => {
                    if matches!(event, crate::connection::ConnectionEvent::Ready) { b_ready = true; }
                }
            }
        }
    }

    /// Two separate connection attempts, offered back to back at the same listener,
    /// both complete and exchange a message - the listener doesn't serialize accepts
    /// behind one another, and the router's routes don't cross-talk between them.
    #[tokio::test]
    async fn accepts_multiple_connections_concurrently() {
        let host_signaling = LanSignaler::bind(loopback(0), 1, false).await.unwrap();
        // A discovery request only gets a response (which is how the requester learns
        // the host's address) once the host has server data to answer with - without
        // this, `discover()` below would be a one-way probe the host silently drops.
        host_signaling.set_server_data(Some(ServerData::new(
            "host".to_string(),
            "world".to_string(),
        )));
        let host_addr = host_signaling.local_addr();
        let mut listener = Listener::new(SignalRouter::new(host_signaling), loopback(0));

        let connect_one = |connection_id: u64| async move {
            let guest_signaling = LanSignaler::bind(loopback(0), connection_id + 1, true)
                .await
                .unwrap();
            guest_signaling.discover(host_addr);
            tokio::time::sleep(StdDuration::from_millis(100)).await;
            let router = SignalRouter::new(guest_signaling);
            crate::connection::connect_via_lan(&router, loopback(0), connection_id, 1)
                .await
                .unwrap()
        };

        let (mut guest_a, mut guest_b) = tokio::join!(connect_one(1), connect_one(2));

        let mut host_a = tokio::time::timeout(StdDuration::from_secs(5), listener.accept())
            .await
            .expect("listener never accepted the first connection")
            .unwrap()
            .unwrap();
        let mut host_b = tokio::time::timeout(StdDuration::from_secs(5), listener.accept())
            .await
            .expect("listener never accepted the second connection")
            .unwrap()
            .unwrap();

        // Which host connection matches which guest isn't guaranteed by arrival order,
        // so just get everything to `Ready` and exchange a message on each pairing by
        // connection identity instead of assuming host_a pairs with guest_a.
        tokio::time::timeout(StdDuration::from_secs(15), async {
            tokio::join!(
                drive_to_ready(&mut host_a, &mut guest_a),
                drive_to_ready(&mut host_b, &mut guest_b),
            )
        })
        .await
        .expect("connections never became ready");

        guest_a.send(Channel::Reliable, Bytes::from_static(b"from a"));
        guest_b.send(Channel::Reliable, Bytes::from_static(b"from b"));

        // host_a/host_b are freshly bound sockets with no fixed correspondence to
        // guest_a/guest_b beyond having exchanged a handshake with one of them - collect
        // both received messages and check the *set*, not per-index equality.
        let (msg_1, msg_2) = tokio::time::timeout(StdDuration::from_secs(5), async {
            let a = async {
                loop {
                    if let Some(crate::connection::ConnectionEvent::Message(_, data)) =
                        host_a.recv().await
                    {
                        return data;
                    }
                }
            };
            let b = async {
                loop {
                    if let Some(crate::connection::ConnectionEvent::Message(_, data)) =
                        host_b.recv().await
                    {
                        return data;
                    }
                }
            };
            tokio::join!(a, b)
        })
        .await
        .expect("host connections never received their messages");

        let mut messages = vec![msg_1, msg_2];
        messages.sort();
        assert_eq!(messages, vec![b"from a".to_vec(), b"from b".to_vec()]);
    }
}
