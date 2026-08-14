use crate::error::{NethernetError, Result};
use crate::protocol::packet::discovery::{
    self, MessagePacket, RequestPacket, ResponsePacket, ServerData,
};
use crate::protocol::{Signal, constants};
use crate::signaling::Signaling;
use futures::Stream;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock as AsyncRwLock, broadcast};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const BROADCAST_INTERVAL: Duration = Duration::from_secs(2);
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(15);

/// Protocol-defined ping token used for keepalive/discovery messages
/// This is the exact wire format expected by the protocol
const PING_TOKEN: &str = "Ping";

/// LAN-based signaling implementation for peer discovery and WebRTC negotiation.
pub struct LanSignaling {
    network_id: u64,
    socket: Arc<UdpSocket>,
    addresses: Arc<AsyncRwLock<HashMap<u64, AddressEntry>>>,
    /// Broadcast sender for fan-out signal distribution to multiple subscribers
    signal_tx: broadcast::Sender<Signal>,
    server_data: Arc<RwLock<Option<ServerData>>>,
    discovered_servers: Arc<AsyncRwLock<HashMap<u64, ServerData>>>,
    cancel_token: CancellationToken,
    background_task: Option<JoinHandle<()>>,
}

struct AddressEntry {
    addr: SocketAddr,
    last_seen: Instant,
}

impl LanSignaling {
    /// Creates and starts a new LanSignaling instance bound to the given address.
    ///
    /// Binds a UDP socket to `bind_addr`, enables broadcast, initializes internal
    /// shared state (address table, discovered servers, optional server pong data),
    /// creates a broadcast channel for outbound signals, and spawns the background
    /// task that handles incoming packets, periodic discovery, and cleanup.
    ///
    /// On success returns a configured `LanSignaling` instance ready to send and
    /// receive LAN signaling messages; on failure returns the underlying I/O or
    /// setup error.
    pub async fn new(network_id: u64, bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.set_broadcast(true)?;

        // Use broadcast channel for fan-out to multiple subscribers
        // Capacity of 100 should be sufficient for signal buffering
        let (signal_tx, _signal_rx) = broadcast::channel(100);

        // If not binding to DEFAULT_PORT, enable broadcast to DEFAULT_PORT
        let broadcast_addr = if bind_addr.port() != constants::LAN_DISCOVERY_PORT {
            Some(SocketAddr::new(
                Ipv4Addr::BROADCAST.into(),
                constants::LAN_DISCOVERY_PORT,
            ))
        } else {
            None
        };

        let cancel_token = CancellationToken::new();

        let socket = Arc::new(socket);
        let addresses = Arc::new(AsyncRwLock::new(HashMap::new()));
        let server_data = Arc::new(RwLock::new(None));
        let discovered_servers = Arc::new(AsyncRwLock::new(HashMap::new()));

        let background_task = Self::start_background_task(
            network_id,
            socket.clone(),
            addresses.clone(),
            signal_tx.clone(),
            server_data.clone(),
            discovered_servers.clone(),
            broadcast_addr,
            cancel_token.clone(),
        );

        let signaling = Self {
            network_id,
            socket,
            addresses,
            signal_tx,
            server_data,
            discovered_servers,
            cancel_token,
            background_task: Some(background_task),
        };

        Ok(signaling)
    }

    /// Gracefully shuts down the LAN signaling instance.
    ///
    /// Cancels the background task and waits for it to complete. This ensures
    /// that all in-flight operations are finished and no packets will be
    /// processed after this method returns.
    ///
    /// Use this method when you need guaranteed cleanup before proceeding,
    /// such as before application shutdown or when transitioning to a different
    /// signaling mechanism.
    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.background_task.take() {
            let _ = task.await;
        }
    }

    /// Returns a snapshot of discovered servers keyed by their network ID.
    ///
    /// Clones and returns the current internal map of discovered `ServerData` entries.
    pub async fn discover(&self) -> HashMap<u64, ServerData> {
        self.discovered_servers.read().await.clone()
    }

    /// Return the last-known socket address for the given network ID, if any.
    pub async fn get_address(&self, network_id: u64) -> Option<SocketAddr> {
        self.addresses
            .read()
            .await
            .get(&network_id)
            .map(|entry| entry.addr)
    }

    /// Spawns a background Tokio task that maintains LAN signaling I/O and state.
    ///
    /// The spawned task receives and handles UDP packets, periodically removes stale peer addresses, optionally issues discovery requests to the provided broadcast address, and exits when `cancel_token` is triggered.
    #[allow(clippy::too_many_arguments)]
    fn start_background_task(
        network_id: u64,
        socket: Arc<UdpSocket>,
        addresses: Arc<AsyncRwLock<HashMap<u64, AddressEntry>>>,
        signal_tx: broadcast::Sender<Signal>,
        server_data: Arc<RwLock<Option<ServerData>>>,
        discovered_servers: Arc<AsyncRwLock<HashMap<u64, ServerData>>>,
        broadcast_addr: Option<SocketAddr>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut interval = tokio::time::interval(BROADCAST_INTERVAL);

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((n, addr)) => {
                                let _ = Self::handle_packet(
                                    &buf[..n],
                                    addr,
                                    network_id,
                                    &addresses,
                                    &signal_tx,
                                    &socket,
                                    &server_data,
                                    &discovered_servers,
                                ).await;
                            }
                            Err(e) => {
                                tracing::debug!("Socket receive error: {}", e);
                                continue;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        Self::cleanup_addresses(&addresses).await;

                        // Send broadcast request if client
                        if let Some(addr) = broadcast_addr {
                            let _ = Self::send_request(&socket, network_id, addr).await;
                        }
                    }
                }
            }
        })
    }

    /// Sends a discovery request packet for the specified network to the given address.
    ///
    /// The function marshals a discovery request for `network_id` and sends it via `socket` to `addr`.
    async fn send_request(socket: &UdpSocket, network_id: u64, addr: SocketAddr) -> Result<()> {
        let request = RequestPacket;
        let data = discovery::marshal(&request, network_id)?;
        socket.send_to(&data, addr).await?;
        tracing::trace!(
            "Broadcast discovery request sent to {} (network_id: {})",
            addr,
            network_id
        );
        Ok(())
    }

    /// Handle an incoming discovery or message packet received over UDP.
    ///
    /// Updates the last-seen address for the packet's sender, ignores packets that originate
    /// from this node, and processes packets by type:
    /// - REQUEST: if local server data is configured, send a discovery response to the requester.
    /// - RESPONSE: parse and store discovered ServerData into the discovered_servers map.
    /// - MESSAGE: ignore ping tokens; if the message is addressed to this node, parse it into
    ///   a Signal and broadcast it via the provided signal channel.
    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        data: &[u8],
        addr: SocketAddr,
        own_network_id: u64,
        addresses: &Arc<AsyncRwLock<HashMap<u64, AddressEntry>>>,
        signal_tx: &broadcast::Sender<Signal>,
        socket: &Arc<UdpSocket>,
        server_data: &Arc<RwLock<Option<ServerData>>>,
        discovered_servers: &Arc<AsyncRwLock<HashMap<u64, ServerData>>>,
    ) -> Result<()> {
        // Unmarshal the encrypted packet
        let (packet, sender_id) = match discovery::unmarshal(data) {
            Ok(result) => {
                tracing::trace!(
                    "Received packet from {} (sender_id: {}, packet_id: {})",
                    addr,
                    result.1,
                    result.0.id()
                );
                result
            }
            Err(e) => {
                tracing::trace!(
                    "Ignoring unrecognized packet from {}: {} (likely from another service)",
                    addr,
                    e
                );
                return Ok(());
            }
        };

        if sender_id == own_network_id {
            tracing::trace!("Ignoring packet from self (network_id: {})", sender_id);
            return Ok(());
        }

        // Update address mapping
        {
            let mut addrs = addresses.write().await;
            addrs.insert(
                sender_id,
                AddressEntry {
                    addr,
                    last_seen: Instant::now(),
                },
            );
        }

        match packet.id() {
            constants::ID_REQUEST_PACKET => {
                tracing::trace!(
                    "Received discovery REQUEST from {} (network_id: {})",
                    addr,
                    sender_id
                );

                // Request packet - send response if we have server data
                let server_data_copy = server_data
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();

                if let Some(data) = server_data_copy.as_ref() {
                    let app_data = data.marshal()?;
                    let response = ResponsePacket::new(app_data);
                    let response_data = discovery::marshal(&response, own_network_id)?;
                    let _ = socket.send_to(&response_data, addr).await;
                } else {
                    tracing::debug!(
                        "No server data configured - cannot respond to discovery request from {}",
                        addr
                    );
                }
            }
            constants::ID_RESPONSE_PACKET => {
                // Response packet - parse and store server data
                let response = packet
                    .as_any()
                    .downcast_ref::<ResponsePacket>()
                    .ok_or_else(|| {
                        NethernetError::Other("failed to downcast ResponsePacket".to_string())
                    })?;

                if let Ok(server_info) = ServerData::unmarshal(&response.application_data) {
                    discovered_servers
                        .write()
                        .await
                        .insert(sender_id, server_info);
                }
            }
            constants::ID_MESSAGE_PACKET => {
                // Message packet - parse signaling data
                let message = packet
                    .as_any()
                    .downcast_ref::<MessagePacket>()
                    .ok_or_else(|| {
                        NethernetError::Other("failed to downcast MessagePacket".to_string())
                    })?;

                // Ignore Ping messages - these are not WebRTC negotiation signals
                // Use protocol-aware check: match exact wire format to avoid false positives
                if message.data == PING_TOKEN {
                    tracing::trace!("Ignoring ping message from network_id: {}", sender_id);
                    return Ok(());
                }

                // Only process WebRTC signals if message is for us
                if message.recipient_id == own_network_id {
                    tracing::debug!(
                        "Received WebRTC signal from network_id: {} (recipient: {})",
                        sender_id,
                        message.recipient_id
                    );
                    if let Ok(signal) = Signal::from_string(&message.data, sender_id.to_string()) {
                        let _ = signal_tx.send(signal);
                    }
                } else {
                    tracing::trace!(
                        "Ignoring message for different recipient (expected: {}, got: {})",
                        own_network_id,
                        message.recipient_id
                    );
                }
            }
            _ => {
                tracing::debug!("Unknown packet type: {}", packet.id());
            }
        }

        Ok(())
    }

    /// Removes peer address entries whose `last_seen` timestamp is older than `ADDRESS_TIMEOUT`.
    ///
    /// This function acquires a write lock on the provided address map and retains only entries
    /// observed within the configured timeout window, mutating the map in place.
    async fn cleanup_addresses(addresses: &Arc<AsyncRwLock<HashMap<u64, AddressEntry>>>) {
        let mut addrs = addresses.write().await;
        addrs.retain(|_, entry| entry.last_seen.elapsed() < ADDRESS_TIMEOUT);
    }
}

impl Drop for LanSignaling {
    /// Cancels the internal background task when the instance is dropped.
    ///
    /// Note: This only signals cancellation but does not wait for the task to complete.
    /// For graceful shutdown, use the [`shutdown()`](Self::shutdown) method instead.
    fn drop(&mut self) {
        self.cancel_token.cancel();
        // Abort the task to ensure it stops as soon as possible
        if let Some(task) = self.background_task.take() {
            task.abort();
        }
    }
}

impl Signaling for LanSignaling {
    /// Sends a signaling message to the peer identified by the signal's `network_id`.
    ///
    /// Looks up the last-known socket address for the target network ID, serializes the signal
    /// into a `MessagePacket`, and transmits it over the internal UDP socket.
    async fn signal(&self, signal: Signal) -> Result<()> {
        let network_id = signal
            .network_id
            .parse::<u64>()
            .map_err(|e| NethernetError::Other(format!("Invalid network ID: {}", e)))?;

        let addr = {
            let addrs = self.addresses.read().await;
            addrs
                .get(&network_id)
                .map(|entry| entry.addr)
                .ok_or_else(|| {
                    NethernetError::Other(format!("Address not found for network {}", network_id))
                })?
        };

        let signal_str = signal.to_string();
        let message = MessagePacket::new(network_id, signal_str);
        let data = discovery::marshal(&message, self.network_id)?;

        self.socket.send_to(&data, addr).await?;
        Ok(())
    }

    /// Create a stream that yields incoming Signals for a new subscriber.
    ///
    /// Each call produces an independent stream that receives all future broadcasted
    /// signals. If the subscriber falls behind, missed signals are skipped and a
    /// warning is emitted; the stream ends if the broadcaster is closed.
    fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue; // Skip lost messages, keep receiving
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    /// Returns the local network identifier as a decimal string.
    fn network_id(&self) -> String {
        self.network_id.to_string()
    }

    /// Update the stored server "pong" data from marshalled bytes.
    fn set_pong_data(&self, data: Vec<u8>) {
        *self.server_data.write().unwrap_or_else(|e| e.into_inner()) =
            ServerData::unmarshal(&data).ok();
    }
}
