use crate::error::{NethernetError, Result};
use crate::protocol::constants::DEFAULT_PACKET_CHANNEL_CAPACITY;
use crate::protocol::{Message, MessageSegment};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::RTCPeerConnection;

/// WebRTC session manager
pub struct Session {
    peer_connection: Arc<RTCPeerConnection>,
    reliable_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    unreliable_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    message_buffer: Arc<Mutex<Message>>,
    packet_tx: mpsc::Sender<Bytes>,
    packet_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    closed: Arc<RwLock<bool>>,
}

impl Session {
    /// Creates a Session using the default packet channel capacity.
    pub fn new(peer_connection: Arc<RTCPeerConnection>) -> Self {
        Self::with_capacity(peer_connection, DEFAULT_PACKET_CHANNEL_CAPACITY)
    }

    /// Creates a Session backed by the given RTCPeerConnection and a bounded packet channel with the specified capacity.
    pub fn with_capacity(peer_connection: Arc<RTCPeerConnection>, capacity: usize) -> Self {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);

        Self {
            peer_connection,
            reliable_channel: Arc::new(Mutex::new(None)),
            unreliable_channel: Arc::new(Mutex::new(None)),
            message_buffer: Arc::new(Mutex::new(Message::new())),
            packet_tx,
            packet_rx: Arc::new(Mutex::new(packet_rx)),
            closed: Arc::new(RwLock::new(false)),
        }
    }

    /// Attaches a reliable RTCDataChannel to the session and route incoming message segments into the session's reassembly pipeline.
    ///
    /// The provided channel will receive an `on_message` handler that decodes incoming bytes as `MessageSegment`s, accumulates segments in the session's internal buffer, and forwards completed messages to the session's packet receiver. The channel is then stored as the session's reliable data channel.
    pub async fn set_reliable_channel(&self, channel: Arc<RTCDataChannel>) -> Result<()> {
        let message_buffer = self.message_buffer.clone();
        let packet_tx = self.packet_tx.clone();

        channel.on_message(Box::new(move |msg| {
            let data = msg.data.clone();
            let buffer = message_buffer.clone();
            let tx = packet_tx.clone();

            Box::pin(async move {
                let data_len = data.len();
                match MessageSegment::decode(data.clone()) {
                    Ok(segment) => {
                        let result = {
                            let mut buf = buffer.lock().await;
                            buf.add_segment(segment)
                        };
                        match result {
                            Ok(Some(complete_msg)) => {
                                // Use async send to handle backpressure with bounded channel
                                // If send fails, it means the receiver has been dropped
                                let _ = tx.send(complete_msg).await;
                            }
                            Ok(None) => {
                                tracing::debug!("incomplete segment added to buffer, waiting for more segments");
                            }
                            Err(e) => {
                                tracing::warn!("failed to add segment to buffer: {:?}, data length: {}", e, data_len);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "failed to decode message segment: {:?}, data length: {}, data preview: {:?}",
                            e,
                            data_len,
                            &data.as_ref()[..data_len.min(64)]
                        );
                    }
                }
            })
        }));

        *self.reliable_channel.lock().await = Some(channel);
        Ok(())
    }

    /// Attaches an unreliable RTC data channel to the session.
    ///
    /// Replaces any previously set unreliable data channel with the provided one.
    pub async fn set_unreliable_channel(&self, channel: Arc<RTCDataChannel>) -> Result<()> {
        *self.unreliable_channel.lock().await = Some(channel);
        Ok(())
    }

    /// Sends data over the session using the reliable data channel, splitting the payload into protocol segments as needed.
    ///
    /// # Errors
    ///
    /// - Returns `NethernetError::ConnectionClosed` if the session has been closed.
    /// - Returns `NethernetError::DataChannel(...)` if the reliable channel is not set or if sending a segment fails.
    /// - Returns any error produced by `Message::split_into_segments` when segmenting the input.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        if *self.closed.read().await {
            return Err(NethernetError::ConnectionClosed);
        }

        let channel = {
            let guard = self.reliable_channel.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| NethernetError::DataChannel("Reliable channel not set".to_string()))?
                .clone()
        };

        let segments = Message::split_into_segments(data)?;
        for segment in segments {
            let encoded = segment.encode();
            channel
                .send(&encoded)
                .await
                .map_err(|e| NethernetError::DataChannel(e.to_string()))?;
        }

        Ok(())
    }

    /// Receives the next complete packet from the session.
    ///
    /// This returns the next reassembled message produced by the session's incoming
    /// segment stream. If the session has been closed, or the underlying packet
    /// channel has been closed, this returns `Ok(None)`.
    pub async fn recv(&self) -> Result<Option<Bytes>> {
        if *self.closed.read().await {
            return Ok(None);
        }

        // Lock and receive - the lock is automatically released when MutexGuard
        // goes out of scope at the end of this expression, even if cancelled
        Ok(self.packet_rx.lock().await.recv().await)
    }

    /// Shuts down the session by marking it closed and closing any attached data channels and the peer connection.
    ///
    /// After this call the session is considered closed; calling `close` again is a no-op.
    pub async fn close(&self) -> Result<()> {
        let mut closed = self.closed.write().await;
        if *closed {
            return Ok(());
        }
        *closed = true;
        drop(closed);

        // Acquire lock, clone the channel, drop the lock, then close
        let reliable = self.reliable_channel.lock().await.clone();
        if let Some(channel) = reliable {
            let _ = channel.close().await;
        }

        let unreliable = self.unreliable_channel.lock().await.clone();
        if let Some(channel) = unreliable {
            let _ = channel.close().await;
        }

        self.peer_connection
            .close()
            .await
            .map_err(NethernetError::WebRtc)?;

        Ok(())
    }

    /// Returns the current ICE connection state of the underlying peer connection.
    pub fn connection_state(&self) -> RTCIceConnectionState {
        self.peer_connection.ice_connection_state()
    }

    /// Gets a clone of the session's RTCPeerConnection.
    pub fn peer_connection(&self) -> Arc<RTCPeerConnection> {
        self.peer_connection.clone()
    }

    /// Reports whether the session has been closed.
    pub async fn is_closed(&self) -> bool {
        *self.closed.read().await
    }

    /// Checks if both reliable and unreliable channels are set.
    pub async fn is_fully_connected(&self) -> bool {
        // Avoid holding both locks at once to prevent potential deadlocks
        let reliable_connected = self.reliable_channel.lock().await.is_some();
        if !reliable_connected {
            return false;
        }
        self.unreliable_channel.lock().await.is_some()
    }

    /// Waits for the WebRTC connection to be fully established.
    ///
    /// This method polls the ICE connection state until it reaches Connected or Completed state,
    /// or returns an error if the connection fails.
    pub async fn wait_for_connection(&self, timeout_ms: Option<u64>) -> Result<()> {
        let timeout = timeout_ms.unwrap_or(5000);
        let max_attempts = (timeout / 100).max(1); // Check every 100ms

        for attempt in 0..max_attempts {
            let state = self.connection_state();

            tracing::trace!(
                "Waiting for WebRTC connection... (attempt {}/{}), state: {:?}",
                attempt + 1,
                max_attempts,
                state
            );

            match state {
                RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
                    tracing::info!("WebRTC connection established!");
                    return Ok(());
                }
                RTCIceConnectionState::Failed
                | RTCIceConnectionState::Disconnected
                | RTCIceConnectionState::Closed => {
                    return Err(NethernetError::ConnectionClosed);
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }

        Err(NethernetError::Timeout)
    }
}
