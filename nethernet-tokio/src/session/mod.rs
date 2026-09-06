use crate::addr::Addr;
use crate::error::{NethernetError, Result};
use crate::protocol::constants::DEFAULT_PACKET_CHANNEL_CAPACITY;
use crate::protocol::{Message, MessageSegment};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing;
use webrtc::data_channel::RTCDataChannel;
use webrtc::dtls_transport::RTCDtlsTransport;
use webrtc::ice_transport::RTCIceTransport;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_transport_state::RTCIceTransportState;
use webrtc::sctp_transport::RTCSctpTransport;

/// Routes the message segments received on the channel into the buffer, forwarding
/// each reassembled message to the receiver.
fn attach_message_handler(
    channel: &Arc<RTCDataChannel>,
    buffer: Arc<Mutex<Message>>,
    tx: mpsc::Sender<Bytes>,
) {
    channel.on_message(Box::new(move |msg| {
        let data = msg.data.clone();
        let buffer = buffer.clone();
        let tx = tx.clone();

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
                            tracing::debug!(
                                "incomplete segment added to buffer, waiting for more segments"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "failed to add segment to buffer: {:?}, data length: {}",
                                e,
                                data_len
                            );
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
}

/// WebRTC session manager
pub struct Session {
    ice: Arc<RTCIceTransport>,
    dtls: Arc<RTCDtlsTransport>,
    sctp: Arc<RTCSctpTransport>,
    local: Addr,
    remote: Arc<Mutex<Addr>>,
    reliable_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    unreliable_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    message_buffer: Arc<Mutex<Message>>,
    unreliable_buffer: Arc<Mutex<Message>>,
    packet_tx: mpsc::Sender<Bytes>,
    packet_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    unreliable_tx: mpsc::Sender<Bytes>,
    unreliable_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    closed: Arc<RwLock<bool>>,
    close_token: CancellationToken,
}

impl Session {
    /// Creates a Session using the default packet channel capacity.
    ///
    /// The local address holds the locally gathered candidates, while the remote address
    /// is extended with the candidates signaled by the remote connection.
    pub fn new(
        ice: Arc<RTCIceTransport>,
        dtls: Arc<RTCDtlsTransport>,
        sctp: Arc<RTCSctpTransport>,
        local: Addr,
        remote: Addr,
    ) -> Self {
        Self::with_capacity(
            ice,
            dtls,
            sctp,
            local,
            remote,
            DEFAULT_PACKET_CHANNEL_CAPACITY,
        )
    }

    /// Creates a Session backed by the given transports and a bounded packet channel with the specified capacity.
    pub fn with_capacity(
        ice: Arc<RTCIceTransport>,
        dtls: Arc<RTCDtlsTransport>,
        sctp: Arc<RTCSctpTransport>,
        local: Addr,
        remote: Addr,
        capacity: usize,
    ) -> Self {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);
        let (unreliable_tx, unreliable_rx) = mpsc::channel(capacity);

        Self {
            ice,
            dtls,
            sctp,
            local,
            remote: Arc::new(Mutex::new(remote)),
            reliable_channel: Arc::new(Mutex::new(None)),
            unreliable_channel: Arc::new(Mutex::new(None)),
            message_buffer: Arc::new(Mutex::new(Message::new())),
            unreliable_buffer: Arc::new(Mutex::new(Message::new())),
            packet_tx,
            packet_rx: Arc::new(Mutex::new(packet_rx)),
            unreliable_tx,
            unreliable_rx: Arc::new(Mutex::new(unreliable_rx)),
            closed: Arc::new(RwLock::new(false)),
            close_token: CancellationToken::new(),
        }
    }

    /// Attaches a reliable RTCDataChannel to the session and route incoming message segments into the session's reassembly pipeline.
    ///
    /// The provided channel will receive an `on_message` handler that decodes incoming bytes as `MessageSegment`s, accumulates segments in the session's internal buffer, and forwards completed messages to the session's packet receiver. The channel is then stored as the session's reliable data channel.
    pub async fn set_reliable_channel(&self, channel: Arc<RTCDataChannel>) -> Result<()> {
        attach_message_handler(
            &channel,
            self.message_buffer.clone(),
            self.packet_tx.clone(),
        );

        *self.reliable_channel.lock().await = Some(channel);
        Ok(())
    }

    /// Attaches an unreliable RTC data channel to the session and routes incoming
    /// message segments into a separate reassembly pipeline.
    ///
    /// Replaces any previously set unreliable data channel with the provided one.
    pub async fn set_unreliable_channel(&self, channel: Arc<RTCDataChannel>) -> Result<()> {
        attach_message_handler(
            &channel,
            self.unreliable_buffer.clone(),
            self.unreliable_tx.clone(),
        );

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

    /// Sends data over the session using the unreliable data channel.
    ///
    /// # Errors
    ///
    /// - Returns `NethernetError::ConnectionClosed` if the session has been closed.
    /// - Returns `NethernetError::DataChannel(...)` if the unreliable channel is not set
    ///   or if sending a segment fails.
    ///
    /// Data sent over a channel that was opened out of band is dropped by remote
    /// connections that did not open the matching channel themselves.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        if *self.closed.read().await {
            return Err(NethernetError::ConnectionClosed);
        }

        let channel = {
            let guard = self.unreliable_channel.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| {
                    NethernetError::DataChannel("Unreliable channel not set".to_string())
                })?
                .clone()
        };
        for segment in Message::split_into_segments(data)? {
            channel
                .send(&segment.encode())
                .await
                .map_err(|e| NethernetError::DataChannel(e.to_string()))?;
        }

        Ok(())
    }

    /// Receives the next complete packet from the unreliable data channel.
    ///
    /// Returns `Ok(None)` once the session has been closed.
    pub async fn recv_unreliable(&self) -> Result<Option<Bytes>> {
        if *self.closed.read().await {
            return Ok(None);
        }

        Ok(self.unreliable_rx.lock().await.recv().await)
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

        self.close_token.cancel();

        // Acquire lock, clone the channel, drop the lock, then close
        let reliable = self.reliable_channel.lock().await.clone();
        if let Some(channel) = reliable {
            let _ = channel.close().await;
        }

        let unreliable = self.unreliable_channel.lock().await.clone();
        if let Some(channel) = unreliable {
            let _ = channel.close().await;
        }

        let mut errors = Vec::new();
        if let Err(e) = self.sctp.stop().await {
            errors.push(e);
        }
        if let Err(e) = self.dtls.stop().await {
            errors.push(e);
        }
        if let Err(e) = self.ice.stop().await {
            errors.push(e);
        }

        match errors.into_iter().next() {
            Some(e) => Err(NethernetError::WebRtc(e)),
            None => Ok(()),
        }
    }

    /// Adds a candidate signaled by the remote connection to the ICE transport and
    /// records it in the remote address of the session.
    pub async fn add_remote_candidate(&self, candidate: RTCIceCandidate) -> Result<()> {
        self.ice
            .add_remote_candidate(Some(candidate.clone()))
            .await?;
        self.remote.lock().await.candidates.push(candidate);
        Ok(())
    }

    /// Returns the local address of the session, including the candidate selected by
    /// the ICE transport if a pair has been selected.
    pub async fn local_addr(&self) -> Addr {
        let mut addr = self.local.clone();
        addr.selected_candidate = self
            .ice
            .get_selected_candidate_pair()
            .await
            .map(|pair| pair.local);
        addr
    }

    /// Returns the address of the remote connection, including the candidates it has
    /// signaled and the candidate selected by the ICE transport.
    pub async fn remote_addr(&self) -> Addr {
        let mut addr = self.remote.lock().await.clone();
        addr.selected_candidate = self
            .ice
            .get_selected_candidate_pair()
            .await
            .map(|pair| pair.remote);
        addr
    }

    /// Returns the current state of the ICE transport.
    pub fn connection_state(&self) -> RTCIceTransportState {
        self.ice.state()
    }

    /// Gets a clone of the session's ICE transport.
    pub fn ice_transport(&self) -> Arc<RTCIceTransport> {
        self.ice.clone()
    }

    /// Resolves once the session has been closed.
    pub async fn closed(&self) {
        self.close_token.cancelled().await
    }

    /// Reports whether the session has been closed.
    pub async fn is_closed(&self) -> bool {
        *self.closed.read().await
    }
}
