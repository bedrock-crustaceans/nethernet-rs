use crate::error::{NethernetError, Result};
use crate::protocol::{
    Signal, SignalType,
    constants::{RELIABLE_CHANNEL, UNRELIABLE_CHANNEL},
};
use crate::session::Session;
use crate::signaling::Signaling;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use rand::Rng;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::StreamReader;
use tokio_util::sync::{CancellationToken, ReusableBoxFuture};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice::network_type::NetworkType;
use webrtc::peer_connection::configuration::RTCConfiguration;

/// NetherNet stream - data transmission over WebRTC
struct SessionStream {
    session: Arc<Session>,
    recv_future: ReusableBoxFuture<'static, Result<Option<Bytes>>>,
}

impl Stream for SessionStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.recv_future.poll(cx) {
            Poll::Ready(result) => {
                let session = self.session.clone();
                self.recv_future.set(async move { session.recv().await });
                match result {
                    Ok(Some(data)) => Poll::Ready(Some(Ok(data))),
                    Ok(None) => Poll::Ready(None),
                    Err(e) => Poll::Ready(Some(Err(io::Error::other(e)))),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// NetherNet stream - data transmission over WebRTC
pub struct NethernetStream {
    session: Arc<Session>,
    remote_addr: SocketAddr,
    reader: StreamReader<SessionStream, Bytes>,
    send_future: Option<ReusableBoxFuture<'static, Result<()>>>,
    shutdown_future: Option<ReusableBoxFuture<'static, Result<()>>>,
}

impl NethernetStream {
    /// Establishes a WebRTC-backed NethernetStream to a remote peer.
    ///
    /// Performs WebRTC offer/answer negotiation via the provided signaling implementation,
    /// creates reliable and unreliable data channels, exchanges ICE candidates, and waits
    /// for both data channels to open and for ICE to reach a connected state before
    /// returning a ready `NethernetStream`.
    ///
    /// On success, the returned stream is ready for send/recv operations. This function
    /// may return `NethernetError::Timeout` if signaling, channel opening, or ICE
    /// convergence does not complete within the allotted timeout, or `NethernetError::ConnectionClosed`
    /// if the ICE connection enters a closed/failed state.
    pub async fn connect<S: Signaling + 'static>(
        signaling: Arc<S>,
        remote_network_id: String,
        remote_addr: SocketAddr,
    ) -> Result<Self> {
        // Create WebRTC API with custom settings
        let media_engine = MediaEngine::default();

        // Configure SettingEngine to avoid IPv6 link-local binding issues
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_network_types(vec![NetworkType::Udp4]);

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine)
            .build();

        // Create peer connection
        let config = RTCConfiguration {
            ..Default::default()
        };

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        // Create data channels
        let reliable_channel = peer_connection
            .create_data_channel(
                RELIABLE_CHANNEL,
                Some(RTCDataChannelInit {
                    ordered: Some(true),
                    ..Default::default()
                }),
            )
            .await?;

        let unreliable_channel = peer_connection
            .create_data_channel(
                UNRELIABLE_CHANNEL,
                Some(RTCDataChannelInit {
                    ordered: Some(false),
                    max_retransmits: Some(0),
                    ..Default::default()
                }),
            )
            .await?;

        // Generate connection ID
        let mut connection_id_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut connection_id_bytes);
        let connection_id = u64::from_ne_bytes(connection_id_bytes);

        // Create channels to wait for DataChannel open events
        let (reliable_open_tx, reliable_open_rx) = tokio::sync::oneshot::channel::<()>();
        let (unreliable_open_tx, unreliable_open_rx) = tokio::sync::oneshot::channel::<()>();

        // Set up on_open handlers for DataChannels
        let reliable_open_tx = Arc::new(tokio::sync::Mutex::new(Some(reliable_open_tx)));
        let unreliable_open_tx = Arc::new(tokio::sync::Mutex::new(Some(unreliable_open_tx)));

        let reliable_tx_clone = reliable_open_tx.clone();
        reliable_channel.on_open(Box::new(move || {
            let tx = reliable_tx_clone.clone();
            Box::pin(async move {
                if let Some(sender) = tx.lock().await.take() {
                    let _ = sender.send(());
                }
            })
        }));

        let unreliable_tx_clone = unreliable_open_tx.clone();
        unreliable_channel.on_open(Box::new(move || {
            let tx = unreliable_tx_clone.clone();
            Box::pin(async move {
                if let Some(sender) = tx.lock().await.take() {
                    let _ = sender.send(());
                }
            })
        }));

        // Set up ICE candidate handler to signal candidates
        let signaling_clone = signaling.clone();
        let remote_network_id_clone = remote_network_id.clone();
        peer_connection.on_ice_candidate(Box::new(
            move |candidate: Option<webrtc::ice_transport::ice_candidate::RTCIceCandidate>| {
                let signaling = signaling_clone.clone();
                let network_id = remote_network_id_clone.clone();
                Box::pin(async move {
                    if let Some(candidate) = candidate {
                        if let Ok(json) = candidate.to_json() {
                            // Serialize full RTCIceCandidateInit (includes candidate, sdp_mid, sdp_mline_index)
                            if let Ok(candidate_json) = serde_json::to_string(&json) {
                                let candidate_signal =
                                    Signal::candidate(connection_id, candidate_json, network_id);
                                let _ = signaling.signal(candidate_signal).await;
                            }
                        }
                    }
                })
            },
        ));

        // Create offer
        let offer = peer_connection.create_offer(None).await?;
        peer_connection.set_local_description(offer.clone()).await?;

        // Create signal stream BEFORE sending offer to avoid race condition where
        // answer/candidates arrive before we subscribe
        let mut signals = signaling.signals();

        // Signal the offer
        let offer_signal = Signal::offer(connection_id, offer.sdp, remote_network_id.clone());
        signaling.signal(offer_signal).await?;

        // Wait for answer and handle candidates
        let mut pending_candidates = Vec::new();
        let answer = loop {
            if let Some(signal) = signals.next().await {
                if signal.connection_id == connection_id {
                    match signal.signal_type {
                        SignalType::Answer => {
                            break signal.data;
                        }
                        SignalType::Candidate => {
                            // Buffer remote ICE candidates until after set_remote_description
                            let candidate_init = match serde_json::from_str::<
                                webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                            >(&signal.data)
                            {
                                Ok(init) => init,
                                Err(_) => {
                                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit {
                                        candidate: signal.data.clone(),
                                        sdp_mid: None,
                                        sdp_mline_index: None,
                                        username_fragment: None,
                                    }
                                }
                            };
                            pending_candidates.push(candidate_init);
                        }
                        _ => {}
                    }
                }
            } else {
                return Err(NethernetError::Timeout);
            }
        };

        // Set the answer
        let answer_desc =
            webrtc::peer_connection::sdp::session_description::RTCSessionDescription::answer(
                answer,
            )?;
        peer_connection.set_remote_description(answer_desc).await?;

        tracing::trace!("Applying {} buffered candidates", pending_candidates.len());
        for candidate_init in pending_candidates {
            if let Err(e) = peer_connection.add_ice_candidate(candidate_init).await {
                tracing::warn!("Failed to add buffered ICE candidate: {}", e);
            } else {
                tracing::debug!("Successfully added buffered ICE candidate");
            }
        }

        // Continue processing candidates with cancellation support
        let peer_connection_clone = peer_connection.clone();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token_clone.cancelled() => {
                        // Task cancelled, exit loop
                        tracing::debug!("Candidate processing task cancelled");
                        break;
                    }
                    signal_opt = signals.next() => {
                        if let Some(signal) = signal_opt {
                            if signal.connection_id == connection_id
                                && signal.signal_type == SignalType::Candidate
                            {
                                let candidate_init = match serde_json::from_str::<
                                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                                >(&signal.data)
                                {
                                    Ok(init) => init,
                                    Err(_) => {
                                        tracing::debug!("Failed to parse candidate as JSON, treating as raw string");
                                        webrtc::ice_transport::ice_candidate::RTCIceCandidateInit {
                                            candidate: signal.data.clone(),
                                            sdp_mid: None,
                                            sdp_mline_index: None,
                                            username_fragment: None,
                                        }
                                    }
                                };
                                tracing::debug!("Received ICE candidate: {}", candidate_init.candidate);
                                if let Err(e) = peer_connection_clone
                                    .add_ice_candidate(candidate_init)
                                    .await
                                {
                                    tracing::warn!("Failed to add ICE candidate: {}", e);
                                } else {
                                    tracing::debug!("Successfully added ICE candidate");
                                }
                            }
                        } else {
                            // Signal stream ended, exit loop
                            break;
                        }
                    }
                }
            }
        });

        let session = Arc::new(Session::new(peer_connection.clone()));

        // Set up data channels
        session.set_reliable_channel(reliable_channel).await?;
        session.set_unreliable_channel(unreliable_channel).await?;

        // Wait for both DataChannels to open (with timeout)
        let timeout_duration = std::time::Duration::from_secs(10);

        // Wait for both channels concurrently within the same timeout window
        tokio::time::timeout(timeout_duration, async {
            let _ = tokio::join!(reliable_open_rx, unreliable_open_rx);
        })
        .await
        .map_err(|_| NethernetError::Timeout)?;

        // Wait for ICE connection to establish
        let peer_conn_clone = peer_connection.clone();
        let ice_connected = tokio::time::timeout(timeout_duration, async move {
            loop {
                let state = peer_conn_clone.ice_connection_state();
                match state {
                    webrtc::ice_transport::ice_connection_state::RTCIceConnectionState::Connected |
                    webrtc::ice_transport::ice_connection_state::RTCIceConnectionState::Completed => {
                        return Ok::<(), NethernetError>(());
                    }
                    webrtc::ice_transport::ice_connection_state::RTCIceConnectionState::Failed |
                    webrtc::ice_transport::ice_connection_state::RTCIceConnectionState::Disconnected |
                    webrtc::ice_transport::ice_connection_state::RTCIceConnectionState::Closed => {
                        return Err(NethernetError::ConnectionClosed);
                    }
                    _ => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }).await;

        match ice_connected {
            Ok(Ok(())) => {
                // ICE connection established, cancel the candidate processing task
                cancel_token.cancel();
            }
            Ok(Err(e)) => {
                cancel_token.cancel();
                return Err(e);
            }
            Err(_) => {
                cancel_token.cancel();
                return Err(NethernetError::Timeout);
            }
        }

        Ok(Self::from_session(session, remote_addr))
    }

    /// Constructs a NethernetStream from an existing Session and the peer's socket address.
    pub fn from_session(session: Arc<Session>, remote_addr: SocketAddr) -> Self {
        let session_clone = session.clone();
        let recv_future = ReusableBoxFuture::new(async move { session_clone.recv().await });

        let stream = SessionStream {
            session: session.clone(),
            recv_future,
        };

        Self {
            session,
            remote_addr,
            reader: StreamReader::new(stream),
            send_future: None,
            shutdown_future: None,
        }
    }

    /// Transmits a payload to the remote endpoint associated with this stream.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.session.send(data).await
    }

    /// Receive the next available data frame from this stream.
    pub async fn recv(&self) -> Result<Option<Bytes>> {
        self.session.recv().await
    }

    /// Close the stream and its underlying session.
    pub async fn close(&self) -> Result<()> {
        self.session.close().await
    }

    /// Get the socket address of the remote endpoint for this stream.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Access the underlying session.
    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }
}

impl AsyncRead for NethernetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for NethernetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If there's an active send future, poll it first
        if let Some(mut fut) = self.send_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {
                    // Previous send completed
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => {
                    // Still sending
                    self.send_future = Some(fut);
                    return Poll::Pending;
                }
            }
        }

        // Start new send
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        let session = self.session.clone();
        let mut fut = ReusableBoxFuture::new(async move { session.send(data).await });

        // Poll immediately to start the future
        match fut.poll(cx) {
            Poll::Ready(Ok(())) => {
                // Completed immediately
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Pending => {
                self.send_future = Some(fut);
            }
        }

        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(mut fut) = self.send_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => {
                    self.send_future = Some(fut);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First flush any pending writes
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if self.shutdown_future.is_none() {
            let session = self.session.clone();
            self.shutdown_future =
                Some(ReusableBoxFuture::new(async move { session.close().await }));
        }

        if let Some(mut fut) = self.shutdown_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => {
                    self.shutdown_future = Some(fut);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
