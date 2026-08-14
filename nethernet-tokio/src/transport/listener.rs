use crate::error::{NethernetError, Result};
use crate::protocol::{
    Signal, SignalType,
    constants::{RELIABLE_CHANNEL, UNRELIABLE_CHANNEL},
};
use crate::session::Session;
use crate::signaling::Signaling;
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::peer_connection::configuration::RTCConfiguration;

/// NetherNet listener - accepts WebRTC connections
pub struct NethernetListener<S: Signaling> {
    incoming: mpsc::UnboundedReceiver<Arc<Session>>,
    local_addr: SocketAddr,
    cancel_token: CancellationToken,
    _signal_handler_task: JoinHandle<()>,
    _phantom: PhantomData<S>,
}

impl<S: Signaling + 'static> NethernetListener<S> {
    /// Create a new [`NethernetListener`] bound to the given local address using the provided signaling implementation.
    ///
    /// The returned listener is ready to accept inbound WebRTC sessions. It initializes internal queues and dispatch
    /// structures, and spawns a background task to process signaling events; dropping the listener cancels that task.
    pub async fn bind(signaling: S, local_addr: SocketAddr) -> Result<Self> {
        let signaling = Arc::new(signaling);
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let signal_dispatchers = Arc::new(Mutex::new(HashMap::new()));
        let candidate_notifiers = Arc::new(Mutex::new(HashMap::new()));
        let cancel_token = CancellationToken::new();

        // Start signal handler task
        let signal_handler_task = Self::start_signal_handler(
            signaling,
            incoming_tx,
            signal_dispatchers,
            candidate_notifiers.clone(),
            cancel_token.clone(),
        );

        let listener = Self {
            incoming: incoming_rx,
            local_addr,
            cancel_token,
            _signal_handler_task: signal_handler_task,
            _phantom: PhantomData,
        };

        Ok(listener)
    }

    fn start_signal_handler(
        signaling: Arc<S>,
        incoming_tx: mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Signal>>>>,
        candidate_notifiers: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<()>>>>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut signals = signaling.signals();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    signal = signals.next() => {
                        match signal {
                            Some(signal) => {
                                match signal.signal_type {
                                    SignalType::Offer => {
                                        if let Err(e) = Self::handle_offer(
                                            signal,
                                            &signaling,
                                            &incoming_tx,
                                            &signal_dispatchers,
                                            &candidate_notifiers,
                                        )
                                        .await
                                        {
                                            tracing::debug!("Failed to handle offer: {}", e);
                                        }
                                    }
                                    SignalType::Answer | SignalType::Candidate | SignalType::Error => {
                                        // Dispatch to per-connection channel
                                        let dispatchers = signal_dispatchers.lock().await;
                                        if let Some(tx) = dispatchers.get(&signal.connection_id) {
                                            let _ = tx.send(signal);
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    async fn handle_offer(
        signal: Signal,
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: &Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Signal>>>>,
        candidate_notifiers: &Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<()>>>>,
    ) -> Result<()> {
        // Create WebRTC API with custom settings
        let media_engine = MediaEngine::default();

        // Configure SettingEngine to avoid IPv6 link-local binding issues
        let setting_engine = SettingEngine::default();

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine)
            .build();

        // Create peer connection
        let config = RTCConfiguration {
            ..Default::default()
        };

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        // Set up ICE candidate handler
        let signaling_clone = signaling.clone();
        let network_id_clone = signal.network_id.clone();
        let connection_id = signal.connection_id;
        peer_connection.on_ice_candidate(Box::new(
            move |candidate: Option<webrtc::ice_transport::ice_candidate::RTCIceCandidate>| {
                let signaling = signaling_clone.clone();
                let network_id = network_id_clone.clone();
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

        // Create oneshot channel to wait for first ICE candidate BEFORE set_remote_description
        // This ensures the candidate handler is ready before ICE negotiation starts
        let (candidate_tx, candidate_rx) = tokio::sync::oneshot::channel();
        {
            let mut notifiers = candidate_notifiers.lock().await;
            notifiers.insert(connection_id, candidate_tx);
        }

        // Register per-connection signal channel BEFORE set_remote_description
        // This ensures we can receive remote candidates as soon as they arrive
        let (signal_tx, mut signal_rx) = mpsc::unbounded_channel();
        {
            let mut dispatchers = signal_dispatchers.lock().await;
            dispatchers.insert(connection_id, signal_tx);
        }

        // Handle incoming ICE candidates for this connection
        // This must be set up BEFORE set_remote_description to receive candidates immediately
        let peer_connection_clone = peer_connection.clone();
        let signal_dispatchers_clone = signal_dispatchers.clone();
        let candidate_notifiers_clone = candidate_notifiers.clone();
        tokio::spawn(async move {
            let mut first_candidate = true;
            while let Some(sig) = signal_rx.recv().await {
                if sig.signal_type == SignalType::Candidate {
                    // Deserialize sig.data into an RTCIceCandidateInit
                    let candidate_init = match serde_json::from_str::<
                        webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                    >(&sig.data)
                    {
                        Ok(init) => init,
                        Err(_) => webrtc::ice_transport::ice_candidate::RTCIceCandidateInit {
                            candidate: sig.data.clone(),
                            sdp_mid: None,
                            sdp_mline_index: None,
                            username_fragment: None,
                        },
                    };

                    if let Err(e) = peer_connection_clone
                        .add_ice_candidate(candidate_init)
                        .await
                    {
                        tracing::warn!("Failed to add ICE candidate: {}", e);
                        continue;
                    }

                    // Notify waiting handler AFTER adding first candidate to peer connection
                    if first_candidate {
                        first_candidate = false;
                        tracing::debug!("First candidate received and added successfully");
                        let mut notifiers = candidate_notifiers_clone.lock().await;
                        if let Some(tx) = notifiers.remove(&connection_id) {
                            let _ = tx.send(());
                        }
                    }
                }
            }
            // Clean up dispatcher when channel closes (if not already removed by state handler)
            {
                let mut dispatchers = signal_dispatchers_clone.lock().await;
                dispatchers.remove(&connection_id);
            }

            // Clean up candidate notifier if it wasn't already removed
            let mut notifiers = candidate_notifiers_clone.lock().await;
            notifiers.remove(&connection_id);
        });

        // Set remote description (offer)
        let offer =
            webrtc::peer_connection::sdp::session_description::RTCSessionDescription::offer(
                signal.data.clone(),
            )?;
        peer_connection.set_remote_description(offer).await?;

        // Create answer
        let answer = peer_connection.create_answer(None).await?;
        peer_connection
            .set_local_description(answer.clone())
            .await?;

        // Signal the answer
        let answer_signal =
            Signal::answer(signal.connection_id, answer.sdp, signal.network_id.clone());
        signaling.signal(answer_signal).await?;

        // Set up connection state change handler to clean up dispatcher
        let signal_dispatchers_for_cleanup = signal_dispatchers.clone();
        peer_connection.on_peer_connection_state_change(Box::new(move |state| {
            let signal_dispatchers = signal_dispatchers_for_cleanup.clone();
            Box::pin(async move {
                use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
                match state {
                    RTCPeerConnectionState::Failed
                    | RTCPeerConnectionState::Disconnected
                    | RTCPeerConnectionState::Closed => {
                        // Remove dispatcher to allow signal_tx to drop and signal_rx to close
                        let mut dispatchers = signal_dispatchers.lock().await;
                        dispatchers.remove(&connection_id);
                    }
                    _ => {}
                }
            })
        }));

        let session = Arc::new(Session::new(peer_connection.clone()));

        // Channel to notify when data channels are ready
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let ready_tx = Arc::new(tokio::sync::Mutex::new(Some(ready_tx)));

        // Event handler for data channels
        let session_clone = session.clone();
        let ready_tx_clone = ready_tx.clone();
        peer_connection.on_data_channel(Box::new(move |channel| {
            let session = session_clone.clone();
            let ready_tx = ready_tx_clone.clone();
            Box::pin(async move {
                let label = channel.label().to_string();
                match label.as_str() {
                    RELIABLE_CHANNEL => {
                        let _ = session.set_reliable_channel(channel).await;
                        // Check if both channels are ready
                        if session.is_fully_connected().await {
                            let mut tx_guard = ready_tx.lock().await;
                            if let Some(tx) = tx_guard.take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                    UNRELIABLE_CHANNEL => {
                        let _ = session.set_unreliable_channel(channel).await;
                        // Check if both channels are ready
                        if session.is_fully_connected().await {
                            let mut tx_guard = ready_tx.lock().await;
                            if let Some(tx) = tx_guard.take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                    _ => {}
                }
            })
        }));

        // Wait for first ICE candidate and then data channel before adding to incoming queue
        let session_clone = session.clone();
        let incoming_tx_clone = incoming_tx.clone();
        tokio::spawn(async move {
            // Wait for first ICE candidate (with timeout)
            match tokio::time::timeout(tokio::time::Duration::from_secs(5), candidate_rx).await {
                Ok(Ok(())) => {
                    tracing::debug!("Received first ICE candidate");
                }
                Ok(Err(_)) => {
                    tracing::warn!("Candidate notifier dropped before receiving candidate");
                }
                Err(_) => {
                    tracing::warn!("Timeout waiting for first ICE candidate");
                    let _ = incoming_tx_clone.send(session_clone);
                    return;
                }
            }

            // Wait up to 5 seconds for data channel to be ready
            match tokio::time::timeout(tokio::time::Duration::from_secs(5), ready_rx).await {
                Ok(Ok(())) => {
                    tracing::debug!("Data channel ready, adding session to incoming queue");
                    let _ = incoming_tx_clone.send(session_clone);
                }
                Ok(Err(_)) | Err(_) => {
                    tracing::warn!("Timeout waiting for data channel to be ready");
                    // Still add to incoming queue, client will handle the error
                    let _ = incoming_tx_clone.send(session_clone);
                }
            }
        });

        Ok(())
    }

    /// Waits for and returns the next inbound session.
    pub async fn accept(&mut self) -> Result<Arc<Session>> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| NethernetError::ConnectionClosed)
    }

    /// Local socket address that this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl<S: Signaling> Drop for NethernetListener<S> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<S: Signaling + 'static + Unpin> Stream for NethernetListener<S> {
    type Item = Arc<Session>;

    /// Polls the listener for the next inbound session, returning Pending if the internal queue is empty.
    ///
    /// This method delegates to the inner receiver's poll to produce the next [`Arc<Session>`].
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().incoming.poll_recv(cx)
    }
}
