use crate::addr::Addr;
use crate::error::{NethernetError, Result, SignalErrorCode};
use crate::protocol::constants::{RELIABLE_CHANNEL, SCTP_PORT, UNRELIABLE_CHANNEL};
use crate::protocol::webrtc::{Description, format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::session::Session;
use crate::signaling::Signaling;
use crate::transport::stream::parse_error_code;
use crate::transport::{ConnectionConfig, Transports};
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice_transport::ice_role::RTCIceRole;

/// Signals an error back to the remote connection referenced by the IDs.
async fn signal_error<S: Signaling>(
    signaling: &Arc<S>,
    connection_id: u64,
    network_id: String,
    code: SignalErrorCode,
) {
    if let Err(e) = signaling
        .signal(Signal::error(connection_id, code, network_id))
        .await
    {
        tracing::debug!("Failed to signal error: {}", e);
    }
}

/// Starts a transport, reporting the error code to be signaled back to the remote
/// connection when it does not start in time.
async fn start_transport(
    start: impl Future<Output = std::result::Result<(), webrtc::Error>>,
    timeout: Duration,
) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
    match tokio::time::timeout(timeout, start).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err((Some(SignalErrorCode::Ice), NethernetError::WebRtc(e))),
        Err(_) => Err((
            Some(SignalErrorCode::InactivityTimeout),
            NethernetError::Timeout,
        )),
    }
}

/// Connections are referenced by both the remote network ID and the connection ID, as
/// connection IDs are only unique within a single network.
type ConnectionKey = (String, u64);

type SignalDispatchers = Arc<Mutex<HashMap<ConnectionKey, mpsc::UnboundedSender<Signal>>>>;

/// NetherNet listener - accepts WebRTC connections
pub struct NethernetListener<S: Signaling> {
    incoming: mpsc::UnboundedReceiver<Arc<Session>>,
    local_addr: Addr,
    signal_dispatchers: SignalDispatchers,
    cancel_token: CancellationToken,
    _signal_handler_task: JoinHandle<()>,
    _phantom: PhantomData<S>,
}

impl<S: Signaling + 'static> NethernetListener<S> {
    /// Create a new [`NethernetListener`] on the local network of the signaling implementation.
    ///
    /// The returned listener is ready to accept inbound WebRTC sessions. It initializes internal queues and dispatch
    /// structures, and spawns a background task to process signaling events; dropping the listener cancels that task.
    pub async fn bind(signaling: S) -> Result<Self> {
        Self::bind_with(signaling, ConnectionConfig::default()).await
    }

    /// Creates a [`NethernetListener`] using the timeouts of the given configuration.
    pub async fn bind_with(signaling: S, config: ConnectionConfig) -> Result<Self> {
        let signaling = Arc::new(signaling);
        let local_addr = Addr::network(signaling.network_id());
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let signal_dispatchers = Arc::new(Mutex::new(HashMap::new()));
        let cancel_token = CancellationToken::new();

        // Start signal handler task
        let signal_handler_task = Self::start_signal_handler(
            signaling,
            incoming_tx,
            signal_dispatchers.clone(),
            cancel_token.clone(),
            config,
        );

        let listener = Self {
            incoming: incoming_rx,
            local_addr,
            signal_dispatchers,
            cancel_token,
            _signal_handler_task: signal_handler_task,
            _phantom: PhantomData,
        };

        Ok(listener)
    }

    fn start_signal_handler(
        signaling: Arc<S>,
        incoming_tx: mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: SignalDispatchers,
        cancel_token: CancellationToken,
        config: ConnectionConfig,
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
                                            config.clone(),
                                        )
                                        .await
                                        {
                                            tracing::debug!("Failed to handle offer: {}", e);
                                        }
                                    }
                                    SignalType::Answer | SignalType::Candidate | SignalType::Error => {
                                        // Dispatch to per-connection channel
                                        let dispatchers = signal_dispatchers.lock().await;
                                        let key = (signal.network_id.clone(), signal.connection_id);
                                        if let Some(tx) = dispatchers.get(&key) {
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

    /// Answers an offer signaled by a remote connection with the parameters of the local
    /// transports and establishes them once the remote connection signals its candidates.
    async fn handle_offer(
        signal: Signal,
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: &SignalDispatchers,
        config: ConnectionConfig,
    ) -> Result<()> {
        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();

        let cancel_token = config.cancel_token.clone();
        let result = tokio::select! {
            _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
            result = Self::answer_offer(signal, signaling, incoming_tx, signal_dispatchers, config.clone()) => result,
        };

        match result {
            Ok(()) => Ok(()),
            Err((code, e)) => {
                if let Some(code) = code {
                    signal_error(signaling, connection_id, network_id, code).await;
                }
                Err(e)
            }
        }
    }

    /// Answers the offer, reporting the error code to be signaled back to the remote
    /// connection when a step fails.
    async fn answer_offer(
        signal: Signal,
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: &SignalDispatchers,
        config: ConnectionConfig,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
        let description = Description::parse(&signal.data)
            .map_err(|e| (Some(SignalErrorCode::FailedToSetRemoteDescription), e))?;

        let credentials = signaling
            .credentials()
            .await
            .map_err(|e| (Some(SignalErrorCode::SignalingTurnAuthFailed), e))?;
        let transports = Transports::new(SettingEngine::default(), credentials.as_ref())
            .map_err(|e| (Some(SignalErrorCode::FailedToCreatePeerConnection), e))?;
        let (candidates, ice_parameters) = transports
            .gather()
            .await
            .map_err(|e| (Some(SignalErrorCode::FailedToCreatePeerConnection), e))?;

        let answer = transports
            .local_description(ice_parameters.clone(), DTLSRole::Unspecified)
            .and_then(|description| description.encode())
            .map_err(|e| (Some(SignalErrorCode::FailedToCreateAnswer), e))?;

        let connection_id = signal.connection_id;
        let network_id = signal.network_id;
        let key = (network_id.clone(), connection_id);

        let (signal_tx, mut signal_rx) = mpsc::unbounded_channel();
        signal_dispatchers
            .lock()
            .await
            .insert(key.clone(), signal_tx);

        signaling
            .signal(Signal::answer(connection_id, answer, network_id.clone()))
            .await
            .map_err(|e| (None, e))?;
        for (index, candidate) in candidates.iter().enumerate() {
            signaling
                .signal(Signal::candidate(
                    connection_id,
                    format_ice_candidate(index, candidate, &ice_parameters.username_fragment),
                    network_id.clone(),
                ))
                .await
                .map_err(|e| (None, e))?;
        }

        let mut local = Addr::new(signaling.network_id(), connection_id);
        local.candidates = candidates;

        let session = Arc::new(Session::new(
            transports.ice.clone(),
            transports.dtls.clone(),
            transports.sctp.clone(),
            local,
            Addr::new(network_id.clone(), connection_id),
        ));

        let (candidate_tx, candidate_rx) = oneshot::channel();
        let session_clone = session.clone();
        let dispatchers = signal_dispatchers.clone();
        tokio::spawn(async move {
            let mut candidate_tx = Some(candidate_tx);
            loop {
                let signal = tokio::select! {
                    _ = session_clone.closed() => break,
                    signal = signal_rx.recv() => match signal {
                        Some(signal) => signal,
                        None => break,
                    },
                };
                if signal.signal_type == SignalType::Error {
                    let code = parse_error_code(&signal.data);
                    tracing::debug!("Remote connection signaled an error: {:?}", code);
                    let _ = session_clone.close().await;
                    break;
                }
                if signal.signal_type != SignalType::Candidate {
                    continue;
                }
                let candidate = match parse_ice_candidate(&signal.data) {
                    Ok(candidate) => candidate,
                    Err(e) => {
                        tracing::warn!("Failed to parse remote candidate: {}", e);
                        continue;
                    }
                };
                if let Err(e) = session_clone.add_remote_candidate(candidate).await {
                    tracing::warn!("Failed to add remote candidate: {}", e);
                    continue;
                }
                if let Some(tx) = candidate_tx.take() {
                    let _ = tx.send(());
                }
            }
            dispatchers.lock().await.remove(&key);
        });

        let incoming_tx = incoming_tx.clone();
        let signaling = signaling.clone();
        tokio::spawn(async move {
            let cancel_token = config.cancel_token.clone();
            let result = tokio::select! {
                _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
                result = Self::start_transports(
                    transports,
                    session,
                    description,
                    candidate_rx,
                    incoming_tx,
                    config,
                ) => result,
            };

            if let Err((code, e)) = result {
                tracing::debug!("Failed to establish incoming connection: {}", e);
                if let Some(code) = code {
                    signal_error(&signaling, connection_id, network_id, code).await;
                }
            }
        });

        Ok(())
    }

    /// Starts the transports of an answered connection and queues the session once the
    /// remote connection has created both data channels.
    async fn start_transports(
        transports: Transports,
        session: Arc<Session>,
        description: Description,
        candidate_rx: oneshot::Receiver<()>,
        incoming_tx: mpsc::UnboundedSender<Arc<Session>>,
        config: ConnectionConfig,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
        tokio::time::timeout(config.timeouts.candidate, candidate_rx)
            .await
            .map_err(|_| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                    NethernetError::Timeout,
                )
            })?
            .map_err(|_| (None, NethernetError::ConnectionClosed))?;
        tracing::debug!("Received first candidate");

        let (opened_tx, opened_rx) = oneshot::channel();
        let opened_tx = Arc::new(Mutex::new(Some(opened_tx)));
        let session_clone = session.clone();
        transports
            .sctp
            .on_data_channel_opened(Box::new(move |channel| {
                let session = session_clone.clone();
                let opened_tx = opened_tx.clone();
                Box::pin(async move {
                    let label = channel.label().to_string();
                    match label.as_str() {
                        RELIABLE_CHANNEL => {
                            let _ = session.set_reliable_channel(channel).await;
                            if let Some(tx) = opened_tx.lock().await.take() {
                                let _ = tx.send(());
                            }
                        }
                        UNRELIABLE_CHANNEL => {
                            let _ = session.set_unreliable_channel(channel).await;
                        }
                        _ => {}
                    }
                })
            }));

        start_transport(
            transports
                .ice
                .start(&description.ice, Some(RTCIceRole::Controlled)),
            config.timeouts.start,
        )
        .await?;
        start_transport(
            transports.dtls.start(description.dtls),
            config.timeouts.start,
        )
        .await?;
        start_transport(
            transports
                .sctp
                .start(description.sctp, SCTP_PORT, SCTP_PORT),
            config.timeouts.start,
        )
        .await?;

        tokio::time::timeout(config.timeouts.channel, opened_rx)
            .await
            .map_err(|_| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                    NethernetError::Timeout,
                )
            })?
            .map_err(|_| (None, NethernetError::ConnectionClosed))?;

        let _ = incoming_tx.send(session);
        Ok(())
    }

    /// Waits for and returns the next inbound session.
    pub async fn accept(&mut self) -> Result<Arc<Session>> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| NethernetError::ConnectionClosed)
    }

    /// Closes the listener and every session that has not been accepted yet.
    ///
    /// Blocked calls to [`NethernetListener::accept`] return
    /// [`NethernetError::ConnectionClosed`] once the listener is closed.
    pub async fn close(&mut self) -> Result<()> {
        self.cancel_token.cancel();
        self.incoming.close();

        while let Ok(session) = self.incoming.try_recv() {
            if let Err(e) = session.close().await {
                tracing::debug!("Failed to close pending session: {}", e);
            }
        }
        self.signal_dispatchers.lock().await.clear();

        Ok(())
    }

    /// Address of the local network this listener accepts connections on.
    pub fn local_addr(&self) -> &Addr {
        &self.local_addr
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
