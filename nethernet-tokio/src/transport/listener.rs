use crate::error::{NethernetError, Result};
use crate::protocol::constants::{RELIABLE_CHANNEL, SCTP_PORT, UNRELIABLE_CHANNEL};
use crate::protocol::webrtc::{Description, format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::session::Session;
use crate::signaling::Signaling;
use crate::transport::Transports;
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
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

/// Time to wait for the first candidate signaled by the remote connection.
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Time to wait for each transport to start.
const START_TIMEOUT: Duration = Duration::from_secs(5);

/// Time to wait for the data channels created by the remote connection.
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(5);

type SignalDispatchers = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Signal>>>>;

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
        let cancel_token = CancellationToken::new();

        // Start signal handler task
        let signal_handler_task = Self::start_signal_handler(
            signaling,
            incoming_tx,
            signal_dispatchers,
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
        signal_dispatchers: SignalDispatchers,
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

    /// Answers an offer signaled by a remote connection with the parameters of the local
    /// transports and establishes them once the remote connection signals its candidates.
    async fn handle_offer(
        signal: Signal,
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: &SignalDispatchers,
    ) -> Result<()> {
        let description = Description::parse(&signal.data)?;

        let transports = Transports::new(SettingEngine::default())?;
        let (candidates, ice_parameters) = transports.gather().await?;

        let answer = transports
            .local_description(ice_parameters.clone(), DTLSRole::Unspecified)?
            .encode()?;

        let connection_id = signal.connection_id;
        let network_id = signal.network_id;

        let (signal_tx, mut signal_rx) = mpsc::unbounded_channel();
        signal_dispatchers
            .lock()
            .await
            .insert(connection_id, signal_tx);

        signaling
            .signal(Signal::answer(connection_id, answer, network_id.clone()))
            .await?;
        for (index, candidate) in candidates.iter().enumerate() {
            signaling
                .signal(Signal::candidate(
                    connection_id,
                    format_ice_candidate(index, candidate, &ice_parameters.username_fragment),
                    network_id.clone(),
                ))
                .await?;
        }

        let (candidate_tx, candidate_rx) = oneshot::channel();
        let ice = transports.ice.clone();
        let dispatchers = signal_dispatchers.clone();
        tokio::spawn(async move {
            let mut candidate_tx = Some(candidate_tx);
            while let Some(signal) = signal_rx.recv().await {
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
                if let Err(e) = ice.add_remote_candidate(Some(candidate)).await {
                    tracing::warn!("Failed to add remote candidate: {}", e);
                    continue;
                }
                if let Some(tx) = candidate_tx.take() {
                    let _ = tx.send(());
                }
            }
            dispatchers.lock().await.remove(&connection_id);
        });

        let incoming_tx = incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                Self::start_transports(transports, description, candidate_rx, incoming_tx).await
            {
                tracing::debug!("Failed to establish incoming connection: {}", e);
            }
        });

        Ok(())
    }

    /// Starts the transports of an answered connection and queues the session once the
    /// remote connection has created both data channels.
    async fn start_transports(
        transports: Transports,
        description: Description,
        candidate_rx: oneshot::Receiver<()>,
        incoming_tx: mpsc::UnboundedSender<Arc<Session>>,
    ) -> Result<()> {
        tokio::time::timeout(CANDIDATE_TIMEOUT, candidate_rx)
            .await
            .map_err(|_| NethernetError::Timeout)?
            .map_err(|_| NethernetError::ConnectionClosed)?;
        tracing::debug!("Received first candidate");

        let session = Arc::new(Session::new(
            transports.ice.clone(),
            transports.dtls.clone(),
            transports.sctp.clone(),
        ));

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

        tokio::time::timeout(
            START_TIMEOUT,
            transports
                .ice
                .start(&description.ice, Some(RTCIceRole::Controlled)),
        )
        .await
        .map_err(|_| NethernetError::Timeout)??;

        tokio::time::timeout(START_TIMEOUT, transports.dtls.start(description.dtls))
            .await
            .map_err(|_| NethernetError::Timeout)??;

        tokio::time::timeout(
            START_TIMEOUT,
            transports
                .sctp
                .start(description.sctp, SCTP_PORT, SCTP_PORT),
        )
        .await
        .map_err(|_| NethernetError::Timeout)??;

        tokio::time::timeout(CHANNEL_TIMEOUT, opened_rx)
            .await
            .map_err(|_| NethernetError::Timeout)?
            .map_err(|_| NethernetError::ConnectionClosed)?;

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
