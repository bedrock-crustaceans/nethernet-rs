use crate::addr::Addr;
use crate::error::{NethernetError, Result, SignalErrorCode};
use crate::protocol::constants::{RELIABLE_CHANNEL, SCTP_PORT, UNRELIABLE_CHANNEL};
use crate::protocol::webrtc::{Description, format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::session::Session;
use crate::signaling::Signaling;
use crate::transport::{ConnectionConfig, Transports};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use rand::Rng;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::io::StreamReader;
use tokio_util::sync::ReusableBoxFuture;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::data_channel_parameters::DataChannelParameters;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice_transport::ice_role::RTCIceRole;

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

/// Parses the error code of a `CONNECTERROR` signal.
pub(crate) fn parse_error_code(data: &str) -> SignalErrorCode {
    data.trim().parse::<u32>().map_or(
        SignalErrorCode::SignalingUnknownError,
        SignalErrorCode::from,
    )
}

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
    reader: StreamReader<SessionStream, Bytes>,
    send_future: Option<ReusableBoxFuture<'static, Result<()>>>,
    shutdown_future: Option<ReusableBoxFuture<'static, Result<()>>>,
}
impl NethernetStream {
    /// Establishes a NethernetStream with the remote network referenced by the ID.
    ///
    /// An offer is signaled with the parameters of the local transports, and the answer
    /// signaled back by the remote connection is used to start them. Once the transports
    /// are running, the reliable and unreliable data channels are created and the stream
    /// is ready for send/recv operations.
    pub async fn connect<S: Signaling + 'static>(
        signaling: Arc<S>,
        remote_network_id: String,
    ) -> Result<Self> {
        Self::connect_with(signaling, remote_network_id, ConnectionConfig::default()).await
    }

    /// Establishes a NethernetStream using the timeouts of the given configuration.
    pub async fn connect_with<S: Signaling + 'static>(
        signaling: Arc<S>,
        remote_network_id: String,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let mut connection_id_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut connection_id_bytes);
        let connection_id = u64::from_le_bytes(connection_id_bytes);

        let cancel_token = config.cancel_token.clone();
        let result = tokio::select! {
            _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
            result = Self::negotiate(&signaling, &remote_network_id, connection_id, config) => result,
        };

        match result {
            Ok(stream) => Ok(stream),
            Err((code, e)) => {
                if let Some(code) = code {
                    let _ = signaling
                        .signal(Signal::error(
                            connection_id,
                            code,
                            remote_network_id.clone(),
                        ))
                        .await;
                }
                Err(e)
            }
        }
    }

    /// Negotiates the connection, reporting the error code to be signaled back to the
    /// remote connection when a step fails.
    async fn negotiate<S: Signaling + 'static>(
        signaling: &Arc<S>,
        remote_network_id: &str,
        connection_id: u64,
        config: ConnectionConfig,
    ) -> std::result::Result<Self, (Option<SignalErrorCode>, NethernetError)> {
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_network_types(vec![NetworkType::Udp4]);

        let credentials = signaling
            .credentials()
            .await
            .map_err(|e| (Some(SignalErrorCode::SignalingTurnAuthFailed), e))?;
        let transports = Transports::new(setting_engine, credentials.as_ref())
            .map_err(|e| (Some(SignalErrorCode::FailedToCreatePeerConnection), e))?;
        let (candidates, ice_parameters) = transports
            .gather()
            .await
            .map_err(|e| (Some(SignalErrorCode::FailedToCreatePeerConnection), e))?;

        // Non-trickle connections carry every local candidate in the offer itself
        let disable_trickle_ice = signaling.disable_trickle_ice();
        let offer_candidates = if disable_trickle_ice {
            candidates.clone()
        } else {
            Vec::new()
        };

        let offer = transports
            .local_description(ice_parameters.clone(), DTLSRole::Server, offer_candidates)
            .and_then(|description| description.encode())
            .map_err(|e| (Some(SignalErrorCode::FailedToCreateOffer), e))?;

        let mut signals = signaling.signals();

        signaling
            .signal(Signal::offer(
                connection_id,
                offer,
                remote_network_id.to_string(),
            ))
            .await
            .map_err(|e| (None, e))?;
        if !disable_trickle_ice {
            for (index, candidate) in candidates.iter().enumerate() {
                signaling
                    .signal(Signal::candidate(
                        connection_id,
                        format_ice_candidate(index, candidate, &ice_parameters.username_fragment),
                        remote_network_id.to_string(),
                    ))
                    .await
                    .map_err(|e| (None, e))?;
            }
        }

        let mut pending_candidates = Vec::new();
        let answer = tokio::time::timeout(config.timeouts.negotiation, async {
            loop {
                let Some(signal) = signals.next().await else {
                    return Err((None, NethernetError::ConnectionClosed));
                };
                if signal.connection_id != connection_id || signal.network_id != remote_network_id {
                    continue;
                }
                match signal.signal_type {
                    SignalType::Answer => return Ok(signal.data),
                    SignalType::Candidate => match parse_ice_candidate(&signal.data) {
                        Ok(candidate) => pending_candidates.push(candidate),
                        Err(e) => tracing::warn!("Failed to parse remote candidate: {}", e),
                    },
                    SignalType::Error => {
                        let code = parse_error_code(&signal.data);
                        return Err((None, NethernetError::Signaled(code)));
                    }
                    SignalType::Offer => {
                        return Err((
                            Some(SignalErrorCode::IncomingConnectionIgnored),
                            NethernetError::Other("received offer while dialing".to_string()),
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            (
                Some(SignalErrorCode::NegotiationTimeoutWaitingForResponse),
                NethernetError::Timeout,
            )
        })??;

        let description = Description::parse(&answer)
            .map_err(|e| (Some(SignalErrorCode::FailedToSetRemoteDescription), e))?;

        let mut local = Addr::new(signaling.network_id(), connection_id);
        local.candidates = candidates;

        let session = Arc::new(Session::new(
            transports.ice.clone(),
            transports.dtls.clone(),
            transports.sctp.clone(),
            local,
            Addr::new(remote_network_id.to_string(), connection_id),
        ));

        let mut candidate_received = false;
        for candidate in description
            .candidates
            .iter()
            .cloned()
            .chain(pending_candidates)
        {
            if let Err(e) = session.add_remote_candidate(candidate).await {
                tracing::warn!("Failed to add remote candidate: {}", e);
                continue;
            }
            candidate_received = true;
        }

        let (candidate_tx, candidate_rx) = oneshot::channel();
        let session_clone = session.clone();
        let remote_network_id = remote_network_id.to_string();
        tokio::spawn(async move {
            let mut candidate_tx = Some(candidate_tx);
            loop {
                let signal = tokio::select! {
                    _ = session_clone.closed() => break,
                    signal = signals.next() => match signal {
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
                if signal.connection_id != connection_id
                    || signal.network_id != remote_network_id
                    || signal.signal_type != SignalType::Candidate
                {
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
        });

        if !candidate_received {
            tokio::time::timeout(config.timeouts.candidate, candidate_rx)
                .await
                .map_err(|_| {
                    (
                        Some(SignalErrorCode::InactivityTimeout),
                        NethernetError::Timeout,
                    )
                })?
                .map_err(|_| (None, NethernetError::ConnectionClosed))?;
        }
        tracing::debug!("Received first candidate");

        start_transport(
            transports
                .ice
                .start(&description.ice, Some(RTCIceRole::Controlling)),
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

        let reliable = Arc::new(
            transports
                .api
                .new_data_channel(
                    transports.sctp.clone(),
                    DataChannelParameters {
                        label: RELIABLE_CHANNEL.to_string(),
                        ordered: true,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| (Some(SignalErrorCode::Ice), NethernetError::WebRtc(e)))?,
        );
        let unreliable = Arc::new(
            transports
                .api
                .new_data_channel(
                    transports.sctp.clone(),
                    DataChannelParameters {
                        label: UNRELIABLE_CHANNEL.to_string(),
                        max_retransmits: Some(0),
                        negotiated: Some(reliable.id() + 2),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| (Some(SignalErrorCode::Ice), NethernetError::WebRtc(e)))?,
        );

        session
            .set_reliable_channel(reliable)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;
        session
            .set_unreliable_channel(unreliable)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;

        Ok(Self::from_session(session))
    }

    /// Constructs a NethernetStream from an existing Session.
    pub fn from_session(session: Arc<Session>) -> Self {
        let session_clone = session.clone();
        let recv_future = ReusableBoxFuture::new(async move { session_clone.recv().await });

        let stream = SessionStream {
            session: session.clone(),
            recv_future,
        };

        Self {
            session,
            reader: StreamReader::new(stream),
            send_future: None,
            shutdown_future: None,
        }
    }

    /// Transmits a payload to the remote endpoint associated with this stream.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.session.send(data).await
    }

    /// Transmits a payload over the unreliable data channel of this stream.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.session.send_unreliable(data).await
    }

    /// Receive the next available data frame from the unreliable data channel.
    pub async fn recv_unreliable(&self) -> Result<Option<Bytes>> {
        self.session.recv_unreliable().await
    }

    /// Receive the next available data frame from this stream.
    pub async fn recv(&self) -> Result<Option<Bytes>> {
        self.session.recv().await
    }

    /// Close the stream and its underlying session.
    pub async fn close(&self) -> Result<()> {
        self.session.close().await
    }

    /// Get the address of the remote endpoint for this stream.
    pub async fn remote_addr(&self) -> Addr {
        self.session.remote_addr().await
    }

    /// Get the local address of this stream.
    pub async fn local_addr(&self) -> Addr {
        self.session.local_addr().await
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
