use crate::addr::Addr;
use crate::error::{NethernetError, Result};
use crate::protocol::constants::{RELIABLE_CHANNEL, SCTP_PORT, UNRELIABLE_CHANNEL};
use crate::protocol::webrtc::{Description, format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::session::Session;
use crate::signaling::Signaling;
use crate::transport::Transports;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use rand::Rng;
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

/// Time to wait for the answer of the remote connection.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Time to wait for the first candidate signaled by the remote connection.
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Time to wait for each transport to start.
const START_TIMEOUT: Duration = Duration::from_secs(5);

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
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_network_types(vec![NetworkType::Udp4]);

        let credentials = signaling.credentials().await?;
        let transports = Transports::new(setting_engine, credentials.as_ref())?;
        let (candidates, ice_parameters) = transports.gather().await?;

        let offer = transports
            .local_description(ice_parameters.clone(), DTLSRole::Server)?
            .encode()?;

        let mut connection_id_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut connection_id_bytes);
        let connection_id = u64::from_le_bytes(connection_id_bytes);

        let mut signals = signaling.signals();

        signaling
            .signal(Signal::offer(
                connection_id,
                offer,
                remote_network_id.clone(),
            ))
            .await?;
        for (index, candidate) in candidates.iter().enumerate() {
            signaling
                .signal(Signal::candidate(
                    connection_id,
                    format_ice_candidate(index, candidate, &ice_parameters.username_fragment),
                    remote_network_id.clone(),
                ))
                .await?;
        }

        let mut pending_candidates = Vec::new();
        let answer = tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
            loop {
                let Some(signal) = signals.next().await else {
                    return Err(NethernetError::ConnectionClosed);
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
                    SignalType::Error => return Err(NethernetError::ConnectionClosed),
                    SignalType::Offer => {}
                }
            }
        })
        .await
        .map_err(|_| NethernetError::Timeout)??;

        let description = Description::parse(&answer)?;

        let mut local = Addr::new(signaling.network_id(), connection_id);
        local.candidates = candidates;

        let session = Arc::new(Session::new(
            transports.ice.clone(),
            transports.dtls.clone(),
            transports.sctp.clone(),
            local,
            Addr::new(remote_network_id.clone(), connection_id),
        ));

        let mut candidate_received = false;
        for candidate in pending_candidates {
            if let Err(e) = session.add_remote_candidate(candidate).await {
                tracing::warn!("Failed to add remote candidate: {}", e);
                continue;
            }
            candidate_received = true;
        }

        let (candidate_tx, candidate_rx) = oneshot::channel();
        let session_clone = session.clone();
        tokio::spawn(async move {
            let mut candidate_tx = Some(candidate_tx);
            while let Some(signal) = signals.next().await {
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
            tokio::time::timeout(CANDIDATE_TIMEOUT, candidate_rx)
                .await
                .map_err(|_| NethernetError::Timeout)?
                .map_err(|_| NethernetError::ConnectionClosed)?;
        }
        tracing::debug!("Received first candidate");

        tokio::time::timeout(
            START_TIMEOUT,
            transports
                .ice
                .start(&description.ice, Some(RTCIceRole::Controlling)),
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
                .await?,
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
                .await?,
        );

        session.set_reliable_channel(reliable).await?;
        session.set_unreliable_channel(unreliable).await?;

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
