pub mod listener;
pub mod stream;

pub use listener::NethernetListener;
pub use stream::NethernetStream;

use crate::credentials::{Credentials, gather_options};
use crate::error::{NethernetError, Result};
use crate::protocol::constants::SCTP_MAX_MESSAGE_SIZE;
use crate::protocol::webrtc::Description;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{API, APIBuilder};
use webrtc::dtls_transport::RTCDtlsTransport;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice_transport::RTCIceTransport;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_gatherer::RTCIceGatherer;
use webrtc::ice_transport::ice_parameters::RTCIceParameters;
use webrtc::sctp_transport::RTCSctpTransport;
use webrtc::sctp_transport::sctp_transport_capabilities::SCTPTransportCapabilities;

/// Timeouts applied while negotiating and establishing a connection.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionConfig {
    /// Time to wait for the answer of the remote connection. Only used while dialing.
    pub negotiation_timeout: Duration,

    /// Time to wait for the first candidate signaled by the remote connection.
    pub candidate_timeout: Duration,

    /// Time to wait for each transport to start.
    pub start_timeout: Duration,

    /// Time to wait for the data channels created by the remote connection. Only used
    /// while listening, as the dialing side creates them itself.
    pub channel_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            negotiation_timeout: Duration::from_secs(15),
            candidate_timeout: Duration::from_secs(5),
            start_timeout: Duration::from_secs(5),
            channel_timeout: Duration::from_secs(5),
        }
    }
}

/// The transports backing a single connection.
///
/// NetherNet does not use a peer connection, as it does not allow signaling a session
/// description with the exact layout expected by vanilla clients. The transports are
/// therefore created and started directly.
pub(crate) struct Transports {
    pub(crate) api: API,
    pub(crate) gatherer: Arc<RTCIceGatherer>,
    pub(crate) ice: Arc<RTCIceTransport>,
    pub(crate) dtls: Arc<RTCDtlsTransport>,
    pub(crate) sctp: Arc<RTCSctpTransport>,
}

impl Transports {
    pub(crate) fn new(
        setting_engine: SettingEngine,
        credentials: Option<&Credentials>,
    ) -> Result<Self> {
        let api = APIBuilder::new()
            .with_media_engine(MediaEngine::default())
            .with_setting_engine(setting_engine)
            .build();

        let gatherer = Arc::new(api.new_ice_gatherer(gather_options(credentials))?);
        let ice = Arc::new(api.new_ice_transport(gatherer.clone()));
        let dtls = Arc::new(api.new_dtls_transport(ice.clone(), vec![])?);
        let sctp = Arc::new(api.new_sctp_transport(dtls.clone())?);

        Ok(Self {
            api,
            gatherer,
            ice,
            dtls,
            sctp,
        })
    }

    /// Gathers the local candidates and returns them along with the local ICE parameters.
    pub(crate) async fn gather(&self) -> Result<(Vec<RTCIceCandidate>, RTCIceParameters)> {
        let (finished_tx, finished_rx) = oneshot::channel();
        let finished_tx = Arc::new(tokio::sync::Mutex::new(Some(finished_tx)));

        self.gatherer
            .on_local_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
                let finished_tx = finished_tx.clone();
                Box::pin(async move {
                    if candidate.is_none()
                        && let Some(tx) = finished_tx.lock().await.take()
                    {
                        let _ = tx.send(());
                    }
                })
            }));

        self.gatherer.gather().await?;
        let _ = finished_rx.await;

        Ok((
            self.gatherer.get_local_candidates().await?,
            self.gatherer.get_local_parameters().await?,
        ))
    }

    /// Builds the description to be signaled as an offer or an answer. The DTLS role is
    /// the role the local connection announces, not the role it ends up acting as.
    pub(crate) fn local_description(
        &self,
        ice: RTCIceParameters,
        role: DTLSRole,
    ) -> Result<Description> {
        let mut dtls = self.dtls.get_local_parameters()?;
        if dtls.fingerprints.is_empty() {
            return Err(NethernetError::Dtls(
                "local DTLS parameters have no fingerprints".to_string(),
            ));
        }
        dtls.role = role;

        Ok(Description {
            ice,
            dtls,
            sctp: SCTPTransportCapabilities {
                max_message_size: SCTP_MAX_MESSAGE_SIZE,
            },
        })
    }
}
