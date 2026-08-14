//! Signaling over the HTTP endpoints exposed by NetherNet servers.
//!
//! Dedicated servers accept an SDP offer on `/v1/join/{network id}` and answer with the
//! SDP of the connection in the response body. As a request only carries a single
//! description, candidates are embedded in it instead of being signaled separately.

use crate::error::{NethernetError, Result};
use crate::protocol::{Signal, SignalType};
use crate::signaling::Signaling;
use futures::Stream;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use std::pin::Pin;
use std::sync::Once;
use std::time::Duration;
use tokio::sync::broadcast;
use url::Url;

/// User agent of the HTTP client of Minecraft.
const CLIENT_USER_AGENT: &str = "libhttpclient/1.0.0.0";

/// Guards installation of the process-wide TLS provider.
static PROVIDER: Once = Once::new();

/// Maximum size of an SDP body accepted from a server.
const MAX_SDP_SIZE: usize = 1 << 20;

/// Signaling implementation for connecting to servers that expose an HTTP endpoint.
///
/// The network ID of a remote connection is the base URL of its endpoint, such as
/// `https://example.com:19132`, while the local network ID identifies this client to
/// the server.
pub struct HttpSignaling {
    network_id: String,
    client: Client,
    signal_tx: broadcast::Sender<Signal>,
}

impl HttpSignaling {
    /// Creates a signaling implementation using a default HTTP client.
    ///
    /// Installs the process-wide TLS provider if no other one has been installed yet,
    /// as building an HTTP client requires one.
    pub fn new(network_id: String) -> Result<Self> {
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| NethernetError::Other(format!("create HTTP client: {}", e)))?;

        Ok(Self::with_client(network_id, client))
    }

    /// Creates a signaling implementation using the given HTTP client.
    ///
    /// Building a client requires a process-wide TLS provider, which
    /// [`HttpSignaling::new`] installs.
    pub fn with_client(network_id: String, client: Client) -> Self {
        let (signal_tx, _) = broadcast::channel(16);

        Self {
            network_id,
            client,
            signal_tx,
        }
    }

    /// Returns the URL an offer for the remote network is sent to.
    fn join_url(&self, network_id: &str) -> Result<Url> {
        let url = Url::parse(network_id)
            .map_err(|e| NethernetError::Other(format!("parse network ID as URL: {}", e)))?;
        if !matches!(url.scheme(), "http" | "https") || url.port().is_none() {
            return Err(NethernetError::Other(format!(
                "network ID must be a HTTP/HTTPS URL with a port: {}",
                network_id
            )));
        }

        url.join(&format!("/v1/join/{}", self.network_id))
            .map_err(|e| NethernetError::Other(format!("build join URL: {}", e)))
    }

    /// Sends the offer to the endpoint of the remote network and returns its answer.
    async fn join(&self, signal: &Signal) -> Result<String> {
        let response = self
            .client
            .post(self.join_url(&signal.network_id)?)
            .header(CONTENT_TYPE, "application/sdp")
            .header(USER_AGENT, CLIENT_USER_AGENT)
            .body(signal.data.clone())
            .send()
            .await
            .map_err(|e| NethernetError::Other(format!("signal offer: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(NethernetError::Other(format!("signal offer: {}", status)));
        }

        let body = response
            .text()
            .await
            .map_err(|e| NethernetError::Other(format!("read answer: {}", e)))?;
        if body.is_empty() {
            return Err(NethernetError::Other(
                "missing answer in response".to_string(),
            ));
        }
        if body.len() > MAX_SDP_SIZE {
            return Err(NethernetError::Other(format!(
                "answer exceeds {} bytes",
                MAX_SDP_SIZE
            )));
        }
        // Servers report a failed negotiation by answering with an error code
        if let Ok(code) = body.trim().parse::<u32>() {
            return Err(NethernetError::Signaled(code.into()));
        }

        Ok(body)
    }
}

impl Signaling for HttpSignaling {
    /// Signals an offer to the endpoint of the remote network and notifies its answer.
    ///
    /// Only offers are supported, as an answer is the response of the request carrying
    /// the offer and candidates are embedded in both.
    async fn signal(&self, signal: Signal) -> Result<()> {
        match signal.signal_type {
            SignalType::Offer => {
                let answer = self.join(&signal).await?;
                let _ = self.signal_tx.send(Signal::answer(
                    signal.connection_id,
                    answer,
                    signal.network_id,
                ));
                Ok(())
            }
            SignalType::Error => Ok(()),
            signal_type => Err(NethernetError::Other(format!(
                "{} is not supported over HTTP signaling",
                signal_type
            ))),
        }
    }

    fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    fn network_id(&self) -> String {
        self.network_id.clone()
    }

    /// Always returns `true`, as a request carries a single description that must
    /// already contain every local candidate.
    fn disable_trickle_ice(&self) -> bool {
        true
    }

    /// Servers are not discovered over HTTP signaling, so the data is discarded.
    fn set_pong_data(&self, _data: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_is_built_from_the_network_id() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        assert_eq!(
            signaling.join_url("https://example.com:19132").unwrap(),
            Url::parse("https://example.com:19132/v1/join/1234").unwrap()
        );
    }

    #[test]
    fn join_url_rejects_network_ids_without_a_port() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        assert!(signaling.join_url("https://example.com").is_err());
        assert!(signaling.join_url("5678").is_err());
    }
}
