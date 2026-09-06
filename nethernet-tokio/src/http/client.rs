//! Connecting out to a partner's NetherNet HTTP signaling endpoint (the guide's
//! section 4): a capability check, then a single POST carrying the offer SDP and
//! receiving the answer SDP back in the response.

use reqwest::{Client, StatusCode};
use url::Url;

/// Maximum accepted size of an answer SDP body, guarding against a misbehaving or
/// malicious endpoint.
const MAX_SDP_SIZE: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("build join URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("signaling failed with status {0}")]
    Failed(StatusCode),
    #[error("answer exceeds {MAX_SDP_SIZE} bytes")]
    AnswerTooLarge,
}

/// Checks whether `base_url` supports NetherNet HTTP signaling (guide section 4,
/// "Capability Check"): `GET {serverUrl}/v1/join` returning a `2xx` status. The
/// response body is ignored, matching the guide.
pub async fn supports_nethernet(client: &Client, base_url: &Url) -> bool {
    let Ok(url) = base_url.join("v1/join") else {
        return false;
    };
    client
        .get(url)
        .send()
        .await
        .map(|response| response.status().is_success())
        .unwrap_or(false)
}

/// Sends `offer_sdp` to `base_url`'s `/v1/join/{network_id}` endpoint and returns the
/// answer SDP (guide section 4, "SDP Exchange"): a single POST, `Content-Type:
/// application/sdp`, the complete offer (full ICE, every candidate already gathered)
/// as the body. Any non-2xx response is treated as a signaling failure, per the guide -
/// the client does not retry.
pub async fn join(
    client: &Client,
    base_url: &Url,
    network_id: u64,
    offer_sdp: String,
) -> Result<String, ClientError> {
    let url = base_url.join(&format!("v1/join/{network_id}"))?;

    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/sdp")
        .body(offer_sdp)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(ClientError::Failed(status));
    }

    let answer = response.text().await?;
    if answer.len() > MAX_SDP_SIZE {
        return Err(ClientError::AnswerTooLarge);
    }

    Ok(answer)
}
