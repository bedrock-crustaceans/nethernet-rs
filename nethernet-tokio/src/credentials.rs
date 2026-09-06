//! ICE server credentials used for gathering relayed candidates.

use serde::{Deserialize, Serialize};
use webrtc::ice_transport::ice_gatherer::RTCIceGatherOptions;
use webrtc::ice_transport::ice_server::RTCIceServer;

/// Credentials for the ICE servers a connection may gather candidates from.
///
/// They are typically received from a signaling connection and expire, in which case
/// new credentials must be obtained before negotiating another connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(rename = "ExpirationInSeconds")]
    pub expiration_in_seconds: i32,

    #[serde(rename = "TurnAuthServers")]
    pub ice_servers: Vec<IceServer>,
}

/// A single ICE server with the credentials required to authenticate with it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IceServer {
    #[serde(rename = "Username")]
    pub username: String,

    #[serde(rename = "Password")]
    pub password: String,

    #[serde(rename = "Urls")]
    pub urls: Vec<String>,
}

/// Transforms the credentials into the options used for gathering local candidates.
///
/// Returns the default options when no credentials are available, which gathers host
/// candidates only.
pub fn gather_options(credentials: Option<&Credentials>) -> RTCIceGatherOptions {
    let mut options = RTCIceGatherOptions::default();
    if let Some(credentials) = credentials {
        options.ice_servers = credentials
            .ice_servers
            .iter()
            .map(|server| RTCIceServer {
                urls: server.urls.clone(),
                username: server.username.clone(),
                credential: server.password.clone(),
            })
            .collect();
    }
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_credentials_gathers_host_candidates_only() {
        assert!(gather_options(None).ice_servers.is_empty());
    }

    #[test]
    fn credentials_are_mapped_to_ice_servers() {
        let credentials = Credentials {
            expiration_in_seconds: 86400,
            ice_servers: vec![IceServer {
                username: "user".to_string(),
                password: "secret".to_string(),
                urls: vec!["turn:127.0.0.1:3478".to_string()],
            }],
        };

        let options = gather_options(Some(&credentials));
        assert_eq!(options.ice_servers.len(), 1);
        assert_eq!(options.ice_servers[0].username, "user");
        assert_eq!(options.ice_servers[0].credential, "secret");
        assert_eq!(options.ice_servers[0].urls, vec!["turn:127.0.0.1:3478"]);
    }

    #[test]
    fn credentials_decode_from_signaling_json() {
        let json = r#"{"ExpirationInSeconds":86400,"TurnAuthServers":[{"Username":"user","Password":"secret","Urls":["turn:127.0.0.1:3478"]}]}"#;
        let credentials: Credentials = serde_json::from_str(json).unwrap();

        assert_eq!(credentials.expiration_in_seconds, 86400);
        assert_eq!(credentials.ice_servers[0].urls.len(), 1);
    }
}
