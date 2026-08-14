//! ICE candidate wire format used by NetherNet.
//!
//! Candidates are signaled as plain strings in the format produced by the C++
//! implementation of WebRTC. Candidates in any other representation are ignored
//! by vanilla clients.

use crate::error::{NethernetError, Result};
use std::fmt::Write;
use std::sync::Arc;
use webrtc::ice::candidate::Candidate;
use webrtc::ice::candidate::candidate_base::unmarshal_candidate;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType;

/// Formats a locally gathered candidate for a `CANDIDATEADD` signal. The index is
/// the position of the candidate within the locally gathered candidates and the
/// ufrag is the username fragment of the local ICE parameters.
pub fn format_ice_candidate(index: usize, candidate: &RTCIceCandidate, ufrag: &str) -> String {
    let mut s = String::with_capacity(160);
    let _ = write!(
        s,
        "candidate:{} 1 {} {} {} {} typ {} ",
        candidate.foundation,
        candidate.protocol,
        candidate.priority,
        candidate.address,
        candidate.port,
        candidate.typ
    );
    if matches!(
        candidate.typ,
        RTCIceCandidateType::Relay | RTCIceCandidateType::Srflx
    ) {
        let _ = write!(
            s,
            "raddr {} rport {} ",
            candidate.related_address, candidate.related_port
        );
    }
    let _ = write!(
        s,
        "generation 0 ufrag {} network-id {} network-cost 0",
        ufrag, index
    );
    s
}

/// Parses a candidate signaled by a remote connection.
pub fn parse_ice_candidate(data: &str) -> Result<RTCIceCandidate> {
    let raw = data.strip_prefix("candidate:").unwrap_or(data);
    let candidate: Arc<dyn Candidate + Send + Sync> = Arc::new(
        unmarshal_candidate(raw)
            .map_err(|e| NethernetError::Other(format!("decode candidate: {}", e)))?,
    );
    Ok(RTCIceCandidate::from(&candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc::ice_transport::ice_protocol::RTCIceProtocol;

    #[test]
    fn host_candidate() {
        let candidate = RTCIceCandidate {
            foundation: "1234567890".to_string(),
            priority: 2130706431,
            address: "192.168.1.10".to_string(),
            protocol: RTCIceProtocol::Udp,
            port: 54321,
            typ: RTCIceCandidateType::Host,
            ..Default::default()
        };

        assert_eq!(
            format_ice_candidate(0, &candidate, "abcd"),
            "candidate:1234567890 1 udp 2130706431 192.168.1.10 54321 typ host generation 0 ufrag abcd network-id 0 network-cost 0"
        );
    }

    #[test]
    fn server_reflexive_candidate_has_related_address() {
        let candidate = RTCIceCandidate {
            foundation: "42".to_string(),
            priority: 1694498815,
            address: "203.0.113.5".to_string(),
            protocol: RTCIceProtocol::Udp,
            port: 40000,
            typ: RTCIceCandidateType::Srflx,
            related_address: "192.168.1.10".to_string(),
            related_port: 54321,
            ..Default::default()
        };

        assert_eq!(
            format_ice_candidate(1, &candidate, "efgh"),
            "candidate:42 1 udp 1694498815 203.0.113.5 40000 typ srflx raddr 192.168.1.10 rport 54321 generation 0 ufrag efgh network-id 1 network-cost 0"
        );
    }
}
