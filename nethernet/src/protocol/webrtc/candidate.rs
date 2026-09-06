//! ICE candidate wire format used by NetherNet.
//!
//! Candidates are signaled as plain strings in the format produced by the C++
//! implementation of WebRTC. Candidates in any other representation are ignored
//! by vanilla clients.

use crate::protocol::error::{ProtocolError, Result};
use rtc::ice::candidate::{Candidate, unmarshal_candidate};

/// Builds the candidate attribute *value* (no `candidate:` key prefix): the payload of
/// an SDP `a=candidate` line. `index` is the position of the candidate within the
/// locally gathered candidates and `ufrag` is the username fragment of the local ICE
/// parameters.
pub(crate) fn attribute_value(index: usize, candidate: &Candidate, ufrag: &str) -> String {
    format!(
        "{} generation 0 ufrag {} network-id {} network-cost 0",
        candidate.marshal(),
        ufrag,
        index
    )
}

/// Formats a locally gathered candidate for a `CANDIDATEADD` signal (LAN/trickle ICE).
pub fn format_ice_candidate(index: usize, candidate: &Candidate, ufrag: &str) -> String {
    format!("candidate:{}", attribute_value(index, candidate, ufrag))
}

/// Parses a candidate signaled by a remote connection, or embedded in an `a=candidate`
/// SDP line.
pub fn parse_ice_candidate(data: &str) -> Result<Candidate> {
    let raw = data.strip_prefix("candidate:").unwrap_or(data);
    unmarshal_candidate(raw).map_err(|e| ProtocolError::Other(format!("decode candidate: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::ice::candidate::CandidateConfig;
    use rtc::ice::candidate::candidate_host::CandidateHostConfig;
    use rtc::ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;

    #[test]
    fn host_candidate_roundtrip() {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: "192.168.1.10".to_string(),
                port: 54321,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap();

        let formatted = format_ice_candidate(0, &candidate, "abcd");
        assert!(formatted.starts_with("candidate:"));
        assert!(formatted.contains(" 1 udp "));
        assert!(formatted.contains(" 192.168.1.10 54321 typ host"));
        assert!(formatted.ends_with("ufrag abcd network-id 0 network-cost 0"));

        let parsed = parse_ice_candidate(&formatted).unwrap();
        assert_eq!(parsed.address(), "192.168.1.10");
        assert_eq!(parsed.port(), 54321);
    }

    #[test]
    fn server_reflexive_candidate_has_related_address() {
        let candidate = CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: "203.0.113.5".to_string(),
                port: 40000,
                component: 1,
                ..Default::default()
            },
            rel_addr: "192.168.1.10".to_string(),
            rel_port: 54321,
            ..Default::default()
        }
        .new_candidate_server_reflexive()
        .unwrap();

        let formatted = format_ice_candidate(1, &candidate, "efgh");
        assert!(formatted.contains(" typ srflx raddr 192.168.1.10 rport 54321 "));

        let parsed = parse_ice_candidate(&formatted).unwrap();
        assert_eq!(parsed.address(), "203.0.113.5");
        assert_eq!(parsed.related_address().unwrap().address, "192.168.1.10");
    }
}
