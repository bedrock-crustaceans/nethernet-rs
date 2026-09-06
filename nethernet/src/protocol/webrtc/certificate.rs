//! DTLS certificate generation and fingerprinting.
//!
//! WebRTC (and NetherNet) authenticates a peer by comparing the DTLS certificate's
//! fingerprint against the one signaled in SDP, not by validating a CA chain, so a
//! fresh self-signed certificate is generated per session.

use crate::protocol::error::{ProtocolError, Result};
use rtc::dtls::crypto::Certificate;
use sha2::{Digest, Sha256};

/// Generates a fresh self-signed certificate for a single DTLS session.
pub fn generate() -> Result<Certificate> {
    Certificate::generate_self_signed(vec!["nethernet".to_string()])
        .map_err(|e| ProtocolError::Other(format!("generate certificate: {e}")))
}

/// Computes the SDP `a=fingerprint` value for a certificate: the algorithm name and
/// a colon-separated uppercase hex digest, e.g. `("sha-256", "AA:BB:CC:...")`.
pub fn fingerprint(certificate: &Certificate) -> Result<(String, String)> {
    let der = certificate
        .certificate
        .first()
        .ok_or_else(|| ProtocolError::Other("certificate has no DER bytes".to_string()))?;

    let digest = Sha256::digest(der.as_ref());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    Ok(("sha-256".to_string(), hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex() {
        let cert = generate().unwrap();
        let (algorithm, digest) = fingerprint(&cert).unwrap();

        assert_eq!(algorithm, "sha-256");
        // 32 bytes, colon-separated, uppercase hex: "AA:BB:...:FF" -> 32*2 hex chars + 31 colons.
        assert_eq!(digest.len(), 32 * 2 + 31);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
        assert_eq!(digest, digest.to_uppercase());
    }

    #[test]
    fn each_certificate_has_a_distinct_fingerprint() {
        let (_, a) = fingerprint(&generate().unwrap()).unwrap();
        let (_, b) = fingerprint(&generate().unwrap()).unwrap();
        assert_ne!(a, b);
    }
}
