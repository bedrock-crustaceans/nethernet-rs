//! NetherNet's `a=identity` assertions (RFC 8827 section 5), authenticating both
//! directions of the HTTP signaling SDP exchange. See the NetherNet HTTP signaling
//! guide, section 5.
//!
//! This module implements the assertion's *structure* and *cryptographic mechanics* -
//! the `a=identity` envelope, the detached-JWS-over-fingerprints construction, and
//! self-signed-JWT building/verification - not *policy*. In particular, it cannot and
//! does not validate a `GameServerToken` JWT against the Minecraft auth service's keys:
//! that requires network access to a service this crate knows nothing about. Callers
//! wanting that guarantee must verify the token themselves (e.g. against a cached
//! JWKS) before trusting its claims; [`verify_self_signed`] only proves a token is
//! *internally consistent* (signed by whoever holds the private key matching its own
//! `cpk` claim), which is what the *server's own* assertion actually needs (section
//! 5.2) but is not sufficient on its own for the *client's* `GameServerToken` (section 5.1).

use crate::protocol::error::{ProtocolError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
pub use ring::signature::EcdsaKeyPair;
use ring::signature::{ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, KeyPair};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The JWA algorithm identifier NetherNet's identity assertions use throughout: ECDSA
/// over P-384 with SHA-384, in the JWS "fixed" (raw `r || s`) signature encoding.
const ALG: &str = "ES384";

/// Generates a fresh ES384 keypair for signing identity assertions, along with its
/// PKCS#8 encoding for persistence ([`load_keypair`] reloads it).
///
/// Operators should generate this once and keep it: per the guide's section 5.2,
/// rotating the keypair forces every plaintext-HTTP client to see a fresh first-use
/// trust prompt, since trust is anchored to the key, not the server.
pub fn generate_keypair() -> Result<(EcdsaKeyPair, Vec<u8>)> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
        .map_err(|_| ProtocolError::Other("generate identity keypair".to_string()))?;
    let keypair = load_keypair(pkcs8.as_ref())?;
    Ok((keypair, pkcs8.as_ref().to_vec()))
}

/// Loads a keypair from its PKCS#8 encoding, as returned by [`generate_keypair`].
pub fn load_keypair(pkcs8: &[u8]) -> Result<EcdsaKeyPair> {
    let rng = SystemRandom::new();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8, &rng)
        .map_err(|e| ProtocolError::Other(format!("load identity keypair: {e}")))
}

/// The raw (SEC1 uncompressed point) public key bytes: the value carried in the `cpk`
/// claim, base64url-encoded.
pub fn public_key_base64(keypair: &EcdsaKeyPair) -> String {
    B64.encode(keypair.public_key().as_ref())
}

/// One SDP `a=fingerprint` value: `(algorithm, digest)`, e.g. `("sha-256", "AA:BB:...")`.
pub type Fingerprint = (String, String);

/// The `idp` (identity provider) block of an `a=identity` attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub domain: String,
    pub protocol: String,
}

impl IdentityProvider {
    /// Builds an `idp` block with `protocol` fixed to `"default"`, as the guide
    /// requires.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            protocol: "default".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    idp: IdentityProvider,
    assertion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssertionBody {
    token: String,
    fingerprints: String,
}

/// An `a=identity` attribute value, decoded but not yet verified.
#[derive(Debug, Clone)]
pub struct ParsedAssertion {
    pub idp: IdentityProvider,
    /// This side's JWT, not yet verified against any issuer's keys - see the module
    /// documentation. Use [`decode_jwt_unverified`]/[`verify_jwt`]/[`verify_self_signed`]
    /// on it as your trust policy requires.
    pub token: String,
    fingerprints_jws: String,
}

impl ParsedAssertion {
    /// Verifies that this assertion's signed fingerprints match `public_key` and
    /// `fingerprints` (typically the `cpk` from [`Self::token`]'s claims, and the SDP's
    /// own `a=fingerprint` values - see
    /// [`crate::protocol::webrtc::description::Description::fingerprint`]).
    pub fn verify_fingerprints(
        &self,
        public_key: &[u8],
        fingerprints: &[Fingerprint],
    ) -> Result<()> {
        let payload = canonical_fingerprint_json(fingerprints)?;
        verify_detached(&self.fingerprints_jws, &payload, public_key)
    }
}

/// Builds the `a=identity` attribute value: signs a detached JWS over `fingerprints`
/// with `keypair`, wraps it with `token` (this side's already-encoded JWT) in the
/// assertion envelope, and encodes the result for direct use as the attribute value.
pub fn build_identity(
    idp_domain: &str,
    token: &str,
    fingerprints: &[Fingerprint],
    keypair: &EcdsaKeyPair,
) -> Result<String> {
    let payload = canonical_fingerprint_json(fingerprints)?;
    let jws = sign_detached(&payload, keypair)?;

    let body = AssertionBody {
        token: token.to_string(),
        fingerprints: jws,
    };
    let body_json = serde_json::to_string(&body)
        .map_err(|e| ProtocolError::Other(format!("encode assertion body: {e}")))?;

    let envelope = Envelope {
        idp: IdentityProvider::new(idp_domain),
        assertion: body_json,
    };
    let envelope_json = serde_json::to_string(&envelope)
        .map_err(|e| ProtocolError::Other(format!("encode identity envelope: {e}")))?;

    Ok(B64.encode(envelope_json))
}

/// Parses an `a=identity` attribute value into its envelope and assertion body,
/// without verifying anything yet.
pub fn parse_identity(value: &str) -> Result<ParsedAssertion> {
    let json = B64
        .decode(value)
        .map_err(|e| ProtocolError::Other(format!("decode a=identity: {e}")))?;
    let envelope: Envelope = serde_json::from_slice(&json)
        .map_err(|e| ProtocolError::Other(format!("parse a=identity envelope: {e}")))?;
    let body: AssertionBody = serde_json::from_str(&envelope.assertion)
        .map_err(|e| ProtocolError::Other(format!("parse assertion body: {e}")))?;

    Ok(ParsedAssertion {
        idp: envelope.idp,
        token: body.token,
        fingerprints_jws: body.fingerprints,
    })
}

/// Builds a self-signed identity JWT: `extra_claims` plus a required `cpk` (this side's
/// own public key) and `iat`, self-signed with `keypair` (whose public key must be the
/// `cpk` embedded). `exp` is a Unix timestamp; the guide's section 5.2 allows a long-
/// lived token or periodic rotation.
pub fn build_server_token(
    keypair: &EcdsaKeyPair,
    mut extra_claims: serde_json::Map<String, serde_json::Value>,
    exp: Option<u64>,
) -> Result<String> {
    extra_claims.insert(
        "cpk".to_string(),
        serde_json::Value::String(public_key_base64(keypair)),
    );
    extra_claims.insert("iat".to_string(), serde_json::Value::from(unix_now()));
    if let Some(exp) = exp {
        extra_claims.insert("exp".to_string(), serde_json::Value::from(exp));
    }

    let header_json = format!(r#"{{"alg":"{ALG}","typ":"JWT"}}"#);
    let claims_json = serde_json::to_string(&serde_json::Value::Object(extra_claims))
        .map_err(|e| ProtocolError::Other(format!("encode JWT claims: {e}")))?;

    sign_jwt(&header_json, &claims_json, keypair)
}

/// A JWT's header and claims, decoded but (depending on how you got here) not
/// necessarily signature-verified.
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: serde_json::Value,
    pub claims: serde_json::Value,
}

/// Decodes a JWT's header and claims without verifying its signature.
pub fn decode_jwt_unverified(jwt: &str) -> Result<DecodedJwt> {
    let (header_b64, payload_b64, _sig_b64) = split_jws(jwt)?;
    Ok(DecodedJwt {
        header: decode_json_segment(header_b64)?,
        claims: decode_json_segment(payload_b64)?,
    })
}

/// Verifies a JWT's signature against a known `public_key`, returning its decoded
/// header and claims on success.
pub fn verify_jwt(jwt: &str, public_key: &[u8]) -> Result<DecodedJwt> {
    let (header_b64, payload_b64, sig_b64) = split_jws(jwt)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_signature(&signing_input, sig_b64, public_key)?;

    Ok(DecodedJwt {
        header: decode_json_segment(header_b64)?,
        claims: decode_json_segment(payload_b64)?,
    })
}

/// Verifies a *self-signed* JWT: extracts its own `cpk` claim, then checks the JWT's
/// signature against that same key. This proves the token is internally consistent -
/// produced by whoever holds the `cpk` private key - which is exactly what the guide's
/// server assertion (section 5.2) needs. It does **not** prove `cpk` itself is
/// trustworthy; anchoring that trust (TLS, TOFU pinning, an allowlist, ...) is the
/// caller's policy decision.
pub fn verify_self_signed(jwt: &str) -> Result<DecodedJwt> {
    let unverified = decode_jwt_unverified(jwt)?;
    let cpk_b64 = unverified
        .claims
        .get("cpk")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::Other("JWT is missing the cpk claim".to_string()))?;
    let cpk = B64
        .decode(cpk_b64)
        .map_err(|e| ProtocolError::Other(format!("decode cpk claim: {e}")))?;

    verify_jwt(jwt, &cpk)
}

/// Canonical JSON (a subset of RFC 8785 sufficient for this fixed shape: lexicographic
/// key order, no insignificant whitespace) for a set of SDP `a=fingerprint` values, as
/// reconstructed on both sides of a detached-JWS fingerprint signature.
pub fn canonical_fingerprint_json(fingerprints: &[Fingerprint]) -> Result<String> {
    #[derive(Serialize)]
    struct Entry<'a> {
        algorithm: &'a str,
        digest: &'a str,
    }
    #[derive(Serialize)]
    struct Wrapper<'a> {
        fingerprint: Vec<Entry<'a>>,
    }

    let wrapper = Wrapper {
        fingerprint: fingerprints
            .iter()
            .map(|(algorithm, digest)| Entry { algorithm, digest })
            .collect(),
    };

    serde_json::to_string(&wrapper).map_err(|e| ProtocolError::Other(format!("{e}")))
}

fn sign_jwt(header_json: &str, payload_json: &str, keypair: &EcdsaKeyPair) -> Result<String> {
    let header_b64 = B64.encode(header_json);
    let payload_b64 = B64.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = sign(&signing_input, keypair)?;
    Ok(format!("{signing_input}.{}", B64.encode(sig)))
}

/// Signs a *detached* JWS (RFC 7515 Appendix F): `base64url(header)..base64url(sig)`,
/// with the payload segment omitted (it's reconstructed by the verifier instead).
fn sign_detached(payload_json: &str, keypair: &EcdsaKeyPair) -> Result<String> {
    let header_json = format!(r#"{{"alg":"{ALG}"}}"#);
    let header_b64 = B64.encode(&header_json);
    let payload_b64 = B64.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = sign(&signing_input, keypair)?;
    Ok(format!("{header_b64}..{}", B64.encode(sig)))
}

fn verify_detached(jws: &str, payload_json: &str, public_key: &[u8]) -> Result<()> {
    let mut parts = jws.split('.');
    let header_b64 = parts.next().ok_or_else(malformed)?;
    let empty = parts.next().ok_or_else(malformed)?;
    let sig_b64 = parts.next().ok_or_else(malformed)?;
    if !empty.is_empty() || parts.next().is_some() {
        return Err(malformed());
    }

    let payload_b64 = B64.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_signature(&signing_input, sig_b64, public_key)
}

fn sign(signing_input: &str, keypair: &EcdsaKeyPair) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    keypair
        .sign(&rng, signing_input.as_bytes())
        .map(|sig| sig.as_ref().to_vec())
        .map_err(|_| ProtocolError::Other("sign identity assertion".to_string()))
}

fn verify_signature(signing_input: &str, sig_b64: &str, public_key: &[u8]) -> Result<()> {
    let sig = B64
        .decode(sig_b64)
        .map_err(|e| ProtocolError::Other(format!("decode signature: {e}")))?;

    ring::signature::UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key)
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| ProtocolError::Other("signature verification failed".to_string()))
}

fn split_jws(jws: &str) -> Result<(&str, &str, &str)> {
    let mut parts = jws.split('.');
    let header = parts.next().ok_or_else(malformed)?;
    let payload = parts.next().ok_or_else(malformed)?;
    let sig = parts.next().ok_or_else(malformed)?;
    if parts.next().is_some() {
        return Err(malformed());
    }
    Ok((header, payload, sig))
}

fn decode_json_segment(segment: &str) -> Result<serde_json::Value> {
    let bytes = B64
        .decode(segment)
        .map_err(|e| ProtocolError::Other(format!("decode JWT segment: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ProtocolError::Other(format!("parse JWT segment: {e}")))
}

fn malformed() -> ProtocolError {
    ProtocolError::Other("malformed JWS/JWT".to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fingerprint_json_matches_the_guides_example() {
        let json = canonical_fingerprint_json(&[(
            "sha-256".to_string(),
            "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB".to_string(),
        )])
        .unwrap();

        assert_eq!(
            json,
            r#"{"fingerprint":[{"algorithm":"sha-256","digest":"4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB"}]}"#
        );
    }

    #[test]
    fn detached_jws_roundtrip() {
        let (keypair, _) = generate_keypair().unwrap();
        let fingerprints = vec![("sha-256".to_string(), "AA:BB:CC".to_string())];
        let payload = canonical_fingerprint_json(&fingerprints).unwrap();

        let jws = sign_detached(&payload, &keypair).unwrap();
        // Detached form: header..signature (payload segment empty).
        assert_eq!(jws.matches('.').count(), 2);
        assert!(jws.contains(".."));

        verify_detached(&jws, &payload, keypair.public_key().as_ref()).unwrap();
    }

    #[test]
    fn detached_jws_rejects_tampered_fingerprint() {
        let (keypair, _) = generate_keypair().unwrap();
        let fingerprints = vec![("sha-256".to_string(), "AA:BB:CC".to_string())];
        let payload = canonical_fingerprint_json(&fingerprints).unwrap();
        let jws = sign_detached(&payload, &keypair).unwrap();

        let tampered =
            canonical_fingerprint_json(&[("sha-256".to_string(), "FF:FF:FF".to_string())]).unwrap();
        assert!(verify_detached(&jws, &tampered, keypair.public_key().as_ref()).is_err());
    }

    #[test]
    fn server_token_is_self_signed_and_verifiable() {
        let (keypair, _) = generate_keypair().unwrap();
        let mut claims = serde_json::Map::new();
        claims.insert(
            "iss".to_string(),
            serde_json::Value::String("test-partner".to_string()),
        );

        let token = build_server_token(&keypair, claims, None).unwrap();
        let decoded = verify_self_signed(&token).unwrap();

        assert_eq!(decoded.claims["iss"], "test-partner");
        assert_eq!(
            decoded.claims["cpk"].as_str().unwrap(),
            public_key_base64(&keypair)
        );
    }

    #[test]
    fn server_token_with_wrong_key_fails_verification() {
        let (keypair, _) = generate_keypair().unwrap();
        let (other_keypair, _) = generate_keypair().unwrap();

        let token = build_server_token(&keypair, serde_json::Map::new(), None).unwrap();
        assert!(verify_jwt(&token, other_keypair.public_key().as_ref()).is_err());
    }

    #[test]
    fn full_assertion_roundtrip() {
        let (keypair, _) = generate_keypair().unwrap();
        let fingerprints = vec![("sha-256".to_string(), "11:22:33".to_string())];

        let token =
            build_server_token(&keypair, serde_json::Map::new(), Some(unix_now() + 3600)).unwrap();
        let identity = build_identity("partner.example", &token, &fingerprints, &keypair).unwrap();

        let parsed = parse_identity(&identity).unwrap();
        assert_eq!(parsed.idp.domain, "partner.example");
        assert_eq!(parsed.idp.protocol, "default");

        let decoded = verify_self_signed(&parsed.token).unwrap();
        let cpk = B64.decode(decoded.claims["cpk"].as_str().unwrap()).unwrap();

        parsed.verify_fingerprints(&cpk, &fingerprints).unwrap();
    }

    #[test]
    fn keypair_persists_and_reloads() {
        let (keypair, pkcs8) = generate_keypair().unwrap();
        let reloaded = load_keypair(&pkcs8).unwrap();
        assert_eq!(public_key_base64(&keypair), public_key_base64(&reloaded));
    }
}
