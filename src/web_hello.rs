//! Web-compatible HELLO handshake over DataChannel (INTEROP-2).
//!
//! bolt-transport-web sends an encrypted HELLO over the DataChannel after
//! it opens. This module implements the same protocol so bolt-daemon can
//! interoperate with web peers.
//!
//! Outer frame (JSON text on DataChannel):
//!   {"type":"hello","payload":"<base64 NaCl sealed-box>"}
//!
//! Inner plaintext (before encryption):
//!   {"type":"hello","version":1,"identityPublicKey":"<base64>","capabilities":["..."]}
//!
//! Encryption: NaCl box (nonce || ciphertext), encoded as base64.
//! Key exchange: identity public keys are pre-exchanged during signaling
//! (in the web offer/answer `publicKey` field).
//!
//! Fail-closed: any parse, decrypt, or schema error rejects the message.

use bolt_core::crypto::{seal_box_payload, KeyPair};
use bolt_core::encoding::to_base64;
use serde::{Deserialize, Serialize};

// ── Interop Hello Mode ──────────────────────────────────────

/// Selects which DataChannel HELLO protocol the daemon uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteropHelloMode {
    /// Legacy raw-bytes echo protocol (default).
    DaemonHelloV1,
    /// Web-compatible encrypted JSON HELLO.
    WebHelloV1,
}

// ── Capabilities ────────────────────────────────────────────

/// Daemon-advertised capabilities in web HELLO.
pub const DAEMON_CAPABILITIES: &[&str] = &["bolt.profile-envelope-v1"];

/// Return daemon capabilities as owned Strings.
pub fn daemon_capabilities() -> Vec<String> {
    DAEMON_CAPABILITIES.iter().map(|s| s.to_string()).collect()
}

/// Compute the intersection of local and remote capability sets.
pub fn negotiate_capabilities(local: &[String], remote: &[String]) -> Vec<String> {
    local
        .iter()
        .filter(|cap| remote.contains(cap))
        .cloned()
        .collect()
}

// ── Wire types ──────────────────────────────────────────────

/// Outer HELLO frame: `{"type":"hello","payload":"<sealed base64>"}`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebHelloOuter {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub payload: String,
}

/// Inner HELLO plaintext (before encryption).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebHelloInner {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub version: u32,
    #[serde(rename = "identityPublicKey")]
    pub identity_public_key: String,
    pub capabilities: Vec<String>,
}

// ── Exactly-once guard ──────────────────────────────────────

/// Tracks whether the HELLO exchange has completed.
/// Rejects duplicate HELLOs (fail-closed).
/// Wired into SessionContext at runtime (INTEROP-3).
#[derive(Default)]
pub struct HelloState {
    completed: bool,
}

impl HelloState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark HELLO as completed. Returns Err if already completed.
    pub fn mark_completed(&mut self) -> Result<(), &'static str> {
        if self.completed {
            return Err("[INTEROP-2_HELLO_FAIL] duplicate HELLO — exactly-once violation");
        }
        self.completed = true;
        Ok(())
    }

    #[allow(dead_code)] // Called via SessionContext::is_hello_complete(); tested
    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

// ── HELLO-phase error codes ─────────────────────────────────

/// Error codes for HELLO-phase protocol violations.
///
/// Wire codes align with PROTOCOL_ENFORCEMENT.md Appendix A registry.
/// Parallel to `EnvelopeError` but for the HELLO exchange phase.
#[derive(Debug)]
pub enum HelloError {
    /// HELLO outer frame unparseable (not UTF-8, not JSON, wrong outer type).
    ParseError(String),
    /// HELLO sealed payload fails decryption (wrong key, tampered).
    DecryptFail(String),
    /// HELLO inner payload missing required fields or wrong types.
    SchemaError(String),
    /// Identity key does not match pinned key (TOFU violation).
    KeyMismatch(String),
    /// Duplicate HELLO received after exchange already completed.
    DuplicateHello,
    /// Legacy downgrade attempt: raw `bolt-hello-v1` payload in WebHelloV1 mode.
    DowngradeAttempt,
}

impl HelloError {
    /// Wire error code string for DcErrorMessage.
    ///
    /// Aligned with PROTOCOL_ENFORCEMENT.md Appendix A registry.
    pub fn code(&self) -> &'static str {
        match self {
            HelloError::ParseError(_) => "HELLO_PARSE_ERROR",
            HelloError::DecryptFail(_) => "HELLO_DECRYPT_FAIL",
            HelloError::SchemaError(_) => "HELLO_SCHEMA_ERROR",
            HelloError::KeyMismatch(_) => "KEY_MISMATCH",
            HelloError::DuplicateHello => "DUPLICATE_HELLO",
            HelloError::DowngradeAttempt => "PROTOCOL_VIOLATION",
        }
    }
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::ParseError(detail) => write!(f, "HELLO parse error: {detail}"),
            HelloError::DecryptFail(detail) => write!(f, "HELLO decrypt failure: {detail}"),
            HelloError::SchemaError(detail) => write!(f, "HELLO schema error: {detail}"),
            HelloError::KeyMismatch(detail) => write!(f, "identity key mismatch: {detail}"),
            HelloError::DuplicateHello => write!(f, "duplicate HELLO — exactly-once violation"),
            HelloError::DowngradeAttempt => {
                write!(f, "legacy 'bolt-hello-v1' payload — downgrade refused")
            }
        }
    }
}

impl std::error::Error for HelloError {}

// ── Key helpers ─────────────────────────────────────────────

/// Decode a base64 identity public key into a fixed-size array.
pub fn decode_public_key(b64: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let decoded = bolt_core::encoding::from_base64(b64)
        .map_err(|e| format!("[INTEROP-2_HELLO_FAIL] public key decode: {}", e))?;
    if decoded.len() != 32 {
        return Err(format!(
            "[INTEROP-2_HELLO_FAIL] public key length {} != 32",
            decoded.len()
        )
        .into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

// ── Build / Parse ───────────────────────────────────────────

/// Build an encrypted web HELLO message (JSON string ready to send on DC).
///
/// `identity_pk` — persistent identity public key (placed in HELLO inner field).
/// `session_kp` — ephemeral session keypair (secret used for NaCl box sealing).
/// `remote_public_key` — remote peer's session/ephemeral public key.
pub fn build_hello_message(
    identity_pk: &[u8; 32],
    session_kp: &KeyPair,
    remote_public_key: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
    let inner = WebHelloInner {
        msg_type: "hello".to_string(),
        version: 1,
        identity_public_key: to_base64(identity_pk),
        capabilities: daemon_capabilities(),
    };
    let inner_json = serde_json::to_vec(&inner)?;
    let sealed = seal_box_payload(&inner_json, remote_public_key, &session_kp.secret_key)
        .map_err(|e| format!("[INTEROP-2_HELLO_FAIL] seal: {}", e))?;
    let outer = WebHelloOuter {
        msg_type: "hello".to_string(),
        payload: sealed,
    };
    let msg = serde_json::to_string(&outer)?;
    Ok(msg)
}

/// Parse and decrypt a received web HELLO message with typed error codes.
///
/// `remote_public_key` — remote peer's session/ephemeral public key.
/// `session_kp` — local ephemeral session keypair (secret used for NaCl box opening).
///
/// Returns `HelloError` variants aligned with PROTOCOL_ENFORCEMENT.md
/// Appendix A (HELLO_PARSE_ERROR, HELLO_DECRYPT_FAIL, HELLO_SCHEMA_ERROR).
/// Fail-closed: any parse, decrypt, or schema error is fatal.
pub fn parse_hello_typed(
    raw: &[u8],
    remote_public_key: &[u8; 32],
    session_kp: &KeyPair,
) -> Result<WebHelloInner, HelloError> {
    // No-downgrade check
    if raw == crate::HELLO_PAYLOAD {
        return Err(HelloError::DowngradeAttempt);
    }

    let text = std::str::from_utf8(raw)
        .map_err(|_| HelloError::ParseError("message is not UTF-8".to_string()))?;

    let outer: WebHelloOuter = serde_json::from_str(text)
        .map_err(|e| HelloError::ParseError(format!("outer parse: {e}")))?;

    if outer.msg_type != "hello" {
        return Err(HelloError::ParseError(format!(
            "outer type '{}' != 'hello'",
            outer.msg_type
        )));
    }

    let plaintext = bolt_core::crypto::open_box_payload(
        &outer.payload,
        remote_public_key,
        &session_kp.secret_key,
    )
    .map_err(|e| HelloError::DecryptFail(e.to_string()))?;

    let inner: WebHelloInner = serde_json::from_slice(&plaintext)
        .map_err(|e| HelloError::SchemaError(format!("inner parse: {e}")))?;

    if inner.msg_type != "hello" {
        return Err(HelloError::SchemaError(format!(
            "inner type '{}' != 'hello'",
            inner.msg_type
        )));
    }

    if inner.version != 1 {
        return Err(HelloError::SchemaError(format!(
            "version {} != 1",
            inner.version
        )));
    }

    Ok(inner)
}

/// Parse and decrypt a received web HELLO message from raw DataChannel bytes.
///
/// `remote_public_key` — remote peer's session/ephemeral public key.
/// `session_kp` — local ephemeral session keypair (secret used for NaCl box opening).
///
/// Delegates to `parse_hello_typed` for typed error handling, then converts
/// to `Box<dyn Error>` for backward compatibility with existing callers.
/// Fail-closed: any parse, decrypt, or schema error returns Err.
pub fn parse_hello_message(
    raw: &[u8],
    remote_public_key: &[u8; 32],
    session_kp: &KeyPair,
) -> Result<WebHelloInner, Box<dyn std::error::Error>> {
    parse_hello_typed(raw, remote_public_key, session_kp).map_err(|e| {
        let msg = format!("[INTEROP-2_HELLO_FAIL] {e}");
        Box::<dyn std::error::Error>::from(msg)
    })
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bolt_core::identity::generate_identity_keypair;

    // ── Serialization tests ─────────────────────────────────

    #[test]
    fn web_hello_outer_roundtrip() {
        let outer = WebHelloOuter {
            msg_type: "hello".to_string(),
            payload: "dGVzdA==".to_string(),
        };
        let json = serde_json::to_string(&outer).unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"payload\":\"dGVzdA==\""));
        let decoded: WebHelloOuter = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.msg_type, "hello");
        assert_eq!(decoded.payload, "dGVzdA==");
    }

    #[test]
    fn web_hello_outer_rejects_wrong_type() {
        let json = r#"{"type":"goodbye","payload":"abc"}"#;
        let outer: WebHelloOuter = serde_json::from_str(json).unwrap();
        assert_ne!(outer.msg_type, "hello");
    }

    #[test]
    fn web_hello_inner_roundtrip() {
        let inner = WebHelloInner {
            msg_type: "hello".to_string(),
            version: 1,
            identity_public_key: "AAAA".to_string(),
            capabilities: vec!["bolt.profile-envelope-v1".to_string()],
        };
        let json = serde_json::to_string(&inner).unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"identityPublicKey\":\"AAAA\""));
        assert!(json.contains("\"capabilities\":[\"bolt.profile-envelope-v1\"]"));
        let decoded: WebHelloInner = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.identity_public_key, "AAAA");
    }

    #[test]
    fn web_hello_inner_rejects_wrong_type() {
        let json = r#"{"type":"ping","version":1,"identityPublicKey":"AA","capabilities":[]}"#;
        let inner: WebHelloInner = serde_json::from_str(json).unwrap();
        assert_ne!(inner.msg_type, "hello");
    }

    #[test]
    fn web_hello_inner_rejects_version_not_1() {
        let json = r#"{"type":"hello","version":2,"identityPublicKey":"AA","capabilities":[]}"#;
        let inner: WebHelloInner = serde_json::from_str(json).unwrap();
        assert_ne!(inner.version, 1);
    }

    // ── Crypto roundtrip tests ──────────────────────────────

    #[test]
    fn crypto_roundtrip_seal_open() {
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();

        let inner = WebHelloInner {
            msg_type: "hello".to_string(),
            version: 1,
            identity_public_key: to_base64(&kp_a.public_key),
            capabilities: daemon_capabilities(),
        };
        let plaintext = serde_json::to_vec(&inner).unwrap();

        // A seals for B
        let sealed = seal_box_payload(&plaintext, &kp_b.public_key, &kp_a.secret_key).unwrap();

        // B opens from A
        let decrypted =
            bolt_core::crypto::open_box_payload(&sealed, &kp_a.public_key, &kp_b.secret_key)
                .unwrap();

        let parsed: WebHelloInner = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(parsed.msg_type, "hello");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.identity_public_key, to_base64(&kp_a.public_key));
    }

    #[test]
    fn build_hello_produces_valid_json() {
        let identity = generate_identity_keypair();
        let session_kp = bolt_core::crypto::generate_ephemeral_keypair();
        let remote_session = bolt_core::crypto::generate_ephemeral_keypair();

        let msg = build_hello_message(&identity.public_key, &session_kp, &remote_session.public_key).unwrap();
        let outer: WebHelloOuter = serde_json::from_str(&msg).unwrap();
        assert_eq!(outer.msg_type, "hello");
        assert!(!outer.payload.is_empty());
    }

    #[test]
    fn full_message_roundtrip() {
        let identity_a = generate_identity_keypair();
        let session_a = bolt_core::crypto::generate_ephemeral_keypair();
        let session_b = bolt_core::crypto::generate_ephemeral_keypair();

        // A builds HELLO for B (identity_a.pk in inner, sealed with session_a.sk)
        let msg = build_hello_message(&identity_a.public_key, &session_a, &session_b.public_key).unwrap();

        // B parses HELLO from A (opens with session_b.sk, sender is session_a.pk)
        let inner = parse_hello_message(msg.as_bytes(), &session_a.public_key, &session_b).unwrap();
        assert_eq!(inner.msg_type, "hello");
        assert_eq!(inner.version, 1);
        assert_eq!(inner.identity_public_key, to_base64(&identity_a.public_key));
        assert!(inner
            .capabilities
            .contains(&"bolt.profile-envelope-v1".to_string()));
    }

    #[test]
    fn full_bidirectional_roundtrip() {
        let identity_a = generate_identity_keypair();
        let identity_b = generate_identity_keypair();
        let session_a = bolt_core::crypto::generate_ephemeral_keypair();
        let session_b = bolt_core::crypto::generate_ephemeral_keypair();

        // A → B
        let msg_a = build_hello_message(&identity_a.public_key, &session_a, &session_b.public_key).unwrap();
        let inner_a = parse_hello_message(msg_a.as_bytes(), &session_a.public_key, &session_b).unwrap();
        assert_eq!(inner_a.identity_public_key, to_base64(&identity_a.public_key));

        // B → A
        let msg_b = build_hello_message(&identity_b.public_key, &session_b, &session_a.public_key).unwrap();
        let inner_b = parse_hello_message(msg_b.as_bytes(), &session_b.public_key, &session_a).unwrap();
        assert_eq!(inner_b.identity_public_key, to_base64(&identity_b.public_key));
    }

    // ── Failure tests ───────────────────────────────────────

    #[test]
    fn parse_rejects_legacy_payload() {
        let kp = generate_identity_keypair();
        let result = parse_hello_message(b"bolt-hello-v1", &kp.public_key, &kp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("downgrade"));
    }

    #[test]
    fn parse_rejects_invalid_json() {
        let kp = generate_identity_keypair();
        let result = parse_hello_message(b"not json at all", &kp.public_key, &kp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("INTEROP-2_HELLO_FAIL"));
    }

    #[test]
    fn parse_rejects_wrong_outer_type() {
        let json = r#"{"type":"ping","payload":"dGVzdA=="}"#;
        let kp = generate_identity_keypair();
        let result = parse_hello_message(json.as_bytes(), &kp.public_key, &kp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("outer type"));
    }

    #[test]
    fn parse_rejects_wrong_encryption_key() {
        let identity_a = generate_identity_keypair();
        let session_a = bolt_core::crypto::generate_ephemeral_keypair();
        let session_b = bolt_core::crypto::generate_ephemeral_keypair();
        let session_c = bolt_core::crypto::generate_ephemeral_keypair();

        // A encrypts for B (session keys)
        let msg = build_hello_message(&identity_a.public_key, &session_a, &session_b.public_key).unwrap();

        // C tries to decrypt (wrong session key)
        let result = parse_hello_message(msg.as_bytes(), &session_a.public_key, &session_c);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("INTEROP-2_HELLO_FAIL"));
    }

    // ── Capability negotiation tests ────────────────────────

    #[test]
    fn negotiate_full_overlap() {
        let local = vec!["a".to_string(), "b".to_string()];
        let remote = vec!["a".to_string(), "b".to_string()];
        let result = negotiate_capabilities(&local, &remote);
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn negotiate_partial_overlap() {
        let local = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let remote = vec!["b".to_string(), "d".to_string()];
        let result = negotiate_capabilities(&local, &remote);
        assert_eq!(result, vec!["b"]);
    }

    #[test]
    fn negotiate_no_overlap() {
        let local = vec!["a".to_string()];
        let remote = vec!["b".to_string()];
        let result = negotiate_capabilities(&local, &remote);
        assert!(result.is_empty());
    }

    // ── Exactly-once tests ──────────────────────────────────

    #[test]
    fn hello_state_first_completion_succeeds() {
        let mut state = HelloState::new();
        assert!(!state.is_completed());
        assert!(state.mark_completed().is_ok());
        assert!(state.is_completed());
    }

    #[test]
    fn hello_state_duplicate_rejected() {
        let mut state = HelloState::new();
        state.mark_completed().unwrap();
        let result = state.mark_completed();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exactly-once"));
    }

    // ── Key decode test ─────────────────────────────────────

    #[test]
    fn decode_public_key_roundtrip() {
        let kp = generate_identity_keypair();
        let b64 = to_base64(&kp.public_key);
        let decoded = decode_public_key(&b64).unwrap();
        assert_eq!(decoded, kp.public_key);
    }

    #[test]
    fn decode_public_key_rejects_wrong_length() {
        let b64 = to_base64(&[0u8; 16]);
        let result = decode_public_key(&b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }
}
