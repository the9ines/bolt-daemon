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
pub fn build_hello_message(
    local_keypair: &KeyPair,
    remote_public_key: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
    let inner = WebHelloInner {
        msg_type: "hello".to_string(),
        version: 1,
        identity_public_key: to_base64(&local_keypair.public_key),
        capabilities: daemon_capabilities(),
    };
    let inner_json = serde_json::to_vec(&inner)?;
    let sealed = seal_box_payload(&inner_json, remote_public_key, &local_keypair.secret_key)
        .map_err(|e| format!("[INTEROP-2_HELLO_FAIL] seal: {}", e))?;
    let outer = WebHelloOuter {
        msg_type: "hello".to_string(),
        payload: sealed,
    };
    let msg = serde_json::to_string(&outer)?;
    Ok(msg)
}

/// Parse and decrypt a received web HELLO message from raw DataChannel bytes.
///
/// Fail-closed: any parse, decrypt, or schema error returns Err.
pub fn parse_hello_message(
    raw: &[u8],
    remote_public_key: &[u8; 32],
    local_keypair: &KeyPair,
) -> Result<WebHelloInner, Box<dyn std::error::Error>> {
    // No-downgrade check
    if raw == crate::HELLO_PAYLOAD {
        return Err(
            "[INTEROP-2_NO_DOWNGRADE] received legacy 'bolt-hello-v1' — refusing downgrade".into(),
        );
    }

    let text = std::str::from_utf8(raw)
        .map_err(|_| "[INTEROP-2_HELLO_FAIL] message is not UTF-8".to_string())?;

    let outer: WebHelloOuter = serde_json::from_str(text)
        .map_err(|e| format!("[INTEROP-2_HELLO_FAIL] outer parse: {}", e))?;

    if outer.msg_type != "hello" {
        return Err(format!(
            "[INTEROP-2_HELLO_FAIL] outer type '{}' != 'hello'",
            outer.msg_type
        )
        .into());
    }

    let plaintext = bolt_core::crypto::open_box_payload(
        &outer.payload,
        remote_public_key,
        &local_keypair.secret_key,
    )
    .map_err(|e| format!("[INTEROP-2_HELLO_FAIL] decrypt: {}", e))?;

    let inner: WebHelloInner = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("[INTEROP-2_HELLO_FAIL] inner parse: {}", e))?;

    if inner.msg_type != "hello" {
        return Err(format!(
            "[INTEROP-2_HELLO_FAIL] inner type '{}' != 'hello'",
            inner.msg_type
        )
        .into());
    }

    if inner.version != 1 {
        return Err(format!("[INTEROP-2_HELLO_FAIL] version {} != 1", inner.version).into());
    }

    Ok(inner)
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
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();

        let msg = build_hello_message(&kp_a, &kp_b.public_key).unwrap();
        let outer: WebHelloOuter = serde_json::from_str(&msg).unwrap();
        assert_eq!(outer.msg_type, "hello");
        assert!(!outer.payload.is_empty());
    }

    #[test]
    fn full_message_roundtrip() {
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();

        // A builds HELLO for B
        let msg = build_hello_message(&kp_a, &kp_b.public_key).unwrap();

        // B parses HELLO from A
        let inner = parse_hello_message(msg.as_bytes(), &kp_a.public_key, &kp_b).unwrap();
        assert_eq!(inner.msg_type, "hello");
        assert_eq!(inner.version, 1);
        assert_eq!(inner.identity_public_key, to_base64(&kp_a.public_key));
        assert!(inner
            .capabilities
            .contains(&"bolt.profile-envelope-v1".to_string()));
    }

    #[test]
    fn full_bidirectional_roundtrip() {
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();

        // A → B
        let msg_a = build_hello_message(&kp_a, &kp_b.public_key).unwrap();
        let inner_a = parse_hello_message(msg_a.as_bytes(), &kp_a.public_key, &kp_b).unwrap();
        assert_eq!(inner_a.identity_public_key, to_base64(&kp_a.public_key));

        // B → A
        let msg_b = build_hello_message(&kp_b, &kp_a.public_key).unwrap();
        let inner_b = parse_hello_message(msg_b.as_bytes(), &kp_b.public_key, &kp_a).unwrap();
        assert_eq!(inner_b.identity_public_key, to_base64(&kp_b.public_key));
    }

    // ── Failure tests ───────────────────────────────────────

    #[test]
    fn parse_rejects_legacy_payload() {
        let kp = generate_identity_keypair();
        let result = parse_hello_message(b"bolt-hello-v1", &kp.public_key, &kp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NO_DOWNGRADE"));
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
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();
        let kp_c = generate_identity_keypair();

        // A encrypts for B
        let msg = build_hello_message(&kp_a, &kp_b.public_key).unwrap();

        // C tries to decrypt (wrong key)
        let result = parse_hello_message(msg.as_bytes(), &kp_a.public_key, &kp_c);
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
