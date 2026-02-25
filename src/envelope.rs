//! Profile Envelope v1 codec for DataChannel messages (INTEROP-3).
//!
//! After the encrypted HELLO exchange establishes a session, all
//! DataChannel messages in web_dc_v1 mode are wrapped in a Profile
//! Envelope:
//!
//!   {"type":"profile-envelope","version":1,"encoding":"base64","payload":"<sealed>"}
//!
//! The payload is NaCl-box encrypted (same primitives as HELLO).
//! Fail-closed: any parse, version, or decrypt error is a protocol violation.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::session::SessionContext;

// ── Wire types ──────────────────────────────────────────────

/// Profile Envelope v1 outer frame.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileEnvelopeV1 {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub version: u32,
    pub encoding: String,
    pub payload: String,
}

/// DataChannel error message.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DcErrorMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub code: String,
    pub message: String,
}

// ── Envelope error ──────────────────────────────────────────

/// Error codes for envelope protocol violations.
#[derive(Debug)]
pub enum EnvelopeError {
    /// Envelope received but capability not negotiated.
    Unnegotiated,
    /// Envelope version or encoding field invalid.
    Invalid(String),
    /// Decryption failed (wrong key, tampered, etc).
    DecryptFail(String),
    /// Received message is not a profile-envelope.
    NotEnvelope,
    /// JSON parse error.
    ParseError(String),
    /// Inner message protocol error (unknown type, malformed).
    Protocol(String),
}

impl EnvelopeError {
    /// Wire error code string for DcErrorMessage.
    pub fn code(&self) -> &'static str {
        match self {
            EnvelopeError::Unnegotiated => "ENVELOPE_UNNEGOTIATED",
            EnvelopeError::Invalid(_) => "ENVELOPE_INVALID",
            EnvelopeError::DecryptFail(_) => "ENVELOPE_DECRYPT_FAIL",
            EnvelopeError::NotEnvelope => "INVALID_STATE",
            EnvelopeError::ParseError(_) => "ENVELOPE_INVALID",
            EnvelopeError::Protocol(_) => "INVALID_MESSAGE",
        }
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::Unnegotiated => {
                write!(f, "profile-envelope received but capability not negotiated")
            }
            EnvelopeError::Invalid(detail) => {
                write!(f, "invalid envelope: {detail}")
            }
            EnvelopeError::DecryptFail(detail) => {
                write!(f, "envelope decryption failed: {detail}")
            }
            EnvelopeError::NotEnvelope => {
                write!(f, "expected profile-envelope, got different message type")
            }
            EnvelopeError::ParseError(detail) => {
                write!(f, "envelope parse error: {detail}")
            }
            EnvelopeError::Protocol(detail) => {
                write!(f, "inner message protocol error: {detail}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ── Encode ──────────────────────────────────────────────────

/// Encrypt inner JSON bytes and wrap in a Profile Envelope v1.
///
/// Requires `bolt.profile-envelope-v1` to be negotiated.
/// Returns UTF-8 JSON bytes ready to send on the DataChannel.
#[allow(dead_code)] // Used in tests + will be called when file transfer sends envelopes
pub fn encode_envelope(
    inner_json: &[u8],
    session: &SessionContext,
) -> Result<Vec<u8>, EnvelopeError> {
    if !session.envelope_v1_negotiated() {
        return Err(EnvelopeError::Unnegotiated);
    }

    let sealed = bolt_core::crypto::seal_box_payload(
        inner_json,
        &session.remote_public_key,
        &session.local_keypair.secret_key,
    )
    .map_err(|e| EnvelopeError::DecryptFail(format!("seal: {e}")))?;

    let envelope = ProfileEnvelopeV1 {
        msg_type: "profile-envelope".to_string(),
        version: 1,
        encoding: "base64".to_string(),
        payload: sealed,
    };

    let json = serde_json::to_vec(&envelope)
        .map_err(|e| EnvelopeError::ParseError(format!("serialize: {e}")))?;
    Ok(json)
}

// ── Decode ──────────────────────────────────────────────────

/// Decrypt a Profile Envelope v1 from raw DataChannel bytes.
///
/// Fail-closed: any parse, version, encoding, or decrypt error is fatal.
pub fn decode_envelope(raw: &[u8], session: &SessionContext) -> Result<Vec<u8>, EnvelopeError> {
    // Parse outer JSON
    let text =
        std::str::from_utf8(raw).map_err(|_| EnvelopeError::ParseError("not UTF-8".to_string()))?;

    // Check message type first
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| EnvelopeError::ParseError(e.to_string()))?;

    let msg_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

    if msg_type != "profile-envelope" {
        return Err(EnvelopeError::NotEnvelope);
    }

    // Require capability negotiated
    if !session.envelope_v1_negotiated() {
        return Err(EnvelopeError::Unnegotiated);
    }

    let envelope: ProfileEnvelopeV1 =
        serde_json::from_value(value).map_err(|e| EnvelopeError::ParseError(e.to_string()))?;

    // Validate version and encoding
    if envelope.version != 1 {
        return Err(EnvelopeError::Invalid(format!(
            "version {} != 1",
            envelope.version
        )));
    }
    if envelope.encoding != "base64" {
        return Err(EnvelopeError::Invalid(format!(
            "encoding '{}' != 'base64'",
            envelope.encoding
        )));
    }

    // Decrypt: sender_pk = remote, receiver_sk = local
    let plaintext = bolt_core::crypto::open_box_payload(
        &envelope.payload,
        &session.remote_public_key,
        &session.local_keypair.secret_key,
    )
    .map_err(|e| EnvelopeError::DecryptFail(e.to_string()))?;

    Ok(plaintext)
}

// ── Inner message router ────────────────────────────────────

/// Route a decrypted inner message: handle ping/pong/app_message.
///
/// Returns `Ok(Some(envelope_bytes))` if a reply should be sent on the DC,
/// `Ok(None)` if no reply is needed, or `Err` on protocol violation.
///
/// All reply bytes are already envelope-encrypted and ready for `dc.send()`.
pub fn route_inner_message(
    inner: &[u8],
    session: &SessionContext,
) -> Result<Option<Vec<u8>>, EnvelopeError> {
    use crate::dc_messages::{encode_dc_message, now_ms, parse_dc_message, DcMessage};

    let msg =
        parse_dc_message(inner).map_err(|e| EnvelopeError::Protocol(format!("parse: {e}")))?;

    match msg {
        DcMessage::Ping { ts_ms } => {
            let pong = DcMessage::Pong {
                ts_ms: now_ms(),
                reply_to_ms: ts_ms,
            };
            let pong_json = encode_dc_message(&pong)
                .map_err(|e| EnvelopeError::Protocol(format!("encode pong: {e}")))?;
            let envelope_bytes = encode_envelope(&pong_json, session)?;
            eprintln!("[INTEROP-4] recv ping ts={ts_ms}, sent pong");
            Ok(Some(envelope_bytes))
        }
        DcMessage::Pong { ts_ms, reply_to_ms } => {
            let rtt = ts_ms.saturating_sub(reply_to_ms);
            eprintln!("[INTEROP-4] recv pong ts={ts_ms} reply_to={reply_to_ms} rtt_ms={rtt}");
            Ok(None)
        }
        DcMessage::AppMessage { ref text } => {
            eprintln!("[INTEROP-4] app_message recv: \"{text}\"");
            // Echo back
            let echo = DcMessage::AppMessage {
                text: format!("echo: {text}"),
            };
            let echo_json = encode_dc_message(&echo)
                .map_err(|e| EnvelopeError::Protocol(format!("encode echo: {e}")))?;
            let envelope_bytes = encode_envelope(&echo_json, session)?;
            eprintln!("[INTEROP-4] sent echo");
            Ok(Some(envelope_bytes))
        }
    }
}

// ── Error message helper ────────────────────────────────────

/// Build a DC error message as UTF-8 JSON bytes.
pub fn make_error_message(code: &str, message: &str) -> Vec<u8> {
    let msg = DcErrorMessage {
        msg_type: "error".to_string(),
        code: code.to_string(),
        message: message.to_string(),
    };
    // Serialization of a simple struct cannot fail in practice.
    serde_json::to_vec(&msg).unwrap_or_else(|_| {
        format!(r#"{{"type":"error","code":"{code}","message":"serialization failed"}}"#)
            .into_bytes()
    })
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bolt_core::identity::generate_identity_keypair;

    fn make_session_pair() -> (SessionContext, SessionContext) {
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();
        let pk_a = kp_a.public_key;
        let pk_b = kp_b.public_key;
        let caps = vec!["bolt.profile-envelope-v1".to_string()];
        let sess_a = SessionContext::new(kp_a, pk_b, caps.clone());
        let sess_b = SessionContext::new(kp_b, pk_a, caps);
        (sess_a, sess_b)
    }

    #[test]
    fn profile_envelope_v1_serde_roundtrip() {
        let env = ProfileEnvelopeV1 {
            msg_type: "profile-envelope".to_string(),
            version: 1,
            encoding: "base64".to_string(),
            payload: "dGVzdA==".to_string(),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""type":"profile-envelope"#));
        assert!(json.contains(r#""version":1"#));
        assert!(json.contains(r#""encoding":"base64"#));
        let decoded: ProfileEnvelopeV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.msg_type, "profile-envelope");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.encoding, "base64");
        assert_eq!(decoded.payload, "dGVzdA==");
    }

    #[test]
    fn dc_error_message_serde_roundtrip() {
        let msg = DcErrorMessage {
            msg_type: "error".to_string(),
            code: "ENVELOPE_INVALID".to_string(),
            message: "version 2 != 1".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"error"#));
        assert!(json.contains(r#""code":"ENVELOPE_INVALID"#));
        let decoded: DcErrorMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.code, "ENVELOPE_INVALID");
        assert_eq!(decoded.message, "version 2 != 1");
    }

    #[test]
    fn encode_requires_negotiated_cap() {
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session = SessionContext::new(kp, remote_pk, vec![]); // no caps
        let result = encode_envelope(b"{}", &session);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "ENVELOPE_UNNEGOTIATED");
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let (sess_a, sess_b) = make_session_pair();
        // Encode normally, then tamper version
        let encoded = encode_envelope(b"{}", &sess_a).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["version"] = serde_json::json!(2);
        let tampered = serde_json::to_vec(&value).unwrap();
        let result = decode_envelope(&tampered, &sess_b);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
    }

    #[test]
    fn decode_rejects_wrong_encoding() {
        let (sess_a, sess_b) = make_session_pair();
        let encoded = encode_envelope(b"{}", &sess_a).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["encoding"] = serde_json::json!("hex");
        let tampered = serde_json::to_vec(&value).unwrap();
        let result = decode_envelope(&tampered, &sess_b);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
    }

    #[test]
    fn decode_rejects_when_cap_absent() {
        let kp_a = generate_identity_keypair();
        let kp_b = generate_identity_keypair();
        // A has cap (can encode), B does NOT (should reject decode)
        let sess_a = SessionContext::new(
            kp_a,
            kp_b.public_key,
            vec!["bolt.profile-envelope-v1".to_string()],
        );
        let sess_b_no_cap = SessionContext::new(kp_b, sess_a.local_keypair.public_key, vec![]);
        let encoded = encode_envelope(b"{}", &sess_a).unwrap();
        let result = decode_envelope(&encoded, &sess_b_no_cap);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_UNNEGOTIATED");
    }

    #[test]
    fn decode_decrypt_fail_with_wrong_keys() {
        let (sess_a, _sess_b) = make_session_pair();
        let encoded = encode_envelope(b"{}", &sess_a).unwrap();
        // Try to decode with a completely different session
        let kp_c = generate_identity_keypair();
        let sess_c = SessionContext::new(
            kp_c,
            sess_a.local_keypair.public_key,
            vec!["bolt.profile-envelope-v1".to_string()],
        );
        let result = decode_envelope(&encoded, &sess_c);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_DECRYPT_FAIL");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (sess_a, sess_b) = make_session_pair();
        let inner = b"hello world from A";
        let encoded = encode_envelope(inner, &sess_a).unwrap();
        let decoded = decode_envelope(&encoded, &sess_b).unwrap();
        assert_eq!(decoded, inner);
    }

    #[test]
    fn bidirectional_roundtrip() {
        let (sess_a, sess_b) = make_session_pair();

        // A → B
        let inner_a = b"message from A";
        let enc_a = encode_envelope(inner_a, &sess_a).unwrap();
        let dec_a = decode_envelope(&enc_a, &sess_b).unwrap();
        assert_eq!(dec_a, inner_a);

        // B → A
        let inner_b = b"message from B";
        let enc_b = encode_envelope(inner_b, &sess_b).unwrap();
        let dec_b = decode_envelope(&enc_b, &sess_a).unwrap();
        assert_eq!(dec_b, inner_b);
    }

    #[test]
    fn make_error_message_produces_expected_shape() {
        let bytes = make_error_message("ENVELOPE_INVALID", "version 2 != 1");
        let parsed: DcErrorMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.msg_type, "error");
        assert_eq!(parsed.code, "ENVELOPE_INVALID");
        assert_eq!(parsed.message, "version 2 != 1");
    }

    #[test]
    fn decode_rejects_non_envelope_type() {
        let json = r#"{"type":"file-chunk","data":{}}"#;
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session =
            SessionContext::new(kp, remote_pk, vec!["bolt.profile-envelope-v1".to_string()]);
        let result = decode_envelope(json.as_bytes(), &session);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "INVALID_STATE");
    }

    #[test]
    fn decode_rejects_non_utf8() {
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session =
            SessionContext::new(kp, remote_pk, vec!["bolt.profile-envelope-v1".to_string()]);
        let result = decode_envelope(&[0xFF, 0xFE], &session);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
    }
}
