//! Profile Envelope v1 codec — encrypt/decrypt/route inner messages.
//!
//! # Module Contract (MODULARITY-AUDITABILITY-1)
//!
//! **Owner:** bolt-daemon
//! **Consumers:** ws_endpoint.rs, wt_endpoint.rs, rendezvous.rs (legacy), tests
//!
//! **Exports:**
//! - `ProfileEnvelopeV1` — wire type with optional BTR fields
//! - `BtrEnvelopeFields` — extracted BTR envelope metadata
//! - `encode_envelope()` / `encode_envelope_with_btr()` — seal inner JSON
//! - `decode_envelope()` / `decode_envelope_with_btr()` — unseal + extract BTR fields
//! - `extract_btr_fields()` — parse BTR fields from envelope
//! - `route_inner_message()` — dispatch decrypted inner message (ping/pong/error/file)
//! - `build_error_payload()` — construct error frames
//!
//! **Invariants:**
//! - Envelope version must be 1 (ENVELOPE_INVALID on mismatch)
//! - Envelope encoding must be "base64"
//! - Capability negotiation required before encode/decode
//! - Inbound error codes validated against canonical registry
//! - Fail-closed on any parse, version, or decrypt error

use serde::{Deserialize, Serialize};
use std::fmt;

use bolt_core::session::SessionContext;

// ── Wire types ──────────────────────────────────────────────

/// Profile Envelope v1 outer frame.
///
/// BTR fields (§16.2): optional envelope-level fields present when
/// `bolt.transfer-ratchet-v1` is negotiated and a BTR transfer is active.
/// Omitted entirely for non-BTR sessions — serde skip_serializing_if = None.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileEnvelopeV1 {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub version: u32,
    pub encoding: String,
    pub payload: String,

    /// BTR chain index — present on every BTR-protected chunk.
    /// Monotonically increasing per transfer (0, 1, 2, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub chain_index: Option<u32>,

    /// BTR ratchet public key — present on the first chunk of each transfer.
    /// Base64-encoded 32-byte X25519 public key from the sender's per-transfer keypair.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ratchet_public_key: Option<String>,

    /// BTR ratchet generation — present on the first chunk of each transfer.
    /// Monotonically increasing per session (incremented on each DH ratchet step).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ratchet_generation: Option<u32>,
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
///
/// Wire codes align with PROTOCOL_ENFORCEMENT.md Appendix A registry.
#[derive(Debug)]
pub enum EnvelopeError {
    /// Envelope received but capability not negotiated.
    Unnegotiated,
    /// Envelope version or encoding field invalid.
    Invalid(String),
    /// Decryption failed (wrong key, tampered, etc).
    DecryptFail(String),
    /// Plaintext frame received in envelope-required session.
    /// Appendix A: ENVELOPE_REQUIRED.
    EnvelopeRequired,
    /// JSON parse error.
    ParseError(String),
    /// Inner message parse failure (valid JSON, invalid structure).
    /// Appendix A: INVALID_MESSAGE.
    InvalidMessage(String),
    /// Inner message type field present but unrecognized.
    /// Appendix A: UNKNOWN_MESSAGE_TYPE.
    UnknownMessageType(String),
    /// Message received in unexpected session state.
    /// Appendix A: INVALID_STATE.
    InvalidState(String),
    /// Catch-all for violations not covered by a specific code.
    /// Appendix A: PROTOCOL_VIOLATION.
    ProtocolViolation(String),
}

impl EnvelopeError {
    /// Wire error code string for DcErrorMessage.
    ///
    /// Aligned with PROTOCOL_ENFORCEMENT.md Appendix A registry.
    pub fn code(&self) -> &'static str {
        match self {
            EnvelopeError::Unnegotiated => "ENVELOPE_UNNEGOTIATED",
            EnvelopeError::Invalid(_) => "ENVELOPE_INVALID",
            EnvelopeError::DecryptFail(_) => "ENVELOPE_DECRYPT_FAIL",
            EnvelopeError::EnvelopeRequired => "ENVELOPE_REQUIRED",
            EnvelopeError::ParseError(_) => "ENVELOPE_INVALID",
            EnvelopeError::InvalidMessage(_) => "INVALID_MESSAGE",
            EnvelopeError::UnknownMessageType(_) => "UNKNOWN_MESSAGE_TYPE",
            EnvelopeError::InvalidState(_) => "INVALID_STATE",
            EnvelopeError::ProtocolViolation(_) => "PROTOCOL_VIOLATION",
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
            EnvelopeError::EnvelopeRequired => {
                write!(f, "plaintext frame in envelope-required session")
            }
            EnvelopeError::ParseError(detail) => {
                write!(f, "envelope parse error: {detail}")
            }
            EnvelopeError::InvalidMessage(detail) => {
                write!(f, "inner message parse failure: {detail}")
            }
            EnvelopeError::UnknownMessageType(detail) => {
                write!(f, "unrecognized inner message type: {detail}")
            }
            EnvelopeError::InvalidState(detail) => {
                write!(f, "message in unexpected session state: {detail}")
            }
            EnvelopeError::ProtocolViolation(detail) => {
                write!(f, "protocol violation: {detail}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ── Canonical error code registry ──────────────────────────
//
// RC2-EXEC-E (AC-RC-07): The canonical wire error code registry now lives
// in bolt_core::errors::WIRE_ERROR_CODES (26 codes: 11 PROTOCOL + 11
// ENFORCEMENT + 4 BTR). The daemon's former 22-code CANONICAL_ERROR_CODES
// was a subset missing BTR codes. Validation now uses the complete registry.

/// Re-export for backward compatibility with test_support consumers.
pub use bolt_core::errors::WIRE_ERROR_CODES as CANONICAL_ERROR_CODES;

/// Validate an inbound remote error message against the canonical registry.
///
/// Checks:
/// - `code` field exists and is a non-empty string
/// - `code` matches a registered canonical error code (bolt_core::errors)
/// - `message` field, if present, is a string
///
/// Returns validated (code, message) on success.
/// Returns `EnvelopeError::ProtocolViolation` on any validation failure.
pub fn validate_inbound_error(
    value: &serde_json::Value,
) -> Result<(String, Option<String>), EnvelopeError> {
    // code: must exist, must be a string, must be in registry
    let code = match value.get("code") {
        Some(v) => match v.as_str() {
            Some(s) if !s.is_empty() => s,
            Some(_) => {
                return Err(EnvelopeError::ProtocolViolation(
                    "inbound error: empty 'code' field".to_string(),
                ))
            }
            None => {
                return Err(EnvelopeError::ProtocolViolation(
                    "inbound error: 'code' field is not a string".to_string(),
                ))
            }
        },
        None => {
            return Err(EnvelopeError::ProtocolViolation(
                "inbound error: missing 'code' field".to_string(),
            ))
        }
    };

    if !bolt_core::errors::is_valid_wire_error_code(code) {
        return Err(EnvelopeError::ProtocolViolation(format!(
            "inbound error: unknown error code '{code}'"
        )));
    }

    // message: optional, but if present must be a string
    let message = match value.get("message") {
        Some(v) => match v.as_str() {
            Some(m) => Some(m.to_string()),
            None => {
                return Err(EnvelopeError::ProtocolViolation(
                    "inbound error: 'message' field is not a string".to_string(),
                ))
            }
        },
        None => None,
    };

    Ok((code.to_string(), message))
}

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
        chain_index: None,
        ratchet_public_key: None,
        ratchet_generation: None,
    };

    let json = serde_json::to_vec(&envelope)
        .map_err(|e| EnvelopeError::ParseError(format!("serialize: {e}")))?;
    Ok(json)
}

/// Encode a Profile Envelope v1 frame WITH BTR envelope fields.
///
/// Same encryption as `encode_envelope`, but populates optional BTR fields
/// on the outer envelope (chain_index, ratchet_public_key, ratchet_generation).
pub fn encode_envelope_with_btr(
    inner_json: &[u8],
    session: &SessionContext,
    btr_fields: &BtrEnvelopeFields,
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
        chain_index: Some(btr_fields.chain_index),
        ratchet_public_key: btr_fields.ratchet_public_key.clone(),
        ratchet_generation: btr_fields.ratchet_generation,
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
        // Appendix A: ENVELOPE_REQUIRED when envelope was negotiated but
        // plaintext/non-envelope frame arrives. INVALID_STATE otherwise.
        if session.envelope_v1_negotiated() {
            return Err(EnvelopeError::EnvelopeRequired);
        }
        return Err(EnvelopeError::InvalidState(format!(
            "expected profile-envelope, got '{msg_type}'"
        )));
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

/// Decode a Profile Envelope v1 frame AND extract BTR fields if present.
///
/// Same validation and decryption as `decode_envelope`, but also returns
/// any BTR envelope-level fields (chain_index, ratchet_public_key, ratchet_generation).
/// Returns (plaintext_inner_bytes, Option<BtrEnvelopeFields>).
pub fn decode_envelope_with_btr(
    raw: &[u8],
    session: &SessionContext,
) -> Result<(Vec<u8>, Option<BtrEnvelopeFields>), EnvelopeError> {
    let text =
        std::str::from_utf8(raw).map_err(|_| EnvelopeError::ParseError("not UTF-8".to_string()))?;

    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| EnvelopeError::ParseError(e.to_string()))?;

    let msg_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

    if msg_type != "profile-envelope" {
        if session.envelope_v1_negotiated() {
            return Err(EnvelopeError::EnvelopeRequired);
        }
        return Err(EnvelopeError::InvalidState(format!(
            "expected profile-envelope, got '{msg_type}'"
        )));
    }

    if !session.envelope_v1_negotiated() {
        return Err(EnvelopeError::Unnegotiated);
    }

    let envelope: ProfileEnvelopeV1 =
        serde_json::from_value(value).map_err(|e| EnvelopeError::ParseError(e.to_string()))?;

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

    let btr_fields = extract_btr_fields(&envelope);

    let plaintext = bolt_core::crypto::open_box_payload(
        &envelope.payload,
        &session.remote_public_key,
        &session.local_keypair.secret_key,
    )
    .map_err(|e| EnvelopeError::DecryptFail(e.to_string()))?;

    Ok((plaintext, btr_fields))
}

/// BTR envelope fields extracted from a ProfileEnvelopeV1.
/// Present when the sending peer has `bolt.transfer-ratchet-v1` negotiated
/// and a BTR transfer is active.
#[derive(Debug, Clone, PartialEq)]
pub struct BtrEnvelopeFields {
    pub chain_index: u32,
    pub ratchet_public_key: Option<String>,
    pub ratchet_generation: Option<u32>,
}

/// Extract BTR fields from a parsed ProfileEnvelopeV1, if present.
/// Returns None if chain_index is absent (non-BTR envelope).
pub fn extract_btr_fields(envelope: &ProfileEnvelopeV1) -> Option<BtrEnvelopeFields> {
    envelope.chain_index.map(|ci| BtrEnvelopeFields {
        chain_index: ci,
        ratchet_public_key: envelope.ratchet_public_key.clone(),
        ratchet_generation: envelope.ratchet_generation,
    })
}

// ── Inner message router ────────────────────────────────────

/// Route a decrypted inner message: handle ping/pong/app_message/error.
///
/// Returns `Ok(Some(envelope_bytes))` if a reply should be sent on the DC,
/// `Ok(None)` if no reply is needed, or `Err` on protocol violation.
///
/// All reply bytes are already envelope-encrypted and ready for `dc.send()`.
///
/// Inbound error messages (`type: "error"`) are intercepted and validated
/// via `validate_inbound_error()` before the DcMessage dispatch path.
/// Unknown or malformed error codes become `PROTOCOL_VIOLATION` + disconnect.
pub fn route_inner_message(
    inner: &[u8],
    session: &SessionContext,
) -> Result<Option<Vec<u8>>, EnvelopeError> {
    use crate::dc_messages::{
        encode_dc_message, now_ms, parse_dc_message, DcMessage, DcParseError,
    };

    // ── P1: intercept inbound error messages ──────────────────
    // Pre-parse to check type field before DcMessage dispatch.
    // Error messages are validated via validate_inbound_error(),
    // not through the DcMessage serde path.
    let pre_value: serde_json::Value = serde_json::from_slice(inner)
        .map_err(|e| EnvelopeError::InvalidMessage(format!("inner JSON parse: {e}")))?;

    if pre_value.get("type").and_then(|v| v.as_str()) == Some("error") {
        let (code, message) = validate_inbound_error(&pre_value)?;
        eprintln!("[P1_REMOTE_ERROR] validated remote error: code={code}, message={message:?}");
        return Ok(None);
    }
    // ── end P1 intercept ──────────────────────────────────────

    let msg = parse_dc_message(inner).map_err(|e| match e {
        DcParseError::UnknownType(ref t) => EnvelopeError::UnknownMessageType(t.clone()),
        _ => EnvelopeError::InvalidMessage(e.to_string()),
    })?;

    match msg {
        DcMessage::Ping { ts_ms } => {
            let pong = DcMessage::Pong {
                ts_ms: now_ms(),
                reply_to_ms: ts_ms,
            };
            let pong_json = encode_dc_message(&pong)
                .map_err(|e| EnvelopeError::ProtocolViolation(format!("encode pong: {e}")))?;
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
                .map_err(|e| EnvelopeError::ProtocolViolation(format!("encode echo: {e}")))?;
            let envelope_bytes = encode_envelope(&echo_json, session)?;
            eprintln!("[INTEROP-4] sent echo");
            Ok(Some(envelope_bytes))
        }
        // B3-P2: FileOffer, FileChunk, FileFinish are handled at loop level
        // (TransferSession) after envelope decrypt.
        // Ok(None) here prevents disconnect; loop-level handler MUST intercept.
        DcMessage::FileOffer { .. }
        | DcMessage::FileChunk { .. }
        | DcMessage::FileFinish { .. } => Ok(None),
        // B3-P3: FileAccept and Cancel handled at loop level (send-side SM).
        // B-XFER-1: Pause and Resume handled at loop level (send-side pause control).
        DcMessage::FileAccept { .. }
        | DcMessage::Cancel { .. }
        | DcMessage::Pause { .. }
        | DcMessage::Resume { .. } => Ok(None),
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

/// Build an error message, wrapping in profile-envelope-v1 when negotiated.
///
/// If `session` is `Some` and envelope-v1 was negotiated, the error JSON
/// becomes the inner payload of an encrypted envelope. Otherwise the error
/// is sent as plaintext (pre-HELLO or no envelope capability).
///
/// Returns bytes ready for `dc.send()`.
pub fn build_error_payload(code: &str, message: &str, session: Option<&SessionContext>) -> Vec<u8> {
    let error_bytes = make_error_message(code, message);
    match session {
        Some(s) if s.envelope_v1_negotiated() => {
            // Wrap in envelope. On encode failure, fall back to plaintext
            // (better to send something than nothing before disconnect).
            encode_envelope(&error_bytes, s).unwrap_or(error_bytes)
        }
        _ => error_bytes,
    }
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
        let sess_a = SessionContext::new(kp_a, pk_b, caps.clone()).unwrap();
        let sess_b = SessionContext::new(kp_b, pk_a, caps).unwrap();
        (sess_a, sess_b)
    }

    #[test]
    fn profile_envelope_v1_serde_roundtrip() {
        let env = ProfileEnvelopeV1 {
            msg_type: "profile-envelope".to_string(),
            version: 1,
            encoding: "base64".to_string(),
            payload: "dGVzdA==".to_string(),
            chain_index: None,
            ratchet_public_key: None,
            ratchet_generation: None,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""type":"profile-envelope"#));
        assert!(json.contains(r#""version":1"#));
        assert!(json.contains(r#""encoding":"base64"#));
        // BTR fields must be absent when None (skip_serializing_if)
        assert!(!json.contains("chain_index"));
        assert!(!json.contains("ratchet_public_key"));
        assert!(!json.contains("ratchet_generation"));
        let decoded: ProfileEnvelopeV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.msg_type, "profile-envelope");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.encoding, "base64");
        assert_eq!(decoded.payload, "dGVzdA==");
        assert_eq!(decoded.chain_index, None);
        assert_eq!(decoded.ratchet_public_key, None);
        assert_eq!(decoded.ratchet_generation, None);
    }

    #[test]
    fn profile_envelope_v1_btr_fields_roundtrip() {
        let env = ProfileEnvelopeV1 {
            msg_type: "profile-envelope".to_string(),
            version: 1,
            encoding: "base64".to_string(),
            payload: "dGVzdA==".to_string(),
            chain_index: Some(0),
            ratchet_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            ratchet_generation: Some(1),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""chain_index":0"#));
        assert!(json.contains(r#""ratchet_public_key":"#));
        assert!(json.contains(r#""ratchet_generation":1"#));
        let decoded: ProfileEnvelopeV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.chain_index, Some(0));
        assert_eq!(decoded.ratchet_public_key, Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()));
        assert_eq!(decoded.ratchet_generation, Some(1));
    }

    #[test]
    fn profile_envelope_v1_btr_subsequent_chunk_no_ratchet_key() {
        // Chunks after the first have chain_index but no ratchet_public_key or generation
        let env = ProfileEnvelopeV1 {
            msg_type: "profile-envelope".to_string(),
            version: 1,
            encoding: "base64".to_string(),
            payload: "dGVzdA==".to_string(),
            chain_index: Some(5),
            ratchet_public_key: None,
            ratchet_generation: None,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""chain_index":5"#));
        assert!(!json.contains("ratchet_public_key"));
        assert!(!json.contains("ratchet_generation"));
        let decoded: ProfileEnvelopeV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.chain_index, Some(5));
        assert_eq!(decoded.ratchet_public_key, None);
        assert_eq!(decoded.ratchet_generation, None);
    }

    #[test]
    fn profile_envelope_v1_btr_fields_absent_from_browser_non_btr() {
        // Browser sends envelope without BTR fields — must deserialize correctly
        let json = r#"{"type":"profile-envelope","version":1,"encoding":"base64","payload":"dGVzdA=="}"#;
        let decoded: ProfileEnvelopeV1 = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.chain_index, None);
        assert_eq!(decoded.ratchet_public_key, None);
        assert_eq!(decoded.ratchet_generation, None);
    }

    #[test]
    fn profile_envelope_v1_btr_fields_from_browser_first_chunk() {
        // Browser sends first BTR chunk with all fields
        let json = r#"{"type":"profile-envelope","version":1,"encoding":"base64","payload":"dGVzdA==","chain_index":0,"ratchet_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","ratchet_generation":1}"#;
        let decoded: ProfileEnvelopeV1 = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.chain_index, Some(0));
        assert!(decoded.ratchet_public_key.is_some());
        assert_eq!(decoded.ratchet_generation, Some(1));
    }

    #[test]
    fn profile_envelope_v1_malformed_btr_chain_index_type() {
        // chain_index as string instead of number — must fail to parse
        let json = r#"{"type":"profile-envelope","version":1,"encoding":"base64","payload":"dGVzdA==","chain_index":"zero"}"#;
        let result = serde_json::from_str::<ProfileEnvelopeV1>(json);
        assert!(result.is_err(), "string chain_index must fail parse");
    }

    #[test]
    fn profile_envelope_v1_malformed_btr_ratchet_generation_negative() {
        // ratchet_generation as negative — must fail (u32 cannot be negative)
        let json = r#"{"type":"profile-envelope","version":1,"encoding":"base64","payload":"dGVzdA==","ratchet_generation":-1}"#;
        let result = serde_json::from_str::<ProfileEnvelopeV1>(json);
        assert!(result.is_err(), "negative ratchet_generation must fail parse");
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
        let session = SessionContext::new(kp, remote_pk, vec![]).unwrap(); // no caps
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
        )
        .unwrap();
        let sess_b_no_cap =
            SessionContext::new(kp_b, sess_a.local_keypair.public_key, vec![]).unwrap();
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
        )
        .unwrap();
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
    fn decode_rejects_non_envelope_type_with_envelope_required() {
        // Session has envelope negotiated → plaintext/non-envelope = ENVELOPE_REQUIRED
        let json = r#"{"type":"file-chunk","data":{}}"#;
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session =
            SessionContext::new(kp, remote_pk, vec!["bolt.profile-envelope-v1".to_string()])
                .unwrap();
        let result = decode_envelope(json.as_bytes(), &session);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");
    }

    #[test]
    fn decode_rejects_non_envelope_type_without_cap_with_invalid_state() {
        // Session has NO envelope negotiated → wrong type = INVALID_STATE
        let json = r#"{"type":"file-chunk","data":{}}"#;
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session = SessionContext::new(kp, remote_pk, vec![]).unwrap();
        let result = decode_envelope(json.as_bytes(), &session);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "INVALID_STATE");
    }

    #[test]
    fn decode_rejects_non_utf8() {
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session =
            SessionContext::new(kp, remote_pk, vec!["bolt.profile-envelope-v1".to_string()])
                .unwrap();
        let result = decode_envelope(&[0xFF, 0xFE], &session);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
    }

    // ── I5: build_error_payload tests ──────────────────────

    #[test]
    fn build_error_payload_wraps_when_envelope_negotiated() {
        let (sess_a, sess_b) = make_session_pair();
        let payload = build_error_payload("TEST_ERROR", "test message", Some(&sess_a));
        // Should be a valid profile-envelope JSON
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value["type"], "profile-envelope");
        assert_eq!(value["version"], 1);
        assert_eq!(value["encoding"], "base64");
        // Decrypt and verify inner is a valid error message
        let inner = decode_envelope(&payload, &sess_b).unwrap();
        let parsed: DcErrorMessage = serde_json::from_slice(&inner).unwrap();
        assert_eq!(parsed.msg_type, "error");
        assert_eq!(parsed.code, "TEST_ERROR");
        assert_eq!(parsed.message, "test message");
    }

    #[test]
    fn build_error_payload_plaintext_when_no_session() {
        let payload = build_error_payload("PRE_HELLO_ERR", "no session yet", None);
        let parsed: DcErrorMessage = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed.msg_type, "error");
        assert_eq!(parsed.code, "PRE_HELLO_ERR");
        assert_eq!(parsed.message, "no session yet");
    }

    #[test]
    fn build_error_payload_plaintext_when_no_envelope_cap() {
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        let session = SessionContext::new(kp, remote_pk, vec![]).unwrap();
        let payload = build_error_payload("TEST_ERROR", "no cap", Some(&session));
        let parsed: DcErrorMessage = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed.msg_type, "error");
        assert_eq!(parsed.code, "TEST_ERROR");
    }

    #[test]
    fn build_error_payload_no_double_wrapping() {
        let (sess_a, sess_b) = make_session_pair();
        let payload = build_error_payload("DOUBLE_WRAP_CHECK", "check", Some(&sess_a));
        // Outer must be profile-envelope
        let outer: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(outer["type"], "profile-envelope");
        // Inner must be error, NOT another profile-envelope
        let inner_bytes = decode_envelope(&payload, &sess_b).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&inner_bytes).unwrap();
        assert_eq!(inner["type"], "error");
        assert_ne!(inner["type"], "profile-envelope");
    }

    // ── P1: inbound error validation tests ────────────────────

    #[test]
    fn route_inbound_error_known_code_accepted() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"ENVELOPE_INVALID","message":"test"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "remote errors produce no reply");
    }

    #[test]
    fn route_inbound_error_unknown_code_rejected() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"BOGUS_CODE","message":"test"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "PROTOCOL_VIOLATION");
    }

    #[test]
    fn route_inbound_error_missing_code_rejected() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","message":"no code field"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "PROTOCOL_VIOLATION");
    }

    #[test]
    fn route_inbound_error_non_string_code_rejected() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":42,"message":"numeric code"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "PROTOCOL_VIOLATION");
    }

    #[test]
    fn route_inbound_error_non_string_message_rejected() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"ENVELOPE_INVALID","message":42}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "PROTOCOL_VIOLATION");
    }

    // ── PROTO-HARDEN-2A: registry expansion tests ────────────

    #[test]
    fn canonical_registry_has_expected_code_count() {
        // RC2-EXEC-E: Now uses bolt_core::errors::WIRE_ERROR_CODES (26 = 11P + 11E + 4BTR)
        assert_eq!(CANONICAL_ERROR_CODES.len(), 26);
    }

    #[test]
    fn canonical_registry_all_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in &CANONICAL_ERROR_CODES {
            assert!(seen.insert(code), "duplicate code: {code}");
        }
    }

    #[test]
    fn route_inbound_error_duplicate_hello_accepted() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"DUPLICATE_HELLO","message":"test"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_ok());
    }

    #[test]
    fn route_inbound_error_envelope_required_accepted() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"ENVELOPE_REQUIRED","message":"test"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_ok());
    }

    #[test]
    fn route_inbound_error_hello_decrypt_fail_accepted() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"HELLO_DECRYPT_FAIL","message":"test"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_ok());
    }

    #[test]
    fn route_inbound_error_protocol_violation_accepted() {
        let (sess_a, _) = make_session_pair();
        let error_json = r#"{"type":"error","code":"PROTOCOL_VIOLATION","message":"test"}"#;
        let result = route_inner_message(error_json.as_bytes(), &sess_a);
        assert!(result.is_ok());
    }

    #[test]
    fn route_inbound_error_all_protocol_class_codes_accepted() {
        let protocol_codes = [
            "VERSION_MISMATCH",
            "ENCRYPTION_FAILED",
            "INTEGRITY_FAILED",
            "REPLAY_DETECTED",
            "TRANSFER_FAILED",
            "LIMIT_EXCEEDED",
            "CONNECTION_LOST",
            "PEER_NOT_FOUND",
            "ALREADY_CONNECTED",
            "INVALID_STATE",
            "KEY_MISMATCH",
        ];
        let (sess_a, _) = make_session_pair();
        for code in protocol_codes {
            let json = format!(r#"{{"type":"error","code":"{code}","message":"test"}}"#);
            let result = route_inner_message(json.as_bytes(), &sess_a);
            assert!(result.is_ok(), "PROTOCOL code {code} should be accepted");
        }
    }

    #[test]
    fn route_inbound_error_all_enforcement_class_codes_accepted() {
        let enforcement_codes = [
            "DUPLICATE_HELLO",
            "ENVELOPE_REQUIRED",
            "ENVELOPE_UNNEGOTIATED",
            "ENVELOPE_DECRYPT_FAIL",
            "ENVELOPE_INVALID",
            "HELLO_PARSE_ERROR",
            "HELLO_DECRYPT_FAIL",
            "HELLO_SCHEMA_ERROR",
            "INVALID_MESSAGE",
            "UNKNOWN_MESSAGE_TYPE",
            "PROTOCOL_VIOLATION",
        ];
        let (sess_a, _) = make_session_pair();
        for code in enforcement_codes {
            let json = format!(r#"{{"type":"error","code":"{code}","message":"test"}}"#);
            let result = route_inner_message(json.as_bytes(), &sess_a);
            assert!(result.is_ok(), "ENFORCEMENT code {code} should be accepted");
        }
    }

    // ── B3-P1: FileOffer carve-out + remaining transfer INVALID_STATE ──

    #[test]
    fn b3_file_offer_routes_to_ok_none() {
        let (sess_a, _) = make_session_pair();
        let offer_json = r#"{"type":"file-offer","transferId":"t1","filename":"f.txt","size":100,"totalChunks":1,"chunkSize":16384}"#;
        let result = route_inner_message(offer_json.as_bytes(), &sess_a);
        assert!(result.is_ok(), "FileOffer should return Ok");
        assert!(
            result.unwrap().is_none(),
            "FileOffer should return Ok(None)"
        );
    }

    #[test]
    fn b3_file_chunk_routes_to_ok_none() {
        let (sess_a, _) = make_session_pair();
        let chunk_json = r#"{"type":"file-chunk","transferId":"t1","filename":"test.bin","chunkIndex":0,"totalChunks":1,"chunk":"dGVzdA==","fileSize":4}"#;
        let result = route_inner_message(chunk_json.as_bytes(), &sess_a);
        assert!(result.is_ok(), "FileChunk should return Ok");
        assert!(
            result.unwrap().is_none(),
            "FileChunk should return Ok(None)"
        );
    }

    #[test]
    fn b3p3_file_accept_routes_to_ok_none() {
        // B3-P3: FileAccept carved out to Ok(None) — handled at loop level.
        let (sess_a, _) = make_session_pair();
        let accept_json = r#"{"type":"file-accept","transferId":"t1"}"#;
        let result = route_inner_message(accept_json.as_bytes(), &sess_a);
        assert!(result.is_ok(), "FileAccept should return Ok");
        assert!(
            result.unwrap().is_none(),
            "FileAccept should return Ok(None)"
        );
    }

    #[test]
    fn b3p3_cancel_routes_to_ok_none() {
        // B3-P3: Cancel carved out to Ok(None) — handled at loop level.
        let (sess_a, _) = make_session_pair();
        let cancel_json = r#"{"type":"cancel","transferId":"t1","cancelledBy":"receiver"}"#;
        let result = route_inner_message(cancel_json.as_bytes(), &sess_a);
        assert!(result.is_ok(), "Cancel should return Ok");
        assert!(result.unwrap().is_none(), "Cancel should return Ok(None)");
    }

    #[test]
    fn bxfer1_pause_carved_out_to_loop() {
        let (sess_a, _) = make_session_pair();
        let pause_json = r#"{"type":"pause","transferId":"t1"}"#;
        let result = route_inner_message(pause_json.as_bytes(), &sess_a);
        assert!(result.is_ok(), "Pause should return Ok");
        assert!(result.unwrap().is_none(), "Pause should return Ok(None)");
    }

    #[test]
    fn bxfer1_resume_carved_out_to_loop() {
        let (sess_a, _) = make_session_pair();
        let resume_json = r#"{"type":"resume","transferId":"t1"}"#;
        let result = route_inner_message(resume_json.as_bytes(), &sess_a);
        assert!(result.is_ok(), "Resume should return Ok");
        assert!(result.unwrap().is_none(), "Resume should return Ok(None)");
    }
}
