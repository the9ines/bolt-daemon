//! Inner DataChannel message types for post-HELLO communication (INTEROP-4).
//!
//! These messages are exchanged *after* envelope decryption. They represent
//! the plaintext JSON payload inside a Profile Envelope v1 frame.
//!
//! Message set:
//!   - `ping`  — heartbeat request with timestamp
//!   - `pong`  — heartbeat reply echoing the ping timestamp
//!   - `app_message` — arbitrary text payload for validation/testing

use serde::{Deserialize, Serialize};

// ── Inner message enum ──────────────────────────────────────

/// Post-HELLO DataChannel message types (inside envelope).
///
/// Tagged by `"type"` field to match web-side expectations.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum DcMessage {
    #[serde(rename = "ping")]
    Ping { ts_ms: u64 },

    #[serde(rename = "pong")]
    Pong { ts_ms: u64, reply_to_ms: u64 },

    #[serde(rename = "app_message")]
    AppMessage { text: String },
}

// ── Parse / encode helpers ──────────────────────────────────

/// Known inner message type strings.
///
/// Includes `"error"` so that inbound remote errors are not reported as
/// `UnknownType` — they are intercepted and validated in
/// `route_inner_message()` before reaching `parse_dc_message()`.
const KNOWN_TYPES: &[&str] = &["ping", "pong", "app_message", "error"];

/// Error detail for inner message parse operations.
///
/// Distinguishes "unrecognized type" from "parse failure" to emit the
/// correct Appendix A wire code (UNKNOWN_MESSAGE_TYPE vs INVALID_MESSAGE).
#[derive(Debug, Clone, PartialEq)]
pub enum DcParseError {
    /// Inner message is not valid UTF-8.
    NotUtf8,
    /// Inner message is not valid JSON or missing required fields.
    InvalidMessage(String),
    /// Inner message has a `type` field but the value is not recognized.
    UnknownType(String),
}

impl std::fmt::Display for DcParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DcParseError::NotUtf8 => write!(f, "inner message is not UTF-8"),
            DcParseError::InvalidMessage(detail) => {
                write!(f, "inner message parse error: {detail}")
            }
            DcParseError::UnknownType(t) => write!(f, "unrecognized inner message type: {t}"),
        }
    }
}

/// Parse a decrypted inner message from bytes.
///
/// Distinguishes unknown type (valid JSON with unrecognized `type` field)
/// from parse failure (invalid JSON or missing required fields) per
/// PROTOCOL_ENFORCEMENT.md Appendix A.
pub fn parse_dc_message(bytes: &[u8]) -> Result<DcMessage, DcParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DcParseError::NotUtf8)?;

    // First: try to extract the type field to distinguish unknown-type from parse-error.
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| DcParseError::InvalidMessage(e.to_string()))?;

    if let Some(type_str) = value.get("type").and_then(|v| v.as_str()) {
        if !KNOWN_TYPES.contains(&type_str) {
            return Err(DcParseError::UnknownType(type_str.to_string()));
        }
    }

    // Type is known (or absent — serde will reject missing "type" as parse error).
    serde_json::from_value(value).map_err(|e| DcParseError::InvalidMessage(e.to_string()))
}

/// Encode a DcMessage to JSON bytes (ready for envelope encryption).
pub fn encode_dc_message(msg: &DcMessage) -> Result<Vec<u8>, String> {
    serde_json::to_vec(msg).map_err(|e| format!("inner message encode error: {e}"))
}

/// Current time in milliseconds since UNIX epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_serde_roundtrip() {
        let msg = DcMessage::Ping {
            ts_ms: 1700000000000,
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Verify wire format
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "ping");
        assert_eq!(json["ts_ms"], 1700000000000u64);
    }

    #[test]
    fn pong_serde_roundtrip() {
        let msg = DcMessage::Pong {
            ts_ms: 1700000001000,
            reply_to_ms: 1700000000000,
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "pong");
        assert_eq!(json["reply_to_ms"], 1700000000000u64);
    }

    #[test]
    fn app_message_serde_roundtrip() {
        let msg = DcMessage::AppMessage {
            text: "hello from daemon".to_string(),
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "app_message");
        assert_eq!(json["text"], "hello from daemon");
    }

    #[test]
    fn parse_invalid_json_fails() {
        let result = parse_dc_message(b"not json");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), DcParseError::InvalidMessage(_)),
            "expected InvalidMessage for bad JSON"
        );
    }

    #[test]
    fn parse_non_utf8_fails() {
        let result = parse_dc_message(&[0xFF, 0xFE]);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), DcParseError::NotUtf8),
            "expected NotUtf8 for binary data"
        );
    }

    #[test]
    fn parse_unknown_type_returns_unknown_type_error() {
        let json = r#"{"type":"file-chunk","data":{}}"#;
        let result = parse_dc_message(json.as_bytes());
        assert!(result.is_err());
        match result.unwrap_err() {
            DcParseError::UnknownType(t) => assert_eq!(t, "file-chunk"),
            other => panic!("expected UnknownType, got: {other:?}"),
        }
    }

    #[test]
    fn now_ms_returns_reasonable_value() {
        let ts = now_ms();
        // Should be after 2020-01-01 and before 2100-01-01
        assert!(ts > 1_577_836_800_000);
        assert!(ts < 4_102_444_800_000);
    }

    #[test]
    fn ping_from_raw_json() {
        let json = r#"{"type":"ping","ts_ms":42}"#;
        let msg = parse_dc_message(json.as_bytes()).unwrap();
        assert_eq!(msg, DcMessage::Ping { ts_ms: 42 });
    }

    #[test]
    fn pong_from_raw_json() {
        let json = r#"{"type":"pong","ts_ms":100,"reply_to_ms":42}"#;
        let msg = parse_dc_message(json.as_bytes()).unwrap();
        assert_eq!(
            msg,
            DcMessage::Pong {
                ts_ms: 100,
                reply_to_ms: 42
            }
        );
    }
}
