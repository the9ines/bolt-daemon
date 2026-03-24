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
///
/// Legacy messages (ping, pong, app_message) use snake_case fields on the wire.
/// File transfer messages (B2) use camelCase fields per LOCALBOLT_PROFILE.md
/// canonical JSON encoding (e.g., `transferId`, `chunkIndex`, `totalChunks`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum DcMessage {
    #[serde(rename = "ping")]
    Ping { ts_ms: u64 },

    #[serde(rename = "pong")]
    Pong { ts_ms: u64, reply_to_ms: u64 },

    #[serde(rename = "app_message")]
    AppMessage { text: String },

    // ── B2: File transfer message types ─────────────────────────
    // Wire format: LOCALBOLT_PROFILE.md § FILE_OFFER / FILE_CHUNK / etc.
    // Field naming: camelCase per profile JSON encoding convention.
    #[serde(rename = "file-offer")]
    FileOffer {
        #[serde(rename = "transferId")]
        transfer_id: String,
        filename: String,
        size: u64,
        #[serde(rename = "totalChunks")]
        total_chunks: u32,
        #[serde(rename = "chunkSize")]
        chunk_size: u32,
        #[serde(rename = "fileHash")]
        #[serde(skip_serializing_if = "Option::is_none")]
        file_hash: Option<String>,
    },

    #[serde(rename = "file-accept")]
    FileAccept {
        #[serde(rename = "transferId")]
        transfer_id: String,
    },

    #[serde(rename = "file-chunk")]
    FileChunk {
        #[serde(rename = "transferId")]
        transfer_id: String,
        filename: String,
        #[serde(rename = "chunkIndex")]
        chunk_index: u32,
        #[serde(rename = "totalChunks")]
        total_chunks: u32,
        /// Encrypted chunk data (base64). Browser sends as "chunk".
        chunk: String,
        #[serde(rename = "fileSize")]
        file_size: u64,
        #[serde(rename = "fileHash")]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        file_hash: Option<String>,
    },

    #[serde(rename = "file-finish")]
    FileFinish {
        #[serde(rename = "transferId")]
        transfer_id: String,
        #[serde(rename = "fileHash")]
        #[serde(skip_serializing_if = "Option::is_none")]
        file_hash: Option<String>,
    },

    #[serde(rename = "pause")]
    Pause {
        #[serde(rename = "transferId")]
        transfer_id: String,
    },

    #[serde(rename = "resume")]
    Resume {
        #[serde(rename = "transferId")]
        transfer_id: String,
    },

    #[serde(rename = "cancel")]
    Cancel {
        #[serde(rename = "transferId")]
        transfer_id: String,
        #[serde(rename = "cancelledBy")]
        cancelled_by: String,
    },
}

// ── Parse / encode helpers ──────────────────────────────────

/// Known inner message type strings.
///
/// Includes `"error"` so that inbound remote errors are not reported as
/// `UnknownType` — they are intercepted and validated in
/// `route_inner_message()` before reaching `parse_dc_message()`.
const KNOWN_TYPES: &[&str] = &[
    "ping",
    "pong",
    "app_message",
    "error",
    // B2: file transfer message types
    "file-offer",
    "file-accept",
    "file-chunk",
    "file-finish",
    "pause",
    "resume",
    "cancel",
];

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
        // B2: "file-chunk" is now a known type. Use a genuinely unknown type.
        let json = r#"{"type":"file-magic","data":{}}"#;
        let result = parse_dc_message(json.as_bytes());
        assert!(result.is_err());
        match result.unwrap_err() {
            DcParseError::UnknownType(t) => assert_eq!(t, "file-magic"),
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

    // ── B2: file transfer message serde tests ───────────────────

    #[test]
    fn file_offer_serde_roundtrip() {
        let msg = DcMessage::FileOffer {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
            filename: "example.pdf".to_string(),
            size: 688128,
            total_chunks: 42,
            chunk_size: 16384,
            file_hash: None,
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "file-offer");
        assert_eq!(json["transferId"], "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        assert_eq!(json["filename"], "example.pdf");
        assert_eq!(json["size"], 688128);
        assert_eq!(json["totalChunks"], 42);
        assert_eq!(json["chunkSize"], 16384);
        assert!(json.get("fileHash").is_none(), "fileHash absent when None");
    }

    #[test]
    fn file_offer_with_hash_serde_roundtrip() {
        let msg = DcMessage::FileOffer {
            transfer_id: "abcdef0123456789abcdef0123456789".to_string(),
            filename: "data.bin".to_string(),
            size: 1024,
            total_chunks: 1,
            chunk_size: 16384,
            file_hash: Some("e3b0c44298fc1c149afbf4c8996fb924".to_string()),
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["fileHash"], "e3b0c44298fc1c149afbf4c8996fb924");
    }

    #[test]
    fn file_accept_serde_roundtrip() {
        let msg = DcMessage::FileAccept {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "file-accept");
        assert_eq!(json["transferId"], "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
    }

    #[test]
    fn file_chunk_serde_roundtrip() {
        let msg = DcMessage::FileChunk {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
            filename: "test.bin".to_string(),
            chunk_index: 0,
            total_chunks: 42,
            chunk: "dGVzdCBjaHVuayBkYXRh".to_string(),
            file_size: 688128,
            file_hash: None,
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "file-chunk");
        assert_eq!(json["chunkIndex"], 0);
        assert_eq!(json["totalChunks"], 42);
        assert_eq!(json["chunk"], "dGVzdCBjaHVuayBkYXRh");
        assert_eq!(json["filename"], "test.bin");
        assert_eq!(json["fileSize"], 688128);
    }

    #[test]
    fn file_finish_serde_roundtrip() {
        let msg = DcMessage::FileFinish {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
            file_hash: None,
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "file-finish");
        assert!(json.get("fileHash").is_none());
    }

    #[test]
    fn pause_serde_roundtrip() {
        let msg = DcMessage::Pause {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "pause");
        assert_eq!(json["transferId"], "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
    }

    #[test]
    fn resume_serde_roundtrip() {
        let msg = DcMessage::Resume {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "resume");
    }

    #[test]
    fn cancel_serde_roundtrip() {
        let msg = DcMessage::Cancel {
            transfer_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
            cancelled_by: "initiator".to_string(),
        };
        let bytes = encode_dc_message(&msg).unwrap();
        let parsed = parse_dc_message(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "cancel");
        assert_eq!(json["cancelledBy"], "initiator");
    }

    #[test]
    fn file_offer_from_raw_json() {
        let json = r#"{"type":"file-offer","transferId":"abc123","filename":"test.txt","size":100,"totalChunks":1,"chunkSize":16384}"#;
        let msg = parse_dc_message(json.as_bytes()).unwrap();
        match msg {
            DcMessage::FileOffer {
                transfer_id,
                filename,
                size,
                total_chunks,
                chunk_size,
                file_hash,
            } => {
                assert_eq!(transfer_id, "abc123");
                assert_eq!(filename, "test.txt");
                assert_eq!(size, 100);
                assert_eq!(total_chunks, 1);
                assert_eq!(chunk_size, 16384);
                assert!(file_hash.is_none());
            }
            other => panic!("expected FileOffer, got: {other:?}"),
        }
    }

    #[test]
    fn known_types_includes_file_transfer() {
        for t in &[
            "file-offer",
            "file-accept",
            "file-chunk",
            "file-finish",
            "pause",
            "resume",
            "cancel",
        ] {
            assert!(KNOWN_TYPES.contains(t), "KNOWN_TYPES missing '{t}'");
        }
    }

    #[test]
    fn unknown_type_still_rejected_after_b2() {
        let json = r#"{"type":"file-magic","data":{}}"#;
        let result = parse_dc_message(json.as_bytes());
        assert!(result.is_err());
        match result.unwrap_err() {
            DcParseError::UnknownType(t) => assert_eq!(t, "file-magic"),
            other => panic!("expected UnknownType, got: {other:?}"),
        }
    }
}
