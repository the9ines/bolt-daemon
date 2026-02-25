//! IPC message types for daemon <-> UI communication.
//!
//! Wire format: NDJSON (one JSON object per line, terminated by `\n`).

use serde::{Deserialize, Serialize};

use super::id::generate_request_id;

// ── Envelope ────────────────────────────────────────────────

/// Top-level IPC message envelope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IpcMessage {
    pub id: String,
    pub kind: IpcKind,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub ts_ms: u64,
    pub payload: serde_json::Value,
}

/// Message direction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpcKind {
    Event,
    Decision,
}

/// Decision variants returned by the UI.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    AllowOnce,
    AllowAlways,
    DenyOnce,
    DenyAlways,
}

// ── Event Payloads (daemon -> UI) ───────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PairingRequestPayload {
    pub request_id: String,
    pub remote_device_name: String,
    pub remote_device_type: String,
    pub remote_identity_pk_b64: String,
    pub sas: String,
    pub capabilities_requested: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransferIncomingRequestPayload {
    pub request_id: String,
    pub from_device_name: String,
    pub from_identity_pk_b64: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DaemonStatusPayload {
    pub connected_peers: u32,
    pub ui_connected: bool,
    pub version: String,
}

// ── Decision Payloads (UI -> daemon) ────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DecisionPayload {
    pub request_id: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl IpcMessage {
    /// Create a new event message.
    pub fn new_event(msg_type: &str, payload: serde_json::Value) -> Self {
        Self {
            id: generate_request_id(),
            kind: IpcKind::Event,
            msg_type: msg_type.to_string(),
            ts_ms: now_ms(),
            payload,
        }
    }

    /// Create a new decision message.
    #[allow(dead_code)]
    pub fn new_decision(msg_type: &str, payload: serde_json::Value) -> Self {
        Self {
            id: generate_request_id(),
            kind: IpcKind::Decision,
            msg_type: msg_type.to_string(),
            ts_ms: now_ms(),
            payload,
        }
    }

    /// Serialize to a single NDJSON line (with trailing newline).
    pub fn to_ndjson(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Try to extract a DecisionPayload from this message.
    pub fn as_decision_payload(&self) -> Option<DecisionPayload> {
        if self.kind != IpcKind::Decision {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_message_event_roundtrip() {
        let msg = IpcMessage::new_event(
            "daemon.status",
            serde_json::to_value(DaemonStatusPayload {
                connected_peers: 0,
                ui_connected: true,
                version: "0.0.1".to_string(),
            })
            .unwrap(),
        );
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, IpcKind::Event);
        assert_eq!(decoded.msg_type, "daemon.status");
    }

    #[test]
    fn ipc_message_decision_roundtrip() {
        let msg = IpcMessage::new_decision(
            "pairing.decision",
            serde_json::to_value(DecisionPayload {
                request_id: "evt-42".to_string(),
                decision: Decision::AllowOnce,
                note: None,
            })
            .unwrap(),
        );
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, IpcKind::Decision);
        assert_eq!(decoded.msg_type, "pairing.decision");
    }

    #[test]
    fn pairing_request_payload_roundtrip() {
        let p = PairingRequestPayload {
            request_id: "evt-0".to_string(),
            remote_device_name: "iPhone 15".to_string(),
            remote_device_type: "mobile".to_string(),
            remote_identity_pk_b64: "AAAA".to_string(),
            sas: "123456".to_string(),
            capabilities_requested: vec!["file_transfer".to_string()],
        };
        let v = serde_json::to_value(&p).unwrap();
        let decoded: PairingRequestPayload = serde_json::from_value(v).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn transfer_payload_with_optional_fields() {
        let p = TransferIncomingRequestPayload {
            request_id: "evt-1".to_string(),
            from_device_name: "Mac".to_string(),
            from_identity_pk_b64: "BBBB".to_string(),
            file_name: "photo.jpg".to_string(),
            file_size_bytes: 1_048_576,
            sha256_hex: Some("abcd1234".to_string()),
            mime: Some("image/jpeg".to_string()),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("sha256_hex"));
        assert!(json.contains("mime"));
        let decoded: TransferIncomingRequestPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn transfer_payload_without_optional_fields() {
        let p = TransferIncomingRequestPayload {
            request_id: "evt-2".to_string(),
            from_device_name: "Mac".to_string(),
            from_identity_pk_b64: "CCCC".to_string(),
            file_name: "doc.pdf".to_string(),
            file_size_bytes: 512,
            sha256_hex: None,
            mime: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("sha256_hex"));
        assert!(!json.contains("mime"));
        let decoded: TransferIncomingRequestPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn daemon_status_payload_roundtrip() {
        let p = DaemonStatusPayload {
            connected_peers: 3,
            ui_connected: true,
            version: "0.0.1".to_string(),
        };
        let v = serde_json::to_value(&p).unwrap();
        let decoded: DaemonStatusPayload = serde_json::from_value(v).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn decision_payload_all_variants() {
        for decision in [
            Decision::AllowOnce,
            Decision::AllowAlways,
            Decision::DenyOnce,
            Decision::DenyAlways,
        ] {
            let p = DecisionPayload {
                request_id: "evt-99".to_string(),
                decision,
                note: Some("test".to_string()),
            };
            let json = serde_json::to_string(&p).unwrap();
            let decoded: DecisionPayload = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.decision, decision);
        }
    }

    #[test]
    fn decision_enum_snake_case() {
        let json = serde_json::to_string(&Decision::AllowOnce).unwrap();
        assert_eq!(json, "\"allow_once\"");
        let json = serde_json::to_string(&Decision::DenyAlways).unwrap();
        assert_eq!(json, "\"deny_always\"");
        let decoded: Decision = serde_json::from_str("\"allow_always\"").unwrap();
        assert_eq!(decoded, Decision::AllowAlways);
    }

    #[test]
    fn unknown_kind_value_fails_deserialization() {
        let json = r#"{"id":"x","kind":"unknown","type":"t","ts_ms":0,"payload":{}}"#;
        let result = serde_json::from_str::<IpcMessage>(json);
        assert!(result.is_err());
    }

    #[test]
    fn new_event_helper_structure() {
        let msg = IpcMessage::new_event("test.event", serde_json::json!({"key": "val"}));
        assert_eq!(msg.kind, IpcKind::Event);
        assert_eq!(msg.msg_type, "test.event");
        assert!(msg.id.starts_with("evt-"));
        assert!(msg.ts_ms > 0);
        assert_eq!(msg.payload["key"], "val");
    }

    #[test]
    fn extra_fields_in_payload_are_preserved() {
        let json =
            r#"{"id":"x","kind":"event","type":"t","ts_ms":0,"payload":{"known":"v","extra":42}}"#;
        let msg: IpcMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.payload["extra"], 42);
    }

    #[test]
    fn ts_ms_u64_large_values() {
        let msg = IpcMessage {
            id: "evt-0".to_string(),
            kind: IpcKind::Event,
            msg_type: "t".to_string(),
            ts_ms: u64::MAX,
            payload: serde_json::json!({}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ts_ms, u64::MAX);
    }

    #[test]
    fn to_ndjson_ends_with_newline() {
        let msg = IpcMessage::new_event("t", serde_json::json!({}));
        let line = msg.to_ndjson().unwrap();
        assert!(line.ends_with('\n'));
        assert!(!line[..line.len() - 1].contains('\n'));
    }

    #[test]
    fn as_decision_payload_returns_none_for_events() {
        let msg = IpcMessage::new_event("t", serde_json::json!({}));
        assert!(msg.as_decision_payload().is_none());
    }

    #[test]
    fn as_decision_payload_returns_some_for_decisions() {
        let dp = DecisionPayload {
            request_id: "evt-0".to_string(),
            decision: Decision::DenyOnce,
            note: None,
        };
        let msg = IpcMessage::new_decision("pairing.decision", serde_json::to_value(&dp).unwrap());
        let extracted = msg.as_decision_payload().unwrap();
        assert_eq!(extracted.decision, Decision::DenyOnce);
        assert_eq!(extracted.request_id, "evt-0");
    }
}
