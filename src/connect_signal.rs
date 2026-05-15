//! Structured native connect signal parsing (APP-TO-APP-QUIC-MIGRATION-1 Q2D).
//!
//! `connect_remote.signal` historically contained a plain WS URL. Q2D adds a
//! JSON form that can carry QUIC metadata while preserving the legacy plain
//! string path so current app-to-app WS routing remains safe.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRemoteSignal {
    #[serde(default)]
    pub ws_url: Option<String>,
    #[serde(default)]
    pub quic_addr: Option<String>,
    #[serde(default)]
    pub quic_cert_hash: Option<String>,
}

impl ConnectRemoteSignal {
    pub fn from_raw(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("connect signal is empty".to_string());
        }

        if trimmed.starts_with('{') {
            let signal: Self = serde_json::from_str(trimmed)
                .map_err(|e| format!("invalid connect signal JSON: {e}"))?;
            let signal = signal.normalized();
            if signal.ws_url.is_none() && signal.quic_addr.is_none() {
                return Err("connect signal missing wsUrl or quicAddr".to_string());
            }
            Ok(signal)
        } else {
            Ok(Self {
                ws_url: Some(trimmed.to_string()),
                quic_addr: None,
                quic_cert_hash: None,
            })
        }
    }

    pub fn quic_metadata_complete(&self) -> bool {
        let Some(addr) = self.quic_addr.as_deref() else {
            return false;
        };
        let Some(hash) = self.quic_cert_hash.as_deref() else {
            return false;
        };
        !addr.trim().is_empty() && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn normalized(mut self) -> Self {
        self.ws_url = clean_optional(self.ws_url);
        self.quic_addr = clean_optional(self.quic_addr);
        self.quic_cert_hash = clean_optional(self.quic_cert_hash);
        self
    }
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_plain_ws_url() {
        let signal = ConnectRemoteSignal::from_raw(" ws://127.0.0.1:9100 ").unwrap();
        assert_eq!(signal.ws_url.as_deref(), Some("ws://127.0.0.1:9100"));
        assert_eq!(signal.quic_addr, None);
        assert!(!signal.quic_metadata_complete());
    }

    #[test]
    fn parses_structured_signal_with_quic_metadata() {
        let raw = r#"{
            "wsUrl": "ws://127.0.0.1:9100",
            "quicAddr": "127.0.0.1:9102",
            "quicCertHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"#;

        let signal = ConnectRemoteSignal::from_raw(raw).unwrap();
        assert_eq!(signal.ws_url.as_deref(), Some("ws://127.0.0.1:9100"));
        assert_eq!(signal.quic_addr.as_deref(), Some("127.0.0.1:9102"));
        assert!(signal.quic_metadata_complete());
    }

    #[test]
    fn incomplete_quic_metadata_does_not_count_as_complete() {
        let raw = r#"{"wsUrl":"ws://127.0.0.1:9100","quicAddr":"127.0.0.1:9102"}"#;
        let signal = ConnectRemoteSignal::from_raw(raw).unwrap();
        assert!(!signal.quic_metadata_complete());
    }

    #[test]
    fn malformed_json_is_rejected() {
        let result = ConnectRemoteSignal::from_raw(r#"{"wsUrl":"ws://127.0.0.1:9100""#);
        assert!(result.is_err());
    }

    #[test]
    fn whitespace_only_json_fields_are_rejected() {
        let result = ConnectRemoteSignal::from_raw(r#"{"wsUrl":"  ","quicAddr":"  "}"#);
        assert!(result.is_err());
    }

    #[test]
    fn empty_signal_is_rejected() {
        let result = ConnectRemoteSignal::from_raw("  ");
        assert!(result.is_err());
    }
}
