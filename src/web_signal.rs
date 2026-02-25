//! Web-compatible inner signaling payload types (INTEROP-1).
//!
//! bolt-transport-web uses `{type, data, from, to}` as the inner payload
//! inside `Signal.payload`. This module provides serde types for parsing
//! and emitting that schema, plus conversion to/from daemon-internal types.
//!
//! Supported web message types:
//!   - "offer"         — SDP offer + optional publicKey/peerCode
//!   - "answer"        — SDP answer + optional publicKey/peerCode
//!   - "ice-candidate" — individual trickled ICE candidate
//!
//! Unknown types are logged and dropped (fail-closed).

use serde::{Deserialize, Serialize};

use crate::{CandidateInfo, SdpInfo, SignalBundle};

// ── Interop Signal Mode ─────────────────────────────────────

/// Selects which inner payload schema the daemon uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteropSignal {
    /// Daemon-native bundled schema (default).
    DaemonV1,
    /// Web-compatible trickle schema.
    WebV1,
}

// ── Web Payload Envelope ────────────────────────────────────

/// Top-level web signal payload: `{type, data, from, to}`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebSignalPayload {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub data: serde_json::Value,
    pub from: String,
    pub to: String,
}

// ── Typed data structs ──────────────────────────────────────

/// Offer data: `{offer: {type, sdp}, publicKey?, peerCode?}`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebOfferData {
    pub offer: WebSdp,
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "peerCode", skip_serializing_if = "Option::is_none")]
    pub peer_code: Option<String>,
}

/// Answer data: `{answer: {type, sdp}, publicKey?, peerCode?}`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAnswerData {
    pub answer: WebSdp,
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "peerCode", skip_serializing_if = "Option::is_none")]
    pub peer_code: Option<String>,
}

/// SDP description: `{type, sdp}` matching RTCSessionDescription.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebSdp {
    #[serde(rename = "type")]
    pub sdp_type: String,
    pub sdp: String,
}

/// ICE candidate data matching RTCIceCandidateInit.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebIceCandidateData {
    pub candidate: String,
    #[serde(rename = "sdpMid", skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(rename = "sdpMLineIndex", skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u32>,
    #[serde(rename = "usernameFragment", skip_serializing_if = "Option::is_none")]
    pub username_fragment: Option<String>,
}

// ── Parsed web signal (internal) ────────────────────────────

/// Parsed web signal ready for daemon consumption.
#[derive(Debug)]
pub enum ParsedWebSignal {
    Offer {
        sdp_type: String,
        sdp: String,
        public_key_b64: Option<String>,
    },
    Answer {
        sdp_type: String,
        sdp: String,
        public_key_b64: Option<String>,
    },
    IceCandidate {
        candidate: String,
        mid: String,
    },
}

// ── Parsing ─────────────────────────────────────────────────

/// Parse a web-schema inner payload from a `serde_json::Value`.
///
/// Returns `Ok(Some(signal))` for known types, `Ok(None)` for unknown
/// types (logged and dropped), `Err` for malformed payloads.
pub fn parse_web_payload(value: &serde_json::Value) -> Result<Option<ParsedWebSignal>, String> {
    let envelope: WebSignalPayload = serde_json::from_value(value.clone())
        .map_err(|e| format!("[INTEROP-1_PARSE_FAIL] envelope: {e}"))?;

    match envelope.msg_type.as_str() {
        "offer" => {
            let data: WebOfferData = serde_json::from_value(envelope.data)
                .map_err(|e| format!("[INTEROP-1_PARSE_FAIL] offer data: {e}"))?;
            Ok(Some(ParsedWebSignal::Offer {
                sdp_type: data.offer.sdp_type,
                sdp: data.offer.sdp,
                public_key_b64: data.public_key,
            }))
        }
        "answer" => {
            let data: WebAnswerData = serde_json::from_value(envelope.data)
                .map_err(|e| format!("[INTEROP-1_PARSE_FAIL] answer data: {e}"))?;
            Ok(Some(ParsedWebSignal::Answer {
                sdp_type: data.answer.sdp_type,
                sdp: data.answer.sdp,
                public_key_b64: data.public_key,
            }))
        }
        "ice-candidate" => {
            let data: WebIceCandidateData = serde_json::from_value(envelope.data)
                .map_err(|e| format!("[INTEROP-1_PARSE_FAIL] ice-candidate data: {e}"))?;
            let mid = data.sdp_mid.unwrap_or_else(|| "0".to_string());
            Ok(Some(ParsedWebSignal::IceCandidate {
                candidate: data.candidate,
                mid,
            }))
        }
        unknown => {
            eprintln!("[INTEROP-1_DROP_UNKNOWN] ignoring web signal type: '{unknown}'");
            Ok(None)
        }
    }
}

// ── Encoding (daemon → web) ─────────────────────────────────

/// Encode an SDP offer into a web-schema payload.
pub fn encode_web_offer(
    sdp_info: &SdpInfo,
    from_peer: &str,
    to_peer: &str,
    identity_pk_b64: Option<&str>,
) -> serde_json::Value {
    let payload = WebSignalPayload {
        msg_type: "offer".to_string(),
        data: serde_json::to_value(WebOfferData {
            offer: WebSdp {
                sdp_type: sdp_info.sdp_type.clone(),
                sdp: sdp_info.sdp.clone(),
            },
            public_key: identity_pk_b64.map(|s| s.to_string()),
            peer_code: Some(from_peer.to_string()),
        })
        .unwrap(),
        from: from_peer.to_string(),
        to: to_peer.to_string(),
    };
    serde_json::to_value(payload).unwrap()
}

/// Encode an SDP answer into a web-schema payload.
pub fn encode_web_answer(
    sdp_info: &SdpInfo,
    from_peer: &str,
    to_peer: &str,
    identity_pk_b64: Option<&str>,
) -> serde_json::Value {
    let payload = WebSignalPayload {
        msg_type: "answer".to_string(),
        data: serde_json::to_value(WebAnswerData {
            answer: WebSdp {
                sdp_type: sdp_info.sdp_type.clone(),
                sdp: sdp_info.sdp.clone(),
            },
            public_key: identity_pk_b64.map(|s| s.to_string()),
            peer_code: Some(from_peer.to_string()),
        })
        .unwrap(),
        from: from_peer.to_string(),
        to: to_peer.to_string(),
    };
    serde_json::to_value(payload).unwrap()
}

/// Encode a single ICE candidate into a web-schema payload.
pub fn encode_web_ice_candidate(
    candidate: &CandidateInfo,
    from_peer: &str,
    to_peer: &str,
) -> serde_json::Value {
    let payload = WebSignalPayload {
        msg_type: "ice-candidate".to_string(),
        data: serde_json::to_value(WebIceCandidateData {
            candidate: candidate.candidate.clone(),
            sdp_mid: Some(candidate.mid.clone()),
            sdp_m_line_index: None,
            username_fragment: None,
        })
        .unwrap(),
        from: from_peer.to_string(),
        to: to_peer.to_string(),
    };
    serde_json::to_value(payload).unwrap()
}

// ── Conversion helpers ──────────────────────────────────────

/// Convert a daemon `SignalBundle` to a list of web payloads
/// (one offer/answer + N ice-candidate messages).
pub fn bundle_to_web_payloads(
    bundle: &SignalBundle,
    msg_type: &str,
    from_peer: &str,
    to_peer: &str,
    identity_pk_b64: Option<&str>,
) -> Vec<serde_json::Value> {
    let mut payloads = Vec::new();

    // SDP message
    match msg_type {
        "offer" => payloads.push(encode_web_offer(
            &bundle.description,
            from_peer,
            to_peer,
            identity_pk_b64,
        )),
        "answer" => payloads.push(encode_web_answer(
            &bundle.description,
            from_peer,
            to_peer,
            identity_pk_b64,
        )),
        _ => {
            eprintln!("[INTEROP-1] WARNING: unknown bundle msg_type '{msg_type}' for web encoding");
        }
    }

    // Trickled ICE candidates
    for cand in &bundle.candidates {
        payloads.push(encode_web_ice_candidate(cand, from_peer, to_peer));
    }

    payloads
}

/// Convert a parsed web offer/answer into a daemon `SdpInfo`.
/// Used in round-trip tests now; will be used at runtime when web_v1
/// receive path is integrated into the DataChannel pipeline.
#[allow(dead_code)]
pub fn parsed_signal_to_sdp_info(signal: &ParsedWebSignal) -> Option<SdpInfo> {
    match signal {
        ParsedWebSignal::Offer { sdp_type, sdp, .. }
        | ParsedWebSignal::Answer { sdp_type, sdp, .. } => Some(SdpInfo {
            sdp_type: sdp_type.clone(),
            sdp: sdp.clone(),
        }),
        _ => None,
    }
}

/// Convert a parsed web ice-candidate into a daemon `CandidateInfo`.
/// Used in round-trip tests now; will be used at runtime when web_v1
/// receive path is integrated into the DataChannel pipeline.
#[allow(dead_code)]
pub fn parsed_signal_to_candidate(signal: &ParsedWebSignal) -> Option<CandidateInfo> {
    match signal {
        ParsedWebSignal::IceCandidate { candidate, mid } => Some(CandidateInfo {
            candidate: candidate.clone(),
            mid: mid.clone(),
        }),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Serialization tests ─────────────────────────────────

    #[test]
    fn web_offer_serialization_matches_schema() {
        let payload = encode_web_offer(
            &SdpInfo {
                sdp_type: "offer".to_string(),
                sdp: "v=0\r\ntest sdp".to_string(),
            },
            "peer-a",
            "peer-b",
            None,
        );
        let obj = payload.as_object().unwrap();
        assert_eq!(obj["type"], "offer");
        assert_eq!(obj["from"], "peer-a");
        assert_eq!(obj["to"], "peer-b");
        let data = obj["data"].as_object().unwrap();
        assert_eq!(data["offer"]["type"], "offer");
        assert_eq!(data["offer"]["sdp"], "v=0\r\ntest sdp");
    }

    #[test]
    fn web_answer_serialization_matches_schema() {
        let payload = encode_web_answer(
            &SdpInfo {
                sdp_type: "answer".to_string(),
                sdp: "v=0\r\nanswer sdp".to_string(),
            },
            "peer-b",
            "peer-a",
            None,
        );
        let obj = payload.as_object().unwrap();
        assert_eq!(obj["type"], "answer");
        assert_eq!(obj["from"], "peer-b");
        assert_eq!(obj["to"], "peer-a");
        let data = obj["data"].as_object().unwrap();
        assert_eq!(data["answer"]["type"], "answer");
        assert_eq!(data["answer"]["sdp"], "v=0\r\nanswer sdp");
    }

    #[test]
    fn web_ice_candidate_serialization_matches_schema() {
        let payload = encode_web_ice_candidate(
            &CandidateInfo {
                candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host".to_string(),
                mid: "0".to_string(),
            },
            "peer-a",
            "peer-b",
        );
        let obj = payload.as_object().unwrap();
        assert_eq!(obj["type"], "ice-candidate");
        assert_eq!(obj["from"], "peer-a");
        assert_eq!(obj["to"], "peer-b");
        let data = obj["data"].as_object().unwrap();
        assert!(data["candidate"]
            .as_str()
            .unwrap()
            .starts_with("candidate:"));
        assert_eq!(data["sdpMid"], "0");
    }

    // ── Parsing tests ───────────────────────────────────────

    #[test]
    fn parse_realistic_web_offer() {
        let json = serde_json::json!({
            "type": "offer",
            "data": {
                "offer": {
                    "type": "offer",
                    "sdp": "v=0\r\no=- 123456 2 IN IP4 127.0.0.1\r\ns=-\r\n"
                },
                "publicKey": "AABBCCDD",
                "peerCode": "ABCD1234"
            },
            "from": "ABCD1234",
            "to": "EFGH5678"
        });

        let parsed = parse_web_payload(&json).unwrap().unwrap();
        match &parsed {
            ParsedWebSignal::Offer {
                sdp_type,
                sdp,
                public_key_b64,
            } => {
                assert_eq!(sdp_type, "offer");
                assert!(sdp.starts_with("v=0"));
                assert_eq!(public_key_b64.as_deref(), Some("AABBCCDD"));
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn parse_web_offer_ignores_extra_data_fields() {
        let json = serde_json::json!({
            "type": "offer",
            "data": {
                "offer": { "type": "offer", "sdp": "v=0\r\nsdp" },
                "publicKey": "key",
                "peerCode": "code",
                "unknownField": 42,
                "anotherExtra": true
            },
            "from": "a",
            "to": "b"
        });
        let parsed = parse_web_payload(&json).unwrap().unwrap();
        assert!(matches!(parsed, ParsedWebSignal::Offer { .. }));
    }

    #[test]
    fn parse_realistic_web_answer() {
        let json = serde_json::json!({
            "type": "answer",
            "data": {
                "answer": {
                    "type": "answer",
                    "sdp": "v=0\r\no=- 789 2 IN IP4 127.0.0.1\r\n"
                },
                "publicKey": "EEFF0011",
                "peerCode": "EFGH5678"
            },
            "from": "EFGH5678",
            "to": "ABCD1234"
        });

        let parsed = parse_web_payload(&json).unwrap().unwrap();
        match &parsed {
            ParsedWebSignal::Answer {
                sdp_type,
                sdp,
                public_key_b64,
            } => {
                assert_eq!(sdp_type, "answer");
                assert!(sdp.starts_with("v=0"));
                assert_eq!(public_key_b64.as_deref(), Some("EEFF0011"));
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn parse_web_ice_candidate_full() {
        let json = serde_json::json!({
            "type": "ice-candidate",
            "data": {
                "candidate": "candidate:842163049 1 udp 1677729535 192.168.1.100 54321 typ host",
                "sdpMLineIndex": 0,
                "sdpMid": "0",
                "usernameFragment": "abc123"
            },
            "from": "a",
            "to": "b"
        });

        let parsed = parse_web_payload(&json).unwrap().unwrap();
        match &parsed {
            ParsedWebSignal::IceCandidate { candidate, mid } => {
                assert!(candidate.starts_with("candidate:"));
                assert_eq!(mid, "0");
            }
            other => panic!("expected IceCandidate, got {other:?}"),
        }
    }

    #[test]
    fn parse_web_ice_candidate_minimal() {
        // sdpMid and sdpMLineIndex are optional
        let json = serde_json::json!({
            "type": "ice-candidate",
            "data": {
                "candidate": "candidate:1 1 UDP 2130706431 10.0.0.1 9999 typ host"
            },
            "from": "a",
            "to": "b"
        });

        let parsed = parse_web_payload(&json).unwrap().unwrap();
        match &parsed {
            ParsedWebSignal::IceCandidate { candidate, mid } => {
                assert!(candidate.contains("10.0.0.1"));
                assert_eq!(mid, "0"); // default when sdpMid absent
            }
            other => panic!("expected IceCandidate, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_type_returns_none() {
        let json = serde_json::json!({
            "type": "connection_request",
            "data": {},
            "from": "a",
            "to": "b"
        });
        let result = parse_web_payload(&json).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_envelope_returns_error() {
        let json = serde_json::json!({"not": "a valid envelope"});
        let result = parse_web_payload(&json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INTEROP-1_PARSE_FAIL"));
    }

    #[test]
    fn parse_offer_missing_sdp_returns_error() {
        let json = serde_json::json!({
            "type": "offer",
            "data": { "publicKey": "key" },
            "from": "a",
            "to": "b"
        });
        let result = parse_web_payload(&json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INTEROP-1_PARSE_FAIL"));
    }

    // ── Round-trip conversion tests ─────────────────────────

    #[test]
    fn roundtrip_daemon_bundle_to_web_and_back_offer() {
        let bundle = SignalBundle {
            description: SdpInfo {
                sdp_type: "offer".to_string(),
                sdp: "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\n".to_string(),
            },
            candidates: vec![
                CandidateInfo {
                    candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host"
                        .to_string(),
                    mid: "0".to_string(),
                },
                CandidateInfo {
                    candidate: "candidate:2 1 UDP 2130706175 10.0.0.1 54321 typ host".to_string(),
                    mid: "0".to_string(),
                },
            ],
        };

        // Encode to web payloads
        let payloads = bundle_to_web_payloads(&bundle, "offer", "from-peer", "to-peer", None);
        assert_eq!(payloads.len(), 3); // 1 offer + 2 ice candidates

        // Parse back
        let offer = parse_web_payload(&payloads[0]).unwrap().unwrap();
        let sdp_info = parsed_signal_to_sdp_info(&offer).unwrap();
        assert_eq!(sdp_info.sdp_type, "offer");
        assert_eq!(sdp_info.sdp, bundle.description.sdp);

        let ice1 = parse_web_payload(&payloads[1]).unwrap().unwrap();
        let cand1 = parsed_signal_to_candidate(&ice1).unwrap();
        assert_eq!(cand1.candidate, bundle.candidates[0].candidate);
        assert_eq!(cand1.mid, "0");

        let ice2 = parse_web_payload(&payloads[2]).unwrap().unwrap();
        let cand2 = parsed_signal_to_candidate(&ice2).unwrap();
        assert_eq!(cand2.candidate, bundle.candidates[1].candidate);
    }

    #[test]
    fn roundtrip_daemon_bundle_to_web_and_back_answer() {
        let bundle = SignalBundle {
            description: SdpInfo {
                sdp_type: "answer".to_string(),
                sdp: "v=0\r\nanswer sdp\r\n".to_string(),
            },
            candidates: vec![CandidateInfo {
                candidate: "candidate:1 1 UDP 2130706431 10.0.0.1 9999 typ host".to_string(),
                mid: "data".to_string(),
            }],
        };

        let payloads = bundle_to_web_payloads(&bundle, "answer", "b", "a", None);
        assert_eq!(payloads.len(), 2); // 1 answer + 1 ice candidate

        let answer = parse_web_payload(&payloads[0]).unwrap().unwrap();
        let sdp_info = parsed_signal_to_sdp_info(&answer).unwrap();
        assert_eq!(sdp_info.sdp_type, "answer");

        let ice = parse_web_payload(&payloads[1]).unwrap().unwrap();
        let cand = parsed_signal_to_candidate(&ice).unwrap();
        assert_eq!(cand.mid, "data");
    }

    #[test]
    fn roundtrip_web_offer_to_daemon_sdp_info() {
        let json = serde_json::json!({
            "type": "offer",
            "data": {
                "offer": { "type": "offer", "sdp": "v=0\r\nthe sdp" },
                "publicKey": "key",
                "peerCode": "code"
            },
            "from": "a",
            "to": "b"
        });

        let parsed = parse_web_payload(&json).unwrap().unwrap();
        let sdp_info = parsed_signal_to_sdp_info(&parsed).unwrap();

        // Convert back to web
        let re_encoded = encode_web_offer(&sdp_info, "a", "b", None);
        let re_parsed = parse_web_payload(&re_encoded).unwrap().unwrap();
        let re_sdp = parsed_signal_to_sdp_info(&re_parsed).unwrap();
        assert_eq!(re_sdp.sdp_type, "offer");
        assert_eq!(re_sdp.sdp, "v=0\r\nthe sdp");
    }

    // ── Identity public key tests (INTEROP-2) ────────────────

    #[test]
    fn encode_offer_with_identity_pk() {
        let payload = encode_web_offer(
            &SdpInfo {
                sdp_type: "offer".to_string(),
                sdp: "v=0\r\nsdp".to_string(),
            },
            "a",
            "b",
            Some("AAAA_test_pk"),
        );
        let data = payload["data"].as_object().unwrap();
        assert_eq!(data["publicKey"], "AAAA_test_pk");
    }

    #[test]
    fn encode_answer_with_identity_pk() {
        let payload = encode_web_answer(
            &SdpInfo {
                sdp_type: "answer".to_string(),
                sdp: "v=0\r\nsdp".to_string(),
            },
            "b",
            "a",
            Some("BBBB_test_pk"),
        );
        let data = payload["data"].as_object().unwrap();
        assert_eq!(data["publicKey"], "BBBB_test_pk");
    }

    #[test]
    fn parse_offer_extracts_public_key() {
        let json = serde_json::json!({
            "type": "offer",
            "data": {
                "offer": { "type": "offer", "sdp": "v=0\r\nsdp" },
                "publicKey": "my_identity_key_b64"
            },
            "from": "a",
            "to": "b"
        });
        let parsed = parse_web_payload(&json).unwrap().unwrap();
        match parsed {
            ParsedWebSignal::Offer { public_key_b64, .. } => {
                assert_eq!(public_key_b64.as_deref(), Some("my_identity_key_b64"));
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn parse_offer_without_public_key_gives_none() {
        let json = serde_json::json!({
            "type": "offer",
            "data": {
                "offer": { "type": "offer", "sdp": "v=0\r\nsdp" }
            },
            "from": "a",
            "to": "b"
        });
        let parsed = parse_web_payload(&json).unwrap().unwrap();
        match parsed {
            ParsedWebSignal::Offer { public_key_b64, .. } => {
                assert!(public_key_b64.is_none());
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    // ── Compatibility test ──────────────────────────────────

    #[test]
    fn daemon_v1_payload_unchanged_by_web_module() {
        // Verify the daemon-native SignalBundle serde is untouched
        let bundle = SignalBundle {
            description: SdpInfo {
                sdp_type: "offer".to_string(),
                sdp: "v=0\r\ntest".to_string(),
            },
            candidates: vec![CandidateInfo {
                candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host".to_string(),
                mid: "0".to_string(),
            }],
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: SignalBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.description.sdp_type, "offer");
        assert_eq!(decoded.candidates.len(), 1);
        assert_eq!(decoded.candidates[0].mid, "0");
    }

    // ── Conversion helper tests ─────────────────────────────

    #[test]
    fn parsed_signal_to_sdp_info_returns_none_for_ice() {
        let ice = ParsedWebSignal::IceCandidate {
            candidate: "c".to_string(),
            mid: "0".to_string(),
        };
        assert!(parsed_signal_to_sdp_info(&ice).is_none());
    }

    #[test]
    fn parsed_signal_to_candidate_returns_none_for_offer() {
        let offer = ParsedWebSignal::Offer {
            sdp_type: "offer".to_string(),
            sdp: "sdp".to_string(),
            public_key_b64: None,
        };
        assert!(parsed_signal_to_candidate(&offer).is_none());
    }

    #[test]
    fn bundle_to_web_payloads_count() {
        let bundle = SignalBundle {
            description: SdpInfo {
                sdp_type: "offer".to_string(),
                sdp: "sdp".to_string(),
            },
            candidates: vec![
                CandidateInfo {
                    candidate: "c1".to_string(),
                    mid: "0".to_string(),
                },
                CandidateInfo {
                    candidate: "c2".to_string(),
                    mid: "0".to_string(),
                },
                CandidateInfo {
                    candidate: "c3".to_string(),
                    mid: "0".to_string(),
                },
            ],
        };
        let payloads = bundle_to_web_payloads(&bundle, "offer", "a", "b", None);
        assert_eq!(payloads.len(), 4); // 1 offer + 3 candidates
    }
}
