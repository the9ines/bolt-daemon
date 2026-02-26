//! H3 golden vector tests for bolt-daemon.
//!
//! Vectors are vendored into `tests/vectors/` and embedded at compile time
//! via `include_str!`. No sibling repo access required at build or runtime.
//!
//! Exercises parse_hello_message and decode_envelope against precomputed
//! sealed payloads, verifying cross-implementation parity.
//!
//! Requires: `cargo test --features test-support`

#![cfg(feature = "test-support")]
#![allow(non_snake_case)]

use serde::Deserialize;

const HELLO_VECTORS_JSON: &str = include_str!("vectors/web-hello-open.vectors.json");
const ENVELOPE_VECTORS_JSON: &str = include_str!("vectors/envelope-open.vectors.json");
const SAS_VECTORS_JSON: &str = include_str!("vectors/sas.vectors.json");

fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes = bolt_core::encoding::from_hex(hex).expect("invalid hex");
    bytes.try_into().expect("expected 32 bytes")
}

// ── HELLO open vector schema ─────────────────────────────

#[derive(Deserialize)]
struct HelloVectors {
    version: u32,
    cases: Vec<HelloCase>,
}

#[derive(Deserialize)]
struct HelloCase {
    name: String,
    sender_public_hex: String,
    receiver_secret_hex: String,
    sealed_payload_base64: String,
    expected_inner: HelloInner,
}

#[derive(Deserialize, Debug, PartialEq)]
struct HelloInner {
    #[serde(rename = "type")]
    msg_type: String,
    version: u32,
    #[serde(rename = "identityPublicKey")]
    identity_public_key: String,
    capabilities: Vec<String>,
}

// ── Envelope open vector schema ──────────────────────────

#[derive(Deserialize)]
struct EnvelopeVectors {
    version: u32,
    cases: Vec<EnvelopeCase>,
}

#[derive(Deserialize)]
struct EnvelopeCase {
    name: String,
    sender_public_hex: String,
    receiver_secret_hex: String,
    envelope_json: EnvelopeFrame,
    expected_inner: serde_json::Value,
}

#[derive(Deserialize)]
struct EnvelopeFrame {
    #[serde(rename = "type")]
    msg_type: String,
    version: u32,
    encoding: String,
    payload: String,
}

// ── SAS vector schema (sanity parse) ─────────────────────

#[derive(Deserialize)]
struct SasVectors {
    version: u32,
    cases: Vec<SasCase>,
}

#[derive(Deserialize)]
struct SasCase {
    name: String,
    #[allow(dead_code)]
    expected_sas: String,
}

// ── HELLO open tests (exercises open_box_payload path) ───

#[test]
fn hello_open_golden_vectors_via_open_box_payload() {
    let vecs: HelloVectors =
        serde_json::from_str(HELLO_VECTORS_JSON).expect("hello open vectors failed to parse");

    assert_eq!(vecs.version, 1);

    for case in &vecs.cases {
        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        let decrypted = bolt_core::crypto::open_box_payload(
            &case.sealed_payload_base64,
            &sender_pk,
            &receiver_sk,
        )
        .unwrap_or_else(|e| panic!("HELLO open failed for case '{}': {}", case.name, e));

        let inner: HelloInner = serde_json::from_slice(&decrypted).unwrap_or_else(|e| {
            panic!(
                "HELLO inner JSON parse failed for case '{}': {}",
                case.name, e
            )
        });

        assert_eq!(
            inner, case.expected_inner,
            "HELLO inner mismatch for case '{}'",
            case.name
        );

        assert_eq!(inner.msg_type, "hello");
        assert_eq!(inner.version, 1);
        assert!(!inner.identity_public_key.is_empty());
    }
}

#[test]
fn hello_open_golden_vectors_via_parse_hello_message() {
    use bolt_daemon::test_support::parse_hello_message;

    let vecs: HelloVectors =
        serde_json::from_str(HELLO_VECTORS_JSON).expect("hello open vectors failed to parse");

    for case in &vecs.cases {
        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        let outer_json = serde_json::json!({
            "type": "hello",
            "payload": case.sealed_payload_base64
        });
        let outer_bytes = serde_json::to_vec(&outer_json).unwrap();

        let receiver_kp = bolt_core::crypto::KeyPair {
            public_key: [0u8; 32], // not used for decryption
            secret_key: receiver_sk,
        };

        let result = parse_hello_message(&outer_bytes, &sender_pk, &receiver_kp);

        match result {
            Ok(inner) => {
                assert_eq!(inner.msg_type, "hello");
                assert_eq!(inner.version, 1);
                assert_eq!(
                    inner.identity_public_key, case.expected_inner.identity_public_key,
                    "identity key mismatch for case '{}'",
                    case.name
                );
                assert_eq!(
                    inner.capabilities, case.expected_inner.capabilities,
                    "capabilities mismatch for case '{}'",
                    case.name
                );
            }
            Err(e) => {
                panic!("parse_hello_message failed for case '{}': {}", case.name, e);
            }
        }
    }
}

// ── Envelope open tests ──────────────────────────────────

#[test]
fn envelope_open_golden_vectors_via_open_box_payload() {
    let vecs: EnvelopeVectors =
        serde_json::from_str(ENVELOPE_VECTORS_JSON).expect("envelope open vectors failed to parse");

    assert_eq!(vecs.version, 1);

    for case in &vecs.cases {
        assert_eq!(case.envelope_json.msg_type, "profile-envelope");
        assert_eq!(case.envelope_json.version, 1);
        assert_eq!(case.envelope_json.encoding, "base64");

        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        let decrypted = bolt_core::crypto::open_box_payload(
            &case.envelope_json.payload,
            &sender_pk,
            &receiver_sk,
        )
        .unwrap_or_else(|e| panic!("envelope open failed for case '{}': {}", case.name, e));

        let inner: serde_json::Value = serde_json::from_slice(&decrypted).unwrap_or_else(|e| {
            panic!(
                "envelope inner JSON parse failed for case '{}': {}",
                case.name, e
            )
        });

        assert_eq!(
            inner, case.expected_inner,
            "envelope inner mismatch for case '{}'",
            case.name
        );
    }
}

#[test]
fn envelope_open_golden_vectors_via_decode_envelope() {
    use bolt_daemon::test_support::{decode_envelope, SessionContext};

    let vecs: EnvelopeVectors =
        serde_json::from_str(ENVELOPE_VECTORS_JSON).expect("envelope open vectors failed to parse");

    for case in &vecs.cases {
        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        let receiver_kp = bolt_core::crypto::KeyPair {
            public_key: [0u8; 32], // not used in decode
            secret_key: receiver_sk,
        };
        let caps = vec!["bolt.profile-envelope-v1".to_string()];
        let session = SessionContext::new(receiver_kp, sender_pk, caps).unwrap();

        let envelope_bytes = serde_json::to_vec(&serde_json::json!({
            "type": case.envelope_json.msg_type,
            "version": case.envelope_json.version,
            "encoding": case.envelope_json.encoding,
            "payload": case.envelope_json.payload,
        }))
        .unwrap();

        let decrypted = decode_envelope(&envelope_bytes, &session)
            .unwrap_or_else(|e| panic!("decode_envelope failed for case '{}': {}", case.name, e));

        let inner: serde_json::Value = serde_json::from_slice(&decrypted).unwrap_or_else(|e| {
            panic!(
                "envelope inner parse failed for case '{}': {}",
                case.name, e
            )
        });

        assert_eq!(
            inner, case.expected_inner,
            "envelope inner mismatch for case '{}'",
            case.name
        );
    }
}

// ── SAS vector sanity check ─────────────────────────────

#[test]
fn sas_vectors_parse_successfully() {
    let vecs: SasVectors =
        serde_json::from_str(SAS_VECTORS_JSON).expect("sas vectors failed to parse");

    assert_eq!(vecs.version, 1);
    assert!(
        !vecs.cases.is_empty(),
        "sas vectors must contain at least one case"
    );

    for case in &vecs.cases {
        assert!(!case.name.is_empty(), "sas case name must not be empty");
        assert!(
            !case.expected_sas.is_empty(),
            "sas expected_sas must not be empty for case '{}'",
            case.name
        );
    }
}
