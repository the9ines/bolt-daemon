//! H3 golden vector tests for bolt-daemon.
//!
//! Reads the SAME vector JSON files from bolt-core-sdk (no duplication).
//! Exercises parse_hello_message and decode_envelope against precomputed
//! sealed payloads, verifying cross-implementation parity.

#![allow(non_snake_case)]

use serde::Deserialize;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("bolt-core-sdk")
        .join("ts")
        .join("bolt-core")
        .join("__tests__")
        .join("vectors")
}

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

// ── HELLO open tests (exercises open_box_payload path) ───

#[test]
fn hello_open_golden_vectors_via_open_box_payload() {
    let path = vectors_dir().join("web-hello-open.vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let vecs: HelloVectors =
        serde_json::from_str(&data).expect("hello open vectors failed to parse");

    assert_eq!(vecs.version, 1);

    for case in &vecs.cases {
        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        // Use bolt-core's open_box_payload directly (same path as parse_hello_message)
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

        // Verify it matches the daemon's expected HELLO schema
        assert_eq!(inner.msg_type, "hello");
        assert_eq!(inner.version, 1);
        assert!(!inner.identity_public_key.is_empty());
    }
}

#[test]
fn hello_open_golden_vectors_via_parse_hello_message() {
    let path = vectors_dir().join("web-hello-open.vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let vecs: HelloVectors =
        serde_json::from_str(&data).expect("hello open vectors failed to parse");

    for case in &vecs.cases {
        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        // Build the outer HELLO frame as the daemon would receive it on the DC
        let outer_json = serde_json::json!({
            "type": "hello",
            "payload": case.sealed_payload_base64
        });
        let outer_bytes = serde_json::to_vec(&outer_json).unwrap();

        // Build a keypair for the receiver
        let receiver_kp = bolt_core::crypto::KeyPair {
            public_key: [0u8; 32], // not used for decryption
            secret_key: receiver_sk,
        };

        let result =
            bolt_daemon::web_hello::parse_hello_message(&outer_bytes, &sender_pk, &receiver_kp);

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
    let path = vectors_dir().join("envelope-open.vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let vecs: EnvelopeVectors =
        serde_json::from_str(&data).expect("envelope open vectors failed to parse");

    assert_eq!(vecs.version, 1);

    for case in &vecs.cases {
        // Validate envelope frame structure
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
    let path = vectors_dir().join("envelope-open.vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let vecs: EnvelopeVectors =
        serde_json::from_str(&data).expect("envelope open vectors failed to parse");

    for case in &vecs.cases {
        let sender_pk = hex_to_32(&case.sender_public_hex);
        let receiver_sk = hex_to_32(&case.receiver_secret_hex);

        // Build a SessionContext with the correct keys
        let receiver_kp = bolt_core::crypto::KeyPair {
            public_key: [0u8; 32], // not used in decode
            secret_key: receiver_sk,
        };
        let caps = vec!["bolt.profile-envelope-v1".to_string()];
        let session = bolt_daemon::session::SessionContext::new(receiver_kp, sender_pk, caps);

        // Serialize the full envelope frame as the daemon would receive it
        let envelope_bytes = serde_json::to_vec(&serde_json::json!({
            "type": case.envelope_json.msg_type,
            "version": case.envelope_json.version,
            "encoding": case.envelope_json.encoding,
            "payload": case.envelope_json.payload,
        }))
        .unwrap();

        let decrypted = bolt_daemon::envelope::decode_envelope(&envelope_bytes, &session)
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

// ── Vector file existence checks ─────────────────────────

#[test]
fn h3_vector_files_accessible_from_daemon() {
    let dir = vectors_dir();
    let files = [
        "sas.vectors.json",
        "web-hello-open.vectors.json",
        "envelope-open.vectors.json",
    ];
    for filename in &files {
        let path = dir.join(filename);
        assert!(path.exists(), "vector file not found at {}", path.display());
    }
}
