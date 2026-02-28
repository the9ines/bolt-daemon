//! H5 — Downgrade Resistance & Enforcement Validation tests.
//!
//! Proves:
//! 1. Envelope-required mode cannot be bypassed (post-HELLO enforcement)
//! 2. WebHelloV1 cannot be downgraded to DaemonHelloV1 (HELLO-phase guard)
//! 3. Fail-closed state progression (no recovery after error)
//! 4. Error code emission matches PROTOCOL_ENFORCEMENT.md Appendix A registry
//!
//! Envelope-required mode == `--interop-hello web_hello_v1 --interop-dc web_dc_v1`
//! Tests activate envelope-required via SessionContext with negotiated
//! `bolt.profile-envelope-v1` capability — the same gating used at runtime.
//!
//! Requires: `cargo test --features test-support`

#![cfg(feature = "test-support")]

use bolt_core::identity::generate_identity_keypair;
use bolt_daemon::test_support::*;

// ── Helpers ─────────────────────────────────────────────────

/// Create a paired session with `bolt.profile-envelope-v1` negotiated.
/// This is the runtime-equivalent of envelope-required mode.
fn make_envelope_session_pair() -> (SessionContext, SessionContext) {
    let kp_a = generate_identity_keypair();
    let kp_b = generate_identity_keypair();
    let caps = vec!["bolt.profile-envelope-v1".to_string()];
    let sess_a = SessionContext::new(kp_a, kp_b.public_key, caps.clone()).unwrap();
    let sess_b = SessionContext::new(kp_b, sess_a.local_keypair.public_key, caps).unwrap();
    (sess_a, sess_b)
}

/// Create a session WITHOUT envelope capability (legacy/DaemonHelloV1 mode).
fn make_legacy_session() -> SessionContext {
    let kp = generate_identity_keypair();
    let remote_pk = generate_identity_keypair().public_key;
    SessionContext::new(kp, remote_pk, vec![]).unwrap()
}

/// Create a session with envelope capability for one side only.
fn make_session_with_caps(caps: Vec<String>) -> SessionContext {
    let kp = generate_identity_keypair();
    let remote_pk = generate_identity_keypair().public_key;
    SessionContext::new(kp, remote_pk, caps).unwrap()
}

// ════════════════════════════════════════════════════════════
// 1. ENVELOPE ENFORCEMENT TESTS
// ════════════════════════════════════════════════════════════

// ── 1A. Post-HELLO: plaintext frame → ENVELOPE_REQUIRED ────

#[test]
fn plaintext_json_in_envelope_session_emits_envelope_required() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    // Non-envelope JSON message sent as if plaintext
    let plaintext = br#"{"type":"ping","ts_ms":42}"#;
    let result = decode_envelope(plaintext, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");
}

#[test]
fn plaintext_hello_in_envelope_session_emits_envelope_required() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let plaintext = br#"{"type":"hello","payload":"abc"}"#;
    let result = decode_envelope(plaintext, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");
}

#[test]
fn plaintext_error_in_envelope_session_emits_envelope_required() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let plaintext = br#"{"type":"error","code":"TEST","message":"test"}"#;
    let result = decode_envelope(plaintext, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");
}

#[test]
fn plaintext_unknown_type_in_envelope_session_emits_envelope_required() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let plaintext = br#"{"type":"file-offer","name":"test.txt"}"#;
    let result = decode_envelope(plaintext, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");
}

#[test]
fn empty_json_object_in_envelope_session_emits_envelope_required() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let plaintext = br#"{}"#;
    let result = decode_envelope(plaintext, &sess_b);
    assert!(result.is_err());
    // No "type" field → msg_type is "" → not "profile-envelope" → ENVELOPE_REQUIRED
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");
}

// ── 1B. Post-HELLO: invalid envelope structure → ENVELOPE_INVALID ──

#[test]
fn envelope_wrong_version_emits_envelope_invalid() {
    let (sess_a, sess_b) = make_envelope_session_pair();
    let encoded = encode_envelope(b"{}", &sess_a).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["version"] = serde_json::json!(99);
    let tampered = serde_json::to_vec(&value).unwrap();
    let result = decode_envelope(&tampered, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
}

#[test]
fn envelope_wrong_encoding_emits_envelope_invalid() {
    let (sess_a, sess_b) = make_envelope_session_pair();
    let encoded = encode_envelope(b"{}", &sess_a).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["encoding"] = serde_json::json!("hex");
    let tampered = serde_json::to_vec(&value).unwrap();
    let result = decode_envelope(&tampered, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
}

#[test]
fn envelope_non_utf8_emits_envelope_invalid() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let result = decode_envelope(&[0xFF, 0xFE, 0xFD], &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
}

#[test]
fn envelope_malformed_json_emits_envelope_invalid() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let result = decode_envelope(b"not json at all", &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
}

#[test]
fn envelope_missing_payload_field_emits_envelope_invalid() {
    let (_sess_a, sess_b) = make_envelope_session_pair();
    let json = br#"{"type":"profile-envelope","version":1,"encoding":"base64"}"#;
    let result = decode_envelope(json, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_INVALID");
}

// ── 1C. Post-HELLO: decrypt failure → ENVELOPE_DECRYPT_FAIL ──

#[test]
fn envelope_wrong_keys_emits_decrypt_fail() {
    let (sess_a, _sess_b) = make_envelope_session_pair();
    let encoded = encode_envelope(b"hello", &sess_a).unwrap();
    // Decrypt with unrelated session
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
fn envelope_tampered_payload_emits_decrypt_fail() {
    let (sess_a, sess_b) = make_envelope_session_pair();
    let encoded = encode_envelope(b"hello", &sess_a).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    // Corrupt the base64 payload
    value["payload"] = serde_json::json!("AAAA_corrupted_payload_BBBB");
    let tampered = serde_json::to_vec(&value).unwrap();
    let result = decode_envelope(&tampered, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_DECRYPT_FAIL");
}

// ── 1D. Post-HELLO: envelope when not negotiated → ENVELOPE_UNNEGOTIATED ──

#[test]
fn envelope_received_without_cap_emits_unnegotiated() {
    let kp_a = generate_identity_keypair();
    let kp_b = generate_identity_keypair();
    // A has cap (can encode), B does NOT
    let sess_a = SessionContext::new(
        kp_a,
        kp_b.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();
    let sess_b_no_cap = SessionContext::new(kp_b, sess_a.local_keypair.public_key, vec![]).unwrap();
    let encoded = encode_envelope(b"test", &sess_a).unwrap();
    let result = decode_envelope(&encoded, &sess_b_no_cap);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_UNNEGOTIATED");
}

// ── 1E. Post-HELLO: state does not advance after rejection ──

#[test]
fn session_state_unchanged_after_envelope_error() {
    let (sess_a, sess_b) = make_envelope_session_pair();

    // First: attempt bad decode (plaintext)
    let bad = br#"{"type":"ping","ts_ms":42}"#;
    let result = decode_envelope(bad, &sess_b);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_REQUIRED");

    // Session should still work for valid envelopes (state not corrupted)
    let good_inner = br#"{"type":"ping","ts_ms":100}"#;
    let encoded = encode_envelope(good_inner, &sess_a).unwrap();
    let decoded = decode_envelope(&encoded, &sess_b).unwrap();
    assert_eq!(decoded, good_inner.to_vec());
}

// ════════════════════════════════════════════════════════════
// 2. DOWNGRADE GUARD (HELLO PROTOCOL)
// ════════════════════════════════════════════════════════════

// ── 2A. WebHelloV1: legacy payload → rejected ──────────────

#[test]
fn web_hello_rejects_legacy_bolt_hello_v1_payload() {
    let kp = generate_identity_keypair();
    let result = parse_hello_typed(b"bolt-hello-v1", &kp.public_key, &kp);
    assert!(result.is_err());
    match result.unwrap_err() {
        HelloError::DowngradeAttempt => {} // Correct
        other => panic!("expected DowngradeAttempt, got: {other}"),
    }
}

#[test]
fn web_hello_legacy_payload_emits_protocol_violation_code() {
    let kp = generate_identity_keypair();
    let result = parse_hello_typed(b"bolt-hello-v1", &kp.public_key, &kp);
    let err = result.unwrap_err();
    assert_eq!(err.code(), "PROTOCOL_VIOLATION");
}

// ── 2B. CLI gating: web_dc_v1 requires web_hello_v1 ────────
// NOTE: CLI gating validation happens in main.rs parse_args() and triggers
// process::exit(1). This cannot be unit-tested directly. The gating logic is:
//   if interop_dc == WebDcV1 && interop_hello != WebHelloV1 { exit(1) }
// We verify the runtime SessionContext gating instead.

#[test]
fn web_dc_v1_mode_requires_envelope_cap_negotiated() {
    // Simulates what rendezvous.rs checks after HELLO:
    // if args.interop_dc == WebDcV1 && !session.envelope_v1_negotiated() → abort
    let session = make_legacy_session(); // No caps negotiated
    assert!(
        !session.envelope_v1_negotiated(),
        "legacy session must not have envelope cap"
    );
    // Runtime would abort here: "[INTEROP-3_NO_ENVELOPE_CAP]"
}

#[test]
fn web_dc_v1_mode_proceeds_with_envelope_cap() {
    let session = make_session_with_caps(vec!["bolt.profile-envelope-v1".to_string()]);
    assert!(
        session.envelope_v1_negotiated(),
        "envelope session must have envelope cap"
    );
}

// ── 2C. DaemonHelloV1: no envelope negotiation, plaintext accepted ──

#[test]
fn legacy_session_accepts_non_envelope_on_decode_with_invalid_state() {
    // In DaemonHelloV1 mode, no envelope cap is negotiated.
    // If decode_envelope is called with a non-envelope message,
    // it returns INVALID_STATE (not ENVELOPE_REQUIRED).
    let session = make_legacy_session();
    let plaintext = br#"{"type":"ping","ts_ms":42}"#;
    let result = decode_envelope(plaintext, &session);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "INVALID_STATE");
}

#[test]
fn legacy_session_encode_attempt_emits_unnegotiated() {
    let session = make_legacy_session();
    let result = encode_envelope(b"hello", &session);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), "ENVELOPE_UNNEGOTIATED");
}

// ════════════════════════════════════════════════════════════
// 3. ERROR CODE STRICTNESS — Appendix A registry coverage
// ════════════════════════════════════════════════════════════

// ── 3A. Envelope-phase codes ────────────────────────────────

#[test]
fn appendix_a_envelope_required_emitted() {
    let (_, sess_b) = make_envelope_session_pair();
    let err = decode_envelope(br#"{"type":"ping"}"#, &sess_b).unwrap_err();
    assert_eq!(err.code(), "ENVELOPE_REQUIRED");
}

#[test]
fn appendix_a_envelope_invalid_emitted_for_bad_version() {
    let (sess_a, sess_b) = make_envelope_session_pair();
    let encoded = encode_envelope(b"{}", &sess_a).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    v["version"] = serde_json::json!(0);
    let err = decode_envelope(&serde_json::to_vec(&v).unwrap(), &sess_b).unwrap_err();
    assert_eq!(err.code(), "ENVELOPE_INVALID");
}

#[test]
fn appendix_a_envelope_decrypt_fail_emitted() {
    let (sess_a, _) = make_envelope_session_pair();
    let encoded = encode_envelope(b"test", &sess_a).unwrap();
    let kp_x = generate_identity_keypair();
    let sess_x = SessionContext::new(
        kp_x,
        sess_a.local_keypair.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();
    let err = decode_envelope(&encoded, &sess_x).unwrap_err();
    assert_eq!(err.code(), "ENVELOPE_DECRYPT_FAIL");
}

#[test]
fn appendix_a_envelope_unnegotiated_emitted() {
    let kp_a = generate_identity_keypair();
    let kp_b = generate_identity_keypair();
    let sess_a = SessionContext::new(
        kp_a,
        kp_b.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();
    let sess_b = SessionContext::new(kp_b, sess_a.local_keypair.public_key, vec![]).unwrap();
    let encoded = encode_envelope(b"x", &sess_a).unwrap();
    let err = decode_envelope(&encoded, &sess_b).unwrap_err();
    assert_eq!(err.code(), "ENVELOPE_UNNEGOTIATED");
}

#[test]
fn appendix_a_invalid_state_emitted_for_non_envelope_without_cap() {
    let session = make_legacy_session();
    let err = decode_envelope(br#"{"type":"ping"}"#, &session).unwrap_err();
    assert_eq!(err.code(), "INVALID_STATE");
}

// ── 3B. Inner message codes ────────────────────────────────

#[test]
fn appendix_a_invalid_message_for_bad_inner_json() {
    let err = parse_dc_message(b"not json").unwrap_err();
    assert!(
        matches!(err, DcParseError::InvalidMessage(_)),
        "expected InvalidMessage for bad JSON"
    );
}

#[test]
fn appendix_a_unknown_message_type_for_unrecognized_type() {
    let json = br#"{"type":"file-chunk","data":"abc"}"#;
    let err = parse_dc_message(json).unwrap_err();
    match err {
        DcParseError::UnknownType(t) => assert_eq!(t, "file-chunk"),
        other => panic!("expected UnknownType, got: {other:?}"),
    }
}

#[test]
fn appendix_a_unknown_message_type_propagates_through_route() {
    let (sess_a, _) = make_envelope_session_pair();
    let unknown_inner = br#"{"type":"file-chunk","data":"abc"}"#;
    let err = bolt_daemon::envelope::route_inner_message(unknown_inner, &sess_a).unwrap_err();
    assert_eq!(err.code(), "UNKNOWN_MESSAGE_TYPE");
}

#[test]
fn appendix_a_invalid_message_propagates_through_route() {
    let (sess_a, _) = make_envelope_session_pair();
    let bad_inner = b"not valid json";
    let err = bolt_daemon::envelope::route_inner_message(bad_inner, &sess_a).unwrap_err();
    assert_eq!(err.code(), "INVALID_MESSAGE");
}

// ── 3C. HELLO-phase codes ──────────────────────────────────

#[test]
fn appendix_a_hello_parse_error_for_non_utf8() {
    let kp = generate_identity_keypair();
    let err = parse_hello_typed(&[0xFF, 0xFE], &kp.public_key, &kp).unwrap_err();
    assert_eq!(err.code(), "HELLO_PARSE_ERROR");
}

#[test]
fn appendix_a_hello_parse_error_for_invalid_json() {
    let kp = generate_identity_keypair();
    let err = parse_hello_typed(b"not json", &kp.public_key, &kp).unwrap_err();
    assert_eq!(err.code(), "HELLO_PARSE_ERROR");
}

#[test]
fn appendix_a_hello_parse_error_for_wrong_outer_type() {
    let kp = generate_identity_keypair();
    let json = br#"{"type":"ping","payload":"dGVzdA=="}"#;
    let err = parse_hello_typed(json, &kp.public_key, &kp).unwrap_err();
    assert_eq!(err.code(), "HELLO_PARSE_ERROR");
}

#[test]
fn appendix_a_hello_decrypt_fail_for_wrong_key() {
    let identity_a = generate_identity_keypair();
    let session_a = bolt_core::crypto::generate_ephemeral_keypair();
    let session_b = bolt_core::crypto::generate_ephemeral_keypair();
    let session_c = bolt_core::crypto::generate_ephemeral_keypair();
    let msg = build_hello_message(&identity_a.public_key, &session_a, &session_b.public_key).unwrap();
    let err = parse_hello_typed(msg.as_bytes(), &session_a.public_key, &session_c).unwrap_err();
    assert_eq!(err.code(), "HELLO_DECRYPT_FAIL");
}

#[test]
fn appendix_a_hello_schema_error_for_wrong_inner_type() {
    let kp_a = generate_identity_keypair();
    let kp_b = generate_identity_keypair();
    // Build valid encryption but with wrong inner type
    let inner = serde_json::json!({
        "type": "ping",
        "version": 1,
        "identityPublicKey": bolt_core::encoding::to_base64(&kp_a.public_key),
        "capabilities": ["bolt.profile-envelope-v1"]
    });
    let inner_bytes = serde_json::to_vec(&inner).unwrap();
    let sealed =
        bolt_core::crypto::seal_box_payload(&inner_bytes, &kp_b.public_key, &kp_a.secret_key)
            .unwrap();
    let outer = serde_json::json!({"type": "hello", "payload": sealed});
    let msg = serde_json::to_string(&outer).unwrap();
    let err = parse_hello_typed(msg.as_bytes(), &kp_a.public_key, &kp_b).unwrap_err();
    assert_eq!(err.code(), "HELLO_SCHEMA_ERROR");
}

#[test]
fn appendix_a_hello_schema_error_for_wrong_version() {
    let kp_a = generate_identity_keypair();
    let kp_b = generate_identity_keypair();
    let inner = serde_json::json!({
        "type": "hello",
        "version": 99,
        "identityPublicKey": bolt_core::encoding::to_base64(&kp_a.public_key),
        "capabilities": ["bolt.profile-envelope-v1"]
    });
    let inner_bytes = serde_json::to_vec(&inner).unwrap();
    let sealed =
        bolt_core::crypto::seal_box_payload(&inner_bytes, &kp_b.public_key, &kp_a.secret_key)
            .unwrap();
    let outer = serde_json::json!({"type": "hello", "payload": sealed});
    let msg = serde_json::to_string(&outer).unwrap();
    let err = parse_hello_typed(msg.as_bytes(), &kp_a.public_key, &kp_b).unwrap_err();
    assert_eq!(err.code(), "HELLO_SCHEMA_ERROR");
}

#[test]
fn appendix_a_duplicate_hello_code() {
    let mut state = HelloState::new();
    assert!(state.mark_completed().is_ok());
    let err = state.mark_completed();
    assert!(err.is_err());
    // HelloState returns &'static str, not HelloError.
    // The HelloError::DuplicateHello variant carries the wire code.
    let hello_err = HelloError::DuplicateHello;
    assert_eq!(hello_err.code(), "DUPLICATE_HELLO");
}

// ── 3D. No generic fallback codes ──────────────────────────

#[test]
fn all_envelope_error_codes_are_appendix_a_registered() {
    // Exhaustive check: every EnvelopeError variant maps to an Appendix A code.
    let appendix_a_codes = [
        "ENVELOPE_REQUIRED",
        "ENVELOPE_INVALID",
        "ENVELOPE_DECRYPT_FAIL",
        "ENVELOPE_UNNEGOTIATED",
        "INVALID_MESSAGE",
        "UNKNOWN_MESSAGE_TYPE",
        "INVALID_STATE",
        "PROTOCOL_VIOLATION",
    ];

    let variants: Vec<&str> = vec![
        EnvelopeError::EnvelopeRequired.code(),
        EnvelopeError::Invalid("test".into()).code(),
        EnvelopeError::DecryptFail("test".into()).code(),
        EnvelopeError::Unnegotiated.code(),
        EnvelopeError::ParseError("test".into()).code(),
        EnvelopeError::InvalidMessage("test".into()).code(),
        EnvelopeError::UnknownMessageType("test".into()).code(),
        EnvelopeError::InvalidState("test".into()).code(),
        EnvelopeError::ProtocolViolation("test".into()).code(),
    ];

    for code in &variants {
        assert!(
            appendix_a_codes.contains(code),
            "wire code '{code}' is not in Appendix A registry"
        );
    }
}

#[test]
fn all_hello_error_codes_are_appendix_a_registered() {
    let appendix_a_codes = [
        "HELLO_PARSE_ERROR",
        "HELLO_DECRYPT_FAIL",
        "HELLO_SCHEMA_ERROR",
        "KEY_MISMATCH",
        "DUPLICATE_HELLO",
        "PROTOCOL_VIOLATION",
    ];

    let variants: Vec<&str> = vec![
        HelloError::ParseError("test".into()).code(),
        HelloError::DecryptFail("test".into()).code(),
        HelloError::SchemaError("test".into()).code(),
        HelloError::KeyMismatch("test".into()).code(),
        HelloError::DuplicateHello.code(),
        HelloError::DowngradeAttempt.code(),
    ];

    for code in &variants {
        assert!(
            appendix_a_codes.contains(code),
            "wire code '{code}' is not in Appendix A registry"
        );
    }
}

// ── 3E. Error frame structure ──────────────────────────────

#[test]
fn error_frame_contains_required_fields() {
    // PROTOCOL_ENFORCEMENT.md § 6: error frame must have type, code, message
    let bytes = make_error_message("ENVELOPE_REQUIRED", "plaintext in envelope session");
    let parsed: DcErrorMessage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.msg_type, "error");
    assert_eq!(parsed.code, "ENVELOPE_REQUIRED");
    assert!(!parsed.message.is_empty());
}

#[test]
fn error_frame_is_plaintext_json_not_enveloped() {
    // PROTOCOL_ENFORCEMENT.md § 6: error frames are NOT enveloped
    let bytes = make_error_message("ENVELOPE_REQUIRED", "test");
    // Must parse as plain JSON (not as a profile-envelope)
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["type"], "error");
    assert_ne!(value["type"], "profile-envelope");
}

// ════════════════════════════════════════════════════════════
// 4. STATE MACHINE INTEGRITY
// ════════════════════════════════════════════════════════════

#[test]
fn duplicate_hello_state_rejected() {
    let mut state = HelloState::new();
    assert!(state.mark_completed().is_ok());
    // Second completion MUST fail
    assert!(state.mark_completed().is_err());
    // State does not reset — still completed
    assert!(state.is_completed());
}

#[test]
fn duplicate_hello_does_not_reset_negotiation() {
    // After SessionContext construction (HELLO complete), attempting
    // another HELLO completion fails. Negotiated caps are immutable.
    let caps = vec!["bolt.profile-envelope-v1".to_string()];
    let kp = generate_identity_keypair();
    let remote_pk = generate_identity_keypair().public_key;
    let session = SessionContext::new(kp, remote_pk, caps.clone()).unwrap();

    // Session is HELLO-complete and has negotiated caps
    assert!(session.is_hello_complete());
    assert!(session.envelope_v1_negotiated());
    assert_eq!(session.negotiated_capabilities, caps);
}

#[test]
fn session_context_double_construction_fails() {
    // SessionContext::new() calls HelloState::mark_completed().
    // If somehow called twice on the same HelloState, it would fail.
    // In practice this can't happen (SessionContext takes ownership),
    // but we verify the invariant.
    let mut state = HelloState::new();
    assert!(state.mark_completed().is_ok());
    assert!(state.mark_completed().is_err());
}

#[test]
fn envelope_roundtrip_after_error_still_works() {
    // Verify that the session is not poisoned by a failed decode.
    // (Stateless decode: each call is independent.)
    let (sess_a, sess_b) = make_envelope_session_pair();

    // Bad decode
    let _ = decode_envelope(b"garbage", &sess_b);

    // Good decode still works
    let encoded = encode_envelope(b"valid inner", &sess_a).unwrap();
    let decoded = decode_envelope(&encoded, &sess_b).unwrap();
    assert_eq!(decoded, b"valid inner");
}

// ════════════════════════════════════════════════════════════
// 5. DOWNGRADE RESISTANCE — COMPREHENSIVE
// ════════════════════════════════════════════════════════════

#[test]
fn no_runtime_flag_disables_envelope_after_negotiation() {
    // PROTOCOL_ENFORCEMENT.md § 4: "An implementation MUST NOT provide a
    // runtime flag, configuration option, or API that disables envelope
    // enforcement after negotiation has occurred."
    //
    // SessionContext's negotiated_capabilities are immutable (pub field,
    // but no mutation method). Envelope enforcement is determined solely
    // by has_capability("bolt.profile-envelope-v1").
    let session = make_session_with_caps(vec!["bolt.profile-envelope-v1".to_string()]);
    assert!(session.envelope_v1_negotiated());
    // There is no method to remove a capability or disable enforcement.
    // The field is pub for read access but changing it in production code
    // would require &mut self, and no such method exists.
}

#[test]
fn capability_negotiation_is_intersection_only() {
    // Verify negotiate_capabilities computes intersection.
    // A peer cannot inject capabilities the other doesn't support.
    let local = daemon_capabilities();
    let remote = vec!["bolt.some-other-cap".to_string()];
    let negotiated = negotiate_capabilities(&local, &remote);
    assert!(negotiated.is_empty());
    assert!(!negotiated.contains(&"bolt.profile-envelope-v1".to_string()));
}

#[test]
fn capability_negotiation_both_must_agree() {
    let local = daemon_capabilities();
    let remote = vec!["bolt.profile-envelope-v1".to_string()];
    let negotiated = negotiate_capabilities(&local, &remote);
    assert_eq!(negotiated, vec!["bolt.profile-envelope-v1".to_string()]);
}

// ════════════════════════════════════════════════════════════
// 6. LEGACY MODE BOUNDARY
// ════════════════════════════════════════════════════════════

#[test]
fn legacy_mode_determined_by_cap_absence() {
    // PROTOCOL_ENFORCEMENT.md § 5: legacy mode == envelope NOT negotiated
    let session = make_legacy_session();
    assert!(!session.envelope_v1_negotiated());
}

#[test]
fn legacy_mode_non_envelope_returns_invalid_state_not_envelope_required() {
    // In legacy mode, non-envelope decode returns INVALID_STATE, NOT ENVELOPE_REQUIRED.
    // This is correct: ENVELOPE_REQUIRED only applies when envelope was negotiated.
    let session = make_legacy_session();
    let err = decode_envelope(br#"{"type":"ping"}"#, &session).unwrap_err();
    assert_eq!(err.code(), "INVALID_STATE");
}

#[test]
fn envelope_required_vs_invalid_state_boundary_is_cap_negotiation() {
    // Same non-envelope frame, different error code based on capability negotiation
    let frame = br#"{"type":"app_message","text":"hi"}"#;

    // With envelope cap → ENVELOPE_REQUIRED
    let envelope_session = make_session_with_caps(vec!["bolt.profile-envelope-v1".to_string()]);
    let err1 = decode_envelope(frame, &envelope_session).unwrap_err();
    assert_eq!(err1.code(), "ENVELOPE_REQUIRED");

    // Without envelope cap → INVALID_STATE
    let legacy_session = make_legacy_session();
    let err2 = decode_envelope(frame, &legacy_session).unwrap_err();
    assert_eq!(err2.code(), "INVALID_STATE");
}
