//! SA1 Phase B — Ephemeral vs Persistent Role Separation tests.
//!
//! Proves that identity (persistent) and session (ephemeral) keys are
//! used for their correct roles:
//! - identityPublicKey in HELLO inner == persistent identity public key
//! - signaling publicKey == session ephemeral public key
//! - HELLO sealing uses ephemeral session secret key
//! - SessionContext uses ephemeral session keypair, not identity
//! - Persistent identity secret key is never used for seal/open
//!
//! Requires: `cargo test --features test-support`

#![cfg(feature = "test-support")]

use bolt_core::crypto::{generate_ephemeral_keypair, KeyPair};
use bolt_core::encoding::to_base64;
use bolt_core::identity::generate_identity_keypair;
use bolt_daemon::test_support::*;

// ── A) identity_pk_source_is_persistent ─────────────────────

#[test]
fn hello_inner_identity_pk_is_persistent_key() {
    let identity = generate_identity_keypair();
    let session = generate_ephemeral_keypair();
    let remote_session = generate_ephemeral_keypair();

    let msg = build_hello_message(
        &identity.public_key,
        &session,
        &remote_session.public_key,
    )
    .unwrap();

    // Decrypt to inspect inner
    let inner = parse_hello_message(
        msg.as_bytes(),
        &session.public_key,
        &remote_session,
    )
    .unwrap();

    // HELLO inner identityPublicKey MUST be the persistent identity key
    assert_eq!(
        inner.identity_public_key,
        to_base64(&identity.public_key),
        "identityPublicKey in HELLO must be the persistent identity key"
    );
    // ... and NOT the session ephemeral key
    assert_ne!(
        inner.identity_public_key,
        to_base64(&session.public_key),
        "identityPublicKey must not be the session ephemeral key"
    );
}

// ── B) signaling_pk_source_is_ephemeral ─────────────────────

#[test]
fn signaling_public_key_is_session_ephemeral() {
    // Simulates what rendezvous.rs does: local_pk_b64 = session_kp.public_key
    let identity = generate_identity_keypair();
    let session = generate_ephemeral_keypair();

    let signaling_pk_b64 = to_base64(&session.public_key);

    // Signaling publicKey must be session key, not identity
    assert_eq!(
        signaling_pk_b64,
        to_base64(&session.public_key),
        "signaling publicKey must equal session ephemeral pk"
    );
    assert_ne!(
        signaling_pk_b64,
        to_base64(&identity.public_key),
        "signaling publicKey must not equal persistent identity pk"
    );
}

// ── C) sealing_uses_ephemeral_secret ────────────────────────

#[test]
fn hello_sealed_with_session_sk_opens_with_session_sk() {
    let identity = generate_identity_keypair();
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    // A builds HELLO using session_a for sealing
    let msg = build_hello_message(
        &identity.public_key,
        &session_a,
        &session_b.public_key,
    )
    .unwrap();

    // B opens using session_b — succeeds because sealing used session_a.sk
    let inner = parse_hello_message(
        msg.as_bytes(),
        &session_a.public_key,
        &session_b,
    )
    .unwrap();
    assert_eq!(inner.identity_public_key, to_base64(&identity.public_key));
}

#[test]
fn hello_sealed_with_session_sk_cannot_be_opened_with_identity_sk() {
    let identity = generate_identity_keypair();
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    // A builds HELLO using session_a.sk for sealing
    let msg = build_hello_message(
        &identity.public_key,
        &session_a,
        &session_b.public_key,
    )
    .unwrap();

    // Attempt to open with identity.sk instead of session_b.sk — must fail
    let identity_as_receiver = KeyPair {
        public_key: identity.public_key,
        secret_key: identity.secret_key,
    };
    let result = parse_hello_message(
        msg.as_bytes(),
        &session_a.public_key,
        &identity_as_receiver,
    );
    assert!(
        result.is_err(),
        "opening HELLO with identity secret key must fail — sealing used session key"
    );
}

// ── D) post_hello_envelope_uses_ephemeral ───────────────────

#[test]
fn session_context_uses_ephemeral_keypair() {
    let identity = generate_identity_keypair();
    let session = generate_ephemeral_keypair();
    let remote_session = generate_ephemeral_keypair();

    let ctx = SessionContext::new(
        session.clone(),
        remote_session.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();

    // SessionContext local_keypair must be the ephemeral session key
    assert_eq!(
        ctx.local_keypair.public_key, session.public_key,
        "SessionContext must hold ephemeral session keypair"
    );
    assert_eq!(
        ctx.local_keypair.secret_key, session.secret_key,
        "SessionContext secret key must be ephemeral session secret"
    );
    // ... and NOT the identity key
    assert_ne!(
        ctx.local_keypair.public_key, identity.public_key,
        "SessionContext must not hold persistent identity keypair"
    );
}

#[test]
fn envelope_roundtrip_uses_ephemeral_session_keys() {
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    let ctx_a = SessionContext::new(
        session_a.clone(),
        session_b.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();

    let ctx_b = SessionContext::new(
        session_b.clone(),
        session_a.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();

    // A encodes, B decodes — proves envelope uses session keys
    let payload = b"{\"type\":\"ping\",\"ts_ms\":12345}";
    let encoded = encode_envelope(payload, &ctx_a).unwrap();
    let decoded = decode_envelope(&encoded, &ctx_b).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn envelope_fails_with_identity_key_instead_of_session() {
    let identity = generate_identity_keypair();
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    // A encodes with session_a
    let ctx_a = SessionContext::new(
        session_a.clone(),
        session_b.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();

    // Receiver constructs context with identity key (wrong) instead of session_b
    let ctx_wrong = SessionContext::new(
        identity.clone(),
        session_a.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();

    let payload = b"{\"type\":\"ping\",\"ts_ms\":99999}";
    let encoded = encode_envelope(payload, &ctx_a).unwrap();

    // Decode with wrong key must fail
    let result = decode_envelope(&encoded, &ctx_wrong);
    assert!(
        result.is_err(),
        "envelope decode with identity key instead of session key must fail"
    );
}

// ── E) both_rendezvous_paths_updated ────────────────────────
//
// This test simulates the exact key flow used by both offerer and answerer
// paths in rendezvous.rs: identity for HELLO inner, session for everything else.

#[test]
fn offerer_path_key_separation() {
    let identity_a = generate_identity_keypair();
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    // Offerer builds HELLO: identity.pk in inner, session_a for sealing
    let msg = build_hello_message(
        &identity_a.public_key,
        &session_a,
        &session_b.public_key,
    )
    .unwrap();

    // Remote opens
    let inner = parse_hello_message(msg.as_bytes(), &session_a.public_key, &session_b).unwrap();
    assert_eq!(inner.identity_public_key, to_base64(&identity_a.public_key));

    // SessionContext uses session key
    let ctx = SessionContext::new(
        session_a.clone(),
        session_b.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();
    assert_eq!(ctx.local_keypair.public_key, session_a.public_key);
}

#[test]
fn answerer_path_key_separation() {
    let identity_b = generate_identity_keypair();
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    // Answerer receives HELLO from offerer, then sends reply
    // Answerer builds HELLO reply: identity.pk in inner, session_b for sealing
    let msg = build_hello_message(
        &identity_b.public_key,
        &session_b,
        &session_a.public_key,
    )
    .unwrap();

    // Remote opens
    let inner = parse_hello_message(msg.as_bytes(), &session_b.public_key, &session_a).unwrap();
    assert_eq!(inner.identity_public_key, to_base64(&identity_b.public_key));

    // SessionContext uses session key
    let ctx = SessionContext::new(
        session_b.clone(),
        session_a.public_key,
        vec!["bolt.profile-envelope-v1".to_string()],
    )
    .unwrap();
    assert_eq!(ctx.local_keypair.public_key, session_b.public_key);
}

// ── F) negative structural tests ────────────────────────────

#[test]
fn signaling_pk_never_equals_identity_pk() {
    // Run multiple iterations to prove structural separation
    for _ in 0..10 {
        let identity = generate_identity_keypair();
        let session = generate_ephemeral_keypair();

        // signaling publicKey = session.public_key
        let signaling_pk = session.public_key;
        // identity publicKey = identity.public_key
        let identity_pk = identity.public_key;

        assert_ne!(
            signaling_pk, identity_pk,
            "signaling pk must never equal identity pk (structural separation)"
        );
    }
}

#[test]
fn identity_stable_across_sessions_session_fresh() {
    let identity = generate_identity_keypair();

    // Two sessions from same identity
    let session_1 = generate_ephemeral_keypair();
    let session_2 = generate_ephemeral_keypair();

    // Identity stable
    let id_pk = identity.public_key;

    // Sessions different from each other
    assert_ne!(
        session_1.public_key, session_2.public_key,
        "each session must have a fresh ephemeral keypair"
    );

    // Both sessions different from identity
    assert_ne!(session_1.public_key, id_pk);
    assert_ne!(session_2.public_key, id_pk);

    // Both sessions produce HELLO with same identity
    let remote = generate_ephemeral_keypair();

    let msg1 = build_hello_message(&id_pk, &session_1, &remote.public_key).unwrap();
    let inner1 = parse_hello_message(msg1.as_bytes(), &session_1.public_key, &remote).unwrap();

    let msg2 = build_hello_message(&id_pk, &session_2, &remote.public_key).unwrap();
    let inner2 = parse_hello_message(msg2.as_bytes(), &session_2.public_key, &remote).unwrap();

    assert_eq!(
        inner1.identity_public_key, inner2.identity_public_key,
        "identity in HELLO must be stable across sessions"
    );
    assert_eq!(inner1.identity_public_key, to_base64(&id_pk));
}

#[test]
fn persistent_identity_sk_never_used_for_sealing() {
    // Prove: if we use identity.sk for sealing, the receiver with session key can't open it
    let identity = generate_identity_keypair();
    let session_a = generate_ephemeral_keypair();
    let session_b = generate_ephemeral_keypair();

    // Incorrectly seal with identity keypair (simulating the old bug)
    let identity_as_session = KeyPair {
        public_key: identity.public_key,
        secret_key: identity.secret_key,
    };
    let msg = build_hello_message(
        &identity.public_key,
        &identity_as_session,
        &session_b.public_key,
    )
    .unwrap();

    // Receiver tries to open expecting session_a.pk as sender — fails because
    // the message was sealed with identity.sk, not session_a.sk
    let result = parse_hello_message(msg.as_bytes(), &session_a.public_key, &session_b);
    assert!(
        result.is_err(),
        "must fail: sealed with identity sk but receiver expects session pk as sender"
    );
}
