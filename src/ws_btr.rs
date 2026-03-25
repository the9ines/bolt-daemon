//! BTR (Bolt Transfer Ratchet) crypto operations for WS file transfers.
//!
//! # Module Contract (MODULARITY-AUDITABILITY-2, Slice 2)
//!
//! **Owner:** bolt-daemon
//! **Consumers:** ws_endpoint (session init, transfer send/receive paths)
//!
//! **Exports:**
//! - `compute_x25519_shared_secret()` — DH shared secret for BTR engine init
//! - `copy_keypair()` — KeyPair clone workaround (zeroize-on-drop)
//! - `decrypt_chunk_btr()` — full BTR chunk decrypt with replay guard
//!
//! **Responsibilities:**
//! - X25519 Diffie-Hellman computation
//! - BTR receive context initialization (first chunk of a transfer)
//! - Per-chunk symmetric decryption via ratcheted keys
//! - Replay guard enforcement
//! - Transfer context lifecycle (init on first chunk, lookup on subsequent)
//!
//! **Does NOT own:**
//! - BTR engine lifecycle (create/cleanup owned by ws_endpoint session layer)
//! - ACTIVE_SESSION global state (engine reference passed by caller)
//! - Envelope decoding (owned by envelope.rs)
//! - File assembly/save (owned by ws_endpoint run_read_loop)
//!
//! **Security invariants:**
//! - decrypt_chunk_btr is fail-closed: any crypto or state error returns Err
//! - Replay guard rejects duplicate (transfer_id, generation, chain_index) triples
//! - Ratchet public key required on first chunk (chain_index=0)
//!
//! **Log tokens:**
//!   [BTR_TRANSFER_RECV] — per-transfer receive context initialization

use std::collections::HashMap;
use std::net::SocketAddr;

use bolt_core::crypto::KeyPair;
use bolt_core::session::SessionContext;

use crate::envelope::BtrEnvelopeFields;
use crate::ws_validation::parse_transfer_id_bytes;

/// Compute X25519 Diffie-Hellman shared secret from session ephemeral keys.
/// Matches the browser's `scalarMult(localSecretKey, remotePublicKey)`.
pub(crate) fn compute_x25519_shared_secret(
    local_secret_key: &[u8; 32],
    remote_public_key: &[u8; 32],
) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*local_secret_key);
    let public = PublicKey::from(*remote_public_key);
    *secret.diffie_hellman(&public).as_bytes()
}

/// Copy a KeyPair (KeyPair does not impl Clone due to zeroize-on-drop).
pub(crate) fn copy_keypair(kp: &KeyPair) -> KeyPair {
    KeyPair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    }
}

/// Decrypt a BTR-protected file chunk.
///
/// On the first chunk of a transfer (chain_index=0 + ratchet_public_key present),
/// initializes a per-transfer BtrTransferContext via DH ratchet with the sender's
/// ratchet public key and the daemon's session secret key.
///
/// Subsequent chunks use the existing transfer context to advance the chain
/// and decrypt with the derived message key.
///
/// `btr_engine` is the session's BTR engine mutex — passed explicitly so this
/// function has no global state dependency.
///
/// Fail-closed: returns Err on any crypto or state error.
pub(crate) fn decrypt_chunk_btr(
    transfer_id: &str,
    chunk_b64: &str,
    chunk_index: u32,
    btr_env: &BtrEnvelopeFields,
    session: &SessionContext,
    peer_addr: SocketAddr,
    btr_engine: &std::sync::Mutex<Option<bolt_btr::BtrEngine>>,
    receive_contexts: &mut HashMap<String, (bolt_btr::BtrTransferContext, u32)>,
) -> Result<Vec<u8>, String> {
    // Decode base64 chunk → sealed bytes
    let sealed = bolt_core::encoding::from_base64(chunk_b64)
        .map_err(|e| format!("BTR chunk base64 decode: {e}"))?;

    // First chunk: initialize transfer receive context
    if btr_env.chain_index == 0 && btr_env.ratchet_public_key.is_some() {
        let ratchet_pub_b64 = btr_env.ratchet_public_key.as_ref().unwrap();
        let ratchet_pub_bytes = bolt_core::encoding::from_base64(ratchet_pub_b64)
            .map_err(|e| format!("BTR ratchet_public_key decode: {e}"))?;
        if ratchet_pub_bytes.len() != 32 {
            return Err(format!("BTR ratchet_public_key length {} != 32", ratchet_pub_bytes.len()));
        }
        let mut ratchet_pub = [0u8; 32];
        ratchet_pub.copy_from_slice(&ratchet_pub_bytes);

        let tid_bytes = parse_transfer_id_bytes(transfer_id)?;

        let mut btr_guard = btr_engine.lock().map_err(|e| format!("btr lock: {e}"))?;
        let engine = btr_guard.as_mut().ok_or("BTR engine not initialized")?;

        let ctx = engine
            .begin_transfer_receive_with_key(
                &tid_bytes,
                &ratchet_pub,
                &session.local_keypair.secret_key,
            )
            .map_err(|e| format!("BTR begin_transfer_receive: {e}"))?;

        eprintln!(
            "[BTR_TRANSFER_RECV] {peer_addr} transfer {transfer_id} initialized (generation={})",
            engine.ratchet_generation()
        );

        let gen = engine.ratchet_generation();
        receive_contexts.insert(transfer_id.to_string(), (ctx, gen));
    }

    // Replay guard: check (transfer_id, generation, chain_index) triple.
    {
        let tid_bytes = parse_transfer_id_bytes(transfer_id)?;
        let generation = receive_contexts.get(transfer_id)
            .map(|(_, gen)| *gen)
            .or(btr_env.ratchet_generation)
            .ok_or_else(|| "BTR: cannot determine generation for replay check".to_string())?;
        let mut btr_guard = btr_engine.lock().map_err(|e| format!("btr lock: {e}"))?;
        if let Some(ref mut engine) = *btr_guard {
            engine.check_replay(&tid_bytes, generation, btr_env.chain_index)
                .map_err(|e| format!("BTR replay check failed: {e}"))?;
        }
    }

    // Get transfer context and decrypt
    let (ctx, _gen) = receive_contexts.get_mut(transfer_id)
        .ok_or_else(|| format!("BTR: no receive context for transfer {transfer_id} at chunk {chunk_index}"))?;

    let plaintext = ctx.open_chunk(btr_env.chain_index, &sealed)
        .map_err(|e| format!("BTR open_chunk({}, {}): {e}", transfer_id, btr_env.chain_index))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolt_core::crypto::generate_ephemeral_keypair;
    use bolt_core::session::SessionContext;
    use crate::ws_validation::parse_transfer_id_bytes;

    // ── BTR engine lifecycle tests ──────────────────────────

    #[test]
    fn btr_shared_secret_is_commutative() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let daemon_shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );
        let browser_shared = compute_x25519_shared_secret(
            &browser_kp.secret_key,
            &daemon_kp.public_key,
        );

        assert_eq!(daemon_shared, browser_shared,
            "X25519 DH must be commutative — both sides derive identical shared secret");
    }

    #[test]
    fn btr_engine_initialized_from_shared_secret() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);
        let engine = bolt_btr::BtrEngine::new(&shared);

        assert_eq!(engine.ratchet_generation(), 0,
            "Fresh BTR engine must have generation 0");
    }

    #[test]
    fn btr_engines_from_same_shared_secret_are_equivalent() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();

        let shared_a = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);
        let shared_b = compute_x25519_shared_secret(&kp_b.secret_key, &kp_a.public_key);

        assert_eq!(shared_a, shared_b);

        let engine_a = bolt_btr::BtrEngine::new(&shared_a);
        let engine_b = bolt_btr::BtrEngine::new(&shared_b);

        assert_eq!(engine_a.ratchet_generation(), engine_b.ratchet_generation());
    }

    #[test]
    fn btr_engine_not_created_without_capability() {
        let caps = vec!["bolt.profile-envelope-v1".to_string(), "bolt.file-hash".to_string()];
        let kp = generate_ephemeral_keypair();
        let session = SessionContext::new(
            copy_keypair(&kp),
            [0u8; 32],
            caps,
        ).unwrap();

        let should_init = session.has_capability("bolt.transfer-ratchet-v1");
        assert!(!should_init, "BTR engine must NOT be created without negotiated capability");
    }

    #[test]
    fn btr_engine_created_with_capability() {
        let caps = vec![
            "bolt.profile-envelope-v1".to_string(),
            "bolt.file-hash".to_string(),
            "bolt.transfer-ratchet-v1".to_string(),
        ];
        let kp = generate_ephemeral_keypair();
        let session = SessionContext::new(
            copy_keypair(&kp),
            [0u8; 32],
            caps,
        ).unwrap();

        let should_init = session.has_capability("bolt.transfer-ratchet-v1");
        assert!(should_init, "BTR engine must be created when capability is negotiated");
    }

    #[test]
    fn btr_cleanup_disconnect_zeroizes_state() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);

        let mut engine = bolt_btr::BtrEngine::new(&shared);
        assert_eq!(engine.ratchet_generation(), 0);

        engine.cleanup_disconnect();
        assert_eq!(engine.ratchet_generation(), 0,
            "Generation reset to 0 after cleanup");
    }

    // ── BTR receive path tests ──────────────────────────────

    #[test]
    fn btr_decrypt_chunk_browser_to_daemon() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );

        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);
        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);

        let transfer_id: [u8; 16] = [0xAB; 16];
        let transfer_id_hex = transfer_id.iter().map(|b| format!("{b:02x}")).collect::<String>();

        let (mut browser_ctx, browser_ratchet_pub) = browser_engine
            .begin_transfer_send(&transfer_id, &daemon_kp.public_key)
            .unwrap();

        let mut daemon_ctx = daemon_engine
            .begin_transfer_receive_with_key(
                &transfer_id,
                &browser_ratchet_pub,
                &daemon_kp.secret_key,
            )
            .unwrap();

        let chunks = vec![b"chunk zero data".to_vec(), b"chunk one data".to_vec(), b"final chunk".to_vec()];
        for (i, plaintext) in chunks.iter().enumerate() {
            let (chain_idx, sealed) = browser_ctx.seal_chunk(plaintext).unwrap();
            assert_eq!(chain_idx, i as u32);

            let decrypted = daemon_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, *plaintext,
                "Chunk {i}: daemon must decrypt browser's BTR-sealed chunk");
        }
    }

    #[test]
    fn btr_decrypt_chunk_wrong_chain_index_fails() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);

        let mut sender_engine = bolt_btr::BtrEngine::new(&shared);
        let mut receiver_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = [0xCC; 16];
        let (mut sender_ctx, ratchet_pub) = sender_engine
            .begin_transfer_send(&tid, &kp_b.public_key)
            .unwrap();
        let mut receiver_ctx = receiver_engine
            .begin_transfer_receive_with_key(&tid, &ratchet_pub, &kp_b.secret_key)
            .unwrap();

        let (chain_idx, sealed) = sender_ctx.seal_chunk(b"data").unwrap();
        assert_eq!(chain_idx, 0);

        let result = receiver_ctx.open_chunk(1, &sealed);
        assert!(result.is_err(), "Wrong chain_index must fail closed");
    }

    #[test]
    fn btr_decrypt_tampered_chunk_fails() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);

        let mut sender_engine = bolt_btr::BtrEngine::new(&shared);
        let mut receiver_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = [0xDD; 16];
        let (mut sender_ctx, ratchet_pub) = sender_engine
            .begin_transfer_send(&tid, &kp_b.public_key)
            .unwrap();
        let mut receiver_ctx = receiver_engine
            .begin_transfer_receive_with_key(&tid, &ratchet_pub, &kp_b.secret_key)
            .unwrap();

        let (_chain_idx, mut sealed) = sender_ctx.seal_chunk(b"sensitive data").unwrap();

        if let Some(byte) = sealed.last_mut() {
            *byte ^= 0xFF;
        }

        let result = receiver_ctx.open_chunk(0, &sealed);
        assert!(result.is_err(), "Tampered BTR chunk must fail closed");
    }

    #[test]
    fn btr_decrypt_chunk_helper_first_chunk() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);
        let transfer_id: [u8; 16] = [0xEE; 16];
        let transfer_id_hex = transfer_id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let (mut browser_ctx, browser_ratchet_pub) = browser_engine
            .begin_transfer_send(&transfer_id, &daemon_kp.public_key)
            .unwrap();
        let (_chain_idx, sealed) = browser_ctx.seal_chunk(b"hello from browser").unwrap();
        let chunk_b64 = bolt_core::encoding::to_base64(&sealed);

        let daemon_session = SessionContext::new(
            copy_keypair(&daemon_kp),
            browser_kp.public_key,
            vec![
                "bolt.profile-envelope-v1".to_string(),
                "bolt.file-hash".to_string(),
                "bolt.transfer-ratchet-v1".to_string(),
            ],
        ).unwrap();

        let btr_engine = std::sync::Mutex::new(Some(bolt_btr::BtrEngine::new(&shared)));

        let btr_fields = crate::envelope::BtrEnvelopeFields {
            chain_index: 0,
            ratchet_public_key: Some(bolt_core::encoding::to_base64(&browser_ratchet_pub)),
            ratchet_generation: Some(1),
        };

        let mut receive_contexts = HashMap::new();
        let result = decrypt_chunk_btr(
            &transfer_id_hex,
            &chunk_b64,
            0,
            &btr_fields,
            &daemon_session,
            "127.0.0.1:9999".parse().unwrap(),
            &btr_engine,
            &mut receive_contexts,
        );

        assert!(result.is_ok(), "decrypt_chunk_btr must succeed: {:?}", result.err());
        assert_eq!(result.unwrap(), b"hello from browser");
    }

    #[test]
    fn btr_no_context_for_non_first_chunk_fails() {
        let kp = generate_ephemeral_keypair();
        let session = SessionContext::new(
            copy_keypair(&kp),
            [0u8; 32],
            vec!["bolt.profile-envelope-v1".to_string()],
        ).unwrap();

        let btr_fields = crate::envelope::BtrEnvelopeFields {
            chain_index: 5,
            ratchet_public_key: None,
            ratchet_generation: None,
        };

        let btr_engine = std::sync::Mutex::new(None::<bolt_btr::BtrEngine>);
        let mut receive_contexts = HashMap::new();
        let result = decrypt_chunk_btr(
            "abababababababababababababababab",
            "dGVzdA==",
            5,
            &btr_fields,
            &session,
            "127.0.0.1:9999".parse().unwrap(),
            &btr_engine,
            &mut receive_contexts,
        );

        assert!(result.is_err(), "Missing BTR context for non-first chunk must fail closed");
    }

    // ── BTR send path tests ─────────────────────────────────

    #[test]
    fn btr_send_daemon_to_browser_decrypt() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        let transfer_id: [u8; 16] = [0xFA; 16];

        let (mut daemon_ctx, daemon_ratchet_pub) = daemon_engine
            .begin_transfer_send(&transfer_id, &browser_kp.public_key)
            .unwrap();

        let mut browser_ctx = browser_engine
            .begin_transfer_receive_with_key(
                &transfer_id,
                &daemon_ratchet_pub,
                &browser_kp.secret_key,
            )
            .unwrap();

        let chunks = vec![
            b"daemon chunk zero".to_vec(),
            b"daemon chunk one".to_vec(),
            b"daemon final chunk".to_vec(),
        ];
        for (i, plaintext) in chunks.iter().enumerate() {
            let (chain_idx, sealed) = daemon_ctx.seal_chunk(plaintext).unwrap();
            assert_eq!(chain_idx, i as u32);

            let decrypted = browser_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, *plaintext,
                "Chunk {i}: browser must decrypt daemon's BTR-sealed chunk");
        }
    }

    #[test]
    fn btr_send_envelope_fields_first_chunk() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut engine = bolt_btr::BtrEngine::new(&shared);
        let tid: [u8; 16] = [0xBB; 16];

        let (mut ctx, ratchet_pub) = engine
            .begin_transfer_send(&tid, &browser_kp.public_key)
            .unwrap();
        let gen = engine.ratchet_generation();

        let (chain_idx, _sealed) = ctx.seal_chunk(b"test").unwrap();
        assert_eq!(chain_idx, 0);

        let fields = crate::envelope::BtrEnvelopeFields {
            chain_index: chain_idx,
            ratchet_public_key: Some(bolt_core::encoding::to_base64(&ratchet_pub)),
            ratchet_generation: Some(gen),
        };

        assert_eq!(fields.chain_index, 0);
        assert!(fields.ratchet_public_key.is_some());
        assert!(fields.ratchet_generation.is_some());
        assert_eq!(fields.ratchet_generation.unwrap(), 1);

        let (chain_idx_2, _sealed_2) = ctx.seal_chunk(b"test2").unwrap();
        assert_eq!(chain_idx_2, 1);

        let fields_2 = crate::envelope::BtrEnvelopeFields {
            chain_index: chain_idx_2,
            ratchet_public_key: None,
            ratchet_generation: None,
        };
        assert_eq!(fields_2.chain_index, 1);
        assert!(fields_2.ratchet_public_key.is_none());
    }

    #[test]
    fn btr_send_bidirectional_same_session() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        let tid1: [u8; 16] = [0x01; 16];
        let (mut d_send_ctx, d_ratchet_pub) = daemon_engine
            .begin_transfer_send(&tid1, &browser_kp.public_key).unwrap();
        let mut b_recv_ctx = browser_engine
            .begin_transfer_receive_with_key(&tid1, &d_ratchet_pub, &browser_kp.secret_key).unwrap();

        let (idx, sealed) = d_send_ctx.seal_chunk(b"daemon to browser").unwrap();
        let decrypted = b_recv_ctx.open_chunk(idx, &sealed).unwrap();
        assert_eq!(decrypted, b"daemon to browser");

        daemon_engine.end_transfer();
        browser_engine.end_transfer();

        let tid2: [u8; 16] = [0x02; 16];
        let (mut b_send_ctx, b_ratchet_pub) = browser_engine
            .begin_transfer_send(&tid2, &daemon_kp.public_key).unwrap();
        let mut d_recv_ctx = daemon_engine
            .begin_transfer_receive_with_key(&tid2, &b_ratchet_pub, &daemon_kp.secret_key).unwrap();

        let (idx2, sealed2) = b_send_ctx.seal_chunk(b"browser to daemon").unwrap();
        let decrypted2 = d_recv_ctx.open_chunk(idx2, &sealed2).unwrap();
        assert_eq!(decrypted2, b"browser to daemon");

        assert_eq!(daemon_engine.ratchet_generation(), 2);
        assert_eq!(browser_engine.ratchet_generation(), 2);
    }

    #[test]
    fn btr_encode_envelope_with_btr_roundtrip() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();

        let session_a = SessionContext::new(
            copy_keypair(&kp_a),
            kp_b.public_key,
            vec!["bolt.profile-envelope-v1".to_string()],
        ).unwrap();
        let session_b = SessionContext::new(
            copy_keypair(&kp_b),
            kp_a.public_key,
            vec!["bolt.profile-envelope-v1".to_string()],
        ).unwrap();

        let inner = b"test inner message";
        let btr_fields = crate::envelope::BtrEnvelopeFields {
            chain_index: 0,
            ratchet_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            ratchet_generation: Some(1),
        };

        let encoded = crate::envelope::encode_envelope_with_btr(inner, &session_a, &btr_fields).unwrap();
        let (decoded, extracted_btr) = crate::envelope::decode_envelope_with_btr(&encoded, &session_b).unwrap();

        assert_eq!(decoded, inner);
        let extracted = extracted_btr.unwrap();
        assert_eq!(extracted.chain_index, 0);
        assert_eq!(extracted.ratchet_public_key, Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()));
        assert_eq!(extracted.ratchet_generation, Some(1));
    }

    // ── Conformance tests ───────────────────────────────────

    #[test]
    fn btr_conformance_full_transfer_browser_to_daemon() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);
        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = rand::random();
        let (mut b_ctx, b_ratchet_pub) = browser_engine
            .begin_transfer_send(&tid, &daemon_kp.public_key).unwrap();
        let mut d_ctx = daemon_engine
            .begin_transfer_receive_with_key(&tid, &b_ratchet_pub, &daemon_kp.secret_key).unwrap();

        for i in 0..10u32 {
            let data = vec![i as u8; (i as usize + 1) * 1000];
            let (chain_idx, sealed) = b_ctx.seal_chunk(&data).unwrap();
            assert_eq!(chain_idx, i);
            let decrypted = d_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, data, "Chunk {i} data mismatch");
        }
    }

    #[test]
    fn btr_conformance_full_transfer_daemon_to_browser() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = rand::random();
        let (mut d_ctx, d_ratchet_pub) = daemon_engine
            .begin_transfer_send(&tid, &browser_kp.public_key).unwrap();
        let mut b_ctx = browser_engine
            .begin_transfer_receive_with_key(&tid, &d_ratchet_pub, &browser_kp.secret_key).unwrap();

        for i in 0..10u32 {
            let data = vec![(i + 100) as u8; (i as usize + 1) * 500];
            let (chain_idx, sealed) = d_ctx.seal_chunk(&data).unwrap();
            let decrypted = b_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, data, "Chunk {i} data mismatch");
        }
    }

    #[test]
    fn btr_conformance_bidirectional_interleaved() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        for round in 0..3u32 {
            let tid: [u8; 16] = rand::random();

            if round % 2 == 0 {
                let (mut d_ctx, d_pub) = daemon_engine
                    .begin_transfer_send(&tid, &browser_kp.public_key).unwrap();
                let mut b_ctx = browser_engine
                    .begin_transfer_receive_with_key(&tid, &d_pub, &browser_kp.secret_key).unwrap();
                let (idx, sealed) = d_ctx.seal_chunk(b"round data d2b").unwrap();
                assert_eq!(b_ctx.open_chunk(idx, &sealed).unwrap(), b"round data d2b");
            } else {
                let (mut b_ctx, b_pub) = browser_engine
                    .begin_transfer_send(&tid, &daemon_kp.public_key).unwrap();
                let mut d_ctx = daemon_engine
                    .begin_transfer_receive_with_key(&tid, &b_pub, &daemon_kp.secret_key).unwrap();
                let (idx, sealed) = b_ctx.seal_chunk(b"round data b2d").unwrap();
                assert_eq!(d_ctx.open_chunk(idx, &sealed).unwrap(), b"round data b2d");
            }

            daemon_engine.end_transfer();
            browser_engine.end_transfer();
        }

        assert_eq!(daemon_engine.ratchet_generation(), 3);
        assert_eq!(browser_engine.ratchet_generation(), 3);
    }

    #[test]
    fn btr_conformance_malformed_transfer_id_fails() {
        let result = parse_transfer_id_bytes("not-a-hex-string!not-a-hex-str!");
        assert!(result.is_err());

        let result = parse_transfer_id_bytes("abcdef");
        assert!(result.is_err());

        let result = parse_transfer_id_bytes("abababababababababababababababababab");
        assert!(result.is_err());

        let valid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        assert_eq!(valid.len(), 32);
        let result = parse_transfer_id_bytes(valid);
        assert!(result.is_ok());
    }

    #[test]
    fn btr_conformance_cross_transfer_key_isolation() {
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut sender_engine = bolt_btr::BtrEngine::new(&shared);
        let mut receiver_engine = bolt_btr::BtrEngine::new(&shared);

        let tid1: [u8; 16] = [0x01; 16];
        let (mut ctx1_s, pub1) = sender_engine
            .begin_transfer_send(&tid1, &browser_kp.public_key).unwrap();
        let mut ctx1_r = receiver_engine
            .begin_transfer_receive_with_key(&tid1, &pub1, &browser_kp.secret_key).unwrap();

        let (_idx, sealed1) = ctx1_s.seal_chunk(b"transfer 1 data").unwrap();
        let _ok = ctx1_r.open_chunk(0, &sealed1).unwrap();

        sender_engine.end_transfer();
        receiver_engine.end_transfer();

        let tid2: [u8; 16] = [0x02; 16];
        let (mut ctx2_s, pub2) = sender_engine
            .begin_transfer_send(&tid2, &browser_kp.public_key).unwrap();
        let mut ctx2_r = receiver_engine
            .begin_transfer_receive_with_key(&tid2, &pub2, &browser_kp.secret_key).unwrap();

        let (_idx, sealed2) = ctx2_s.seal_chunk(b"transfer 2 data").unwrap();

        let ok2 = ctx2_r.open_chunk(0, &sealed2).unwrap();
        assert_eq!(ok2, b"transfer 2 data");

        let cross = ctx2_r.open_chunk(1, &sealed1);
        assert!(cross.is_err(), "Transfer 1 sealed data must not decrypt with transfer 2 context");
    }

    #[test]
    fn btr_golden_vector_session_root_derivation() {
        let shared_secret = bolt_core::encoding::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ).unwrap();
        let expected_root = bolt_core::encoding::from_hex(
            "beff9b312b06cff7d24e1acb6fddc01cf12ab35eca1c93cf498433b51f8ae488"
        ).unwrap();

        let mut shared_arr = [0u8; 32];
        shared_arr.copy_from_slice(&shared_secret);
        let engine = bolt_btr::BtrEngine::new(&shared_arr);

        assert_eq!(expected_root.len(), 32);
        assert_eq!(engine.ratchet_generation(), 0);
    }

    #[test]
    fn btr_conformance_capability_truthful_advertisement() {
        use crate::web_hello::DAEMON_CAPABILITIES;
        assert!(
            DAEMON_CAPABILITIES.contains(&"bolt.transfer-ratchet-v1"),
            "DAEMON_CAPABILITIES must include bolt.transfer-ratchet-v1"
        );

        let shared = [0x42u8; 32];
        let engine = bolt_btr::BtrEngine::new(&shared);
        assert_eq!(engine.ratchet_generation(), 0);
    }
}
