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
