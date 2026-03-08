//! Transfer adapter — thin facade over bolt-transfer-core.
//!
//! T-STREAM-0: This module re-exports the canonical transfer state machine
//! from `bolt_transfer_core` and provides the daemon-specific
//! `Sha256Verifier` (backed by `bolt_core::hash::sha256_hex`).
//!
//! Prior to T-STREAM-0, this file contained the inline state machines.
//! All state machine logic now lives in bolt-transfer-core.

// ── Re-exports from bolt-transfer-core ──────────────────────
// These maintain backward-compatible import paths for rendezvous.rs
// and test_support consumers.

pub use bolt_transfer_core::error::TransferError;
pub use bolt_transfer_core::receive::{ReceiveSession, MAX_TRANSFER_BYTES};
pub use bolt_transfer_core::send::{SendChunk, SendOffer, SendSession, DEFAULT_CHUNK_SIZE};
pub use bolt_transfer_core::state::{CancelReason, TransferState};

// ── Legacy type aliases ─────────────────────────────────────
// bolt-daemon code and test_support previously exported TransferSession
// and SendState. These aliases maintain compatibility without requiring
// changes to every consumer.

/// Legacy alias: ReceiveSession was previously TransferSession in the daemon.
pub type TransferSession = ReceiveSession;

/// Legacy alias: SendState was a separate enum, now unified into TransferState.
pub type SendState = TransferState;

// ── Daemon-specific integrity verifier ──────────────────────

/// SHA-256 integrity verifier using bolt_core::hash.
///
/// Injected into ReceiveSession::on_file_finish() when bolt.file-hash
/// is negotiated. The transfer core has no crypto dependency — this
/// is the daemon's concrete implementation.
pub struct Sha256Verifier;

impl bolt_transfer_core::IntegrityVerifier for Sha256Verifier {
    fn verify(&self, data: &[u8], expected_hash: &str) -> bool {
        let computed = bolt_core::hash::sha256_hex(data);
        computed.eq_ignore_ascii_case(expected_hash)
    }
}
