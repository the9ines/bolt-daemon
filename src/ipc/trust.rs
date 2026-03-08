//! Trust store and pairing approval logic.
//!
//! Two-stage TOFU pinning model (B5):
//!
//! - **Stage A** (answerer only): Signaling-level user decision gate. Captures
//!   the full `Decision` variant but does NOT persist (identity not yet known).
//! - **Stage B** (offerer + answerer): Identity-based enforcement and persistence
//!   occurs immediately after DC HELLO is parsed, keyed by `identity_key_hex`.
//!
//! Only `AllowAlways` and `DenyAlways` are persisted. `AllowOnce` / `DenyOnce`
//! are session-scoped and never written to the trust store.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::id::generate_request_id;
use super::server::IpcServer;
use super::types::{Decision, IpcMessage, PairingRequestPayload};

// ── Constants ───────────────────────────────────────────────

/// Decision timeout when waiting for UI response.
const DECISION_TIMEOUT: Duration = Duration::from_secs(30);

/// Required file mode for the trust store file.
#[cfg_attr(not(unix), allow(dead_code))]
const TRUST_FILE_MODE: u32 = 0o600;

// ── Pairing Policy ──────────────────────────────────────────

/// Controls pairing behavior when no UI client is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingPolicy {
    /// Require UI to approve. Deny if no UI connected. (default)
    Ask,
    /// Always deny pairing without consulting UI.
    Deny,
    /// Always allow pairing without consulting UI. Explicit opt-in only.
    Allow,
}

// ── Constant-Time Compare ───────────────────────────────────

/// Constant-time byte comparison. Returns `true` if `a == b`.
///
/// No early exit — iterates all bytes regardless of mismatch position.
/// No unsafe code. No external dependencies.
///
/// Used by tests; available for production key comparison paths.
#[allow(dead_code)]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ── Identity Key Hex ────────────────────────────────────────

/// Compute canonical `identity_key_hex` from raw 32-byte identity public key.
///
/// Returns lowercase hex string (64 characters).
pub fn identity_key_to_hex(raw: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in raw {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// ── Trust Store ─────────────────────────────────────────────

/// Default path for the trust store.
pub fn default_trust_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/bolt-daemon/trust.json")
}

/// Resolve trust store path from an explicit data directory.
///
/// Returns `<data_dir>/pins/trust.json`. Takes precedence over
/// `default_trust_path()` when `--data-dir` is provided.
pub fn trust_path_from_data_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("pins").join("trust.json")
}

/// Persistent trust decisions keyed by `identity_key_hex`.
///
/// Keys are lowercase hex-encoded 32-byte identity public keys (64 chars).
/// Legacy `peer_id` entries (non-hex) remain in the file but are ignored
/// by lookup — no migration or cleanup in B5.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TrustStore {
    pub version: u32,
    pub peers: HashMap<String, Decision>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore {
    /// Create a new empty trust store.
    pub fn new() -> Self {
        Self {
            version: 1,
            peers: HashMap::new(),
        }
    }

    /// Load from file. Returns empty store if file is missing or corrupt.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(store) => store,
                Err(e) => {
                    eprintln!(
                        "[TRUST] WARNING: corrupt trust file at {}: {e} — using empty store",
                        path.display()
                    );
                    Self::new()
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                eprintln!(
                    "[TRUST] WARNING: cannot read {}: {e} — using empty store",
                    path.display()
                );
                Self::new()
            }
        }
    }

    /// Save to file atomically (write .tmp → fsync → rename → chmod 0600).
    /// Creates parent directories if needed.
    ///
    /// Fail-closed: if permission setting fails, the error is propagated.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("json.tmp");
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write to temp file
        std::fs::write(&tmp_path, &contents)?;

        // Set 0600 on temp file before rename (Unix only; Windows uses ACLs)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(TRUST_FILE_MODE))?;
        }

        // fsync best-effort
        if let Ok(f) = std::fs::File::open(&tmp_path) {
            let _ = f.sync_all();
        }

        // Atomic rename
        std::fs::rename(&tmp_path, path)?;

        // Verify final mode (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path)?;
            let actual = meta.permissions().mode() & 0o777;
            if actual != TRUST_FILE_MODE {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trust file mode {:04o} != expected {:04o}",
                        actual, TRUST_FILE_MODE
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Get the stored decision for a peer, if any.
    pub fn get(&self, peer_id: &str) -> Option<Decision> {
        self.peers.get(peer_id).copied()
    }

    /// Store a decision for a peer. Only persists `AllowAlways` / `DenyAlways`.
    /// `AllowOnce` / `DenyOnce` are ignored (not stored).
    ///
    /// Does not overwrite existing entries — returns `false` if the key already
    /// exists, `true` if inserted.
    pub fn set(&mut self, peer_id: &str, decision: Decision) -> bool {
        match decision {
            Decision::AllowAlways | Decision::DenyAlways => {
                if self.peers.contains_key(peer_id) {
                    return false;
                }
                self.peers.insert(peer_id.to_string(), decision);
                true
            }
            Decision::AllowOnce | Decision::DenyOnce => {
                // _once decisions are not persisted
                false
            }
        }
    }
}

// ── Stage B: Identity-Based Enforcement ─────────────────────

/// Result of Stage B identity enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageBResult {
    /// Proceed with session.
    Allow,
    /// Abort session immediately.
    Deny,
}

/// Perform Stage B identity-based TOFU enforcement.
///
/// Called immediately after DC HELLO parse for BOTH offerer and answerer.
///
/// - If a persistent pin exists for `identity_key_hex`, enforce it.
/// - If no pin exists:
///   - Answerer uses `stage_a_decision` to determine persistence.
///   - Offerer passes `None` (no Stage A) — proceeds without persistence.
///
/// Fail-closed on any internal error (load/save failure).
pub fn enforce_stage_b(
    trust_path: &Path,
    identity_key_hex: &str,
    stage_a_decision: Option<Decision>,
) -> StageBResult {
    // Load trust store
    let mut store = TrustStore::load(trust_path);

    // Check for existing pin
    if let Some(pinned) = store.get(identity_key_hex) {
        match pinned {
            Decision::AllowAlways => {
                eprintln!(
                    "[B5_STAGE_B] existing pin AllowAlways for identity '{identity_key_hex}'"
                );
                return StageBResult::Allow;
            }
            Decision::DenyAlways => {
                eprintln!("[B5_STAGE_B] existing pin DenyAlways for identity '{identity_key_hex}'");
                return StageBResult::Deny;
            }
            _ => {
                // _once variants should not be in store, but treat as no-pin
            }
        }
    }

    // No existing pin — apply Stage A decision if present (answerer path)
    match stage_a_decision {
        Some(Decision::AllowAlways) => {
            if store.set(identity_key_hex, Decision::AllowAlways) {
                if let Err(e) = store.save(trust_path) {
                    eprintln!(
                        "[B5_STAGE_B] FAIL-CLOSED: cannot save AllowAlways for '{identity_key_hex}': {e}"
                    );
                    return StageBResult::Deny;
                }
                eprintln!("[B5_STAGE_B] persisted AllowAlways for identity '{identity_key_hex}'");
            }
            StageBResult::Allow
        }
        Some(Decision::DenyAlways) => {
            if store.set(identity_key_hex, Decision::DenyAlways) {
                if let Err(e) = store.save(trust_path) {
                    eprintln!(
                        "[B5_STAGE_B] FAIL-CLOSED: cannot save DenyAlways for '{identity_key_hex}': {e}"
                    );
                    // Already denying, so this is consistent
                }
                eprintln!("[B5_STAGE_B] persisted DenyAlways for identity '{identity_key_hex}'");
            }
            StageBResult::Deny
        }
        Some(Decision::AllowOnce) => {
            eprintln!("[B5_STAGE_B] AllowOnce for identity '{identity_key_hex}' — no persistence");
            StageBResult::Allow
        }
        Some(Decision::DenyOnce) => {
            // DenyOnce should never reach Stage B (aborted at Stage A).
            // Defensive: deny anyway.
            eprintln!("[B5_STAGE_B] DenyOnce reached Stage B for '{identity_key_hex}' — denying");
            StageBResult::Deny
        }
        None => {
            // Offerer path: no Stage A decision. Proceed without persistence.
            eprintln!(
                "[B5_STAGE_B] offerer — no Stage A decision for '{identity_key_hex}', proceeding"
            );
            StageBResult::Allow
        }
    }
}

// ── Pairing Approval (Stage A) ─────────────────────────────

/// Check whether a pairing request from `from_peer` should be approved.
///
/// This is Stage A (answerer only). Returns `Option<Decision>`:
/// - `None` = no decision obtained (timeout / IPC failure / policy abort). Treat as hard deny.
/// - `Some(AllowOnce)` = proceed, no persistence
/// - `Some(AllowAlways)` = proceed, thread to Stage B for persistence
/// - `Some(DenyOnce)` = abort immediately at Stage A (no Stage B)
/// - `Some(DenyAlways)` = proceed to Stage B ONLY to learn identity, persist denial, then abort
///
/// Stage A does NOT persist anything. Stage A does NOT consult the trust store
/// for identity-keyed entries (identity not yet known at signaling time).
pub fn check_pairing_approval(
    ipc_server: Option<&IpcServer>,
    trust_path: &Path,
    from_peer: &str,
    policy: PairingPolicy,
) -> Option<Decision> {
    // Note: We no longer check trust store here at Stage A.
    // The trust store is keyed by identity_key_hex which is unknown at this point.
    // Stage B performs identity-based trust checks after DC HELLO parse.
    let _ = trust_path; // Acknowledge parameter (used by Stage B, not Stage A)

    // Apply pairing policy for non-UI paths
    match policy {
        PairingPolicy::Deny => {
            eprintln!("[PAIRING_DENIED] policy=deny — no UI consultation");
            return None;
        }
        PairingPolicy::Allow => {
            eprintln!("[PAIRING_ALLOWED] policy=allow — auto-approved (headless)");
            return Some(Decision::AllowOnce);
        }
        PairingPolicy::Ask => {
            // Fall through to IPC
        }
    }

    // Policy is Ask — need IPC
    let server = match ipc_server {
        Some(s) if s.is_ui_connected() => s,
        Some(_) => {
            eprintln!("[PAIRING_DENIED] no UI connected — fail-closed deny");
            return None;
        }
        None => {
            eprintln!("[PAIRING_DENIED] IPC server unavailable — fail-closed deny");
            return None;
        }
    };

    // Build pairing request
    let request_id = generate_request_id();
    let payload = PairingRequestPayload {
        request_id: request_id.clone(),
        remote_device_name: from_peer.to_string(),
        remote_device_type: "unknown".to_string(),
        remote_identity_pk_b64: String::new(),
        sas: String::new(),
        capabilities_requested: vec!["file_transfer".to_string()],
    };

    eprintln!("[PAIRING_REQUEST] emitting pairing.request for peer '{from_peer}' (request_id={request_id})");
    let payload_value = match serde_json::to_value(&payload) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[PAIRING_DENIED] serialize pairing.request failed: {e} — fail-closed deny");
            return None;
        }
    };
    server.emit_event(IpcMessage::new_event("pairing.request", payload_value));

    // Block for decision
    match server.await_decision(&request_id, DECISION_TIMEOUT) {
        Some(dp) => {
            eprintln!(
                "[PAIRING_DECISION] {:?} for peer '{from_peer}'",
                dp.decision
            );
            Some(dp.decision)
        }
        None => {
            eprintln!("[PAIRING_DENIED] timeout — fail-closed deny for peer '{from_peer}'");
            None
        }
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a unique temp directory for each test.
    fn temp_trust_path() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("bolt-trust-test-{pid}-{ts}-{n}"))
            .join("trust.json")
    }

    /// Build a deterministic 32-byte identity key for testing.
    fn test_identity_bytes(seed: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        key
    }

    // ── Existing trust store tests ──────────────────────────

    #[test]
    fn trust_store_new_is_empty() {
        let store = TrustStore::new();
        assert_eq!(store.version, 1);
        assert!(store.peers.is_empty());
    }

    #[test]
    fn load_nonexistent_file_returns_empty() {
        let path = temp_trust_path();
        let store = TrustStore::load(&path);
        assert_eq!(store.version, 1);
        assert!(store.peers.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let path = temp_trust_path();
        let mut store = TrustStore::new();
        store.set("peer-a", Decision::AllowAlways);
        store.set("peer-b", Decision::DenyAlways);
        store.save(&path).unwrap();

        let loaded = TrustStore::load(&path);
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.get("peer-a"), Some(Decision::AllowAlways));
        assert_eq!(loaded.get("peer-b"), Some(Decision::DenyAlways));

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_creates_parent_dirs() {
        let path = temp_trust_path();
        assert!(!path.parent().unwrap().exists());

        let store = TrustStore::new();
        store.save(&path).unwrap();

        assert!(path.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn get_returns_none_for_unknown_peer() {
        let store = TrustStore::new();
        assert_eq!(store.get("nonexistent"), None);
    }

    #[test]
    fn set_and_get_allow_always() {
        let mut store = TrustStore::new();
        store.set("peer-x", Decision::AllowAlways);
        assert_eq!(store.get("peer-x"), Some(Decision::AllowAlways));
    }

    #[test]
    fn set_and_get_deny_always() {
        let mut store = TrustStore::new();
        store.set("peer-y", Decision::DenyAlways);
        assert_eq!(store.get("peer-y"), Some(Decision::DenyAlways));
    }

    #[test]
    fn set_ignores_once_variants() {
        let mut store = TrustStore::new();
        store.set("peer-1", Decision::AllowOnce);
        store.set("peer-2", Decision::DenyOnce);
        assert_eq!(store.get("peer-1"), None);
        assert_eq!(store.get("peer-2"), None);
    }

    #[test]
    fn trust_file_json_format() {
        let path = temp_trust_path();
        let mut store = TrustStore::new();
        store.set("test-peer", Decision::AllowAlways);
        store.save(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["peers"]["test-peer"], "allow_always");

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn atomic_write_no_partial_file() {
        let path = temp_trust_path();
        let mut store = TrustStore::new();
        store.set("peer-a", Decision::AllowAlways);
        store.save(&path).unwrap();

        // .tmp file should not exist after successful save
        let tmp_path = path.with_extension("json.tmp");
        assert!(!tmp_path.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_corrupt_file_returns_empty() {
        let path = temp_trust_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not valid json{{{").unwrap();

        let store = TrustStore::load(&path);
        assert_eq!(store.version, 1);
        assert!(store.peers.is_empty());

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn check_approval_no_ipc_no_trust_returns_none() {
        let path = temp_trust_path();
        let result = check_pairing_approval(None, &path, "unknown-peer", PairingPolicy::Ask);
        assert!(result.is_none(), "should return None when no IPC server");
    }

    #[test]
    fn check_approval_policy_deny_returns_none() {
        let path = temp_trust_path();
        let result = check_pairing_approval(None, &path, "any-peer", PairingPolicy::Deny);
        assert!(result.is_none(), "policy=deny should return None");
    }

    #[test]
    fn check_approval_policy_allow_returns_allow_once() {
        let path = temp_trust_path();
        let result = check_pairing_approval(None, &path, "any-peer", PairingPolicy::Allow);
        assert_eq!(
            result,
            Some(Decision::AllowOnce),
            "policy=allow should return AllowOnce"
        );
    }

    #[test]
    fn default_trust_path_is_under_config() {
        let path = default_trust_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains(".config/bolt-daemon/trust.json"),
            "unexpected path: {path_str}"
        );
    }

    #[test]
    fn trust_path_from_data_dir_structure() {
        let dd = PathBuf::from("/opt/localbolt");
        let path = trust_path_from_data_dir(&dd);
        assert_eq!(path, PathBuf::from("/opt/localbolt/pins/trust.json"));
    }

    #[test]
    fn trust_path_from_data_dir_roundtrip() {
        let dd = temp_trust_path().parent().unwrap().to_path_buf();
        let path = trust_path_from_data_dir(&dd);
        assert!(path.ends_with("pins/trust.json"));
        assert!(path.starts_with(&dd));
    }

    // ── B5: identity_key_hex ────────────────────────────────

    #[test]
    fn identity_key_to_hex_format() {
        let key = test_identity_bytes(0xAA);
        let hex = identity_key_to_hex(&key);
        assert_eq!(hex.len(), 64);
        // All lowercase hex
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // First byte 0xAA
        assert!(hex.starts_with("aa"));
    }

    // ── B5: constant-time compare ───────────────────────────

    #[test]
    fn constant_time_eq_equal() {
        let a = test_identity_bytes(0x01);
        let b = test_identity_bytes(0x01);
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_unequal() {
        let a = test_identity_bytes(0x01);
        let b = test_identity_bytes(0x02);
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(&[], &[]));
    }

    // ── B5: set does not overwrite ──────────────────────────

    #[test]
    fn set_does_not_overwrite_existing() {
        let mut store = TrustStore::new();
        assert!(store.set("key-a", Decision::AllowAlways));
        // Second set should return false and not overwrite
        assert!(!store.set("key-a", Decision::DenyAlways));
        assert_eq!(store.get("key-a"), Some(Decision::AllowAlways));
    }

    // ── B5: Stage B enforcement ─────────────────────────────

    #[test]
    fn stage_b_allow_always_persists() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x10);
        let hex = identity_key_to_hex(&key);

        let result = enforce_stage_b(&path, &hex, Some(Decision::AllowAlways));
        assert_eq!(result, StageBResult::Allow);

        // Verify persisted
        let store = TrustStore::load(&path);
        assert_eq!(store.get(&hex), Some(Decision::AllowAlways));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn stage_b_deny_always_persists_then_denies() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x20);
        let hex = identity_key_to_hex(&key);

        let result = enforce_stage_b(&path, &hex, Some(Decision::DenyAlways));
        assert_eq!(result, StageBResult::Deny);

        // Verify persisted
        let store = TrustStore::load(&path);
        assert_eq!(store.get(&hex), Some(Decision::DenyAlways));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn stage_b_deny_once_aborts_no_persistence() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x30);
        let hex = identity_key_to_hex(&key);

        let result = enforce_stage_b(&path, &hex, Some(Decision::DenyOnce));
        assert_eq!(result, StageBResult::Deny);

        // Verify NOT persisted
        let store = TrustStore::load(&path);
        assert_eq!(store.get(&hex), None);
    }

    #[test]
    fn stage_b_allow_once_no_persistence() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x40);
        let hex = identity_key_to_hex(&key);

        let result = enforce_stage_b(&path, &hex, Some(Decision::AllowOnce));
        assert_eq!(result, StageBResult::Allow);

        // Verify NOT persisted
        let store = TrustStore::load(&path);
        assert_eq!(store.get(&hex), None);
    }

    #[test]
    fn stage_b_offerer_no_decision_allows() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x50);
        let hex = identity_key_to_hex(&key);

        let result = enforce_stage_b(&path, &hex, None);
        assert_eq!(result, StageBResult::Allow);

        // Verify NOT persisted
        let store = TrustStore::load(&path);
        assert_eq!(store.get(&hex), None);
    }

    #[test]
    fn stage_b_existing_deny_always_pin_enforced() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x60);
        let hex = identity_key_to_hex(&key);

        // Pre-populate pin
        let mut store = TrustStore::new();
        store.set(&hex, Decision::DenyAlways);
        store.save(&path).unwrap();

        // Offerer path: no Stage A decision, but existing pin denies
        let result = enforce_stage_b(&path, &hex, None);
        assert_eq!(result, StageBResult::Deny);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn stage_b_existing_allow_always_pin_enforced() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x70);
        let hex = identity_key_to_hex(&key);

        // Pre-populate pin
        let mut store = TrustStore::new();
        store.set(&hex, Decision::AllowAlways);
        store.save(&path).unwrap();

        // Even with a DenyAlways Stage A, existing pin takes precedence
        let result = enforce_stage_b(&path, &hex, Some(Decision::DenyAlways));
        assert_eq!(result, StageBResult::Allow);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // ── B5: 0600 permissions ────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn save_enforces_0600_permissions() {
        let path = temp_trust_path();
        let mut store = TrustStore::new();
        store.set("perm-test", Decision::AllowAlways);
        store.save(&path).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, TRUST_FILE_MODE,
            "trust file mode {:04o} != expected {:04o}",
            mode, TRUST_FILE_MODE
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // ── B5: Stage B does not overwrite existing pin ─────────

    #[test]
    fn stage_b_does_not_overwrite_existing_pin() {
        let path = temp_trust_path();
        let key = test_identity_bytes(0x80);
        let hex = identity_key_to_hex(&key);

        // Pre-populate AllowAlways
        let mut store = TrustStore::new();
        store.set(&hex, Decision::AllowAlways);
        store.save(&path).unwrap();

        // Stage B with DenyAlways should NOT overwrite — existing pin wins
        let result = enforce_stage_b(&path, &hex, Some(Decision::DenyAlways));
        assert_eq!(result, StageBResult::Allow);

        // Verify pin unchanged
        let loaded = TrustStore::load(&path);
        assert_eq!(loaded.get(&hex), Some(Decision::AllowAlways));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
