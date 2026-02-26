//! Trust store and pairing approval logic.
//!
//! Persistence of `allow_always` / `deny_always` decisions is DISABLED until
//! stable identity keys are available. The trust store infrastructure exists
//! and is tested, but `check_pairing_approval` treats _always as _once and
//! does not write to disk.

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

// ── Trust Store ─────────────────────────────────────────────

/// Default path for the trust store.
pub fn default_trust_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/bolt-daemon/trust.json")
}

/// Persistent trust decisions keyed by peer identity.
///
/// Currently keyed by signaling `peer_id` which is session-ephemeral.
/// Will be re-keyed to stable identity public keys when available.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TrustStore {
    pub version: u32,
    pub peers: HashMap<String, Decision>,
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

    /// Save to file atomically (write .tmp → fsync → rename).
    /// Creates parent directories if needed.
    ///
    /// Currently used by tests only; will be called from `check_pairing_approval`
    /// once stable identity keys enable meaningful persistence.
    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("json.tmp");
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write to temp file
        std::fs::write(&tmp_path, &contents)?;

        // fsync best-effort
        if let Ok(f) = std::fs::File::open(&tmp_path) {
            let _ = f.sync_all();
        }

        // Atomic rename
        std::fs::rename(&tmp_path, path)?;

        Ok(())
    }

    /// Get the stored decision for a peer, if any.
    pub fn get(&self, peer_id: &str) -> Option<Decision> {
        self.peers.get(peer_id).copied()
    }

    /// Store a decision for a peer. Only persists `AllowAlways` / `DenyAlways`.
    /// `AllowOnce` / `DenyOnce` are ignored (not stored).
    ///
    /// Currently used by tests only; will be called from `check_pairing_approval`
    /// once stable identity keys enable meaningful persistence.
    #[allow(dead_code)]
    pub fn set(&mut self, peer_id: &str, decision: Decision) {
        match decision {
            Decision::AllowAlways | Decision::DenyAlways => {
                self.peers.insert(peer_id.to_string(), decision);
            }
            Decision::AllowOnce | Decision::DenyOnce => {
                // _once decisions are not persisted
            }
        }
    }
}

// ── Pairing Approval ────────────────────────────────────────

/// Check whether a pairing request from `from_peer` should be approved.
///
/// Decision flow:
/// 1. Check trust store for stored decision (AllowAlways / DenyAlways)
/// 2. Apply pairing policy (deny/allow bypass UI)
/// 3. If policy is `Ask`: emit pairing.request over IPC, block for decision
/// 4. If UI returns _always variant: log that persistence is disabled
///
/// Returns `true` if pairing is allowed, `false` if denied.
pub fn check_pairing_approval(
    ipc_server: Option<&IpcServer>,
    trust_path: &Path,
    from_peer: &str,
    policy: PairingPolicy,
) -> bool {
    // 1. Check trust store
    let store = TrustStore::load(trust_path);
    if let Some(decision) = store.get(from_peer) {
        match decision {
            Decision::AllowAlways => {
                eprintln!("[PAIRING_TRUST_HIT] allow_always for peer '{from_peer}'");
                return true;
            }
            Decision::DenyAlways => {
                eprintln!("[PAIRING_TRUST_HIT] deny_always for peer '{from_peer}'");
                return false;
            }
            _ => {} // _once variants shouldn't be in store, but handle gracefully
        }
    }

    // 2. Apply pairing policy for non-UI paths
    match policy {
        PairingPolicy::Deny => {
            eprintln!("[PAIRING_DENIED] policy=deny — no UI consultation");
            return false;
        }
        PairingPolicy::Allow => {
            eprintln!("[PAIRING_ALLOWED] policy=allow — auto-approved (headless)");
            return true;
        }
        PairingPolicy::Ask => {
            // Fall through to IPC
        }
    }

    // 3. Policy is Ask — need IPC
    let server = match ipc_server {
        Some(s) if s.is_ui_connected() => s,
        Some(_) => {
            eprintln!("[PAIRING_DENIED] no UI connected — fail-closed deny");
            return false;
        }
        None => {
            eprintln!("[PAIRING_DENIED] IPC server unavailable — fail-closed deny");
            return false;
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
            return false;
        }
    };
    server.emit_event(IpcMessage::new_event("pairing.request", payload_value));

    // 4. Block for decision
    match server.await_decision(&request_id, DECISION_TIMEOUT) {
        Some(dp) => {
            let allowed = matches!(dp.decision, Decision::AllowOnce | Decision::AllowAlways);

            // Log _always decisions but do NOT persist (keys are ephemeral)
            if matches!(dp.decision, Decision::AllowAlways | Decision::DenyAlways) {
                eprintln!(
                    "[PAIRING_DECISION] {:?} for peer '{from_peer}' — persistence disabled \
                     (peer_id is session-ephemeral, stable identity keys required)",
                    dp.decision
                );
            } else {
                eprintln!(
                    "[PAIRING_DECISION] {:?} for peer '{from_peer}'",
                    dp.decision
                );
            }

            allowed
        }
        None => {
            eprintln!("[PAIRING_DENIED] timeout — fail-closed deny for peer '{from_peer}'");
            false
        }
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
    fn check_approval_no_ipc_no_trust_returns_false() {
        let path = temp_trust_path();
        let result = check_pairing_approval(None, &path, "unknown-peer", PairingPolicy::Ask);
        assert!(!result, "should deny when no IPC server and no trust entry");
    }

    #[test]
    fn check_approval_policy_deny_returns_false() {
        let path = temp_trust_path();
        let result = check_pairing_approval(None, &path, "any-peer", PairingPolicy::Deny);
        assert!(!result, "policy=deny should always deny");
    }

    #[test]
    fn check_approval_policy_allow_returns_true() {
        let path = temp_trust_path();
        let result = check_pairing_approval(None, &path, "any-peer", PairingPolicy::Allow);
        assert!(result, "policy=allow should always allow");
    }

    #[test]
    fn check_approval_stored_allow_always_returns_true() {
        let path = temp_trust_path();
        let mut store = TrustStore::new();
        store.set("trusted-peer", Decision::AllowAlways);
        store.save(&path).unwrap();

        // Even with no IPC, trust store hit should return true
        let result = check_pairing_approval(None, &path, "trusted-peer", PairingPolicy::Ask);
        assert!(result, "stored allow_always should return true");

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn check_approval_stored_deny_always_returns_false() {
        let path = temp_trust_path();
        let mut store = TrustStore::new();
        store.set("blocked-peer", Decision::DenyAlways);
        store.save(&path).unwrap();

        let result = check_pairing_approval(None, &path, "blocked-peer", PairingPolicy::Ask);
        assert!(!result, "stored deny_always should return false");

        // Cleanup
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
}
