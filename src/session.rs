//! Session context for web-interop DataChannel mode (INTEROP-3).
//!
//! After the encrypted HELLO exchange completes, the negotiated session
//! state (keypair, remote public key, capabilities) must persist for
//! the lifetime of the DataChannel. `SessionContext` carries this state.
//!
//! Created only when `--interop-dc web_dc_v1` is active.

use bolt_core::crypto::KeyPair;

use crate::web_hello::HelloState;

// ── Session Context ────────────────────────────────────────

/// Holds the HELLO outcome for post-handshake DataChannel operations.
///
/// Invariants:
/// - `hello_state` is completed at construction time (HELLO already done).
/// - `session_legacy` is never true in web_dc_v1 mode (enforced by caller).
pub(crate) struct SessionContext {
    pub local_keypair: KeyPair,
    pub remote_public_key: [u8; 32],
    pub negotiated_capabilities: Vec<String>,
    #[allow(dead_code)] // Wired into is_hello_complete(); not yet called in runtime
    hello_state: HelloState,
}

impl SessionContext {
    /// Build a session context from the HELLO exchange outcome.
    ///
    /// `hello_state` is immediately marked completed — the caller has
    /// already finished the HELLO exchange before calling this.
    pub fn new(
        local_keypair: KeyPair,
        remote_public_key: [u8; 32],
        negotiated_capabilities: Vec<String>,
    ) -> Self {
        let mut hello_state = HelloState::new();
        // Safe: this is the only call, immediately after HELLO completes.
        hello_state
            .mark_completed()
            .expect("BUG: HelloState was already completed before SessionContext::new");
        Self {
            local_keypair,
            remote_public_key,
            negotiated_capabilities,
            hello_state,
        }
    }

    /// Check if a specific capability was negotiated.
    pub fn has_capability(&self, cap: &str) -> bool {
        self.negotiated_capabilities.iter().any(|c| c == cap)
    }

    /// Shorthand: was `bolt.profile-envelope-v1` negotiated?
    pub fn envelope_v1_negotiated(&self) -> bool {
        self.has_capability("bolt.profile-envelope-v1")
    }

    /// Whether the HELLO exchange has completed.
    #[allow(dead_code)] // Infrastructure for future gating; tested
    pub fn is_hello_complete(&self) -> bool {
        self.hello_state.is_completed()
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bolt_core::identity::generate_identity_keypair;

    fn make_ctx(caps: Vec<String>) -> SessionContext {
        let kp = generate_identity_keypair();
        let remote_pk = generate_identity_keypair().public_key;
        SessionContext::new(kp, remote_pk, caps)
    }

    #[test]
    fn envelope_v1_negotiated_true_when_cap_present() {
        let ctx = make_ctx(vec!["bolt.profile-envelope-v1".to_string()]);
        assert!(ctx.envelope_v1_negotiated());
    }

    #[test]
    fn envelope_v1_negotiated_false_when_cap_absent() {
        let ctx = make_ctx(vec![]);
        assert!(!ctx.envelope_v1_negotiated());
    }

    #[test]
    fn envelope_v1_negotiated_false_with_other_caps() {
        let ctx = make_ctx(vec!["bolt.file-hash".to_string()]);
        assert!(!ctx.envelope_v1_negotiated());
    }

    #[test]
    fn has_capability_works() {
        let ctx = make_ctx(vec![
            "bolt.profile-envelope-v1".to_string(),
            "bolt.file-hash".to_string(),
        ]);
        assert!(ctx.has_capability("bolt.profile-envelope-v1"));
        assert!(ctx.has_capability("bolt.file-hash"));
        assert!(!ctx.has_capability("bolt.nonexistent"));
    }

    #[test]
    fn hello_state_completed_after_new() {
        let ctx = make_ctx(vec![]);
        assert!(ctx.is_hello_complete());
    }

    #[test]
    fn stores_remote_pk() {
        let kp = generate_identity_keypair();
        let remote_kp = generate_identity_keypair();
        let remote_pk = remote_kp.public_key;
        let ctx = SessionContext::new(kp, remote_pk, vec![]);
        assert_eq!(ctx.remote_public_key, remote_pk);
    }

    #[test]
    fn stores_negotiated_caps() {
        let caps = vec![
            "bolt.profile-envelope-v1".to_string(),
            "bolt.file-hash".to_string(),
        ];
        let ctx = make_ctx(caps.clone());
        assert_eq!(ctx.negotiated_capabilities, caps);
    }

    #[test]
    fn stores_local_keypair() {
        let kp = generate_identity_keypair();
        let pk = kp.public_key;
        let remote_pk = generate_identity_keypair().public_key;
        let ctx = SessionContext::new(kp, remote_pk, vec![]);
        assert_eq!(ctx.local_keypair.public_key, pk);
    }
}
