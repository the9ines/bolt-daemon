//! Bolt Daemon library — shared modules for binary targets and integration tests.
//!
//! Core protocol modules are `pub` for binary crate access but are NOT a
//! stable public API. This is an application crate, not a reusable library.
//! Use `test_support` (behind the `test-support` feature) for integration tests.

#[doc(hidden)]
pub mod dc_messages;
#[doc(hidden)]
pub mod envelope;
#[doc(hidden)]
pub mod identity_store;
#[doc(hidden)]
pub mod session;
#[doc(hidden)]
pub mod transfer;
#[doc(hidden)]
pub mod web_hello;

/// Input validation boundary for WS file transfers (MODULARITY-AUDITABILITY-2).
/// Pure functions — no global state, no async.
#[doc(hidden)]
pub mod ws_validation;

/// WebSocket server endpoint (RC5 PM-RC-02).
/// Feature-gated behind `transport-ws`.
#[cfg(feature = "transport-ws")]
#[doc(hidden)]
pub mod ws_endpoint;

/// Deterministic payload exchanged during the legacy hello protocol.
/// Used by `web_hello::parse_hello_message` for no-downgrade detection.
pub const HELLO_PAYLOAD: &[u8] = b"bolt-hello-v1";

// ── IPC Transport (for integration tests) ───────────────────

/// Re-export: default IPC endpoint path for the current platform.
pub const IPC_DEFAULT_PATH: &str = ipc::transport::DEFAULT_IPC_PATH;

/// Re-export: check if a path is a Windows named pipe path.
pub fn ipc_transport_is_windows_pipe(path: &str) -> bool {
    ipc::transport::is_windows_pipe_path(path)
}

/// Re-export: start the IPC server (for integration tests).
pub fn ipc_server_start(path: &str) -> std::io::Result<ipc::server::IpcServer> {
    ipc::server::IpcServer::start(path)
}

/// Re-export: bind a raw IPC listener (for integration tests).
pub fn ipc_transport_bind(
    path: &str,
) -> std::io::Result<(ipc::transport::IpcListener, std::path::PathBuf)> {
    ipc::transport::IpcListener::bind(path)
}

#[doc(hidden)]
pub mod ipc;

/// WebTransport/HTTP3 server endpoint (WTI2).
/// Feature-gated behind `transport-webtransport`.
#[cfg(feature = "transport-webtransport")]
#[doc(hidden)]
pub mod wt_endpoint;

/// QUIC transport adapter (RC3 reference path).
/// Feature-gated behind `transport-quic`.
#[cfg(feature = "transport-quic")]
#[doc(hidden)]
pub mod quic_transport;

/// Test-only re-exports for integration tests.
///
/// Gated behind `--features test-support` so release builds carry no
/// implicit API surface commitment. Integration tests should import
/// from `bolt_daemon::test_support` rather than reaching into modules
/// directly.
#[cfg(feature = "test-support")]
pub mod test_support {
    // Envelope-phase
    pub use crate::envelope::{
        decode_envelope, encode_envelope, make_error_message, DcErrorMessage, EnvelopeError,
    };

    // HELLO-phase
    pub use crate::web_hello::{
        build_hello_message, daemon_capabilities, negotiate_capabilities, parse_hello_message,
        parse_hello_typed, HelloError, HelloState, WebHelloInner,
    };

    // Session (canonical in bolt_core::session since RC2-EXEC-E)
    pub use crate::session::{SessionContext, SessionState};

    // Inner messages
    pub use crate::dc_messages::{encode_dc_message, parse_dc_message, DcMessage, DcParseError};

    // Transfer SM (re-exported from bolt-transfer-core via adapter)
    pub use crate::transfer::{
        SendChunk, SendOffer, SendSession, SendState, Sha256Verifier, TransferError,
        TransferSession, TransferState,
    };

    // Identity store
    pub use crate::identity_store::{
        ensure_parent_dir_secure, load_or_create_identity, resolve_identity_path,
        resolve_identity_path_from_data_dir, validate_file_mode_0600, IdentityStoreError,
    };
}
