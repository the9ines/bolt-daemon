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
pub mod session;
#[doc(hidden)]
pub mod web_hello;

/// Deterministic payload exchanged during the legacy hello protocol.
/// Used by `web_hello::parse_hello_message` for no-downgrade detection.
pub const HELLO_PAYLOAD: &[u8] = b"bolt-hello-v1";

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

    // Session
    pub use crate::session::SessionContext;

    // Inner messages
    pub use crate::dc_messages::{encode_dc_message, parse_dc_message, DcMessage, DcParseError};
}
