//! Bolt Daemon library — shared modules for binary targets and integration tests.
//!
//! Exposes the core protocol modules (web_hello, session, envelope, dc_messages)
//! so integration tests can exercise parse/decode paths against golden vectors.

pub mod dc_messages;
pub mod envelope;
pub mod session;
pub mod web_hello;

/// Deterministic payload exchanged during the legacy hello protocol.
/// Used by `web_hello::parse_hello_message` for no-downgrade detection.
pub const HELLO_PAYLOAD: &[u8] = b"bolt-hello-v1";
