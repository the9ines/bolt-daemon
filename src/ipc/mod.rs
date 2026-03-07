//! IPC channel between bolt-daemon and a native UI client.
//!
//! Transport: Unix domain socket (Unix/macOS) or named pipe (Windows).
//! Protocol: NDJSON (line-delimited JSON).
//! Policy: fail-closed (no UI connected = pending/deny).

pub mod id;
pub mod server;
pub mod transport;
pub mod trust;
pub mod types;
