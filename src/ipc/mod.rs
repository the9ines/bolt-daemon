//! IPC channel between bolt-daemon and a native UI client.
//!
//! Transport: Unix domain socket, NDJSON protocol.
//! Policy: fail-closed (no UI connected = pending/deny).

pub mod id;
pub mod server;
pub mod trust;
pub mod types;
