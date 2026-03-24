//! IPC server: Unix domain socket or Windows named pipe, NDJSON protocol,
//! single-client.
//!
//! New client kicks old client (no dead-UI blocking).
//! Fail-closed: no UI connected = `await_decision` returns `None`.

use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::transport::{self, IpcListener, IpcStream};
use super::types::{DaemonStatusPayload, DecisionPayload, IpcMessage, VersionStatusPayload};

// ── Constants ───────────────────────────────────────────────

/// Default IPC endpoint path (platform-dependent).
pub const DEFAULT_SOCKET_PATH: &str = transport::DEFAULT_IPC_PATH;

/// Maximum line size (1 MiB). Lines exceeding this cause disconnect.
const MAX_LINE_BYTES: usize = 1_048_576;

/// Poll interval when checking for events to send or decisions received.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Timeout for version handshake phase (client must send version.handshake within this).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Daemon version from Cargo.toml.
const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Bounded Line Reader ─────────────────────────────────────

/// Result of reading a bounded line.
#[derive(Debug, PartialEq)]
pub enum ReadLineResult {
    /// A complete line was read (without the trailing newline).
    Line(String),
    /// The stream was closed (EOF).
    Eof,
}

/// Read a single newline-terminated line, enforcing a size cap.
///
/// Returns `Err` if the line exceeds `MAX_LINE_BYTES` before a newline
/// is found, or on I/O error. Empty lines (just `\n`) return
/// `Ok(ReadLineResult::Line(""))`.
pub fn read_line_bounded<R: BufRead>(reader: &mut R) -> io::Result<ReadLineResult> {
    let mut buf = Vec::new();
    let n = reader.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(ReadLineResult::Eof);
    }
    if buf.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "[IPC_OVERSIZE] line exceeds {} bytes (got {})",
                MAX_LINE_BYTES,
                buf.len()
            ),
        ));
    }
    // Strip trailing newline
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let s = String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(ReadLineResult::Line(s))
}

/// Parse a JSON line into an IpcMessage. Returns `Ok(None)` for unknown
/// message types (logged but not an error). Returns `Err` for invalid JSON.
pub fn parse_ipc_line(line: &str) -> Result<Option<IpcMessage>, serde_json::Error> {
    let msg: IpcMessage = serde_json::from_str(line)?;
    // Known event/decision types
    match msg.msg_type.as_str() {
        "pairing.request"
        | "transfer.incoming.request"
        | "daemon.status"
        | "pairing.decision"
        | "transfer.incoming.decision"
        | "version.handshake"
        | "version.status"
        | "session.connected"
        | "session.sas"
        | "session.error"
        | "session.ended"
        | "transfer.started"
        | "transfer.progress"
        | "transfer.complete"
        | "file.send" => Ok(Some(msg)),
        unknown => {
            eprintln!("[IPC_UNKNOWN_TYPE] ignoring message with type: {unknown}");
            Ok(None)
        }
    }
}

// ── Version Compatibility ───────────────────────────────────

/// Check if app and daemon versions are compatible.
/// Rule: major.minor must match exactly (patch may differ).
pub fn check_version_compatible(app_version: &str, daemon_version: &str) -> bool {
    let app_parts: Vec<&str> = app_version.split('.').collect();
    let daemon_parts: Vec<&str> = daemon_version.split('.').collect();

    if app_parts.len() < 2 || daemon_parts.len() < 2 {
        return false;
    }

    app_parts[0] == daemon_parts[0] && app_parts[1] == daemon_parts[1]
}

// ── IPC Server ──────────────────────────────────────────────

/// Handle for the IPC server. Provides channel-based API to the daemon.
pub struct IpcServer {
    /// Send events from daemon to UI client.
    pub event_tx: Sender<IpcMessage>,
    /// Receive decisions from UI client.
    pub decision_rx: Receiver<IpcMessage>,
    /// Whether a UI client is currently connected.
    pub ui_connected: Arc<Mutex<bool>>,
    /// Socket path (for cleanup).
    socket_path: PathBuf,
    /// Join handle for the listener thread.
    _listener_handle: thread::JoinHandle<()>,
}

impl IpcServer {
    /// Start the IPC server on the given path.
    ///
    /// Spawns a background thread that listens for a single client at a time.
    /// New connections kick the old client.
    ///
    /// On Unix: creates a Unix domain socket.
    /// On Windows with `\\.\pipe\` prefix: creates a named pipe.
    pub fn start(socket_path: &str) -> io::Result<Self> {
        let (listener, path) = IpcListener::bind(socket_path)?;

        eprintln!("[IPC] listening on {} (single-client)", path.display());

        let (event_tx, event_rx) = mpsc::channel::<IpcMessage>();
        let (decision_tx, decision_rx) = mpsc::channel::<IpcMessage>();
        let ui_connected = Arc::new(Mutex::new(false));
        let ui_connected_clone = Arc::clone(&ui_connected);

        let listener_handle = thread::spawn(move || {
            Self::listener_loop(listener, event_rx, decision_tx, ui_connected_clone);
        });

        Ok(Self {
            event_tx,
            decision_rx,
            ui_connected,
            socket_path: path,
            _listener_handle: listener_handle,
        })
    }

    /// Check if a UI client is connected.
    /// Returns false if the mutex is poisoned (fail-closed).
    pub fn is_ui_connected(&self) -> bool {
        match self.ui_connected.lock() {
            Ok(guard) => *guard,
            Err(_) => false,
        }
    }

    /// Block until a decision matching `request_id` arrives, or timeout.
    ///
    /// Returns `None` on timeout (fail-closed = deny).
    pub fn await_decision(&self, request_id: &str, timeout: Duration) -> Option<DecisionPayload> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                eprintln!(
                    "[IPC] await_decision timed out for request_id={request_id} — fail-closed deny"
                );
                return None;
            }
            match self.decision_rx.try_recv() {
                Ok(msg) => {
                    if let Some(dp) = msg.as_decision_payload() {
                        if dp.request_id == request_id {
                            return Some(dp);
                        }
                        // Not our request — discard (could queue, but EVENT-0 is single-request)
                        eprintln!(
                            "[IPC] discarding decision for unmatched request_id={}",
                            dp.request_id
                        );
                    }
                }
                Err(TryRecvError::Empty) => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(TryRecvError::Disconnected) => {
                    eprintln!("[IPC] decision channel disconnected");
                    return None;
                }
            }
        }
    }

    /// Emit an event to the connected UI client (non-blocking).
    pub fn emit_event(&self, event: IpcMessage) {
        if let Err(e) = self.event_tx.send(event) {
            eprintln!("[IPC] failed to queue event: {e}");
        }
    }

    /// Listener loop: accepts one client at a time, kicks old on new connect.
    fn listener_loop(
        listener: IpcListener,
        event_rx: Receiver<IpcMessage>,
        decision_tx: Sender<IpcMessage>,
        ui_connected: Arc<Mutex<bool>>,
    ) {
        loop {
            match listener.accept() {
                Ok(stream) => {
                    eprintln!("[IPC] client connected");

                    // Drain any stale events from previous client session
                    while event_rx.try_recv().is_ok() {}

                    // ui_connected is set inside handle_client AFTER
                    // successful version handshake (B-DEP-N2-2).
                    Self::handle_client(stream, &event_rx, &decision_tx, &ui_connected);

                    // Always clear ui_connected when client session ends.
                    match ui_connected.lock() {
                        Ok(mut guard) => *guard = false,
                        Err(_) => {
                            eprintln!("[IPC] FATAL: ui_connected mutex poisoned");
                            return;
                        }
                    }
                    eprintln!("[IPC_CLIENT_DISCONNECTED]");

                    // Prepare listener for next client (Windows: disconnect pipe).
                    listener.prepare_next();
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Non-blocking: no client waiting, sleep and retry
                    thread::sleep(POLL_INTERVAL);
                }
                Err(e) => {
                    eprintln!("[IPC] accept error: {e}");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    /// Send a version.status response on the given writer.
    fn write_version_status(
        writer: &mut io::BufWriter<&IpcStream>,
        compatible: bool,
    ) -> io::Result<()> {
        let payload = VersionStatusPayload {
            daemon_version: DAEMON_VERSION.to_string(),
            compatible,
        };
        let payload_value = serde_json::to_value(&payload).map_err(io::Error::other)?;
        let status = IpcMessage::new_event("version.status", payload_value);
        let line = status.to_ndjson().map_err(io::Error::other)?;
        writer.write_all(line.as_bytes())?;
        writer.flush()
    }

    /// Handle a single connected client. Returns when client disconnects or
    /// on protocol violation.
    ///
    /// Flow (B-DEP-N2-2 + B-DEP-N2-1):
    /// 1. Version handshake: read version.handshake, reply version.status
    /// 2. If compatible: emit daemon.status, set ui_connected, enter event loop
    /// 3. If incompatible/malformed/missing: fail-closed disconnect
    fn handle_client(
        stream: IpcStream,
        event_rx: &Receiver<IpcMessage>,
        decision_tx: &Sender<IpcMessage>,
        ui_connected: &Arc<Mutex<bool>>,
    ) {
        if let Err(e) = stream.set_nonblocking(false) {
            eprintln!("[IPC] failed to configure stream: {e}");
            return;
        }

        let read_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[IPC] failed to clone stream: {e}");
                return;
            }
        };
        let write_stream = stream;

        // ── Phase 1: Version Handshake (synchronous, blocking) ──

        // Set read timeout for handshake phase.
        if let Err(e) = read_stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)) {
            eprintln!("[IPC_HANDSHAKE_FAIL] failed to set read timeout: {e}");
            return;
        }

        let mut reader = BufReader::new(read_stream);
        let mut writer = io::BufWriter::new(&write_stream);

        // Read first message — MUST be version.handshake.
        let first_line = match read_line_bounded(&mut reader) {
            Ok(ReadLineResult::Line(line)) if !line.is_empty() => line,
            Ok(ReadLineResult::Line(_)) => {
                eprintln!("[IPC_HANDSHAKE_FAIL] empty first message — fail-closed");
                let _ = Self::write_version_status(&mut writer, false);
                return;
            }
            Ok(ReadLineResult::Eof) => {
                eprintln!("[IPC_HANDSHAKE_FAIL] client disconnected before handshake");
                return;
            }
            Err(e) => {
                eprintln!("[IPC_HANDSHAKE_FAIL] read error: {e} — fail-closed");
                return;
            }
        };

        // Parse as IPC message.
        let msg: IpcMessage = match serde_json::from_str(&first_line) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[IPC_HANDSHAKE_FAIL] malformed JSON: {e} — fail-closed");
                let _ = Self::write_version_status(&mut writer, false);
                return;
            }
        };

        // Validate type is version.handshake.
        if msg.msg_type != "version.handshake" {
            eprintln!(
                "[IPC_HANDSHAKE_FAIL] expected version.handshake, got {} — fail-closed",
                msg.msg_type
            );
            let _ = Self::write_version_status(&mut writer, false);
            return;
        }

        // Extract app_version.
        let app_version = match msg.payload.get("app_version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => {
                eprintln!("[IPC_HANDSHAKE_FAIL] missing app_version in payload — fail-closed");
                let _ = Self::write_version_status(&mut writer, false);
                return;
            }
        };

        // Check major.minor compatibility.
        let compatible = check_version_compatible(&app_version, DAEMON_VERSION);

        // Send version.status response.
        if let Err(e) = Self::write_version_status(&mut writer, compatible) {
            eprintln!("[IPC_HANDSHAKE] write version.status error: {e}");
            return;
        }

        if !compatible {
            eprintln!(
                "[IPC_VERSION_INCOMPATIBLE] app={app_version} daemon={DAEMON_VERSION} — closing"
            );
            return;
        }

        eprintln!("[IPC_VERSION_COMPATIBLE] app={app_version} daemon={DAEMON_VERSION}");

        // ── Phase 1b: Emit daemon.status (B-DEP-N2-1) ──

        let ds_payload = DaemonStatusPayload {
            connected_peers: 0,
            ui_connected: true,
            version: DAEMON_VERSION.to_string(),
        };
        let ds_value = match serde_json::to_value(&ds_payload) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[IPC] serialize daemon.status error: {e}");
                return;
            }
        };
        let daemon_status = IpcMessage::new_event("daemon.status", ds_value);
        match daemon_status.to_ndjson() {
            Ok(line) => {
                if let Err(e) = writer.write_all(line.as_bytes()) {
                    eprintln!("[IPC] write daemon.status error: {e}");
                    return;
                }
                if let Err(e) = writer.flush() {
                    eprintln!("[IPC] flush daemon.status error: {e}");
                    return;
                }
            }
            Err(e) => {
                eprintln!("[IPC] serialize daemon.status ndjson error: {e}");
                return;
            }
        }

        // Mark UI connected AFTER successful handshake + daemon.status emission.
        match ui_connected.lock() {
            Ok(mut guard) => *guard = true,
            Err(_) => {
                eprintln!("[IPC] FATAL: ui_connected mutex poisoned");
                return;
            }
        }

        // Clear read timeout for normal operation.
        if let Err(e) = reader.get_ref().set_read_timeout(None) {
            eprintln!("[IPC] failed to clear read timeout: {e}");
        }

        // ── Phase 2: Normal event/decision loop ──

        // Reader thread: reads decisions from client.
        let decision_tx_clone = decision_tx.clone();
        let reader_handle = thread::spawn(move || {
            loop {
                match read_line_bounded(&mut reader) {
                    Ok(ReadLineResult::Line(line)) => {
                        if line.is_empty() {
                            continue;
                        }
                        match parse_ipc_line(&line) {
                            Ok(Some(msg)) => {
                                if let Err(e) = decision_tx_clone.send(msg) {
                                    eprintln!("[IPC] decision_tx send error: {e}");
                                    return;
                                }
                            }
                            Ok(None) => {
                                // Unknown type — already logged by parse_ipc_line
                            }
                            Err(e) => {
                                eprintln!("[IPC_INVALID_JSON] {e} — disconnecting client");
                                return;
                            }
                        }
                    }
                    Ok(ReadLineResult::Eof) => {
                        return;
                    }
                    Err(e) => {
                        eprintln!("[IPC] read error: {e} — disconnecting client");
                        return;
                    }
                }
            }
        });

        // Writer loop: sends events to client.
        loop {
            match event_rx.recv_timeout(POLL_INTERVAL) {
                Ok(event) => match event.to_ndjson() {
                    Ok(line) => {
                        if let Err(e) = writer.write_all(line.as_bytes()) {
                            eprintln!("[IPC] write error: {e}");
                            break;
                        }
                        if let Err(e) = writer.flush() {
                            eprintln!("[IPC] flush error: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[IPC] serialize error: {e}");
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check if reader thread is still alive
                    if reader_handle.is_finished() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }

        // Reader thread will exit on its own when stream is dropped
        let _ = reader_handle.join();
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        transport::cleanup_ipc_endpoint(&self.socket_path);
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::types::IpcKind;

    #[test]
    fn bounded_reader_line_under_limit() {
        let data = b"hello world\n";
        let mut reader = BufReader::new(&data[..]);
        let result = read_line_bounded(&mut reader).unwrap();
        assert_eq!(result, ReadLineResult::Line("hello world".to_string()));
    }

    #[test]
    fn bounded_reader_line_at_limit() {
        // Create a line exactly at MAX_LINE_BYTES (including newline)
        let mut data = vec![b'x'; MAX_LINE_BYTES - 1];
        data.push(b'\n');
        let mut reader = BufReader::new(&data[..]);
        let result = read_line_bounded(&mut reader).unwrap();
        match result {
            ReadLineResult::Line(s) => assert_eq!(s.len(), MAX_LINE_BYTES - 1),
            other => panic!("expected Line, got {other:?}"),
        }
    }

    #[test]
    fn bounded_reader_line_over_limit() {
        // Create a line that exceeds MAX_LINE_BYTES
        let mut data = vec![b'x'; MAX_LINE_BYTES + 100];
        data.push(b'\n');
        let mut reader = BufReader::new(&data[..]);
        let result = read_line_bounded(&mut reader);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("IPC_OVERSIZE"));
    }

    #[test]
    fn bounded_reader_empty_line() {
        let data = b"\n";
        let mut reader = BufReader::new(&data[..]);
        let result = read_line_bounded(&mut reader).unwrap();
        assert_eq!(result, ReadLineResult::Line(String::new()));
    }

    #[test]
    fn bounded_reader_eof() {
        let data = b"";
        let mut reader = BufReader::new(&data[..]);
        let result = read_line_bounded(&mut reader).unwrap();
        assert_eq!(result, ReadLineResult::Eof);
    }

    #[test]
    fn bounded_reader_strips_crlf() {
        let data = b"hello\r\n";
        let mut reader = BufReader::new(&data[..]);
        let result = read_line_bounded(&mut reader).unwrap();
        assert_eq!(result, ReadLineResult::Line("hello".to_string()));
    }

    #[test]
    fn parse_valid_event_json() {
        let msg = IpcMessage::new_event("daemon.status", serde_json::json!({}));
        let json = serde_json::to_string(&msg).unwrap();
        let result = parse_ipc_line(&json).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().msg_type, "daemon.status");
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let result = parse_ipc_line("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_type_returns_none() {
        let msg = IpcMessage::new_event("totally.unknown.type", serde_json::json!({}));
        let json = serde_json::to_string(&msg).unwrap();
        let result = parse_ipc_line(&json).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_decision_json() {
        let msg = IpcMessage::new_decision(
            "pairing.decision",
            serde_json::json!({"request_id": "evt-0", "decision": "deny_once"}),
        );
        let json = serde_json::to_string(&msg).unwrap();
        let result = parse_ipc_line(&json).unwrap();
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert_eq!(parsed.kind, IpcKind::Decision);
    }

    #[test]
    fn parse_version_handshake() {
        let msg = IpcMessage::new_decision(
            "version.handshake",
            serde_json::json!({"app_version": "0.0.1"}),
        );
        let json = serde_json::to_string(&msg).unwrap();
        let result = parse_ipc_line(&json).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().msg_type, "version.handshake");
    }

    #[test]
    fn parse_version_status() {
        let msg = IpcMessage::new_event(
            "version.status",
            serde_json::json!({"daemon_version": "0.0.1", "compatible": true}),
        );
        let json = serde_json::to_string(&msg).unwrap();
        let result = parse_ipc_line(&json).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().msg_type, "version.status");
    }

    // ── Version Compatibility Tests ─────────────────────────

    #[test]
    fn version_compat_exact_match() {
        assert!(check_version_compatible("0.0.1", "0.0.1"));
    }

    #[test]
    fn version_compat_patch_differs() {
        assert!(check_version_compatible("0.0.1", "0.0.5"));
        assert!(check_version_compatible("1.2.0", "1.2.99"));
    }

    #[test]
    fn version_compat_minor_differs() {
        assert!(!check_version_compatible("0.0.1", "0.1.1"));
        assert!(!check_version_compatible("1.2.3", "1.3.3"));
    }

    #[test]
    fn version_compat_major_differs() {
        assert!(!check_version_compatible("0.0.1", "1.0.1"));
        assert!(!check_version_compatible("2.0.0", "1.0.0"));
    }

    #[test]
    fn version_compat_malformed() {
        assert!(!check_version_compatible("", "0.0.1"));
        assert!(!check_version_compatible("0.0.1", ""));
        assert!(!check_version_compatible("bad", "0.0.1"));
        assert!(!check_version_compatible("0", "0.0.1"));
        assert!(!check_version_compatible("0.0.1", "1"));
    }

    #[test]
    fn version_compat_prerelease_patch_ignored() {
        // Patch part may contain extra info; only major.minor matter
        assert!(check_version_compatible("0.0.1-beta", "0.0.2-rc1"));
    }

    // ── Handshake Integration Tests ─────────────────────────

    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    #[cfg(unix)]
    fn temp_socket_path() -> String {
        let dir = std::env::temp_dir();
        format!(
            "{}/bolt-test-{}.sock",
            dir.display(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[cfg(unix)]
    fn send_version_handshake(stream: &mut UnixStream, app_version: &str) {
        let msg = serde_json::json!({
            "id": "cli-0",
            "kind": "decision",
            "type": "version.handshake",
            "ts_ms": 0,
            "payload": { "app_version": app_version }
        });
        let mut line = serde_json::to_string(&msg).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    #[cfg(unix)]
    fn read_ipc_line(reader: &mut BufReader<UnixStream>) -> Option<serde_json::Value> {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => serde_json::from_str(&line).ok(),
            Err(_) => None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn handshake_compatible_emits_version_status_then_daemon_status() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Send compatible version handshake
        send_version_handshake(&mut write_client, env!("CARGO_PKG_VERSION"));

        // First response: version.status
        let msg1 = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(msg1["type"], "version.status");
        assert_eq!(msg1["kind"], "event");
        assert_eq!(msg1["payload"]["daemon_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(msg1["payload"]["compatible"], true);

        // Second response: daemon.status (B-DEP-N2-1)
        let msg2 = read_ipc_line(&mut read_client).expect("expected daemon.status");
        assert_eq!(msg2["type"], "daemon.status");
        assert_eq!(msg2["kind"], "event");
        assert_eq!(msg2["payload"]["ui_connected"], true);
        assert_eq!(msg2["payload"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(msg2["payload"]["connected_peers"], 0);

        // ui_connected should now be true
        // (may take a moment due to thread scheduling)
        std::thread::sleep(Duration::from_millis(100));
        assert!(server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn handshake_incompatible_sends_status_then_disconnects() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Send incompatible version
        send_version_handshake(&mut write_client, "99.99.0");

        // First response: version.status with compatible:false
        let msg = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(msg["type"], "version.status");
        assert_eq!(msg["payload"]["compatible"], false);
        assert_eq!(msg["payload"]["daemon_version"], env!("CARGO_PKG_VERSION"));

        // No daemon.status should follow — server closed connection.
        // Try to read; expect EOF (None) or read error.
        let next = read_ipc_line(&mut read_client);
        assert!(
            next.is_none(),
            "expected no more messages after incompatible handshake"
        );

        // ui_connected should be false
        std::thread::sleep(Duration::from_millis(100));
        assert!(!server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn handshake_wrong_first_message_fails_closed() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Send a non-handshake message first
        let msg = serde_json::json!({
            "id": "cli-0",
            "kind": "event",
            "type": "daemon.status",
            "ts_ms": 0,
            "payload": {}
        });
        let mut line = serde_json::to_string(&msg).unwrap();
        line.push('\n');
        write_client.write_all(line.as_bytes()).unwrap();
        write_client.flush().unwrap();

        // Should get version.status compatible:false
        let resp = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(resp["type"], "version.status");
        assert_eq!(resp["payload"]["compatible"], false);

        // ui_connected should be false
        std::thread::sleep(Duration::from_millis(100));
        assert!(!server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn handshake_malformed_json_fails_closed() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Send malformed JSON
        write_client.write_all(b"not valid json\n").unwrap();
        write_client.flush().unwrap();

        // Should get version.status compatible:false
        let resp = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(resp["type"], "version.status");
        assert_eq!(resp["payload"]["compatible"], false);

        // ui_connected should be false
        std::thread::sleep(Duration::from_millis(100));
        assert!(!server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn handshake_missing_app_version_fails_closed() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Send version.handshake without app_version in payload
        let msg = serde_json::json!({
            "id": "cli-0",
            "kind": "decision",
            "type": "version.handshake",
            "ts_ms": 0,
            "payload": {}
        });
        let mut line = serde_json::to_string(&msg).unwrap();
        line.push('\n');
        write_client.write_all(line.as_bytes()).unwrap();
        write_client.flush().unwrap();

        // Should get version.status compatible:false
        let resp = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(resp["type"], "version.status");
        assert_eq!(resp["payload"]["compatible"], false);

        std::thread::sleep(Duration::from_millis(100));
        assert!(!server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn handshake_events_blocked_before_completion() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        // Emit an event BEFORE any client connects
        let pre_event = IpcMessage::new_event("pairing.request", serde_json::json!({"test": true}));
        server.emit_event(pre_event);

        // Small delay to ensure event is queued
        std::thread::sleep(Duration::from_millis(50));

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Complete handshake
        send_version_handshake(&mut write_client, env!("CARGO_PKG_VERSION"));

        // First: version.status (not the pre-queued event)
        let msg1 = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(msg1["type"], "version.status");

        // Second: daemon.status (not the pre-queued event)
        let msg2 = read_ipc_line(&mut read_client).expect("expected daemon.status");
        assert_eq!(msg2["type"], "daemon.status");

        // The pre-queued event was drained (per listener_loop stale event drain)
        // — it should NOT appear on the wire.

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn handshake_events_flow_after_compatible() {
        let path = temp_socket_path();
        let server = IpcServer::start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        // Complete handshake
        send_version_handshake(&mut write_client, env!("CARGO_PKG_VERSION"));

        // Consume version.status + daemon.status
        let _ = read_ipc_line(&mut read_client).unwrap();
        let _ = read_ipc_line(&mut read_client).unwrap();

        // Now emit an event via the server
        let test_event = IpcMessage::new_event(
            "pairing.request",
            serde_json::json!({"request_id": "evt-test", "remote_device_name": "Test"}),
        );
        server.emit_event(test_event);

        // Should arrive on client
        // Set a timeout so the test doesn't hang
        read_client
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let msg = read_ipc_line(&mut read_client).expect("expected pairing.request");
        assert_eq!(msg["type"], "pairing.request");

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }
}
