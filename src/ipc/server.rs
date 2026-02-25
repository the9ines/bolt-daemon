//! IPC server: Unix domain socket, NDJSON protocol, single-client.
//!
//! New client kicks old client (no dead-UI blocking).
//! Fail-closed: no UI connected = `await_decision` returns `None`.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::types::{DecisionPayload, IpcMessage};

// ── Constants ───────────────────────────────────────────────

/// Default socket path.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/bolt-daemon.sock";

/// Maximum line size (1 MiB). Lines exceeding this cause disconnect.
const MAX_LINE_BYTES: usize = 1_048_576;

/// Poll interval when checking for events to send or decisions received.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

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
        | "transfer.incoming.decision" => Ok(Some(msg)),
        unknown => {
            eprintln!("[IPC_UNKNOWN_TYPE] ignoring message with type: {unknown}");
            Ok(None)
        }
    }
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
    /// Start the IPC server on the given socket path.
    ///
    /// Spawns a background thread that listens for a single client at a time.
    /// New connections kick the old client.
    pub fn start(socket_path: &str) -> io::Result<Self> {
        let path = PathBuf::from(socket_path);

        // Remove stale socket file if it exists.
        if path.exists() {
            eprintln!("[IPC] removing stale socket: {}", path.display());
            std::fs::remove_file(&path)?;
        }

        let listener = UnixListener::bind(&path)?;

        // chmod 600 — owner-only access.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }

        eprintln!("[IPC] listening on {} (single-client)", path.display());

        // Set non-blocking so we can check for shutdown.
        listener.set_nonblocking(true)?;

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
    pub fn is_ui_connected(&self) -> bool {
        *self.ui_connected.lock().unwrap()
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
        listener: UnixListener,
        event_rx: Receiver<IpcMessage>,
        decision_tx: Sender<IpcMessage>,
        ui_connected: Arc<Mutex<bool>>,
    ) {
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    eprintln!("[IPC] client connected");
                    *ui_connected.lock().unwrap() = true;

                    // Drain any stale events from previous client session
                    while event_rx.try_recv().is_ok() {}

                    Self::handle_client(stream, &event_rx, &decision_tx);

                    *ui_connected.lock().unwrap() = false;
                    eprintln!("[IPC_CLIENT_DISCONNECTED]");
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

    /// Handle a single connected client. Returns when client disconnects or
    /// on protocol violation.
    fn handle_client(
        stream: UnixStream,
        event_rx: &Receiver<IpcMessage>,
        decision_tx: &Sender<IpcMessage>,
    ) {
        // Set stream to non-blocking for the writer side so we can interleave
        // reading decisions and writing events.
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

        // Reader thread: reads decisions from client
        let decision_tx_clone = decision_tx.clone();
        let reader_handle = thread::spawn(move || {
            let mut reader = BufReader::new(&read_stream);
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

        // Writer loop: sends events to client
        let mut writer = io::BufWriter::new(&write_stream);
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
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
            eprintln!("[IPC] cleaned up socket: {}", self.socket_path.display());
        }
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
}
