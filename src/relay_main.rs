//! bolt-relay — Minimal relay skeleton for forwarding Bolt encrypted envelopes.
//!
//! Accepts exactly 2 WebSocket peers, assigns a CSPRNG session_id, and forwards
//! relay envelopes bidirectionally until one peer disconnects.
//!
//! This is a skeleton: no TLS, no auth, no multi-session, single-threaded.
//!
//! Usage:
//!   bolt-relay [--port <PORT>]
//!
//! See `docs/RELAY_ENVELOPE_SPEC.md` for the envelope wire format.
//! See `docs/RELAY_SESSION_PROTOCOL.md` for the session setup protocol.

mod relay;

use std::io;
use std::net::TcpListener;
use std::time::Duration;

use tungstenite::{Message, WebSocket};

// ── Constants ───────────────────────────────────────────────

/// Default TCP listen port.
const DEFAULT_PORT: u16 = 4000;

/// Read timeout for the polling loop. Each direction gets this timeout
/// before switching to the other direction. Low enough for responsive
/// bidirectional forwarding, high enough to avoid busy-spinning.
const POLL_READ_TIMEOUT: Duration = Duration::from_millis(50);

// ── Types ───────────────────────────────────────────────────

/// Server-side WebSocket stream (plain TCP, no TLS for skeleton).
type WsStream = WebSocket<std::net::TcpStream>;

// ── CLI ─────────────────────────────────────────────────────

fn parse_args() -> u16 {
    let argv: Vec<String> = std::env::args().collect();
    let mut port = DEFAULT_PORT;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" => {
                i += 1;
                port = match argv.get(i).and_then(|s| s.parse::<u16>().ok()) {
                    Some(p) if p > 0 => p,
                    _ => {
                        eprintln!("--port requires a valid port number (1-65535)");
                        std::process::exit(1);
                    }
                };
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                eprintln!("Usage: bolt-relay [--port <PORT>]");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    port
}

// ── WebSocket accept ────────────────────────────────────────

/// Accept a single TCP connection and upgrade to WebSocket.
fn accept_ws_peer(listener: &TcpListener) -> Result<WsStream, Box<dyn std::error::Error>> {
    let (stream, addr) = listener.accept()?;
    eprintln!("[relay] peer connected from {}", addr);
    let ws = tungstenite::accept(stream)
        .map_err(|e| format!("WebSocket handshake failed for {}: {}", addr, e))?;
    eprintln!("[relay] WebSocket handshake complete for {}", addr);
    Ok(ws)
}

// ── Forwarding ──────────────────────────────────────────────

/// Result of a single read-and-forward attempt.
enum ForwardAction {
    /// Envelope read, validated, and forwarded to destination.
    Forwarded,
    /// No data available on source (read timeout / WouldBlock).
    WouldBlock,
    /// Source peer closed the connection.
    PeerClosed,
}

/// Attempt to read one message from `src` and forward it to `dst`.
///
/// Envelope validation uses the session_id and max_payload from the relay spec.
/// Invalid envelopes are logged and dropped (non-fatal). Session ID mismatches
/// are logged and dropped (non-fatal). Only connection errors propagate as Err.
fn read_and_forward(
    src: &mut WsStream,
    dst: &mut WsStream,
    session_id: &[u8; 16],
    label: &str,
) -> Result<ForwardAction, Box<dyn std::error::Error>> {
    let msg = match src.read() {
        Ok(msg) => msg,
        Err(tungstenite::Error::Io(ref e))
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
        {
            return Ok(ForwardAction::WouldBlock);
        }
        Err(tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        )) => {
            eprintln!("[relay] {} peer disconnected (reset)", label);
            return Ok(ForwardAction::PeerClosed);
        }
        Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => {
            return Ok(ForwardAction::PeerClosed);
        }
        Err(e) => return Err(e.into()),
    };

    // Handle WebSocket control frames
    if msg.is_ping() || msg.is_pong() {
        return Ok(ForwardAction::WouldBlock);
    }
    if msg.is_close() {
        eprintln!("[relay] {} peer sent close", label);
        return Ok(ForwardAction::PeerClosed);
    }

    // Only binary messages carry relay envelopes
    let data = match msg {
        Message::Binary(ref b) => b,
        _ => {
            eprintln!(
                "[relay] {} ignoring non-binary message ({} bytes)",
                label,
                msg.len()
            );
            return Ok(ForwardAction::WouldBlock);
        }
    };

    // Validate envelope
    let (_version, envelope_session_id, payload) =
        match relay::validate_envelope(data, relay::RELAY_MAX_PAYLOAD_DEFAULT) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("[relay] {} invalid envelope: {}", label, e);
                return Ok(ForwardAction::WouldBlock);
            }
        };

    // Verify session_id matches
    if envelope_session_id != *session_id {
        eprintln!("[relay] {} session_id mismatch — dropping", label);
        return Ok(ForwardAction::WouldBlock);
    }

    let total_bytes = relay::RELAY_HEADER_SIZE + payload.len();

    // Forward the entire frame verbatim (header + payload)
    dst.send(Message::Binary(data.clone()))?;
    eprintln!("[relay] {} forwarded {} bytes", label, total_bytes);

    Ok(ForwardAction::Forwarded)
}

/// Run the bidirectional forwarding loop until one peer disconnects.
fn run_session(
    ws_a: &mut WsStream,
    ws_b: &mut WsStream,
    session_id: &[u8; 16],
) -> Result<(), Box<dyn std::error::Error>> {
    // Set read timeouts on underlying TCP streams for non-blocking polling.
    // tungstenite surfaces these as io::ErrorKind::WouldBlock or TimedOut.
    ws_a.get_ref().set_read_timeout(Some(POLL_READ_TIMEOUT))?;
    ws_b.get_ref().set_read_timeout(Some(POLL_READ_TIMEOUT))?;

    loop {
        // A → B
        match read_and_forward(ws_a, ws_b, session_id, "A\u{2192}B")? {
            ForwardAction::PeerClosed => {
                eprintln!("[relay] peer A disconnected");
                break;
            }
            ForwardAction::Forwarded | ForwardAction::WouldBlock => {}
        }

        // B → A
        match read_and_forward(ws_b, ws_a, session_id, "B\u{2192}A")? {
            ForwardAction::PeerClosed => {
                eprintln!("[relay] peer B disconnected");
                break;
            }
            ForwardAction::Forwarded | ForwardAction::WouldBlock => {}
        }
    }

    eprintln!("[relay] session ended");
    Ok(())
}

// ── Entry ───────────────────────────────────────────────────

fn main() {
    let port = parse_args();

    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => {
            eprintln!("[relay] listening on {}", bind_addr);
            l
        }
        Err(e) => {
            eprintln!("[relay] FATAL: bind {} failed: {}", bind_addr, e);
            std::process::exit(1);
        }
    };

    // Accept exactly 2 peers (skeleton: single session, then exit)
    let mut ws_a = match accept_ws_peer(&listener) {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("[relay] FATAL: accept peer A failed: {}", e);
            std::process::exit(1);
        }
    };

    let mut ws_b = match accept_ws_peer(&listener) {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("[relay] FATAL: accept peer B failed: {}", e);
            std::process::exit(1);
        }
    };

    // Generate session_id and notify both peers
    let session_id = relay::generate_session_id();
    let assigned_msg = relay::make_session_assigned(&session_id);

    if let Err(e) = ws_a.send(Message::Binary(assigned_msg.clone())) {
        eprintln!("[relay] FATAL: send session_assigned to peer A: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = ws_b.send(Message::Binary(assigned_msg)) {
        eprintln!("[relay] FATAL: send session_assigned to peer B: {}", e);
        std::process::exit(1);
    }
    eprintln!(
        "[relay] session_assigned sent to both peers ({} bytes each)",
        1 + relay::RELAY_SESSION_ID_LENGTH
    );

    // Run bidirectional forward loop
    match run_session(&mut ws_a, &mut ws_b, &session_id) {
        Ok(()) => {
            eprintln!("[relay] exit 0");
        }
        Err(e) => {
            eprintln!("[relay] FATAL: {}", e);
            std::process::exit(1);
        }
    }
}
