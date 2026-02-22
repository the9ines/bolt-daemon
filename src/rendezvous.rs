//! Rendezvous signaling via bolt-rendezvous WebSocket server.
//!
//! HARD RULE: Rendezvous mode is opt-in (`--signal rendezvous`).
//! If the rendezvous server is unreachable or misconfigured, we exit 1.
//! There is NO fallback to file mode. Fail-closed by design.

use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::{
    apply_remote_signal, collect_local_signal, create_peer_connection, Args, DcHandler,
    SignalBundle, DC_LABEL, HELLO_PAYLOAD,
};

// ── Protocol message types ──────────────────────────────────
// Mirrors bolt-rendezvous/src/protocol.rs

/// Client → Server messages.
#[derive(Serialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum ClientMsg {
    Register {
        peer_code: String,
        device_name: String,
        device_type: String,
    },
    Signal {
        to: String,
        payload: serde_json::Value,
    },
    Ping,
}

/// Server → Client messages.
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Peers {
        #[allow(dead_code)]
        peers: Vec<PeerInfo>,
    },
    PeerJoined {
        #[allow(dead_code)]
        peer: PeerInfo,
    },
    PeerLeft {
        #[allow(dead_code)]
        peer_code: String,
    },
    Signal {
        from: String,
        payload: serde_json::Value,
    },
    Error {
        message: String,
    },
}

#[derive(Deserialize, Debug)]
struct PeerInfo {
    #[allow(dead_code)]
    peer_code: String,
    #[allow(dead_code)]
    device_name: String,
    #[allow(dead_code)]
    device_type: String,
}

/// Our inner payload format (inside the opaque `payload` field).
#[derive(Serialize, Deserialize, Debug)]
struct SignalPayload {
    room: String,
    msg_type: String,
    bundle: SignalBundle,
}

// ── Helpers ─────────────────────────────────────────────────

type WsStream = WebSocket<MaybeTlsStream<std::net::TcpStream>>;

/// Generate an 8-character alphanumeric peer ID.
fn generate_peer_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:016x}", hash)[..8].to_string()
}

/// Connect to the rendezvous server and register.
/// Fails hard (no fallback) if the server is unreachable.
fn connect_and_register(url: &str, peer_id: &str) -> Result<WsStream, Box<dyn std::error::Error>> {
    eprintln!("[rendezvous] connecting to {} ...", url);

    let (mut ws, _response) = tungstenite::connect(url).map_err(|e| {
        format!(
            "rendezvous server unreachable at {}: {} (no fallback to file mode)",
            url, e
        )
    })?;

    eprintln!("[rendezvous] connected, registering as '{}'", peer_id);

    let register = ClientMsg::Register {
        peer_code: peer_id.to_string(),
        device_name: "bolt-daemon".to_string(),
        device_type: "desktop".to_string(),
    };
    let json = serde_json::to_string(&register)?;
    ws.send(Message::Text(json))?;

    // Wait for the initial Peers response to confirm registration
    let msg = ws.read()?;
    let text = msg
        .into_text()
        .map_err(|e| format!("expected text from server: {}", e))?;
    let server_msg: ServerMsg = serde_json::from_str(&text)?;

    match server_msg {
        ServerMsg::Peers { .. } => {
            eprintln!("[rendezvous] registered successfully");
        }
        ServerMsg::Error { message } => {
            return Err(format!("rendezvous registration failed: {}", message).into());
        }
        other => {
            eprintln!(
                "[rendezvous] unexpected first message (expected peers): {:?}",
                other
            );
        }
    }

    Ok(ws)
}

/// Send a signal to a specific peer.
fn send_signal(
    ws: &mut WsStream,
    to: &str,
    payload: &SignalPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_value = serde_json::to_value(payload)?;
    let msg = ClientMsg::Signal {
        to: to.to_string(),
        payload: payload_value,
    };
    let json = serde_json::to_string(&msg)?;
    ws.send(Message::Text(json))?;
    eprintln!("[rendezvous] sent {} signal to '{}'", payload.msg_type, to);
    Ok(())
}

/// Read the next server message, respecting the deadline.
/// Returns WouldBlock/TimedOut on socket timeout (caller retries).
/// Returns error on connection failure or deadline expiry.
fn recv_with_deadline(
    ws: &mut WsStream,
    deadline: Instant,
) -> Result<ServerMsg, Box<dyn std::error::Error>> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("phase timeout expired")?;

        // Set read timeout on underlying TCP stream (max 5s per read for responsive deadline checking)
        let read_timeout = remaining.min(Duration::from_secs(5));
        match ws.get_ref() {
            MaybeTlsStream::Plain(tcp) => {
                tcp.set_read_timeout(Some(read_timeout))?;
            }
            _ => {
                // TLS stream — set_read_timeout not directly available,
                // but tungstenite handles it via the underlying stream
            }
        }

        match ws.read() {
            Ok(msg) => {
                if msg.is_ping() || msg.is_pong() {
                    continue;
                }
                let text = msg
                    .into_text()
                    .map_err(|e| format!("expected text from server: {}", e))?;
                let server_msg: ServerMsg = serde_json::from_str(&text)?;
                return Ok(server_msg);
            }
            Err(tungstenite::Error::Io(ref e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return Err("phase timeout expired".into());
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Wait for a specific signal from a specific peer, matching room and msg_type.
/// Ignores non-matching signals (wrong peer, wrong room, wrong msg_type).
fn wait_for_signal(
    ws: &mut WsStream,
    deadline: Instant,
    from_peer: &str,
    room: &str,
    expected_msg_type: &str,
) -> Result<SignalBundle, Box<dyn std::error::Error>> {
    eprintln!(
        "[rendezvous] waiting for '{}' signal from '{}' (room '{}')",
        expected_msg_type, from_peer, room
    );

    loop {
        let server_msg = recv_with_deadline(ws, deadline)?;

        match server_msg {
            ServerMsg::Signal { from, payload } => {
                // Primary filter: peer_code must match exactly
                if from != from_peer {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}' (expected '{}')",
                        from, from_peer
                    );
                    continue;
                }

                // Parse our inner payload
                let signal_payload: SignalPayload = match serde_json::from_value(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "[rendezvous] ignoring unparseable payload from '{}': {}",
                            from, e
                        );
                        continue;
                    }
                };

                // Secondary filter: room must match
                if signal_payload.room != room {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}': room '{}' != '{}'",
                        from, signal_payload.room, room
                    );
                    continue;
                }

                // Tertiary filter: msg_type must match expected phase
                if signal_payload.msg_type != expected_msg_type {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}': msg_type '{}' != '{}'",
                        from, signal_payload.msg_type, expected_msg_type
                    );
                    continue;
                }

                eprintln!(
                    "[rendezvous] received '{}' signal from '{}'",
                    expected_msg_type, from
                );
                return Ok(signal_payload.bundle);
            }
            ServerMsg::PeerJoined { peer } => {
                eprintln!("[rendezvous] peer joined: '{}'", peer.peer_code);
            }
            ServerMsg::PeerLeft { peer_code } => {
                eprintln!("[rendezvous] peer left: '{}'", peer_code);
            }
            ServerMsg::Peers { .. } => {
                // Additional peers list, ignore
            }
            ServerMsg::Error { message } => {
                return Err(format!("rendezvous server error: {}", message).into());
            }
        }
    }
}

// ── Entry points ────────────────────────────────────────────

/// Offerer flow via rendezvous signaling.
///
/// INVARIANT: `--signal rendezvous` is required. No fallback to file mode.
/// If the server is down or peer is unreachable, exit 1.
pub fn run_offerer_rendezvous(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Fail-closed: these are validated in parse_args() but double-check here
    let room = args
        .room
        .as_ref()
        .ok_or("BUG: --room required for rendezvous mode")?;
    let to_peer = args
        .to_peer
        .as_ref()
        .ok_or("BUG: --to required for offerer rendezvous mode")?;
    let peer_id = args.peer_id.clone().unwrap_or_else(generate_peer_id);

    eprintln!(
        "[offerer] rendezvous mode: room='{}', peer_id='{}', to='{}'",
        room, peer_id, to_peer
    );

    let deadline = Instant::now() + args.phase_timeout;

    // Connect and register (fails hard if server unreachable — no fallback)
    let mut ws = connect_and_register(&args.rendezvous_url, &peer_id)?;

    // Create PeerConnection + DataChannel → triggers SDP + ICE gathering
    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    let (dc_open_tx, dc_open_rx) = mpsc::channel();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel();

    let dc_handler = DcHandler {
        open_tx: dc_open_tx,
        msg_tx: dc_msg_tx,
    };

    let mut dc = pc.create_data_channel(DC_LABEL, dc_handler)?;
    eprintln!("[offerer] DataChannel '{}' created", DC_LABEL);

    // Collect offer bundle (reuses scope-filtered logic)
    let offer_bundle = collect_local_signal(&ch, args.phase_timeout)?;

    // Send offer to target peer via rendezvous
    let offer_payload = SignalPayload {
        room: room.clone(),
        msg_type: "offer".to_string(),
        bundle: offer_bundle,
    };
    send_signal(&mut ws, to_peer, &offer_payload)?;

    // Wait for answer from target peer (deadline-respecting, filtered)
    let answer_bundle = wait_for_signal(&mut ws, deadline, to_peer, room, "answer")?;

    // Apply answer (reuses scope-filtered logic)
    apply_remote_signal(&mut pc, &answer_bundle, args.network_scope)?;

    // Wait for DataChannel to open
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for DataChannel open")?;
    dc_open_rx.recv_timeout(remaining)?;
    eprintln!("[offerer] DataChannel open");

    // Send hello payload
    dc.send(HELLO_PAYLOAD)?;
    eprintln!(
        "[offerer] sent: {:?}",
        std::str::from_utf8(HELLO_PAYLOAD).unwrap_or("<binary>")
    );

    // Wait for echo
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for echo")?;
    let response = dc_msg_rx.recv_timeout(remaining)?;
    if response == HELLO_PAYLOAD {
        eprintln!("[offerer] SUCCESS — received matching payload");
        Ok(())
    } else {
        Err(format!(
            "payload mismatch: expected {:?}, got {:?}",
            HELLO_PAYLOAD, response
        )
        .into())
    }
}

/// Answerer flow via rendezvous signaling.
///
/// INVARIANT: `--signal rendezvous` is required. No fallback to file mode.
/// If the server is down or peer is unreachable, exit 1.
pub fn run_answerer_rendezvous(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Fail-closed: these are validated in parse_args() but double-check here
    let room = args
        .room
        .as_ref()
        .ok_or("BUG: --room required for rendezvous mode")?;
    let expect_peer = args
        .expect_peer
        .as_ref()
        .ok_or("BUG: --expect-peer required for answerer rendezvous mode")?;
    let peer_id = args.peer_id.clone().unwrap_or_else(generate_peer_id);

    eprintln!(
        "[answerer] rendezvous mode: room='{}', peer_id='{}', expect-peer='{}'",
        room, peer_id, expect_peer
    );

    let deadline = Instant::now() + args.phase_timeout;

    // Connect and register (fails hard if server unreachable — no fallback)
    let mut ws = connect_and_register(&args.rendezvous_url, &peer_id)?;

    // Wait for offer from expected peer (deadline-respecting, filtered)
    let offer_bundle = wait_for_signal(&mut ws, deadline, expect_peer, room, "offer")?;

    // Create PeerConnection
    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    // Apply offer (reuses scope-filtered logic)
    apply_remote_signal(&mut pc, &offer_bundle, args.network_scope)?;

    // Collect answer bundle (reuses scope-filtered logic)
    let answer_bundle = collect_local_signal(&ch, args.phase_timeout)?;

    // Send answer to expected peer via rendezvous
    let answer_payload = SignalPayload {
        room: room.clone(),
        msg_type: "answer".to_string(),
        bundle: answer_bundle,
    };
    send_signal(&mut ws, expect_peer, &answer_payload)?;

    // Wait for incoming DataChannel
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for incoming DataChannel")?;
    let mut dc = ch.incoming_dc_rx.recv_timeout(remaining)?;
    eprintln!("[answerer] DataChannel received");

    // Wait for DC to open
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for DataChannel open")?;
    ch.dc_open_rx.recv_timeout(remaining)?;
    eprintln!("[answerer] DataChannel open");

    // Wait for hello payload
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for hello payload")?;
    let msg = ch.dc_msg_rx.recv_timeout(remaining)?;
    eprintln!(
        "[answerer] received: {:?}",
        std::str::from_utf8(&msg).unwrap_or("<binary>")
    );

    if msg == HELLO_PAYLOAD {
        dc.send(HELLO_PAYLOAD)?;
        eprintln!("[answerer] SUCCESS — echoed matching payload");
        thread::sleep(Duration::from_millis(500));
        Ok(())
    } else {
        Err(format!(
            "payload mismatch: expected {:?}, got {:?}",
            HELLO_PAYLOAD, msg
        )
        .into())
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateInfo, SdpInfo};

    #[test]
    fn signal_payload_serde_roundtrip() {
        let payload = SignalPayload {
            room: "test-room".to_string(),
            msg_type: "offer".to_string(),
            bundle: SignalBundle {
                description: SdpInfo {
                    sdp_type: "offer".to_string(),
                    sdp: "v=0\r\ntest".to_string(),
                },
                candidates: vec![CandidateInfo {
                    candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host"
                        .to_string(),
                    mid: "0".to_string(),
                }],
            },
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: SignalPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.room, "test-room");
        assert_eq!(decoded.msg_type, "offer");
        assert_eq!(decoded.bundle.description.sdp_type, "offer");
        assert_eq!(decoded.bundle.candidates.len(), 1);
    }

    #[test]
    fn client_msg_register_serde() {
        let msg = ClientMsg::Register {
            peer_code: "alice".to_string(),
            device_name: "bolt-daemon".to_string(),
            device_type: "desktop".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"register\""));
        assert!(json.contains("\"peer_code\":\"alice\""));
        assert!(json.contains("\"device_name\":\"bolt-daemon\""));
        assert!(json.contains("\"device_type\":\"desktop\""));
    }

    #[test]
    fn client_msg_signal_serde() {
        let msg = ClientMsg::Signal {
            to: "bob".to_string(),
            payload: serde_json::json!({"room": "test", "msg_type": "offer"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"signal\""));
        assert!(json.contains("\"to\":\"bob\""));
    }

    #[test]
    fn client_msg_ping_serde() {
        let msg = ClientMsg::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "{\"type\":\"ping\"}");
    }

    #[test]
    fn server_msg_peers_deser() {
        let json = r#"{"type":"peers","peers":[{"peer_code":"alice","device_name":"test","device_type":"desktop"}]}"#;
        let msg: ServerMsg = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMsg::Peers { .. }));
    }

    #[test]
    fn server_msg_peer_joined_deser() {
        let json = r#"{"type":"peer_joined","peer":{"peer_code":"bob","device_name":"test","device_type":"desktop"}}"#;
        let msg: ServerMsg = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMsg::PeerJoined { .. }));
    }

    #[test]
    fn server_msg_peer_left_deser() {
        let json = r#"{"type":"peer_left","peer_code":"bob"}"#;
        let msg: ServerMsg = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMsg::PeerLeft { .. }));
    }

    #[test]
    fn server_msg_signal_deser() {
        let json = r#"{"type":"signal","from":"alice","payload":{"room":"test","msg_type":"offer","bundle":{"description":{"sdp_type":"offer","sdp":"v=0"},"candidates":[]}}}"#;
        let msg: ServerMsg = serde_json::from_str(json).unwrap();
        match msg {
            ServerMsg::Signal { from, payload } => {
                assert_eq!(from, "alice");
                let sp: SignalPayload = serde_json::from_value(payload).unwrap();
                assert_eq!(sp.room, "test");
                assert_eq!(sp.msg_type, "offer");
            }
            _ => panic!("expected Signal"),
        }
    }

    #[test]
    fn server_msg_error_deser() {
        let json = r#"{"type":"error","message":"peer not found"}"#;
        let msg: ServerMsg = serde_json::from_str(json).unwrap();
        match msg {
            ServerMsg::Error { message } => assert_eq!(message, "peer not found"),
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn peer_id_auto_generation() {
        let id = generate_peer_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        // Two calls should produce different IDs (time-based)
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_peer_id();
        assert_ne!(id, id2);
    }
}
