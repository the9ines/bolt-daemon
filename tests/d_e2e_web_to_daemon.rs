//! D-E2E-A: Live end-to-end transfer test.
//!
//! Synthetic Rust offerer → bolt-daemon answerer.
//! Real rendezvous, real WebRTC, real HELLO, real file transfer,
//! real SHA-256 hash verification via bolt.file-hash.
//!
//! Requires: bolt-rendezvous binary at ../bolt-rendezvous/target/debug/
//! Run: cargo test --features test-support -- --ignored

#![cfg(feature = "test-support")]

use std::io::Read as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bolt_core::crypto::generate_ephemeral_keypair;
use bolt_core::encoding::to_base64;
use bolt_core::hash::sha256_hex;
use bolt_core::identity::generate_identity_keypair;
use bolt_daemon::test_support::{
    build_hello_message, daemon_capabilities, encode_dc_message, encode_envelope,
    negotiate_capabilities, parse_hello_message, DcMessage, SessionContext,
};
use datachannel::{
    DataChannelHandler, DataChannelInfo, GatheringState, IceCandidate, PeerConnectionHandler,
    RtcConfig, RtcDataChannel, RtcPeerConnection, SessionDescription,
};
use serde_json::{json, Value};
use tungstenite::{connect, Message};

// ── Constants ──────────────────────────────────────────────────

const TEST_ROOM: &str = "e2e-test";
const TEST_SESSION: &str = "e2e-session-1";
const DAEMON_PEER_ID: &str = "daemonbob";
const TEST_PEER_ID: &str = "testalice";
const DC_LABEL: &str = "bolt";
const TOTAL_DEADLINE_SECS: u64 = 20;

// ── Test helpers ───────────────────────────────────────────────

/// Find bolt-rendezvous binary (same discovery as e2e_rendezvous_local.sh).
fn find_rendezvous_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let base = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("bolt-rendezvous")
        .join("target")
        .join("debug");
    let primary = base.join("bolt-rendezvous");
    if primary.exists() {
        return Some(primary);
    }
    let fallback = base.join("localbolt-signal");
    if fallback.exists() {
        return Some(fallback);
    }
    None
}

/// Find bolt-daemon binary.
fn find_daemon_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bin = PathBuf::from(manifest_dir)
        .join("target")
        .join("debug")
        .join("bolt-daemon");
    if bin.exists() {
        Some(bin)
    } else {
        None
    }
}

/// Allocate a free port: bind 127.0.0.1:0, get assigned port, drop listener.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    listener.local_addr().unwrap().port()
}

/// RAII guard that kills a child process on drop.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Take ownership of the child for wait_with_output.
    fn take(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn rendezvous and wait for readiness.
fn spawn_rendezvous(bin: &Path, port: u16) -> ChildGuard {
    let child = Command::new(bin)
        .env("BOLT_SIGNAL_PORT", port.to_string())
        .env("BOLT_SIGNAL_HOST", "127.0.0.1")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rendezvous");

    // Wait until the port is actually accepting WebSocket connections.
    let start = Instant::now();
    loop {
        match connect(&format!("ws://127.0.0.1:{port}")) {
            Ok((mut ws, _)) => {
                // Server is up and accepting WS connections. Close cleanly.
                let _ = ws.close(None);
                break;
            }
            Err(_) => {
                if start.elapsed() > Duration::from_secs(5) {
                    panic!("rendezvous did not accept WS on port {port} within 5s");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    // Grace period for the server to process the probe disconnect.
    std::thread::sleep(Duration::from_millis(200));

    ChildGuard::new(child)
}

/// Spawn daemon answerer.
fn spawn_daemon_answerer(
    bin: &Path,
    port: u16,
    peer_id: &str,
    expect_peer: &str,
    identity_dir: &Path,
) -> ChildGuard {
    let identity_path = identity_dir.join(".bolt").join("identity.key");
    let child = Command::new(bin)
        .env("BOLT_IDENTITY_PATH", &identity_path)
        .arg("--role")
        .arg("answerer")
        .arg("--signal")
        .arg("rendezvous")
        .arg("--rendezvous-url")
        .arg(format!("ws://127.0.0.1:{port}"))
        .arg("--room")
        .arg(TEST_ROOM)
        .arg("--session")
        .arg(TEST_SESSION)
        .arg("--peer-id")
        .arg(peer_id)
        .arg("--expect-peer")
        .arg(expect_peer)
        .arg("--network-scope")
        .arg("lan")
        .arg("--phase-timeout-secs")
        .arg("15")
        .arg("--pairing-policy")
        .arg("allow")
        .arg("--interop-signal")
        .arg("web_v1")
        .arg("--interop-hello")
        .arg("web_hello_v1")
        .arg("--interop-dc")
        .arg("web_dc_v1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon answerer");

    ChildGuard::new(child)
}

type WsStream = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>;

/// Connect to rendezvous WebSocket and register as peer.
/// Uses the canonical bolt-rendezvous-protocol registration format.
/// Retries WebSocket connect up to 10 times (100ms between).
fn ws_connect_and_register(url: &str, peer_id: &str) -> WsStream {
    let mut ws = None;
    for attempt in 0..10 {
        match connect(url) {
            Ok((socket, _)) => {
                ws = Some(socket);
                break;
            }
            Err(e) => {
                if attempt == 9 {
                    panic!("ws connect failed after 10 attempts: {e}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let mut ws = ws.unwrap();

    let register = json!({
        "type": "register",
        "peer_code": peer_id,
        "device_name": "test-harness",
        "device_type": "desktop",
    });
    ws.send(Message::Text(register.to_string())).unwrap();

    // Wait for peers response.
    let msg = ws.read().expect("ws read peers response");
    if let Message::Text(text) = msg {
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v.get("type").and_then(|t| t.as_str()),
            Some("peers"),
            "expected 'peers' response, got: {text}"
        );
    } else {
        panic!("expected text message from rendezvous");
    }

    ws
}

/// Send a signal payload through rendezvous.
fn ws_send_signal(ws: &mut WsStream, to: &str, payload: Value) {
    let msg = json!({
        "type": "signal",
        "to": to,
        "payload": payload,
    });
    ws.send(Message::Text(msg.to_string())).unwrap();
}

/// Wait for a signal from rendezvous with a deadline.
/// Sets a 1s read timeout so deadline checks fire even if no messages arrive.
fn ws_wait_for_signal(ws: &mut WsStream, deadline: Instant) -> (String, Value) {
    // Set read timeout so ws.read() doesn't block forever.
    if let tungstenite::stream::MaybeTlsStream::Plain(ref mut tcp) = ws.get_mut() {
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(1)));
    }
    loop {
        assert!(
            Instant::now() < deadline,
            "ws_wait_for_signal: deadline exceeded"
        );
        match ws.read() {
            Ok(Message::Text(text)) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    if v.get("type").and_then(|t| t.as_str()) == Some("signal") {
                        let from = v["from"].as_str().unwrap_or("").to_string();
                        let payload = v["payload"].clone();
                        // Restore blocking mode.
                        if let tungstenite::stream::MaybeTlsStream::Plain(ref mut tcp) =
                            ws.get_mut()
                        {
                            let _ = tcp.set_read_timeout(None);
                        }
                        return (from, payload);
                    }
                }
            }
            Err(tungstenite::Error::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue; // read timeout — check deadline and retry
            }
            Ok(_) => continue, // non-text message, skip
            Err(e) => panic!("ws_wait_for_signal: unexpected error: {e}"),
        }
    }
}

/// Try to read an ICE candidate from the WebSocket (non-blocking).
/// Handles web format: payload is WebSignalPayload with data.candidate.
/// Returns None on timeout or non-ICE message.
fn try_read_ice_candidate(ws: &mut WsStream) -> Option<IceCandidate> {
    // Set short read timeout
    if let tungstenite::stream::MaybeTlsStream::Plain(ref mut tcp) = ws.get_mut() {
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(200)));
    }
    let result = ws.read();
    // Restore blocking
    if let tungstenite::stream::MaybeTlsStream::Plain(ref mut tcp) = ws.get_mut() {
        let _ = tcp.set_read_timeout(None);
    }
    match result {
        Ok(Message::Text(text)) => {
            let v: Value = serde_json::from_str(&text).ok()?;
            if v.get("type").and_then(|t| t.as_str()) != Some("signal") {
                return None;
            }
            let payload = &v["payload"];
            if payload.get("type").and_then(|t| t.as_str()) != Some("ice-candidate") {
                return None;
            }
            // Web format: data.candidate
            let cand_str = payload["data"].get("candidate").and_then(|v| v.as_str())?;
            if cand_str.is_empty() {
                return None;
            }
            let mid = payload["data"]
                .get("sdpMid")
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string();
            Some(IceCandidate {
                candidate: cand_str.to_string(),
                mid,
            })
        }
        _ => None,
    }
}

// ── DataChannel handler ────────────────────────────────────────

struct TestDcHandler {
    tx: mpsc::Sender<Vec<u8>>,
    open_tx: mpsc::Sender<()>,
}

impl DataChannelHandler for TestDcHandler {
    fn on_open(&mut self) {
        let _ = self.open_tx.send(());
    }
    fn on_message(&mut self, msg: &[u8]) {
        let _ = self.tx.send(msg.to_vec());
    }
    fn on_closed(&mut self) {}
    fn on_error(&mut self, _err: &str) {}
    fn on_buffered_amount_low(&mut self) {}
    fn on_available(&mut self) {}
}

// ── PeerConnection handler ─────────────────────────────────────

struct TestPcHandler {
    desc_tx: mpsc::Sender<SessionDescription>,
    ice_tx: mpsc::Sender<String>,
    gathering_done_tx: mpsc::Sender<()>,
    dc_open_tx: mpsc::Sender<()>,
    dc_msg_tx: mpsc::Sender<Vec<u8>>,
}

impl PeerConnectionHandler for TestPcHandler {
    type DCH = TestDcHandler;

    fn data_channel_handler(&mut self, _info: DataChannelInfo) -> Self::DCH {
        // Incoming DC from answerer — provide handler.
        TestDcHandler {
            tx: self.dc_msg_tx.clone(),
            open_tx: self.dc_open_tx.clone(),
        }
    }

    fn on_description(&mut self, sess_desc: SessionDescription) {
        let _ = self.desc_tx.send(sess_desc);
    }

    fn on_candidate(&mut self, cand: IceCandidate) {
        let _ = self.ice_tx.send(cand.candidate);
    }

    fn on_gathering_state_change(&mut self, state: GatheringState) {
        if state == GatheringState::Complete {
            let _ = self.gathering_done_tx.send(());
        }
    }

    fn on_connection_state_change(&mut self, _state: datachannel::ConnectionState) {}
    fn on_data_channel(&mut self, _dc: Box<RtcDataChannel<Self::DCH>>) {}
}

// ── Main test ──────────────────────────────────────────────────

#[test]
#[ignore]
fn d_e2e_a_live_transfer_hash_verified() {
    let rendezvous_bin = find_rendezvous_binary()
        .expect("bolt-rendezvous binary not found — skip with default cargo test");
    let daemon_bin =
        find_daemon_binary().expect("bolt-daemon binary not found — run cargo build first");

    let port = free_port();
    let deadline = Instant::now() + Duration::from_secs(TOTAL_DEADLINE_SECS);

    let tmp = tempfile::tempdir().unwrap();

    // 1. Spawn rendezvous
    let _rendezvous = spawn_rendezvous(&rendezvous_bin, port);
    std::thread::sleep(Duration::from_millis(200));

    // 2. Spawn daemon answerer
    let mut daemon =
        spawn_daemon_answerer(&daemon_bin, port, DAEMON_PEER_ID, TEST_PEER_ID, tmp.path());
    std::thread::sleep(Duration::from_millis(500));

    // 3. Connect to rendezvous as offerer
    let ws_url = format!("ws://127.0.0.1:{port}");
    let mut ws = ws_connect_and_register(&ws_url, TEST_PEER_ID);

    // 4. Hello/ack exchange (Bolt signaling hello, not HELLO over DC)
    let hello_payload = json!({
        "payload_version": 1,
        "session": TEST_SESSION,
        "room": TEST_ROOM,
        "msg_type": "hello",
        "from_peer": TEST_PEER_ID,
        "to_peer": DAEMON_PEER_ID,
        "network_scope": "lan",
        "phase_timeout_secs": 15
    });
    ws_send_signal(&mut ws, DAEMON_PEER_ID, hello_payload);

    // Wait for ack from daemon
    let (_from, ack_payload) = ws_wait_for_signal(&mut ws, deadline);
    assert_eq!(
        ack_payload.get("msg_type").and_then(|v| v.as_str()),
        Some("ack"),
        "expected ack from daemon, got: {ack_payload}"
    );

    // 5. WebRTC: create PeerConnection + DataChannel
    let (desc_tx, desc_rx) = mpsc::channel::<SessionDescription>();
    let (ice_tx, ice_rx) = mpsc::channel::<String>();
    let (gathering_done_tx, gathering_done_rx) = mpsc::channel::<()>();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel::<Vec<u8>>();
    let (dc_open_tx, dc_open_rx) = mpsc::channel::<()>();

    let config = RtcConfig::new::<&str>(&[]);
    let mut pc = RtcPeerConnection::new(
        &config,
        TestPcHandler {
            desc_tx,
            ice_tx,
            gathering_done_tx,
            dc_open_tx: dc_open_tx.clone(),
            dc_msg_tx: dc_msg_tx.clone(),
        },
    )
    .expect("create PeerConnection");

    // Create DataChannel — triggers SDP offer generation + ICE gathering
    let mut dc = pc
        .create_data_channel(
            DC_LABEL,
            TestDcHandler {
                tx: dc_msg_tx,
                open_tx: dc_open_tx,
            },
        )
        .expect("create DataChannel");

    // Wait for local description (offer SDP)
    let local_desc = desc_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("no local description generated");

    // Wait for gathering to complete
    gathering_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("ICE gathering timed out");

    // Generate session ephemeral keypair for offerer
    let session_kp = generate_ephemeral_keypair();
    let identity_kp = generate_identity_keypair();

    // 6. Send SDP offer through rendezvous (web format: WebSignalPayload)
    let offer_signal = json!({
        "type": "offer",
        "data": {
            "offer": {
                "type": "offer",
                "sdp": local_desc.sdp.to_string(),
            },
            "publicKey": to_base64(&session_kp.public_key),
            "peerCode": TEST_PEER_ID,
        },
        "from": TEST_PEER_ID,
        "to": DAEMON_PEER_ID,
    });
    ws_send_signal(&mut ws, DAEMON_PEER_ID, offer_signal);

    // Send gathered ICE candidates (web format: WebSignalPayload)
    while let Ok(candidate) = ice_rx.try_recv() {
        if candidate.is_empty() {
            continue;
        }
        let ice_signal = json!({
            "type": "ice-candidate",
            "data": {
                "candidate": candidate,
                "sdpMid": "0",
            },
            "from": TEST_PEER_ID,
            "to": DAEMON_PEER_ID,
        });
        ws_send_signal(&mut ws, DAEMON_PEER_ID, ice_signal);
    }

    // Send end-of-candidates marker
    ws_send_signal(
        &mut ws,
        DAEMON_PEER_ID,
        json!({
            "type": "ice-candidate",
            "data": { "candidate": "", "sdpMid": "0" },
            "from": TEST_PEER_ID,
            "to": DAEMON_PEER_ID,
        }),
    );

    // Wait for SDP answer from daemon (web format: WebSignalPayload)
    let mut remote_session_pk: Option<[u8; 32]> = None;
    loop {
        assert!(Instant::now() < deadline, "waiting for SDP answer: timeout");
        let (_from, sig) = ws_wait_for_signal(&mut ws, deadline);

        let sig_type = sig.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match sig_type {
            "answer" => {
                // WebSignalPayload: data.answer.sdp contains the SDP string
                let sdp_str = sig["data"]["answer"]["sdp"]
                    .as_str()
                    .expect("answer missing data.answer.sdp");
                let sdp_parsed =
                    webrtc_sdp::parse_sdp(sdp_str, false).expect("failed to parse answer SDP");
                let answer = SessionDescription {
                    sdp_type: datachannel::SdpType::Answer,
                    sdp: sdp_parsed,
                };
                pc.set_remote_description(&answer).unwrap();

                // Extract remote session public key from data.publicKey
                if let Some(pk_b64) = sig["data"].get("publicKey").and_then(|v| v.as_str()) {
                    let pk_bytes = bolt_core::encoding::from_base64(pk_b64).expect("bad publicKey");
                    assert_eq!(pk_bytes.len(), 32, "publicKey must be 32 bytes");
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&pk_bytes);
                    remote_session_pk = Some(pk);
                }
                break;
            }
            "ice-candidate" => {
                // WebSignalPayload: data.candidate, data.sdpMid
                let cand_str = sig["data"]
                    .get("candidate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !cand_str.is_empty() {
                    let mid = sig["data"]
                        .get("sdpMid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0")
                        .to_string();
                    let _ = pc.add_remote_candidate(&IceCandidate {
                        candidate: cand_str.to_string(),
                        mid,
                    });
                }
            }
            _ => {}
        }
    }

    let remote_session_pk =
        remote_session_pk.expect("daemon answer must include publicKey for HELLO crypto");

    // Drain remaining ICE candidates from daemon (bounded, don't break on non-ICE)
    let ice_drain_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < ice_drain_deadline {
        match try_read_ice_candidate(&mut ws) {
            Some(cand) => {
                let _ = pc.add_remote_candidate(&cand);
            }
            None => {
                // Timeout or non-ICE message — keep trying until deadline
                continue;
            }
        }
    }

    // 7. Wait for DataChannel open (bounded)
    dc_open_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("DataChannel did not open within 10s");

    // 8. HELLO exchange on DataChannel
    let hello_msg = build_hello_message(&identity_kp.public_key, &session_kp, &remote_session_pk)
        .expect("build hello");
    dc.send(hello_msg.as_bytes()).unwrap();

    // Wait for daemon's HELLO reply
    let hello_reply_bytes = dc_msg_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("did not receive HELLO reply");

    let remote_hello = parse_hello_message(&hello_reply_bytes, &remote_session_pk, &session_kp)
        .expect("parse daemon HELLO");

    assert_eq!(remote_hello.version, 1);
    assert_eq!(remote_hello.msg_type, "hello");

    // Negotiate capabilities
    let local_caps = daemon_capabilities(false);
    let negotiated = negotiate_capabilities(&local_caps, &remote_hello.capabilities);
    assert!(
        negotiated.contains(&"bolt.profile-envelope-v1".to_string()),
        "must negotiate bolt.profile-envelope-v1"
    );
    assert!(
        negotiated.contains(&"bolt.file-hash".to_string()),
        "must negotiate bolt.file-hash"
    );

    // 9. Create SessionContext for envelope encryption
    // KeyPair doesn't implement Clone — reconstruct from raw bytes.
    let session_ctx_kp = bolt_core::crypto::KeyPair {
        public_key: session_kp.public_key,
        secret_key: session_kp.secret_key,
    };
    let session_ctx = SessionContext::new(session_ctx_kp, remote_session_pk, negotiated)
        .expect("create SessionContext");

    // 10. Build and send file transfer
    let payload: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let hash = sha256_hex(&payload);

    // FileOffer
    let file_offer = DcMessage::FileOffer {
        transfer_id: "e2e-test-001".to_string(),
        filename: "test.bin".to_string(),
        size: 4096,
        total_chunks: 1,
        chunk_size: 16384,
        file_hash: Some(hash),
    };
    let offer_json = encode_dc_message(&file_offer).unwrap();
    let offer_env = encode_envelope(&offer_json, &session_ctx).unwrap();
    dc.send(&offer_env).unwrap();

    // Wait for FileAccept from daemon (skip periodic pings)
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < accept_deadline,
            "did not receive FileAccept within 5s"
        );
        let msg_bytes = dc_msg_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("DC channel closed waiting for FileAccept");
        let inner = bolt_daemon::test_support::decode_envelope(&msg_bytes, &session_ctx)
            .expect("decode envelope");
        let parsed: Value = serde_json::from_slice(&inner).unwrap();
        let msg_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if msg_type == "file-accept" {
            break;
        }
        // Skip pings, pongs, and other non-transfer messages.
    }

    // FileChunk (single chunk, base64-encoded payload)
    let payload_b64 = bolt_core::encoding::to_base64(&payload);
    let file_chunk = DcMessage::FileChunk {
        transfer_id: "e2e-test-001".to_string(),
        chunk_index: 0,
        total_chunks: 1,
        payload: payload_b64,
    };
    let chunk_json = encode_dc_message(&file_chunk).unwrap();
    let chunk_env = encode_envelope(&chunk_json, &session_ctx).unwrap();
    dc.send(&chunk_env).unwrap();

    // FileFinish
    let file_finish = DcMessage::FileFinish {
        transfer_id: "e2e-test-001".to_string(),
        file_hash: None,
    };
    let finish_json = encode_dc_message(&file_finish).unwrap();
    let finish_env = encode_envelope(&finish_json, &session_ctx).unwrap();
    dc.send(&finish_env).unwrap();

    // 11. Brief pause for daemon to process, then close DataChannel
    std::thread::sleep(Duration::from_millis(500));
    drop(dc);
    drop(pc);

    // 12. Wait for daemon to exit (bounded)
    let mut daemon_child = daemon.take().expect("daemon child already taken");
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match daemon_child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if Instant::now() >= wait_deadline {
                    let _ = daemon_child.kill();
                    let _ = daemon_child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    // Read daemon stderr
    let mut stderr_buf = String::new();
    if let Some(mut stderr) = daemon_child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_buf);
    }

    // 13. Assertions
    assert!(
        stderr_buf.contains("[B4_VERIFY_OK]"),
        "daemon must emit [B4_VERIFY_OK] — hash verification evidence.\nstderr:\n{stderr_buf}"
    );
    assert!(
        !stderr_buf.contains("[B4] integrity failed"),
        "must not have integrity failure.\nstderr:\n{stderr_buf}"
    );
}
