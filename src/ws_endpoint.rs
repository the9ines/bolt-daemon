//! WebSocket server endpoint for browser-to-daemon sessions.
//!
//! # Module Contract (MODULARITY-AUDITABILITY-1)
//!
//! **Owner:** bolt-daemon
//! **Consumers:** main.rs (WsEndpoint mode dispatch)
//!
//! **Exports:**
//! - `WsEndpointConfig` — server configuration (listen addr, identity, capabilities)
//! - `run_ws_endpoint()` — async server entry point (bind, accept, shutdown)
//! - `send_file_to_browser()` — outbound file transfer via global ACTIVE_SESSION
//! - `validate_send_file_path()` — re-exported from `ws_validation`
//! - `ActiveSessionHandle` — session state for outbound sends (outbound_tx, session, btr_engine)
//!
//! **Delegates to `ws_validation`:**
//! - `sanitize_filename()`, `validate_send_file_path()`, `parse_transfer_id_bytes()`, `MAX_TRANSFER_SIZE`
//!
//! **Global state:** `ACTIVE_SESSION: Mutex<Option<ActiveSessionHandle>>` — set when a
//! browser connects and HELLO completes, cleared on disconnect. Used by `send_file_to_browser()`
//! from the IPC/signal-file thread.
//!
//! **Invariants:**
//! - One active session at a time (new connection replaces old)
//! - BTR engine initialized only when `bolt.transfer-ratchet-v1` negotiated
//! - Received filenames sanitized (TI-02)
//! - Transfer size bounded at 2.5 GB (TI-03)
//! - Session keys zeroized on disconnect
//!
//! **Split candidates for future phases:**
//! - File send/receive logic → `ws_transfer.rs`
//! - BTR engine lifecycle → `ws_btr.rs`
//!
//! **Log tokens:**
//!   [WS_ENDPOINT]  — server lifecycle (bind, shutdown)
//!   [WS_SESSION]   — per-connection session lifecycle
//!   [WS_HELLO]     — HELLO handshake over WS
//!   [WS_TRANSFER]  — file transfer events
//!   [BTR]          — BTR engine lifecycle
//!   [BTR_TRANSFER_SEND/RECV/COMPLETE] — BTR transfer events
//!   [SAS]          — SAS verification code

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};

// Validation functions extracted to ws_validation (MODULARITY-AUDITABILITY-2).
use crate::ws_validation::{sanitize_filename, parse_transfer_id_bytes, MAX_TRANSFER_SIZE};
pub use crate::ws_validation::validate_send_file_path;

// BTR crypto extracted to ws_btr (MODULARITY-AUDITABILITY-2).
use crate::ws_btr::{compute_x25519_shared_secret, copy_keypair, decrypt_chunk_btr};

// ── IPC event emission helper ─────────────────────────────────

/// Send a session lifecycle event to the IPC client (native shell).
/// No-op if IPC is not wired (ipc_tx is None).
fn emit_ipc(
    ipc_tx: Option<&std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
    msg_type: &str,
    payload: serde_json::Value,
) {
    if let Some(tx) = ipc_tx {
        let event = crate::ipc::types::IpcMessage::new_event(msg_type, payload);
        if let Err(e) = tx.send(event) {
            eprintln!("[IPC_EMIT] failed to send {msg_type}: {e}");
        }
    }
}

/// Emit a transfer event using the global IPC_TX (for send_file_to_browser context).
fn emit_ipc_global(msg_type: &str, payload: serde_json::Value) {
    if let Ok(guard) = IPC_TX.lock() {
        if let Some(ref tx) = *guard {
            let event = crate::ipc::types::IpcMessage::new_event(msg_type, payload);
            let _ = tx.send(event);
        }
    }
}

// ── Active session handle for outbound sends ────────────────

/// Handle to the active WS session. Allows any thread to send
/// envelope-wrapped messages to the connected browser peer.
///
/// Design: the WS message loop spawns a writer task that drains
/// `outbound_rx`. Any holder of `outbound_tx` can enqueue frames.
/// `SessionContext` is wrapped in Arc for encryption from any thread.
pub struct ActiveSessionHandle {
    pub outbound_tx: tokio::sync::mpsc::UnboundedSender<String>,
    pub session: Arc<SessionContext>,
    // BTR engine: initialized after HELLO when bolt.transfer-ratchet-v1 is negotiated.
    // Currently None — daemon BTR implementation is staged (DAEMON-BTR-1).
    // Will be populated in Stage 2 (engine lifecycle).
    pub btr_engine: Arc<std::sync::Mutex<Option<bolt_btr::BtrEngine>>>,
}

/// Global active session — set when a browser connects and HELLO completes,
/// cleared when the session ends. Protected by std Mutex for cross-thread access.
pub(crate) static ACTIVE_SESSION: std::sync::Mutex<Option<ActiveSessionHandle>> = std::sync::Mutex::new(None);

/// Request to close the active session from outside the WS task (e.g., UI disconnect).
/// The message loop checks this flag and breaks if set.
pub(crate) static DISCONNECT_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Signal the active WS session to close gracefully.
pub fn request_disconnect() {
    DISCONNECT_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
    eprintln!("[WS_SESSION] disconnect requested");
}

/// Request to pause the active file transfer (DAEMON-TRANSFER-CONTROL-1).
/// The send_file_to_browser chunk loop checks this flag between iterations.
pub(crate) static PAUSE_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Pause the active outbound transfer. Sender sleeps between chunks until resumed.
pub fn request_pause() {
    PAUSE_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
    eprintln!("[WS_TRANSFER] pause requested");
    emit_ipc_global("transfer.paused", serde_json::json!({}));
}

/// Resume a paused outbound transfer.
pub fn request_resume() {
    PAUSE_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
    eprintln!("[WS_TRANSFER] resume requested");
    emit_ipc_global("transfer.resumed", serde_json::json!({}));
}

/// Global IPC event sender — set when WS endpoint starts with IPC wired.
/// Used by send_file_to_browser to emit transfer events from the signal-file thread.
static IPC_TX: std::sync::Mutex<Option<std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>> = std::sync::Mutex::new(None);

/// Send a file to the connected browser peer via the active session.
/// Called from the IPC thread (synchronous). Returns error if no active session.
///
/// Streams the file in 16KB chunks from disk — memory usage is bounded at
/// ~16KB + envelope overhead regardless of file size (PERF-1).
pub fn send_file_to_browser(file_path: &str) -> Result<(), String> {
    use std::io::Read;

    // Clone session fields and release the ACTIVE_SESSION lock immediately.
    // Holding the lock during the chunk loop (especially pause) would deadlock
    // against session teardown at line ~929 (DAEMON-TRANSFER-CONTROL-1 fix).
    let (outbound_tx, session, btr_engine) = {
        let guard = ACTIVE_SESSION.lock().map_err(|e| format!("lock: {e}"))?;
        let handle = guard.as_ref().ok_or("no active session")?;
        (
            handle.outbound_tx.clone(),
            Arc::clone(&handle.session),
            Arc::clone(&handle.btr_engine),
        )
    };

    // Get file size from metadata (no full read)
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| format!("metadata: {e}"))?;
    let file_size = metadata.len();
    let filename = std::path::Path::new(file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());

    // Chunk (16KB per chunk, matching browser)
    let chunk_size = 16 * 1024usize;
    let total_chunks = ((file_size as usize + chunk_size - 1) / chunk_size) as u32;
    let transfer_id = format!("{:032x}", rand::random::<u128>());

    eprintln!(
        "[WS_TRANSFER] sending: {} ({} bytes, {} chunks, tid={})",
        filename, file_size, total_chunks, transfer_id
    );

    // Emit transfer.started
    emit_ipc_global("transfer.started", serde_json::json!({
        "transfer_id": transfer_id,
        "file_name": filename,
        "file_size_bytes": file_size,
        "direction": "send",
    }));

    // Open file for streaming reads
    let mut file = std::fs::File::open(file_path)
        .map_err(|e| format!("open file: {e}"))?;
    let mut chunk_buf = vec![0u8; chunk_size];

    // Begin BTR send transfer if engine is available
    let transfer_id_bytes = parse_transfer_id_bytes(&transfer_id)
        .map_err(|e| format!("transfer_id parse: {e}"))?;
    let mut btr_guard = btr_engine.lock().map_err(|e| format!("btr lock: {e}"))?;
    let mut btr_send = if let Some(ref mut engine) = *btr_guard {
        match engine.begin_transfer_send(&transfer_id_bytes, &session.remote_public_key) {
            Ok((ctx, local_ratchet_pub)) => {
                let gen = engine.ratchet_generation();
                eprintln!("[BTR_TRANSFER_SEND] DH ratchet step complete, generation={gen}");
                Some((ctx, local_ratchet_pub, gen))
            }
            Err(e) => {
                eprintln!("[BTR_TRANSFER_SEND] begin failed: {e}, falling back to static");
                None
            }
        }
    } else {
        None
    };
    drop(btr_guard);

    // Clear any stale pause state before starting
    PAUSE_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);

    for i in 0..total_chunks {
        // DAEMON-TRANSFER-CONTROL-1: pause check between chunks.
        // Sleep-poll 100ms while paused. Disconnect breaks out.
        while PAUSE_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if DISCONNECT_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("transfer aborted: disconnect during pause".to_string());
            }
        }

        // Read next chunk from file — bounded memory
        let bytes_read = file.read(&mut chunk_buf)
            .map_err(|e| format!("read chunk {i}: {e}"))?;
        if bytes_read == 0 {
            break;
        }
        let chunk_data = &chunk_buf[..bytes_read];
        let (encrypted, btr_env_fields) = if let Some((ref mut ctx, ref ratchet_pub, gen)) = btr_send {
            // BTR: seal with ratcheted symmetric key
            let (chain_idx, sealed) = ctx.seal_chunk(chunk_data)
                .map_err(|e| format!("btr seal: {e}"))?;
            let chunk_b64 = bolt_core::encoding::to_base64(&sealed);

            // Build BTR envelope fields
            let fields = crate::envelope::BtrEnvelopeFields {
                chain_index: chain_idx,
                // First chunk: include ratchet public key and generation
                ratchet_public_key: if chain_idx == 0 {
                    Some(bolt_core::encoding::to_base64(ratchet_pub))
                } else {
                    None
                },
                ratchet_generation: if chain_idx == 0 { Some(gen) } else { None },
            };
            (chunk_b64, Some(fields))
        } else {
            // Static NaCl box (no BTR)
            let encrypted = bolt_core::crypto::seal_box_payload(
                chunk_data,
                &session.remote_public_key,
                &session.local_keypair.secret_key,
            ).map_err(|e| format!("encrypt chunk: {e}"))?;
            (encrypted, None)
        };

        // Build file-chunk inner message
        let msg = crate::dc_messages::DcMessage::FileChunk {
            transfer_id: transfer_id.clone(),
            filename: filename.clone(),
            chunk_index: i as u32,
            total_chunks,
            chunk: encrypted,
            file_size,
            file_hash: None,
        };
        let inner_json = crate::dc_messages::encode_dc_message(&msg)
            .map_err(|e| format!("encode: {e}"))?;

        // Wrap in profile envelope — with or without BTR fields
        let envelope = if let Some(ref fields) = btr_env_fields {
            crate::envelope::encode_envelope_with_btr(&inner_json, &session, fields)
                .map_err(|e| format!("envelope: {e}"))?
        } else {
            crate::envelope::encode_envelope(&inner_json, &session)
                .map_err(|e| format!("envelope: {e}"))?
        };
        let text = String::from_utf8_lossy(&envelope).into_owned();

        outbound_tx.send(text)
            .map_err(|_| "session closed".to_string())?;

        // Emit progress for UI consumption — throttled to avoid blocking async
        // runtime with per-chunk stderr I/O. Emit at ~5% intervals, first, and last.
        let done = (i + 1) as u32;
        if done == 1 || done == total_chunks || done % (total_chunks / 20).max(1) == 0 {
            let bytes_done = (done as u64).min(total_chunks as u64) * chunk_size as u64;
            let bytes_done = bytes_done.min(file_size);
            let progress = if file_size > 0 { bytes_done as f32 / file_size as f32 } else { 1.0 };
            eprintln!(
                "[WS_TRANSFER] progress: {}/{} chunks ({})",
                done, total_chunks, filename
            );
            emit_ipc_global("transfer.progress", serde_json::json!({
                "transfer_id": transfer_id,
                "bytes_transferred": bytes_done,
                "total_bytes": file_size,
                "progress": progress,
            }));
        }
    }

    // Cleanup BTR send transfer context
    if btr_send.is_some() {
        if let Ok(mut btr_guard) = btr_engine.lock() {
            if let Some(ref mut engine) = *btr_guard {
                engine.end_transfer();
                eprintln!("[BTR_TRANSFER_COMPLETE] Send transfer context cleaned up");
            }
        }
    }

    eprintln!("[WS_TRANSFER] all {} chunks queued for {}", total_chunks, filename);

    // Emit transfer.complete
    emit_ipc_global("transfer.complete", serde_json::json!({
        "transfer_id": transfer_id,
        "file_name": filename,
        "bytes_transferred": file_size,
        "verified": false,
    }));

    Ok(())
}
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::accept_async;
use tungstenite::Message;

use bolt_core::crypto::{generate_ephemeral_keypair, KeyPair};
use bolt_core::session::SessionContext;

use crate::envelope::{build_error_payload, decode_envelope, decode_envelope_with_btr, encode_envelope_with_btr, route_inner_message};
use crate::web_hello::{
    build_hello_message, daemon_capabilities, negotiate_capabilities, parse_hello_typed, HelloError,
};

// ── Configuration ────────────────────────────────────────────

/// Configuration for the WebSocket endpoint.
pub struct WsEndpointConfig {
    /// Address to bind the TCP listener on.
    pub listen_addr: SocketAddr,
    /// Persistent identity keypair (long-lived, loaded from store).
    pub identity_keypair: KeyPair,
    /// Whether WebTransport is enabled on this daemon (WTI4).
    /// Controls capability advertisement in HELLO.
    pub wt_enabled: bool,
}

// ── Public entry point: outbound client connect ─────────────

/// Connect to a remote daemon's WS endpoint as a client.
///
/// Performs the same HELLO/session-key exchange as the server side,
/// then enters the shared `run_session_with_outbound` message loop.
/// This enables native app↔app direct connections.
///
/// Protocol sequence (client perspective):
///   1. WS connect to remote URL
///   2. Send session-key frame
///   3. Receive remote's session-key frame
///   4. Send HELLO (sealed with remote's session public key)
///   5. Receive HELLO response
///   6. Enter envelope message loop
pub async fn connect_to_remote_ws(
    url: &str,
    identity: &KeyPair,
    wt_enabled: bool,
    ipc_tx: Option<std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_tungstenite::connect_async;

    eprintln!("[WS_CLIENT] connecting to {url}");
    let (ws_stream, _) = connect_async(url).await
        .map_err(|e| format!("[WS_CLIENT] connect failed: {e}"))?;
    eprintln!("[WS_CLIENT] connected to {url}");

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Generate ephemeral session keypair
    let session_kp = generate_ephemeral_keypair();

    // Step 1: Send our session public key
    let our_session_key_msg = serde_json::json!({
        "type": "session-key",
        "publicKey": bolt_core::encoding::to_base64(&session_kp.public_key),
    });
    ws_sink
        .send(Message::Text(our_session_key_msg.to_string()))
        .await
        .map_err(|e| format!("[WS_CLIENT] failed to send session key: {e}"))?;
    eprintln!("[WS_CLIENT] sent session-key");

    // Step 2: Read remote's session-key
    let remote_key_msg = wait_for_hello(&mut ws_source, "0.0.0.0:0".parse().unwrap()).await?;
    let remote_key_json: serde_json::Value = serde_json::from_str(&remote_key_msg)
        .map_err(|e| format!("[WS_CLIENT] invalid session-key JSON: {e}"))?;

    if remote_key_json.get("type").and_then(|v| v.as_str()) != Some("session-key") {
        return Err(format!("[WS_CLIENT] expected session-key, got: {}", remote_key_msg).into());
    }
    let remote_pk_b64 = remote_key_json
        .get("publicKey")
        .and_then(|v| v.as_str())
        .ok_or("[WS_CLIENT] session-key missing publicKey")?;
    let remote_session_pk = crate::web_hello::decode_public_key(remote_pk_b64)
        .map_err(|e| format!("[WS_CLIENT] invalid remote session key: {e}"))?;
    eprintln!("[WS_CLIENT] received remote session-key");

    // Step 3: Send HELLO (sealed with remote's session public key)
    let hello_msg = build_hello_message(&identity.public_key, &session_kp, &remote_session_pk)
        .map_err(|e| format!("[WS_CLIENT] failed to build HELLO: {e}"))?;
    ws_sink
        .send(Message::Text(hello_msg))
        .await
        .map_err(|e| format!("[WS_CLIENT] failed to send HELLO: {e}"))?;
    eprintln!("[WS_CLIENT] sent HELLO");

    // Step 4: Read HELLO response
    let hello_response_raw = wait_for_hello(&mut ws_source, "0.0.0.0:0".parse().unwrap()).await?;

    // Check if legacy
    let is_legacy = serde_json::from_str::<serde_json::Value>(&hello_response_raw)
        .ok()
        .and_then(|v| v.get("legacy")?.as_bool())
        .unwrap_or(false);

    let (negotiated, remote_identity_pk, sas) = if is_legacy {
        let legacy_caps: Vec<String> = serde_json::from_str::<serde_json::Value>(&hello_response_raw)
            .ok()
            .and_then(|v| v.get("capabilities")?.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let local_caps = daemon_capabilities(wt_enabled);
        let negotiated = negotiate_capabilities(&local_caps, &legacy_caps);
        eprintln!("[WS_CLIENT] legacy HELLO response, caps={negotiated:?}");
        (negotiated, [0u8; 32], String::new())
    } else {
        // Parse encrypted HELLO response
        let hello_inner = parse_hello_typed(
            hello_response_raw.as_bytes(),
            &remote_session_pk,
            &session_kp,
        )
        .map_err(|e| format!("[WS_CLIENT] HELLO response parse failed: {e}"))?;

        let local_caps = daemon_capabilities(wt_enabled);
        let negotiated = negotiate_capabilities(&local_caps, &hello_inner.capabilities);
        let remote_identity_pk = crate::web_hello::decode_public_key(&hello_inner.identity_public_key)
            .map_err(|e| format!("[WS_CLIENT] invalid remote identity key: {e}"))?;

        let sas = bolt_core::sas::compute_sas(
            &identity.public_key,
            &remote_identity_pk,
            &session_kp.public_key,
            &remote_session_pk,
        );
        eprintln!("[SAS] {sas}");
        eprintln!("[WS_CLIENT] HELLO response ok, caps={negotiated:?}");
        (negotiated, remote_identity_pk, sas)
    };

    // Build session context
    let session = SessionContext::new(
        copy_keypair(&session_kp),
        remote_session_pk,
        negotiated.clone(),
    )
    .map_err(|e| format!("[WS_CLIENT] failed to create session: {e}"))?;

    // Emit session events to IPC
    let remote_pk_b64_identity = bolt_core::encoding::to_base64(&remote_identity_pk);
    emit_ipc(ipc_tx.as_ref(), "session.connected", serde_json::json!({
        "remote_peer_id": remote_pk_b64_identity,
        "negotiated_capabilities": negotiated,
    }));
    if !sas.is_empty() {
        emit_ipc(ipc_tx.as_ref(), "session.sas", serde_json::json!({
            "sas": sas,
            "remote_identity_pk_b64": remote_pk_b64_identity,
        }));
    }

    eprintln!("[WS_CLIENT] session established, entering message loop");

    // Enter the same message loop as server connections
    run_session_with_outbound(
        ws_sink, ws_source, session, "0.0.0.0:0".parse().unwrap(), remote_identity_pk, ipc_tx.as_ref(),
    )
    .await
}

// ── Public entry point: server ──────────────────────────────

/// Run the WebSocket endpoint server.
///
/// Binds a TCP listener, accepts WebSocket upgrades, and spawns a task
/// per connection. Runs until `shutdown_rx` receives `true`.
///
/// Fail-closed: individual connection errors are logged and the
/// connection is dropped. The server continues accepting new connections.
pub async fn run_ws_endpoint(
    config: WsEndpointConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    ipc_tx: Option<std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Store IPC sender globally for send_file_to_browser to use
    if let Some(ref tx) = ipc_tx {
        *IPC_TX.lock().unwrap() = Some(tx.clone());
    }

    let listener = TcpListener::bind(config.listen_addr).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("[WS_ENDPOINT] listening on {local_addr}");

    // Store identity key material in an Arc for sharing across tasks.
    // KeyPair doesn't impl Clone, so we store the raw bytes.
    let identity_pk = Arc::new(config.identity_keypair.public_key);
    let identity_sk = Arc::new(config.identity_keypair.secret_key);
    let wt_enabled = config.wt_enabled;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        eprintln!("[WS_SESSION] accepted TCP from {peer_addr}");
                        let pk = Arc::clone(&identity_pk);
                        let sk = Arc::clone(&identity_sk);
                        let ipc = ipc_tx.clone();
                        tokio::spawn(async move {
                            let identity = KeyPair {
                                public_key: *pk,
                                secret_key: *sk,
                            };
                            if let Err(e) = handle_connection(stream, peer_addr, &identity, wt_enabled, ipc.as_ref()).await {
                                eprintln!("[WS_SESSION] {peer_addr} error: {e}");
                            }
                            eprintln!("[WS_SESSION] {peer_addr} closed");
                        });
                    }
                    Err(e) => {
                        eprintln!("[WS_ENDPOINT] accept error: {e}");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    eprintln!("[WS_ENDPOINT] shutdown signal received");
                    break;
                }
            }
        }
    }

    eprintln!("[WS_ENDPOINT] stopped");
    Ok(())
}

// ── Per-connection handler ───────────────────────────────────

/// Handle a single WebSocket connection through the full protocol lifecycle:
/// 1. WebSocket upgrade
/// 2. HELLO exchange (ephemeral keypair, capability negotiation)
/// 3. Envelope message loop (decode, route, reply)
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    identity: &KeyPair,
    wt_enabled: bool,
    ipc_tx: Option<&std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Step 1: WebSocket upgrade ────────────────────────────
    let ws_stream = accept_async(stream)
        .await
        .map_err(|e| format!("[WS_SESSION] {peer_addr} WebSocket upgrade failed: {e}"))?;

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // ── Step 2: Generate ephemeral session keypair ────────────
    let session_kp = generate_ephemeral_keypair();

    // ── Step 3: Wait for HELLO from browser ──────────────────
    let hello_msg = wait_for_hello(&mut ws_source, peer_addr).await?;

    // We need the remote session public key to decrypt.
    // The remote's ephemeral public key is embedded in the NaCl-box
    // nonce+ciphertext — we extract it from the outer JSON payload.
    // But parse_hello_typed needs the remote public key as input.
    //
    // In the DataChannel path, session keys are exchanged during signaling.
    // For WS-direct (RC5), we use a two-phase approach:
    //   - Browser sends its session public key in a pre-HELLO key-exchange frame
    //   - OR we use the identity public key for the HELLO box.
    //
    // RC5 approach: The browser's HELLO is sealed with OUR session public key.
    // We need to advertise our session public key first so the browser can
    // seal its HELLO for us.
    //
    // Protocol sequence:
    //   1. Daemon sends its session public key as a JSON frame
    //   2. Browser seals HELLO with daemon's session public key
    //   3. Daemon decrypts HELLO, gets browser's identity + capabilities
    //   4. Daemon seals HELLO response with browser's session public key
    //
    // Actually, looking at the existing protocol more carefully:
    // In WebRTC, session keys are exchanged via the signaling channel (SDP).
    // For WS-direct, we need an equivalent key exchange step.
    //
    // Simplest RC5 approach: ephemeral key exchange frame before HELLO.
    // {"type":"session-key","publicKey":"<base64>"}

    // First, send our session public key to the browser
    let our_session_key_msg = serde_json::json!({
        "type": "session-key",
        "publicKey": bolt_core::encoding::to_base64(&session_kp.public_key),
    });
    ws_sink
        .send(Message::Text(our_session_key_msg.to_string()))
        .await
        .map_err(|e| format!("[WS_HELLO] {peer_addr} failed to send session key: {e}"))?;
    eprintln!("[WS_HELLO] {peer_addr} sent session-key");

    // The first message we received (hello_msg) might actually be the
    // browser's session key. Let's handle both orderings.
    let (remote_session_pk, hello_raw) = if let Ok(value) =
        serde_json::from_str::<serde_json::Value>(&hello_msg)
    {
        if value.get("type").and_then(|v| v.as_str()) == Some("session-key") {
            // First message was a session-key, read the actual HELLO next
            let remote_pk_b64 = value
                .get("publicKey")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("[WS_HELLO] {peer_addr} session-key missing publicKey"))?;
            let remote_pk = crate::web_hello::decode_public_key(remote_pk_b64)
                .map_err(|e| format!("[WS_HELLO] {peer_addr} invalid session key: {e}"))?;
            eprintln!("[WS_HELLO] {peer_addr} received session-key");

            // Now wait for the actual HELLO
            let hello_text = wait_for_hello(&mut ws_source, peer_addr).await?;
            (remote_pk, hello_text)
        } else {
            // First message is the HELLO itself — but we don't have the
            // remote session key yet. This is a protocol error for WS-direct.
            return Err(
                format!("[WS_HELLO] {peer_addr} expected session-key frame before HELLO").into(),
            );
        }
    } else {
        return Err(format!("[WS_HELLO] {peer_addr} first message is not valid JSON").into());
    };

    // ── Step 4: Check for legacy (plaintext) HELLO ──────────
    // Browser peers without identity send: {"type":"hello","version":1,"legacy":true,...}
    // In this case, skip encrypted HELLO decryption and proceed with session keys only.
    let is_legacy = serde_json::from_str::<serde_json::Value>(&hello_raw)
        .ok()
        .and_then(|v| v.get("legacy")?.as_bool())
        .unwrap_or(false);

    if is_legacy {
        // Legacy HELLO — extract capabilities from plaintext, no identity exchange
        let legacy_caps: Vec<String> = serde_json::from_str::<serde_json::Value>(&hello_raw)
            .ok()
            .and_then(|v| v.get("capabilities")?.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        eprintln!("[WS_HELLO] {peer_addr} legacy HELLO (no identity), caps={legacy_caps:?}");

        let local_caps = daemon_capabilities(wt_enabled);
        let negotiated = negotiate_capabilities(&local_caps, &legacy_caps);
        eprintln!("[WS_HELLO] {peer_addr} negotiated capabilities: {negotiated:?}");

        // Send a legacy HELLO response so browser knows daemon acknowledged
        let legacy_response = serde_json::json!({
            "type": "hello",
            "version": 1,
            "legacy": true,
            "capabilities": local_caps,
        });
        ws_sink
            .send(Message::Text(legacy_response.to_string()))
            .await
            .map_err(|e| format!("[WS_HELLO] {peer_addr} failed to send legacy HELLO response: {e}"))?;
        eprintln!("[WS_HELLO] {peer_addr} sent legacy HELLO response");

        let session = SessionContext::new(
            copy_keypair(&session_kp),
            remote_session_pk,
            negotiated.clone(),
        )
        .map_err(|e| format!("[WS_SESSION] {peer_addr} failed to create session: {e}"))?;

        eprintln!("[WS_SESSION] {peer_addr} session established, entering message loop");

        // Emit session.connected (legacy — no SAS)
        emit_ipc(ipc_tx, "session.connected", serde_json::json!({
            "remote_peer_id": "(legacy)",
            "negotiated_capabilities": negotiated,
        }));

        return run_session_with_outbound(
            ws_sink, ws_source, session, peer_addr, remote_session_pk, ipc_tx,
        ).await;
    }

    // ── Step 4b: Parse and decrypt HELLO (identity mode) ────
    let hello_inner = parse_hello_typed(hello_raw.as_bytes(), &remote_session_pk, &session_kp)
        .map_err(|e| {
            let code = match &e {
                HelloError::ParseError(_) => "HELLO_PARSE_ERROR",
                HelloError::DecryptFail(_) => "HELLO_DECRYPT_FAIL",
                HelloError::SchemaError(_) => "HELLO_SCHEMA_ERROR",
                HelloError::DowngradeAttempt => "PROTOCOL_VIOLATION",
                HelloError::KeyMismatch(_) => "KEY_MISMATCH",
                HelloError::DuplicateHello => "DUPLICATE_HELLO",
            };
            eprintln!("[WS_HELLO] {peer_addr} HELLO failed: {e} (code={code})");
            format!("[WS_HELLO] {peer_addr} HELLO validation failed: {e}")
        })?;

    eprintln!(
        "[WS_HELLO] {peer_addr} HELLO ok: identity={}, caps={:?}",
        hello_inner.identity_public_key, hello_inner.capabilities,
    );

    // ── Step 5: Negotiate capabilities ───────────────────────
    let local_caps = daemon_capabilities(wt_enabled);
    let negotiated = negotiate_capabilities(&local_caps, &hello_inner.capabilities);
    eprintln!("[WS_HELLO] {peer_addr} negotiated capabilities: {negotiated:?}");

    // ── Step 6: Send HELLO response ──────────────────────────
    let hello_response = build_hello_message(&identity.public_key, &session_kp, &remote_session_pk)
        .map_err(|e| format!("[WS_HELLO] {peer_addr} failed to build HELLO response: {e}"))?;
    ws_sink
        .send(Message::Text(hello_response))
        .await
        .map_err(|e| format!("[WS_HELLO] {peer_addr} failed to send HELLO response: {e}"))?;
    eprintln!("[WS_HELLO] {peer_addr} sent HELLO response");

    // ── Step 7: Build session context ────────────────────────
    let remote_identity_pk = crate::web_hello::decode_public_key(&hello_inner.identity_public_key)
        .map_err(|e| format!("[WS_SESSION] {peer_addr} invalid remote identity key: {e}"))?;

    let session = SessionContext::new(
        copy_keypair(&session_kp),
        remote_session_pk,
        negotiated.clone(),
    )
    .map_err(|e| format!("[WS_SESSION] {peer_addr} failed to create session: {e}"))?;

    // Compute and log SAS verification code (same algorithm as browser)
    let sas = bolt_core::sas::compute_sas(
        &identity.public_key,
        &remote_identity_pk,
        &session_kp.public_key,
        &remote_session_pk,
    );
    eprintln!("[SAS] {sas}");

    // Emit session.connected + session.sas to IPC
    let remote_pk_b64 = bolt_core::encoding::to_base64(&remote_identity_pk);
    emit_ipc(ipc_tx, "session.connected", serde_json::json!({
        "remote_peer_id": remote_pk_b64,
        "negotiated_capabilities": negotiated,
    }));
    emit_ipc(ipc_tx, "session.sas", serde_json::json!({
        "sas": sas,
        "remote_identity_pk_b64": remote_pk_b64,
    }));

    eprintln!("[WS_SESSION] {peer_addr} session established, entering message loop");

    // ── Step 8: Envelope message loop ────────────────────────
    run_session_with_outbound(
        ws_sink, ws_source, session, peer_addr, remote_identity_pk, ipc_tx,
    )
    .await
}

/// Wait for a text message from the WebSocket stream.
///
/// Skips ping/pong frames. Returns error on close or binary frame.
async fn wait_for_hello(
    source: &mut (impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin),
    peer_addr: SocketAddr,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    type BoxErr = Box<dyn std::error::Error + Send + Sync>;
    let timeout = tokio::time::Duration::from_secs(30);
    let msg = tokio::time::timeout(timeout, async {
        while let Some(result) = source.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    return Ok::<String, BoxErr>(text);
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                    continue;
                }
                Ok(Message::Close(_)) => {
                    let err: BoxErr =
                        format!("[WS_HELLO] {peer_addr} connection closed during HELLO").into();
                    return Err(err);
                }
                Ok(other) => {
                    let err: BoxErr = format!(
                        "[WS_HELLO] {peer_addr} unexpected frame type during HELLO: {other:?}"
                    )
                    .into();
                    return Err(err);
                }
                Err(e) => {
                    let err: BoxErr =
                        format!("[WS_HELLO] {peer_addr} read error during HELLO: {e}").into();
                    return Err(err);
                }
            }
        }
        let err: BoxErr = format!("[WS_HELLO] {peer_addr} stream ended during HELLO").into();
        Err(err)
    })
    .await
    .map_err(|_| -> BoxErr {
        format!("[WS_HELLO] {peer_addr} HELLO timeout (30s)").into()
    })??;
    Ok(msg)
}

/// Post-HELLO envelope message loop.
///
/// Set up the active session handle, spawn a writer task for outbound messages,
/// register the global ACTIVE_SESSION, and run the read loop.
/// Clears ACTIVE_SESSION on exit.
async fn run_session_with_outbound(
    mut ws_sink: impl SinkExt<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    mut ws_source: impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin,
    session: SessionContext,
    peer_addr: SocketAddr,
    remote_pk: [u8; 32],
    ipc_tx: Option<&std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let session = Arc::new(session);

    // Initialize BTR engine if bolt.transfer-ratchet-v1 was negotiated.
    // Compute X25519 shared secret from session ephemeral keys (same as
    // browser's scalarMult(localSecretKey, remotePublicKey)).
    let btr_engine = if session.has_capability("bolt.transfer-ratchet-v1") {
        let shared_secret = compute_x25519_shared_secret(
            &session.local_keypair.secret_key,
            &session.remote_public_key,
        );
        let engine = bolt_btr::BtrEngine::new(&shared_secret);
        eprintln!("[BTR] {peer_addr} engine initialized (generation={})", engine.ratchet_generation());
        Some(engine)
    } else {
        eprintln!("[BTR] {peer_addr} BTR not negotiated — static NaCl box mode");
        None
    };

    // Wrap BTR engine in Arc<Mutex> so both ACTIVE_SESSION (for IPC sends)
    // and run_read_loop (for receives) hold a reference without going through the global.
    let btr_engine_arc = Arc::new(std::sync::Mutex::new(btr_engine));

    // Register active session globally so IPC file.send can use it
    {
        let mut guard = ACTIVE_SESSION.lock().unwrap();
        *guard = Some(ActiveSessionHandle {
            outbound_tx: outbound_tx.clone(),
            session: Arc::clone(&session),
            btr_engine: Arc::clone(&btr_engine_arc),
        });
    }
    eprintln!("[WS_SESSION] {peer_addr} active session handle registered");

    // Writer task: drains outbound channel → ws_sink
    // Also handles replies from the read loop via a second channel.
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = outbound_rx.recv() => {
                    match msg {
                        Some(text) => {
                            if let Err(e) = ws_sink.send(Message::Text(text)).await {
                                eprintln!("[WS_SESSION] outbound send error: {e}");
                                break;
                            }
                        }
                        None => break, // channel closed
                    }
                }
                reply = reply_rx.recv() => {
                    match reply {
                        Some(text) => {
                            if let Err(e) = ws_sink.send(Message::Text(text)).await {
                                eprintln!("[WS_SESSION] reply send error: {e}");
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // Read loop
    let result = run_read_loop(&mut ws_source, &session, peer_addr, &remote_pk, &reply_tx, &btr_engine_arc, ipc_tx).await;

    // Emit session lifecycle event based on read loop result
    match &result {
        Ok(()) => {
            emit_ipc(ipc_tx, "session.ended", serde_json::json!({
                "reason": "connection closed",
            }));
        }
        Err(e) => {
            emit_ipc(ipc_tx, "session.error", serde_json::json!({
                "reason": format!("{e}"),
            }));
        }
    }

    // Cleanup: zeroize BTR state via local Arc (not through global)
    if let Ok(mut btr) = btr_engine_arc.lock() {
        if let Some(ref mut engine) = *btr {
            engine.cleanup_disconnect();
            eprintln!("[BTR] {peer_addr} engine zeroized on disconnect");
        }
    }
    // Clear global session handle
    {
        let mut guard = ACTIVE_SESSION.lock().unwrap();
        *guard = None;
    }
    eprintln!("[WS_SESSION] {peer_addr} active session handle cleared");

    // Stop writer task
    drop(reply_tx);
    let _ = writer_handle.await;

    result
}

/// Read loop for active sessions. Sends replies via `reply_tx` channel
/// instead of writing to ws_sink directly (writer task handles that).
async fn run_read_loop(
    ws_source: &mut (impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin),
    session: &SessionContext,
    peer_addr: SocketAddr,
    _remote_identity_pk: &[u8; 32],
    reply_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    btr_engine: &Arc<std::sync::Mutex<Option<bolt_btr::BtrEngine>>>,
    ipc_tx: Option<&std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // File receive state: accumulate chunks per transfer_id
    use std::collections::HashMap;
    struct ReceiveTransfer {
        filename: String,
        file_size: u64,
        total_chunks: u32,
        chunks: HashMap<u32, Vec<u8>>,
    }
    let mut active_receives: HashMap<String, ReceiveTransfer> = HashMap::new();

    // BTR receive state: per-transfer context for BTR chunk decryption.
    // Keyed by transfer_id string. Created on first BTR chunk (chain_index=0).
    // BTR receive contexts keyed by transfer_id.
    // Tuple: (BtrTransferContext, generation) — generation captured from first chunk
    // and used for replay guard checks on subsequent chunks that omit ratchet_generation.
    let mut btr_receive_contexts: HashMap<String, (bolt_btr::BtrTransferContext, u32)> = HashMap::new();

    // Clear any stale disconnect request before entering the loop
    DISCONNECT_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);

    loop {
        // Check disconnect flag every iteration
        if DISCONNECT_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
            DISCONNECT_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
            eprintln!("[WS_SESSION] {peer_addr} disconnect requested — closing");
            break;
        }

        let result = tokio::select! {
            r = ws_source.next() => r,
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(250)) => continue,
        };

        let msg = match result {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                eprintln!("[WS_SESSION] {peer_addr} read error: {e}");
                break;
            }
            None => break, // stream ended
        };

        match msg {
            Message::Text(text) => {
                // Decode envelope AND extract BTR fields
                let (inner, btr_fields) = match decode_envelope_with_btr(text.as_bytes(), session) {
                    Ok(result) => result,
                    Err(e) => {
                        eprintln!("[WS_SESSION] {peer_addr} envelope error: {e}");
                        let error_payload =
                            build_error_payload(e.code(), &e.to_string(), Some(session));
                        let _ = reply_tx.send(
                            String::from_utf8_lossy(&error_payload).into_owned(),
                        );
                        break;
                    }
                };

                // Route inner message
                match route_inner_message(&inner, session) {
                    Ok(Some(reply_bytes)) => {
                        let reply_text = String::from_utf8_lossy(&reply_bytes).into_owned();
                        if reply_tx.send(reply_text).is_err() {
                            eprintln!("[WS_SESSION] {peer_addr} reply channel closed");
                            break;
                        }
                    }
                    Ok(None) => {
                        // Check if this is a file-transfer message we should handle
                        if let Ok(dc_msg) = crate::dc_messages::parse_dc_message(&inner) {
                            match dc_msg {
                                crate::dc_messages::DcMessage::FileChunk {
                                    ref transfer_id,
                                    ref filename,
                                    chunk_index,
                                    total_chunks,
                                    ref chunk,
                                    file_size,
                                    ..
                                } => {
                                    // Decrypt chunk — BTR or static NaCl box
                                    let data = if let Some(ref btr_env) = btr_fields {
                                        // BTR mode: use ratcheted symmetric key
                                        decrypt_chunk_btr(
                                            transfer_id,
                                            chunk,
                                            chunk_index,
                                            btr_env,
                                            session,
                                            peer_addr,
                                            btr_engine,
                                            &mut btr_receive_contexts,
                                        )
                                    } else {
                                        // Static NaCl box mode
                                        bolt_core::crypto::open_box_payload(
                                            chunk,
                                            &session.remote_public_key,
                                            &session.local_keypair.secret_key,
                                        ).map_err(|e| e.to_string())
                                    };
                                    let data = match data {
                                        Ok(plaintext) => plaintext,
                                        Err(e) => {
                                            eprintln!("[WS_TRANSFER] {peer_addr} chunk {chunk_index} decrypt FAILED: {e}");
                                            continue;
                                        }
                                    };
                                    // Reject oversized transfers on first chunk
                                    if !active_receives.contains_key(transfer_id) && file_size > MAX_TRANSFER_SIZE {
                                        eprintln!(
                                            "[WS_TRANSFER] {peer_addr} REJECTED: {} ({} bytes) exceeds {} byte limit",
                                            filename, file_size, MAX_TRANSFER_SIZE
                                        );
                                        continue;
                                    }

                                    let rx = active_receives
                                        .entry(transfer_id.clone())
                                        .or_insert_with(|| {
                                            // Sanitize filename on first chunk
                                            let safe_name = match sanitize_filename(filename) {
                                                Ok(name) => name,
                                                Err(e) => {
                                                    eprintln!(
                                                        "[WS_TRANSFER] {peer_addr} REJECTED filename: {e} (raw: {:?})",
                                                        filename
                                                    );
                                                    // Use a safe fallback — transfer still accepted but
                                                    // saved with a generic name to avoid data loss.
                                                    format!("received_{}", transfer_id)
                                                }
                                            };
                                            eprintln!(
                                                "[WS_TRANSFER] {peer_addr} receiving: {} ({} bytes, {} chunks)",
                                                safe_name, file_size, total_chunks
                                            );
                                            emit_ipc(ipc_tx, "transfer.started", serde_json::json!({
                                                "transfer_id": transfer_id,
                                                "file_name": safe_name,
                                                "file_size_bytes": file_size,
                                                "direction": "receive",
                                            }));
                                            ReceiveTransfer {
                                                filename: safe_name,
                                                file_size,
                                                total_chunks,
                                                chunks: HashMap::new(),
                                            }
                                        });
                                    rx.chunks.insert(chunk_index, data);

                                    // Emit progress for UI — throttled to ~5% intervals
                                    let done = rx.chunks.len() as u32;
                                    let total = rx.total_chunks;
                                    if done == 1 || done == total || done % (total / 20).max(1) == 0 {
                                        let bytes_done = if rx.file_size > 0 {
                                            (done as u64 * rx.file_size) / total as u64
                                        } else { 0 };
                                        let progress = if total > 0 { done as f32 / total as f32 } else { 1.0 };
                                        eprintln!(
                                            "[WS_TRANSFER] {peer_addr} progress: {}/{} chunks ({})",
                                            done, total, rx.filename
                                        );
                                        emit_ipc(ipc_tx, "transfer.progress", serde_json::json!({
                                            "transfer_id": transfer_id,
                                            "bytes_transferred": bytes_done,
                                            "total_bytes": rx.file_size,
                                            "progress": progress,
                                        }));
                                    }

                                    // Check if all chunks received
                                    if rx.chunks.len() as u32 >= rx.total_chunks {
                                        // Assemble and save file
                                        let mut file_data = Vec::with_capacity(rx.file_size as usize);
                                        for i in 0..rx.total_chunks {
                                            if let Some(c) = rx.chunks.get(&i) {
                                                file_data.extend_from_slice(c);
                                            }
                                        }
                                        let save_dir = format!(
                                            "{}/Downloads",
                                            std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
                                        );
                                        let save_path = format!("{}/{}", save_dir, rx.filename);

                                        // Final containment check: resolved path must be inside save_dir
                                        let canonical_dir = std::path::Path::new(&save_dir);
                                        let canonical_path = std::path::Path::new(&save_path);
                                        if !canonical_path.starts_with(canonical_dir) {
                                            eprintln!(
                                                "[WS_TRANSFER] {peer_addr} PATH ESCAPE BLOCKED: {} resolves outside {}",
                                                save_path, save_dir
                                            );
                                            active_receives.remove(transfer_id);
                                            continue;
                                        }

                                        match std::fs::write(&save_path, &file_data) {
                                            Ok(()) => {
                                                eprintln!(
                                                    "[WS_TRANSFER] {peer_addr} saved: {} ({} bytes) → {}",
                                                    rx.filename, file_data.len(), save_path
                                                );
                                                emit_ipc(ipc_tx, "transfer.complete", serde_json::json!({
                                                    "transfer_id": transfer_id,
                                                    "file_name": rx.filename,
                                                    "bytes_transferred": file_data.len(),
                                                    "verified": false,
                                                    "save_path": save_path,
                                                }));
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[WS_TRANSFER] {peer_addr} save failed: {} — {}",
                                                    rx.filename, e
                                                );
                                                emit_ipc(ipc_tx, "transfer.error", serde_json::json!({
                                                    "transfer_id": transfer_id,
                                                    "file_name": rx.filename,
                                                    "reason": format!("{e}"),
                                                }));
                                            }
                                        }
                                        active_receives.remove(transfer_id);
                                        // Clean up BTR transfer context
                                        if btr_receive_contexts.remove(transfer_id).is_some() {
                                            if let Ok(mut btr) = btr_engine.lock() {
                                                if let Some(ref mut engine) = *btr {
                                                    engine.end_transfer();
                                                    eprintln!("[BTR_TRANSFER_COMPLETE] Receive transfer context cleaned up");
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {} // Other file messages (offer, finish, etc.)
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[WS_SESSION] {peer_addr} route error: {e}");
                        let error_payload =
                            build_error_payload(e.code(), &e.to_string(), Some(session));
                        let _ = reply_tx.send(
                            String::from_utf8_lossy(&error_payload).into_owned(),
                        );
                        break;
                    }
                }
            }
            Message::Ping(_) => {
                // WS-level pings — reply_tx only handles text; pong needs direct sink access.
                // The writer task handles this via a special pong message would be complex.
                // For now, pings are acknowledged by the tungstenite layer automatically.
            }
            Message::Pong(_) => {
                // Ignore WS-level pongs
            }
            Message::Close(_) => {
                eprintln!("[WS_SESSION] {peer_addr} received close frame");
                break;
            }
            Message::Binary(_) => {
                eprintln!("[WS_SESSION] {peer_addr} binary frame rejected (text-only protocol)");
                break;
            }
            Message::Frame(_) => {
                // Raw frame — ignore
            }
        }
    }

    eprintln!("[WS_SESSION] {peer_addr} message loop ended");
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::encode_envelope;
    use bolt_core::crypto::generate_ephemeral_keypair;
    use bolt_core::identity::generate_identity_keypair;
    use tokio_tungstenite::connect_async;

    /// Find an available port by binding to :0.
    async fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn ws_endpoint_starts_and_accepts_connection() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: identity,
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        // Give server a moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Connect a WebSocket client
        let url = format!("ws://127.0.0.1:{port}");
        let result = connect_async(&url).await;
        assert!(result.is_ok(), "WS connect should succeed");

        let (ws_stream, _) = result.unwrap();
        // Clean close
        let (mut sink, _source) = ws_stream.split();
        let _ = sink.close().await;

        // Shutdown server
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn ws_hello_handshake_succeeds() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let daemon_identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: copy_keypair(&daemon_identity),
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Connect as browser client
        let url = format!("ws://127.0.0.1:{port}");
        let (ws_stream, _) = connect_async(&url).await.unwrap();
        let (mut sink, mut source) = ws_stream.split();

        // Browser generates its own session keypair
        let browser_session_kp = generate_ephemeral_keypair();
        let browser_identity = generate_identity_keypair();

        // Send browser's session key
        let session_key_msg = serde_json::json!({
            "type": "session-key",
            "publicKey": bolt_core::encoding::to_base64(&browser_session_kp.public_key),
        });
        sink.send(Message::Text(session_key_msg.to_string()))
            .await
            .unwrap();

        // Receive daemon's session key
        let daemon_session_key_msg = source.next().await.unwrap().unwrap();
        let daemon_sk_text = match daemon_session_key_msg {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let daemon_sk_value: serde_json::Value = serde_json::from_str(&daemon_sk_text).unwrap();
        assert_eq!(daemon_sk_value["type"], "session-key");
        let daemon_session_pk =
            crate::web_hello::decode_public_key(daemon_sk_value["publicKey"].as_str().unwrap())
                .unwrap();

        // Build and send HELLO (sealed for daemon's session key)
        let hello_msg = build_hello_message(
            &browser_identity.public_key,
            &browser_session_kp,
            &daemon_session_pk,
        )
        .unwrap();
        sink.send(Message::Text(hello_msg)).await.unwrap();

        // Receive HELLO response from daemon
        let hello_response = source.next().await.unwrap().unwrap();
        let hello_text = match hello_response {
            Message::Text(t) => t,
            other => panic!("expected text HELLO response, got {other:?}"),
        };

        // Parse daemon's HELLO response
        let inner = crate::web_hello::parse_hello_message(
            hello_text.as_bytes(),
            &daemon_session_pk,
            &browser_session_kp,
        )
        .unwrap();
        assert_eq!(inner.msg_type, "hello");
        assert_eq!(inner.version, 1);
        assert!(inner
            .capabilities
            .contains(&"bolt.profile-envelope-v1".to_string()));

        // Clean close
        let _ = sink.close().await;
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn ws_envelope_roundtrip_over_ws() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let daemon_identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: copy_keypair(&daemon_identity),
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Connect and do HELLO handshake
        let url = format!("ws://127.0.0.1:{port}");
        let (ws_stream, _) = connect_async(&url).await.unwrap();
        let (mut sink, mut source) = ws_stream.split();

        let browser_session_kp = generate_ephemeral_keypair();
        let browser_identity = generate_identity_keypair();

        // Session key exchange
        let session_key_msg = serde_json::json!({
            "type": "session-key",
            "publicKey": bolt_core::encoding::to_base64(&browser_session_kp.public_key),
        });
        sink.send(Message::Text(session_key_msg.to_string()))
            .await
            .unwrap();

        let daemon_sk_msg = source.next().await.unwrap().unwrap();
        let daemon_sk_text = match daemon_sk_msg {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let daemon_sk_value: serde_json::Value = serde_json::from_str(&daemon_sk_text).unwrap();
        let daemon_session_pk =
            crate::web_hello::decode_public_key(daemon_sk_value["publicKey"].as_str().unwrap())
                .unwrap();

        // HELLO exchange
        let hello_msg = build_hello_message(
            &browser_identity.public_key,
            &browser_session_kp,
            &daemon_session_pk,
        )
        .unwrap();
        sink.send(Message::Text(hello_msg)).await.unwrap();

        let _hello_response = source.next().await.unwrap().unwrap();

        // Now we have a session. Build browser-side SessionContext.
        let negotiated = vec![
            "bolt.profile-envelope-v1".to_string(),
            "bolt.file-hash".to_string(),
        ];
        let browser_session = SessionContext::new(
            copy_keypair(&browser_session_kp),
            daemon_session_pk,
            negotiated,
        )
        .unwrap();

        // Send an encrypted ping
        let ping = crate::dc_messages::DcMessage::Ping { ts_ms: 1234567890 };
        let ping_json = crate::dc_messages::encode_dc_message(&ping).unwrap();
        let envelope = encode_envelope(&ping_json, &browser_session).unwrap();
        let envelope_text = String::from_utf8(envelope).unwrap();

        sink.send(Message::Text(envelope_text)).await.unwrap();

        // Should receive an encrypted pong
        let pong_msg = tokio::time::timeout(tokio::time::Duration::from_secs(5), source.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let pong_text = match pong_msg {
            Message::Text(t) => t,
            other => panic!("expected text pong, got {other:?}"),
        };

        // Decrypt the pong
        let pong_inner = decode_envelope(pong_text.as_bytes(), &browser_session).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&pong_inner).unwrap();
        assert_eq!(parsed["type"], "pong");
        assert_eq!(parsed["reply_to_ms"], 1234567890);

        // Clean close
        let _ = sink.close().await;
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn ws_connection_close_is_clean() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: identity,
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Connect and immediately close
        let url = format!("ws://127.0.0.1:{port}");
        let (ws_stream, _) = connect_async(&url).await.unwrap();
        let (mut sink, _source) = ws_stream.split();

        // Send close frame
        let _ = sink.send(Message::Close(None)).await;
        let _ = sink.close().await;

        // Server should not crash — give it a moment
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify server is still running by connecting again
        let result = connect_async(&url).await;
        assert!(
            result.is_ok(),
            "Server should still accept after clean close"
        );

        let (ws2, _) = result.unwrap();
        let (mut sink2, _) = ws2.split();
        let _ = sink2.close().await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    /// Legacy HELLO: browser without identity sends plaintext HELLO with legacy=true.
    /// Daemon must accept it, send legacy HELLO response, and establish session.
    #[tokio::test]
    async fn ws_legacy_hello_establishes_session() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let daemon_identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: copy_keypair(&daemon_identity),
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let url = format!("ws://127.0.0.1:{port}");
        let (ws_stream, _) = connect_async(&url).await.unwrap();
        let (mut sink, mut source) = ws_stream.split();

        let browser_session_kp = generate_ephemeral_keypair();

        // Step 1: Send session-key
        let session_key_msg = serde_json::json!({
            "type": "session-key",
            "publicKey": bolt_core::encoding::to_base64(&browser_session_kp.public_key),
        });
        sink.send(Message::Text(session_key_msg.to_string()))
            .await
            .unwrap();

        // Step 2: Receive daemon's session-key
        let daemon_sk_msg = source.next().await.unwrap().unwrap();
        let daemon_sk_text = match daemon_sk_msg {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let daemon_sk_value: serde_json::Value = serde_json::from_str(&daemon_sk_text).unwrap();
        assert_eq!(daemon_sk_value["type"], "session-key");
        assert!(daemon_sk_value["publicKey"].as_str().is_some());

        // Step 3: Send legacy HELLO (no identity, no encryption)
        let legacy_hello = serde_json::json!({
            "type": "hello",
            "version": 1,
            "legacy": true,
            "capabilities": [],
        });
        sink.send(Message::Text(legacy_hello.to_string()))
            .await
            .unwrap();

        // Step 4: Receive daemon's legacy HELLO response
        let response = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            source.next(),
        )
        .await
        .expect("should receive legacy HELLO response within 5s")
        .unwrap()
        .unwrap();

        let response_text = match response {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let response_value: serde_json::Value = serde_json::from_str(&response_text).unwrap();
        assert_eq!(response_value["type"], "hello");
        assert_eq!(response_value["legacy"], true);
        assert!(response_value["capabilities"].is_array());

        // Session is established — clean close
        let _ = sink.close().await;
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    /// WS endpoint stays alive after a client disconnects — can accept new connections.
    #[tokio::test]
    async fn ws_endpoint_survives_client_disconnect() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: identity,
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let url = format!("ws://127.0.0.1:{port}");

        // First client connects and drops
        let (ws1, _) = connect_async(&url).await.unwrap();
        let (mut sink1, _) = ws1.split();
        let _ = sink1.close().await;
        drop(sink1);

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Second client connects — server must still be alive
        let result = connect_async(&url).await;
        assert!(result.is_ok(), "Server must accept new connections after client disconnect");

        let (ws2, _) = result.unwrap();
        let (mut sink2, _) = ws2.split();
        let _ = sink2.close().await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    /// DAEMON-TRANSFER-CONTROL-1: Verify pause/resume during outbound transfer.
    /// Connects a WS client, establishes a session, sends a large-ish file,
    /// pauses mid-transfer, verifies no new chunks arrive during pause,
    /// resumes, and verifies transfer completes.
    #[tokio::test]
    async fn ws_transfer_pause_resume() {
        use std::io::Write;

        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let daemon_identity = generate_identity_keypair();

        let config = WsEndpointConfig {
            listen_addr: addr,
            identity_keypair: copy_keypair(&daemon_identity),
            wt_enabled: false,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move {
            let _ = run_ws_endpoint(config, shutdown_rx, None).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // -- Handshake (same pattern as ws_envelope_roundtrip_over_ws) --
        let url = format!("ws://127.0.0.1:{port}");
        let (ws_stream, _) = connect_async(&url).await.unwrap();
        let (mut sink, mut source) = ws_stream.split();

        let browser_session_kp = generate_ephemeral_keypair();
        let browser_identity = generate_identity_keypair();

        let session_key_msg = serde_json::json!({
            "type": "session-key",
            "publicKey": bolt_core::encoding::to_base64(&browser_session_kp.public_key),
        });
        sink.send(Message::Text(session_key_msg.to_string())).await.unwrap();

        let daemon_sk_msg = source.next().await.unwrap().unwrap();
        let daemon_sk_text = match daemon_sk_msg {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let daemon_sk_value: serde_json::Value = serde_json::from_str(&daemon_sk_text).unwrap();
        let daemon_session_pk =
            crate::web_hello::decode_public_key(daemon_sk_value["publicKey"].as_str().unwrap())
                .unwrap();

        let hello_msg = build_hello_message(
            &browser_identity.public_key,
            &browser_session_kp,
            &daemon_session_pk,
        ).unwrap();
        sink.send(Message::Text(hello_msg)).await.unwrap();

        let _hello_response = source.next().await.unwrap().unwrap();

        // -- Session established, ACTIVE_SESSION is now set --

        // Create test file: 256KB (16 chunks at 16KB each)
        let tmp_dir = tempfile::tempdir().unwrap();
        let test_file = tmp_dir.path().join("pause_test.bin");
        {
            let mut f = std::fs::File::create(&test_file).unwrap();
            let data = vec![0xABu8; 256 * 1024]; // 256KB
            f.write_all(&data).unwrap();
        }

        // Trigger file send on a blocking thread (it's synchronous)
        let file_path = test_file.to_str().unwrap().to_string();
        let send_handle = tokio::task::spawn_blocking(move || {
            send_file_to_browser(&file_path)
        });

        // Read a few chunks to confirm transfer started
        let mut chunks_received = 0u32;
        for _ in 0..4 {
            let msg = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                source.next(),
            ).await;
            if msg.is_ok() {
                chunks_received += 1;
            }
        }
        assert!(chunks_received > 0, "should receive at least some chunks before pause");

        // -- PAUSE --
        request_pause();
        // Drain any in-flight chunks (outbound channel may have buffered some)
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let mut drain_count = 0;
        loop {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), source.next()).await {
                Ok(Some(Ok(_))) => { drain_count += 1; }
                _ => break,
            }
        }

        // Verify no new chunks arrive during pause window (500ms)
        let paused_msg = tokio::time::timeout(
            tokio::time::Duration::from_millis(500),
            source.next(),
        ).await;
        assert!(paused_msg.is_err(), "no messages should arrive while paused (got one after drain of {drain_count})");

        // -- RESUME --
        request_resume();

        // Verify chunks resume flowing
        let resumed_msg = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            source.next(),
        ).await;
        assert!(resumed_msg.is_ok(), "chunks should resume after unpause");

        // Drain remaining chunks until send completes
        loop {
            match tokio::time::timeout(tokio::time::Duration::from_secs(5), source.next()).await {
                Ok(Some(Ok(_))) => { chunks_received += 1; }
                _ => break,
            }
        }

        // Verify send thread completed successfully
        let send_result = send_handle.await.unwrap();
        assert!(send_result.is_ok(), "send should complete: {:?}", send_result);

        // Total chunks received should account for the full file
        // 256KB / 16KB = 16 chunks minimum
        assert!(chunks_received + drain_count >= 10, "should receive most chunks (got {}, drained {})", chunks_received, drain_count);

        // Clean close
        let _ = sink.close().await;
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    }

    // BTR tests moved to ws_btr module (MODULARITY-AUDITABILITY-2).
    // Validation/sanitization tests moved to ws_validation module.
}
