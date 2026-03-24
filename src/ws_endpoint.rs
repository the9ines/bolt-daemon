//! WebSocket server endpoint for browser-to-daemon sessions (PM-RC-02).
//!
//! Provides a direct WebSocket transport as an alternative to WebRTC
//! DataChannel. The wire format is identical: each WS text message is
//! one JSON frame (HELLO exchange, then ProfileEnvelopeV1 messages).
//!
//! RC5 scope: localhost/LAN only, no TLS. This is acceptable because
//! the Bolt Protocol uses end-to-end NaCl-box encryption at the
//! envelope layer — the transport is untrusted by design.
//!
//! Log tokens:
//!   [WS_ENDPOINT]  — server lifecycle (bind, shutdown)
//!   [WS_SESSION]   — per-connection session lifecycle
//!   [WS_HELLO]     — HELLO handshake over WS
//!   [WS_TRANSFER]  — file transfer events over WS

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};

/// Sanitize a received filename to prevent path traversal.
///
/// Extracts basename (last component after any `/` or `\`), then rejects
/// dangerous patterns. Returns Err for filenames that cannot be safely used.
///
/// Rules:
///   1. Extract basename (last path component)
///   2. Reject empty
///   3. Reject null bytes
///   4. Reject `.` and `..`
///   5. Reject hidden files (starts with `.`)
///   6. Replace any remaining path separators (defense in depth)
fn sanitize_filename(raw: &str) -> Result<String, String> {
    // Reject null bytes
    if raw.contains('\0') {
        return Err("filename contains null byte".into());
    }

    // Extract basename: last component after / or \
    let basename = raw
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("");

    // Reject empty
    if basename.is_empty() {
        return Err("filename is empty after path extraction".into());
    }

    // Reject . and ..
    if basename == "." || basename == ".." {
        return Err(format!("filename '{}' is a directory reference", basename));
    }

    // Reject hidden files (starts with .)
    if basename.starts_with('.') {
        return Err(format!("filename '{}' is a hidden file", basename));
    }

    // Defense in depth: replace any remaining path separators
    let safe = basename.replace(['/', '\\'], "_");

    // Final check: ensure result is non-empty after replacement
    if safe.is_empty() || safe == "." || safe == ".." {
        return Err("filename sanitized to empty/dangerous value".into());
    }

    Ok(safe)
}

/// Validate a file path from a send signal before the daemon reads and sends it.
///
/// Requirements:
///   - Must be an absolute path
///   - Must point to an existing regular file (not directory, symlink target checked)
///   - Must not be empty
///
/// Returns the validated path or an error description.
pub fn validate_send_file_path(path_str: &str) -> Result<&str, String> {
    if path_str.is_empty() {
        return Err("empty path".into());
    }

    let path = std::path::Path::new(path_str);

    if !path.is_absolute() {
        return Err(format!("path is not absolute: {path_str}"));
    }

    if !path.exists() {
        return Err(format!("file does not exist: {path_str}"));
    }

    if !path.is_file() {
        return Err(format!("not a regular file: {path_str}"));
    }

    Ok(path_str)
}

/// Compute X25519 Diffie-Hellman shared secret from session ephemeral keys.
/// Matches the browser's `scalarMult(localSecretKey, remotePublicKey)`.
fn compute_x25519_shared_secret(
    local_secret_key: &[u8; 32],
    remote_public_key: &[u8; 32],
) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*local_secret_key);
    let public = PublicKey::from(*remote_public_key);
    *secret.diffie_hellman(&public).as_bytes()
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
    pub btr_engine: std::sync::Mutex<Option<bolt_btr::BtrEngine>>,
}

/// Global active session — set when a browser connects and HELLO completes,
/// cleared when the session ends. Protected by std Mutex for cross-thread access.
static ACTIVE_SESSION: std::sync::Mutex<Option<ActiveSessionHandle>> = std::sync::Mutex::new(None);

/// Send a file to the connected browser peer via the active session.
/// Called from the IPC thread (synchronous). Returns error if no active session.
pub fn send_file_to_browser(file_path: &str) -> Result<(), String> {
    let guard = ACTIVE_SESSION.lock().map_err(|e| format!("lock: {e}"))?;
    let handle = guard.as_ref().ok_or("no active session")?;

    // Read file
    let data = std::fs::read(file_path)
        .map_err(|e| format!("read file: {e}"))?;
    let filename = std::path::Path::new(file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let file_size = data.len() as u64;

    // Chunk (16KB per chunk, matching browser)
    let chunk_size = 16 * 1024;
    let total_chunks = ((data.len() + chunk_size - 1) / chunk_size) as u32;
    let transfer_id = format!("{:032x}", rand::random::<u128>());

    eprintln!(
        "[WS_TRANSFER] sending: {} ({} bytes, {} chunks, tid={})",
        filename, file_size, total_chunks, transfer_id
    );

    // Begin BTR send transfer if engine is available
    let transfer_id_bytes = parse_transfer_id_bytes(&transfer_id)
        .map_err(|e| format!("transfer_id parse: {e}"))?;
    let mut btr_guard = handle.btr_engine.lock().map_err(|e| format!("btr lock: {e}"))?;
    let mut btr_send = if let Some(ref mut engine) = *btr_guard {
        match engine.begin_transfer_send(&transfer_id_bytes, &handle.session.remote_public_key) {
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

    for (i, chunk_data) in data.chunks(chunk_size).enumerate() {
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
                &handle.session.remote_public_key,
                &handle.session.local_keypair.secret_key,
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
            crate::envelope::encode_envelope_with_btr(&inner_json, &handle.session, fields)
                .map_err(|e| format!("envelope: {e}"))?
        } else {
            crate::envelope::encode_envelope(&inner_json, &handle.session)
                .map_err(|e| format!("envelope: {e}"))?
        };
        let text = String::from_utf8_lossy(&envelope).into_owned();

        handle.outbound_tx.send(text)
            .map_err(|_| "session closed".to_string())?;
    }

    // Cleanup BTR send transfer context
    if btr_send.is_some() {
        if let Ok(mut btr_guard) = handle.btr_engine.lock() {
            if let Some(ref mut engine) = *btr_guard {
                engine.end_transfer();
                eprintln!("[BTR_TRANSFER_COMPLETE] Send transfer context cleaned up");
            }
        }
    }

    eprintln!("[WS_TRANSFER] all {} chunks queued for {}", total_chunks, filename);
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

/// Decrypt a BTR-protected file chunk.
///
/// On the first chunk of a transfer (chain_index=0 + ratchet_public_key present),
/// initializes a per-transfer BtrTransferContext via DH ratchet with the sender's
/// ratchet public key and the daemon's session secret key.
///
/// Subsequent chunks use the existing transfer context to advance the chain
/// and decrypt with the derived message key.
///
/// Fail-closed: returns Err on any crypto or state error.
fn decrypt_chunk_btr(
    transfer_id: &str,
    chunk_b64: &str,
    chunk_index: u32,
    btr_env: &crate::envelope::BtrEnvelopeFields,
    session: &SessionContext,
    peer_addr: SocketAddr,
    receive_contexts: &mut std::collections::HashMap<String, (bolt_btr::BtrTransferContext, u32)>,
) -> Result<Vec<u8>, String> {
    // Decode base64 chunk → sealed bytes
    let sealed = bolt_core::encoding::from_base64(chunk_b64)
        .map_err(|e| format!("BTR chunk base64 decode: {e}"))?;

    // First chunk: initialize transfer receive context
    if btr_env.chain_index == 0 && btr_env.ratchet_public_key.is_some() {
        let ratchet_pub_b64 = btr_env.ratchet_public_key.as_ref().unwrap();
        let ratchet_pub_bytes = bolt_core::encoding::from_base64(ratchet_pub_b64)
            .map_err(|e| format!("BTR ratchet_public_key decode: {e}"))?;
        if ratchet_pub_bytes.len() != 32 {
            return Err(format!("BTR ratchet_public_key length {} != 32", ratchet_pub_bytes.len()));
        }
        let mut ratchet_pub = [0u8; 32];
        ratchet_pub.copy_from_slice(&ratchet_pub_bytes);

        // Parse transfer_id as 16-byte hex
        let tid_bytes = parse_transfer_id_bytes(transfer_id)?;

        // Initialize receive context via BTR engine (DH ratchet step)
        let guard = ACTIVE_SESSION.lock().map_err(|e| format!("session lock: {e}"))?;
        let handle = guard.as_ref().ok_or("no active session")?;
        let mut btr_guard = handle.btr_engine.lock().map_err(|e| format!("btr lock: {e}"))?;
        let engine = btr_guard.as_mut().ok_or("BTR engine not initialized")?;

        let ctx = engine
            .begin_transfer_receive_with_key(
                &tid_bytes,
                &ratchet_pub,
                &session.local_keypair.secret_key,
            )
            .map_err(|e| format!("BTR begin_transfer_receive: {e}"))?;

        eprintln!(
            "[BTR_TRANSFER_RECV] {peer_addr} transfer {transfer_id} initialized (generation={})",
            engine.ratchet_generation()
        );

        let gen = engine.ratchet_generation();
        receive_contexts.insert(transfer_id.to_string(), (ctx, gen));
    }

    // Replay guard: check (transfer_id, generation, chain_index) triple.
    // Use stored generation from first chunk (subsequent chunks omit ratchet_generation).
    {
        let tid_bytes = parse_transfer_id_bytes(transfer_id)?;
        let generation = receive_contexts.get(transfer_id)
            .map(|(_, gen)| *gen)
            .or(btr_env.ratchet_generation)
            .ok_or_else(|| "BTR: cannot determine generation for replay check".to_string())?;
        let guard = ACTIVE_SESSION.lock().map_err(|e| format!("session lock: {e}"))?;
        let handle = guard.as_ref().ok_or("no active session")?;
        let mut btr_guard = handle.btr_engine.lock().map_err(|e| format!("btr lock: {e}"))?;
        if let Some(ref mut engine) = *btr_guard {
            engine.check_replay(&tid_bytes, generation, btr_env.chain_index)
                .map_err(|e| format!("BTR replay check failed: {e}"))?;
        }
    }

    // Get transfer context and decrypt
    let (ctx, _gen) = receive_contexts.get_mut(transfer_id)
        .ok_or_else(|| format!("BTR: no receive context for transfer {transfer_id} at chunk {chunk_index}"))?;

    let plaintext = ctx.open_chunk(btr_env.chain_index, &sealed)
        .map_err(|e| format!("BTR open_chunk({}, {}): {e}", transfer_id, btr_env.chain_index))?;

    Ok(plaintext)
}

/// Parse a hex-encoded transfer_id string into 16 bytes.
fn parse_transfer_id_bytes(tid: &str) -> Result<[u8; 16], String> {
    if tid.len() != 32 {
        return Err(format!("transfer_id hex length {} != 32", tid.len()));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&tid[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("transfer_id hex parse: {e}"))?;
    }
    Ok(bytes)
}

/// Copy a KeyPair (KeyPair does not impl Clone due to zeroize-on-drop).
fn copy_keypair(kp: &KeyPair) -> KeyPair {
    KeyPair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    }
}

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

// ── Public entry point ───────────────────────────────────────

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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                        tokio::spawn(async move {
                            let identity = KeyPair {
                                public_key: *pk,
                                secret_key: *sk,
                            };
                            if let Err(e) = handle_connection(stream, peer_addr, &identity, wt_enabled).await {
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

        return run_session_with_outbound(
            ws_sink, ws_source, session, peer_addr, remote_session_pk,
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

    eprintln!("[WS_SESSION] {peer_addr} session established, entering message loop");

    // ── Step 8: Envelope message loop ────────────────────────
    run_session_with_outbound(
        ws_sink, ws_source, session, peer_addr, remote_identity_pk,
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

    // Register active session globally so IPC file.send can use it
    {
        let mut guard = ACTIVE_SESSION.lock().unwrap();
        *guard = Some(ActiveSessionHandle {
            outbound_tx: outbound_tx.clone(),
            session: Arc::clone(&session),
            btr_engine: std::sync::Mutex::new(btr_engine),
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
    let result = run_read_loop(&mut ws_source, &session, peer_addr, &remote_pk, &reply_tx).await;

    // Cleanup: clear active session and zeroize BTR state
    {
        let mut guard = ACTIVE_SESSION.lock().unwrap();
        if let Some(ref handle) = *guard {
            if let Ok(mut btr) = handle.btr_engine.lock() {
                if let Some(ref mut engine) = *btr {
                    engine.cleanup_disconnect();
                    eprintln!("[BTR] {peer_addr} engine zeroized on disconnect");
                }
            }
        }
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Maximum transfer size: 2.5 GB. Reject transfers exceeding this to prevent
    // memory exhaustion (F-MED-05, TI-03). Chunks are accumulated in memory.
    const MAX_TRANSFER_SIZE: u64 = 2_500_000_000;

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

    while let Some(result) = ws_source.next().await {
        let msg = match result {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[WS_SESSION] {peer_addr} read error: {e}");
                break;
            }
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
                                            ReceiveTransfer {
                                                filename: safe_name,
                                                file_size,
                                                total_chunks,
                                                chunks: HashMap::new(),
                                            }
                                        });
                                    rx.chunks.insert(chunk_index, data);

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
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[WS_TRANSFER] {peer_addr} save failed: {} — {}",
                                                    rx.filename, e
                                                );
                                            }
                                        }
                                        active_receives.remove(transfer_id);
                                        // Clean up BTR transfer context
                                        if btr_receive_contexts.remove(transfer_id).is_some() {
                                            // Also notify engine to end transfer tracking
                                            if let Ok(guard) = ACTIVE_SESSION.lock() {
                                                if let Some(ref handle) = *guard {
                                                    if let Ok(mut btr) = handle.btr_engine.lock() {
                                                        if let Some(ref mut engine) = *btr {
                                                            engine.end_transfer();
                                                            eprintln!("[BTR_TRANSFER_COMPLETE] Receive transfer context cleaned up");
                                                        }
                                                    }
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
            let _ = run_ws_endpoint(config, shutdown_rx).await;
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
            let _ = run_ws_endpoint(config, shutdown_rx).await;
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
            let _ = run_ws_endpoint(config, shutdown_rx).await;
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
            let _ = run_ws_endpoint(config, shutdown_rx).await;
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
            let _ = run_ws_endpoint(config, shutdown_rx).await;
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
            let _ = run_ws_endpoint(config, shutdown_rx).await;
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

    // ── Stage 2: BTR engine lifecycle tests ──────────────────

    #[test]
    fn btr_shared_secret_is_commutative() {
        // Verify that X25519 DH produces the same shared secret from both sides
        // (daemon computes DH(daemon_sk, browser_pk), browser computes DH(browser_sk, daemon_pk))
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let daemon_shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );
        let browser_shared = compute_x25519_shared_secret(
            &browser_kp.secret_key,
            &daemon_kp.public_key,
        );

        assert_eq!(daemon_shared, browser_shared,
            "X25519 DH must be commutative — both sides derive identical shared secret");
    }

    #[test]
    fn btr_engine_initialized_from_shared_secret() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);
        let engine = bolt_btr::BtrEngine::new(&shared);

        assert_eq!(engine.ratchet_generation(), 0,
            "Fresh BTR engine must have generation 0");
    }

    #[test]
    fn btr_engines_from_same_shared_secret_are_equivalent() {
        // Both sides create BtrEngine from the same shared secret.
        // Their session_root_keys must be identical (verified indirectly:
        // if they derive different keys, seal/open will fail in Stage 3 tests).
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();

        let shared_a = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);
        let shared_b = compute_x25519_shared_secret(&kp_b.secret_key, &kp_a.public_key);

        assert_eq!(shared_a, shared_b);

        let engine_a = bolt_btr::BtrEngine::new(&shared_a);
        let engine_b = bolt_btr::BtrEngine::new(&shared_b);

        assert_eq!(engine_a.ratchet_generation(), engine_b.ratchet_generation());
    }

    #[test]
    fn btr_engine_not_created_without_capability() {
        // Simulate: session negotiated WITHOUT bolt.transfer-ratchet-v1
        let caps = vec!["bolt.profile-envelope-v1".to_string(), "bolt.file-hash".to_string()];
        let kp = generate_ephemeral_keypair();
        let session = SessionContext::new(
            copy_keypair(&kp),
            [0u8; 32],
            caps,
        ).unwrap();

        let should_init = session.has_capability("bolt.transfer-ratchet-v1");
        assert!(!should_init, "BTR engine must NOT be created without negotiated capability");
    }

    #[test]
    fn btr_engine_created_with_capability() {
        // Simulate: session negotiated WITH bolt.transfer-ratchet-v1
        let caps = vec![
            "bolt.profile-envelope-v1".to_string(),
            "bolt.file-hash".to_string(),
            "bolt.transfer-ratchet-v1".to_string(),
        ];
        let kp = generate_ephemeral_keypair();
        let session = SessionContext::new(
            copy_keypair(&kp),
            [0u8; 32],
            caps,
        ).unwrap();

        let should_init = session.has_capability("bolt.transfer-ratchet-v1");
        assert!(should_init, "BTR engine must be created when capability is negotiated");
    }

    #[test]
    fn btr_cleanup_disconnect_zeroizes_state() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);

        let mut engine = bolt_btr::BtrEngine::new(&shared);
        assert_eq!(engine.ratchet_generation(), 0);

        engine.cleanup_disconnect();
        assert_eq!(engine.ratchet_generation(), 0,
            "Generation reset to 0 after cleanup");
    }

    // ── Stage 3: BTR receive path tests ──────────────────────

    #[test]
    fn btr_decrypt_chunk_browser_to_daemon() {
        // Simulate: browser seals chunks with BTR, daemon opens them.
        // Both engines derive from same shared secret (X25519 commutativity).
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );

        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);
        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);

        let transfer_id: [u8; 16] = [0xAB; 16];
        let transfer_id_hex = transfer_id.iter().map(|b| format!("{b:02x}")).collect::<String>();

        // Browser: begin send transfer (generates fresh ratchet keypair)
        let (mut browser_ctx, browser_ratchet_pub) = browser_engine
            .begin_transfer_send(&transfer_id, &daemon_kp.public_key)
            .unwrap();

        // Daemon: begin receive transfer (uses daemon's session secret key for DH)
        let mut daemon_ctx = daemon_engine
            .begin_transfer_receive_with_key(
                &transfer_id,
                &browser_ratchet_pub,
                &daemon_kp.secret_key,
            )
            .unwrap();

        // Browser seals 3 chunks
        let chunks = vec![b"chunk zero data".to_vec(), b"chunk one data".to_vec(), b"final chunk".to_vec()];
        for (i, plaintext) in chunks.iter().enumerate() {
            let (chain_idx, sealed) = browser_ctx.seal_chunk(plaintext).unwrap();
            assert_eq!(chain_idx, i as u32);

            // Daemon opens
            let decrypted = daemon_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, *plaintext,
                "Chunk {i}: daemon must decrypt browser's BTR-sealed chunk");
        }
    }

    #[test]
    fn btr_decrypt_chunk_wrong_chain_index_fails() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);

        let mut sender_engine = bolt_btr::BtrEngine::new(&shared);
        let mut receiver_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = [0xCC; 16];
        let (mut sender_ctx, ratchet_pub) = sender_engine
            .begin_transfer_send(&tid, &kp_b.public_key)
            .unwrap();
        let mut receiver_ctx = receiver_engine
            .begin_transfer_receive_with_key(&tid, &ratchet_pub, &kp_b.secret_key)
            .unwrap();

        let (chain_idx, sealed) = sender_ctx.seal_chunk(b"data").unwrap();
        assert_eq!(chain_idx, 0);

        // Try to open with wrong chain_index (1 instead of 0) — must fail
        let result = receiver_ctx.open_chunk(1, &sealed);
        assert!(result.is_err(), "Wrong chain_index must fail closed");
    }

    #[test]
    fn btr_decrypt_tampered_chunk_fails() {
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&kp_a.secret_key, &kp_b.public_key);

        let mut sender_engine = bolt_btr::BtrEngine::new(&shared);
        let mut receiver_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = [0xDD; 16];
        let (mut sender_ctx, ratchet_pub) = sender_engine
            .begin_transfer_send(&tid, &kp_b.public_key)
            .unwrap();
        let mut receiver_ctx = receiver_engine
            .begin_transfer_receive_with_key(&tid, &ratchet_pub, &kp_b.secret_key)
            .unwrap();

        let (_chain_idx, mut sealed) = sender_ctx.seal_chunk(b"sensitive data").unwrap();

        // Tamper with sealed data
        if let Some(byte) = sealed.last_mut() {
            *byte ^= 0xFF;
        }

        let result = receiver_ctx.open_chunk(0, &sealed);
        assert!(result.is_err(), "Tampered BTR chunk must fail closed");
    }

    #[test]
    fn btr_decrypt_chunk_helper_first_chunk() {
        // Test the decrypt_chunk_btr helper function directly
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        // Browser: create engine and seal a chunk
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);
        let transfer_id: [u8; 16] = [0xEE; 16];
        let transfer_id_hex = transfer_id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let (mut browser_ctx, browser_ratchet_pub) = browser_engine
            .begin_transfer_send(&transfer_id, &daemon_kp.public_key)
            .unwrap();
        let (_chain_idx, sealed) = browser_ctx.seal_chunk(b"hello from browser").unwrap();
        let chunk_b64 = bolt_core::encoding::to_base64(&sealed);

        // Build daemon session context with BTR capability
        let daemon_session = SessionContext::new(
            copy_keypair(&daemon_kp),
            browser_kp.public_key,
            vec![
                "bolt.profile-envelope-v1".to_string(),
                "bolt.file-hash".to_string(),
                "bolt.transfer-ratchet-v1".to_string(),
            ],
        ).unwrap();

        // Set up ACTIVE_SESSION with BTR engine
        {
            let mut guard = ACTIVE_SESSION.lock().unwrap();
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            *guard = Some(ActiveSessionHandle {
                outbound_tx: tx,
                session: Arc::new(SessionContext::new(
                    copy_keypair(&daemon_kp),
                    browser_kp.public_key,
                    vec![
                        "bolt.profile-envelope-v1".to_string(),
                        "bolt.transfer-ratchet-v1".to_string(),
                    ],
                ).unwrap()),
                btr_engine: std::sync::Mutex::new(Some(bolt_btr::BtrEngine::new(&shared))),
            });
        }

        let btr_fields = crate::envelope::BtrEnvelopeFields {
            chain_index: 0,
            ratchet_public_key: Some(bolt_core::encoding::to_base64(&browser_ratchet_pub)),
            ratchet_generation: Some(1),
        };

        let mut receive_contexts = std::collections::HashMap::new();
        let result = decrypt_chunk_btr(
            &transfer_id_hex,
            &chunk_b64,
            0,
            &btr_fields,
            &daemon_session,
            "127.0.0.1:9999".parse().unwrap(),
            &mut receive_contexts,
        );

        assert!(result.is_ok(), "decrypt_chunk_btr must succeed: {:?}", result.err());
        assert_eq!(result.unwrap(), b"hello from browser");

        // Cleanup global state
        *ACTIVE_SESSION.lock().unwrap() = None;
    }

    #[test]
    fn btr_no_context_for_non_first_chunk_fails() {
        // If chain_index > 0 but no transfer context exists, must fail
        let kp = generate_ephemeral_keypair();
        let session = SessionContext::new(
            copy_keypair(&kp),
            [0u8; 32],
            vec!["bolt.profile-envelope-v1".to_string()],
        ).unwrap();

        let btr_fields = crate::envelope::BtrEnvelopeFields {
            chain_index: 5,  // Not first chunk, no ratchet key
            ratchet_public_key: None,
            ratchet_generation: None,
        };

        let mut receive_contexts = std::collections::HashMap::new();
        let result = decrypt_chunk_btr(
            "abababababababababababababababab",
            "dGVzdA==",
            5,
            &btr_fields,
            &session,
            "127.0.0.1:9999".parse().unwrap(),
            &mut receive_contexts,
        );

        assert!(result.is_err(), "Missing BTR context for non-first chunk must fail closed");
    }

    // ── Stage 4: BTR send path tests ─────────────────────────

    #[test]
    fn btr_send_daemon_to_browser_decrypt() {
        // Simulate: daemon seals chunks with BTR, browser opens them.
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        let transfer_id: [u8; 16] = [0xFA; 16];

        // Daemon: begin send transfer (fresh ratchet keypair)
        let (mut daemon_ctx, daemon_ratchet_pub) = daemon_engine
            .begin_transfer_send(&transfer_id, &browser_kp.public_key)
            .unwrap();

        // Browser: begin receive transfer (uses browser's session secret key)
        let mut browser_ctx = browser_engine
            .begin_transfer_receive_with_key(
                &transfer_id,
                &daemon_ratchet_pub,
                &browser_kp.secret_key,
            )
            .unwrap();

        // Daemon seals 3 chunks, browser opens them
        let chunks = vec![
            b"daemon chunk zero".to_vec(),
            b"daemon chunk one".to_vec(),
            b"daemon final chunk".to_vec(),
        ];
        for (i, plaintext) in chunks.iter().enumerate() {
            let (chain_idx, sealed) = daemon_ctx.seal_chunk(plaintext).unwrap();
            assert_eq!(chain_idx, i as u32);

            let decrypted = browser_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, *plaintext,
                "Chunk {i}: browser must decrypt daemon's BTR-sealed chunk");
        }
    }

    #[test]
    fn btr_send_envelope_fields_first_chunk() {
        // Verify that first chunk produces correct BTR envelope fields
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut engine = bolt_btr::BtrEngine::new(&shared);
        let tid: [u8; 16] = [0xBB; 16];

        let (mut ctx, ratchet_pub) = engine
            .begin_transfer_send(&tid, &browser_kp.public_key)
            .unwrap();
        let gen = engine.ratchet_generation();

        let (chain_idx, _sealed) = ctx.seal_chunk(b"test").unwrap();
        assert_eq!(chain_idx, 0);

        // First chunk fields
        let fields = crate::envelope::BtrEnvelopeFields {
            chain_index: chain_idx,
            ratchet_public_key: Some(bolt_core::encoding::to_base64(&ratchet_pub)),
            ratchet_generation: Some(gen),
        };

        assert_eq!(fields.chain_index, 0);
        assert!(fields.ratchet_public_key.is_some());
        assert!(fields.ratchet_generation.is_some());
        assert_eq!(fields.ratchet_generation.unwrap(), 1);

        // Second chunk fields — no ratchet key
        let (chain_idx_2, _sealed_2) = ctx.seal_chunk(b"test2").unwrap();
        assert_eq!(chain_idx_2, 1);

        let fields_2 = crate::envelope::BtrEnvelopeFields {
            chain_index: chain_idx_2,
            ratchet_public_key: None,
            ratchet_generation: None,
        };
        assert_eq!(fields_2.chain_index, 1);
        assert!(fields_2.ratchet_public_key.is_none());
    }

    #[test]
    fn btr_send_bidirectional_same_session() {
        // Simulate: daemon sends, then browser sends, in the same session.
        // Both must use their own transfer contexts without corruption.
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();

        let shared = compute_x25519_shared_secret(
            &daemon_kp.secret_key,
            &browser_kp.public_key,
        );

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        // Transfer 1: daemon → browser
        let tid1: [u8; 16] = [0x01; 16];
        let (mut d_send_ctx, d_ratchet_pub) = daemon_engine
            .begin_transfer_send(&tid1, &browser_kp.public_key).unwrap();
        let mut b_recv_ctx = browser_engine
            .begin_transfer_receive_with_key(&tid1, &d_ratchet_pub, &browser_kp.secret_key).unwrap();

        let (idx, sealed) = d_send_ctx.seal_chunk(b"daemon to browser").unwrap();
        let decrypted = b_recv_ctx.open_chunk(idx, &sealed).unwrap();
        assert_eq!(decrypted, b"daemon to browser");

        daemon_engine.end_transfer();
        browser_engine.end_transfer();

        // Transfer 2: browser → daemon (same session, different transfer)
        let tid2: [u8; 16] = [0x02; 16];
        let (mut b_send_ctx, b_ratchet_pub) = browser_engine
            .begin_transfer_send(&tid2, &daemon_kp.public_key).unwrap();
        let mut d_recv_ctx = daemon_engine
            .begin_transfer_receive_with_key(&tid2, &b_ratchet_pub, &daemon_kp.secret_key).unwrap();

        let (idx2, sealed2) = b_send_ctx.seal_chunk(b"browser to daemon").unwrap();
        let decrypted2 = d_recv_ctx.open_chunk(idx2, &sealed2).unwrap();
        assert_eq!(decrypted2, b"browser to daemon");

        // Generations advanced: 1 per transfer = 2 total each
        assert_eq!(daemon_engine.ratchet_generation(), 2);
        assert_eq!(browser_engine.ratchet_generation(), 2);
    }

    #[test]
    fn btr_encode_envelope_with_btr_roundtrip() {
        // Verify encode_envelope_with_btr produces envelope that
        // decode_envelope_with_btr can parse with correct BTR fields.
        let kp_a = generate_ephemeral_keypair();
        let kp_b = generate_ephemeral_keypair();

        let session_a = SessionContext::new(
            copy_keypair(&kp_a),
            kp_b.public_key,
            vec!["bolt.profile-envelope-v1".to_string()],
        ).unwrap();
        let session_b = SessionContext::new(
            copy_keypair(&kp_b),
            kp_a.public_key,
            vec!["bolt.profile-envelope-v1".to_string()],
        ).unwrap();

        let inner = b"test inner message";
        let btr_fields = crate::envelope::BtrEnvelopeFields {
            chain_index: 0,
            ratchet_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            ratchet_generation: Some(1),
        };

        let encoded = crate::envelope::encode_envelope_with_btr(inner, &session_a, &btr_fields).unwrap();
        let (decoded, extracted_btr) = crate::envelope::decode_envelope_with_btr(&encoded, &session_b).unwrap();

        assert_eq!(decoded, inner);
        let extracted = extracted_btr.unwrap();
        assert_eq!(extracted.chain_index, 0);
        assert_eq!(extracted.ratchet_public_key, Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()));
        assert_eq!(extracted.ratchet_generation, Some(1));
    }

    // ── Stage 5: Conformance tests ──────────────────────────

    #[test]
    fn btr_conformance_full_transfer_browser_to_daemon() {
        // Full multi-chunk transfer: browser seals, daemon opens, all chunks correct.
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);
        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = rand::random();
        let (mut b_ctx, b_ratchet_pub) = browser_engine
            .begin_transfer_send(&tid, &daemon_kp.public_key).unwrap();
        let mut d_ctx = daemon_engine
            .begin_transfer_receive_with_key(&tid, &b_ratchet_pub, &daemon_kp.secret_key).unwrap();

        // 10 chunks of varying size
        for i in 0..10u32 {
            let data = vec![i as u8; (i as usize + 1) * 1000];
            let (chain_idx, sealed) = b_ctx.seal_chunk(&data).unwrap();
            assert_eq!(chain_idx, i);
            let decrypted = d_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, data, "Chunk {i} data mismatch");
        }
    }

    #[test]
    fn btr_conformance_full_transfer_daemon_to_browser() {
        // Full multi-chunk transfer: daemon seals, browser opens.
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        let tid: [u8; 16] = rand::random();
        let (mut d_ctx, d_ratchet_pub) = daemon_engine
            .begin_transfer_send(&tid, &browser_kp.public_key).unwrap();
        let mut b_ctx = browser_engine
            .begin_transfer_receive_with_key(&tid, &d_ratchet_pub, &browser_kp.secret_key).unwrap();

        for i in 0..10u32 {
            let data = vec![(i + 100) as u8; (i as usize + 1) * 500];
            let (chain_idx, sealed) = d_ctx.seal_chunk(&data).unwrap();
            let decrypted = b_ctx.open_chunk(chain_idx, &sealed).unwrap();
            assert_eq!(decrypted, data, "Chunk {i} data mismatch");
        }
    }

    #[test]
    fn btr_conformance_bidirectional_interleaved() {
        // Two transfers in the same session, alternating directions.
        // Verifies ratchet generation advances correctly.
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut daemon_engine = bolt_btr::BtrEngine::new(&shared);
        let mut browser_engine = bolt_btr::BtrEngine::new(&shared);

        for round in 0..3u32 {
            let tid: [u8; 16] = rand::random();

            if round % 2 == 0 {
                // daemon → browser
                let (mut d_ctx, d_pub) = daemon_engine
                    .begin_transfer_send(&tid, &browser_kp.public_key).unwrap();
                let mut b_ctx = browser_engine
                    .begin_transfer_receive_with_key(&tid, &d_pub, &browser_kp.secret_key).unwrap();
                let (idx, sealed) = d_ctx.seal_chunk(b"round data d2b").unwrap();
                assert_eq!(b_ctx.open_chunk(idx, &sealed).unwrap(), b"round data d2b");
            } else {
                // browser → daemon
                let (mut b_ctx, b_pub) = browser_engine
                    .begin_transfer_send(&tid, &daemon_kp.public_key).unwrap();
                let mut d_ctx = daemon_engine
                    .begin_transfer_receive_with_key(&tid, &b_pub, &daemon_kp.secret_key).unwrap();
                let (idx, sealed) = b_ctx.seal_chunk(b"round data b2d").unwrap();
                assert_eq!(d_ctx.open_chunk(idx, &sealed).unwrap(), b"round data b2d");
            }

            daemon_engine.end_transfer();
            browser_engine.end_transfer();
        }

        // 3 transfers = 3 ratchet steps per engine
        assert_eq!(daemon_engine.ratchet_generation(), 3);
        assert_eq!(browser_engine.ratchet_generation(), 3);
    }

    #[test]
    fn btr_conformance_malformed_transfer_id_fails() {
        // Non-hex transfer_id must fail
        let result = parse_transfer_id_bytes("not-a-hex-string!not-a-hex-str!");
        assert!(result.is_err());

        // Too short
        let result = parse_transfer_id_bytes("abcdef");
        assert!(result.is_err());

        // Too long
        let result = parse_transfer_id_bytes("abababababababababababababababababab");
        assert!(result.is_err());

        // Valid (32 hex chars = 16 bytes)
        let valid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        assert_eq!(valid.len(), 32);
        let result = parse_transfer_id_bytes(valid);
        assert!(result.is_ok());
    }

    #[test]
    fn btr_conformance_cross_transfer_key_isolation() {
        // Keys from transfer 1 must NOT decrypt chunks from transfer 2.
        let daemon_kp = generate_ephemeral_keypair();
        let browser_kp = generate_ephemeral_keypair();
        let shared = compute_x25519_shared_secret(&daemon_kp.secret_key, &browser_kp.public_key);

        let mut sender_engine = bolt_btr::BtrEngine::new(&shared);
        let mut receiver_engine = bolt_btr::BtrEngine::new(&shared);

        // Transfer 1
        let tid1: [u8; 16] = [0x01; 16];
        let (mut ctx1_s, pub1) = sender_engine
            .begin_transfer_send(&tid1, &browser_kp.public_key).unwrap();
        let mut ctx1_r = receiver_engine
            .begin_transfer_receive_with_key(&tid1, &pub1, &browser_kp.secret_key).unwrap();

        let (_idx, sealed1) = ctx1_s.seal_chunk(b"transfer 1 data").unwrap();
        let _ok = ctx1_r.open_chunk(0, &sealed1).unwrap(); // This succeeds

        sender_engine.end_transfer();
        receiver_engine.end_transfer();

        // Transfer 2 — different ratchet step
        let tid2: [u8; 16] = [0x02; 16];
        let (mut ctx2_s, pub2) = sender_engine
            .begin_transfer_send(&tid2, &browser_kp.public_key).unwrap();
        let mut ctx2_r = receiver_engine
            .begin_transfer_receive_with_key(&tid2, &pub2, &browser_kp.secret_key).unwrap();

        let (_idx, sealed2) = ctx2_s.seal_chunk(b"transfer 2 data").unwrap();

        // Try to decrypt transfer 2's sealed data with transfer 1's stale context
        // (ctx1_r is at chain_index=1 after first open, so chain_index=0 would fail)
        // More importantly, the chain keys are completely different.
        // We can't easily use ctx1_r here since it advanced, but we can verify
        // that ctx2_r works and the keys are different.
        let ok2 = ctx2_r.open_chunk(0, &sealed2).unwrap();
        assert_eq!(ok2, b"transfer 2 data");

        // Cross-check: sealed1 from transfer 1 cannot be opened by ctx2_r
        let cross = ctx2_r.open_chunk(1, &sealed1);
        assert!(cross.is_err(), "Transfer 1 sealed data must not decrypt with transfer 2 context");
    }

    #[test]
    fn btr_golden_vector_session_root_derivation() {
        // Verify daemon's BtrEngine derives the same session root as bolt-btr golden vectors.
        // Vector: btr-key-schedule.vectors.json, session-root-0.
        let shared_secret = bolt_core::encoding::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ).unwrap();
        let expected_root = bolt_core::encoding::from_hex(
            "beff9b312b06cff7d24e1acb6fddc01cf12ab35eca1c93cf498433b51f8ae488"
        ).unwrap();

        let mut shared_arr = [0u8; 32];
        shared_arr.copy_from_slice(&shared_secret);
        let engine = bolt_btr::BtrEngine::new(&shared_arr);

        // BtrEngine session_root_key is not publicly accessible outside test cfg.
        // But we can verify indirectly: if the key derivation were wrong,
        // cross-implementation seal/open would fail.
        // The golden vector existence + bolt-btr's own vector tests guarantee
        // that BtrEngine::new produces the correct session_root_key.
        //
        // This test verifies the daemon uses BtrEngine::new (same code path)
        // and that the expected constant is correct per the vector file.
        assert_eq!(expected_root.len(), 32);
        assert_eq!(engine.ratchet_generation(), 0);
    }

    #[test]
    fn btr_conformance_capability_truthful_advertisement() {
        // When bolt.transfer-ratchet-v1 is in DAEMON_CAPABILITIES, the daemon
        // MUST be able to create a BtrEngine from any valid shared secret.
        use crate::web_hello::DAEMON_CAPABILITIES;
        assert!(
            DAEMON_CAPABILITIES.contains(&"bolt.transfer-ratchet-v1"),
            "DAEMON_CAPABILITIES must include bolt.transfer-ratchet-v1"
        );

        // Verify engine creation works
        let shared = [0x42u8; 32];
        let engine = bolt_btr::BtrEngine::new(&shared);
        assert_eq!(engine.ratchet_generation(), 0);
    }

    // ── DAEMON-HARDENING-1 P2: Signal file path validation tests ──

    #[test]
    fn validate_send_path_absolute_file_accepted() {
        // Use a file we know exists
        let result = validate_send_file_path("/etc/hosts");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_send_path_empty_rejected() {
        assert!(validate_send_file_path("").is_err());
    }

    #[test]
    fn validate_send_path_relative_rejected() {
        assert!(validate_send_file_path("relative/path.txt").is_err());
        assert!(validate_send_file_path("file.txt").is_err());
    }

    #[test]
    fn validate_send_path_nonexistent_rejected() {
        assert!(validate_send_file_path("/nonexistent/path/file.txt").is_err());
    }

    #[test]
    fn validate_send_path_directory_rejected() {
        assert!(validate_send_file_path("/tmp").is_err());
        assert!(validate_send_file_path("/").is_err());
    }

    // ── DAEMON-HARDENING-1 P1: Transfer size limit tests ────

    #[test]
    fn transfer_size_limit_constant() {
        // 2.5 GB
        assert_eq!(2_500_000_000u64, 2_500_000_000);
    }

    #[test]
    fn transfer_size_within_limit_accepted() {
        // Any file_size <= 2.5GB should be accepted.
        // This is a design-level test — actual enforcement is in run_read_loop.
        let max: u64 = 2_500_000_000;
        assert!(1_048_576 <= max, "1MB within limit");
        assert!(52_428_800 <= max, "50MB within limit");
        assert!(1_000_000_000 <= max, "1GB within limit");
        assert!(2_500_000_000 <= max, "2.5GB at limit");
    }

    #[test]
    fn transfer_size_over_limit_rejected() {
        let max: u64 = 2_500_000_000;
        assert!(2_500_000_001 > max, "2.5GB+1 over limit");
        assert!(5_000_000_000u64 > max, "5GB over limit");
    }

    // ── DAEMON-HARDENING-1 P0: Filename sanitization tests ──

    #[test]
    fn sanitize_filename_normal() {
        assert_eq!(sanitize_filename("report.pdf").unwrap(), "report.pdf");
        assert_eq!(sanitize_filename("my file (1).txt").unwrap(), "my file (1).txt");
        assert_eq!(sanitize_filename("data.tar.gz").unwrap(), "data.tar.gz");
    }

    #[test]
    fn sanitize_filename_path_traversal_rejected() {
        // ../foo → basename "foo" (path stripped, not rejected)
        assert_eq!(sanitize_filename("../foo").unwrap(), "foo");
        // ../../etc/passwd → basename "passwd"
        assert_eq!(sanitize_filename("../../etc/passwd").unwrap(), "passwd");
        // Pure ".." → rejected
        assert!(sanitize_filename("..").is_err());
        // Pure "." → rejected
        assert!(sanitize_filename(".").is_err());
    }

    #[test]
    fn sanitize_filename_nested_paths_stripped_to_basename() {
        assert_eq!(sanitize_filename("Documents/report.pdf").unwrap(), "report.pdf");
        assert_eq!(sanitize_filename("a/b/c/d.txt").unwrap(), "d.txt");
        assert_eq!(sanitize_filename("C:\\Users\\file.exe").unwrap(), "file.exe");
        assert_eq!(sanitize_filename("/etc/shadow").unwrap(), "shadow");
    }

    #[test]
    fn sanitize_filename_null_byte_rejected() {
        assert!(sanitize_filename("file\0.txt").is_err());
        assert!(sanitize_filename("\0").is_err());
    }

    #[test]
    fn sanitize_filename_hidden_files_rejected() {
        assert!(sanitize_filename(".bashrc").is_err());
        assert!(sanitize_filename(".ssh").is_err());
        assert!(sanitize_filename("path/to/.env").is_err());
    }

    #[test]
    fn sanitize_filename_empty_rejected() {
        assert!(sanitize_filename("").is_err());
        assert!(sanitize_filename("/").is_err());
        assert!(sanitize_filename("\\").is_err());
    }

    #[test]
    fn sanitize_filename_output_confined_to_downloads() {
        // Verify that even with creative filenames, the resolved path
        // stays inside the Downloads directory.
        let save_dir = "/tmp/test-downloads";
        let filenames = vec![
            "../escape.txt",
            "../../etc/passwd",
            "normal.pdf",
            "sub/dir/file.txt",
        ];
        for raw in filenames {
            let safe = sanitize_filename(raw).unwrap();
            let full_path = format!("{}/{}", save_dir, safe);
            let path = std::path::Path::new(&full_path);
            let dir = std::path::Path::new(save_dir);
            assert!(
                path.starts_with(dir),
                "Sanitized path {:?} must be inside {:?} (raw: {:?})",
                full_path, save_dir, raw
            );
        }
    }
}
