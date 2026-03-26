//! WebTransport server endpoint for browser-to-daemon sessions (WTI2).
//!
//! Provides a WebTransport/HTTP3 transport as an alternative to WebSocket.
//! The wire format over bidirectional streams uses 4-byte big-endian
//! length-prefixed JSON frames (HELLO exchange, then ProfileEnvelopeV1).
//!
//! Requires TLS cert/key PEM files (e.g. from mkcert) since HTTP/3
//! mandates TLS. The Bolt Protocol uses end-to-end NaCl-box encryption
//! at the envelope layer — the transport-level TLS is for HTTP/3 compliance.
//!
//! Log tokens:
//!   [WT_ENDPOINT]  — server lifecycle (bind, shutdown)
//!   [WT_SESSION]   — per-connection session lifecycle
//!   [WT_HELLO]     — HELLO handshake over WebTransport

use std::net::SocketAddr;

use tokio::sync::watch;
use wtransport::endpoint::IncomingSession;
use wtransport::{Connection, Endpoint, Identity, ServerConfig};

use bolt_core::crypto::{generate_ephemeral_keypair, KeyPair};
use bolt_core::session::SessionContext;

use crate::envelope::{build_error_payload, decode_envelope, route_inner_message};
use crate::ws_validation::{sanitize_filename, MAX_TRANSFER_SIZE};
use crate::web_hello::{
    build_hello_message, daemon_capabilities, negotiate_capabilities, parse_hello_typed, HelloError,
};

/// Copy a KeyPair (KeyPair does not impl Clone due to zeroize-on-drop).
fn copy_keypair(kp: &KeyPair) -> KeyPair {
    KeyPair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    }
}

// ── Configuration ────────────────────────────────────────────

/// Configuration for the WebTransport endpoint.
pub struct WtEndpointConfig {
    /// Address to bind the UDP listener on.
    pub listen_addr: SocketAddr,
    /// Persistent identity keypair (long-lived, loaded from store).
    pub identity_keypair: KeyPair,
    /// Path to PEM-encoded TLS certificate chain.
    pub cert_path: String,
    /// Path to PEM-encoded TLS private key.
    pub key_path: String,
}

// ── Framing helpers (4-byte big-endian length prefix) ────────

/// Write a length-prefixed JSON frame to a WebTransport send stream.
async fn write_frame(
    send: &mut wtransport::stream::SendStream,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed JSON frame from a WebTransport recv stream.
/// Returns None on clean stream close. Enforces a 1 MiB max frame size.
async fn read_frame(
    recv: &mut wtransport::stream::RecvStream,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    use wtransport::error::StreamReadExactError;

    const MAX_FRAME: u32 = 1_048_576; // 1 MiB

    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(StreamReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(format!("frame too large: {len} bytes (max {MAX_FRAME})").into());
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

// ── Public entry point ───────────────────────────────────────

/// Run the WebTransport endpoint server.
///
/// Binds a UDP socket, loads TLS identity from PEM files, accepts
/// WebTransport sessions over HTTP/3, and spawns a task per session.
/// Runs until `shutdown_rx` receives `true`.
///
/// Fail-closed: individual session errors are logged and the session
/// is dropped. The server continues accepting new sessions.
pub async fn run_wt_endpoint(
    config: WtEndpointConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load TLS identity from PEM files
    let identity = Identity::load_pemfiles(&config.cert_path, &config.key_path)
        .await
        .map_err(|e| {
            format!(
                "[WT_ENDPOINT] failed to load TLS identity (cert={}, key={}): {e}",
                config.cert_path, config.key_path
            )
        })?;

    let server_config = ServerConfig::builder()
        .with_bind_address(config.listen_addr)
        .with_identity(identity)
        .keep_alive_interval(Some(std::time::Duration::from_secs(10)))
        .max_idle_timeout(Some(std::time::Duration::from_secs(60)))
        .map_err(|e| format!("[WT_ENDPOINT] invalid idle timeout: {e}"))?
        .build();

    let server = Endpoint::server(server_config)
        .map_err(|e| format!("[WT_ENDPOINT] failed to bind: {e}"))?;

    let local_addr = server
        .local_addr()
        .map_err(|e| format!("[WT_ENDPOINT] failed to get local addr: {e}"))?;
    eprintln!("[WT_ENDPOINT] listening on {local_addr}");

    // Store identity key material in an Arc for sharing across tasks.
    let identity_pk = std::sync::Arc::new(config.identity_keypair.public_key);
    let identity_sk = std::sync::Arc::new(config.identity_keypair.secret_key);

    loop {
        tokio::select! {
            incoming = server.accept() => {
                let pk = std::sync::Arc::clone(&identity_pk);
                let sk = std::sync::Arc::clone(&identity_sk);
                tokio::spawn(async move {
                    let identity = KeyPair {
                        public_key: *pk,
                        secret_key: *sk,
                    };
                    if let Err(e) = handle_incoming_session(incoming, &identity).await {
                        eprintln!("[WT_SESSION] error: {e}");
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    eprintln!("[WT_ENDPOINT] shutdown signal received");
                    break;
                }
            }
        }
    }

    eprintln!("[WT_ENDPOINT] stopped");
    Ok(())
}

// ── Per-session handler ──────────────────────────────────────

/// Handle an incoming WebTransport session through the full lifecycle:
/// 1. Accept session request (HTTP/3 CONNECT)
/// 2. Accept bidirectional stream
/// 3. HELLO exchange (ephemeral keypair, capability negotiation)
/// 4. Envelope message loop (decode, route, reply)
async fn handle_incoming_session(
    incoming: IncomingSession,
    identity: &KeyPair,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Step 1: Accept WebTransport session ──────────────────
    let session_request = incoming
        .await
        .map_err(|e| format!("[WT_SESSION] session request failed: {e}"))?;

    let peer_addr = session_request.remote_address();
    eprintln!(
        "[WT_SESSION] {peer_addr} session request: authority={}, path={}",
        session_request.authority(),
        session_request.path(),
    );

    let connection: Connection = session_request
        .accept()
        .await
        .map_err(|e| format!("[WT_SESSION] {peer_addr} accept failed: {e}"))?;
    eprintln!("[WT_SESSION] {peer_addr} session accepted");

    // ── Step 2: Accept bidirectional stream ───────────────────
    let timeout = tokio::time::Duration::from_secs(30);
    let (mut send, mut recv) = tokio::time::timeout(timeout, connection.accept_bi())
        .await
        .map_err(|_| format!("[WT_SESSION] {peer_addr} timeout waiting for bidi stream (30s)"))?
        .map_err(|e| format!("[WT_SESSION] {peer_addr} bidi stream accept failed: {e}"))?;
    eprintln!("[WT_SESSION] {peer_addr} bidi stream opened");

    // ── Step 3: Generate ephemeral session keypair ────────────
    let session_kp = generate_ephemeral_keypair();

    // ── Step 4: Session key exchange ──────────────────────────
    // Send our session public key
    let our_session_key_msg = serde_json::json!({
        "type": "session-key",
        "publicKey": bolt_core::encoding::to_base64(&session_kp.public_key),
    });
    write_frame(&mut send, our_session_key_msg.to_string().as_bytes()).await?;
    eprintln!("[WT_HELLO] {peer_addr} sent session-key");

    // Read first frame from browser
    let first_frame = read_frame_with_timeout(&mut recv, peer_addr).await?;

    // Parse: expect session-key first, then HELLO
    let (remote_session_pk, hello_raw) = {
        let text = String::from_utf8(first_frame)
            .map_err(|_| format!("[WT_HELLO] {peer_addr} first frame is not valid UTF-8"))?;

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| format!("[WT_HELLO] {peer_addr} first frame is not valid JSON"))?;

        if value.get("type").and_then(|v| v.as_str()) == Some("session-key") {
            let remote_pk_b64 = value
                .get("publicKey")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("[WT_HELLO] {peer_addr} session-key missing publicKey"))?;
            let remote_pk = crate::web_hello::decode_public_key(remote_pk_b64)
                .map_err(|e| format!("[WT_HELLO] {peer_addr} invalid session key: {e}"))?;
            eprintln!("[WT_HELLO] {peer_addr} received session-key");

            // Now read the actual HELLO
            let hello_frame = read_frame_with_timeout(&mut recv, peer_addr).await?;
            let hello_text = String::from_utf8(hello_frame)
                .map_err(|_| format!("[WT_HELLO] {peer_addr} HELLO frame is not valid UTF-8"))?;
            (remote_pk, hello_text)
        } else {
            return Err(
                format!("[WT_HELLO] {peer_addr} expected session-key frame before HELLO").into(),
            );
        }
    };

    // ── Step 5: Parse and decrypt HELLO ──────────────────────
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
            eprintln!("[WT_HELLO] {peer_addr} HELLO failed: {e} (code={code})");
            format!("[WT_HELLO] {peer_addr} HELLO validation failed: {e}")
        })?;

    eprintln!(
        "[WT_HELLO] {peer_addr} HELLO ok: identity={}, caps={:?}",
        hello_inner.identity_public_key, hello_inner.capabilities,
    );

    // ── Step 6: Negotiate capabilities ────────────────────────
    let local_caps = daemon_capabilities(true); // WT endpoint always advertises WT
    let negotiated = negotiate_capabilities(&local_caps, &hello_inner.capabilities);
    eprintln!("[WT_HELLO] {peer_addr} negotiated capabilities: {negotiated:?}");

    // ── Step 7: Send HELLO response ──────────────────────────
    let hello_response = build_hello_message(&identity.public_key, &session_kp, &remote_session_pk)
        .map_err(|e| format!("[WT_HELLO] {peer_addr} failed to build HELLO response: {e}"))?;
    write_frame(&mut send, hello_response.as_bytes()).await?;
    eprintln!("[WT_HELLO] {peer_addr} sent HELLO response");

    // ── Step 8: Build session context ─────────────────────────
    let remote_identity_pk = crate::web_hello::decode_public_key(&hello_inner.identity_public_key)
        .map_err(|e| format!("[WT_SESSION] {peer_addr} invalid remote identity key: {e}"))?;

    let session = SessionContext::new(copy_keypair(&session_kp), remote_session_pk, negotiated)
        .map_err(|e| format!("[WT_SESSION] {peer_addr} failed to create session: {e}"))?;

    // Compute SAS verification code (same algorithm as WS endpoint and browser)
    let sas = bolt_core::sas::compute_sas(
        &identity.public_key,
        &remote_identity_pk,
        &session_kp.public_key,
        &remote_session_pk,
    );
    eprintln!("[SAS] {sas}");

    eprintln!("[WT_SESSION] {peer_addr} session established, entering message loop");

    // ── Step 9: Envelope message loop ─────────────────────────
    run_message_loop(
        &mut send,
        &mut recv,
        &session,
        peer_addr,
        &remote_identity_pk,
    )
    .await
}

/// Read a frame with a 30s timeout.
async fn read_frame_with_timeout(
    recv: &mut wtransport::stream::RecvStream,
    peer_addr: SocketAddr,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let timeout = tokio::time::Duration::from_secs(30);
    let frame = tokio::time::timeout(timeout, read_frame(recv))
        .await
        .map_err(|_| format!("[WT_HELLO] {peer_addr} timeout (30s)"))??
        .ok_or_else(|| format!("[WT_HELLO] {peer_addr} stream closed during handshake"))?;
    Ok(frame)
}

/// Post-HELLO envelope message loop.
///
/// Receives encrypted ProfileEnvelopeV1 frames (length-prefixed),
/// decrypts, routes via `route_inner_message`, and sends any reply.
/// Runs until the peer disconnects or a protocol violation occurs.
async fn run_message_loop(
    send: &mut wtransport::stream::SendStream,
    recv: &mut wtransport::stream::RecvStream,
    session: &SessionContext,
    peer_addr: SocketAddr,
    _remote_identity_pk: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::collections::HashMap;

    struct ReceiveTransfer {
        filename: String,
        file_size: u64,
        total_chunks: u32,
        chunks: HashMap<u32, Vec<u8>>,
    }
    let mut active_receives: HashMap<String, ReceiveTransfer> = HashMap::new();

    loop {
        let frame = match read_frame(recv).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                eprintln!("[WT_SESSION] {peer_addr} stream closed cleanly");
                break;
            }
            Err(e) => {
                eprintln!("[WT_SESSION] {peer_addr} read error: {e}");
                break;
            }
        };

        // Decode envelope
        let inner = match decode_envelope(&frame, session) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                eprintln!("[WT_SESSION] {peer_addr} envelope error: {e}");
                let error_payload = build_error_payload(e.code(), &e.to_string(), Some(session));
                let _ = write_frame(send, &error_payload).await;
                break;
            }
        };

        // Route inner message
        match route_inner_message(&inner, session) {
            Ok(Some(reply_bytes)) => {
                if let Err(e) = write_frame(send, &reply_bytes).await {
                    eprintln!("[WT_SESSION] {peer_addr} send error: {e}");
                    break;
                }
            }
            Ok(None) => {
                // Check for file-transfer messages (FileChunk, etc.)
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
                            // Decrypt chunk (static NaCl box — WT path)
                            let data = match bolt_core::crypto::open_box_payload(
                                chunk,
                                &session.remote_public_key,
                                &session.local_keypair.secret_key,
                            ) {
                                Ok(plaintext) => plaintext,
                                Err(e) => {
                                    eprintln!("[WT_TRANSFER] {peer_addr} chunk {chunk_index} decrypt FAILED: {e}");
                                    continue;
                                }
                            };

                            // Reject oversized transfers
                            if !active_receives.contains_key(transfer_id) && file_size > MAX_TRANSFER_SIZE {
                                eprintln!(
                                    "[WT_TRANSFER] {peer_addr} REJECTED: {} ({} bytes) exceeds {} byte limit",
                                    filename, file_size, MAX_TRANSFER_SIZE
                                );
                                continue;
                            }

                            let rx = active_receives
                                .entry(transfer_id.clone())
                                .or_insert_with(|| {
                                    let safe_name = match sanitize_filename(filename) {
                                        Ok(name) => name,
                                        Err(e) => {
                                            eprintln!("[WT_TRANSFER] {peer_addr} REJECTED filename: {e} (raw: {filename:?})");
                                            format!("received_{}", transfer_id)
                                        }
                                    };
                                    eprintln!(
                                        "[WT_TRANSFER] {peer_addr} receiving: {} ({} bytes, {} chunks)",
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

                            // Progress (throttled)
                            let done = rx.chunks.len() as u32;
                            let total = rx.total_chunks;
                            if done == 1 || done == total || done % (total / 20).max(1) == 0 {
                                eprintln!(
                                    "[WT_TRANSFER] {peer_addr} progress: {}/{} chunks ({})",
                                    done, total, rx.filename
                                );
                            }

                            // All chunks received — assemble and save
                            if rx.chunks.len() as u32 >= rx.total_chunks {
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

                                let canonical_dir = std::path::Path::new(&save_dir);
                                let canonical_path = std::path::Path::new(&save_path);
                                if !canonical_path.starts_with(canonical_dir) {
                                    eprintln!(
                                        "[WT_TRANSFER] {peer_addr} PATH ESCAPE BLOCKED: {} resolves outside {}",
                                        save_path, save_dir
                                    );
                                } else {
                                    let _ = std::fs::create_dir_all(&save_dir);
                                    match std::fs::write(&save_path, &file_data) {
                                        Ok(()) => {
                                            eprintln!(
                                                "[WT_TRANSFER] {peer_addr} saved: {} ({} bytes) \u{2192} {}",
                                                rx.filename, file_data.len(), save_path
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "[WT_TRANSFER] {peer_addr} save failed: {} \u{2014} {}",
                                                rx.filename, e
                                            );
                                        }
                                    }
                                }
                                active_receives.remove(transfer_id);
                            }
                        }
                        _ => {} // Other message types (FileOffer, etc.) — ignored for now
                    }
                }
            }
            Err(e) => {
                eprintln!("[WT_SESSION] {peer_addr} route error: {e}");
                let error_payload = build_error_payload(e.code(), &e.to_string(), Some(session));
                let _ = write_frame(send, &error_payload).await;
                break;
            }
        }
    }

    eprintln!("[WT_SESSION] {peer_addr} message loop ended");
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Find an available port by binding to :0.
    async fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn wt_endpoint_starts_with_self_signed_cert() {
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let _identity_kp = bolt_core::identity::generate_identity_keypair();

        // Use self-signed identity for testing (avoids needing PEM files)
        let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let server_config = ServerConfig::builder()
            .with_bind_address(addr)
            .with_identity(wt_identity)
            .build();

        let server = Endpoint::server(server_config);
        assert!(server.is_ok(), "WT server should bind successfully");

        let server = server.unwrap();
        let bound = server.local_addr().unwrap();
        assert_eq!(bound.port(), port);

        // Verify the server is ready to accept (non-blocking check)
        eprintln!("[TEST] WT endpoint bound on {bound}");

        // Clean shutdown — we don't need full session interop here,
        // just proving the server starts and binds correctly.
        drop(server);
    }

    #[tokio::test]
    async fn wt_config_struct_fields() {
        let config = WtEndpointConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            identity_keypair: bolt_core::identity::generate_identity_keypair(),
            cert_path: "/tmp/test-cert.pem".to_string(),
            key_path: "/tmp/test-key.pem".to_string(),
        };
        assert_eq!(config.listen_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(config.cert_path, "/tmp/test-cert.pem");
        assert_eq!(config.key_path, "/tmp/test-key.pem");
    }

    #[tokio::test]
    async fn wt_frame_roundtrip() {
        // Test the length-prefixed framing over an in-process WT connection
        // using self-signed certs.
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let server_config = ServerConfig::builder()
            .with_bind_address(addr)
            .with_identity(wt_identity)
            .build();

        let server = Endpoint::server(server_config).unwrap();
        let bound_addr = server.local_addr().unwrap();

        // Spawn server that accepts one bidi stream, reads one frame, echoes it back
        let server_handle = tokio::spawn(async move {
            let incoming = server.accept().await;
            let req = incoming.await.unwrap();
            let conn = req.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            let frame = read_frame(&mut recv).await.unwrap().unwrap();
            write_frame(&mut send, &frame).await.unwrap();
            send.finish().await.unwrap();
        });

        // Give server a moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Client side: connect with dangerous config (self-signed)
        let client_config = wtransport::ClientConfig::builder()
            .with_bind_default()
            .with_no_cert_validation()
            .build();

        let client = Endpoint::client(client_config).unwrap();
        let url = format!("https://127.0.0.1:{}", bound_addr.port());
        let conn = tokio::time::timeout(tokio::time::Duration::from_secs(5), client.connect(&url))
            .await
            .expect("client connect should not timeout")
            .expect("client connect should succeed");

        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

        // Write a test frame
        let test_payload = b"hello-webtransport";
        write_frame(&mut send, test_payload).await.unwrap();
        send.finish().await.unwrap();

        // Read echoed frame
        let echoed = read_frame(&mut recv).await.unwrap().unwrap();
        assert_eq!(echoed, test_payload);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn wt_endpoint_run_and_shutdown() {
        // Test that run_wt_endpoint can be started and cleanly shut down.
        // We use a temp dir with self-signed PEM files.
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // Generate self-signed cert to PEM files
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");

        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let config = WtEndpointConfig {
            listen_addr: addr,
            identity_keypair: bolt_core::identity::generate_identity_keypair(),
            cert_path: cert_path.to_str().unwrap().to_string(),
            key_path: key_path.to_str().unwrap().to_string(),
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move { run_wt_endpoint(config, shutdown_rx).await });

        // Give server time to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Signal shutdown
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle)
            .await
            .expect("server should shut down within 5s");

        assert!(result.is_ok());
    }
}
