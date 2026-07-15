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

use crate::web_hello::{
    build_hello_message, daemon_capabilities, negotiate_capabilities, parse_hello_typed, HelloError,
};
// TRANSPORT-UNIFY-1 Phase 2: WT routes through the shared session loop; the
// envelope/BTR/transfer machinery is inherited from it, not re-owned here.
use crate::session_loop::{
    enforce_session_trust, run_session_with_outbound, SessionTrustConfig, SessionTrustRole,
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
    /// Session trust policy, same as WS/QUIC. `None` fails closed (EA3 / item 2):
    /// no WT session reaches the shared loop without passing trust enforcement.
    pub trust_config: Option<SessionTrustConfig>,
}

// ── Framing helpers (4-byte big-endian length prefix) ────────

/// Write a length-prefixed JSON frame to a WebTransport send stream.
pub(crate) async fn write_frame(
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
pub(crate) async fn read_frame(
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
    ipc_tx: Option<std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
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
    // Trust policy shared across per-session tasks (EA3: WT is gated like WS/QUIC).
    let trust_config = std::sync::Arc::new(config.trust_config);

    loop {
        tokio::select! {
            incoming = server.accept() => {
                let pk = std::sync::Arc::clone(&identity_pk);
                let sk = std::sync::Arc::clone(&identity_sk);
                let ipc = ipc_tx.clone();
                let trust = std::sync::Arc::clone(&trust_config);
                tokio::spawn(async move {
                    let identity = KeyPair {
                        public_key: *pk,
                        secret_key: *sk,
                    };
                    if let Err(e) =
                        handle_incoming_session(incoming, &identity, ipc, trust.as_ref().clone())
                            .await
                    {
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
    ipc_tx: Option<std::sync::mpsc::Sender<crate::ipc::types::IpcMessage>>,
    trust_config: Option<SessionTrustConfig>,
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

    // ── Trust gate (EA3): WebTransport now passes the SAME enforcement path as
    // WS/QUIC, BEFORE the shared session loop. Fail-closed on a missing trust_config
    // (item 2); Ask/Deny/Allow per the current policy. A denied peer never reaches
    // run_session_with_outbound / transfer handling. Authorization gating only: not
    // verification, pins nothing.
    enforce_session_trust(
        trust_config.as_ref(),
        SessionTrustRole::Answerer,
        "WT_SESSION",
        peer_addr,
        &remote_identity_pk,
    )?;

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

    eprintln!("[WT_SESSION] {peer_addr} session established, entering shared session loop");

    run_session_with_outbound(
        crate::session_frame::WtFrameSink(send),
        crate::session_frame::wt_message_stream(recv),
        session,
        peer_addr,
        remote_identity_pk,
        ipc_tx.as_ref(),
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

    /// Explicit auto-accept trust config for WT session tests that must establish a
    /// session (mirrors `session_loop::auto_accept_trust_config`). `Allow` yields
    /// `AllowOnce`, which never persists. NOT verified/pin behavior.
    fn wt_allow_trust_config() -> SessionTrustConfig {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SessionTrustConfig {
            trust_path: std::env::temp_dir().join(format!(
                "bolt-wt-test-trust-{}-{n}.json",
                std::process::id()
            )),
            pairing_policy: crate::ipc::trust::PairingPolicy::Allow,
        }
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
            trust_config: None,
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
            trust_config: None,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move { run_wt_endpoint(config, shutdown_rx, None).await });

        // Give server time to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Signal shutdown
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle)
            .await
            .expect("server should shut down within 5s");

        assert!(result.is_ok());
    }

    /// TRANSPORT-UNIFY-1 Phase 2 coverage: a real WebTransport client drives
    /// `handle_incoming_session` through the HELLO handshake and sends one encrypted
    /// file chunk. Asserts the daemon emits `transfer.started` + `transfer.complete`
    /// via the threaded `ipc_tx` (the shared read loop) and saves the exact bytes.
    /// The WT twin of `session_loop`'s `quic_session_emits_ipc_transfer_events_*` test;
    /// closes the previously-untested WT post-HELLO session path.
    #[tokio::test]
    async fn wt_session_emits_ipc_transfer_events_on_receive() {
        let _session_guard = crate::session_loop::SESSION_GLOBALS_LOCK.lock().await;
        // ── server: one WT session through handle_incoming_session with a real ipc_tx ──
        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address(addr)
                .with_identity(wt_identity)
                .build(),
        )
        .unwrap();
        let bound = server.local_addr().unwrap();

        let server_identity = generate_ephemeral_keypair();
        let (ipc_tx, ipc_rx) = std::sync::mpsc::channel::<crate::ipc::types::IpcMessage>();
        *crate::session_loop::ACTIVE_SESSION.lock().unwrap() = None;

        let server_handle = tokio::spawn(async move {
            let incoming = server.accept().await;
            let _ = handle_incoming_session(
                incoming,
                &server_identity,
                Some(ipc_tx),
                Some(wt_allow_trust_config()),
            )
            .await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // ── client: connect, run the HELLO handshake, send one encrypted chunk ──
        let client = Endpoint::client(
            wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build(),
        )
        .unwrap();
        let url = format!("https://127.0.0.1:{}", bound.port());
        let conn = client.connect(&url).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

        let client_identity = generate_ephemeral_keypair();
        let client_session_kp = generate_ephemeral_keypair();

        // session-key exchange (both sides send first, then read — stream-buffered)
        let session_key_msg = serde_json::json!({
            "type": "session-key",
            "publicKey": bolt_core::encoding::to_base64(&client_session_kp.public_key),
        });
        write_frame(&mut send, session_key_msg.to_string().as_bytes())
            .await
            .unwrap();
        let server_key_frame = read_frame(&mut recv).await.unwrap().unwrap();
        let server_key_json: serde_json::Value = serde_json::from_slice(&server_key_frame).unwrap();
        let server_session_pk =
            crate::web_hello::decode_public_key(server_key_json["publicKey"].as_str().unwrap())
                .unwrap();

        // HELLO
        let hello_msg = build_hello_message(
            &client_identity.public_key,
            &client_session_kp,
            &server_session_pk,
        )
        .unwrap();
        write_frame(&mut send, hello_msg.as_bytes()).await.unwrap();
        let hello_resp = read_frame(&mut recv).await.unwrap().unwrap();
        let hello_inner =
            parse_hello_typed(&hello_resp, &server_session_pk, &client_session_kp).unwrap();
        let negotiated =
            negotiate_capabilities(&daemon_capabilities(true), &hello_inner.capabilities);
        let client_session = SessionContext::new(
            copy_keypair(&client_session_kp),
            server_session_pk,
            negotiated,
        )
        .unwrap();

        // ── send one encrypted file chunk (daemon receive path over the shared loop) ──
        let filename = format!("wt-ipc-recv-{}.txt", rand::random::<u64>());
        let payload = b"wt ipc receive smoke through the unified session loop";
        let encrypted = bolt_core::crypto::seal_box_payload(
            payload,
            &client_session.remote_public_key,
            &client_session.local_keypair.secret_key,
        )
        .unwrap();
        let chunk = crate::dc_messages::DcMessage::FileChunk {
            transfer_id: format!("{:032x}", rand::random::<u128>()),
            filename: filename.clone(),
            chunk_index: 0,
            total_chunks: 1,
            chunk: encrypted,
            file_size: payload.len() as u64,
            file_hash: None,
        };
        let inner = crate::dc_messages::encode_dc_message(&chunk).unwrap();
        let envelope = crate::envelope::encode_envelope(&inner, &client_session).unwrap();
        write_frame(&mut send, &envelope).await.unwrap();

        // ── assert: transfer.started + transfer.complete over the threaded ipc_tx ──
        let started = wait_for_ipc(&ipc_rx, |m| {
            m.msg_type == "transfer.started"
                && m.payload["direction"] == "receive"
                && m.payload["file_name"] == filename
        })
        .await;
        assert!(
            started.is_some(),
            "WT session must emit transfer.started (receive) via the threaded ipc_tx"
        );
        let complete = wait_for_ipc(&ipc_rx, |m| {
            m.msg_type == "transfer.complete"
                && m.payload["file_name"] == filename
                && m.payload["bytes_transferred"].as_u64() == Some(payload.len() as u64)
        })
        .await
        .expect("WT session must emit transfer.complete via the threaded ipc_tx");
        let save_path = complete.payload["save_path"].as_str().unwrap();
        assert_eq!(
            std::fs::read(save_path).unwrap(),
            payload,
            "WT-received file bytes must match exactly"
        );
        let _ = std::fs::remove_file(save_path);

        let _ = send.finish().await;
        *crate::session_loop::ACTIVE_SESSION.lock().unwrap() = None;
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), server_handle).await;
    }

    /// Adversarial (EA3 / item 2): a WT session with a MISSING trust_config must be
    /// DENIED at the trust gate and never reach the shared session loop or transfer
    /// handling. The daemon completes the HELLO exchange (matching WS/QUIC ordering)
    /// then denies; `handle_incoming_session` returns Err and no transfer event is
    /// emitted. Authorization gating only; nothing is verified or pinned.
    #[tokio::test]
    async fn wt_session_missing_trust_config_denies_before_transfer() {
        let _session_guard = crate::session_loop::SESSION_GLOBALS_LOCK.lock().await;

        let port = free_port().await;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address(addr)
                .with_identity(wt_identity)
                .build(),
        )
        .unwrap();
        let bound = server.local_addr().unwrap();

        let server_identity = generate_ephemeral_keypair();
        let (ipc_tx, ipc_rx) = std::sync::mpsc::channel::<crate::ipc::types::IpcMessage>();
        *crate::session_loop::ACTIVE_SESSION.lock().unwrap() = None;

        // trust_config = None -> fail-closed deny at the gate (after HELLO).
        let server_handle = tokio::spawn(async move {
            let incoming = server.accept().await;
            handle_incoming_session(incoming, &server_identity, Some(ipc_tx), None).await
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = Endpoint::client(
            wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build(),
        )
        .unwrap();
        let url = format!("https://127.0.0.1:{}", bound.port());
        let conn = client.connect(&url).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

        let client_identity = generate_ephemeral_keypair();
        let client_session_kp = generate_ephemeral_keypair();

        // Drive the daemon through the HELLO exchange (the gate is right after HELLO).
        let session_key_msg = serde_json::json!({
            "type": "session-key",
            "publicKey": bolt_core::encoding::to_base64(&client_session_kp.public_key),
        });
        write_frame(&mut send, session_key_msg.to_string().as_bytes())
            .await
            .unwrap();
        let server_key_frame = read_frame(&mut recv).await.unwrap().unwrap();
        let server_key_json: serde_json::Value = serde_json::from_slice(&server_key_frame).unwrap();
        let server_session_pk =
            crate::web_hello::decode_public_key(server_key_json["publicKey"].as_str().unwrap())
                .unwrap();
        let hello_msg = build_hello_message(
            &client_identity.public_key,
            &client_session_kp,
            &server_session_pk,
        )
        .unwrap();
        write_frame(&mut send, hello_msg.as_bytes()).await.unwrap();
        // The daemon sends a HELLO response (before gating, like WS), then denies.
        let _ = read_frame(&mut recv).await;

        // ── assert: DENIED (Err) and NO transfer entered ──
        let result = tokio::time::timeout(tokio::time::Duration::from_secs(5), server_handle)
            .await
            .expect("server task should finish within 5s")
            .expect("server task join");
        assert!(
            result.is_err(),
            "WT session with no trust_config must be denied at the gate, not established"
        );
        let mut saw_transfer = false;
        while let Ok(m) = ipc_rx.try_recv() {
            if m.msg_type == "transfer.started" {
                saw_transfer = true;
            }
        }
        assert!(
            !saw_transfer,
            "a denied WT session must NOT reach transfer handling"
        );
        *crate::session_loop::ACTIVE_SESSION.lock().unwrap() = None;
    }

    /// Poll an IPC receiver up to ~5s for an event matching `pred`, without blocking
    /// the (single-threaded) test runtime so the server task can make progress.
    async fn wait_for_ipc(
        rx: &std::sync::mpsc::Receiver<crate::ipc::types::IpcMessage>,
        pred: impl Fn(&crate::ipc::types::IpcMessage) -> bool,
    ) -> Option<crate::ipc::types::IpcMessage> {
        for _ in 0..50 {
            loop {
                match rx.try_recv() {
                    Ok(msg) => {
                        if pred(&msg) {
                            return Some(msg);
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return None,
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        None
    }
}
