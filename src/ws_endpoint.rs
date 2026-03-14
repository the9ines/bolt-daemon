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
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::accept_async;
use tungstenite::Message;

use bolt_core::crypto::{generate_ephemeral_keypair, KeyPair};
use bolt_core::session::SessionContext;

use crate::envelope::{build_error_payload, decode_envelope, route_inner_message};
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

/// Configuration for the WebSocket endpoint.
pub struct WsEndpointConfig {
    /// Address to bind the TCP listener on.
    pub listen_addr: SocketAddr,
    /// Persistent identity keypair (long-lived, loaded from store).
    pub identity_keypair: KeyPair,
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
                            if let Err(e) = handle_connection(stream, peer_addr, &identity).await {
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Step 1: WebSocket upgrade ────────────────────────────
    let ws_stream = accept_async(stream)
        .await
        .map_err(|e| format!("[WS_SESSION] {peer_addr} WebSocket upgrade failed: {e}"))?;
    eprintln!("[WS_SESSION] {peer_addr} WebSocket upgraded");

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

    // ── Step 4: Parse and decrypt HELLO ──────────────────────
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
    let local_caps = daemon_capabilities();
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

    eprintln!("[WS_SESSION] {peer_addr} session established, entering message loop");

    // ── Step 8: Envelope message loop ────────────────────────
    run_message_loop(
        &mut ws_sink,
        &mut ws_source,
        &session,
        peer_addr,
        &remote_identity_pk,
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
                Ok(Message::Text(text)) => return Ok::<String, BoxErr>(text),
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
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
    .map_err(|_| -> BoxErr { format!("[WS_HELLO] {peer_addr} HELLO timeout (30s)").into() })??;
    Ok(msg)
}

/// Post-HELLO envelope message loop.
///
/// Receives encrypted ProfileEnvelopeV1 frames, decrypts, routes via
/// `route_inner_message`, and sends any reply. Runs until the peer
/// disconnects or a protocol violation occurs.
async fn run_message_loop(
    ws_sink: &mut (impl SinkExt<Message, Error = tungstenite::Error> + Unpin),
    ws_source: &mut (impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin),
    session: &SessionContext,
    peer_addr: SocketAddr,
    _remote_identity_pk: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                // Decode envelope
                let inner = match decode_envelope(text.as_bytes(), session) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        eprintln!("[WS_SESSION] {peer_addr} envelope error: {e}");
                        // Send error and disconnect (fail-closed)
                        let error_payload =
                            build_error_payload(e.code(), &e.to_string(), Some(session));
                        let _ = ws_sink
                            .send(Message::Text(
                                String::from_utf8_lossy(&error_payload).into_owned(),
                            ))
                            .await;
                        break;
                    }
                };

                // Route inner message
                match route_inner_message(&inner, session) {
                    Ok(Some(reply_bytes)) => {
                        let reply_text = String::from_utf8_lossy(&reply_bytes).into_owned();
                        if let Err(e) = ws_sink.send(Message::Text(reply_text)).await {
                            eprintln!("[WS_SESSION] {peer_addr} send error: {e}");
                            break;
                        }
                    }
                    Ok(None) => {
                        // No reply needed (pong received, file-transfer message
                        // handled at transfer layer, etc.)
                    }
                    Err(e) => {
                        eprintln!("[WS_SESSION] {peer_addr} route error: {e}");
                        let error_payload =
                            build_error_payload(e.code(), &e.to_string(), Some(session));
                        let _ = ws_sink
                            .send(Message::Text(
                                String::from_utf8_lossy(&error_payload).into_owned(),
                            ))
                            .await;
                        break;
                    }
                }
            }
            Message::Ping(data) => {
                // Respond to WS-level pings
                if let Err(e) = ws_sink.send(Message::Pong(data)).await {
                    eprintln!("[WS_SESSION] {peer_addr} pong send error: {e}");
                    break;
                }
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
}
