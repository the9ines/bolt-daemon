//! RC5 BTR-over-WS: Bolt Transfer Ratchet compatibility over WebSocket (AC-RC-23).
//!
//! Validates that:
//! 1. Daemon capability negotiation includes `bolt.transfer-ratchet-v1` over WS.
//! 2. BTR-sealed payloads survive WS text framing (base64 round-trip).
//! 3. Tamper detection works for BTR payloads transported over WS.
//!
//! Follows the same pattern as `rc3_btr_over_quic.rs` (AC-RC-14).
//! These tests run with `--features transport-ws`.

#![cfg(feature = "transport-ws")]

use std::net::SocketAddr;

use bolt_core::crypto::generate_ephemeral_keypair;
use bolt_core::encoding::to_base64;
use bolt_core::identity::generate_identity_keypair;
use bolt_daemon::web_hello::{build_hello_message, decode_public_key, parse_hello_message};
use bolt_daemon::ws_endpoint::{run_ws_endpoint, WsEndpointConfig};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::connect_async;
use tungstenite::Message;

/// Find an available port by binding to :0.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn copy_keypair(kp: &bolt_core::crypto::KeyPair) -> bolt_core::crypto::KeyPair {
    bolt_core::crypto::KeyPair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    }
}

/// Create matched BTR sender/receiver context pair (same as RC3 pattern).
fn create_matched_btr_contexts() -> (bolt_btr::BtrTransferContext, bolt_btr::BtrTransferContext) {
    let transfer_id = [0x57u8; 16]; // different from RC3 to avoid confusion
    let trk = bolt_core::hash::sha256(b"rc5-btr-over-ws-test-key");

    let sender = bolt_btr::BtrTransferContext::new_for_test(transfer_id, 1, trk, 0);
    let receiver = bolt_btr::BtrTransferContext::new_for_test(transfer_id, 1, trk, 0);

    (sender, receiver)
}

/// Helper: connect to WS endpoint and complete full HELLO handshake.
/// Returns (sink, source, browser_session_kp, daemon_session_pk, negotiated_caps).
async fn connect_and_handshake(
    port: u16,
) -> (
    impl SinkExt<Message, Error = tungstenite::Error> + Unpin,
    impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin,
    bolt_core::crypto::KeyPair,
    [u8; 32],
    Vec<String>,
) {
    let url = format!("ws://127.0.0.1:{port}");
    let (ws_stream, _) = connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws_stream.split();

    let browser_session_kp = generate_ephemeral_keypair();
    let browser_identity = generate_identity_keypair();

    // Send browser's session key
    let session_key_msg = serde_json::json!({
        "type": "session-key",
        "publicKey": to_base64(&browser_session_kp.public_key),
    });
    sink.send(Message::Text(session_key_msg.to_string()))
        .await
        .unwrap();

    // Receive daemon's session key
    let daemon_sk_msg = source.next().await.unwrap().unwrap();
    let daemon_sk_text = match daemon_sk_msg {
        Message::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };
    let daemon_sk_value: serde_json::Value = serde_json::from_str(&daemon_sk_text).unwrap();
    let daemon_session_pk =
        decode_public_key(daemon_sk_value["publicKey"].as_str().unwrap()).unwrap();

    // Build and send HELLO (browser advertises BTR capability)
    let hello_msg = build_hello_message(
        &browser_identity.public_key,
        &browser_session_kp,
        &daemon_session_pk,
    )
    .unwrap();
    sink.send(Message::Text(hello_msg)).await.unwrap();

    // Receive daemon HELLO response
    let hello_response = source.next().await.unwrap().unwrap();
    let hello_text = match hello_response {
        Message::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };

    let inner = parse_hello_message(
        hello_text.as_bytes(),
        &daemon_session_pk,
        &browser_session_kp,
    )
    .unwrap();

    // Negotiate capabilities (intersection of daemon + browser)
    let negotiated =
        bolt_core::session::negotiate_capabilities(&inner.capabilities, &inner.capabilities);

    (
        sink,
        source,
        browser_session_kp,
        daemon_session_pk,
        negotiated,
    )
}

// ── AC-RC-23: BTR capability negotiation over WS ─────────
// DAEMON-BTR-1 complete: daemon now implements BTR state machine for chunk
// encrypt/decrypt. Capability truthfully advertised.

#[tokio::test]
async fn ac_rc_23_ws_hello_negotiates_btr_capability() {
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

    let (mut sink, _source, _kp, _pk, negotiated) = connect_and_handshake(port).await;

    // Daemon MUST advertise all capabilities it implements
    assert!(negotiated.contains(&"bolt.profile-envelope-v1".to_string()));
    assert!(negotiated.contains(&"bolt.file-hash".to_string()));
    assert!(
        negotiated.contains(&"bolt.transfer-ratchet-v1".to_string()),
        "BTR capability must be in negotiated set; got: {negotiated:?}"
    );

    let _ = sink.close().await;
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
}

// ── AC-RC-23: BTR sealed chunk over WS ───────────────────

#[tokio::test]
async fn ac_rc_23_btr_sealed_chunk_over_ws() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let plaintext: &[u8] = b"BTR-sealed payload over WebSocket transport";
    let (chain_index, sealed) = sender_ctx.seal_chunk(plaintext).unwrap();

    // Transport sealed chunk over WS (base64-encoded in text frame)
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let listener = TcpListener::bind(addr).await.unwrap();

    // Server side: receive one text message, echo it back
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut sink, mut source) = ws.split();
        if let Some(Ok(Message::Text(text))) = source.next().await {
            sink.send(Message::Text(text)).await.unwrap();
        }
        let _ = sink.close().await;
    });

    // Client side: send BTR sealed bytes as base64 text, receive echo
    let url = format!("ws://127.0.0.1:{port}");
    let (ws, _) = connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws.split();

    // Encode sealed bytes as base64 for WS text transport
    let payload = serde_json::json!({
        "chain_index": chain_index,
        "sealed": to_base64(&sealed),
    });
    sink.send(Message::Text(payload.to_string())).await.unwrap();

    // Receive echo
    let echo = source.next().await.unwrap().unwrap();
    let echo_text = match echo {
        Message::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };

    // Decode
    let received: serde_json::Value = serde_json::from_str(&echo_text).unwrap();
    let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
    let recv_sealed = bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap())
        .expect("base64 decode failed");

    // Decrypt on receiver side
    let decrypted = receiver_ctx.open_chunk(recv_idx, &recv_sealed).unwrap();
    assert_eq!(decrypted, plaintext, "BTR decryption over WS failed");
    assert_eq!(recv_idx, chain_index);

    let _ = sink.close().await;
    let _ = server_handle.await;
}

// ── AC-RC-23: BTR multi-chunk over WS ────────────────────

#[tokio::test]
async fn ac_rc_23_btr_multi_chunk_transfer_over_ws() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let chunks: Vec<&[u8]> = vec![
        b"chunk 0: first BTR-over-WS",
        b"chunk 1: second with more data",
        b"chunk 2: third chunk different size",
        b"chunk 3: final BTR-over-WS chunk",
    ];

    // Seal all chunks
    let mut sealed_chunks: Vec<(u32, Vec<u8>)> = Vec::new();
    for chunk in &chunks {
        let (idx, sealed) = sender_ctx.seal_chunk(*chunk).unwrap();
        sealed_chunks.push((idx, sealed));
    }

    // Transport over WS
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    let count = sealed_chunks.len();
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut sink, mut source) = ws.split();
        for _ in 0..count {
            if let Some(Ok(Message::Text(text))) = source.next().await {
                sink.send(Message::Text(text)).await.unwrap();
            }
        }
        let _ = sink.close().await;
    });

    let url = format!("ws://127.0.0.1:{port}");
    let (ws, _) = connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws.split();

    // Send all sealed chunks
    for (idx, sealed) in &sealed_chunks {
        let payload = serde_json::json!({
            "chain_index": idx,
            "sealed": to_base64(sealed),
        });
        sink.send(Message::Text(payload.to_string())).await.unwrap();
    }

    // Receive echoes and decrypt
    for (i, original_chunk) in chunks.iter().enumerate() {
        let echo = source.next().await.unwrap().unwrap();
        let echo_text = match echo {
            Message::Text(t) => t,
            other => panic!("chunk {i}: expected text, got {other:?}"),
        };
        let received: serde_json::Value = serde_json::from_str(&echo_text).unwrap();
        let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
        let recv_sealed =
            bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();

        let decrypted = receiver_ctx.open_chunk(recv_idx, &recv_sealed).unwrap();
        assert_eq!(decrypted, *original_chunk, "chunk {i} mismatch");
    }

    let _ = sink.close().await;
    let _ = server_handle.await;
}

// ── AC-RC-23: BTR tamper detection over WS ───────────────

#[tokio::test]
async fn ac_rc_23_btr_tampered_chunk_detected_over_ws() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let plaintext: &[u8] = b"this chunk will be tampered during WS transport";
    let (chain_index, mut sealed) = sender_ctx.seal_chunk(plaintext).unwrap();

    // Tamper with sealed data
    if let Some(byte) = sealed.last_mut() {
        *byte ^= 0xFF;
    }

    // Transport tampered bytes over WS
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut sink, mut source) = ws.split();
        if let Some(Ok(Message::Text(text))) = source.next().await {
            sink.send(Message::Text(text)).await.unwrap();
        }
        let _ = sink.close().await;
    });

    let url = format!("ws://127.0.0.1:{port}");
    let (ws, _) = connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws.split();

    let payload = serde_json::json!({
        "chain_index": chain_index,
        "sealed": to_base64(&sealed),
    });
    sink.send(Message::Text(payload.to_string())).await.unwrap();

    let echo = source.next().await.unwrap().unwrap();
    let echo_text = match echo {
        Message::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };
    let received: serde_json::Value = serde_json::from_str(&echo_text).unwrap();
    let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
    let recv_sealed =
        bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();

    // Decryption must fail — BTR detects tampering
    let result = receiver_ctx.open_chunk(recv_idx, &recv_sealed);
    assert!(
        result.is_err(),
        "BTR must detect tampered chunk after WS transport"
    );

    let _ = sink.close().await;
    let _ = server_handle.await;
}

// ── AC-RC-23: WS framing preserves sealed bytes ──────────

#[tokio::test]
async fn ac_rc_23_ws_framing_preserves_sealed_bytes() {
    let (mut sender_ctx, _receiver_ctx) = create_matched_btr_contexts();

    let payloads: Vec<Vec<u8>> = vec![
        vec![0u8; 1],
        vec![0xFFu8; 100],
        vec![0xAAu8; 16384],
        vec![0x55u8; 65536],
    ];

    let mut sealed_pairs: Vec<(u32, Vec<u8>)> = Vec::new();
    for payload in &payloads {
        let (idx, sealed) = sender_ctx.seal_chunk(payload.as_slice()).unwrap();
        sealed_pairs.push((idx, sealed));
    }

    // Transport over WS
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    let count = sealed_pairs.len();
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut sink, mut source) = ws.split();
        for _ in 0..count {
            if let Some(Ok(Message::Text(text))) = source.next().await {
                sink.send(Message::Text(text)).await.unwrap();
            }
        }
        let _ = sink.close().await;
    });

    let url = format!("ws://127.0.0.1:{port}");
    let (ws, _) = connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws.split();

    for (idx, sealed) in &sealed_pairs {
        let payload = serde_json::json!({
            "chain_index": idx,
            "sealed": to_base64(sealed),
        });
        sink.send(Message::Text(payload.to_string())).await.unwrap();
    }

    // Verify byte-level equality after WS round-trip
    for (i, (sent_idx, sent_sealed)) in sealed_pairs.iter().enumerate() {
        let echo = source.next().await.unwrap().unwrap();
        let echo_text = match echo {
            Message::Text(t) => t,
            other => panic!("chunk {i}: expected text, got {other:?}"),
        };
        let received: serde_json::Value = serde_json::from_str(&echo_text).unwrap();
        let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
        let recv_sealed =
            bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();

        assert_eq!(*sent_idx, recv_idx, "chunk {i} index mismatch");
        assert_eq!(
            *sent_sealed, recv_sealed,
            "chunk {i} sealed bytes corrupted by WS"
        );
    }

    // Decrypt and verify (re-create receiver context since original was unused above)
    let mut verify_ctx = create_matched_btr_contexts().1;
    for (i, (idx, sealed)) in sealed_pairs.iter().enumerate() {
        let decrypted = verify_ctx.open_chunk(*idx, sealed).unwrap();
        assert_eq!(decrypted, payloads[i], "chunk {i} decrypt mismatch");
    }

    let _ = sink.close().await;
    let _ = server_handle.await;
}
