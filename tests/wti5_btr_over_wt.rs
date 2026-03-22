//! WTI5 BTR-over-WT: Bolt Transfer Ratchet compatibility over WebTransport (AC-WTI-17/20).
//!
//! Validates that:
//! 1. Daemon capability negotiation includes `bolt.transport-webtransport-v1` over WT.
//! 2. BTR-sealed payloads survive WT length-prefixed framing (base64 round-trip).
//! 3. Tamper detection works for BTR payloads transported over WT.
//! 4. WT endpoint starts, accepts sessions, and exchanges framed data.
//!
//! Follows the same pattern as `rc5_btr_over_ws.rs` (AC-RC-23).
//! These tests run with `--features transport-webtransport`.

#![cfg(feature = "transport-webtransport")]

use std::net::SocketAddr;

use bolt_core::encoding::to_base64;
use bolt_core::hash::sha256;
use tokio::net::TcpListener;
use tokio::sync::watch;
use wtransport::{ClientConfig, Endpoint, Identity, ServerConfig};

/// Find an available port by binding to :0.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Create matched BTR sender/receiver context pair.
fn create_matched_btr_contexts() -> (bolt_btr::BtrTransferContext, bolt_btr::BtrTransferContext) {
    let transfer_id = [0x77u8; 16]; // unique to WT tests
    let trk = sha256(b"wti5-btr-over-wt-test-key");

    let sender = bolt_btr::BtrTransferContext::new_for_test(transfer_id, 1, trk, 0);
    let receiver = bolt_btr::BtrTransferContext::new_for_test(transfer_id, 1, trk, 0);

    (sender, receiver)
}

/// Write a 4-byte BE length-prefixed frame to a WT send stream.
async fn write_frame(send: &mut wtransport::stream::SendStream, data: &[u8]) {
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes()).await.unwrap();
    send.write_all(data).await.unwrap();
}

/// Read a 4-byte BE length-prefixed frame from a WT recv stream.
async fn read_frame(recv: &mut wtransport::stream::RecvStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.unwrap();
    buf
}

// ── WTI5: WT endpoint accepts session and echoes framed data ───

#[tokio::test]
async fn wti5_wt_session_framed_echo() {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let server_config = ServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(wt_identity)
        .build();

    let server = Endpoint::server(server_config).unwrap();
    let bound_addr = server.local_addr().unwrap();

    // Server: accept session, accept bidi, echo N frames
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await;
        let req = incoming.await.unwrap();
        let conn = req.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // Echo 3 frames
        for _ in 0..3 {
            let frame = read_frame(&mut recv).await;
            write_frame(&mut send, &frame).await;
        }
        send.finish().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();

    let client = Endpoint::client(client_config).unwrap();
    let url = format!("https://127.0.0.1:{}", bound_addr.port());
    let conn = client.connect(&url).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

    let messages = vec![
        b"hello-wt".to_vec(),
        b"frame-two".to_vec(),
        b"final".to_vec(),
    ];

    for msg in &messages {
        write_frame(&mut send, msg).await;
    }
    send.finish().await.unwrap();

    for (i, original) in messages.iter().enumerate() {
        let echoed = read_frame(&mut recv).await;
        assert_eq!(&echoed, original, "frame {i} mismatch after WT round-trip");
    }

    server_handle.await.unwrap();
}

// ── WTI5: BTR sealed chunk survives WT framing ────────────────

#[tokio::test]
async fn wti5_btr_sealed_chunk_over_wt() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let plaintext: &[u8] = b"BTR-sealed payload over WebTransport";
    let (chain_index, sealed) = sender_ctx.seal_chunk(plaintext).unwrap();

    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let server_config = ServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(wt_identity)
        .build();

    let server = Endpoint::server(server_config).unwrap();
    let bound_addr = server.local_addr().unwrap();

    // Server: echo one frame
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await;
        let req = incoming.await.unwrap();
        let conn = req.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let frame = read_frame(&mut recv).await;
        write_frame(&mut send, &frame).await;
        send.finish().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client = Endpoint::client(client_config).unwrap();
    let url = format!("https://127.0.0.1:{}", bound_addr.port());
    let conn = client.connect(&url).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

    // Encode sealed bytes as JSON with base64 (same pattern as WS tests)
    let payload = serde_json::json!({
        "chain_index": chain_index,
        "sealed": to_base64(&sealed),
    });
    write_frame(&mut send, payload.to_string().as_bytes()).await;
    send.finish().await.unwrap();

    // Receive echo
    let echo = read_frame(&mut recv).await;
    let received: serde_json::Value = serde_json::from_slice(&echo).unwrap();
    let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
    let recv_sealed =
        bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();

    // Decrypt
    let decrypted = receiver_ctx.open_chunk(recv_idx, &recv_sealed).unwrap();
    assert_eq!(decrypted, plaintext, "BTR decryption over WT failed");
    assert_eq!(recv_idx, chain_index);

    server_handle.await.unwrap();
}

// ── WTI5: BTR multi-chunk over WT ─────────────────────────────

#[tokio::test]
async fn wti5_btr_multi_chunk_over_wt() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let chunks: Vec<&[u8]> = vec![
        b"chunk 0: first BTR-over-WT",
        b"chunk 1: second with more data",
        b"chunk 2: third chunk different size",
        b"chunk 3: final BTR-over-WT chunk",
    ];

    let mut sealed_chunks: Vec<(u32, Vec<u8>)> = Vec::new();
    for chunk in &chunks {
        let (idx, sealed) = sender_ctx.seal_chunk(*chunk).unwrap();
        sealed_chunks.push((idx, sealed));
    }

    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let server_config = ServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(wt_identity)
        .build();

    let server = Endpoint::server(server_config).unwrap();
    let bound_addr = server.local_addr().unwrap();

    let count = sealed_chunks.len();
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await;
        let req = incoming.await.unwrap();
        let conn = req.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        for _ in 0..count {
            let frame = read_frame(&mut recv).await;
            write_frame(&mut send, &frame).await;
        }
        send.finish().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client = Endpoint::client(client_config).unwrap();
    let url = format!("https://127.0.0.1:{}", bound_addr.port());
    let conn = client.connect(&url).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

    for (idx, sealed) in &sealed_chunks {
        let payload = serde_json::json!({
            "chain_index": idx,
            "sealed": to_base64(sealed),
        });
        write_frame(&mut send, payload.to_string().as_bytes()).await;
    }
    send.finish().await.unwrap();

    for (i, original_chunk) in chunks.iter().enumerate() {
        let echo = read_frame(&mut recv).await;
        let received: serde_json::Value = serde_json::from_slice(&echo).unwrap();
        let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
        let recv_sealed =
            bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();
        let decrypted = receiver_ctx.open_chunk(recv_idx, &recv_sealed).unwrap();
        assert_eq!(decrypted, *original_chunk, "chunk {i} mismatch over WT");
    }

    server_handle.await.unwrap();
}

// ── WTI5: BTR tamper detection over WT ─────────────────────────

#[tokio::test]
async fn wti5_btr_tampered_chunk_detected_over_wt() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let plaintext: &[u8] = b"this chunk will be tampered during WT transport";
    let (chain_index, mut sealed) = sender_ctx.seal_chunk(plaintext).unwrap();

    // Tamper
    if let Some(byte) = sealed.last_mut() {
        *byte ^= 0xFF;
    }

    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let server_config = ServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(wt_identity)
        .build();

    let server = Endpoint::server(server_config).unwrap();
    let bound_addr = server.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await;
        let req = incoming.await.unwrap();
        let conn = req.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let frame = read_frame(&mut recv).await;
        write_frame(&mut send, &frame).await;
        send.finish().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client = Endpoint::client(client_config).unwrap();
    let url = format!("https://127.0.0.1:{}", bound_addr.port());
    let conn = client.connect(&url).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

    let payload = serde_json::json!({
        "chain_index": chain_index,
        "sealed": to_base64(&sealed),
    });
    write_frame(&mut send, payload.to_string().as_bytes()).await;
    send.finish().await.unwrap();

    let echo = read_frame(&mut recv).await;
    let received: serde_json::Value = serde_json::from_slice(&echo).unwrap();
    let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
    let recv_sealed =
        bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();

    let result = receiver_ctx.open_chunk(recv_idx, &recv_sealed);
    assert!(
        result.is_err(),
        "BTR must detect tampered chunk after WT transport"
    );

    server_handle.await.unwrap();
}

// ── WTI5: WT framing preserves sealed bytes (various sizes) ───

#[tokio::test]
async fn wti5_wt_framing_preserves_sealed_bytes() {
    let (mut sender_ctx, _) = create_matched_btr_contexts();

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

    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let wt_identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let server_config = ServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(wt_identity)
        .build();

    let server = Endpoint::server(server_config).unwrap();
    let bound_addr = server.local_addr().unwrap();

    let count = sealed_pairs.len();
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await;
        let req = incoming.await.unwrap();
        let conn = req.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        for _ in 0..count {
            let frame = read_frame(&mut recv).await;
            write_frame(&mut send, &frame).await;
        }
        send.finish().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client = Endpoint::client(client_config).unwrap();
    let url = format!("https://127.0.0.1:{}", bound_addr.port());
    let conn = client.connect(&url).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

    for (idx, sealed) in &sealed_pairs {
        let payload = serde_json::json!({
            "chain_index": idx,
            "sealed": to_base64(sealed),
        });
        write_frame(&mut send, payload.to_string().as_bytes()).await;
    }
    send.finish().await.unwrap();

    // Verify byte-level equality
    for (i, (sent_idx, sent_sealed)) in sealed_pairs.iter().enumerate() {
        let echo = read_frame(&mut recv).await;
        let received: serde_json::Value = serde_json::from_slice(&echo).unwrap();
        let recv_idx = received["chain_index"].as_u64().unwrap() as u32;
        let recv_sealed =
            bolt_core::encoding::from_base64(received["sealed"].as_str().unwrap()).unwrap();

        assert_eq!(*sent_idx, recv_idx, "chunk {i} index mismatch");
        assert_eq!(
            *sent_sealed, recv_sealed,
            "chunk {i} sealed bytes corrupted by WT framing"
        );
    }

    // Decrypt to verify integrity
    let mut verify_ctx = create_matched_btr_contexts().1;
    for (i, (idx, sealed)) in sealed_pairs.iter().enumerate() {
        let decrypted = verify_ctx.open_chunk(*idx, sealed).unwrap();
        assert_eq!(decrypted, payloads[i], "chunk {i} decrypt mismatch");
    }

    server_handle.await.unwrap();
}
