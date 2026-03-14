//! RC3 BTR-over-QUIC: Bolt Transfer Ratchet compatibility over QUIC (AC-RC-14).
//!
//! Validates that BTR seal/open operations work correctly when payloads
//! are transported over QUIC's length-prefixed framing. This proves that
//! Bolt envelope/BTR remains the security authority and QUIC is
//! transport-only.
//!
//! These tests run with `--features transport-quic`.

#![cfg(feature = "transport-quic")]

use bolt_daemon::quic_transport::{QuicDialer, QuicListener};

/// Create a matched BTR sender/receiver context pair with identical chain state.
///
/// Uses `BtrTransferContext::new_for_test` (test-support feature) to inject
/// deterministic key material. Both contexts share the same transfer root key
/// and start at chain_index 0 — equivalent to two peers after a successful
/// DH ratchet step producing identical transfer_root_key.
fn create_matched_btr_contexts() -> (bolt_btr::BtrTransferContext, bolt_btr::BtrTransferContext) {
    let transfer_id = [0x42u8; 16];
    // Deterministic transfer root key for test reproducibility
    let trk = bolt_core::hash::sha256(b"rc3-btr-over-quic-test-key");

    let sender = bolt_btr::BtrTransferContext::new_for_test(transfer_id, 1, trk, 0);
    let receiver = bolt_btr::BtrTransferContext::new_for_test(transfer_id, 1, trk, 0);

    (sender, receiver)
}

// ── AC-RC-14: BTR over QUIC ────────────────────────────────

#[tokio::test]
async fn ac_rc_14_btr_sealed_chunk_over_quic() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let plaintext: &[u8] = b"BTR-sealed payload over QUIC transport";
    let (chain_index, sealed) = sender_ctx.seal_chunk(plaintext).unwrap();

    // Transport sealed chunk over QUIC
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let idx_bytes = stream.recv_message().await.unwrap();
        let sealed_bytes = stream.recv_message().await.unwrap();
        stream.finish().await.ok();
        listener.close();
        (
            u32::from_be_bytes(idx_bytes.try_into().unwrap()),
            sealed_bytes,
        )
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();
    stream
        .send_message(&chain_index.to_be_bytes())
        .await
        .unwrap();
    stream.send_message(&sealed).await.unwrap();
    stream.finish().await.ok();

    let (received_idx, received_sealed) = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    // Decrypt on receiver side
    let decrypted = receiver_ctx
        .open_chunk(received_idx, &received_sealed)
        .unwrap();

    assert_eq!(decrypted, plaintext, "BTR decryption over QUIC failed");
    assert_eq!(received_idx, chain_index);
}

#[tokio::test]
async fn ac_rc_14_btr_multi_chunk_transfer_over_quic() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let chunks: Vec<&[u8]> = vec![
        b"chunk 0: first",
        b"chunk 1: second with more data",
        b"chunk 2: third chunk different size",
        b"chunk 3: final BTR-over-QUIC chunk",
    ];

    // Seal all chunks
    let mut sealed_chunks: Vec<(u32, Vec<u8>)> = Vec::new();
    for chunk in &chunks {
        let (idx, sealed) = sender_ctx.seal_chunk(*chunk).unwrap();
        sealed_chunks.push((idx, sealed));
    }

    // Transport over QUIC
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();
    let count = sealed_chunks.len();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut received = Vec::new();
        for _ in 0..count {
            let idx_bytes = stream.recv_message().await.unwrap();
            let sealed = stream.recv_message().await.unwrap();
            received.push((u32::from_be_bytes(idx_bytes.try_into().unwrap()), sealed));
        }
        stream.finish().await.ok();
        listener.close();
        received
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();
    for (idx, sealed) in &sealed_chunks {
        stream.send_message(&idx.to_be_bytes()).await.unwrap();
        stream.send_message(sealed).await.unwrap();
    }
    stream.finish().await.ok();

    let received = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    // Decrypt and verify each chunk in order
    assert_eq!(received.len(), chunks.len());
    for (i, (idx, sealed)) in received.iter().enumerate() {
        let decrypted = receiver_ctx.open_chunk(*idx, sealed).unwrap();
        assert_eq!(decrypted, chunks[i], "chunk {i} mismatch");
    }
}

#[tokio::test]
async fn ac_rc_14_btr_tampered_chunk_detected_over_quic() {
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

    let plaintext: &[u8] = b"this chunk will be tampered";
    let (chain_index, mut sealed) = sender_ctx.seal_chunk(plaintext).unwrap();

    // Tamper with sealed data
    if let Some(byte) = sealed.last_mut() {
        *byte ^= 0xFF;
    }

    // Transport tampered chunk over QUIC
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let received = stream.recv_message().await.unwrap();
        stream.finish().await.ok();
        listener.close();
        received
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();
    stream.send_message(&sealed).await.unwrap();
    stream.finish().await.ok();

    let received = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    // Decryption must fail — BTR detects tampering
    let result = receiver_ctx.open_chunk(chain_index, &received);
    assert!(
        result.is_err(),
        "BTR must detect tampered chunk after QUIC transport"
    );
}

#[tokio::test]
async fn ac_rc_14_quic_framing_preserves_sealed_bytes() {
    // Verify QUIC framing doesn't corrupt BTR-sealed payloads at various sizes.
    let (mut sender_ctx, mut receiver_ctx) = create_matched_btr_contexts();

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

    // Transport over QUIC
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();
    let count = sealed_pairs.len();

    let sealed_clone: Vec<(u32, Vec<u8>)> = sealed_pairs
        .iter()
        .map(|(idx, s)| (*idx, s.clone()))
        .collect();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut received = Vec::new();
        for _ in 0..count {
            let idx_bytes = stream.recv_message().await.unwrap();
            let sealed = stream.recv_message().await.unwrap();
            received.push((u32::from_be_bytes(idx_bytes.try_into().unwrap()), sealed));
        }
        stream.finish().await.ok();
        listener.close();
        received
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();
    for (idx, sealed) in &sealed_clone {
        stream.send_message(&idx.to_be_bytes()).await.unwrap();
        stream.send_message(sealed).await.unwrap();
    }
    stream.finish().await.ok();

    let received = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    // Byte-level equality: QUIC must not corrupt sealed bytes
    for (i, ((sent_idx, sent_sealed), (recv_idx, recv_sealed))) in
        sealed_pairs.iter().zip(received.iter()).enumerate()
    {
        assert_eq!(sent_idx, recv_idx, "chunk {i} index mismatch");
        assert_eq!(
            sent_sealed, recv_sealed,
            "chunk {i} sealed bytes corrupted by QUIC"
        );
    }

    // Decrypt and verify
    for (i, (idx, sealed)) in received.iter().enumerate() {
        let decrypted = receiver_ctx.open_chunk(*idx, sealed).unwrap();
        assert_eq!(decrypted, payloads[i], "chunk {i} decrypt mismatch");
    }
}
