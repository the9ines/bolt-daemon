//! RC3 E2E: Daemon↔daemon smoke transfer over QUIC (AC-RC-13, AC-RC-15).
//!
//! Validates:
//! - Full daemon↔daemon file transfer over QUIC transport.
//! - SHA-256 integrity verification end-to-end.
//! - Length-prefixed framing preserves message boundaries.
//! - Provisional performance baseline for AC-RC-15.
//!
//! These tests run with `--features transport-quic`.

#![cfg(feature = "transport-quic")]

use bolt_daemon::quic_transport::{QuicDialer, QuicListener};
use std::time::Instant;

/// Deterministic payload generator (matches smoke.rs).
fn generate_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// SHA-256 hex digest via bolt-core canonical implementation.
fn sha256_hex(data: &[u8]) -> String {
    bolt_core::hash::sha256_hex(data)
}

/// Chunk size used for transfer (matches smoke SEND_CHUNK_SIZE).
const SEND_CHUNK_SIZE: usize = 65_536;

// ── AC-RC-13: Daemon↔daemon transfer over QUIC ─────────────

#[tokio::test]
async fn ac_rc_13_quic_smoke_1mib_transfer() {
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();

        // Receive payload
        let mut received = Vec::with_capacity(1_048_576);
        loop {
            let msg = stream.recv_message().await.unwrap();
            if msg.is_empty() {
                break;
            }
            received.extend_from_slice(&msg);
        }
        received.truncate(1_048_576);
        let received_hash = sha256_hex(&received);

        // Send ack
        stream
            .send_message(received_hash.as_bytes())
            .await
            .unwrap();

        // Wait for dialer to finish before dropping endpoint.
        // Otherwise quinn's Endpoint::drop sends CONNECTION_CLOSE
        // before the dialer reads the ack.
        stream.finish().await.ok();
        let _ = stream.recv_message().await; // blocks until dialer finishes

        (received, received_hash)
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

    let payload = generate_payload(1_048_576);
    let expected_hash = sha256_hex(&payload);

    // Send payload in chunks
    for chunk in payload.chunks(SEND_CHUNK_SIZE) {
        stream.send_message(chunk).await.unwrap();
    }
    stream.send_message(&[]).await.unwrap();

    // Receive ack
    let ack = stream.recv_message().await.unwrap();
    let ack_hash = String::from_utf8(ack).unwrap();

    stream.finish().await.ok();

    let (received, received_hash) = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    // AC-RC-13 assertions: transfer completed + integrity verified
    assert_eq!(received.len(), 1_048_576, "transfer size mismatch");
    assert_eq!(received_hash, expected_hash, "SHA-256 integrity mismatch");
    assert_eq!(ack_hash, expected_hash, "ack hash mismatch");
    assert_eq!(received, payload, "payload content mismatch");
}

#[tokio::test]
async fn ac_rc_13_quic_small_payload_transfer() {
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let msg = stream.recv_message().await.unwrap();
        let hash = sha256_hex(&msg);
        stream.send_message(hash.as_bytes()).await.unwrap();
        stream.finish().await.ok();
        let _ = stream.recv_message().await; // wait for dialer finish
        msg
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

    let payload = generate_payload(42);
    let expected_hash = sha256_hex(&payload);

    stream.send_message(&payload).await.unwrap();
    let ack = stream.recv_message().await.unwrap();
    let ack_hash = String::from_utf8(ack).unwrap();

    stream.finish().await.ok();
    let received = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    assert_eq!(received, payload);
    assert_eq!(ack_hash, expected_hash);
}

#[tokio::test]
async fn ac_rc_13_quic_multiple_transfers() {
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();

    let sizes = vec![1024, 65536, 1_048_576];
    let sizes_clone = sizes.clone();

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut results = Vec::new();

        for expected_size in &sizes_clone {
            let mut received = Vec::with_capacity(*expected_size);
            loop {
                let msg = stream.recv_message().await.unwrap();
                if msg.is_empty() {
                    break;
                }
                received.extend_from_slice(&msg);
            }
            received.truncate(*expected_size);
            let hash = sha256_hex(&received);
            stream.send_message(hash.as_bytes()).await.unwrap();
            results.push((received.len(), hash));
        }

        stream.finish().await.ok();
        let _ = stream.recv_message().await; // wait for dialer finish
        results
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

    for size in &sizes {
        let payload = generate_payload(*size);
        let expected_hash = sha256_hex(&payload);

        for chunk in payload.chunks(SEND_CHUNK_SIZE) {
            stream.send_message(chunk).await.unwrap();
        }
        stream.send_message(&[]).await.unwrap();

        let ack = stream.recv_message().await.unwrap();
        let ack_hash = String::from_utf8(ack).unwrap();
        assert_eq!(ack_hash, expected_hash, "transfer {size} ack mismatch");
    }

    stream.finish().await.ok();
    let results = listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    for (i, (size, _hash)) in results.iter().enumerate() {
        assert_eq!(*size, sizes[i], "transfer {i} size mismatch");
    }
}

// ── AC-RC-15: Provisional performance gate ──────────────────

#[tokio::test]
async fn ac_rc_15_quic_throughput_baseline() {
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr();

    let payload_size: usize = 1_048_576;
    let repeats = 3;

    let listener_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();

        for _ in 0..repeats {
            let mut received = Vec::with_capacity(payload_size);
            loop {
                let msg = stream.recv_message().await.unwrap();
                if msg.is_empty() {
                    break;
                }
                received.extend_from_slice(&msg);
            }
            received.truncate(payload_size);
            let hash = sha256_hex(&received);
            stream.send_message(hash.as_bytes()).await.unwrap();
        }

        stream.finish().await.ok();
        let _ = stream.recv_message().await; // wait for dialer finish
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

    let mut throughputs = Vec::new();

    for run in 1..=repeats {
        let payload = generate_payload(payload_size);
        let expected_hash = sha256_hex(&payload);

        let start = Instant::now();

        for chunk in payload.chunks(SEND_CHUNK_SIZE) {
            stream.send_message(chunk).await.unwrap();
        }
        stream.send_message(&[]).await.unwrap();

        let ack = stream.recv_message().await.unwrap();
        let elapsed = start.elapsed();

        let ack_hash = String::from_utf8(ack).unwrap();
        assert_eq!(ack_hash, expected_hash);

        let latency_ms = elapsed.as_millis() as u64;
        let throughput_mbps = if latency_ms > 0 {
            (payload_size as f64 / 1_000_000.0) / (latency_ms as f64 / 1_000.0)
        } else {
            f64::INFINITY
        };

        eprintln!(
            "[AC-RC-15] QUIC run {run}/{repeats}: {payload_size} bytes, \
             {latency_ms} ms, {throughput_mbps:.1} MB/s"
        );
        throughputs.push(throughput_mbps);
    }

    stream.finish().await.ok();
    listener_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    let avg_throughput: f64 = throughputs.iter().sum::<f64>() / throughputs.len() as f64;
    eprintln!(
        "[AC-RC-15] QUIC avg throughput: {avg_throughput:.1} MB/s ({repeats} runs, {payload_size} bytes)"
    );

    assert!(
        avg_throughput > 0.0,
        "throughput must be positive: {avg_throughput}"
    );
}
