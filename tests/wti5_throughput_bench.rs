//! WTI5 Throughput Benchmark: WT vs WS framed payload comparison (AC-WTI-19).
//!
//! Measures round-trip throughput for length-prefixed frames over WebTransport
//! and WebSocket transports at representative payload sizes.
//!
//! This is a scaffold benchmark, not a full production perf suite.
//! Run with: `cargo test --features transport-webtransport,transport-ws --release -- wti5_bench --nocapture`
//!
//! Output format:
//!   [BENCH] transport=ws  payload=1024   rounds=100  total_bytes=204800  elapsed_ms=N  throughput_mbps=X.XX
//!   [BENCH] transport=wt  payload=1024   rounds=100  total_bytes=204800  elapsed_ms=N  throughput_mbps=X.XX

// Both features required for comparison
#![cfg(all(feature = "transport-webtransport", feature = "transport-ws"))]

use std::net::SocketAddr;
use std::time::Instant;

use bolt_core::encoding::to_base64;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tungstenite::Message;
use wtransport::{ClientConfig, Endpoint, Identity, ServerConfig};

/// Find an available port.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Write a 4-byte BE length-prefixed frame.
async fn wt_write_frame(send: &mut wtransport::stream::SendStream, data: &[u8]) {
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes()).await.unwrap();
    send.write_all(data).await.unwrap();
}

/// Read a 4-byte BE length-prefixed frame.
async fn wt_read_frame(recv: &mut wtransport::stream::RecvStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.unwrap();
    buf
}

struct BenchResult {
    transport: &'static str,
    payload_size: usize,
    rounds: usize,
    total_bytes: usize,
    elapsed_ms: u64,
    throughput_mbps: f64,
}

impl BenchResult {
    fn print(&self) {
        eprintln!(
            "[BENCH] transport={:<4} payload={:<8} rounds={:<4} total_bytes={:<10} elapsed_ms={:<6} throughput_mbps={:.2}",
            self.transport, self.payload_size, self.rounds, self.total_bytes, self.elapsed_ms, self.throughput_mbps
        );
    }
}

fn compute_result(
    transport: &'static str,
    payload_size: usize,
    rounds: usize,
    elapsed: std::time::Duration,
) -> BenchResult {
    let total_bytes = payload_size * rounds * 2; // send + receive
    let elapsed_ms = elapsed.as_millis() as u64;
    let throughput_mbps = if elapsed_ms > 0 {
        (total_bytes as f64 / 1_000_000.0) / (elapsed_ms as f64 / 1_000.0)
    } else {
        0.0
    };
    BenchResult {
        transport,
        payload_size,
        rounds,
        total_bytes,
        elapsed_ms,
        throughput_mbps,
    }
}

// ── WS benchmark ──────────────────────────────────────────────

async fn bench_ws(payload_size: usize, rounds: usize) -> BenchResult {
    let port = free_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut sink, mut source) = ws.split();
        for _ in 0..rounds {
            if let Some(Ok(msg)) = source.next().await {
                sink.send(msg).await.unwrap();
            }
        }
        let _ = sink.close().await;
    });

    let url = format!("ws://127.0.0.1:{port}");
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws.split();

    let payload = vec![0xABu8; payload_size];
    let json = serde_json::json!({ "data": to_base64(&payload) });
    let text = json.to_string();

    let start = Instant::now();
    for _ in 0..rounds {
        sink.send(Message::Text(text.clone())).await.unwrap();
        let _ = source.next().await.unwrap().unwrap();
    }
    let elapsed = start.elapsed();

    let _ = sink.close().await;
    let _ = server_handle.await;

    compute_result("ws", payload_size, rounds, elapsed)
}

// ── WT benchmark ──────────────────────────────────────────────

async fn bench_wt(payload_size: usize, rounds: usize) -> BenchResult {
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
        for _ in 0..rounds {
            let frame = wt_read_frame(&mut recv).await;
            wt_write_frame(&mut send, &frame).await;
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

    let payload = vec![0xABu8; payload_size];
    let json = serde_json::json!({ "data": to_base64(&payload) });
    let frame_bytes = json.to_string().into_bytes();

    let start = Instant::now();
    for _ in 0..rounds {
        wt_write_frame(&mut send, &frame_bytes).await;
        let _ = wt_read_frame(&mut recv).await;
    }
    let elapsed = start.elapsed();

    let _ = send.finish().await; // may fail if server already closed
    let _ = server_handle.await;

    compute_result("wt", payload_size, rounds, elapsed)
}

// ── Benchmark test ────────────────────────────────────────────

#[tokio::test]
async fn wti5_bench_wt_vs_ws_throughput() {
    eprintln!();
    eprintln!("[BENCH] WTI5 throughput comparison: WT vs WS (localhost echo, round-trip)");
    eprintln!("[BENCH] ────────────────────────────────────────────────────────────────");

    let configs = vec![
        (256, 50),   // small messages
        (1024, 50),  // 1 KB
        (16384, 50), // 16 KB
        (65536, 20), // 64 KB
    ];

    for (payload_size, rounds) in &configs {
        let ws_result = bench_ws(*payload_size, *rounds).await;
        let wt_result = bench_wt(*payload_size, *rounds).await;
        ws_result.print();
        wt_result.print();

        // Sanity: both transports completed without error
        assert!(ws_result.elapsed_ms > 0 || ws_result.rounds == 0);
        assert!(wt_result.elapsed_ms > 0 || wt_result.rounds == 0);
    }

    eprintln!("[BENCH] ────────────────────────────────────────────────────────────────");
    eprintln!("[BENCH] Done. Results are localhost loopback — not representative of real network conditions.");
    eprintln!();
}
