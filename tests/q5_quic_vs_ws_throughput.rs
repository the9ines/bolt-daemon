//! Q5 throughput evidence: native app-to-app QUIC vs WS fallback.
//!
//! This is a localhost comparison for the native transport migration gate, not
//! a production network benchmark. It proves both transports complete the same
//! framed payload sizes and prints comparable throughput evidence for roadmap
//! documentation.
//!
//! Run with:
//! `cargo test --features native-full --test q5_quic_vs_ws_throughput -- --nocapture`

#![cfg(all(feature = "transport-quic", feature = "transport-ws"))]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bolt_core::encoding::to_base64;
use bolt_daemon::quic_transport::{QuicDialer, QuicListener};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tungstenite::Message;

#[derive(Debug, Clone)]
struct BenchResult {
    transport: &'static str,
    payload_size: usize,
    rounds: usize,
    total_bytes: usize,
    elapsed: Duration,
    throughput_mbps: f64,
}

impl BenchResult {
    fn print(&self) {
        eprintln!(
            "[BENCH-Q5] transport={:<4} payload={:<8} rounds={:<4} total_bytes={:<10} elapsed_ms={:<8.2} throughput_mbps={:.2}",
            self.transport,
            self.payload_size,
            self.rounds,
            self.total_bytes,
            self.elapsed.as_secs_f64() * 1000.0,
            self.throughput_mbps
        );
    }
}

fn payload_frame(payload_size: usize) -> Vec<u8> {
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
    serde_json::json!({
        "kind": "q5_throughput_frame",
        "payload": to_base64(&payload),
    })
    .to_string()
    .into_bytes()
}

fn compute_result(
    transport: &'static str,
    payload_size: usize,
    rounds: usize,
    frame_len: usize,
    elapsed: Duration,
) -> BenchResult {
    let total_bytes = frame_len * rounds * 2;
    let seconds = elapsed.as_secs_f64();
    let throughput_mbps = if seconds > 0.0 {
        (total_bytes as f64 * 8.0 / 1_000_000.0) / seconds
    } else {
        f64::INFINITY
    };

    BenchResult {
        transport,
        payload_size,
        rounds,
        total_bytes,
        elapsed,
        throughput_mbps,
    }
}

async fn bench_ws(payload_size: usize, rounds: usize) -> BenchResult {
    let frame = payload_frame(payload_size);
    let text = String::from_utf8(frame.clone()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut sink, mut source) = ws.split();

        for _ in 0..rounds {
            let msg = source.next().await.unwrap().unwrap();
            sink.send(msg).await.unwrap();
        }

        let _ = sink.close().await;
    });

    let url = format!("ws://{addr}");
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut source) = ws.split();

    let start = Instant::now();
    for _ in 0..rounds {
        sink.send(Message::Text(text.clone())).await.unwrap();
        let reply = source.next().await.unwrap().unwrap();
        assert_eq!(reply.into_data(), frame);
    }
    let elapsed = start.elapsed();

    let _ = sink.close().await;
    server_handle.await.unwrap();

    compute_result("ws", payload_size, rounds, text.len(), elapsed)
}

async fn bench_quic(payload_size: usize, rounds: usize) -> BenchResult {
    let frame = payload_frame(payload_size);

    let listener = QuicListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = listener.local_addr();
    let cert_hash = listener.cert_hash_hex().to_string();

    let server_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();

        for _ in 0..rounds {
            let msg = stream.recv_message().await.unwrap();
            stream.send_message(&msg).await.unwrap();
        }

        stream.finish().await.ok();
        let _ = stream.recv_message().await;
        listener.close();
    });

    let (endpoint, mut stream) = QuicDialer::connect(addr, &cert_hash).await.unwrap();

    let start = Instant::now();
    for _ in 0..rounds {
        stream.send_message(&frame).await.unwrap();
        let reply = stream.recv_message().await.unwrap();
        assert_eq!(reply, frame);
    }
    let elapsed = start.elapsed();

    stream.finish().await.ok();
    server_handle.await.unwrap();
    endpoint.close(0u32.into(), b"done");

    compute_result("quic", payload_size, rounds, frame.len(), elapsed)
}

#[tokio::test]
async fn q5_quic_vs_ws_throughput_comparison() {
    eprintln!();
    eprintln!("[BENCH-Q5] QUIC vs WS fallback throughput (localhost echo, round-trip)");
    eprintln!("[BENCH-Q5] ----------------------------------------------------------------");

    let configs = [
        (1_024usize, 40usize),
        (16_384usize, 30usize),
        (65_536usize, 12usize),
    ];

    for (payload_size, rounds) in configs {
        let ws = bench_ws(payload_size, rounds).await;
        let quic = bench_quic(payload_size, rounds).await;

        ws.print();
        quic.print();

        assert!(ws.elapsed > Duration::ZERO);
        assert!(quic.elapsed > Duration::ZERO);
        assert!(ws.throughput_mbps.is_finite() && ws.throughput_mbps > 0.0);
        assert!(quic.throughput_mbps.is_finite() && quic.throughput_mbps > 0.0);
    }

    eprintln!("[BENCH-Q5] ----------------------------------------------------------------");
    eprintln!(
        "[BENCH-Q5] Done. Localhost loopback results are evidence of completed comparative runs, not a WAN/LAN SLA."
    );
    eprintln!();
}
