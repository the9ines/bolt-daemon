//! E2E echo server for browser WebTransport validation.
//!
//! Starts a WebTransport endpoint (HTTP/3) and a WebSocket endpoint (TCP),
//! both in echo mode. Prints JSON config (ports + cert hash) to stdout
//! for the Playwright test harness to consume.
//!
//! Usage:
//!   cargo run --example wt_e2e_echo --features transport-webtransport,transport-ws
//!
//! The server runs until stdin is closed or SIGTERM is received.

#[cfg(all(feature = "transport-webtransport", feature = "transport-ws"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tungstenite::Message;
    use wtransport::{Endpoint, Identity, ServerConfig};

    // ── Generate self-signed cert (max 14 days for browser serverCertificateHashes) ──
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(13);
    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().to_vec();
    let cert_hash = bolt_core::hash::sha256(&cert_der);
    let cert_hash_hex: String = cert_hash.iter().map(|b| format!("{b:02x}")).collect();

    // Write PEM to temp files
    let tmp = tempfile::tempdir()?;
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;

    // ── Start WebTransport endpoint ──
    let wt_identity =
        Identity::load_pemfiles(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).await?;

    let wt_config = ServerConfig::builder()
        .with_bind_default(0) // random port
        .with_identity(wt_identity)
        .keep_alive_interval(Some(std::time::Duration::from_secs(5)))
        .build();

    let wt_server = Endpoint::server(wt_config)?;
    let wt_addr = wt_server.local_addr()?;

    // ── Start WebSocket endpoint ──
    let ws_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ws_addr = ws_listener.local_addr()?;

    // ── Print config JSON to stdout (harness reads this) ──
    let config = serde_json::json!({
        "wt_port": wt_addr.port(),
        "ws_port": ws_addr.port(),
        "cert_hash": cert_hash_hex,
    });
    println!("{config}");

    eprintln!("[E2E_SERVER] WT on {wt_addr}, WS on {ws_addr}");
    eprintln!("[E2E_SERVER] cert_hash={cert_hash_hex}");

    // ── WT accept loop (echo framed messages) ──
    tokio::spawn(async move {
        loop {
            let incoming = wt_server.accept().await;
            tokio::spawn(async move {
                let Ok(req) = incoming.await else { return };
                eprintln!("[E2E_WT] session from {}", req.remote_address());
                let Ok(conn) = req.accept().await else { return };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                loop {
                                    let mut len_buf = [0u8; 4];
                                    if recv.read_exact(&mut len_buf).await.is_err() {
                                        break;
                                    }
                                    let len = u32::from_be_bytes(len_buf) as usize;
                                    let mut payload = vec![0u8; len];
                                    if recv.read_exact(&mut payload).await.is_err() {
                                        break;
                                    }
                                    let out_len = (payload.len() as u32).to_be_bytes();
                                    if send.write_all(&out_len).await.is_err() {
                                        break;
                                    }
                                    if send.write_all(&payload).await.is_err() {
                                        break;
                                    }
                                    eprintln!("[E2E_WT] echoed {} bytes", payload.len());
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    // ── WS accept loop (echo messages) ──
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = ws_listener.accept().await else {
                continue;
            };
            eprintln!("[E2E_WS] connection from {peer}");
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Text(_) | Message::Binary(_) => {
                            if sink.send(msg).await.is_err() {
                                break;
                            }
                            eprintln!("[E2E_WS] echoed message");
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    });

    // Wait for stdin close (harness closes pipe to signal exit)
    tokio::task::spawn_blocking(|| {
        use std::io::Read;
        let mut buf = [0u8; 1];
        let _ = std::io::stdin().read(&mut buf);
    })
    .await?;

    eprintln!("[E2E_SERVER] shutting down");
    Ok(())
}

#[cfg(not(all(feature = "transport-webtransport", feature = "transport-ws")))]
fn main() {
    eprintln!("Requires: --features transport-webtransport,transport-ws");
    std::process::exit(1);
}
