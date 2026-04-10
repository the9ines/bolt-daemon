//! Bolt Daemon — local protocol authority for Bolt P2P file transfer.
//!
//! # Module Contract (MODULARITY-AUDITABILITY-1)
//!
//! **Modes:**
//! - `WsEndpoint` (default) — WS-only server for browser↔desktop direct transport
//! - `Simulate` — demo/test mode for IPC pairing flow
//!
//! **Zero WebRTC.** All WebRTC/DataChannel code removed (DEWEBRTC-2).
//! No `datachannel` or `webrtc-sdp` dependencies.
//!
//! **This file owns:** CLI parsing, mode dispatch, boot diagnostics.
//! **Delegates to:** ws_endpoint, wt_endpoint, simulate.

// Core protocol modules live in lib.rs for integration-test access.
// Re-export into the binary crate so existing `crate::` paths still resolve.
pub(crate) use bolt_daemon::{
    dc_messages, envelope, identity_store, ipc, session, transfer, web_hello, HELLO_PAYLOAD,
};

mod ice_filter;

#[cfg(feature = "transport-quic")]
mod quic_transport;

#[cfg(feature = "transport-ws")]
pub(crate) use bolt_daemon::ws_endpoint;

#[cfg(feature = "transport-webtransport")]
pub(crate) use bolt_daemon::wt_endpoint;

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub(crate) use ice_filter::NetworkScope;

const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

// ── CLI ─────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub(crate) enum DaemonMode {
    Simulate,
    /// WS-only serving mode — the forward architecture for direct transport.
    WsEndpoint,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SimulateEvent {
    PairingRequest,
    IncomingTransfer,
}

#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) phase_timeout: Duration,
    pub(crate) network_scope: NetworkScope,
    pub(crate) daemon_mode: DaemonMode,
    pub(crate) simulate_event: Option<SimulateEvent>,
    pub(crate) pairing_policy: ipc::trust::PairingPolicy,
    pub(crate) socket_path: Option<String>,
    pub(crate) data_dir: Option<String>,
    /// QUIC listen address (answerer, e.g. "0.0.0.0:4433").
    #[cfg(feature = "transport-quic")]
    pub(crate) quic_listen: Option<String>,
    /// QUIC connect address (offerer, e.g. "192.168.1.50:4433").
    #[cfg(feature = "transport-quic")]
    pub(crate) quic_connect: Option<String>,
    /// WebSocket listen address (e.g. "127.0.0.1:9100").
    /// When present, spawns a WS endpoint alongside the existing transport.
    #[cfg(feature = "transport-ws")]
    pub(crate) ws_listen: Option<String>,
    /// WebTransport listen address (e.g. "127.0.0.1:4433").
    /// When present, spawns a WebTransport/HTTP3 endpoint alongside existing transport.
    #[cfg(feature = "transport-webtransport")]
    pub(crate) wt_listen: Option<String>,
    /// Path to PEM-encoded TLS certificate for WebTransport.
    #[cfg(feature = "transport-webtransport")]
    pub(crate) wt_cert: Option<String>,
    /// Path to PEM-encoded TLS private key for WebTransport.
    #[cfg(feature = "transport-webtransport")]
    pub(crate) wt_key: Option<String>,
    /// Kill-switch: force-disable WebTransport even if --wt-listen is provided (WTI4).
    #[cfg(feature = "transport-webtransport")]
    pub(crate) no_wt: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    parse_args_from(&argv)
}

/// Argument parser — WsEndpoint/Simulate modes.
fn parse_args_from(argv: &[String]) -> Args {
    let mut daemon_mode = None;
    let mut simulate_event = None;
    let mut pairing_policy = None;
    let mut phase_timeout_secs: Option<u64> = None;
    let mut socket_path = None;
    let mut data_dir = None;
    #[cfg(feature = "transport-ws")]
    let mut ws_listen = None;
    #[cfg(feature = "transport-webtransport")]
    let mut wt_listen = None;
    #[cfg(feature = "transport-webtransport")]
    let mut wt_cert = None;
    #[cfg(feature = "transport-webtransport")]
    let mut wt_key = None;
    #[cfg(feature = "transport-webtransport")]
    let mut no_wt = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--mode" => {
                i += 1;
                daemon_mode = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("ws-endpoint") => DaemonMode::WsEndpoint,
                    Some("simulate") => DaemonMode::Simulate,
                    Some(other) => {
                        eprintln!("--mode '{other}' requires --features legacy-webrtc");
                        std::process::exit(1);
                    }
                    None => { eprintln!("--mode requires a value"); std::process::exit(1); }
                });
            }
            "--simulate-event" => {
                i += 1;
                simulate_event = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("pairing-request") => SimulateEvent::PairingRequest,
                    Some("incoming-transfer") => SimulateEvent::IncomingTransfer,
                    other => { eprintln!("--simulate-event: invalid {:?}", other); std::process::exit(1); }
                });
            }
            "--pairing-policy" => {
                i += 1;
                pairing_policy = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("ask") => ipc::trust::PairingPolicy::Ask,
                    Some("allow") => ipc::trust::PairingPolicy::Allow,
                    Some("deny") => ipc::trust::PairingPolicy::Deny,
                    other => { eprintln!("--pairing-policy: invalid {:?}", other); std::process::exit(1); }
                });
            }
            "--phase-timeout-secs" => { i += 1; phase_timeout_secs = argv.get(i).and_then(|s| s.parse().ok()); }
            "--socket-path" => { i += 1; socket_path = argv.get(i).cloned(); }
            "--data-dir" => { i += 1; data_dir = argv.get(i).cloned(); }
            #[cfg(feature = "transport-ws")]
            "--ws-listen" => { i += 1; ws_listen = argv.get(i).and_then(|s| if s.is_empty() { None } else { Some(s.clone()) }); }
            #[cfg(feature = "transport-webtransport")]
            "--wt-listen" => { i += 1; wt_listen = argv.get(i).cloned(); }
            #[cfg(feature = "transport-webtransport")]
            "--wt-cert" => { i += 1; wt_cert = argv.get(i).cloned(); }
            #[cfg(feature = "transport-webtransport")]
            "--wt-key" => { i += 1; wt_key = argv.get(i).cloned(); }
            #[cfg(feature = "transport-webtransport")]
            "--no-wt" => { no_wt = true; }
            other => {
                if other.starts_with("--role") || other.starts_with("--signal") || other.starts_with("--offer")
                    || other.starts_with("--answer") || other.starts_with("--interop") {
                    eprintln!("Legacy flag '{other}' requires --features legacy-webrtc");
                    std::process::exit(1);
                }
                if other.starts_with("--") {
                    if argv.get(i + 1).map_or(false, |v| !v.starts_with("--")) { i += 1; }
                }
            }
        }
        i += 1;
    }

    let daemon_mode = daemon_mode.unwrap_or(DaemonMode::WsEndpoint);
    let phase_timeout = phase_timeout_secs.map(Duration::from_secs).unwrap_or(DEFAULT_PHASE_TIMEOUT);

    Args {
        phase_timeout,
        network_scope: NetworkScope::Lan,
        daemon_mode,
        simulate_event,
        pairing_policy: pairing_policy.unwrap_or(ipc::trust::PairingPolicy::Ask),
        socket_path,
        data_dir,
        #[cfg(feature = "transport-ws")]
        ws_listen,
        #[cfg(feature = "transport-webtransport")]
        wt_listen,
        #[cfg(feature = "transport-webtransport")]
        wt_cert,
        #[cfg(feature = "transport-webtransport")]
        wt_key,
        #[cfg(feature = "transport-webtransport")]
        no_wt,
        #[cfg(feature = "transport-quic")]
        quic_listen: None,
        #[cfg(feature = "transport-quic")]
        quic_connect: None,
    }
}

// ── Simulate mode ────────────────────────────────────────────

fn run_simulate(simulate_event: SimulateEvent) {
    use ipc::server::{IpcServer, DEFAULT_SOCKET_PATH};
    use ipc::types::{IpcMessage, PairingRequestPayload, TransferIncomingRequestPayload};

    let server = match IpcServer::start(DEFAULT_SOCKET_PATH) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[simulate] FATAL: failed to start IPC server: {e}");
            std::process::exit(1);
        }
    };

    // Wait up to 10s for a client to connect
    eprintln!("[simulate] waiting for IPC client to connect...");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !server.is_ui_connected() {
        if std::time::Instant::now() >= deadline {
            eprintln!("[simulate] TIMEOUT: no IPC client connected within 10s");
            std::process::exit(1);
        }
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "[simulate] IPC client connected (version handshake + daemon.status handled by IPC server)"
    );

    // Emit the simulated event
    let request_id = ipc::id::generate_request_id();
    match simulate_event {
        SimulateEvent::PairingRequest => {
            let payload = PairingRequestPayload {
                request_id: request_id.clone(),
                remote_device_name: "Simulated iPhone 15".to_string(),
                remote_device_type: "mobile".to_string(),
                remote_identity_pk_b64: "c2ltdWxhdGVkLXB1YmxpYy1rZXk=".to_string(),
                sas: "482917".to_string(),
                capabilities_requested: vec!["file_transfer".to_string()],
            };
            eprintln!("[simulate] emitting pairing.request (request_id={request_id})");
            let payload_value = match serde_json::to_value(&payload) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[simulate] FATAL: serialize pairing.request: {e}");
                    std::process::exit(1);
                }
            };
            server.emit_event(IpcMessage::new_event("pairing.request", payload_value));
        }
        SimulateEvent::IncomingTransfer => {
            let payload = TransferIncomingRequestPayload {
                request_id: request_id.clone(),
                from_device_name: "Simulated MacBook Pro".to_string(),
                from_identity_pk_b64: "c2ltdWxhdGVkLXB1YmxpYy1rZXk=".to_string(),
                file_name: "test-document.pdf".to_string(),
                file_size_bytes: 2_097_152,
                sha256_hex: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ),
                mime: Some("application/pdf".to_string()),
            };
            eprintln!("[simulate] emitting transfer.incoming.request (request_id={request_id})");
            let payload_value = match serde_json::to_value(&payload) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[simulate] FATAL: serialize transfer.incoming.request: {e}");
                    std::process::exit(1);
                }
            };
            server.emit_event(IpcMessage::new_event(
                "transfer.incoming.request",
                payload_value,
            ));
        }
    }

    // Await decision with 30s timeout
    eprintln!("[simulate] awaiting decision for request_id={request_id} (30s timeout)...");
    match server.await_decision(&request_id, Duration::from_secs(30)) {
        Some(decision) => {
            eprintln!(
                "[simulate] decision received: {:?} (note: {:?})",
                decision.decision, decision.note
            );
            std::process::exit(0);
        }
        None => {
            eprintln!("[simulate] TIMEOUT: no decision received — fail-closed deny");
            std::process::exit(1);
        }
    }
}

// ── Entry ───────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    eprintln!(
        "[bolt-daemon] mode={:?} pairing={:?} timeout={}s socket_path={:?} data_dir={:?}",
        args.daemon_mode, args.pairing_policy, args.phase_timeout.as_secs(),
        args.socket_path, args.data_dir,
    );

    match args.daemon_mode {
        DaemonMode::Simulate => {
            let event = args.simulate_event.unwrap_or_else(|| {
                eprintln!("--simulate-event required in simulate mode");
                std::process::exit(1);
            });
            run_simulate(event);
        }
        DaemonMode::WsEndpoint => {
            // WS-only serving mode: start WS endpoint and stay alive.
            // No WebRTC/file-signal path. Used for browser↔desktop direct transport.
            use ipc::server::{IpcServer, DEFAULT_SOCKET_PATH};

            let socket_path_str = args.socket_path.as_deref().unwrap_or(DEFAULT_SOCKET_PATH);
            let ipc_server = match IpcServer::start(socket_path_str) {
                Ok(s) => {
                    eprintln!("[IPC] listening on {socket_path_str}");
                    Some(s)
                }
                Err(e) => {
                    eprintln!("[bolt-daemon] WARNING: IPC server failed: {e}");
                    None
                }
            };

            let ipc_event_tx = ipc_server.as_ref().map(|s| s.event_tx.clone());
            let _ipc_server = ipc_server;

            let data_dir_path = args.data_dir.as_ref().map(std::path::PathBuf::from);

            // File send signal: bolt-ui writes file path to data_dir/send_file.signal
            // The WS endpoint runtime polls for this file and sends it.
            let send_signal_path = data_dir_path
                .as_ref()
                .map(|dd| dd.join("send_file.signal"))
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp/bolt-send-file.signal"));
            let identity_path = match &data_dir_path {
                Some(dd) => identity_store::resolve_identity_path_from_data_dir(dd),
                None => match identity_store::resolve_identity_path() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[bolt-daemon] FATAL: {e}");
                        std::process::exit(1);
                    }
                },
            };
            let identity = match identity_store::load_or_create_identity(&identity_path) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("[bolt-daemon] FATAL: {e}");
                    std::process::exit(1);
                }
            };

            #[cfg(feature = "transport-ws")]
            let ws_addr_str = match args.ws_listen.as_ref() {
                Some(a) => a.clone(),
                None => {
                    eprintln!("[bolt-daemon] FATAL: --ws-listen required in ws-endpoint mode");
                    std::process::exit(1);
                }
            };

            #[cfg(feature = "transport-ws")]
            {
                let ws_addr: std::net::SocketAddr = match ws_addr_str.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("[WS_ENDPOINT] FATAL: invalid --ws-listen address '{ws_addr_str}': {e}");
                        std::process::exit(1);
                    }
                };
                let ws_identity = bolt_core::crypto::KeyPair {
                    public_key: identity.public_key,
                    secret_key: identity.secret_key,
                };
                // Generate ephemeral TLS cert for WebTransport (SECURE-DIRECT-1 SD1).
                // Cert is short-lived (13 days) for browser serverCertificateHashes.
                let wt_cert = match bolt_daemon::wt_cert::generate_ephemeral_cert() {
                    Ok(c) => {
                        eprintln!("[WT_CERT] hash={}", c.cert_hash_hex);
                        Some(c)
                    }
                    Err(e) => {
                        eprintln!("[WT_CERT] generation failed (WT disabled): {e}");
                        None
                    }
                };

                let wt_enabled = wt_cert.is_some();

                // Write WT metadata for native shell to read (W1 plumbing).
                if let (Some(ref cert), Some(ref dd)) = (&wt_cert, &data_dir_path) {
                    let wt_port = ws_addr.port() + 1;
                    let wt_info = serde_json::json!({
                        "wt_port": wt_port,
                        "wt_cert_hash": cert.cert_hash_hex,
                    });
                    let wt_info_path = dd.join("wt_info.json");
                    if let Err(e) = std::fs::write(&wt_info_path, wt_info.to_string()) {
                        eprintln!("[WT_INFO] failed to write {}: {e}", wt_info_path.display());
                    } else {
                        eprintln!("[WT_INFO] wrote {}", wt_info_path.display());
                    }
                }

                let ws_config = ws_endpoint::WsEndpointConfig {
                    listen_addr: ws_addr,
                    identity_keypair: ws_identity,
                    wt_enabled,
                };
                eprintln!("[WS_ENDPOINT] starting on {ws_addr}");

                // Run WS + WT endpoints on the main thread — blocks until shutdown.
                let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                let signal_path = send_signal_path.clone();
                rt.block_on(async {
                    // Spawn file-send signal watcher
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            if signal_path.exists() {
                                if let Ok(path_str) = std::fs::read_to_string(&signal_path) {
                                    let path_str = path_str.trim();
                                    let _ = std::fs::remove_file(&signal_path);
                                    if path_str.is_empty() {
                                        continue;
                                    }

                                    // Validate the file-to-send path
                                    if let Err(e) = ws_endpoint::validate_send_file_path(path_str) {
                                        eprintln!("[WS_TRANSFER] REJECTED send signal: {e}");
                                        continue;
                                    }

                                    eprintln!("[WS_TRANSFER] send signal: {path_str}");
                                    match ws_endpoint::send_file_to_browser(path_str) {
                                        Ok(()) => eprintln!("[WS_TRANSFER] send complete"),
                                        Err(e) => eprintln!("[WS_TRANSFER] send error: {e}"),
                                    }
                                }
                            }
                        }
                    });

                    // Spawn connect_remote.signal watcher (NATIVE-CONNECT-1)
                    let connect_signal_path = data_dir_path
                        .as_ref()
                        .map(|dd| dd.join("connect_remote.signal"))
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/bolt-connect-remote.signal"));
                    let connect_pk = identity.public_key;
                    let connect_sk = identity.secret_key;
                    let connect_ipc_tx = ipc_event_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            if connect_signal_path.exists() {
                                if let Ok(url_str) = std::fs::read_to_string(&connect_signal_path) {
                                    let url_str = url_str.trim().to_string();
                                    let _ = std::fs::remove_file(&connect_signal_path);
                                    if url_str.is_empty() {
                                        continue;
                                    }
                                    eprintln!("[WS_CLIENT] connect_remote signal: {url_str}");
                                    let id = bolt_core::crypto::KeyPair {
                                        public_key: connect_pk,
                                        secret_key: connect_sk,
                                    };
                                    let ipc = connect_ipc_tx.clone();
                                    tokio::spawn(async move {
                                        match ws_endpoint::connect_to_remote_ws(
                                            &url_str, &id, wt_enabled, ipc,
                                        ).await {
                                            Ok(()) => eprintln!("[WS_CLIENT] session ended normally"),
                                            Err(e) => eprintln!("[WS_CLIENT] session error: {e}"),
                                        }
                                    });
                                }
                            }
                        }
                    });

                    // Spawn disconnect_session.signal watcher (NATIVE-SESSION-UX-2)
                    let disconnect_signal_path = data_dir_path
                        .as_ref()
                        .map(|dd| dd.join("disconnect_session.signal"))
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/bolt-disconnect-session.signal"));
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                            if disconnect_signal_path.exists() {
                                let _ = std::fs::remove_file(&disconnect_signal_path);
                                ws_endpoint::request_disconnect();
                            }
                        }
                    });

                    // Spawn transfer pause/resume signal watchers (DAEMON-TRANSFER-CONTROL-1)
                    let pause_signal_path = data_dir_path
                        .as_ref()
                        .map(|dd| dd.join("transfer_pause.signal"))
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/bolt-transfer-pause.signal"));
                    let resume_signal_path = data_dir_path
                        .as_ref()
                        .map(|dd| dd.join("transfer_resume.signal"))
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/bolt-transfer-resume.signal"));
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                            if pause_signal_path.exists() {
                                let _ = std::fs::remove_file(&pause_signal_path);
                                ws_endpoint::request_pause();
                            }
                            if resume_signal_path.exists() {
                                let _ = std::fs::remove_file(&resume_signal_path);
                                ws_endpoint::request_resume();
                            }
                        }
                    });

                    // Spawn WT endpoint alongside WS if cert was generated
                    #[cfg(feature = "transport-webtransport")]
                    if let Some(ref cert) = wt_cert {
                        let wt_port = ws_addr.port() + 1; // WT on adjacent port
                        let wt_addr: std::net::SocketAddr = format!("0.0.0.0:{wt_port}")
                            .parse().expect("valid WT addr");
                        let wt_identity_kp = bolt_core::crypto::KeyPair {
                            public_key: identity.public_key,
                            secret_key: identity.secret_key,
                        };
                        let wt_config = wt_endpoint::WtEndpointConfig {
                            listen_addr: wt_addr,
                            identity_keypair: wt_identity_kp,
                            cert_path: cert.cert_pem_path.to_string_lossy().to_string(),
                            key_path: cert.key_pem_path.to_string_lossy().to_string(),
                        };
                        let wt_shutdown_rx = _shutdown_tx.subscribe();
                        tokio::spawn(async move {
                            if let Err(e) = wt_endpoint::run_wt_endpoint(wt_config, wt_shutdown_rx).await {
                                eprintln!("[WT_ENDPOINT] error: {e}");
                            }
                        });
                        eprintln!("[WT_ENDPOINT] starting on {wt_addr} (cert_hash={})", cert.cert_hash_hex);
                    }

                    if let Err(e) = ws_endpoint::run_ws_endpoint(ws_config, shutdown_rx, ipc_event_tx).await {
                        eprintln!("[WS_ENDPOINT] FATAL: {e}");
                        std::process::exit(1);
                    }
                });
            }

            #[cfg(not(feature = "transport-ws"))]
            {
                eprintln!("[bolt-daemon] FATAL: ws-endpoint mode requires transport-ws feature");
                std::process::exit(1);
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────

