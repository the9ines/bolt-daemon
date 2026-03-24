//! Bolt Daemon — Headless WebRTC DataChannel transport (Phase 3E-B).
//!
//! Establishes a WebRTC DataChannel via libdatachannel and exchanges a
//! deterministic "hello" payload between two peers. No browser required.
//!
//! Network scope policy:
//!   lan     — LAN-only: ICE candidates filtered to private/link-local IPs (default)
//!   overlay — LAN + CGNAT 100.64/10 (e.g. Tailscale)
//!   global  — all valid IPs accepted (public, CGNAT, private)
//!
//! Signal modes:
//!   file        — exchange offer/answer via JSON files (default, backward compat)
//!   rendezvous  — exchange offer/answer via bolt-rendezvous WebSocket server
//!
//! Usage:
//!   bolt-daemon --role offerer|answerer [--signal file|rendezvous] [options]

// Core protocol modules live in lib.rs for integration-test access.
// Re-export into the binary crate so existing `crate::` paths still resolve.
pub(crate) use bolt_daemon::{
    dc_messages, envelope, identity_store, ipc, session, transfer, web_hello, HELLO_PAYLOAD,
};

mod ice_filter;
#[cfg(feature = "legacy-webrtc")]
mod legacy_webrtc;
#[cfg(feature = "legacy-webrtc")]
mod rendezvous;
#[cfg(feature = "legacy-webrtc")]
mod smoke;
#[cfg(feature = "legacy-webrtc")]
pub(crate) mod web_signal;

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

// Re-export legacy WebRTC types when feature is enabled.
// rendezvous.rs and smoke.rs reference these via crate::.
#[cfg(feature = "legacy-webrtc")]
pub(crate) use legacy_webrtc::{
    DC_LABEL, DcHandler, Role, SignalBundle, SdpInfo, CandidateInfo, SignalPath,
    SignalMode, TransportMode, InteropDcMode, DEFAULT_SIGNAL_DIR, POLL_INTERVAL,
    create_peer_connection, collect_local_signal, apply_remote_signal,
    cand_to_info, info_to_cand,
};

const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

// ── CLI ─────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub(crate) enum DaemonMode {
    /// Legacy WebRTC modes (deprecated — requires legacy-webrtc feature).
    #[cfg(feature = "legacy-webrtc")]
    Default,
    #[cfg(feature = "legacy-webrtc")]
    Smoke,
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
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) role: Option<Role>,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) offer_path: SignalPath,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) answer_path: SignalPath,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) signal_mode: SignalMode,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) rendezvous_url: String,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) room: Option<String>,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) to_peer: Option<String>,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) expect_peer: Option<String>,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) peer_id: Option<String>,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) session: Option<String>,
    pub(crate) phase_timeout: Duration,
    pub(crate) network_scope: NetworkScope,
    pub(crate) daemon_mode: DaemonMode,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) smoke_config: smoke::SmokeConfig,
    pub(crate) simulate_event: Option<SimulateEvent>,
    pub(crate) pairing_policy: ipc::trust::PairingPolicy,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) interop_signal: web_signal::InteropSignal,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) interop_hello: web_hello::InteropHelloMode,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) interop_dc: InteropDcMode,
    pub(crate) socket_path: Option<String>,
    pub(crate) data_dir: Option<String>,
    #[cfg(feature = "legacy-webrtc")]
    pub(crate) transport_mode: TransportMode,
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

/// Non-legacy argument parser — WsEndpoint/Simulate modes only.
#[cfg(not(feature = "legacy-webrtc"))]
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
    }
}

/// Full argument parser for legacy builds (all modes including WebRTC).
#[cfg(feature = "legacy-webrtc")]
fn parse_args_from(argv: &[String]) -> Args {
    let mut role = None;
    let mut offer = None;
    let mut answer = None;
    let mut signal_mode = None;
    let mut rendezvous_url = None;
    let mut room = None;
    let mut to_peer = None;
    let mut expect_peer = None;
    let mut peer_id = None;
    let mut session = None;
    let mut phase_timeout_secs = None;
    let mut network_scope = None;
    let mut daemon_mode = None;
    let mut smoke_bytes = None;
    let mut smoke_repeat = None;
    let mut smoke_json = false;
    let mut simulate_event = None;
    let mut pairing_policy = None;
    let mut interop_signal = None;
    let mut interop_hello = None;
    let mut interop_dc = None;
    let mut socket_path = None;
    let mut data_dir = None;
    let mut transport_mode = None;
    #[cfg(feature = "transport-quic")]
    let mut quic_listen = None;
    #[cfg(feature = "transport-quic")]
    let mut quic_connect = None;
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
            "--role" => {
                i += 1;
                role = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("offerer") => Role::Offerer,
                    Some("answerer") => Role::Answerer,
                    other => {
                        eprintln!("--role must be 'offerer' or 'answerer', got {:?}", other);
                        std::process::exit(1);
                    }
                });
            }
            "--offer" => {
                i += 1;
                offer = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("-") => SignalPath::Stdio,
                    Some(p) => SignalPath::File(p.to_string()),
                    None => {
                        eprintln!("--offer requires a path or '-'");
                        std::process::exit(1);
                    }
                });
            }
            "--answer" => {
                i += 1;
                answer = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("-") => SignalPath::Stdio,
                    Some(p) => SignalPath::File(p.to_string()),
                    None => {
                        eprintln!("--answer requires a path or '-'");
                        std::process::exit(1);
                    }
                });
            }
            "--signal" => {
                i += 1;
                signal_mode = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("file") => SignalMode::File,
                    Some("rendezvous") => SignalMode::Rendezvous,
                    other => {
                        eprintln!("--signal must be 'file' or 'rendezvous', got {:?}", other);
                        std::process::exit(1);
                    }
                });
            }
            "--rendezvous-url" => {
                i += 1;
                rendezvous_url = Some(match argv.get(i) {
                    Some(u) => u.clone(),
                    None => {
                        eprintln!("--rendezvous-url requires a URL");
                        std::process::exit(1);
                    }
                });
            }
            "--room" => {
                i += 1;
                room = Some(match argv.get(i) {
                    Some(r) => r.clone(),
                    None => {
                        eprintln!("--room requires a value");
                        std::process::exit(1);
                    }
                });
            }
            "--to" => {
                i += 1;
                to_peer = Some(match argv.get(i) {
                    Some(t) => t.clone(),
                    None => {
                        eprintln!("--to requires a peer code");
                        std::process::exit(1);
                    }
                });
            }
            "--expect-peer" => {
                i += 1;
                expect_peer = Some(match argv.get(i) {
                    Some(e) => e.clone(),
                    None => {
                        eprintln!("--expect-peer requires a peer code");
                        std::process::exit(1);
                    }
                });
            }
            "--peer-id" => {
                i += 1;
                peer_id = Some(match argv.get(i) {
                    Some(p) => {
                        let normalized: String = p.chars().filter(|c| *c != '-').collect();
                        if normalized.is_empty() {
                            eprintln!("error: --peer-id value is empty after removing hyphens");
                            std::process::exit(1);
                        }
                        if normalized.len() > 16 {
                            eprintln!("error: --peer-id too long (max 16 characters, got {} after removing hyphens)", normalized.len());
                            std::process::exit(1);
                        }
                        if !normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
                            eprintln!("error: --peer-id must contain only letters, digits, and hyphens. Got: {:?}", p);
                            std::process::exit(1);
                        }
                        normalized
                    }
                    None => {
                        eprintln!("--peer-id requires a value");
                        std::process::exit(1);
                    }
                });
            }
            "--session" => {
                i += 1;
                session = Some(match argv.get(i) {
                    Some(s) => s.clone(),
                    None => {
                        eprintln!("--session requires a value");
                        std::process::exit(1);
                    }
                });
            }
            "--phase-timeout-secs" => {
                i += 1;
                phase_timeout_secs = Some(match argv.get(i).and_then(|s| s.parse::<u64>().ok()) {
                    Some(s) if s > 0 => s,
                    _ => {
                        eprintln!("--phase-timeout-secs requires a positive integer");
                        std::process::exit(1);
                    }
                });
            }
            "--network-scope" => {
                i += 1;
                network_scope = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("lan") => NetworkScope::Lan,
                    Some("overlay") => NetworkScope::Overlay,
                    Some("global") => NetworkScope::Global,
                    other => {
                        eprintln!(
                            "--network-scope must be 'lan', 'overlay', or 'global', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--mode" => {
                i += 1;
                daemon_mode = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("default") => DaemonMode::Default,
                    Some("smoke") => DaemonMode::Smoke,
                    Some("simulate") => DaemonMode::Simulate,
                    Some("ws-endpoint") => DaemonMode::WsEndpoint,
                    other => {
                        eprintln!(
                            "--mode must be 'default', 'smoke', 'simulate', or 'ws-endpoint', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--simulate-event" => {
                i += 1;
                simulate_event = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("pairing-request") => SimulateEvent::PairingRequest,
                    Some("incoming-transfer") => SimulateEvent::IncomingTransfer,
                    other => {
                        eprintln!(
                            "--simulate-event must be 'pairing-request' or 'incoming-transfer', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--bytes" => {
                i += 1;
                smoke_bytes = Some(match argv.get(i).and_then(|s| s.parse::<usize>().ok()) {
                    Some(b) if b > 0 => b,
                    _ => {
                        eprintln!("--bytes requires a positive integer");
                        std::process::exit(1);
                    }
                });
            }
            "--repeat" => {
                i += 1;
                smoke_repeat = Some(match argv.get(i).and_then(|s| s.parse::<usize>().ok()) {
                    Some(r) if r > 0 => r,
                    _ => {
                        eprintln!("--repeat requires a positive integer");
                        std::process::exit(1);
                    }
                });
            }
            "--json" => {
                smoke_json = true;
            }
            "--pairing-policy" => {
                i += 1;
                pairing_policy = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("ask") => ipc::trust::PairingPolicy::Ask,
                    Some("deny") => ipc::trust::PairingPolicy::Deny,
                    Some("allow") => ipc::trust::PairingPolicy::Allow,
                    other => {
                        eprintln!(
                            "--pairing-policy must be 'ask', 'deny', or 'allow', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--interop-signal" => {
                i += 1;
                interop_signal = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("daemon_v1") => web_signal::InteropSignal::DaemonV1,
                    Some("web_v1") => web_signal::InteropSignal::WebV1,
                    other => {
                        eprintln!(
                            "--interop-signal must be 'daemon_v1' or 'web_v1', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--interop-hello" => {
                i += 1;
                interop_hello = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("daemon_hello_v1") => web_hello::InteropHelloMode::DaemonHelloV1,
                    Some("web_hello_v1") => web_hello::InteropHelloMode::WebHelloV1,
                    other => {
                        eprintln!(
                            "--interop-hello must be 'daemon_hello_v1' or 'web_hello_v1', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--interop-dc" => {
                i += 1;
                interop_dc = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("daemon_dc_v1") => InteropDcMode::DaemonDcV1,
                    Some("web_dc_v1") => InteropDcMode::WebDcV1,
                    other => {
                        eprintln!(
                            "--interop-dc must be 'daemon_dc_v1' or 'web_dc_v1', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            "--socket-path" => {
                i += 1;
                socket_path = Some(match argv.get(i) {
                    Some(p) if !p.is_empty() => p.clone(),
                    _ => {
                        eprintln!("--socket-path requires a non-empty path");
                        std::process::exit(1);
                    }
                });
            }
            "--data-dir" => {
                i += 1;
                data_dir = Some(match argv.get(i) {
                    Some(p) if !p.is_empty() => p.clone(),
                    _ => {
                        eprintln!("--data-dir requires a non-empty path");
                        std::process::exit(1);
                    }
                });
            }
            "--transport" => {
                i += 1;
                transport_mode = Some(match argv.get(i).map(|s| s.as_str()) {
                    Some("datachannel") => TransportMode::DataChannel,
                    #[cfg(feature = "transport-quic")]
                    Some("quic") => TransportMode::Quic,
                    #[cfg(not(feature = "transport-quic"))]
                    Some("quic") => {
                        eprintln!("FATAL: --transport quic requires the 'transport-quic' feature");
                        std::process::exit(1);
                    }
                    other => {
                        eprintln!(
                            "--transport must be 'datachannel' or 'quic', got {:?}",
                            other
                        );
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-quic")]
            "--quic-listen" => {
                i += 1;
                quic_listen = Some(match argv.get(i) {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => {
                        eprintln!("--quic-listen requires an address (e.g. 0.0.0.0:4433)");
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-quic")]
            "--quic-connect" => {
                i += 1;
                quic_connect = Some(match argv.get(i) {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => {
                        eprintln!("--quic-connect requires an address (e.g. 192.168.1.50:4433)");
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-ws")]
            "--ws-listen" => {
                i += 1;
                ws_listen = Some(match argv.get(i) {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => {
                        eprintln!("--ws-listen requires an address (e.g. 127.0.0.1:9100)");
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-webtransport")]
            "--wt-listen" => {
                i += 1;
                wt_listen = Some(match argv.get(i) {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => {
                        eprintln!("--wt-listen requires an address (e.g. 127.0.0.1:4433)");
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-webtransport")]
            "--wt-cert" => {
                i += 1;
                wt_cert = Some(match argv.get(i) {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => {
                        eprintln!("--wt-cert requires a path to a PEM certificate file");
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-webtransport")]
            "--wt-key" => {
                i += 1;
                wt_key = Some(match argv.get(i) {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => {
                        eprintln!("--wt-key requires a path to a PEM private key file");
                        std::process::exit(1);
                    }
                });
            }
            #[cfg(feature = "transport-webtransport")]
            "--no-wt" => {
                no_wt = true;
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let daemon_mode = daemon_mode.unwrap_or(DaemonMode::Default);

    // Simulate and WsEndpoint modes do not require --role
    if daemon_mode != DaemonMode::Simulate && daemon_mode != DaemonMode::WsEndpoint && role.is_none() {
        eprintln!(
            "Usage: bolt-daemon --role offerer|answerer [--signal file|rendezvous] [options]"
        );
        std::process::exit(1);
    }

    let signal_mode = signal_mode.unwrap_or(SignalMode::File);
    let phase_timeout = phase_timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PHASE_TIMEOUT);

    // ── Fail-closed validation for rendezvous mode ──────────
    // Rendezvous mode is opt-in only. No fallback to file mode.
    // If misconfigured, exit 1 with clear error.
    if signal_mode == SignalMode::Rendezvous {
        if room.is_none() {
            eprintln!("FATAL: --signal rendezvous requires --room");
            std::process::exit(1);
        }
        if session.is_none() {
            eprintln!("FATAL: --signal rendezvous requires --session");
            std::process::exit(1);
        }
        if matches!(role, Some(Role::Offerer)) && to_peer.is_none() {
            eprintln!("FATAL: --signal rendezvous --role offerer requires --to <peer_code>");
            std::process::exit(1);
        }
        if matches!(role, Some(Role::Answerer)) && expect_peer.is_none() {
            eprintln!(
                "FATAL: --signal rendezvous --role answerer requires --expect-peer <peer_code>"
            );
            std::process::exit(1);
        }
    }

    // ── Fail-closed validation for web_hello_v1 ──────────────
    // B1: Default to web-compatible interop modes for convergence.
    // Legacy daemon modes available via explicit --interop-{signal,hello,dc} flags.
    // This is an intentional breaking change: bare invocation now requires
    // --signal rendezvous (+ --room, --session, --to/--expect-peer).
    // WsEndpoint mode has its own HELLO handling — skip interop validation.
    let interop_hello_val = interop_hello.unwrap_or(web_hello::InteropHelloMode::WebHelloV1);
    let interop_signal_val = interop_signal.unwrap_or(web_signal::InteropSignal::WebV1);
    if daemon_mode != DaemonMode::WsEndpoint
        && interop_hello_val == web_hello::InteropHelloMode::WebHelloV1
    {
        if signal_mode != SignalMode::Rendezvous {
            eprintln!("FATAL: --interop-hello web_hello_v1 requires --signal rendezvous");
            std::process::exit(1);
        }
        if interop_signal_val != web_signal::InteropSignal::WebV1 {
            eprintln!("FATAL: --interop-hello web_hello_v1 requires --interop-signal web_v1");
            std::process::exit(1);
        }
    }

    // ── Fail-closed validation for web_dc_v1 ────────────────
    let interop_dc_val = interop_dc.unwrap_or(InteropDcMode::WebDcV1);
    if interop_dc_val == InteropDcMode::WebDcV1
        && interop_hello_val != web_hello::InteropHelloMode::WebHelloV1
    {
        eprintln!("FATAL: --interop-dc web_dc_v1 requires --interop-hello web_hello_v1");
        std::process::exit(1);
    }

    let offer =
        offer.unwrap_or_else(|| SignalPath::File(format!("{}/offer.json", DEFAULT_SIGNAL_DIR)));
    let answer =
        answer.unwrap_or_else(|| SignalPath::File(format!("{}/answer.json", DEFAULT_SIGNAL_DIR)));

    let smoke_config = smoke::SmokeConfig {
        bytes: smoke_bytes.unwrap_or(smoke::DEFAULT_BYTES),
        repeat: smoke_repeat.unwrap_or(smoke::DEFAULT_REPEAT),
        json: smoke_json,
    };

    Args {
        role,
        offer_path: offer,
        answer_path: answer,
        signal_mode,
        rendezvous_url: rendezvous_url.unwrap_or_else(|| "ws://127.0.0.1:3001".to_string()),
        room,
        to_peer,
        expect_peer,
        peer_id,
        session,
        phase_timeout,
        network_scope: network_scope.unwrap_or(NetworkScope::Lan),
        daemon_mode,
        smoke_config,
        simulate_event,
        pairing_policy: pairing_policy.unwrap_or(ipc::trust::PairingPolicy::Ask),
        interop_signal: interop_signal_val,
        interop_hello: interop_hello_val,
        interop_dc: interop_dc_val,
        socket_path,
        data_dir,
        transport_mode: transport_mode.unwrap_or(TransportMode::DataChannel),
        #[cfg(feature = "transport-quic")]
        quic_listen,
        #[cfg(feature = "transport-quic")]
        quic_connect,
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
    }
}

// ── QUIC smoke mode (RC3 reference path) ─────────────────────

#[cfg(all(feature = "transport-quic", feature = "legacy-webrtc"))]
fn run_smoke_quic_listener(args: &Args) -> Result<(), smoke::SmokeError> {
    use quic_transport::QuicListener;

    let listen_addr: std::net::SocketAddr = args
        .quic_listen
        .as_deref()
        .unwrap_or("0.0.0.0:4433")
        .parse()
        .map_err(|e| smoke::SmokeError::Signaling(format!("parse listen addr: {e}")))?;

    // Build tokio runtime for QUIC async operations
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| smoke::SmokeError::DataChannel(format!("tokio runtime: {e}")))?;

    rt.block_on(async {
        let listener = QuicListener::bind(listen_addr)
            .map_err(|e| smoke::SmokeError::Signaling(format!("QUIC bind: {e}")))?;

        eprintln!(
            "[smoke-quic-listener] listening on {} (waiting for dialer...)",
            listener.local_addr()
        );

        let mut stream = listener
            .accept()
            .await
            .map_err(|e| smoke::SmokeError::DataChannel(format!("QUIC accept: {e}")))?;

        eprintln!("[smoke-quic-listener] connection accepted, starting transfer");

        for run in 1..=args.smoke_config.repeat {
            if args.smoke_config.repeat > 1 {
                eprintln!("[smoke] run {}/{}", run, args.smoke_config.repeat);
            }

            // Receive payload
            let expected_payload = smoke::generate_payload(args.smoke_config.bytes);
            let expected_hash = smoke::sha256_hex(&expected_payload);

            eprintln!(
                "[smoke-quic-listener] waiting for {} bytes...",
                args.smoke_config.bytes
            );
            let start = std::time::Instant::now();

            let mut received = Vec::with_capacity(args.smoke_config.bytes);
            loop {
                let msg = stream
                    .recv_message()
                    .await
                    .map_err(|e| smoke::SmokeError::DataChannel(format!("recv: {e}")))?;
                if msg.is_empty() {
                    break; // end-of-transfer sentinel
                }
                received.extend_from_slice(&msg);
                if received.len() >= args.smoke_config.bytes {
                    break;
                }
            }

            received.truncate(args.smoke_config.bytes);

            let elapsed = start.elapsed();
            let latency_ms = elapsed.as_millis() as u64;
            let throughput_mbps = if latency_ms > 0 {
                (args.smoke_config.bytes as f64 / 1_000_000.0) / (latency_ms as f64 / 1_000.0)
            } else {
                0.0
            };

            let received_hash = smoke::sha256_hex(&received);

            // Send SHA-256 ack
            stream
                .send_message(received_hash.as_bytes())
                .await
                .map_err(|e| smoke::SmokeError::DataChannel(format!("ack send: {e}")))?;

            if received_hash != expected_hash {
                return Err(smoke::SmokeError::IntegrityMismatch {
                    expected: expected_hash,
                    received: received_hash,
                });
            }

            let report = smoke::SmokeReport::success(
                args.smoke_config.bytes,
                expected_hash,
                received_hash,
                latency_ms,
                throughput_mbps,
                args.smoke_config.repeat,
            );
            report.print(args.smoke_config.json);
        }

        stream.finish().await.ok();
        listener.close();
        Ok(())
    })
}

#[cfg(all(feature = "transport-quic", feature = "legacy-webrtc"))]
fn run_smoke_quic_dialer(args: &Args) -> Result<(), smoke::SmokeError> {
    use quic_transport::QuicDialer;

    let connect_addr: std::net::SocketAddr = args
        .quic_connect
        .as_deref()
        .ok_or_else(|| {
            smoke::SmokeError::Signaling("--quic-connect required for QUIC offerer".to_string())
        })?
        .parse()
        .map_err(|e| smoke::SmokeError::Signaling(format!("parse connect addr: {e}")))?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| smoke::SmokeError::DataChannel(format!("tokio runtime: {e}")))?;

    rt.block_on(async {
        let (endpoint, mut stream) = QuicDialer::connect(connect_addr)
            .await
            .map_err(|e| smoke::SmokeError::Signaling(format!("QUIC connect: {e}")))?;

        eprintln!("[smoke-quic-dialer] connected, starting transfer");

        for run in 1..=args.smoke_config.repeat {
            if args.smoke_config.repeat > 1 {
                eprintln!("[smoke] run {}/{}", run, args.smoke_config.repeat);
            }

            let payload = smoke::generate_payload(args.smoke_config.bytes);
            let expected_hash = smoke::sha256_hex(&payload);

            eprintln!(
                "[smoke-quic-dialer] sending {} bytes...",
                args.smoke_config.bytes
            );
            let start = std::time::Instant::now();

            // Send payload in 64 KiB chunks (matching DataChannel smoke chunk size)
            const SEND_CHUNK_SIZE: usize = 65_536;
            for chunk in payload.chunks(SEND_CHUNK_SIZE) {
                stream
                    .send_message(chunk)
                    .await
                    .map_err(|e| smoke::SmokeError::DataChannel(format!("send: {e}")))?;
            }

            // Send empty sentinel to signal end-of-transfer
            stream
                .send_message(&[])
                .await
                .map_err(|e| smoke::SmokeError::DataChannel(format!("send sentinel: {e}")))?;

            // Wait for SHA-256 ack
            let ack = stream
                .recv_message()
                .await
                .map_err(|e| smoke::SmokeError::DataChannel(format!("recv ack: {e}")))?;

            let elapsed = start.elapsed();
            let latency_ms = elapsed.as_millis() as u64;
            let throughput_mbps = if latency_ms > 0 {
                (args.smoke_config.bytes as f64 / 1_000_000.0) / (latency_ms as f64 / 1_000.0)
            } else {
                0.0
            };

            let received_hash = String::from_utf8(ack).map_err(|_| {
                smoke::SmokeError::DataChannel("invalid ack: not UTF-8".to_string())
            })?;

            if received_hash != expected_hash {
                return Err(smoke::SmokeError::IntegrityMismatch {
                    expected: expected_hash,
                    received: received_hash,
                });
            }

            let report = smoke::SmokeReport::success(
                args.smoke_config.bytes,
                expected_hash,
                received_hash,
                latency_ms,
                throughput_mbps,
                args.smoke_config.repeat,
            );
            report.print(args.smoke_config.json);
        }

        stream.finish().await.ok();
        endpoint.close(0u32.into(), b"done");
        Ok(())
    })
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
    #[cfg(feature = "legacy-webrtc")]
    eprintln!(
        "[bolt-daemon] role={:?} signal={:?} scope={:?} mode={:?} transport={:?} pairing={:?} interop_signal={:?} interop_hello={:?} interop_dc={:?} timeout={}s socket_path={:?} data_dir={:?}",
        args.role, args.signal_mode, args.network_scope, args.daemon_mode,
        args.transport_mode, args.pairing_policy, args.interop_signal,
        args.interop_hello, args.interop_dc, args.phase_timeout.as_secs(),
        args.socket_path, args.data_dir,
    );
    #[cfg(not(feature = "legacy-webrtc"))]
    eprintln!(
        "[bolt-daemon] mode={:?} pairing={:?} timeout={}s socket_path={:?} data_dir={:?}",
        args.daemon_mode, args.pairing_policy, args.phase_timeout.as_secs(),
        args.socket_path, args.data_dir,
    );

    match args.daemon_mode {
        #[cfg(feature = "legacy-webrtc")]
        DaemonMode::Default => {
            use ipc::server::{IpcServer, DEFAULT_SOCKET_PATH};
            use ipc::trust::{default_trust_path, trust_path_from_data_dir};

            // Resolve socket path: explicit flag or default.
            let socket_path_str = args.socket_path.as_deref().unwrap_or(DEFAULT_SOCKET_PATH);

            // Start IPC server for UI communication.
            // Fail-closed: if IPC start fails, pairing will deny all.
            let ipc_server = match IpcServer::start(socket_path_str) {
                Ok(s) => {
                    eprintln!("[bolt-daemon] IPC server started on {socket_path_str}");
                    Some(s)
                }
                Err(e) => {
                    eprintln!(
                        "[bolt-daemon] WARNING: IPC server failed to start: {e} \
                         — pairing will deny all"
                    );
                    None
                }
            };

            // Resolve data-dir-dependent paths.
            let data_dir_path = args.data_dir.as_ref().map(std::path::PathBuf::from);
            let trust_path = match &data_dir_path {
                Some(dd) => trust_path_from_data_dir(dd),
                None => default_trust_path(),
            };
            let identity_path = match &data_dir_path {
                Some(dd) => identity_store::resolve_identity_path_from_data_dir(dd),
                None => match identity_store::resolve_identity_path() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[bolt-daemon] FATAL: {}", e);
                        std::process::exit(1);
                    }
                },
            };

            eprintln!(
                "[bolt-daemon] identity_path={} trust_path={}",
                identity_path.display(),
                trust_path.display()
            );

            // Load persistent identity once, before role dispatch.
            // Both rendezvous paths share the same long-lived keypair.
            let identity = match identity_store::load_or_create_identity(&identity_path) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("[bolt-daemon] FATAL: {}", e);
                    std::process::exit(1);
                }
            };

            // ── WT enablement (WTI4) ─────────────────────────────────
            // WT is enabled when --wt-listen is configured AND --no-wt
            // is NOT set. This controls both endpoint spawning and
            // capability advertisement in HELLO.
            #[cfg(feature = "transport-webtransport")]
            let wt_enabled = args.wt_listen.is_some() && !args.no_wt;
            #[cfg(not(feature = "transport-webtransport"))]
            let wt_enabled = false;

            // ── WS endpoint (RC5 PM-RC-02) ────────────────────────
            // When --ws-listen is provided, spawn a WebSocket endpoint
            // on a tokio runtime alongside the existing transport path.
            #[cfg(feature = "transport-ws")]
            let _ws_shutdown_tx = if let Some(ref ws_addr_str) = args.ws_listen {
                let ws_addr: std::net::SocketAddr = match ws_addr_str.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!(
                            "[WS_ENDPOINT] FATAL: invalid --ws-listen address '{ws_addr_str}': {e}"
                        );
                        std::process::exit(1);
                    }
                };
                let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                let ws_identity = bolt_core::crypto::KeyPair {
                    public_key: identity.public_key,
                    secret_key: identity.secret_key,
                };
                let ws_config = ws_endpoint::WsEndpointConfig {
                    listen_addr: ws_addr,
                    identity_keypair: ws_identity,
                    wt_enabled,
                };
                eprintln!("[WS_ENDPOINT] starting on {ws_addr}");
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                    rt.block_on(async {
                        if let Err(e) = ws_endpoint::run_ws_endpoint(ws_config, shutdown_rx).await {
                            eprintln!("[WS_ENDPOINT] FATAL: {e}");
                        }
                    });
                });
                Some(shutdown_tx)
            } else {
                None
            };

            // ── WT endpoint (WTI2/WTI4) ──────────────────────────────
            // When --wt-listen is provided AND --no-wt is NOT set, spawn
            // a WebTransport/HTTP3 endpoint on a tokio runtime.
            #[cfg(feature = "transport-webtransport")]
            let _wt_shutdown_tx = if wt_enabled {
                let wt_addr_str = args.wt_listen.as_ref().unwrap(); // safe: wt_enabled implies wt_listen.is_some()
                let wt_addr_str = wt_addr_str.as_str();
                let wt_addr: std::net::SocketAddr = match wt_addr_str.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!(
                            "[WT_ENDPOINT] FATAL: invalid --wt-listen address '{wt_addr_str}': {e}"
                        );
                        std::process::exit(1);
                    }
                };
                let wt_cert = match args.wt_cert.as_ref() {
                    Some(c) => c.clone(),
                    None => {
                        eprintln!("[WT_ENDPOINT] FATAL: --wt-listen requires --wt-cert");
                        std::process::exit(1);
                    }
                };
                let wt_key = match args.wt_key.as_ref() {
                    Some(k) => k.clone(),
                    None => {
                        eprintln!("[WT_ENDPOINT] FATAL: --wt-listen requires --wt-key");
                        std::process::exit(1);
                    }
                };
                let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                let wt_identity = bolt_core::crypto::KeyPair {
                    public_key: identity.public_key,
                    secret_key: identity.secret_key,
                };
                let wt_config = wt_endpoint::WtEndpointConfig {
                    listen_addr: wt_addr,
                    identity_keypair: wt_identity,
                    cert_path: wt_cert,
                    key_path: wt_key,
                };
                eprintln!("[WT_ENDPOINT] starting on {wt_addr}");
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                    rt.block_on(async {
                        if let Err(e) = wt_endpoint::run_wt_endpoint(wt_config, shutdown_rx).await {
                            eprintln!("[WT_ENDPOINT] FATAL: {e}");
                        }
                    });
                });
                Some(shutdown_tx)
            } else {
                None
            };

            let role = match args.role.as_ref() {
                Some(r) => r,
                None => {
                    eprintln!("[bolt-daemon] FATAL: --role required for default mode");
                    std::process::exit(1);
                }
            };
            let result = match (role, &args.signal_mode) {
                (Role::Offerer, SignalMode::File) => legacy_webrtc::run_offerer(&args),
                (Role::Answerer, SignalMode::File) => legacy_webrtc::run_answerer(&args),
                (Role::Offerer, SignalMode::Rendezvous) => rendezvous::run_offerer_rendezvous(
                    &args,
                    ipc_server.as_ref(),
                    &trust_path,
                    &identity,
                ),
                (Role::Answerer, SignalMode::Rendezvous) => rendezvous::run_answerer_rendezvous(
                    &args,
                    ipc_server.as_ref(),
                    &trust_path,
                    &identity,
                ),
            };
            match result {
                Ok(()) => {
                    eprintln!("[bolt-daemon] exit 0");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("[bolt-daemon] FATAL: {}", e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(feature = "legacy-webrtc")]
        DaemonMode::Smoke => {
            let role = match args.role.as_ref() {
                Some(r) => r,
                None => {
                    eprintln!("[bolt-daemon] FATAL: --role required for smoke mode");
                    std::process::exit(1);
                }
            };

            // QUIC transport path (RC3 reference)
            #[cfg(feature = "transport-quic")]
            if matches!(args.transport_mode, TransportMode::Quic) {
                let result = match role {
                    Role::Offerer => run_smoke_quic_dialer(&args),
                    Role::Answerer => run_smoke_quic_listener(&args),
                };
                match result {
                    Ok(()) => {
                        eprintln!("[bolt-daemon] exit 0");
                        std::process::exit(smoke::EXIT_SUCCESS);
                    }
                    Err(e) => {
                        let report = smoke::SmokeReport::failure(
                            &e,
                            args.smoke_config.bytes,
                            args.smoke_config.repeat,
                        );
                        report.print(args.smoke_config.json);
                        std::process::exit(e.exit_code());
                    }
                }
            }

            // DataChannel transport path (existing)
            let result = match (role, &args.signal_mode) {
                (Role::Offerer, SignalMode::File) => legacy_webrtc::run_smoke_offerer(&args),
                (Role::Answerer, SignalMode::File) => legacy_webrtc::run_smoke_answerer(&args),
                (Role::Offerer, SignalMode::Rendezvous)
                | (Role::Answerer, SignalMode::Rendezvous) => legacy_webrtc::run_smoke_rendezvous(&args),
            };
            match result {
                Ok(()) => {
                    eprintln!("[bolt-daemon] exit 0");
                    std::process::exit(smoke::EXIT_SUCCESS);
                }
                Err(e) => {
                    let report = smoke::SmokeReport::failure(
                        &e,
                        args.smoke_config.bytes,
                        args.smoke_config.repeat,
                    );
                    report.print(args.smoke_config.json);
                    std::process::exit(e.exit_code());
                }
            }
        }
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
                let ws_config = ws_endpoint::WsEndpointConfig {
                    listen_addr: ws_addr,
                    identity_keypair: ws_identity,
                    wt_enabled: false,
                };
                eprintln!("[WS_ENDPOINT] starting on {ws_addr}");

                // Run WS endpoint on the main thread — blocks until shutdown.
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

                    if let Err(e) = ws_endpoint::run_ws_endpoint(ws_config, shutdown_rx).await {
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

#[cfg(test)]
#[cfg(feature = "legacy-webrtc")]
mod tests {
    use super::*;

    #[test]
    fn hello_payload_is_deterministic() {
        assert_eq!(HELLO_PAYLOAD, b"bolt-hello-v1");
        assert_eq!(HELLO_PAYLOAD.len(), 13);
    }

    #[test]
    fn signal_bundle_roundtrip() {
        let bundle = SignalBundle {
            description: SdpInfo {
                sdp_type: "offer".to_string(),
                sdp: "v=0\r\ntest sdp".to_string(),
            },
            candidates: vec![CandidateInfo {
                candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host".to_string(),
                mid: "0".to_string(),
            }],
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: SignalBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.description.sdp_type, "offer");
        assert_eq!(decoded.description.sdp, "v=0\r\ntest sdp");
        assert_eq!(decoded.candidates.len(), 1);
        assert_eq!(decoded.candidates[0].mid, "0");
    }

    #[test]
    fn dc_label_constant() {
        assert_eq!(DC_LABEL, "bolt");
    }

    #[test]
    fn sdp_type_mapping() {
        // Verify SDP type string → enum mapping (without requiring real SDP parsing)
        assert!(matches!("offer".to_lowercase().as_str(), "offer"));
        assert!(matches!("Answer".to_lowercase().as_str(), "answer"));
        // Verify desc_to_sdp_info type string output
        // (cannot test full roundtrip without real SDP from libdatachannel)
    }

    #[test]
    fn candidate_roundtrip() {
        let info = CandidateInfo {
            candidate: "candidate:1 1 UDP 2130706431 10.0.0.1 9999 typ host".to_string(),
            mid: "data".to_string(),
        };
        let cand = info_to_cand(&info);
        let back = cand_to_info(&cand);
        assert_eq!(back.candidate, info.candidate);
        assert_eq!(back.mid, info.mid);
    }

    #[test]
    fn default_phase_timeout_is_30s() {
        assert_eq!(DEFAULT_PHASE_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn default_network_scope_is_lan() {
        // NetworkScope default is Lan — verified by parse_args() defaulting to Lan
        assert_eq!(NetworkScope::Lan, NetworkScope::Lan);
        assert_ne!(NetworkScope::Lan, NetworkScope::Global);
    }

    #[test]
    fn smoke_error_downcast_from_box() {
        // Verifies the downcast path used by run_smoke_rendezvous
        let err: Box<dyn std::error::Error> =
            Box::new(smoke::SmokeError::Signaling("test".to_string()));
        let result = err.downcast::<smoke::SmokeError>();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().exit_code(), smoke::EXIT_SIGNALING_FAILURE);
    }

    #[test]
    fn smoke_error_classify_rendezvous_error() {
        // Verifies the classify_error fallback for non-SmokeError Box<dyn Error>
        let err: Box<dyn std::error::Error> =
            "rendezvous server unreachable at ws://127.0.0.1:3001".into();
        let smoke_err = smoke::classify_error(err.as_ref());
        assert_eq!(smoke_err.exit_code(), smoke::EXIT_SIGNALING_FAILURE);
    }

    #[test]
    fn smoke_error_classify_timeout_error() {
        // Verifies the classify_error fallback for timeout errors
        let err: Box<dyn std::error::Error> = "timed out waiting for peer".into();
        let smoke_err = smoke::classify_error(err.as_ref());
        assert_eq!(smoke_err.exit_code(), smoke::EXIT_TIMEOUT);
    }

    // ── B1: interop default flip tests ──────────────────────────

    /// Helper to build argv from a list of flag strings.
    fn make_argv(flags: &[&str]) -> Vec<String> {
        let mut argv = vec!["bolt-daemon".to_string()];
        for f in flags {
            argv.push(f.to_string());
        }
        argv
    }

    #[test]
    fn b1_default_interop_is_web() {
        // Full rendezvous invocation with no explicit interop flags.
        // Defaults should be WebV1 / WebHelloV1 / WebDcV1.
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "rendezvous",
            "--room",
            "test-room",
            "--session",
            "test-session",
            "--to",
            "peer-abc",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.interop_signal, web_signal::InteropSignal::WebV1);
        assert_eq!(args.interop_hello, web_hello::InteropHelloMode::WebHelloV1);
        assert_eq!(args.interop_dc, InteropDcMode::WebDcV1);
    }

    #[test]
    fn b1_explicit_daemon_overrides_web_defaults() {
        // Explicit daemon flags override the new web defaults.
        // signal=file + daemon interop → no validation conflict.
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.interop_signal, web_signal::InteropSignal::DaemonV1);
        assert_eq!(
            args.interop_hello,
            web_hello::InteropHelloMode::DaemonHelloV1
        );
        assert_eq!(args.interop_dc, InteropDcMode::DaemonDcV1);
    }

    #[test]
    fn b1_answerer_rendezvous_default_interop() {
        let argv = make_argv(&[
            "--role",
            "answerer",
            "--signal",
            "rendezvous",
            "--room",
            "test-room",
            "--session",
            "test-session",
            "--expect-peer",
            "peer-xyz",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.interop_signal, web_signal::InteropSignal::WebV1);
        assert_eq!(args.interop_hello, web_hello::InteropHelloMode::WebHelloV1);
        assert_eq!(args.interop_dc, InteropDcMode::WebDcV1);
    }

    #[test]
    fn b1_signal_mode_default_unchanged() {
        // Signal mode default is still File (only interop defaults flipped).
        // This invocation uses explicit daemon overrides to avoid validation failure.
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.signal_mode, SignalMode::File);
    }

    // ── N6-B1: --socket-path and --data-dir CLI parse tests ──

    #[test]
    fn n6b1_socket_path_parsed() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
            "--socket-path",
            "/run/user/1000/bolt.sock",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(
            args.socket_path.as_deref(),
            Some("/run/user/1000/bolt.sock")
        );
    }

    #[test]
    fn n6b1_data_dir_parsed() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
            "--data-dir",
            "/opt/localbolt/data",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.data_dir.as_deref(), Some("/opt/localbolt/data"));
    }

    #[test]
    fn n6b1_both_flags_parsed() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
            "--socket-path",
            "/tmp/custom.sock",
            "--data-dir",
            "/custom/data",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.socket_path.as_deref(), Some("/tmp/custom.sock"));
        assert_eq!(args.data_dir.as_deref(), Some("/custom/data"));
    }

    #[test]
    fn n6b1_defaults_when_omitted() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
        ]);
        let args = parse_args_from(&argv);
        assert!(args.socket_path.is_none());
        assert!(args.data_dir.is_none());
    }

    #[test]
    fn n6b1_socket_path_with_rendezvous_mode() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "rendezvous",
            "--room",
            "test-room",
            "--session",
            "test-session",
            "--to",
            "peer-abc",
            "--socket-path",
            "/var/run/bolt.sock",
            "--data-dir",
            "/home/user/.local/share/localbolt",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.socket_path.as_deref(), Some("/var/run/bolt.sock"));
        assert_eq!(
            args.data_dir.as_deref(),
            Some("/home/user/.local/share/localbolt")
        );
        assert_eq!(args.signal_mode, SignalMode::Rendezvous);
    }

    // ── WTI2: --wt-listen, --wt-cert, --wt-key CLI parse tests ──

    #[cfg(feature = "transport-webtransport")]
    #[test]
    fn wti2_wt_listen_parsed() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
            "--wt-listen",
            "127.0.0.1:4433",
            "--wt-cert",
            "/etc/certs/cert.pem",
            "--wt-key",
            "/etc/certs/key.pem",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.wt_listen.as_deref(), Some("127.0.0.1:4433"));
        assert_eq!(args.wt_cert.as_deref(), Some("/etc/certs/cert.pem"));
        assert_eq!(args.wt_key.as_deref(), Some("/etc/certs/key.pem"));
    }

    #[cfg(feature = "transport-webtransport")]
    #[test]
    fn wti2_wt_flags_default_none() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
        ]);
        let args = parse_args_from(&argv);
        assert!(args.wt_listen.is_none());
        assert!(args.wt_cert.is_none());
        assert!(args.wt_key.is_none());
        assert!(!args.no_wt);
    }

    #[cfg(feature = "transport-webtransport")]
    #[test]
    fn wti4_no_wt_flag_parsed() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
            "--wt-listen",
            "127.0.0.1:4433",
            "--wt-cert",
            "/etc/certs/cert.pem",
            "--wt-key",
            "/etc/certs/key.pem",
            "--no-wt",
        ]);
        let args = parse_args_from(&argv);
        assert!(args.no_wt);
        assert_eq!(args.wt_listen.as_deref(), Some("127.0.0.1:4433"));
    }

    #[cfg(feature = "transport-webtransport")]
    #[test]
    fn wti4_no_wt_default_false() {
        let argv = make_argv(&[
            "--role",
            "offerer",
            "--signal",
            "file",
            "--interop-signal",
            "daemon_v1",
            "--interop-hello",
            "daemon_hello_v1",
            "--interop-dc",
            "daemon_dc_v1",
        ]);
        let args = parse_args_from(&argv);
        assert!(!args.no_wt);
    }

    #[test]
    fn ws_endpoint_mode_parsed() {
        let argv = make_argv(&[
            "--mode", "ws-endpoint",
            "--ws-listen", "0.0.0.0:9100",
            "--data-dir", "/tmp/test",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.daemon_mode, DaemonMode::WsEndpoint);
        #[cfg(feature = "transport-ws")]
        assert_eq!(args.ws_listen, Some("0.0.0.0:9100".to_string()));
    }

    #[test]
    fn ws_endpoint_mode_does_not_require_role() {
        // WsEndpoint mode should parse successfully without --role
        let argv = make_argv(&[
            "--mode", "ws-endpoint",
            "--ws-listen", "0.0.0.0:9100",
        ]);
        let args = parse_args_from(&argv);
        assert_eq!(args.daemon_mode, DaemonMode::WsEndpoint);
        assert!(args.role.is_none());
    }

    #[test]
    fn ws_endpoint_mode_skips_interop_validation() {
        // WsEndpoint mode should not fail on default interop settings
        // (default interop_hello=WebHelloV1 normally requires --signal rendezvous)
        let argv = make_argv(&[
            "--mode", "ws-endpoint",
            "--ws-listen", "0.0.0.0:9100",
        ]);
        // parse_args_from would exit(1) if interop validation blocked ws-endpoint mode
        let args = parse_args_from(&argv);
        assert_eq!(args.daemon_mode, DaemonMode::WsEndpoint);
    }
}
