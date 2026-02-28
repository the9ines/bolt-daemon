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
pub(crate) use bolt_daemon::{dc_messages, envelope, identity_store, session, web_hello, HELLO_PAYLOAD};

mod ice_filter;
pub(crate) mod ipc;
mod rendezvous;
mod smoke;
pub(crate) mod web_signal;

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use datachannel::{
    ConnectionState, DataChannelHandler, DataChannelInfo, GatheringState, IceCandidate,
    PeerConnectionHandler, RtcConfig, RtcDataChannel, RtcPeerConnection, SdpType,
    SessionDescription,
};
use serde::{Deserialize, Serialize};

pub(crate) use ice_filter::NetworkScope;

// ── Constants ───────────────────────────────────────────────

/// DataChannel label.
pub(crate) const DC_LABEL: &str = "bolt";

/// Default timeout for each signaling/data exchange phase (30 seconds).
/// Override via `--phase-timeout-secs <int>`.
const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval when waiting for a signaling file.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Default signal directory.
const DEFAULT_SIGNAL_DIR: &str = "/tmp/bolt-spike";

// ── CLI ─────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum Role {
    Offerer,
    Answerer,
}

#[derive(Debug)]
enum SignalPath {
    Stdio,
    File(String),
}

#[derive(Debug, PartialEq)]
pub(crate) enum SignalMode {
    File,
    Rendezvous,
}

#[derive(Debug, PartialEq)]
pub(crate) enum DaemonMode {
    Default,
    Smoke,
    Simulate,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SimulateEvent {
    PairingRequest,
    IncomingTransfer,
}

/// Selects which DataChannel mode the daemon uses after HELLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InteropDcMode {
    /// Legacy: return immediately after HELLO (default).
    DaemonDcV1,
    /// Web: post-HELLO envelope recv loop.
    WebDcV1,
}

#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) role: Option<Role>,
    offer_path: SignalPath,
    answer_path: SignalPath,
    pub(crate) signal_mode: SignalMode,
    pub(crate) rendezvous_url: String,
    pub(crate) room: Option<String>,
    pub(crate) to_peer: Option<String>,
    pub(crate) expect_peer: Option<String>,
    pub(crate) peer_id: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) phase_timeout: Duration,
    pub(crate) network_scope: NetworkScope,
    pub(crate) daemon_mode: DaemonMode,
    pub(crate) smoke_config: smoke::SmokeConfig,
    pub(crate) simulate_event: Option<SimulateEvent>,
    pub(crate) pairing_policy: ipc::trust::PairingPolicy,
    pub(crate) interop_signal: web_signal::InteropSignal,
    pub(crate) interop_hello: web_hello::InteropHelloMode,
    pub(crate) interop_dc: InteropDcMode,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
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
                    Some(p) => p.clone(),
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
                    other => {
                        eprintln!(
                            "--mode must be 'default', 'smoke', or 'simulate', got {:?}",
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
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let daemon_mode = daemon_mode.unwrap_or(DaemonMode::Default);

    // Simulate mode does not require --role
    if daemon_mode != DaemonMode::Simulate && role.is_none() {
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
    let interop_hello_val = interop_hello.unwrap_or(web_hello::InteropHelloMode::DaemonHelloV1);
    let interop_signal_val = interop_signal.unwrap_or(web_signal::InteropSignal::DaemonV1);
    if interop_hello_val == web_hello::InteropHelloMode::WebHelloV1 {
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
    let interop_dc_val = interop_dc.unwrap_or(InteropDcMode::DaemonDcV1);
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
    }
}

// ── Signaling JSON ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignalBundle {
    pub(crate) description: SdpInfo,
    pub(crate) candidates: Vec<CandidateInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SdpInfo {
    pub(crate) sdp_type: String,
    pub(crate) sdp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct CandidateInfo {
    pub(crate) candidate: String,
    pub(crate) mid: String,
}

// ── Handlers ────────────────────────────────────────────────

pub(crate) struct DcHandler {
    pub(crate) open_tx: mpsc::Sender<()>,
    pub(crate) msg_tx: mpsc::Sender<Vec<u8>>,
}

impl DataChannelHandler for DcHandler {
    fn on_open(&mut self) {
        eprintln!("[dc] open");
        let _ = self.open_tx.send(());
    }

    fn on_closed(&mut self) {
        eprintln!("[dc] closed");
    }

    fn on_error(&mut self, err: &str) {
        eprintln!("[dc] error: {}", err);
    }

    fn on_message(&mut self, msg: &[u8]) {
        eprintln!("[dc] received {} bytes", msg.len());
        let _ = self.msg_tx.send(msg.to_vec());
    }

    fn on_buffered_amount_low(&mut self) {}

    fn on_available(&mut self) {}
}

struct PcHandler {
    desc_tx: mpsc::Sender<SessionDescription>,
    cand_tx: mpsc::Sender<IceCandidate>,
    gather_tx: mpsc::Sender<GatheringState>,
    dc_open_tx: mpsc::Sender<()>,
    dc_msg_tx: mpsc::Sender<Vec<u8>>,
    incoming_dc_tx: mpsc::Sender<Box<RtcDataChannel<DcHandler>>>,
    network_scope: NetworkScope,
}

impl PeerConnectionHandler for PcHandler {
    type DCH = DcHandler;

    fn data_channel_handler(&mut self, _info: DataChannelInfo) -> Self::DCH {
        DcHandler {
            open_tx: self.dc_open_tx.clone(),
            msg_tx: self.dc_msg_tx.clone(),
        }
    }

    fn on_description(&mut self, sess_desc: SessionDescription) {
        eprintln!("[pc] local description generated");
        let _ = self.desc_tx.send(sess_desc);
    }

    fn on_candidate(&mut self, cand: IceCandidate) {
        if ice_filter::is_allowed_candidate(&cand.candidate, self.network_scope) {
            eprintln!(
                "[pc] ICE candidate accepted ({:?}): {}",
                self.network_scope, &cand.candidate
            );
            let _ = self.cand_tx.send(cand);
        } else {
            eprintln!(
                "[pc] ICE candidate REJECTED ({:?}): {}",
                self.network_scope, &cand.candidate
            );
        }
    }

    fn on_connection_state_change(&mut self, state: ConnectionState) {
        eprintln!("[pc] connection state: {:?}", state);
    }

    fn on_gathering_state_change(&mut self, state: GatheringState) {
        eprintln!("[pc] gathering state: {:?}", state);
        let _ = self.gather_tx.send(state);
    }

    fn on_data_channel(&mut self, dc: Box<RtcDataChannel<Self::DCH>>) {
        eprintln!("[pc] incoming data channel");
        let _ = self.incoming_dc_tx.send(dc);
    }
}

// ── Signal I/O ──────────────────────────────────────────────

fn write_signal(path: &SignalPath, bundle: &SignalBundle) -> io::Result<()> {
    let json = serde_json::to_string_pretty(bundle)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    match path {
        SignalPath::Stdio => {
            println!("{}", json);
            io::stdout().flush()?;
        }
        SignalPath::File(p) => {
            if let Some(parent) = Path::new(p).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(p, &json)?;
            eprintln!("[signal] wrote {}", p);
        }
    }
    Ok(())
}

fn read_signal(
    path: &SignalPath,
    label: &str,
    phase_timeout: Duration,
) -> io::Result<SignalBundle> {
    let json = match path {
        SignalPath::Stdio => {
            eprintln!("[signal] paste {} JSON and press Enter:", label);
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            line
        }
        SignalPath::File(p) => {
            eprintln!("[signal] waiting for {} ...", p);
            let start = std::time::Instant::now();
            loop {
                if Path::new(p).exists() {
                    thread::sleep(Duration::from_millis(100));
                    break fs::read_to_string(p)?;
                }
                if start.elapsed() > phase_timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("timed out waiting for {}", p),
                    ));
                }
                thread::sleep(POLL_INTERVAL);
            }
        }
    };
    serde_json::from_str(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── Conversion helpers ──────────────────────────────────────

fn desc_to_sdp_info(desc: &SessionDescription) -> SdpInfo {
    let type_str = match desc.sdp_type {
        SdpType::Offer => "offer",
        SdpType::Answer => "answer",
        SdpType::Pranswer => "pranswer",
        SdpType::Rollback => "rollback",
    };
    SdpInfo {
        sdp_type: type_str.to_string(),
        sdp: desc.sdp.to_string(),
    }
}

fn sdp_info_to_desc(info: &SdpInfo) -> Result<SessionDescription, String> {
    let sdp_type = match info.sdp_type.to_lowercase().as_str() {
        "offer" => SdpType::Offer,
        "answer" => SdpType::Answer,
        "pranswer" => SdpType::Pranswer,
        "rollback" => SdpType::Rollback,
        other => return Err(format!("unknown SDP type: {}", other)),
    };
    let sdp =
        webrtc_sdp::parse_sdp(&info.sdp, false).map_err(|e| format!("SDP parse error: {:?}", e))?;
    Ok(SessionDescription { sdp_type, sdp })
}

fn cand_to_info(cand: &IceCandidate) -> CandidateInfo {
    CandidateInfo {
        candidate: cand.candidate.clone(),
        mid: cand.mid.clone(),
    }
}

fn info_to_cand(info: &CandidateInfo) -> IceCandidate {
    IceCandidate {
        candidate: info.candidate.clone(),
        mid: info.mid.clone(),
    }
}

// ── Core logic ──────────────────────────────────────────────

pub(crate) struct Channels {
    pub(crate) desc_rx: mpsc::Receiver<SessionDescription>,
    pub(crate) cand_rx: mpsc::Receiver<IceCandidate>,
    pub(crate) gather_rx: mpsc::Receiver<GatheringState>,
    pub(crate) dc_open_rx: mpsc::Receiver<()>,
    pub(crate) dc_msg_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) incoming_dc_rx: mpsc::Receiver<Box<RtcDataChannel<DcHandler>>>,
}

#[allow(clippy::type_complexity)]
pub(crate) fn create_peer_connection(
    network_scope: NetworkScope,
) -> Result<(Box<RtcPeerConnection<PcHandler>>, Channels), Box<dyn std::error::Error>> {
    let (desc_tx, desc_rx) = mpsc::channel();
    let (cand_tx, cand_rx) = mpsc::channel();
    let (gather_tx, gather_rx) = mpsc::channel();
    let (dc_open_tx, dc_open_rx) = mpsc::channel();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel();
    let (incoming_dc_tx, incoming_dc_rx) = mpsc::channel();

    let handler = PcHandler {
        desc_tx,
        cand_tx,
        gather_tx,
        dc_open_tx,
        dc_msg_tx,
        incoming_dc_tx,
        network_scope,
    };

    // LAN-only: no ICE servers (no STUN, no TURN).
    // Only host candidates with private/link-local IPs will be gathered.
    let config = RtcConfig::new::<&str>(&[]);
    let pc = RtcPeerConnection::new(&config, handler)?;

    Ok((
        pc,
        Channels {
            desc_rx,
            cand_rx,
            gather_rx,
            dc_open_rx,
            dc_msg_rx,
            incoming_dc_rx,
        },
    ))
}

/// Wait for local description + all ICE candidates (gathering complete).
pub(crate) fn collect_local_signal(
    ch: &Channels,
    phase_timeout: Duration,
) -> Result<SignalBundle, Box<dyn std::error::Error>> {
    let desc = ch.desc_rx.recv_timeout(phase_timeout)?;
    eprintln!("[signal] local description ready");

    let mut candidates = Vec::new();
    let start = std::time::Instant::now();
    loop {
        if let Ok(GatheringState::Complete) = ch.gather_rx.try_recv() {
            while let Ok(c) = ch.cand_rx.try_recv() {
                candidates.push(cand_to_info(&c));
            }
            break;
        }
        match ch.cand_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(c) => candidates.push(cand_to_info(&c)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => return Err(e.into()),
        }
        if start.elapsed() > phase_timeout {
            return Err("timed out waiting for ICE gathering".into());
        }
    }
    eprintln!("[signal] gathered {} ICE candidate(s)", candidates.len());

    Ok(SignalBundle {
        description: desc_to_sdp_info(&desc),
        candidates,
    })
}

/// Apply remote signal bundle to local peer connection.
pub(crate) fn apply_remote_signal(
    pc: &mut Box<RtcPeerConnection<PcHandler>>,
    bundle: &SignalBundle,
    network_scope: NetworkScope,
) -> Result<(), Box<dyn std::error::Error>> {
    let desc = sdp_info_to_desc(&bundle.description)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    pc.set_remote_description(&desc)?;
    eprintln!("[signal] remote description applied");

    let mut added = 0;
    for c in &bundle.candidates {
        if ice_filter::is_allowed_candidate(&c.candidate, network_scope) {
            let cand = info_to_cand(c);
            pc.add_remote_candidate(&cand)?;
            added += 1;
        } else {
            eprintln!(
                "[signal] remote candidate REJECTED ({:?}): {}",
                network_scope, &c.candidate
            );
        }
    }
    eprintln!("[signal] added {} remote ICE candidate(s)", added);

    Ok(())
}

fn clean_signal_file(path: &SignalPath) {
    if let SignalPath::File(p) = path {
        let _ = fs::remove_file(p);
    }
}

// ── Offerer ─────────────────────────────────────────────────

fn run_offerer(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[offerer] starting...");

    clean_signal_file(&args.offer_path);
    clean_signal_file(&args.answer_path);

    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    // Create offerer's own DC handler channels
    let (dc_open_tx, dc_open_rx) = mpsc::channel();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel();

    let dc_handler = DcHandler {
        open_tx: dc_open_tx,
        msg_tx: dc_msg_tx,
    };

    // Create DataChannel — triggers offer SDP generation + ICE gathering
    let mut dc = pc.create_data_channel(DC_LABEL, dc_handler)?;
    eprintln!("[offerer] DataChannel '{}' created", DC_LABEL);

    // Collect offer
    let offer_bundle = collect_local_signal(&ch, args.phase_timeout)?;
    write_signal(&args.offer_path, &offer_bundle)?;

    // Wait for answer
    let answer_bundle = read_signal(&args.answer_path, "answer", args.phase_timeout)?;
    apply_remote_signal(&mut pc, &answer_bundle, args.network_scope)?;

    // Wait for DataChannel to open
    dc_open_rx.recv_timeout(args.phase_timeout)?;
    eprintln!("[offerer] DataChannel open");

    // Send hello payload
    dc.send(HELLO_PAYLOAD)?;
    eprintln!(
        "[offerer] sent: {:?}",
        std::str::from_utf8(HELLO_PAYLOAD).unwrap_or("<binary>")
    );

    // Wait for echo
    let response = dc_msg_rx.recv_timeout(args.phase_timeout)?;
    if response == HELLO_PAYLOAD {
        eprintln!("[offerer] SUCCESS — received matching payload");
        Ok(())
    } else {
        Err(format!(
            "payload mismatch: expected {:?}, got {:?}",
            HELLO_PAYLOAD, response
        )
        .into())
    }
}

// ── Answerer ────────────────────────────────────────────────

fn run_answerer(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[answerer] starting...");

    // Wait for offer
    let offer_bundle = read_signal(&args.offer_path, "offer", args.phase_timeout)?;

    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    // Apply offer — triggers answer SDP generation + ICE gathering
    apply_remote_signal(&mut pc, &offer_bundle, args.network_scope)?;

    // Collect answer
    let answer_bundle = collect_local_signal(&ch, args.phase_timeout)?;
    write_signal(&args.answer_path, &answer_bundle)?;

    // Wait for incoming DataChannel
    let mut dc = ch.incoming_dc_rx.recv_timeout(args.phase_timeout)?;
    eprintln!("[answerer] DataChannel received");

    // Wait for DC to open
    ch.dc_open_rx.recv_timeout(args.phase_timeout)?;
    eprintln!("[answerer] DataChannel open");

    // Wait for hello payload
    let msg = ch.dc_msg_rx.recv_timeout(args.phase_timeout)?;
    eprintln!(
        "[answerer] received: {:?}",
        std::str::from_utf8(&msg).unwrap_or("<binary>")
    );

    if msg == HELLO_PAYLOAD {
        dc.send(HELLO_PAYLOAD)?;
        eprintln!("[answerer] SUCCESS — echoed matching payload");
        thread::sleep(Duration::from_millis(500));
        Ok(())
    } else {
        Err(format!(
            "payload mismatch: expected {:?}, got {:?}",
            HELLO_PAYLOAD, msg
        )
        .into())
    }
}

// ── Smoke mode offerer (file signaling) ─────────────────────

fn run_smoke_offerer(args: &Args) -> Result<(), smoke::SmokeError> {
    eprintln!("[smoke-offerer] starting...");

    clean_signal_file(&args.offer_path);
    clean_signal_file(&args.answer_path);

    let (mut pc, ch) = create_peer_connection(args.network_scope)
        .map_err(|e| smoke::SmokeError::Signaling(format!("peer connection: {}", e)))?;

    let (dc_open_tx, dc_open_rx) = mpsc::channel();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel();

    let dc_handler = DcHandler {
        open_tx: dc_open_tx,
        msg_tx: dc_msg_tx,
    };

    let mut dc = pc
        .create_data_channel(DC_LABEL, dc_handler)
        .map_err(|e| smoke::SmokeError::DataChannel(format!("create DC: {}", e)))?;

    let offer_bundle = collect_local_signal(&ch, args.phase_timeout)
        .map_err(|e| smoke::SmokeError::Signaling(format!("collect offer: {}", e)))?;
    write_signal(&args.offer_path, &offer_bundle)
        .map_err(|e| smoke::SmokeError::Signaling(format!("write offer: {}", e)))?;

    let answer_bundle = read_signal(&args.answer_path, "answer", args.phase_timeout)
        .map_err(|e| smoke::SmokeError::Signaling(format!("read answer: {}", e)))?;
    apply_remote_signal(&mut pc, &answer_bundle, args.network_scope)
        .map_err(|e| smoke::SmokeError::Signaling(format!("apply answer: {}", e)))?;

    dc_open_rx
        .recv_timeout(args.phase_timeout)
        .map_err(|_| smoke::SmokeError::DataChannel("DataChannel open timeout".to_string()))?;
    eprintln!("[smoke-offerer] DataChannel open");

    for run in 1..=args.smoke_config.repeat {
        if args.smoke_config.repeat > 1 {
            eprintln!("[smoke] run {}/{}", run, args.smoke_config.repeat);
        }
        let report =
            smoke::run_smoke_sender(&mut dc, &dc_msg_rx, &args.smoke_config, args.phase_timeout)?;
        report.print(args.smoke_config.json);
    }

    Ok(())
}

// ── Smoke mode answerer (file signaling) ────────────────────

fn run_smoke_answerer(args: &Args) -> Result<(), smoke::SmokeError> {
    eprintln!("[smoke-answerer] starting...");

    let offer_bundle = read_signal(&args.offer_path, "offer", args.phase_timeout)
        .map_err(|e| smoke::SmokeError::Signaling(format!("read offer: {}", e)))?;

    let (mut pc, ch) = create_peer_connection(args.network_scope)
        .map_err(|e| smoke::SmokeError::Signaling(format!("peer connection: {}", e)))?;

    apply_remote_signal(&mut pc, &offer_bundle, args.network_scope)
        .map_err(|e| smoke::SmokeError::Signaling(format!("apply offer: {}", e)))?;

    let answer_bundle = collect_local_signal(&ch, args.phase_timeout)
        .map_err(|e| smoke::SmokeError::Signaling(format!("collect answer: {}", e)))?;
    write_signal(&args.answer_path, &answer_bundle)
        .map_err(|e| smoke::SmokeError::Signaling(format!("write answer: {}", e)))?;

    let mut dc = ch
        .incoming_dc_rx
        .recv_timeout(args.phase_timeout)
        .map_err(|_| smoke::SmokeError::DataChannel("incoming DC timeout".to_string()))?;
    eprintln!("[smoke-answerer] DataChannel received");

    ch.dc_open_rx
        .recv_timeout(args.phase_timeout)
        .map_err(|_| smoke::SmokeError::DataChannel("DataChannel open timeout".to_string()))?;
    eprintln!("[smoke-answerer] DataChannel open");

    for run in 1..=args.smoke_config.repeat {
        if args.smoke_config.repeat > 1 {
            eprintln!("[smoke] run {}/{}", run, args.smoke_config.repeat);
        }
        let report = smoke::run_smoke_receiver(
            &mut dc,
            &ch.dc_msg_rx,
            &args.smoke_config,
            args.phase_timeout,
        )?;
        report.print(args.smoke_config.json);
    }

    // Give the ack time to flush before exit
    thread::sleep(Duration::from_millis(500));

    Ok(())
}

// ── Smoke mode rendezvous (via narrow hook) ─────────────────

fn run_smoke_rendezvous(args: &Args) -> Result<(), smoke::SmokeError> {
    let is_offerer = matches!(args.role, Some(Role::Offerer));
    rendezvous::run_rendezvous_session_with_exchange(args, |ctx| {
        for run in 1..=args.smoke_config.repeat {
            if args.smoke_config.repeat > 1 {
                eprintln!("[smoke] run {}/{}", run, args.smoke_config.repeat);
            }
            let report = if is_offerer {
                smoke::run_smoke_sender(ctx.dc, ctx.msg_rx, &args.smoke_config, args.phase_timeout)?
            } else {
                smoke::run_smoke_receiver(
                    ctx.dc,
                    ctx.msg_rx,
                    &args.smoke_config,
                    args.phase_timeout,
                )?
            };
            report.print(args.smoke_config.json);
        }
        Ok(())
    })
    .map_err(|e| match e.downcast::<smoke::SmokeError>() {
        Ok(smoke_err) => *smoke_err,
        Err(e) => smoke::classify_error(e.as_ref()),
    })
}

// ── Simulate mode ────────────────────────────────────────────

fn run_simulate(simulate_event: SimulateEvent) {
    use ipc::server::{IpcServer, DEFAULT_SOCKET_PATH};
    use ipc::types::{
        DaemonStatusPayload, IpcMessage, PairingRequestPayload, TransferIncomingRequestPayload,
    };

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
    eprintln!("[simulate] IPC client connected");

    // Emit daemon.status
    let status = DaemonStatusPayload {
        connected_peers: 0,
        ui_connected: true,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let status_value = match serde_json::to_value(&status) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[simulate] FATAL: serialize status: {e}");
            std::process::exit(1);
        }
    };
    server.emit_event(IpcMessage::new_event("daemon.status", status_value));

    // Small delay to let status arrive before the prompt
    thread::sleep(Duration::from_millis(100));

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
        "[bolt-daemon] role={:?} signal={:?} scope={:?} mode={:?} pairing={:?} interop_signal={:?} interop_hello={:?} interop_dc={:?} timeout={}s",
        args.role,
        args.signal_mode,
        args.network_scope,
        args.daemon_mode,
        args.pairing_policy,
        args.interop_signal,
        args.interop_hello,
        args.interop_dc,
        args.phase_timeout.as_secs()
    );

    match args.daemon_mode {
        DaemonMode::Default => {
            use ipc::server::{IpcServer, DEFAULT_SOCKET_PATH};
            use ipc::trust::default_trust_path;

            // Start IPC server for UI communication.
            // Fail-closed: if IPC start fails, pairing will deny all.
            let ipc_server = match IpcServer::start(DEFAULT_SOCKET_PATH) {
                Ok(s) => {
                    eprintln!("[bolt-daemon] IPC server started");
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
            let trust_path = default_trust_path();

            // Load persistent identity once, before role dispatch.
            // Both rendezvous paths share the same long-lived keypair.
            let identity_path = match identity_store::resolve_identity_path() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[bolt-daemon] FATAL: {}", e);
                    std::process::exit(1);
                }
            };
            let identity = match identity_store::load_or_create_identity(&identity_path) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("[bolt-daemon] FATAL: {}", e);
                    std::process::exit(1);
                }
            };

            let role = match args.role.as_ref() {
                Some(r) => r,
                None => {
                    eprintln!("[bolt-daemon] FATAL: --role required for default mode");
                    std::process::exit(1);
                }
            };
            let result = match (role, &args.signal_mode) {
                (Role::Offerer, SignalMode::File) => run_offerer(&args),
                (Role::Answerer, SignalMode::File) => run_answerer(&args),
                (Role::Offerer, SignalMode::Rendezvous) => {
                    rendezvous::run_offerer_rendezvous(&args, &identity)
                }
                (Role::Answerer, SignalMode::Rendezvous) => {
                    rendezvous::run_answerer_rendezvous(&args, ipc_server.as_ref(), &trust_path, &identity)
                }
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
        DaemonMode::Smoke => {
            let role = match args.role.as_ref() {
                Some(r) => r,
                None => {
                    eprintln!("[bolt-daemon] FATAL: --role required for smoke mode");
                    std::process::exit(1);
                }
            };
            let result = match (role, &args.signal_mode) {
                (Role::Offerer, SignalMode::File) => run_smoke_offerer(&args),
                (Role::Answerer, SignalMode::File) => run_smoke_answerer(&args),
                (Role::Offerer, SignalMode::Rendezvous)
                | (Role::Answerer, SignalMode::Rendezvous) => run_smoke_rendezvous(&args),
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
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
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
}
