//! Legacy WebRTC/DataChannel code — deprecated transitional compatibility.
//!
//! This module contains all WebRTC/DataChannel-specific types, handlers, and
//! mode runners. It is gated behind the `legacy-webrtc` feature flag.
//!
//! **NOT a supported forward path.** The forward architecture is WsEndpoint
//! mode (direct WS/WT transport). This code will be removed in a future
//! DEWEBRTC phase.

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

use crate::ice_filter;
use crate::ice_filter::NetworkScope;
use crate::{smoke, Args, HELLO_PAYLOAD};

// Re-export rendezvous runners for dispatch in main.rs
pub(crate) use crate::rendezvous;

// ── Constants ───────────────────────────────────────────────

pub(crate) const DC_LABEL: &str = "bolt";
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(500);
pub(crate) const DEFAULT_SIGNAL_DIR: &str = "/tmp/bolt-spike";

// ── Types ───────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum Role {
    Offerer,
    Answerer,
}

#[derive(Debug)]
pub(crate) enum SignalPath {
    Stdio,
    File(String),
}

#[derive(Debug, PartialEq)]
pub(crate) enum SignalMode {
    File,
    Rendezvous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportMode {
    DataChannel,
    #[cfg(feature = "transport-quic")]
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InteropDcMode {
    DaemonDcV1,
    WebDcV1,
}

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

pub(crate) struct PcHandler {
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

pub(crate) fn cand_to_info(cand: &IceCandidate) -> CandidateInfo {
    CandidateInfo {
        candidate: cand.candidate.clone(),
        mid: cand.mid.clone(),
    }
}

pub(crate) fn info_to_cand(info: &CandidateInfo) -> IceCandidate {
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

pub(crate) fn run_offerer(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
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

pub(crate) fn run_answerer(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
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

pub(crate) fn run_smoke_offerer(args: &Args) -> Result<(), smoke::SmokeError> {
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

pub(crate) fn run_smoke_answerer(args: &Args) -> Result<(), smoke::SmokeError> {
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

pub(crate) fn run_smoke_rendezvous(args: &Args) -> Result<(), smoke::SmokeError> {
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

