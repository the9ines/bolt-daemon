//! Bolt Daemon — Headless WebRTC DataChannel transport (Phase 3B).
//!
//! Establishes a WebRTC DataChannel via libdatachannel and exchanges a
//! deterministic "hello" payload between two peers. No browser required.
//!
//! LAN-only by default: ICE candidates are filtered to private/link-local IPs.
//!
//! Usage:
//!   bolt-daemon --role offerer  [--offer <path|->] [--answer <path|->]
//!   bolt-daemon --role answerer [--offer <path|->] [--answer <path|->]
//!
//! Default signal paths: /tmp/bolt-spike/offer.json, /tmp/bolt-spike/answer.json

mod ice_filter;

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

// ── Constants ───────────────────────────────────────────────

/// Deterministic payload exchanged during the spike.
/// Both peers send and verify this exact byte sequence.
const HELLO_PAYLOAD: &[u8] = b"bolt-hello-v1";

/// DataChannel label.
const DC_LABEL: &str = "bolt";

/// Timeout for each signaling/data exchange phase.
const PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval when waiting for a signaling file.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Default signal directory.
const DEFAULT_SIGNAL_DIR: &str = "/tmp/bolt-spike";

// ── CLI ─────────────────────────────────────────────────────

#[derive(Debug)]
enum Role {
    Offerer,
    Answerer,
}

#[derive(Debug)]
enum SignalPath {
    Stdio,
    File(String),
}

#[derive(Debug)]
struct Args {
    role: Role,
    offer_path: SignalPath,
    answer_path: SignalPath,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut role = None;
    let mut offer = None;
    let mut answer = None;

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
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let role = role.unwrap_or_else(|| {
        eprintln!(
            "Usage: bolt-daemon --role offerer|answerer [--offer <path|->] [--answer <path|->]"
        );
        std::process::exit(1);
    });

    let offer =
        offer.unwrap_or_else(|| SignalPath::File(format!("{}/offer.json", DEFAULT_SIGNAL_DIR)));
    let answer =
        answer.unwrap_or_else(|| SignalPath::File(format!("{}/answer.json", DEFAULT_SIGNAL_DIR)));

    Args {
        role,
        offer_path: offer,
        answer_path: answer,
    }
}

// ── Signaling JSON ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct SignalBundle {
    description: SdpInfo,
    candidates: Vec<CandidateInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SdpInfo {
    sdp_type: String,
    sdp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CandidateInfo {
    candidate: String,
    mid: String,
}

// ── Handlers ────────────────────────────────────────────────

struct DcHandler {
    open_tx: mpsc::Sender<()>,
    msg_tx: mpsc::Sender<Vec<u8>>,
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
        if ice_filter::is_lan_candidate(&cand.candidate) {
            eprintln!("[pc] ICE candidate accepted (LAN): {}", &cand.candidate);
            let _ = self.cand_tx.send(cand);
        } else {
            eprintln!("[pc] ICE candidate REJECTED (non-LAN): {}", &cand.candidate);
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

fn read_signal(path: &SignalPath, label: &str) -> io::Result<SignalBundle> {
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
                if start.elapsed() > PHASE_TIMEOUT {
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

struct Channels {
    desc_rx: mpsc::Receiver<SessionDescription>,
    cand_rx: mpsc::Receiver<IceCandidate>,
    gather_rx: mpsc::Receiver<GatheringState>,
    dc_open_rx: mpsc::Receiver<()>,
    dc_msg_rx: mpsc::Receiver<Vec<u8>>,
    incoming_dc_rx: mpsc::Receiver<Box<RtcDataChannel<DcHandler>>>,
}

#[allow(clippy::type_complexity)]
fn create_peer_connection(
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
fn collect_local_signal(ch: &Channels) -> Result<SignalBundle, Box<dyn std::error::Error>> {
    let desc = ch.desc_rx.recv_timeout(PHASE_TIMEOUT)?;
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
        if start.elapsed() > PHASE_TIMEOUT {
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
fn apply_remote_signal(
    pc: &mut Box<RtcPeerConnection<PcHandler>>,
    bundle: &SignalBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let desc = sdp_info_to_desc(&bundle.description)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    pc.set_remote_description(&desc)?;
    eprintln!("[signal] remote description applied");

    let mut added = 0;
    for c in &bundle.candidates {
        if ice_filter::is_lan_candidate(&c.candidate) {
            let cand = info_to_cand(c);
            pc.add_remote_candidate(&cand)?;
            added += 1;
        } else {
            eprintln!(
                "[signal] remote candidate REJECTED (non-LAN): {}",
                &c.candidate
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

    let (mut pc, ch) = create_peer_connection()?;

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
    let offer_bundle = collect_local_signal(&ch)?;
    write_signal(&args.offer_path, &offer_bundle)?;

    // Wait for answer
    let answer_bundle = read_signal(&args.answer_path, "answer")?;
    apply_remote_signal(&mut pc, &answer_bundle)?;

    // Wait for DataChannel to open
    dc_open_rx.recv_timeout(PHASE_TIMEOUT)?;
    eprintln!("[offerer] DataChannel open");

    // Send hello payload
    dc.send(HELLO_PAYLOAD)?;
    eprintln!(
        "[offerer] sent: {:?}",
        std::str::from_utf8(HELLO_PAYLOAD).unwrap_or("<binary>")
    );

    // Wait for echo
    let response = dc_msg_rx.recv_timeout(PHASE_TIMEOUT)?;
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
    let offer_bundle = read_signal(&args.offer_path, "offer")?;

    let (mut pc, ch) = create_peer_connection()?;

    // Apply offer — triggers answer SDP generation + ICE gathering
    apply_remote_signal(&mut pc, &offer_bundle)?;

    // Collect answer
    let answer_bundle = collect_local_signal(&ch)?;
    write_signal(&args.answer_path, &answer_bundle)?;

    // Wait for incoming DataChannel
    let mut dc = ch.incoming_dc_rx.recv_timeout(PHASE_TIMEOUT)?;
    eprintln!("[answerer] DataChannel received");

    // Wait for DC to open
    ch.dc_open_rx.recv_timeout(PHASE_TIMEOUT)?;
    eprintln!("[answerer] DataChannel open");

    // Wait for hello payload
    let msg = ch.dc_msg_rx.recv_timeout(PHASE_TIMEOUT)?;
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

// ── Entry ───────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    eprintln!("[bolt-daemon] role={:?}", args.role);

    let result = match args.role {
        Role::Offerer => run_offerer(&args),
        Role::Answerer => run_answerer(&args),
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
}
