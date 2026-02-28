//! Rendezvous signaling via bolt-rendezvous WebSocket server.
//!
//! HARD RULE: Rendezvous mode is opt-in (`--signal rendezvous`).
//! If the rendezvous server is unreachable or misconfigured, we exit 1.
//! There is NO fallback to file mode. Fail-closed by design.
//!
//! Protocol flow (Phase 3G):
//!   register → create PC+DC → hello/ack handshake → collect offer → send offer
//!   → wait answer → apply answer → DataChannel exchange
//!
//! All payloads carry `payload_version` (must be 1) and `session` (must match).

use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bolt_rendezvous_protocol::{ClientMessage, DeviceType, ServerMessage};
use serde::{Deserialize, Serialize};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::{
    apply_remote_signal, collect_local_signal, create_peer_connection, Args, DcHandler,
    NetworkScope, SignalBundle, DC_LABEL, HELLO_PAYLOAD,
};

// ── Constants ───────────────────────────────────────────────

/// Current payload version. Reject any payload with a different version.
const PAYLOAD_VERSION: u32 = 1;

/// Our inner payload format (inside the opaque `payload` field).
/// All msg_types use this struct. Optional fields are present/absent depending on msg_type:
///   hello: from_peer, to_peer, network_scope, phase_timeout_secs
///   ack:   from_peer, to_peer
///   offer/answer: bundle
#[derive(Serialize, Deserialize, Debug)]
struct SignalPayload {
    payload_version: u32,
    session: String,
    room: String,
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<SignalBundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase_timeout_secs: Option<u64>,
}

// ── Helpers ─────────────────────────────────────────────────

type WsStream = WebSocket<MaybeTlsStream<std::net::TcpStream>>;

/// Generate an 8-character alphanumeric peer ID.
fn generate_peer_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:016x}", hash)[..8].to_string()
}

/// Convert NetworkScope to its CLI string representation.
fn scope_to_str(scope: NetworkScope) -> &'static str {
    match scope {
        NetworkScope::Lan => "lan",
        NetworkScope::Overlay => "overlay",
        NetworkScope::Global => "global",
    }
}

/// Returns true if the server error is a retryable "peer not found" for the
/// specific target peer. The rendezvous server emits: `"peer '<code>' not found"`.
/// Only this exact pattern is retryable; all other errors are fatal.
fn is_retryable_peer_not_found(error_msg: &str, target_peer: &str) -> bool {
    let expected = format!("peer '{}' not found", target_peer);
    error_msg == expected
}

/// Connect to the rendezvous server and register.
/// Fails hard (no fallback) if the server is unreachable.
fn connect_and_register(url: &str, peer_id: &str) -> Result<WsStream, Box<dyn std::error::Error>> {
    eprintln!("[rendezvous] connecting to {} ...", url);

    let (mut ws, _response) = tungstenite::connect(url).map_err(|e| {
        format!(
            "rendezvous server unreachable at {}: {} (no fallback to file mode)",
            url, e
        )
    })?;

    eprintln!("[rendezvous] connected, registering as '{}'", peer_id);

    let register = ClientMessage::Register {
        peer_code: peer_id.to_string(),
        device_name: "bolt-daemon".to_string(),
        device_type: DeviceType::Desktop,
    };
    let json = serde_json::to_string(&register)?;
    ws.send(Message::Text(json))?;

    // Wait for the initial Peers response to confirm registration
    let msg = ws.read()?;
    let text = msg
        .into_text()
        .map_err(|e| format!("expected text from server: {}", e))?;
    let server_msg: ServerMessage = serde_json::from_str(&text)?;

    match server_msg {
        ServerMessage::Peers { .. } => {
            eprintln!("[rendezvous] registered successfully");
        }
        ServerMessage::Error { message } => {
            return Err(format!("rendezvous registration failed: {}", message).into());
        }
        other => {
            eprintln!(
                "[rendezvous] unexpected first message (expected peers): {:?}",
                other
            );
        }
    }

    Ok(ws)
}

/// Send a signal to a specific peer.
fn send_signal(
    ws: &mut WsStream,
    to: &str,
    payload: &SignalPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_value = serde_json::to_value(payload)?;
    let msg = ClientMessage::Signal {
        to: to.to_string(),
        payload: payload_value,
    };
    let json = serde_json::to_string(&msg)?;
    ws.send(Message::Text(json))?;
    eprintln!("[rendezvous] sent {} signal to '{}'", payload.msg_type, to);
    Ok(())
}

/// Read the next server message, respecting the deadline.
/// Returns WouldBlock/TimedOut on socket timeout (caller retries).
/// Returns error on connection failure or deadline expiry.
fn recv_with_deadline(
    ws: &mut WsStream,
    deadline: Instant,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("phase timeout expired")?;

        // Set read timeout on underlying TCP stream (max 5s per read for responsive deadline checking)
        let read_timeout = remaining.min(Duration::from_secs(5));
        match ws.get_ref() {
            MaybeTlsStream::Plain(tcp) => {
                tcp.set_read_timeout(Some(read_timeout))?;
            }
            // SA16: fail-closed — no TLS crate compiled in; if a TLS variant is
            // added in the future, this arm forces an explicit timeout implementation
            // rather than silently blocking indefinitely on ws.read().
            #[allow(unreachable_patterns)]
            _ => {
                return Err("read timeout not supported for this stream type — TLS timeout handler required".into());
            }
        }

        match ws.read() {
            Ok(msg) => {
                if msg.is_ping() || msg.is_pong() {
                    continue;
                }
                let text = msg
                    .into_text()
                    .map_err(|e| format!("expected text from server: {}", e))?;
                let server_msg: ServerMessage = serde_json::from_str(&text)?;
                return Ok(server_msg);
            }
            Err(tungstenite::Error::Io(ref e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return Err("phase timeout expired".into());
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Wait for a specific signal from a specific peer, matching session, room, and msg_type.
/// Version mismatch is fatal (exit 1). Session mismatch is non-fatal (ignore, continue).
/// Returns the full SignalPayload so callers can inspect hello/ack fields.
fn wait_for_signal(
    ws: &mut WsStream,
    deadline: Instant,
    from_peer: &str,
    room: &str,
    session: &str,
    expected_msg_type: &str,
) -> Result<SignalPayload, Box<dyn std::error::Error>> {
    eprintln!(
        "[rendezvous] waiting for '{}' signal from '{}' (room '{}', session '{}')",
        expected_msg_type, from_peer, room, session
    );

    loop {
        let server_msg = recv_with_deadline(ws, deadline)?;

        match server_msg {
            ServerMessage::Signal { from, payload } => {
                // Primary filter: peer_code must match exactly
                if from != from_peer {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}' (expected '{}')",
                        from, from_peer
                    );
                    continue;
                }

                // Parse our inner payload
                let signal_payload: SignalPayload = match serde_json::from_value(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "[rendezvous] ignoring unparseable payload from '{}': {}",
                            from, e
                        );
                        continue;
                    }
                };

                // Version gate (FATAL — fail-closed, exit 1)
                if signal_payload.payload_version != PAYLOAD_VERSION {
                    return Err(format!(
                        "unsupported payload_version {} (expected {})",
                        signal_payload.payload_version, PAYLOAD_VERSION
                    )
                    .into());
                }

                // Session gate (non-fatal — different run, ignore)
                if signal_payload.session != session {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}': session '{}' != '{}'",
                        from, signal_payload.session, session
                    );
                    continue;
                }

                // Room filter
                if signal_payload.room != room {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}': room '{}' != '{}'",
                        from, signal_payload.room, room
                    );
                    continue;
                }

                // msg_type filter
                if signal_payload.msg_type != expected_msg_type {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}': msg_type '{}' != '{}'",
                        from, signal_payload.msg_type, expected_msg_type
                    );
                    continue;
                }

                eprintln!(
                    "[rendezvous] received '{}' signal from '{}'",
                    expected_msg_type, from
                );
                return Ok(signal_payload);
            }
            ServerMessage::PeerJoined { peer } => {
                eprintln!("[rendezvous] peer joined: '{}'", peer.peer_code);
            }
            ServerMessage::PeerLeft { peer_code } => {
                eprintln!("[rendezvous] peer left: '{}'", peer_code);
            }
            ServerMessage::Peers { .. } => {
                // Additional peers list, ignore
            }
            ServerMessage::Error { message } => {
                return Err(format!("rendezvous server error: {}", message).into());
            }
        }
    }
}

// ── Web-compat helpers (INTEROP-1) ──────────────────────────

/// Send a daemon SignalBundle as web-schema payloads (1 SDP + N ICE candidates).
/// Each web payload is sent as a separate rendezvous Signal message.
/// If `identity_pk_b64` is Some, the identity public key is included in the
/// SDP payload's `publicKey` field (required for INTEROP-2 web HELLO).
fn send_web_payloads(
    ws: &mut WsStream,
    to: &str,
    bundle: &crate::SignalBundle,
    sdp_type: &str,
    from_peer: &str,
    identity_pk_b64: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payloads = crate::web_signal::bundle_to_web_payloads(
        bundle,
        sdp_type,
        from_peer,
        to,
        identity_pk_b64,
    )?;

    for (i, payload) in payloads.iter().enumerate() {
        let msg = ClientMessage::Signal {
            to: to.to_string(),
            payload: payload.clone(),
        };
        let json = serde_json::to_string(&msg)?;
        ws.send(Message::Text(json))?;

        if i == 0 {
            eprintln!("[INTEROP-1] sent web {} to '{}'", sdp_type, to);
        }
    }

    if payloads.len() > 1 {
        eprintln!(
            "[INTEROP-1] sent {} ice-candidate(s) to '{}'",
            payloads.len() - 1,
            to
        );
    }

    Ok(())
}

/// Receive web-schema signals and assemble into a daemon SignalBundle.
///
/// Collects the SDP (offer or answer) and trickled ICE candidates from
/// web-format payloads. Falls back to daemon-format if web parsing fails
/// (defensive compat). Returns once:
/// - ICE collection timeout expires (3s after SDP received), OR
/// - End-of-candidates marker received (empty candidate string), OR
/// - Phase deadline expires
///
/// Returns `(SignalBundle, Option<String>)` — the assembled bundle and the
/// remote peer's identity public key (base64), if present in the SDP payload.
fn receive_web_bundle(
    ws: &mut WsStream,
    deadline: Instant,
    from_peer: &str,
    room: &str,
    session: &str,
    expected_sdp_type: &str,
    network_scope: crate::NetworkScope,
) -> Result<(crate::SignalBundle, Option<String>), Box<dyn std::error::Error>> {
    use crate::web_signal::{self, ParsedWebSignal};

    let mut sdp_info: Option<crate::SdpInfo> = None;
    let mut remote_pk_b64: Option<String> = None;
    let mut candidates: Vec<crate::CandidateInfo> = Vec::new();
    let mut ice_deadline: Option<Instant> = None;

    /// ICE collection window after SDP is received (seconds).
    const ICE_COLLECT_SECS: u64 = 3;

    eprintln!(
        "[INTEROP-1] waiting for web '{}' + ice-candidates from '{}' (room '{}', session '{}')",
        expected_sdp_type, from_peer, room, session
    );

    loop {
        // After SDP, use tighter ICE collection deadline
        let effective_deadline = match (sdp_info.is_some(), ice_deadline) {
            (true, Some(ice_dl)) => ice_dl.min(deadline),
            _ => deadline,
        };

        let server_msg = match recv_with_deadline(ws, effective_deadline) {
            Ok(msg) => msg,
            Err(_) if sdp_info.is_some() => {
                // Timeout during ICE collection — proceed with what we have
                eprintln!(
                    "[INTEROP-1] ICE collection timeout — proceeding with {} candidate(s)",
                    candidates.len()
                );
                break;
            }
            Err(e) => return Err(e),
        };

        match server_msg {
            ServerMessage::Signal { from, payload } => {
                if from != from_peer {
                    eprintln!(
                        "[rendezvous] ignoring signal from '{}' (expected '{}')",
                        from, from_peer
                    );
                    continue;
                }

                // Try web schema first
                match web_signal::parse_web_payload(&payload) {
                    Ok(Some(parsed)) => match parsed {
                        ParsedWebSignal::Offer {
                            sdp_type,
                            sdp,
                            public_key_b64,
                        } if expected_sdp_type == "offer" => {
                            eprintln!("[INTEROP-1] received web offer from '{}'", from_peer);
                            sdp_info = Some(crate::SdpInfo { sdp_type, sdp });
                            remote_pk_b64 = public_key_b64;
                            ice_deadline =
                                Some(Instant::now() + Duration::from_secs(ICE_COLLECT_SECS));
                        }
                        ParsedWebSignal::Answer {
                            sdp_type,
                            sdp,
                            public_key_b64,
                        } if expected_sdp_type == "answer" => {
                            eprintln!("[INTEROP-1] received web answer from '{}'", from_peer);
                            sdp_info = Some(crate::SdpInfo { sdp_type, sdp });
                            remote_pk_b64 = public_key_b64;
                            ice_deadline =
                                Some(Instant::now() + Duration::from_secs(ICE_COLLECT_SECS));
                        }
                        ParsedWebSignal::IceCandidate { candidate, mid } => {
                            if candidate.is_empty() {
                                eprintln!("[INTEROP-1] end-of-candidates from '{}'", from_peer);
                                if sdp_info.is_some() {
                                    break;
                                }
                            } else if crate::ice_filter::is_allowed_candidate(
                                &candidate,
                                network_scope,
                            ) {
                                eprintln!(
                                    "[INTEROP-1] ICE candidate accepted ({:?}): {}",
                                    network_scope, &candidate
                                );
                                candidates.push(crate::CandidateInfo { candidate, mid });
                            } else {
                                eprintln!(
                                    "[INTEROP-1] ICE candidate REJECTED ({:?}): {}",
                                    network_scope, &candidate
                                );
                            }
                        }
                        _ => {
                            eprintln!(
                                "[INTEROP-1] ignoring unexpected web signal type from '{}'",
                                from_peer
                            );
                        }
                    },
                    Ok(None) => {
                        // Unknown web type, already logged by parse_web_payload
                    }
                    Err(_) => {
                        // Web parsing failed — try daemon format as fallback
                        if let Ok(sp) = serde_json::from_value::<SignalPayload>(payload) {
                            if sp.payload_version != PAYLOAD_VERSION {
                                return Err(format!(
                                    "unsupported payload_version {} (expected {})",
                                    sp.payload_version, PAYLOAD_VERSION
                                )
                                .into());
                            }
                            if sp.session != session || sp.room != room {
                                continue;
                            }
                            if sp.msg_type == expected_sdp_type {
                                if let Some(bundle) = sp.bundle {
                                    eprintln!(
                                        "[INTEROP-1] received daemon-format {} (fallback compat)",
                                        expected_sdp_type
                                    );
                                    return Ok((bundle, None));
                                }
                            }
                        }
                        // Both formats failed — continue listening
                    }
                }
            }
            ServerMessage::PeerJoined { peer } => {
                eprintln!("[rendezvous] peer joined: '{}'", peer.peer_code);
            }
            ServerMessage::PeerLeft { peer_code } => {
                eprintln!("[rendezvous] peer left: '{}'", peer_code);
            }
            ServerMessage::Peers { .. } => {}
            ServerMessage::Error { message } => {
                return Err(format!("rendezvous server error: {}", message).into());
            }
        }
    }

    let description = sdp_info.ok_or("phase timeout — did not receive SDP")?;
    eprintln!(
        "[INTEROP-1] assembled bundle: {} + {} candidate(s)",
        expected_sdp_type,
        candidates.len()
    );
    Ok((
        crate::SignalBundle {
            description,
            candidates,
        },
        remote_pk_b64,
    ))
}

// ── Smoke exchange context ──────────────────────────────────

/// Narrow context passed to the exchange closure after rendezvous
/// handshake and DataChannel open. Contains only what smoke mode needs.
/// No rendezvous signaling handles or message types are exposed.
pub(crate) struct SmokeDcContext<'a> {
    pub dc: &'a mut datachannel::RtcDataChannel<crate::DcHandler>,
    pub msg_rx: &'a std::sync::mpsc::Receiver<Vec<u8>>,
    /// Local peer ID (for reporting). Not used by smoke transfer functions.
    #[allow(dead_code)]
    pub peer_id: Option<&'a str>,
    /// Remote peer ID (for reporting). Not used by smoke transfer functions.
    #[allow(dead_code)]
    pub expect_peer: Option<&'a str>,
}

// ── Entry points ────────────────────────────────────────────

/// Offerer flow via rendezvous signaling.
///
/// Flow: register → create PC+DC → hello/ack → collect offer → send offer
///       → wait answer → apply answer → DataChannel exchange
///
/// INVARIANT: `--signal rendezvous` is required. No fallback to file mode.
/// If the server is down or peer is unreachable, exit 1.
pub fn run_offerer_rendezvous(args: &Args, identity: &bolt_core::identity::IdentityKeyPair) -> Result<(), Box<dyn std::error::Error>> {
    // Fail-closed: these are validated in parse_args() but double-check here
    let room = args
        .room
        .as_ref()
        .ok_or("BUG: --room required for rendezvous mode")?;
    let to_peer = args
        .to_peer
        .as_ref()
        .ok_or("BUG: --to required for offerer rendezvous mode")?;
    let session = args
        .session
        .as_ref()
        .ok_or("BUG: --session required for rendezvous mode")?;
    let peer_id = args.peer_id.clone().unwrap_or_else(generate_peer_id);

    eprintln!(
        "[offerer] rendezvous mode: room='{}', session='{}', peer_id='{}', to='{}'",
        room, session, peer_id, to_peer
    );
    if args.interop_signal == crate::web_signal::InteropSignal::WebV1 {
        eprintln!("[INTEROP-1] web_v1 mode enabled — using web payload schema");
    }
    let use_web_hello = args.interop_hello == crate::web_hello::InteropHelloMode::WebHelloV1;
    if use_web_hello {
        eprintln!("[INTEROP-2] web_hello_v1 mode enabled — encrypted HELLO");
    }

    // Generate ephemeral session keypair for signaling + sealing (per session).
    // Persistent identity is used ONLY for identityPublicKey in HELLO inner field.
    let session_kp = if use_web_hello {
        let kp = bolt_core::crypto::generate_ephemeral_keypair();
        eprintln!(
            "[SA1] session ephemeral pk={}, persistent identity pk={}",
            bolt_core::encoding::to_base64(&kp.public_key),
            bolt_core::encoding::to_base64(&identity.public_key)
        );
        Some(kp)
    } else {
        None
    };
    let local_pk_b64 = session_kp
        .as_ref()
        .map(|kp| bolt_core::encoding::to_base64(&kp.public_key));

    let deadline = Instant::now() + args.phase_timeout;

    // Connect and register (fails hard if server unreachable — no fallback)
    let mut ws = connect_and_register(&args.rendezvous_url, &peer_id)?;

    // Create PeerConnection + DataChannel → triggers SDP + ICE gathering
    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    let (dc_open_tx, dc_open_rx) = mpsc::channel();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel();

    let dc_handler = DcHandler {
        open_tx: dc_open_tx,
        msg_tx: dc_msg_tx,
    };

    let mut dc = pc.create_data_channel(DC_LABEL, dc_handler)?;
    eprintln!("[offerer] DataChannel '{}' created", DC_LABEL);

    // ── Hello/ack handshake (with retry on peer-not-found) ──
    let hello_payload = SignalPayload {
        payload_version: PAYLOAD_VERSION,
        session: session.clone(),
        room: room.clone(),
        msg_type: "hello".to_string(),
        bundle: None,
        from_peer: Some(peer_id.clone()),
        to_peer: Some(to_peer.clone()),
        network_scope: Some(scope_to_str(args.network_scope).to_string()),
        phase_timeout_secs: Some(args.phase_timeout.as_secs()),
    };

    // Send hello with retry: the target peer may not have registered yet.
    // The server returns "peer '<code>' not found" in that case. We retry
    // with backoff until the peer appears or the deadline expires.
    let mut backoff = Duration::from_millis(100);
    let max_backoff = Duration::from_secs(1);

    let ack = loop {
        send_signal(&mut ws, to_peer, &hello_payload)?;

        // Try to receive the ack (or a peer-not-found error)
        match wait_for_signal(&mut ws, deadline, to_peer, room, session, "ack") {
            Ok(ack) => break ack,
            Err(e) => {
                let msg = e.to_string();
                // Extract the server error message (strip our prefix)
                let server_msg = msg
                    .strip_prefix("rendezvous server error: ")
                    .unwrap_or(&msg);
                if is_retryable_peer_not_found(server_msg, to_peer) {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out waiting for peer '{}' to register",
                            to_peer
                        )
                        .into());
                    }
                    eprintln!(
                        "[rendezvous] hello retry: target '{}' not registered yet",
                        to_peer
                    );
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                    continue;
                }
                // All other errors are fatal
                return Err(e);
            }
        }
    };

    // Validate ack fields
    if let Some(ref from) = ack.from_peer {
        if from != to_peer {
            return Err(format!(
                "ack from_peer mismatch: expected '{}', got '{}'",
                to_peer, from
            )
            .into());
        }
    }
    if let Some(ref to) = ack.to_peer {
        if to != &peer_id {
            return Err(
                format!("ack to_peer mismatch: expected '{}', got '{}'", peer_id, to).into(),
            );
        }
    }

    eprintln!("[rendezvous] hello/ack complete — session '{}'", session);

    // ── Offer/answer exchange ────────────────────────────────

    // Collect offer bundle (reuses scope-filtered logic)
    let offer_bundle = collect_local_signal(&ch, args.phase_timeout)?;

    // Send offer to target peer via rendezvous
    match args.interop_signal {
        crate::web_signal::InteropSignal::WebV1 => {
            eprintln!("[INTEROP-1] offerer sending web-format offer");
            send_web_payloads(
                &mut ws,
                to_peer,
                &offer_bundle,
                "offer",
                &peer_id,
                local_pk_b64.as_deref(),
            )?;
        }
        crate::web_signal::InteropSignal::DaemonV1 => {
            let offer_payload = SignalPayload {
                payload_version: PAYLOAD_VERSION,
                session: session.clone(),
                room: room.clone(),
                msg_type: "offer".to_string(),
                bundle: Some(offer_bundle),
                from_peer: None,
                to_peer: None,
                network_scope: None,
                phase_timeout_secs: None,
            };
            send_signal(&mut ws, to_peer, &offer_payload)?;
        }
    }

    // Wait for answer from target peer (deadline-respecting, filtered)
    let (answer_bundle, remote_pk_b64) = match args.interop_signal {
        crate::web_signal::InteropSignal::WebV1 => receive_web_bundle(
            &mut ws,
            deadline,
            to_peer,
            room,
            session,
            "answer",
            args.network_scope,
        )?,
        crate::web_signal::InteropSignal::DaemonV1 => {
            let answer_sp = wait_for_signal(&mut ws, deadline, to_peer, room, session, "answer")?;
            let bundle = answer_sp.bundle.ok_or("answer signal missing bundle")?;
            (bundle, None)
        }
    };

    // Apply answer (reuses scope-filtered logic)
    apply_remote_signal(&mut pc, &answer_bundle, args.network_scope)?;

    // Wait for DataChannel to open
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for DataChannel open")?;
    dc_open_rx.recv_timeout(remaining)?;
    eprintln!("[offerer] DataChannel open");

    // ── DataChannel HELLO exchange ──────────────────────────
    if use_web_hello {
        // SA1 Phase B: Separated identity (persistent) + session (ephemeral) keys
        let local_session = session_kp
            .as_ref()
            .ok_or("[INTEROP-2_HELLO_FAIL] session keypair missing for web HELLO (offerer)")?;
        let remote_pk_b64_str = remote_pk_b64.as_deref().ok_or(
            "[INTEROP-2_HELLO_FAIL] no remote session key in answer signal — cannot encrypt HELLO",
        )?;
        let remote_pk = crate::web_hello::decode_public_key(remote_pk_b64_str)?;
        eprintln!("[INTEROP-2] remote session pk: {}", remote_pk_b64_str);

        // Send encrypted HELLO (identity.pk in inner field, session_kp for sealing)
        let hello_msg = crate::web_hello::build_hello_message(&identity.public_key, local_session, &remote_pk)?;
        dc.send(hello_msg.as_bytes())?;
        eprintln!("[INTEROP-2] sent encrypted HELLO");

        // Receive + decrypt remote HELLO (session_kp for opening)
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("phase timeout expired waiting for web HELLO")?;
        let response = dc_msg_rx.recv_timeout(remaining)?;
        let remote_hello = crate::web_hello::parse_hello_message(&response, &remote_pk, local_session)?;

        // Negotiate capabilities
        let local_caps = crate::web_hello::daemon_capabilities();
        let negotiated =
            crate::web_hello::negotiate_capabilities(&local_caps, &remote_hello.capabilities);
        eprintln!(
            "[INTEROP-2] HELLO exchange complete — remote_identity={}, negotiated_caps={:?}",
            remote_hello.identity_public_key, negotiated
        );

        // ── INTEROP-3: Session context uses ephemeral session keypair ────
        let session =
            crate::session::SessionContext::new(local_session.clone(), remote_pk, negotiated.clone())?;

        if args.interop_dc == crate::InteropDcMode::WebDcV1 {
            if !session.envelope_v1_negotiated() {
                return Err("[INTEROP-3_NO_ENVELOPE_CAP] bolt.profile-envelope-v1 not negotiated — aborting".into());
            }
            eprintln!("[INTEROP-3] entering post-HELLO DC envelope loop (offerer)");

            // Send initial ping + app_message for E2E validation
            let ping = crate::dc_messages::DcMessage::Ping {
                ts_ms: crate::dc_messages::now_ms(),
            };
            let ping_json = crate::dc_messages::encode_dc_message(&ping)
                .map_err(|e| format!("[INTEROP-4] encode ping: {e}"))?;
            let ping_env = crate::envelope::encode_envelope(&ping_json, &session)?;
            dc.send(&ping_env)?;
            eprintln!("[INTEROP-4] sent initial ping");

            let app = crate::dc_messages::DcMessage::AppMessage {
                text: "hello from offerer".to_string(),
            };
            let app_json = crate::dc_messages::encode_dc_message(&app)
                .map_err(|e| format!("[INTEROP-4] encode app_message: {e}"))?;
            let app_env = crate::envelope::encode_envelope(&app_json, &session)?;
            dc.send(&app_env)?;
            eprintln!("[INTEROP-4] sent app_message");

            // Periodic ping interval
            const PING_INTERVAL: Duration = Duration::from_secs(2);
            let mut last_ping = Instant::now();

            loop {
                // Use short poll interval so we can send periodic pings
                let poll_timeout = std::cmp::min(
                    deadline
                        .checked_duration_since(Instant::now())
                        .unwrap_or(Duration::ZERO),
                    Duration::from_millis(200),
                );
                if deadline <= Instant::now() {
                    eprintln!("[INTEROP-4] DC loop timeout — clean exit");
                    break;
                }

                let raw = match dc_msg_rx.recv_timeout(poll_timeout) {
                    Ok(r) => r,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Send periodic ping if interval elapsed
                        if last_ping.elapsed() >= PING_INTERVAL {
                            let ping = crate::dc_messages::DcMessage::Ping {
                                ts_ms: crate::dc_messages::now_ms(),
                            };
                            if let Ok(json) = crate::dc_messages::encode_dc_message(&ping) {
                                if let Ok(env) = crate::envelope::encode_envelope(&json, &session) {
                                    let _ = dc.send(&env);
                                    eprintln!("[INTEROP-4] sent periodic ping");
                                }
                            }
                            last_ping = Instant::now();
                        }
                        continue;
                    }
                    Err(e) => return Err(format!("[INTEROP-4] DC recv error: {e}").into()),
                };

                match crate::envelope::decode_envelope(&raw, &session) {
                    Ok(inner) => match crate::envelope::route_inner_message(&inner, &session) {
                        Ok(Some(reply)) => {
                            let _ = dc.send(&reply);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            eprintln!("[INTEROP-4] route error: {e}");
                            let err_payload = crate::envelope::build_error_payload(
                                e.code(),
                                &e.to_string(),
                                Some(&session),
                            );
                            let _ = dc.send(&err_payload);
                            return Err(format!("[INTEROP-4] {e}").into());
                        }
                    },
                    Err(e) => {
                        eprintln!("[INTEROP-3_ENVELOPE_ERR] {e}");
                        let err_payload = crate::envelope::build_error_payload(
                            e.code(),
                            &e.to_string(),
                            Some(&session),
                        );
                        let _ = dc.send(&err_payload);
                        return Err(format!("[INTEROP-3_ENVELOPE_ERR] {e}").into());
                    }
                }
            }
        }
    } else {
        // Legacy daemon HELLO
        dc.send(HELLO_PAYLOAD)?;
        eprintln!(
            "[offerer] sent: {:?}",
            std::str::from_utf8(HELLO_PAYLOAD).unwrap_or("<binary>")
        );

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("phase timeout expired waiting for echo")?;
        let response = dc_msg_rx.recv_timeout(remaining)?;
        if response != HELLO_PAYLOAD {
            return Err(format!(
                "payload mismatch: expected {:?}, got {:?}",
                HELLO_PAYLOAD, response
            )
            .into());
        }
        eprintln!("[offerer] SUCCESS — received matching payload");
    }

    Ok(())
}

/// Answerer flow via rendezvous signaling.
///
/// Flow: register → wait hello → validate hello → send ack → wait offer
///       → create PC → apply offer → collect answer → send answer → DataChannel exchange
///
/// INVARIANT: `--signal rendezvous` is required. No fallback to file mode.
/// If the server is down or peer is unreachable, exit 1.
pub fn run_answerer_rendezvous(
    args: &Args,
    ipc_server: Option<&crate::ipc::server::IpcServer>,
    trust_path: &std::path::Path,
    identity: &bolt_core::identity::IdentityKeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fail-closed: these are validated in parse_args() but double-check here
    let room = args
        .room
        .as_ref()
        .ok_or("BUG: --room required for rendezvous mode")?;
    let expect_peer = args
        .expect_peer
        .as_ref()
        .ok_or("BUG: --expect-peer required for answerer rendezvous mode")?;
    let session = args
        .session
        .as_ref()
        .ok_or("BUG: --session required for rendezvous mode")?;
    let peer_id = args.peer_id.clone().unwrap_or_else(generate_peer_id);

    eprintln!(
        "[answerer] rendezvous mode: room='{}', session='{}', peer_id='{}', expect-peer='{}'",
        room, session, peer_id, expect_peer
    );
    if args.interop_signal == crate::web_signal::InteropSignal::WebV1 {
        eprintln!("[INTEROP-1] web_v1 mode enabled — using web payload schema");
    }
    let use_web_hello = args.interop_hello == crate::web_hello::InteropHelloMode::WebHelloV1;
    if use_web_hello {
        eprintln!("[INTEROP-2] web_hello_v1 mode enabled — encrypted HELLO");
    }

    // Generate ephemeral session keypair for signaling + sealing (per session).
    // Persistent identity is used ONLY for identityPublicKey in HELLO inner field.
    let session_kp = if use_web_hello {
        let kp = bolt_core::crypto::generate_ephemeral_keypair();
        eprintln!(
            "[SA1] session ephemeral pk={}, persistent identity pk={}",
            bolt_core::encoding::to_base64(&kp.public_key),
            bolt_core::encoding::to_base64(&identity.public_key)
        );
        Some(kp)
    } else {
        None
    };
    let local_pk_b64 = session_kp
        .as_ref()
        .map(|kp| bolt_core::encoding::to_base64(&kp.public_key));

    let deadline = Instant::now() + args.phase_timeout;

    // Connect and register (fails hard if server unreachable — no fallback)
    let mut ws = connect_and_register(&args.rendezvous_url, &peer_id)?;

    // ── Hello/ack handshake ──────────────────────────────────
    // Wait for hello from expected peer
    let hello = wait_for_signal(&mut ws, deadline, expect_peer, room, session, "hello")?;

    // Validate hello fields
    if let Some(ref from) = hello.from_peer {
        if from != expect_peer {
            return Err(format!(
                "hello from_peer mismatch: expected '{}', got '{}'",
                expect_peer, from
            )
            .into());
        }
    }
    if let Some(ref to) = hello.to_peer {
        if to != &peer_id {
            return Err(format!(
                "hello to_peer mismatch: expected '{}', got '{}'",
                peer_id, to
            )
            .into());
        }
    }
    // Validate network_scope match
    let local_scope_str = scope_to_str(args.network_scope);
    if let Some(ref remote_scope) = hello.network_scope {
        if remote_scope != local_scope_str {
            return Err(format!(
                "network_scope mismatch: remote='{}' local='{}'",
                remote_scope, local_scope_str
            )
            .into());
        }
    }

    // ── Pairing approval gate ──────────────────────────────────
    let remote_peer = hello.from_peer.as_deref().unwrap_or(expect_peer);
    if !crate::ipc::trust::check_pairing_approval(
        ipc_server,
        trust_path,
        remote_peer,
        args.pairing_policy,
    ) {
        return Err(format!(
            "pairing denied for peer '{}' — aborting handshake",
            remote_peer
        )
        .into());
    }
    eprintln!("[rendezvous] pairing approved for peer '{}'", remote_peer);

    // Send ack to expected peer
    let ack_payload = SignalPayload {
        payload_version: PAYLOAD_VERSION,
        session: session.clone(),
        room: room.clone(),
        msg_type: "ack".to_string(),
        bundle: None,
        from_peer: Some(peer_id.clone()),
        to_peer: Some(expect_peer.clone()),
        network_scope: None,
        phase_timeout_secs: None,
    };
    send_signal(&mut ws, expect_peer, &ack_payload)?;

    eprintln!("[rendezvous] hello/ack complete — session '{}'", session);

    // ── Offer/answer exchange ────────────────────────────────

    // Wait for offer from expected peer (deadline-respecting, filtered)
    let (offer_bundle, remote_pk_b64) = match args.interop_signal {
        crate::web_signal::InteropSignal::WebV1 => receive_web_bundle(
            &mut ws,
            deadline,
            expect_peer,
            room,
            session,
            "offer",
            args.network_scope,
        )?,
        crate::web_signal::InteropSignal::DaemonV1 => {
            let offer_sp = wait_for_signal(&mut ws, deadline, expect_peer, room, session, "offer")?;
            let bundle = offer_sp.bundle.ok_or("offer signal missing bundle")?;
            (bundle, None)
        }
    };

    // Create PeerConnection
    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    // Apply offer (reuses scope-filtered logic)
    apply_remote_signal(&mut pc, &offer_bundle, args.network_scope)?;

    // Collect answer bundle (reuses scope-filtered logic)
    let answer_bundle = collect_local_signal(&ch, args.phase_timeout)?;

    // Send answer to expected peer via rendezvous
    match args.interop_signal {
        crate::web_signal::InteropSignal::WebV1 => {
            eprintln!("[INTEROP-1] answerer sending web-format answer");
            send_web_payloads(
                &mut ws,
                expect_peer,
                &answer_bundle,
                "answer",
                &peer_id,
                local_pk_b64.as_deref(),
            )?;
        }
        crate::web_signal::InteropSignal::DaemonV1 => {
            let answer_payload = SignalPayload {
                payload_version: PAYLOAD_VERSION,
                session: session.clone(),
                room: room.clone(),
                msg_type: "answer".to_string(),
                bundle: Some(answer_bundle),
                from_peer: None,
                to_peer: None,
                network_scope: None,
                phase_timeout_secs: None,
            };
            send_signal(&mut ws, expect_peer, &answer_payload)?;
        }
    }

    // Wait for incoming DataChannel
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for incoming DataChannel")?;
    let mut dc = ch.incoming_dc_rx.recv_timeout(remaining)?;
    eprintln!("[answerer] DataChannel received");

    // Wait for DC to open
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for DataChannel open")?;
    ch.dc_open_rx.recv_timeout(remaining)?;
    eprintln!("[answerer] DataChannel open");

    // ── DataChannel HELLO exchange ──────────────────────────
    if use_web_hello {
        // SA1 Phase B: Separated identity (persistent) + session (ephemeral) keys
        let local_session = session_kp
            .as_ref()
            .ok_or("[INTEROP-2_HELLO_FAIL] session keypair missing for web HELLO (answerer)")?;
        let remote_pk_b64_str = remote_pk_b64.as_deref().ok_or(
            "[INTEROP-2_HELLO_FAIL] no remote session key in offer signal — cannot encrypt HELLO",
        )?;
        let remote_pk = crate::web_hello::decode_public_key(remote_pk_b64_str)?;
        eprintln!("[INTEROP-2] remote session pk: {}", remote_pk_b64_str);

        // Receive + decrypt remote HELLO (session_kp for opening)
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("phase timeout expired waiting for web HELLO")?;
        let msg = ch.dc_msg_rx.recv_timeout(remaining)?;
        let remote_hello = crate::web_hello::parse_hello_message(&msg, &remote_pk, local_session)?;

        // Send encrypted HELLO reply (identity.pk in inner field, session_kp for sealing)
        let hello_msg = crate::web_hello::build_hello_message(&identity.public_key, local_session, &remote_pk)?;
        dc.send(hello_msg.as_bytes())?;
        eprintln!("[INTEROP-2] sent encrypted HELLO reply");

        // Negotiate capabilities
        let local_caps = crate::web_hello::daemon_capabilities();
        let negotiated =
            crate::web_hello::negotiate_capabilities(&local_caps, &remote_hello.capabilities);
        eprintln!(
            "[INTEROP-2] HELLO exchange complete — remote_identity={}, negotiated_caps={:?}",
            remote_hello.identity_public_key, negotiated
        );

        // ── INTEROP-3: Session context uses ephemeral session keypair ────
        let session =
            crate::session::SessionContext::new(local_session.clone(), remote_pk, negotiated.clone())?;

        if args.interop_dc == crate::InteropDcMode::WebDcV1 {
            if !session.envelope_v1_negotiated() {
                return Err("[INTEROP-3_NO_ENVELOPE_CAP] bolt.profile-envelope-v1 not negotiated — aborting".into());
            }
            eprintln!("[INTEROP-3] entering post-HELLO DC envelope loop (answerer)");

            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("phase timeout expired in DC envelope loop")?;
                let raw = match ch.dc_msg_rx.recv_timeout(remaining) {
                    Ok(r) => r,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        eprintln!("[INTEROP-4] DC loop timeout — clean exit");
                        break;
                    }
                    Err(e) => return Err(format!("[INTEROP-4] DC recv error: {e}").into()),
                };

                match crate::envelope::decode_envelope(&raw, &session) {
                    Ok(inner) => match crate::envelope::route_inner_message(&inner, &session) {
                        Ok(Some(reply)) => {
                            let _ = dc.send(&reply);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            eprintln!("[INTEROP-4] route error: {e}");
                            let err_payload = crate::envelope::build_error_payload(
                                e.code(),
                                &e.to_string(),
                                Some(&session),
                            );
                            let _ = dc.send(&err_payload);
                            return Err(format!("[INTEROP-4] {e}").into());
                        }
                    },
                    Err(e) => {
                        eprintln!("[INTEROP-3_ENVELOPE_ERR] {e}");
                        let err_payload = crate::envelope::build_error_payload(
                            e.code(),
                            &e.to_string(),
                            Some(&session),
                        );
                        let _ = dc.send(&err_payload);
                        return Err(format!("[INTEROP-3_ENVELOPE_ERR] {e}").into());
                    }
                }
            }
        } else {
            thread::sleep(Duration::from_millis(500));
        }
    } else {
        // Legacy daemon HELLO
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("phase timeout expired waiting for hello payload")?;
        let msg = ch.dc_msg_rx.recv_timeout(remaining)?;
        eprintln!(
            "[answerer] received: {:?}",
            std::str::from_utf8(&msg).unwrap_or("<binary>")
        );

        if msg == HELLO_PAYLOAD {
            dc.send(HELLO_PAYLOAD)?;
            eprintln!("[answerer] SUCCESS — echoed matching payload");
            thread::sleep(Duration::from_millis(500));
        } else {
            return Err(format!(
                "payload mismatch: expected {:?}, got {:?}",
                HELLO_PAYLOAD, msg
            )
            .into());
        }
    }

    Ok(())
}

// ── Parameterized rendezvous session (smoke hook) ───────────

/// Run the full rendezvous signaling flow (connect, hello/ack, offer/answer,
/// DataChannel open), then hand control to `exchange` for the data phase.
///
/// This is the ONLY pub(crate) entry point for custom exchange logic over
/// rendezvous. The existing `run_offerer_rendezvous` and `run_answerer_rendezvous`
/// functions are untouched. No rendezvous internals are exposed.
pub(crate) fn run_rendezvous_session_with_exchange<F>(
    args: &crate::Args,
    exchange: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(SmokeDcContext<'a>) -> Result<(), Box<dyn std::error::Error>>,
{
    match args.role.as_ref().ok_or("role required for rendezvous")? {
        crate::Role::Offerer => offerer_with_exchange(args, exchange),
        crate::Role::Answerer => answerer_with_exchange(args, exchange),
    }
}

/// Offerer flow with custom exchange. Identical to `run_offerer_rendezvous`
/// except the DataChannel data phase is delegated to `exchange`.
fn offerer_with_exchange<F>(
    args: &crate::Args,
    exchange: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(SmokeDcContext<'a>) -> Result<(), Box<dyn std::error::Error>>,
{
    let room = args
        .room
        .as_ref()
        .ok_or("BUG: --room required for rendezvous mode")?;
    let to_peer = args
        .to_peer
        .as_ref()
        .ok_or("BUG: --to required for offerer rendezvous mode")?;
    let session = args
        .session
        .as_ref()
        .ok_or("BUG: --session required for rendezvous mode")?;
    let peer_id = args.peer_id.clone().unwrap_or_else(generate_peer_id);

    eprintln!(
        "[offerer] rendezvous mode: room='{}', session='{}', peer_id='{}', to='{}'",
        room, session, peer_id, to_peer
    );

    let deadline = Instant::now() + args.phase_timeout;
    let mut ws = connect_and_register(&args.rendezvous_url, &peer_id)?;

    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    let (dc_open_tx, dc_open_rx) = mpsc::channel();
    let (dc_msg_tx, dc_msg_rx) = mpsc::channel();

    let dc_handler = crate::DcHandler {
        open_tx: dc_open_tx,
        msg_tx: dc_msg_tx,
    };

    let mut dc = pc.create_data_channel(crate::DC_LABEL, dc_handler)?;
    eprintln!("[offerer] DataChannel '{}' created", crate::DC_LABEL);

    // Hello/ack handshake with retry (identical to run_offerer_rendezvous)
    let hello_payload = SignalPayload {
        payload_version: PAYLOAD_VERSION,
        session: session.clone(),
        room: room.clone(),
        msg_type: "hello".to_string(),
        bundle: None,
        from_peer: Some(peer_id.clone()),
        to_peer: Some(to_peer.clone()),
        network_scope: Some(scope_to_str(args.network_scope).to_string()),
        phase_timeout_secs: Some(args.phase_timeout.as_secs()),
    };

    let mut backoff = Duration::from_millis(100);
    let max_backoff = Duration::from_secs(1);

    let ack = loop {
        send_signal(&mut ws, to_peer, &hello_payload)?;

        match wait_for_signal(&mut ws, deadline, to_peer, room, session, "ack") {
            Ok(ack) => break ack,
            Err(e) => {
                let msg = e.to_string();
                let server_msg = msg
                    .strip_prefix("rendezvous server error: ")
                    .unwrap_or(&msg);
                if is_retryable_peer_not_found(server_msg, to_peer) {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out waiting for peer '{}' to register",
                            to_peer
                        )
                        .into());
                    }
                    eprintln!(
                        "[rendezvous] hello retry: target '{}' not registered yet",
                        to_peer
                    );
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                    continue;
                }
                return Err(e);
            }
        }
    };

    // Validate ack fields
    if let Some(ref from) = ack.from_peer {
        if from != to_peer {
            return Err(format!(
                "ack from_peer mismatch: expected '{}', got '{}'",
                to_peer, from
            )
            .into());
        }
    }
    if let Some(ref to) = ack.to_peer {
        if to != &peer_id {
            return Err(
                format!("ack to_peer mismatch: expected '{}', got '{}'", peer_id, to).into(),
            );
        }
    }

    eprintln!("[rendezvous] hello/ack complete — session '{}'", session);

    // Offer/answer exchange
    let offer_bundle = collect_local_signal(&ch, args.phase_timeout)?;

    let offer_payload = SignalPayload {
        payload_version: PAYLOAD_VERSION,
        session: session.clone(),
        room: room.clone(),
        msg_type: "offer".to_string(),
        bundle: Some(offer_bundle),
        from_peer: None,
        to_peer: None,
        network_scope: None,
        phase_timeout_secs: None,
    };
    send_signal(&mut ws, to_peer, &offer_payload)?;

    let answer_sp = wait_for_signal(&mut ws, deadline, to_peer, room, session, "answer")?;
    let answer_bundle = answer_sp.bundle.ok_or("answer signal missing bundle")?;

    apply_remote_signal(&mut pc, &answer_bundle, args.network_scope)?;

    // Wait for DataChannel open
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for DataChannel open")?;
    dc_open_rx.recv_timeout(remaining)?;
    eprintln!("[offerer] DataChannel open");

    // Hand off to exchange closure
    let ctx = SmokeDcContext {
        dc: &mut dc,
        msg_rx: &dc_msg_rx,
        peer_id: Some(&peer_id),
        expect_peer: Some(to_peer),
    };
    exchange(ctx)
}

/// Answerer flow with custom exchange. Identical to `run_answerer_rendezvous`
/// except the DataChannel data phase is delegated to `exchange`.
fn answerer_with_exchange<F>(
    args: &crate::Args,
    exchange: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: for<'a> FnOnce(SmokeDcContext<'a>) -> Result<(), Box<dyn std::error::Error>>,
{
    let room = args
        .room
        .as_ref()
        .ok_or("BUG: --room required for rendezvous mode")?;
    let expect_peer = args
        .expect_peer
        .as_ref()
        .ok_or("BUG: --expect-peer required for answerer rendezvous mode")?;
    let session = args
        .session
        .as_ref()
        .ok_or("BUG: --session required for rendezvous mode")?;
    let peer_id = args.peer_id.clone().unwrap_or_else(generate_peer_id);

    eprintln!(
        "[answerer] rendezvous mode: room='{}', session='{}', peer_id='{}', expect-peer='{}'",
        room, session, peer_id, expect_peer
    );

    let deadline = Instant::now() + args.phase_timeout;
    let mut ws = connect_and_register(&args.rendezvous_url, &peer_id)?;

    // Hello/ack handshake (identical to run_answerer_rendezvous)
    let hello = wait_for_signal(&mut ws, deadline, expect_peer, room, session, "hello")?;

    // Validate hello fields
    if let Some(ref from) = hello.from_peer {
        if from != expect_peer {
            return Err(format!(
                "hello from_peer mismatch: expected '{}', got '{}'",
                expect_peer, from
            )
            .into());
        }
    }
    if let Some(ref to) = hello.to_peer {
        if to != &peer_id {
            return Err(format!(
                "hello to_peer mismatch: expected '{}', got '{}'",
                peer_id, to
            )
            .into());
        }
    }
    let local_scope_str = scope_to_str(args.network_scope);
    if let Some(ref remote_scope) = hello.network_scope {
        if remote_scope != local_scope_str {
            return Err(format!(
                "network_scope mismatch: remote='{}' local='{}'",
                remote_scope, local_scope_str
            )
            .into());
        }
    }

    // Send ack
    let ack_payload = SignalPayload {
        payload_version: PAYLOAD_VERSION,
        session: session.clone(),
        room: room.clone(),
        msg_type: "ack".to_string(),
        bundle: None,
        from_peer: Some(peer_id.clone()),
        to_peer: Some(expect_peer.clone()),
        network_scope: None,
        phase_timeout_secs: None,
    };
    send_signal(&mut ws, expect_peer, &ack_payload)?;

    eprintln!("[rendezvous] hello/ack complete — session '{}'", session);

    // Offer/answer exchange
    let offer_sp = wait_for_signal(&mut ws, deadline, expect_peer, room, session, "offer")?;
    let offer_bundle = offer_sp.bundle.ok_or("offer signal missing bundle")?;

    let (mut pc, ch) = create_peer_connection(args.network_scope)?;

    apply_remote_signal(&mut pc, &offer_bundle, args.network_scope)?;

    let answer_bundle = collect_local_signal(&ch, args.phase_timeout)?;

    let answer_payload = SignalPayload {
        payload_version: PAYLOAD_VERSION,
        session: session.clone(),
        room: room.clone(),
        msg_type: "answer".to_string(),
        bundle: Some(answer_bundle),
        from_peer: None,
        to_peer: None,
        network_scope: None,
        phase_timeout_secs: None,
    };
    send_signal(&mut ws, expect_peer, &answer_payload)?;

    // Wait for incoming DataChannel
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for incoming DataChannel")?;
    let mut dc = ch.incoming_dc_rx.recv_timeout(remaining)?;
    eprintln!("[answerer] DataChannel received");

    // Wait for DC to open
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("phase timeout expired waiting for DataChannel open")?;
    ch.dc_open_rx.recv_timeout(remaining)?;
    eprintln!("[answerer] DataChannel open");

    // Hand off to exchange closure
    let ctx = SmokeDcContext {
        dc: &mut dc,
        msg_rx: &ch.dc_msg_rx,
        peer_id: Some(&peer_id),
        expect_peer: Some(expect_peer),
    };
    let result = exchange(ctx);

    // Answerer drain sleep (same as default mode)
    if result.is_ok() {
        thread::sleep(Duration::from_millis(500));
    }

    result
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateInfo, SdpInfo};

    #[test]
    fn signal_payload_offer_serde_roundtrip() {
        let payload = SignalPayload {
            payload_version: PAYLOAD_VERSION,
            session: "test-session".to_string(),
            room: "test-room".to_string(),
            msg_type: "offer".to_string(),
            bundle: Some(SignalBundle {
                description: SdpInfo {
                    sdp_type: "offer".to_string(),
                    sdp: "v=0\r\ntest".to_string(),
                },
                candidates: vec![CandidateInfo {
                    candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host"
                        .to_string(),
                    mid: "0".to_string(),
                }],
            }),
            from_peer: None,
            to_peer: None,
            network_scope: None,
            phase_timeout_secs: None,
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: SignalPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.payload_version, 1);
        assert_eq!(decoded.session, "test-session");
        assert_eq!(decoded.room, "test-room");
        assert_eq!(decoded.msg_type, "offer");
        assert!(decoded.bundle.is_some());
        let bundle = decoded.bundle.unwrap();
        assert_eq!(bundle.description.sdp_type, "offer");
        assert_eq!(bundle.candidates.len(), 1);
        // hello-specific fields absent
        assert!(decoded.from_peer.is_none());
        assert!(decoded.to_peer.is_none());
        assert!(decoded.network_scope.is_none());
        assert!(decoded.phase_timeout_secs.is_none());
        // verify absent fields are not in JSON
        assert!(!json.contains("from_peer"));
        assert!(!json.contains("to_peer"));
        assert!(!json.contains("network_scope"));
        assert!(!json.contains("phase_timeout_secs"));
    }

    #[test]
    fn hello_payload_serde_roundtrip() {
        let payload = SignalPayload {
            payload_version: PAYLOAD_VERSION,
            session: "sess-abc".to_string(),
            room: "room-1".to_string(),
            msg_type: "hello".to_string(),
            bundle: None,
            from_peer: Some("alice".to_string()),
            to_peer: Some("bob".to_string()),
            network_scope: Some("lan".to_string()),
            phase_timeout_secs: Some(30),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: SignalPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.payload_version, 1);
        assert_eq!(decoded.session, "sess-abc");
        assert_eq!(decoded.msg_type, "hello");
        assert!(decoded.bundle.is_none());
        assert_eq!(decoded.from_peer.as_deref(), Some("alice"));
        assert_eq!(decoded.to_peer.as_deref(), Some("bob"));
        assert_eq!(decoded.network_scope.as_deref(), Some("lan"));
        assert_eq!(decoded.phase_timeout_secs, Some(30));
        // verify bundle not in JSON
        assert!(!json.contains("bundle"));
    }

    #[test]
    fn ack_payload_serde_roundtrip() {
        let payload = SignalPayload {
            payload_version: PAYLOAD_VERSION,
            session: "sess-abc".to_string(),
            room: "room-1".to_string(),
            msg_type: "ack".to_string(),
            bundle: None,
            from_peer: Some("bob".to_string()),
            to_peer: Some("alice".to_string()),
            network_scope: None,
            phase_timeout_secs: None,
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: SignalPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.msg_type, "ack");
        assert_eq!(decoded.from_peer.as_deref(), Some("bob"));
        assert_eq!(decoded.to_peer.as_deref(), Some("alice"));
        assert!(decoded.bundle.is_none());
        assert!(decoded.network_scope.is_none());
    }

    #[test]
    fn reject_unknown_payload_version() {
        // Simulate a payload with version 99 — the check logic should detect it
        let payload = SignalPayload {
            payload_version: 99,
            session: "test".to_string(),
            room: "test".to_string(),
            msg_type: "offer".to_string(),
            bundle: None,
            from_peer: None,
            to_peer: None,
            network_scope: None,
            phase_timeout_secs: None,
        };
        assert_ne!(payload.payload_version, PAYLOAD_VERSION);
    }

    #[test]
    fn session_mismatch_detected() {
        let payload = SignalPayload {
            payload_version: PAYLOAD_VERSION,
            session: "session-A".to_string(),
            room: "test".to_string(),
            msg_type: "offer".to_string(),
            bundle: None,
            from_peer: None,
            to_peer: None,
            network_scope: None,
            phase_timeout_secs: None,
        };
        let expected_session = "session-B";
        assert_ne!(payload.session, expected_session);
    }

    #[test]
    fn scope_to_str_values() {
        assert_eq!(scope_to_str(NetworkScope::Lan), "lan");
        assert_eq!(scope_to_str(NetworkScope::Overlay), "overlay");
        assert_eq!(scope_to_str(NetworkScope::Global), "global");
    }

    #[test]
    fn client_msg_register_serde() {
        let msg = ClientMessage::Register {
            peer_code: "alice".to_string(),
            device_name: "bolt-daemon".to_string(),
            device_type: DeviceType::Desktop,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"register\""));
        assert!(json.contains("\"peer_code\":\"alice\""));
        assert!(json.contains("\"device_name\":\"bolt-daemon\""));
        assert!(json.contains("\"device_type\":\"desktop\""));
    }

    #[test]
    fn client_msg_signal_serde() {
        let msg = ClientMessage::Signal {
            to: "bob".to_string(),
            payload: serde_json::json!({"room": "test", "msg_type": "offer"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"signal\""));
        assert!(json.contains("\"to\":\"bob\""));
    }

    #[test]
    fn client_msg_ping_serde() {
        let msg = ClientMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "{\"type\":\"ping\"}");
    }

    #[test]
    fn server_msg_peers_deser() {
        let json = r#"{"type":"peers","peers":[{"peer_code":"alice","device_name":"test","device_type":"desktop"}]}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMessage::Peers { .. }));
    }

    #[test]
    fn server_msg_peer_joined_deser() {
        let json = r#"{"type":"peer_joined","peer":{"peer_code":"bob","device_name":"test","device_type":"desktop"}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMessage::PeerJoined { .. }));
    }

    #[test]
    fn server_msg_peer_left_deser() {
        let json = r#"{"type":"peer_left","peer_code":"bob"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMessage::PeerLeft { .. }));
    }

    #[test]
    fn server_msg_signal_deser() {
        let json = r#"{"type":"signal","from":"alice","payload":{"payload_version":1,"session":"s1","room":"test","msg_type":"offer","bundle":{"description":{"sdp_type":"offer","sdp":"v=0"},"candidates":[]}}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Signal { from, payload } => {
                assert_eq!(from, "alice");
                let sp: SignalPayload = serde_json::from_value(payload).unwrap();
                assert_eq!(sp.room, "test");
                assert_eq!(sp.msg_type, "offer");
                assert_eq!(sp.payload_version, 1);
                assert_eq!(sp.session, "s1");
            }
            _ => panic!("expected Signal"),
        }
    }

    #[test]
    fn server_msg_error_deser() {
        let json = r#"{"type":"error","message":"peer not found"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Error { message } => assert_eq!(message, "peer not found"),
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn peer_id_auto_generation() {
        let id = generate_peer_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        // Two calls should produce different IDs (time-based)
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_peer_id();
        assert_ne!(id, id2);
    }

    // ── Retry classifier tests ──────────────────────────────

    #[test]
    fn retryable_peer_not_found_exact_match() {
        assert!(is_retryable_peer_not_found("peer 'bob' not found", "bob"));
        assert!(is_retryable_peer_not_found(
            "peer 'alice' not found",
            "alice"
        ));
    }

    #[test]
    fn retryable_peer_not_found_wrong_peer() {
        // Error mentions a different peer than the target — not retryable
        assert!(!is_retryable_peer_not_found(
            "peer 'charlie' not found",
            "bob"
        ));
    }

    #[test]
    fn retryable_peer_not_found_rejects_generic_errors() {
        assert!(!is_retryable_peer_not_found("connection refused", "bob"));
        assert!(!is_retryable_peer_not_found("internal server error", "bob"));
        assert!(!is_retryable_peer_not_found("peer not found", "bob")); // missing quotes
        assert!(!is_retryable_peer_not_found("", "bob"));
    }
}
