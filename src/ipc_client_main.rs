//! bolt-ipc-client — Dev harness for the daemon IPC channel.
//!
//! Connects to the bolt-daemon IPC endpoint (Unix socket or Windows named pipe),
//! prints incoming events, and auto-replies to approval prompts.
//!
//! Usage:
//!   bolt-ipc-client [--socket <path>] [--auto-allow]

use std::io::{BufRead, BufReader, Write};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut socket_path = bolt_daemon::IPC_DEFAULT_PATH.to_string();
    let mut auto_allow = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--socket" => {
                i += 1;
                socket_path = argv.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("--socket requires a path");
                    std::process::exit(1);
                });
            }
            "--auto-allow" => {
                auto_allow = true;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!("Usage: bolt-ipc-client [--socket <path>] [--auto-allow]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let decision_str = if auto_allow {
        "allow_once"
    } else {
        "deny_once"
    };
    eprintln!("[ipc-client] connecting to {socket_path} (auto-reply: {decision_str})");

    let (reader, mut writer) = connect_ipc(&socket_path);

    eprintln!("[ipc-client] connected, sending version.handshake...");

    // Send version.handshake as first message (B-DEP-N2-2 contract).
    let handshake = serde_json::json!({
        "id": "cli-handshake",
        "kind": "decision",
        "type": "version.handshake",
        "ts_ms": now_ms(),
        "payload": { "app_version": env!("CARGO_PKG_VERSION") }
    });
    let mut hs_line = match serde_json::to_string(&handshake) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ipc-client] FATAL: serialize version.handshake: {e}");
            std::process::exit(1);
        }
    };
    hs_line.push('\n');
    if let Err(e) = writer.write_all(hs_line.as_bytes()) {
        eprintln!("[ipc-client] FATAL: write version.handshake: {e}");
        std::process::exit(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("[ipc-client] FATAL: flush version.handshake: {e}");
        std::process::exit(1);
    }
    eprintln!("[ipc-client] version.handshake sent, reading events...");

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[ipc-client] read error: {e}");
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        // Parse the message
        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[ipc-client] invalid JSON: {e}");
                continue;
            }
        };

        let msg_type = msg["type"].as_str().unwrap_or("unknown");
        let kind = msg["kind"].as_str().unwrap_or("unknown");

        println!(
            "[ipc-client] << {kind} | {msg_type} | {}",
            serde_json::to_string(&msg["payload"]).unwrap_or_default()
        );

        // Auto-reply to approval prompts
        match msg_type {
            "pairing.request" => {
                let request_id = msg["payload"]["request_id"].as_str().unwrap_or("unknown");
                let reply = serde_json::json!({
                    "id": format!("cli-reply-{}", request_id),
                    "kind": "decision",
                    "type": "pairing.decision",
                    "ts_ms": now_ms(),
                    "payload": {
                        "request_id": request_id,
                        "decision": decision_str,
                        "note": "auto-reply from bolt-ipc-client"
                    }
                });
                let mut reply_line = match serde_json::to_string(&reply) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[ipc-client] FATAL: serialize reply: {e}");
                        break;
                    }
                };
                reply_line.push('\n');
                if let Err(e) = writer.write_all(reply_line.as_bytes()) {
                    eprintln!("[ipc-client] write error: {e}");
                    break;
                }
                if let Err(e) = writer.flush() {
                    eprintln!("[ipc-client] flush error: {e}");
                    break;
                }
                println!(
                    "[ipc-client] >> pairing.decision: {decision_str} (request_id={request_id})"
                );
            }
            "transfer.incoming.request" => {
                let request_id = msg["payload"]["request_id"].as_str().unwrap_or("unknown");
                let reply = serde_json::json!({
                    "id": format!("cli-reply-{}", request_id),
                    "kind": "decision",
                    "type": "transfer.incoming.decision",
                    "ts_ms": now_ms(),
                    "payload": {
                        "request_id": request_id,
                        "decision": decision_str,
                        "note": "auto-reply from bolt-ipc-client"
                    }
                });
                let mut reply_line = match serde_json::to_string(&reply) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[ipc-client] FATAL: serialize reply: {e}");
                        break;
                    }
                };
                reply_line.push('\n');
                if let Err(e) = writer.write_all(reply_line.as_bytes()) {
                    eprintln!("[ipc-client] write error: {e}");
                    break;
                }
                if let Err(e) = writer.flush() {
                    eprintln!("[ipc-client] flush error: {e}");
                    break;
                }
                println!(
                    "[ipc-client] >> transfer.incoming.decision: {decision_str} (request_id={request_id})"
                );
            }
            _ => {
                // Just print, no reply needed (e.g. daemon.status)
            }
        }
    }

    eprintln!("[ipc-client] disconnected");
}

/// Connect to the IPC endpoint and return (reader, writer) pair.
#[cfg(unix)]
fn connect_ipc(
    path: &str,
) -> (
    BufReader<std::os::unix::net::UnixStream>,
    std::os::unix::net::UnixStream,
) {
    use std::os::unix::net::UnixStream;
    let stream = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ipc-client] FATAL: failed to connect to {path}: {e}");
            std::process::exit(1);
        }
    };
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ipc-client] FATAL: failed to clone stream: {e}");
            std::process::exit(1);
        }
    };
    (BufReader::new(read_stream), stream)
}

/// Connect to the IPC endpoint (Windows named pipe) and return (reader, writer) pair.
#[cfg(windows)]
fn connect_ipc(path: &str) -> (BufReader<std::fs::File>, std::fs::File) {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ipc-client] FATAL: failed to connect to {path}: {e}");
            std::process::exit(1);
        }
    };
    let read_file = match file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ipc-client] FATAL: failed to clone pipe handle: {e}");
            std::process::exit(1);
        }
    };
    (BufReader::new(read_file), file)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
