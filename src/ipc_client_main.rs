//! bolt-ipc-client — Dev harness for the daemon IPC channel.
//!
//! Connects to the bolt-daemon Unix socket, prints incoming events,
//! and auto-replies to approval prompts.
//!
//! Usage:
//!   bolt-ipc-client [--socket <path>] [--auto-allow]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const DEFAULT_SOCKET: &str = "/tmp/bolt-daemon.sock";

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut socket_path = DEFAULT_SOCKET.to_string();
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

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ipc-client] FATAL: failed to connect to {socket_path}: {e}");
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
    let mut writer = stream;
    let reader = BufReader::new(read_stream);

    eprintln!("[ipc-client] connected, reading events...");

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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
