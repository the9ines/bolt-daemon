//! N6-B2 integration tests: Windows named pipe transport + transport abstraction.
//!
//! Tests are organized by scope:
//! - Transport detection: all platforms (path format classification)
//! - Unix regression: unix-only (IpcServer with IpcStream through transport layer)
//! - Windows pipe: windows-only (NamedPipeListener + NamedPipeStream lifecycle)
//! - Handshake ordering: unix (N2 handshake semantics through transport layer)
//! - Reconnect/single-client: unix (kick-on-reconnect through transport layer)

// ── Transport Detection (all platforms) ─────────────────────

#[test]
fn transport_detect_unix_socket_path() {
    assert!(!bolt_daemon::ipc_transport_is_windows_pipe(
        "/tmp/bolt-daemon.sock"
    ));
}

#[test]
fn transport_detect_windows_pipe_path() {
    assert!(bolt_daemon::ipc_transport_is_windows_pipe(
        r"\\.\pipe\bolt-daemon"
    ));
}

#[test]
fn transport_detect_windows_pipe_uppercase() {
    assert!(bolt_daemon::ipc_transport_is_windows_pipe(
        r"\\.\PIPE\bolt-daemon"
    ));
}

#[test]
fn transport_detect_empty_path() {
    assert!(!bolt_daemon::ipc_transport_is_windows_pipe(""));
}

#[test]
fn transport_detect_relative_path() {
    assert!(!bolt_daemon::ipc_transport_is_windows_pipe(
        "bolt-daemon.sock"
    ));
}

#[test]
fn transport_detect_windows_pipe_with_subdirectory() {
    assert!(bolt_daemon::ipc_transport_is_windows_pipe(
        r"\\.\pipe\the9ines\bolt-daemon"
    ));
}

// ── Default Path (all platforms) ─────────────────────────────

#[test]
fn default_ipc_path_not_empty() {
    assert!(!bolt_daemon::IPC_DEFAULT_PATH.is_empty());
}

#[cfg(unix)]
#[test]
fn default_ipc_path_is_unix_on_unix() {
    assert!(bolt_daemon::IPC_DEFAULT_PATH.ends_with(".sock"));
}

// ── Unix Regression: IpcServer through transport layer ──────

#[cfg(unix)]
mod unix_regression {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn temp_socket_path() -> String {
        let dir = std::env::temp_dir();
        format!(
            "{}/bolt-n6b2-test-{}.sock",
            dir.display(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    fn send_version_handshake(stream: &mut UnixStream, app_version: &str) {
        let msg = serde_json::json!({
            "id": "cli-0",
            "kind": "decision",
            "type": "version.handshake",
            "ts_ms": 0,
            "payload": { "app_version": app_version }
        });
        let mut line = serde_json::to_string(&msg).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    fn read_ipc_line(reader: &mut BufReader<UnixStream>) -> Option<serde_json::Value> {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => serde_json::from_str(&line).ok(),
            Err(_) => None,
        }
    }

    /// Verify the transport-abstracted IpcServer still produces correct
    /// N2 handshake ordering: version.status → daemon.status.
    #[test]
    fn n2_handshake_ordering_through_transport_layer() {
        use bolt_daemon::ipc_server_start;

        let path = temp_socket_path();
        let server = ipc_server_start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        send_version_handshake(&mut write_client, env!("CARGO_PKG_VERSION"));

        // First: version.status
        let msg1 = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(msg1["type"], "version.status");
        assert_eq!(msg1["payload"]["compatible"], true);

        // Second: daemon.status
        let msg2 = read_ipc_line(&mut read_client).expect("expected daemon.status");
        assert_eq!(msg2["type"], "daemon.status");
        assert_eq!(msg2["payload"]["ui_connected"], true);

        std::thread::sleep(Duration::from_millis(100));
        assert!(server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    /// Verify single-client + kick-on-reconnect semantics survive transport refactor.
    #[test]
    fn single_client_kick_on_reconnect_through_transport() {
        use bolt_daemon::ipc_server_start;

        let path = temp_socket_path();
        let server = ipc_server_start(&path).unwrap();

        // First client connects and completes handshake.
        let client1 = UnixStream::connect(&path).unwrap();
        let mut w1 = client1.try_clone().unwrap();
        let mut r1 = BufReader::new(client1);
        send_version_handshake(&mut w1, env!("CARGO_PKG_VERSION"));
        let _ = read_ipc_line(&mut r1); // version.status
        let _ = read_ipc_line(&mut r1); // daemon.status

        std::thread::sleep(Duration::from_millis(100));
        assert!(server.is_ui_connected());

        // Disconnect first client.
        drop(w1);
        drop(r1);
        std::thread::sleep(Duration::from_millis(200));

        // Second client connects — should succeed (kick semantics).
        let client2 = UnixStream::connect(&path).unwrap();
        let mut w2 = client2.try_clone().unwrap();
        let mut r2 = BufReader::new(client2);
        send_version_handshake(&mut w2, env!("CARGO_PKG_VERSION"));

        let msg1 = read_ipc_line(&mut r2).expect("expected version.status for client2");
        assert_eq!(msg1["type"], "version.status");
        assert_eq!(msg1["payload"]["compatible"], true);

        let msg2 = read_ipc_line(&mut r2).expect("expected daemon.status for client2");
        assert_eq!(msg2["type"], "daemon.status");

        std::thread::sleep(Duration::from_millis(100));
        assert!(server.is_ui_connected());

        drop(w2);
        drop(r2);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    /// Verify incompatible version fails closed through transport layer.
    #[test]
    fn incompatible_version_fails_closed_through_transport() {
        use bolt_daemon::ipc_server_start;

        let path = temp_socket_path();
        let server = ipc_server_start(&path).unwrap();

        let client = UnixStream::connect(&path).unwrap();
        let mut write_client = client.try_clone().unwrap();
        let mut read_client = BufReader::new(client);

        send_version_handshake(&mut write_client, "99.99.0");

        let msg = read_ipc_line(&mut read_client).expect("expected version.status");
        assert_eq!(msg["payload"]["compatible"], false);

        // Should disconnect — no daemon.status.
        let next = read_ipc_line(&mut read_client);
        assert!(next.is_none());

        std::thread::sleep(Duration::from_millis(100));
        assert!(!server.is_ui_connected());

        drop(write_client);
        drop(read_client);
        drop(server);
        let _ = std::fs::remove_file(&path);
    }
}

// ── Windows Named Pipe Tests (compile on Windows only) ──────

#[cfg(windows)]
mod windows_pipe_tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::time::Duration;

    /// Verify named pipe listener creation with security descriptor.
    #[test]
    fn named_pipe_listener_bind() {
        use bolt_daemon::ipc_server_start;

        let path = r"\\.\pipe\bolt-n6b2-test-bind";
        let server = ipc_server_start(path).unwrap();
        // If we got here, bind succeeded with DACL.
        drop(server);
    }

    /// Verify named pipe accept returns WouldBlock when no client.
    #[test]
    fn named_pipe_accept_wouldblock() {
        use bolt_daemon::ipc_transport_bind;

        let path = r"\\.\pipe\bolt-n6b2-test-wouldblock";
        let (listener, _) = ipc_transport_bind(path).unwrap();
        let result = listener.accept();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    /// Verify named pipe client connection lifecycle.
    #[test]
    fn named_pipe_connection_lifecycle() {
        use bolt_daemon::ipc_server_start;
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        let pipe_path = r"\\.\pipe\bolt-n6b2-test-lifecycle";
        let server = ipc_server_start(pipe_path).unwrap();

        // Connect client via CreateFile (standard Windows pipe client).
        let client = OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_path)
            .expect("failed to connect to named pipe");

        // Send version handshake.
        let msg = serde_json::json!({
            "id": "cli-0",
            "kind": "decision",
            "type": "version.handshake",
            "ts_ms": 0,
            "payload": { "app_version": env!("CARGO_PKG_VERSION") }
        });
        let mut line = serde_json::to_string(&msg).unwrap();
        line.push('\n');
        (&client).write_all(line.as_bytes()).unwrap();
        (&client).flush().unwrap();

        // Read version.status + daemon.status.
        let mut reader = BufReader::new(&client);
        let mut resp = String::new();
        reader.read_line(&mut resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["type"], "version.status");
        assert_eq!(parsed["payload"]["compatible"], true);

        std::thread::sleep(Duration::from_millis(100));
        assert!(server.is_ui_connected());

        drop(client);
        drop(server);
    }
}
