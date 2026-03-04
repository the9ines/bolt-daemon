//! D-E2E-B: Cross-implementation bidirectional E2E transfer test.
//!
//! Node.js harness (offerer) ↔ bolt-daemon (answerer).
//! Direction 1: Harness → Daemon (pattern A, 4096 bytes, SHA-256 verified)
//! Direction 2: Daemon → Harness (pattern B, 6144 bytes, SHA-256 verified)
//!
//! Both directions enforce bolt.file-hash capability and integrity verification.
//!
//! Requires:
//!   - bolt-rendezvous binary at ../bolt-rendezvous/target/debug/
//!   - Node.js >= v18
//!   - npm ci in tests/ts-harness/
//!
//! Run: cargo test --features test-support -- --ignored d_e2e_b

#![cfg(feature = "test-support")]

use std::io::Read as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bolt_core::hash::sha256_hex;

// ── Constants ──────────────────────────────────────────────────

const TEST_ROOM: &str = "e2e-bidir-test";
const TEST_SESSION: &str = "e2e-bidir-session-1";
const DAEMON_PEER_ID: &str = "daemon-bob";
const HARNESS_PEER_ID: &str = "harness-alice";
const TOTAL_DEADLINE_SECS: u64 = 30;

const PATTERN_A_SIZE: usize = 4096;
const PATTERN_B_SIZE: usize = 6144;

// ── Deterministic payload generators ───────────────────────────

/// Pattern A: byte[i] = ((i + 1) * 31) & 0xFF
fn generate_pattern_a() -> Vec<u8> {
    (0..PATTERN_A_SIZE)
        .map(|i| (((i + 1) * 31) & 0xFF) as u8)
        .collect()
}

/// Pattern B: byte[i] = ((i + 1) * 37) & 0xFF
fn generate_pattern_b() -> Vec<u8> {
    (0..PATTERN_B_SIZE)
        .map(|i| (((i + 1) * 37) & 0xFF) as u8)
        .collect()
}

// ── Test helpers (reused from D-E2E-A) ─────────────────────────

fn find_rendezvous_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let base = PathBuf::from(manifest_dir)
        .parent()?
        .join("bolt-rendezvous")
        .join("target")
        .join("debug");
    let primary = base.join("bolt-rendezvous");
    if primary.exists() {
        return Some(primary);
    }
    let fallback = base.join("localbolt-signal");
    if fallback.exists() {
        return Some(fallback);
    }
    None
}

fn find_daemon_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bin = PathBuf::from(manifest_dir)
        .join("target")
        .join("debug")
        .join("bolt-daemon");
    if bin.exists() {
        Some(bin)
    } else {
        None
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    listener.local_addr().unwrap().port()
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
    fn take(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_rendezvous(bin: &Path, port: u16) -> ChildGuard {
    let child = Command::new(bin)
        .env("BOLT_SIGNAL_PORT", port.to_string())
        .env("BOLT_SIGNAL_HOST", "127.0.0.1")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rendezvous");

    // Wait until the port accepts TCP connections.
    let start = Instant::now();
    loop {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("rendezvous did not accept on port {port} within 5s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Grace period for server to fully start.
    std::thread::sleep(Duration::from_millis(300));

    ChildGuard::new(child)
}

fn harness_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("ts-harness")
}

fn ensure_harness_deps() {
    let dir = harness_dir();
    let nm = dir.join("node_modules");
    if nm.exists() {
        return;
    }
    let status = Command::new("npm")
        .arg("ci")
        .arg("--no-audit")
        .arg("--no-fund")
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .expect("npm ci failed to start");
    assert!(status.success(), "npm ci failed");
}

// ── Main test ──────────────────────────────────────────────────

#[test]
#[ignore]
fn d_e2e_b_bidirectional_cross_impl() {
    let rendezvous_bin = find_rendezvous_binary()
        .expect("bolt-rendezvous binary not found — skip with default cargo test");
    let daemon_bin =
        find_daemon_binary().expect("bolt-daemon binary not found — run cargo build first");

    let port = free_port();
    let _deadline = Instant::now() + Duration::from_secs(TOTAL_DEADLINE_SECS);

    let tmp = tempfile::tempdir().unwrap();

    // Generate deterministic payloads
    let pattern_a = generate_pattern_a();
    let pattern_b = generate_pattern_b();
    let pattern_b_hash = sha256_hex(&pattern_b);

    // Write pattern B to temp file for daemon send trigger
    let send_payload_path = tmp.path().join("pattern_b.bin");
    std::fs::write(&send_payload_path, &pattern_b).expect("write pattern B");

    // Compute pattern A as hex for harness CLI
    let pattern_a_hex: String = pattern_a.iter().map(|b| format!("{b:02x}")).collect();

    // 1. Spawn rendezvous
    let _rendezvous = spawn_rendezvous(&rendezvous_bin, port);

    // 2. Spawn daemon answerer with test send trigger
    let identity_path = tmp.path().join(".bolt").join("identity.key");
    let daemon_child = Command::new(&daemon_bin)
        .env("BOLT_IDENTITY_PATH", &identity_path)
        .env(
            "BOLT_TEST_SEND_PAYLOAD_PATH",
            send_payload_path.to_str().unwrap(),
        )
        .arg("--role")
        .arg("answerer")
        .arg("--signal")
        .arg("rendezvous")
        .arg("--rendezvous-url")
        .arg(format!("ws://127.0.0.1:{port}"))
        .arg("--room")
        .arg(TEST_ROOM)
        .arg("--session")
        .arg(TEST_SESSION)
        .arg("--peer-id")
        .arg(DAEMON_PEER_ID)
        .arg("--expect-peer")
        .arg(HARNESS_PEER_ID)
        .arg("--network-scope")
        .arg("lan")
        .arg("--phase-timeout-secs")
        .arg("20")
        .arg("--pairing-policy")
        .arg("allow")
        .arg("--interop-signal")
        .arg("web_v1")
        .arg("--interop-hello")
        .arg("web_hello_v1")
        .arg("--interop-dc")
        .arg("web_dc_v1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon answerer");
    let mut daemon = ChildGuard::new(daemon_child);

    std::thread::sleep(Duration::from_millis(500));

    // 3. Ensure harness deps installed
    ensure_harness_deps();

    // 4. Spawn harness
    let harness_script = harness_dir().join("harness.mjs");
    let harness_child = Command::new("node")
        .arg(&harness_script)
        .arg("--rendezvous-url")
        .arg(format!("ws://127.0.0.1:{port}"))
        .arg("--room-code")
        .arg(TEST_ROOM)
        .arg("--session")
        .arg(TEST_SESSION)
        .arg("--peer-id")
        .arg(HARNESS_PEER_ID)
        .arg("--to")
        .arg(DAEMON_PEER_ID)
        .arg("--send-payload-hex")
        .arg(&pattern_a_hex)
        .arg("--expect-receive-sha256")
        .arg(&pattern_b_hash)
        .arg("--expect-receive-size")
        .arg(PATTERN_B_SIZE.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn harness");
    let mut harness = ChildGuard::new(harness_child);

    // 5. Wait for harness to complete (bounded)
    let harness_child = harness.take().expect("harness child");
    let harness_output = match harness_child.wait_with_output() {
        Ok(o) => o,
        Err(e) => panic!("harness wait error: {e}"),
    };

    // 6. Wait for daemon to exit (bounded)
    let mut daemon_child = daemon.take().expect("daemon child");
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match daemon_child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= wait_deadline {
                    let _ = daemon_child.kill();
                    let _ = daemon_child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    // Read daemon stderr
    let mut daemon_stderr = String::new();
    if let Some(mut stderr) = daemon_child.stderr.take() {
        let _ = stderr.read_to_string(&mut daemon_stderr);
    }

    // 7. Assertions
    let harness_stdout = String::from_utf8_lossy(&harness_output.stdout);
    let harness_stderr = String::from_utf8_lossy(&harness_output.stderr);

    // Harness assertions
    assert_eq!(
        harness_output.status.code(),
        Some(0),
        "harness must exit 0.\nstdout:\n{harness_stdout}\nstderr:\n{harness_stderr}\ndaemon stderr:\n{daemon_stderr}"
    );
    assert!(
        harness_stdout.contains("BOLT_E2E_BIDIR_OK"),
        "harness stdout must contain BOLT_E2E_BIDIR_OK.\nstdout:\n{harness_stdout}\nstderr:\n{harness_stderr}"
    );
    assert!(
        harness_stdout.contains("ts_to_daemon_bytes=4096"),
        "must report ts_to_daemon_bytes=4096.\nstdout:\n{harness_stdout}"
    );
    assert!(
        harness_stdout.contains("daemon_to_ts_bytes=6144"),
        "must report daemon_to_ts_bytes=6144.\nstdout:\n{harness_stdout}"
    );
    assert!(
        !harness_stderr.contains("BOLT_E2E_BIDIR_FAIL"),
        "harness stderr must not contain BOLT_E2E_BIDIR_FAIL.\nstderr:\n{harness_stderr}"
    );

    // Daemon assertions
    assert!(
        daemon_stderr.contains("[B4_VERIFY_OK]"),
        "daemon must emit [B4_VERIFY_OK].\ndaemon stderr:\n{daemon_stderr}"
    );
    assert!(
        !daemon_stderr.contains("[B4] integrity failed"),
        "daemon must not have integrity failure.\ndaemon stderr:\n{daemon_stderr}"
    );
}

// ── Negative integrity test ────────────────────────────────────

#[test]
#[ignore]
fn d_e2e_b_negative_integrity_mismatch() {
    let rendezvous_bin = find_rendezvous_binary()
        .expect("bolt-rendezvous binary not found — skip with default cargo test");
    let daemon_bin =
        find_daemon_binary().expect("bolt-daemon binary not found — run cargo build first");

    let port = free_port();

    let tmp = tempfile::tempdir().unwrap();

    // Generate payloads
    let pattern_a = generate_pattern_a();
    let pattern_b = generate_pattern_b();

    // Correct hash, but we'll flip one nibble to make it wrong
    let correct_hash = sha256_hex(&pattern_b);
    let wrong_hash = {
        let mut h = correct_hash.clone();
        let bytes = unsafe { h.as_bytes_mut() };
        // Flip first hex nibble: if '0'-'9' → next, if 'a'-'f' → prev
        bytes[0] = match bytes[0] {
            b'0'..=b'8' => bytes[0] + 1,
            b'9' => b'a',
            b'a'..=b'e' => bytes[0] + 1,
            b'f' => b'0',
            x => x,
        };
        String::from_utf8(bytes.to_vec()).unwrap()
    };

    let send_payload_path = tmp.path().join("pattern_b.bin");
    std::fs::write(&send_payload_path, &pattern_b).expect("write pattern B");

    let pattern_a_hex: String = pattern_a.iter().map(|b| format!("{b:02x}")).collect();

    // 1. Spawn rendezvous
    let _rendezvous = spawn_rendezvous(&rendezvous_bin, port);

    // 2. Spawn daemon
    let identity_path = tmp.path().join(".bolt").join("identity.key");
    let daemon_child = Command::new(&daemon_bin)
        .env("BOLT_IDENTITY_PATH", &identity_path)
        .env(
            "BOLT_TEST_SEND_PAYLOAD_PATH",
            send_payload_path.to_str().unwrap(),
        )
        .arg("--role")
        .arg("answerer")
        .arg("--signal")
        .arg("rendezvous")
        .arg("--rendezvous-url")
        .arg(format!("ws://127.0.0.1:{port}"))
        .arg("--room")
        .arg(TEST_ROOM)
        .arg("--session")
        .arg(TEST_SESSION)
        .arg("--peer-id")
        .arg(DAEMON_PEER_ID)
        .arg("--expect-peer")
        .arg(HARNESS_PEER_ID)
        .arg("--network-scope")
        .arg("lan")
        .arg("--phase-timeout-secs")
        .arg("20")
        .arg("--pairing-policy")
        .arg("allow")
        .arg("--interop-signal")
        .arg("web_v1")
        .arg("--interop-hello")
        .arg("web_hello_v1")
        .arg("--interop-dc")
        .arg("web_dc_v1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon answerer");
    let mut daemon = ChildGuard::new(daemon_child);

    std::thread::sleep(Duration::from_millis(500));

    ensure_harness_deps();

    // 3. Spawn harness with WRONG expected hash
    let harness_script = harness_dir().join("harness.mjs");
    let harness_child = Command::new("node")
        .arg(&harness_script)
        .arg("--rendezvous-url")
        .arg(format!("ws://127.0.0.1:{port}"))
        .arg("--room-code")
        .arg(TEST_ROOM)
        .arg("--session")
        .arg(TEST_SESSION)
        .arg("--peer-id")
        .arg(HARNESS_PEER_ID)
        .arg("--to")
        .arg(DAEMON_PEER_ID)
        .arg("--send-payload-hex")
        .arg(&pattern_a_hex)
        .arg("--expect-receive-sha256")
        .arg(&wrong_hash) // Intentionally wrong
        .arg("--expect-receive-size")
        .arg(PATTERN_B_SIZE.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn harness");
    let mut harness = ChildGuard::new(harness_child);

    // 4. Wait for harness
    let harness_child = harness.take().expect("harness child");
    let harness_output = harness_child.wait_with_output().expect("harness wait");

    // 5. Wait for daemon
    let mut daemon_child = daemon.take().expect("daemon child");
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match daemon_child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= wait_deadline {
                    let _ = daemon_child.kill();
                    let _ = daemon_child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    let mut daemon_stderr = String::new();
    if let Some(mut stderr) = daemon_child.stderr.take() {
        let _ = stderr.read_to_string(&mut daemon_stderr);
    }

    let harness_stdout = String::from_utf8_lossy(&harness_output.stdout);
    let harness_stderr = String::from_utf8_lossy(&harness_output.stderr);

    // 6. Assertions
    // Harness must fail (non-zero exit)
    assert_ne!(
        harness_output.status.code(),
        Some(0),
        "harness must exit non-zero with wrong hash.\nstdout:\n{harness_stdout}\nstderr:\n{harness_stderr}"
    );
    assert!(
        harness_stderr.contains("BOLT_E2E_BIDIR_FAIL"),
        "harness stderr must contain BOLT_E2E_BIDIR_FAIL.\nstderr:\n{harness_stderr}"
    );

    // Daemon still verifies its own receive correctly
    assert!(
        daemon_stderr.contains("[B4_VERIFY_OK]"),
        "daemon must still emit [B4_VERIFY_OK] for its receive.\ndaemon stderr:\n{daemon_stderr}"
    );
}
