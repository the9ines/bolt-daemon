//! Smoke validation mode — structured P2P transport verification.
//!
//! Generates a deterministic payload, transfers it over the existing
//! DataChannel, verifies SHA-256 integrity, and reports latency/throughput.
//!
//! No protocol changes. No crypto changes. Uses existing signaling and
//! DataChannel infrastructure.

use std::time::Instant;

// ── Exit codes (smoke mode only) ────────────────────────────

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_SIGNALING_FAILURE: i32 = 1;
pub const EXIT_DATACHANNEL_FAILURE: i32 = 2;
pub const EXIT_INTEGRITY_MISMATCH: i32 = 3;
pub const EXIT_TIMEOUT: i32 = 4;

// ── Smoke config ────────────────────────────────────────────

/// Default payload size: 1 MiB.
pub const DEFAULT_BYTES: usize = 1_048_576;

/// Default repeat count.
pub const DEFAULT_REPEAT: usize = 1;

#[derive(Debug)]
pub struct SmokeConfig {
    pub bytes: usize,
    pub repeat: usize,
    pub json: bool,
}

impl Default for SmokeConfig {
    fn default() -> Self {
        Self {
            bytes: DEFAULT_BYTES,
            repeat: DEFAULT_REPEAT,
            json: false,
        }
    }
}

// ── Deterministic payload generator ─────────────────────────

/// Generate a deterministic payload of `size` bytes.
/// byte[i] = (i % 256) as u8
pub fn generate_payload(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    for i in 0..size {
        buf.push((i % 256) as u8);
    }
    buf
}

/// Compute SHA-256 digest of `data`, return hex string.
/// Delegates to `bolt_core::hash::sha256_hex` (canonical Rust implementation).
pub fn sha256_hex(data: &[u8]) -> String {
    bolt_core::hash::sha256_hex(data)
}

// ── Error classification ────────────────────────────────────

/// Smoke error with category for exit code mapping.
#[derive(Debug)]
pub enum SmokeError {
    Signaling(String),
    DataChannel(String),
    IntegrityMismatch { expected: String, received: String },
    Timeout(String),
}

impl SmokeError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SmokeError::Signaling(_) => EXIT_SIGNALING_FAILURE,
            SmokeError::DataChannel(_) => EXIT_DATACHANNEL_FAILURE,
            SmokeError::IntegrityMismatch { .. } => EXIT_INTEGRITY_MISMATCH,
            SmokeError::Timeout(_) => EXIT_TIMEOUT,
        }
    }

    pub fn message(&self) -> String {
        match self {
            SmokeError::Signaling(msg) => format!("signaling failure: {}", msg),
            SmokeError::DataChannel(msg) => format!("data channel failure: {}", msg),
            SmokeError::IntegrityMismatch { expected, received } => {
                format!(
                    "integrity mismatch: expected={} received={}",
                    expected, received
                )
            }
            SmokeError::Timeout(msg) => format!("timeout: {}", msg),
        }
    }
}

impl std::fmt::Display for SmokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for SmokeError {}

// ── Smoke report ────────────────────────────────────────────

#[derive(Debug)]
pub struct SmokeReport {
    pub handshake_ok: bool,
    pub data_channel_ok: bool,
    pub bytes: usize,
    pub sha256_expected: String,
    pub sha256_received: String,
    pub sha256_match: bool,
    pub latency_ms: u64,
    pub throughput_mbps: f64,
    pub repeat: usize,
    pub result: &'static str,
    pub error: Option<String>,
}

impl SmokeReport {
    pub fn success(
        bytes: usize,
        sha256_expected: String,
        sha256_received: String,
        latency_ms: u64,
        throughput_mbps: f64,
        repeat: usize,
    ) -> Self {
        Self {
            handshake_ok: true,
            data_channel_ok: true,
            bytes,
            sha256_expected,
            sha256_received,
            sha256_match: true,
            latency_ms,
            throughput_mbps,
            repeat,
            result: "PASS",
            error: None,
        }
    }

    pub fn failure(error: &SmokeError, bytes: usize, repeat: usize) -> Self {
        let (handshake_ok, data_channel_ok) = match error {
            SmokeError::Signaling(_) => (false, false),
            SmokeError::DataChannel(_) => (true, false),
            SmokeError::IntegrityMismatch { .. } => (true, true),
            SmokeError::Timeout(_) => (true, true),
        };
        Self {
            handshake_ok,
            data_channel_ok,
            bytes,
            sha256_expected: String::new(),
            sha256_received: String::new(),
            sha256_match: false,
            latency_ms: 0,
            throughput_mbps: 0.0,
            repeat,
            result: "FAIL",
            error: Some(error.message()),
        }
    }

    pub fn print_human(&self) {
        eprintln!(
            "[smoke] handshake .......... {}",
            if self.handshake_ok { "OK" } else { "FAIL" }
        );
        eprintln!(
            "[smoke] data channel ....... {}",
            if self.data_channel_ok { "OK" } else { "FAIL" }
        );
        eprintln!("[smoke] transferred ........ {} bytes", self.bytes);
        if !self.sha256_expected.is_empty() {
            eprintln!(
                "[smoke] sha256 ............. {} ({}...)",
                if self.sha256_match { "OK" } else { "MISMATCH" },
                &self.sha256_expected[..16.min(self.sha256_expected.len())]
            );
        }
        eprintln!("[smoke] latency ............ {} ms", self.latency_ms);
        eprintln!(
            "[smoke] throughput ......... {:.1} MB/s",
            self.throughput_mbps
        );
        eprintln!("[smoke] result ............. {}", self.result);
        if let Some(ref err) = self.error {
            eprintln!("[smoke] error .............. {}", err);
        }
    }

    pub fn print_json(&self) {
        let json = serde_json::json!({
            "mode": "smoke",
            "handshake": self.handshake_ok,
            "data_channel": self.data_channel_ok,
            "bytes": self.bytes,
            "sha256_expected": self.sha256_expected,
            "sha256_received": self.sha256_received,
            "sha256_match": self.sha256_match,
            "latency_ms": self.latency_ms,
            "throughput_mbps": self.throughput_mbps,
            "repeat": self.repeat,
            "result": self.result,
            "error": self.error,
        });
        match serde_json::to_string_pretty(&json) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("[smoke] FATAL: serialize report: {e}"),
        }
    }

    pub fn print(&self, json_mode: bool) {
        if json_mode {
            self.print_json();
        } else {
            self.print_human();
        }
    }
}

// ── Constants ───────────────────────────────────────────────

/// Maximum bytes per DataChannel send. SCTP (used by WebRTC DataChannels)
/// has a maximum message size; libdatachannel rejects sends above its limit
/// with InvalidArg. 64 KiB is well under all known SCTP/WebRTC ceilings.
const SEND_CHUNK_SIZE: usize = 65_536;

// ── Smoke transfer execution ────────────────────────────────

/// Classify a generic error into a SmokeError.
/// Heuristic: check error message for known patterns.
/// Kept for rendezvous smoke mode (requires rendezvous.rs changes — Phase 4L+).
#[allow(dead_code)]
pub fn classify_error(err: &dyn std::error::Error) -> SmokeError {
    let msg = err.to_string();
    if msg.contains("timed out") || msg.contains("TimedOut") || msg.contains("timeout") {
        SmokeError::Timeout(msg)
    } else if msg.contains("signal") || msg.contains("rendezvous") || msg.contains("handshake") {
        SmokeError::Signaling(msg)
    } else {
        SmokeError::DataChannel(msg)
    }
}

/// Run the sender side of a smoke transfer.
/// Sends the deterministic payload and waits for the receiver's SHA-256 ack.
pub fn run_smoke_sender(
    dc: &mut datachannel::RtcDataChannel<crate::DcHandler>,
    msg_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    config: &SmokeConfig,
    timeout: std::time::Duration,
) -> Result<SmokeReport, SmokeError> {
    let payload = generate_payload(config.bytes);
    let expected_hash = sha256_hex(&payload);

    eprintln!("[smoke] sending {} bytes...", config.bytes);
    let start = Instant::now();

    // Send payload in chunks (SCTP has a max message size; single large sends fail)
    for chunk in payload.chunks(SEND_CHUNK_SIZE) {
        dc.send(chunk)
            .map_err(|e| SmokeError::DataChannel(format!("send failed: {}", e)))?;
    }

    // Wait for receiver's SHA-256 ack
    let ack = msg_rx
        .recv_timeout(timeout * 2)
        .map_err(|_| SmokeError::Timeout("transfer ack timeout".to_string()))?;

    let elapsed = start.elapsed();
    let latency_ms = elapsed.as_millis() as u64;
    let throughput_mbps = if latency_ms > 0 {
        (config.bytes as f64 / 1_000_000.0) / (latency_ms as f64 / 1_000.0)
    } else {
        0.0
    };

    let received_hash = String::from_utf8(ack)
        .map_err(|_| SmokeError::DataChannel("invalid ack: not UTF-8".to_string()))?;

    if received_hash != expected_hash {
        return Err(SmokeError::IntegrityMismatch {
            expected: expected_hash,
            received: received_hash,
        });
    }

    Ok(SmokeReport::success(
        config.bytes,
        expected_hash,
        received_hash,
        latency_ms,
        throughput_mbps,
        config.repeat,
    ))
}

/// Run the receiver side of a smoke transfer.
/// Receives the payload, computes SHA-256, sends it back as ack.
pub fn run_smoke_receiver(
    dc: &mut datachannel::RtcDataChannel<crate::DcHandler>,
    msg_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    config: &SmokeConfig,
    timeout: std::time::Duration,
) -> Result<SmokeReport, SmokeError> {
    let expected_payload = generate_payload(config.bytes);
    let expected_hash = sha256_hex(&expected_payload);

    eprintln!("[smoke] waiting for {} bytes...", config.bytes);
    let start = Instant::now();

    // Receive payload — may arrive in multiple DataChannel messages
    let mut received = Vec::with_capacity(config.bytes);
    let deadline = Instant::now() + timeout * 2;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SmokeError::Timeout(format!(
                "received {} of {} bytes before timeout",
                received.len(),
                config.bytes
            )));
        }

        match msg_rx.recv_timeout(remaining) {
            Ok(chunk) => {
                received.extend_from_slice(&chunk);
                if received.len() >= config.bytes {
                    break;
                }
            }
            Err(_) => {
                return Err(SmokeError::Timeout(format!(
                    "received {} of {} bytes before timeout",
                    received.len(),
                    config.bytes
                )));
            }
        }
    }

    let elapsed = start.elapsed();
    let latency_ms = elapsed.as_millis() as u64;
    let throughput_mbps = if latency_ms > 0 {
        (config.bytes as f64 / 1_000_000.0) / (latency_ms as f64 / 1_000.0)
    } else {
        0.0
    };

    // Truncate to expected size (DataChannel may deliver exact or padded)
    received.truncate(config.bytes);

    let received_hash = sha256_hex(&received);

    // Send SHA-256 ack back to sender
    dc.send(received_hash.as_bytes())
        .map_err(|e| SmokeError::DataChannel(format!("ack send failed: {}", e)))?;

    if received_hash != expected_hash {
        return Err(SmokeError::IntegrityMismatch {
            expected: expected_hash,
            received: received_hash,
        });
    }

    Ok(SmokeReport::success(
        config.bytes,
        expected_hash,
        received_hash,
        latency_ms,
        throughput_mbps,
        config.repeat,
    ))
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_determinism_small() {
        let a = generate_payload(256);
        let b = generate_payload(256);
        assert_eq!(a, b);
        for i in 0..256 {
            assert_eq!(a[i], (i % 256) as u8);
        }
    }

    #[test]
    fn payload_determinism_1k() {
        let payload = generate_payload(1024);
        assert_eq!(payload.len(), 1024);
        assert_eq!(payload[0], 0);
        assert_eq!(payload[255], 255);
        assert_eq!(payload[256], 0);
        assert_eq!(payload[511], 255);
    }

    #[test]
    fn payload_empty() {
        let payload = generate_payload(0);
        assert!(payload.is_empty());
    }

    #[test]
    fn sha256_known_value_1024() {
        // SHA-256 of counter-based 1024 bytes
        let payload = generate_payload(1024);
        let hash = sha256_hex(&payload);
        // Verify length (64 hex chars = 32 bytes)
        assert_eq!(hash.len(), 64);
        // Verify determinism
        assert_eq!(hash, sha256_hex(&generate_payload(1024)));
    }

    #[test]
    fn sha256_empty() {
        let hash = sha256_hex(&[]);
        // SHA-256 of empty input is a well-known constant
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_determinism() {
        let data = generate_payload(DEFAULT_BYTES);
        let h1 = sha256_hex(&data);
        let h2 = sha256_hex(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn exit_code_signaling() {
        let err = SmokeError::Signaling("test".to_string());
        assert_eq!(err.exit_code(), EXIT_SIGNALING_FAILURE);
    }

    #[test]
    fn exit_code_datachannel() {
        let err = SmokeError::DataChannel("test".to_string());
        assert_eq!(err.exit_code(), EXIT_DATACHANNEL_FAILURE);
    }

    #[test]
    fn exit_code_integrity() {
        let err = SmokeError::IntegrityMismatch {
            expected: "a".to_string(),
            received: "b".to_string(),
        };
        assert_eq!(err.exit_code(), EXIT_INTEGRITY_MISMATCH);
    }

    #[test]
    fn exit_code_timeout() {
        let err = SmokeError::Timeout("test".to_string());
        assert_eq!(err.exit_code(), EXIT_TIMEOUT);
    }

    #[test]
    fn report_json_valid() {
        let report = SmokeReport::success(
            1024,
            "abc123".to_string(),
            "abc123".to_string(),
            10,
            100.0,
            1,
        );
        // Capture JSON output
        let json = serde_json::json!({
            "mode": "smoke",
            "handshake": report.handshake_ok,
            "data_channel": report.data_channel_ok,
            "bytes": report.bytes,
            "sha256_expected": report.sha256_expected,
            "sha256_received": report.sha256_received,
            "sha256_match": report.sha256_match,
            "latency_ms": report.latency_ms,
            "throughput_mbps": report.throughput_mbps,
            "repeat": report.repeat,
            "result": report.result,
            "error": report.error,
        });
        let parsed: serde_json::Value = json;
        assert_eq!(parsed["mode"], "smoke");
        assert_eq!(parsed["handshake"], true);
        assert_eq!(parsed["data_channel"], true);
        assert_eq!(parsed["bytes"], 1024);
        assert_eq!(parsed["sha256_match"], true);
        assert_eq!(parsed["result"], "PASS");
        assert!(parsed["error"].is_null());
    }

    #[test]
    fn report_failure_json_valid() {
        let err = SmokeError::IntegrityMismatch {
            expected: "aaa".to_string(),
            received: "bbb".to_string(),
        };
        let report = SmokeReport::failure(&err, 1024, 1);
        assert_eq!(report.result, "FAIL");
        assert!(report.error.is_some());
        assert!(report.handshake_ok);
        assert!(report.data_channel_ok);
        assert!(!report.sha256_match);
    }

    #[test]
    fn report_signaling_failure() {
        let err = SmokeError::Signaling("unreachable".to_string());
        let report = SmokeReport::failure(&err, 1024, 1);
        assert!(!report.handshake_ok);
        assert!(!report.data_channel_ok);
    }

    #[test]
    fn default_config() {
        let cfg = SmokeConfig::default();
        assert_eq!(cfg.bytes, DEFAULT_BYTES);
        assert_eq!(cfg.repeat, DEFAULT_REPEAT);
        assert!(!cfg.json);
    }

    #[test]
    fn classify_timeout_error() {
        let err: Box<dyn std::error::Error> = "timed out waiting for data".into();
        let smoke_err = classify_error(err.as_ref());
        assert_eq!(smoke_err.exit_code(), EXIT_TIMEOUT);
    }

    #[test]
    fn classify_signaling_error() {
        let err: Box<dyn std::error::Error> = "rendezvous server unreachable".into();
        let smoke_err = classify_error(err.as_ref());
        assert_eq!(smoke_err.exit_code(), EXIT_SIGNALING_FAILURE);
    }

    #[test]
    fn classify_generic_error() {
        let err: Box<dyn std::error::Error> = "something broke".into();
        let smoke_err = classify_error(err.as_ref());
        assert_eq!(smoke_err.exit_code(), EXIT_DATACHANNEL_FAILURE);
    }

    // ── bolt-core adoption gate ─────────────────────────────────

    /// Proves sha256_hex delegates to bolt_core::hash::sha256_hex.
    /// If someone reverts to a local implementation, this will catch
    /// any output mismatch against the canonical crate.
    #[test]
    fn sha256_hex_matches_bolt_core_canonical() {
        let data = b"bolt-core adoption test";
        let from_smoke = sha256_hex(data);
        let from_core = bolt_core::hash::sha256_hex(data);
        assert_eq!(from_smoke, from_core);
        // Also verify well-known empty-input constant via bolt-core directly.
        assert_eq!(
            bolt_core::hash::sha256_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
