//! Relay envelope parsing, validation, and construction.
//!
//! Implements the wire format defined in `docs/RELAY_ENVELOPE_SPEC.md`:
//!   version (u8) + session_id ([u8;16]) + payload_length (u32 BE) + payload (variable)
//!
//! The relay envelope wraps exactly one opaque Bolt encrypted envelope per frame.
//! The relay does not inspect, modify, or interpret the payload bytes.

use rand::Rng;

// ── Constants (RELAY_ENVELOPE_SPEC.md Appendix B) ───────────

/// Current relay envelope version. Reject any envelope with a different version.
pub const RELAY_ENVELOPE_VERSION: u8 = 1;

/// Session identifier length in bytes.
pub const RELAY_SESSION_ID_LENGTH: usize = 16;

/// Fixed header size: version (1) + session_id (16) + payload_length (4).
pub const RELAY_HEADER_SIZE: usize = 21;

/// Recommended maximum payload size. Strictly enforced by `validate_envelope`.
pub const RELAY_MAX_PAYLOAD_DEFAULT: usize = 65_536;

/// Control message type byte: session_assigned (relay → peer).
pub const CTRL_SESSION_ASSIGNED: u8 = 0x01;

// ── Error types ─────────────────────────────────────────────

/// Relay envelope errors. All variants are non-panicking.
#[derive(Debug, PartialEq)]
pub enum RelayError {
    /// Frame shorter than 21-byte header.
    TruncatedHeader,
    /// `version` field is not `RELAY_ENVELOPE_VERSION`.
    UnsupportedVersion(u8),
    /// `payload_length` exceeds the configured maximum.
    PayloadTooLarge { length: usize, max: usize },
    /// Frame has fewer payload bytes than `payload_length` declares.
    TruncatedPayload { expected: usize, actual: usize },
    /// `payload_length` is zero. Empty payloads are invalid.
    EmptyPayload,
    /// Session ID in envelope does not match expected session.
    #[allow(dead_code)]
    SessionMismatch,
    /// Frame is not a valid binary WebSocket message or other structural issue.
    #[allow(dead_code)]
    InvalidFrame(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::TruncatedHeader => {
                write!(f, "truncated header (< {} bytes)", RELAY_HEADER_SIZE)
            }
            RelayError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported version {} (expected {})",
                    v, RELAY_ENVELOPE_VERSION
                )
            }
            RelayError::PayloadTooLarge { length, max } => {
                write!(f, "payload too large: {} bytes (max {})", length, max)
            }
            RelayError::TruncatedPayload { expected, actual } => {
                write!(
                    f,
                    "truncated payload: expected {} bytes, got {}",
                    expected, actual
                )
            }
            RelayError::EmptyPayload => write!(f, "empty payload (payload_length == 0)"),
            RelayError::SessionMismatch => write!(f, "session_id mismatch"),
            RelayError::InvalidFrame(msg) => write!(f, "invalid frame: {}", msg),
        }
    }
}

impl std::error::Error for RelayError {}

// ── Parsing ─────────────────────────────────────────────────

/// Parse the 21-byte relay envelope header.
///
/// Returns `(version, session_id, payload_length)`.
/// Validates that `version == RELAY_ENVELOPE_VERSION`.
/// Does NOT validate payload bounds (use `validate_envelope` for that).
pub fn parse_header(data: &[u8]) -> Result<(u8, [u8; 16], u32), RelayError> {
    if data.len() < RELAY_HEADER_SIZE {
        return Err(RelayError::TruncatedHeader);
    }
    let version = data[0];
    if version != RELAY_ENVELOPE_VERSION {
        return Err(RelayError::UnsupportedVersion(version));
    }
    let mut session_id = [0u8; RELAY_SESSION_ID_LENGTH];
    session_id.copy_from_slice(&data[1..17]);
    let payload_length = u32::from_be_bytes(
        data[17..21]
            .try_into()
            .map_err(|_| RelayError::TruncatedHeader)?,
    );
    Ok((version, session_id, payload_length))
}

/// Validate a complete relay envelope: header + payload bounds.
///
/// Returns `(version, session_id, payload_slice)`.
/// Enforces `max_payload` strictly — payloads exceeding it are rejected.
pub fn validate_envelope(
    data: &[u8],
    max_payload: usize,
) -> Result<(u8, [u8; 16], &[u8]), RelayError> {
    let (version, session_id, payload_length) = parse_header(data)?;
    let len = payload_length as usize;
    if len == 0 {
        return Err(RelayError::EmptyPayload);
    }
    if len > max_payload {
        return Err(RelayError::PayloadTooLarge {
            length: len,
            max: max_payload,
        });
    }
    let available = data.len() - RELAY_HEADER_SIZE;
    if available < len {
        return Err(RelayError::TruncatedPayload {
            expected: len,
            actual: available,
        });
    }
    let payload = &data[RELAY_HEADER_SIZE..RELAY_HEADER_SIZE + len];
    Ok((version, session_id, payload))
}

// ── Construction ────────────────────────────────────────────

/// Generate a cryptographically random 16-byte session ID.
pub fn generate_session_id() -> [u8; 16] {
    rand::thread_rng().gen()
}

/// Construct a `session_assigned` control message (relay → peer).
///
/// Wire format: `CTRL_SESSION_ASSIGNED (1 byte)` + `session_id (16 bytes)` = 17 bytes.
/// See `docs/RELAY_SESSION_PROTOCOL.md` for specification.
pub fn make_session_assigned(session_id: &[u8; 16]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + RELAY_SESSION_ID_LENGTH);
    msg.push(CTRL_SESSION_ASSIGNED);
    msg.extend_from_slice(session_id);
    msg
}

/// Construct a complete relay envelope from session_id and payload.
/// Used by tests and future client code.
#[cfg(test)]
fn wrap_envelope(session_id: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(RELAY_HEADER_SIZE + payload.len());
    frame.push(RELAY_ENVELOPE_VERSION);
    frame.extend_from_slice(session_id);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Known session_id for deterministic tests (all 0xAA).
    const TEST_SESSION: [u8; 16] = [0xAA; 16];

    /// Build a valid 21-byte header + payload for testing.
    fn make_test_envelope(version: u8, session_id: &[u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RELAY_HEADER_SIZE + payload.len());
        buf.push(version);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    // ── 1. Constants ────────────────────────────────────────

    #[test]
    fn constants_match_spec() {
        assert_eq!(RELAY_ENVELOPE_VERSION, 1);
        assert_eq!(RELAY_SESSION_ID_LENGTH, 16);
        assert_eq!(RELAY_HEADER_SIZE, 1 + 16 + 4);
        assert_eq!(RELAY_HEADER_SIZE, 21);
        assert_eq!(RELAY_MAX_PAYLOAD_DEFAULT, 65_536);
    }

    // ── 2-6. parse_header ───────────────────────────────────

    #[test]
    fn parse_header_valid() {
        let payload = b"hello";
        let data = make_test_envelope(RELAY_ENVELOPE_VERSION, &TEST_SESSION, payload);
        let (version, session_id, payload_length) = parse_header(&data).expect("should parse");
        assert_eq!(version, RELAY_ENVELOPE_VERSION);
        assert_eq!(session_id, TEST_SESSION);
        assert_eq!(payload_length, payload.len() as u32);
    }

    #[test]
    fn parse_header_truncated() {
        let data = [0u8; 20]; // 1 byte short
        assert_eq!(parse_header(&data), Err(RelayError::TruncatedHeader));
    }

    #[test]
    fn parse_header_empty() {
        assert_eq!(parse_header(&[]), Err(RelayError::TruncatedHeader));
    }

    #[test]
    fn parse_header_wrong_version() {
        let data = make_test_envelope(2, &TEST_SESSION, b"x");
        assert_eq!(parse_header(&data), Err(RelayError::UnsupportedVersion(2)));
    }

    #[test]
    fn parse_header_version_zero() {
        let data = make_test_envelope(0, &TEST_SESSION, b"x");
        assert_eq!(parse_header(&data), Err(RelayError::UnsupportedVersion(0)));
    }

    // ── 7-10. validate_envelope ─────────────────────────────

    #[test]
    fn validate_envelope_valid() {
        let payload = b"opaque-bolt-envelope-bytes";
        let data = make_test_envelope(RELAY_ENVELOPE_VERSION, &TEST_SESSION, payload);
        let (version, session_id, extracted) =
            validate_envelope(&data, RELAY_MAX_PAYLOAD_DEFAULT).expect("should validate");
        assert_eq!(version, RELAY_ENVELOPE_VERSION);
        assert_eq!(session_id, TEST_SESSION);
        assert_eq!(extracted, payload);
    }

    #[test]
    fn validate_envelope_empty_payload() {
        // payload_length = 0 in header
        let mut data = vec![RELAY_ENVELOPE_VERSION];
        data.extend_from_slice(&TEST_SESSION);
        data.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            validate_envelope(&data, RELAY_MAX_PAYLOAD_DEFAULT),
            Err(RelayError::EmptyPayload)
        );
    }

    #[test]
    fn validate_envelope_too_large() {
        // payload_length = 100, max = 50
        let mut data = vec![RELAY_ENVELOPE_VERSION];
        data.extend_from_slice(&TEST_SESSION);
        data.extend_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 100]);
        assert_eq!(
            validate_envelope(&data, 50),
            Err(RelayError::PayloadTooLarge {
                length: 100,
                max: 50
            })
        );
    }

    #[test]
    fn validate_envelope_truncated_payload() {
        // Header says 10 bytes, but only 5 are present
        let mut data = vec![RELAY_ENVELOPE_VERSION];
        data.extend_from_slice(&TEST_SESSION);
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 5]);
        assert_eq!(
            validate_envelope(&data, RELAY_MAX_PAYLOAD_DEFAULT),
            Err(RelayError::TruncatedPayload {
                expected: 10,
                actual: 5
            })
        );
    }

    // ── 11-12. generate_session_id ──────────────────────────

    #[test]
    fn generate_session_id_length() {
        let id = generate_session_id();
        assert_eq!(id.len(), RELAY_SESSION_ID_LENGTH);
    }

    #[test]
    fn generate_session_id_not_all_zeros() {
        // A CSPRNG-generated 16-byte value must not be all zeros.
        // Probability of all zeros: 2^-128 — deterministically testable.
        let id = generate_session_id();
        assert_ne!(id, [0u8; 16], "session_id must not be all zeros");
    }

    // ── 13-14. make_session_assigned ────────────────────────

    #[test]
    fn session_assigned_format() {
        let msg = make_session_assigned(&TEST_SESSION);
        assert_eq!(msg[0], CTRL_SESSION_ASSIGNED);
        assert_eq!(&msg[1..], &TEST_SESSION);
    }

    #[test]
    fn session_assigned_length() {
        let msg = make_session_assigned(&TEST_SESSION);
        assert_eq!(msg.len(), 1 + RELAY_SESSION_ID_LENGTH);
        assert_eq!(msg.len(), 17);
    }

    // ── 15. wrap_envelope roundtrip ─────────────────────────

    #[test]
    fn wrap_envelope_roundtrip() {
        let payload = b"test-bolt-encrypted-envelope-data-here";
        let frame = wrap_envelope(&TEST_SESSION, payload);

        // Frame size: 21 header + payload
        assert_eq!(frame.len(), RELAY_HEADER_SIZE + payload.len());

        // Validate via the public API
        let (version, session_id, extracted) =
            validate_envelope(&frame, RELAY_MAX_PAYLOAD_DEFAULT).expect("roundtrip should succeed");
        assert_eq!(version, RELAY_ENVELOPE_VERSION);
        assert_eq!(session_id, TEST_SESSION);
        assert_eq!(extracted, payload);
    }
}
