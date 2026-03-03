//! Transfer state machine for post-HELLO file transfer control (B3-P2, B4).
//!
//! Implements a deterministic transfer session tracker integrated into
//! `run_post_hello_loop`. Phase B3-P2 scope: FileOffer auto-accept,
//! chunk receive with in-memory reassembly, transfer completion.
//! Phase B4 scope: receiver-side SHA-256 hash verification gated by
//! bolt.file-hash capability negotiation.
//! No disk I/O, no send-side streaming, no concurrent transfers.

// ── Constants ────────────────────────────────────────────────

/// Maximum transfer size in bytes (256 MiB).
/// Conservative bound for in-memory reassembly. No disk writes in B3-P2.
pub const MAX_TRANSFER_BYTES: u64 = 256 * 1024 * 1024;

// ── State ────────────────────────────────────────────────────

/// Transfer session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    Idle,
    OfferReceived { transfer_id: String },
    Receiving { transfer_id: String },
    Completed { transfer_id: String },
    Rejected,
}

// ── Error ────────────────────────────────────────────────────

/// Transfer state machine error.
#[derive(Debug)]
pub enum TransferError {
    InvalidTransition(String),
    /// B4: SHA-256 hash mismatch after reassembly (receiver-side).
    IntegrityFailed(String),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::InvalidTransition(detail) => write!(f, "{detail}"),
            TransferError::IntegrityFailed(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for TransferError {}

// ── Session ──────────────────────────────────────────────────

/// Single-transfer session tracker.
///
/// Enforces: Idle → OfferReceived → Receiving → Completed.
/// Also supports: OfferReceived → Rejected (B3-P1 reject path).
/// Second offer while not Idle is INVALID_STATE + disconnect.
pub struct TransferSession {
    state: TransferState,
    buffer: Vec<u8>,
    expected_len: u64,
    total_chunks: u32,
    next_chunk_index: u32,
    expected_hash: Option<String>, // B4: from FileOffer, hex SHA-256
}

impl Default for TransferSession {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferSession {
    pub fn new() -> Self {
        Self {
            state: TransferState::Idle,
            buffer: Vec::new(),
            expected_len: 0,
            total_chunks: 0,
            next_chunk_index: 0,
            expected_hash: None,
        }
    }

    /// Current state (for test observability).
    pub fn state(&self) -> &TransferState {
        &self.state
    }

    /// Transition: Idle → OfferReceived.
    ///
    /// Validates offer fields and stores metadata on the struct.
    /// Errors if not Idle (locked detail strings per B3 spec).
    ///
    /// `expected_hash`: B4 — if `Some`, SHA-256 hex hash to verify at finish.
    /// The loop passes `Some` only when `bolt.file-hash` is negotiated AND the
    /// offer includes a hash. `None` means no verification.
    pub fn on_file_offer(
        &mut self,
        transfer_id: &str,
        size: u64,
        total_chunks: u32,
        expected_hash: Option<&str>,
    ) -> Result<(), TransferError> {
        // Validate offer fields before state check (per spec: "any" state)
        if size == 0 {
            return Err(TransferError::InvalidTransition(
                "invalid offer: size is zero".to_string(),
            ));
        }
        if total_chunks == 0 {
            return Err(TransferError::InvalidTransition(
                "invalid offer: zero chunks".to_string(),
            ));
        }
        if size > MAX_TRANSFER_BYTES {
            return Err(TransferError::InvalidTransition(
                "transfer size exceeded".to_string(),
            ));
        }

        match &self.state {
            TransferState::Idle => {
                self.expected_len = size;
                self.total_chunks = total_chunks;
                self.expected_hash = expected_hash.map(|s| s.to_string());
                self.state = TransferState::OfferReceived {
                    transfer_id: transfer_id.to_string(),
                };
                Ok(())
            }
            TransferState::OfferReceived { .. } => Err(TransferError::InvalidTransition(
                "offer already active".to_string(),
            )),
            TransferState::Receiving { .. } => Err(TransferError::InvalidTransition(
                "transfer already active".to_string(),
            )),
            TransferState::Completed { .. } | TransferState::Rejected => Err(
                TransferError::InvalidTransition("transfer session ended".to_string()),
            ),
        }
    }

    /// Transition: OfferReceived → Receiving. Returns the transfer_id for Accept message.
    ///
    /// Pre-allocates buffer with capacity = min(expected_len, MAX_TRANSFER_BYTES) as usize.
    pub fn accept_current_offer(&mut self) -> Result<String, TransferError> {
        match &self.state {
            TransferState::OfferReceived { transfer_id } => {
                let tid = transfer_id.clone();
                let capacity = std::cmp::min(self.expected_len, MAX_TRANSFER_BYTES) as usize;
                self.buffer = Vec::with_capacity(capacity);
                self.next_chunk_index = 0;
                self.state = TransferState::Receiving {
                    transfer_id: tid.clone(),
                };
                Ok(tid)
            }
            _ => Err(TransferError::InvalidTransition(
                "no active offer".to_string(),
            )),
        }
    }

    /// Transition: OfferReceived → Rejected. Returns the transfer_id.
    ///
    /// Errors if not OfferReceived (locked detail string per B3-P1 spec).
    pub fn reject_current_offer(&mut self) -> Result<String, TransferError> {
        match &self.state {
            TransferState::OfferReceived { transfer_id } => {
                let tid = transfer_id.clone();
                self.state = TransferState::Rejected;
                Ok(tid)
            }
            _ => Err(TransferError::InvalidTransition(
                "no active offer".to_string(),
            )),
        }
    }

    /// Receiving → Receiving. Appends decoded bytes to buffer.
    ///
    /// Validates transfer_id, sequential chunk_index, bounds, and buffer capacity.
    pub fn on_file_chunk(
        &mut self,
        transfer_id: &str,
        chunk_index: u32,
        data: &[u8],
    ) -> Result<(), TransferError> {
        let active_tid = match &self.state {
            TransferState::Receiving { transfer_id: tid } => tid.clone(),
            _ => {
                return Err(TransferError::InvalidTransition(
                    "no active transfer".to_string(),
                ))
            }
        };

        if transfer_id != active_tid {
            return Err(TransferError::InvalidTransition(
                "transfer_id mismatch".to_string(),
            ));
        }

        if chunk_index >= self.total_chunks {
            return Err(TransferError::InvalidTransition(
                "chunk index out of range".to_string(),
            ));
        }

        if chunk_index != self.next_chunk_index {
            return Err(TransferError::InvalidTransition(
                "unexpected chunk index".to_string(),
            ));
        }

        if self.buffer.len() + data.len() > MAX_TRANSFER_BYTES as usize {
            return Err(TransferError::InvalidTransition(
                "transfer size exceeded".to_string(),
            ));
        }

        self.buffer.extend_from_slice(data);
        self.next_chunk_index += 1;
        Ok(())
    }

    /// Transition: Receiving → Completed.
    ///
    /// Validates transfer_id matches active transfer.
    /// B4: If `expected_hash` is `Some`, computes SHA-256 of the reassembled
    /// buffer and verifies (case-insensitive). Mismatch → `IntegrityFailed`.
    pub fn on_file_finish(&mut self, transfer_id: &str) -> Result<(), TransferError> {
        let active_tid = match &self.state {
            TransferState::Receiving { transfer_id: tid } => tid.clone(),
            _ => {
                return Err(TransferError::InvalidTransition(
                    "no active transfer".to_string(),
                ))
            }
        };

        if transfer_id != active_tid {
            return Err(TransferError::InvalidTransition(
                "transfer_id mismatch".to_string(),
            ));
        }

        // B4: Verify SHA-256 hash if expected_hash was set by on_file_offer.
        if let Some(ref expected) = self.expected_hash {
            let computed = bolt_core::hash::sha256_hex(&self.buffer);
            if !computed.eq_ignore_ascii_case(expected) {
                return Err(TransferError::IntegrityFailed(
                    "file hash mismatch".to_string(),
                ));
            }
        }

        self.state = TransferState::Completed {
            transfer_id: active_tid,
        };
        Ok(())
    }

    /// Returns true if this transfer completed with hash verification (B4 evidence).
    pub fn hash_verified(&self) -> bool {
        matches!(&self.state, TransferState::Completed { .. }) && self.expected_hash.is_some()
    }

    /// Returns buffer contents if Completed, None otherwise.
    pub fn completed_bytes(&self) -> Option<&[u8]> {
        match &self.state {
            TransferState::Completed { .. } => Some(&self.buffer),
            _ => None,
        }
    }
}

// ── Send-side state (B3-P3) ──────────────────────────────────

/// Send-side transfer state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendState {
    Idle,
    OfferSent { transfer_id: String },
    Sending { transfer_id: String },
    Completed { transfer_id: String },
    Cancelled { transfer_id: String },
}

/// Metadata returned by `begin_send()`.
#[derive(Debug)]
pub struct SendOffer {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub total_chunks: u32,
    pub chunk_size: u32,
    pub file_hash: Option<String>,
}

/// Single chunk returned by `next_chunk()`.
#[derive(Debug)]
pub struct SendChunk {
    pub transfer_id: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
}

/// Outbound transfer session tracker (sender side).
///
/// Enforces: Idle → OfferSent → Sending → Completed.
/// Also supports: OfferSent/Sending → Cancelled (receiver Cancel).
/// One outbound transfer per connection maximum.
pub struct SendSession {
    state: SendState,
    payload: Vec<u8>,
    chunk_size: usize,
    cursor: usize,
    total_chunks: u32,
    next_chunk_index: u32,
    send_count: u64,
    file_hash: Option<String>,
}

impl Default for SendSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SendSession {
    pub fn new() -> Self {
        Self {
            state: SendState::Idle,
            payload: Vec::new(),
            chunk_size: bolt_core::constants::DEFAULT_CHUNK_SIZE,
            cursor: 0,
            total_chunks: 0,
            next_chunk_index: 0,
            send_count: 0,
            file_hash: None,
        }
    }

    /// Current state (for test observability).
    pub fn state(&self) -> &SendState {
        &self.state
    }

    /// Begin an outbound transfer. Must be Idle.
    ///
    /// Computes metadata, generates transfer_id, transitions Idle → OfferSent.
    /// Returns structured metadata for the loop to build DcMessage::FileOffer.
    pub fn begin_send(
        &mut self,
        payload: Vec<u8>,
        filename: &str,
        file_hash_negotiated: bool,
    ) -> Result<SendOffer, TransferError> {
        if !matches!(self.state, SendState::Idle) {
            return Err(TransferError::InvalidTransition(
                "outbound transfer already active".to_string(),
            ));
        }

        if payload.is_empty() {
            return Err(TransferError::InvalidTransition(
                "empty payload".to_string(),
            ));
        }

        let size = payload.len() as u64;
        let total_chunks = payload.len().div_ceil(self.chunk_size) as u32;
        let hash = if file_hash_negotiated {
            Some(bolt_core::hash::sha256_hex(&payload))
        } else {
            None
        };

        self.send_count += 1;
        let transfer_id = format!("daemon-send-{:016x}", self.send_count);

        self.payload = payload;
        self.cursor = 0;
        self.total_chunks = total_chunks;
        self.next_chunk_index = 0;
        self.file_hash = hash.clone();
        self.state = SendState::OfferSent {
            transfer_id: transfer_id.clone(),
        };

        Ok(SendOffer {
            transfer_id,
            filename: filename.to_string(),
            size,
            total_chunks,
            chunk_size: self.chunk_size as u32,
            file_hash: hash,
        })
    }

    /// Receiver accepted our offer. Transitions OfferSent → Sending.
    pub fn on_accept(&mut self, transfer_id: &str) -> Result<(), TransferError> {
        match &self.state {
            SendState::OfferSent { transfer_id: tid } => {
                if transfer_id != tid {
                    return Err(TransferError::InvalidTransition(
                        "transfer_id mismatch".to_string(),
                    ));
                }
                let tid = tid.clone();
                self.cursor = 0;
                self.next_chunk_index = 0;
                self.state = SendState::Sending { transfer_id: tid };
                Ok(())
            }
            _ => Err(TransferError::InvalidTransition(
                "not awaiting accept".to_string(),
            )),
        }
    }

    /// Receiver cancelled. Transitions OfferSent/Sending → Cancelled.
    pub fn on_cancel(&mut self, transfer_id: &str) -> Result<(), TransferError> {
        match &self.state {
            SendState::OfferSent { transfer_id: tid } | SendState::Sending { transfer_id: tid } => {
                if transfer_id != tid {
                    return Err(TransferError::InvalidTransition(
                        "transfer_id mismatch".to_string(),
                    ));
                }
                self.state = SendState::Cancelled {
                    transfer_id: transfer_id.to_string(),
                };
                Ok(())
            }
            _ => Err(TransferError::InvalidTransition(
                "no active outbound transfer".to_string(),
            )),
        }
    }

    /// Yield next chunk. Must be Sending. Returns None when all chunks yielded.
    pub fn next_chunk(&mut self) -> Result<Option<SendChunk>, TransferError> {
        let tid = match &self.state {
            SendState::Sending { transfer_id } => transfer_id.clone(),
            _ => {
                return Err(TransferError::InvalidTransition(
                    "not in sending state".to_string(),
                ))
            }
        };

        if self.cursor >= self.payload.len() {
            return Ok(None);
        }

        let end = std::cmp::min(self.cursor + self.chunk_size, self.payload.len());
        let data = self.payload[self.cursor..end].to_vec();
        let chunk_index = self.next_chunk_index;

        self.cursor = end;
        self.next_chunk_index += 1;

        Ok(Some(SendChunk {
            transfer_id: tid,
            chunk_index,
            total_chunks: self.total_chunks,
            data,
        }))
    }

    /// Finalize transfer. Must be Sending with all chunks yielded.
    /// Transitions Sending → Completed. Returns transfer_id.
    pub fn finish(&mut self) -> Result<String, TransferError> {
        let tid = match &self.state {
            SendState::Sending { transfer_id } => transfer_id.clone(),
            _ => {
                return Err(TransferError::InvalidTransition(
                    "not in sending state".to_string(),
                ))
            }
        };

        if self.cursor < self.payload.len() {
            return Err(TransferError::InvalidTransition(
                "not all chunks yielded".to_string(),
            ));
        }

        self.state = SendState::Completed {
            transfer_id: tid.clone(),
        };
        Ok(tid)
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── B3-P1 tests (updated for new on_file_offer signature) ──

    #[test]
    fn b3_offer_then_reject_lifecycle() {
        let mut ts = TransferSession::new();
        assert_eq!(*ts.state(), TransferState::Idle);

        // Idle → OfferReceived
        ts.on_file_offer("t1", 100, 1, None).unwrap();
        assert_eq!(
            *ts.state(),
            TransferState::OfferReceived {
                transfer_id: "t1".to_string()
            }
        );

        // OfferReceived → Rejected, returns transfer_id
        let tid = ts.reject_current_offer().unwrap();
        assert_eq!(tid, "t1");
        assert_eq!(*ts.state(), TransferState::Rejected);
    }

    #[test]
    fn b3_double_offer_rejected() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 100, 1, None).unwrap();

        let err = ts.on_file_offer("t2", 200, 2, None).unwrap_err();
        assert!(
            err.to_string().contains("offer already active"),
            "expected 'offer already active', got: {err}"
        );
    }

    #[test]
    fn b3_reject_in_idle_fails() {
        let mut ts = TransferSession::new();
        let err = ts.reject_current_offer().unwrap_err();
        assert!(
            err.to_string().contains("no active offer"),
            "expected 'no active offer', got: {err}"
        );
    }

    // ── B3-P2 unit tests ──

    #[test]
    fn b3_offer_accept_lifecycle() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 100, 1, None).unwrap();
        assert_eq!(
            *ts.state(),
            TransferState::OfferReceived {
                transfer_id: "t1".to_string()
            }
        );

        let tid = ts.accept_current_offer().unwrap();
        assert_eq!(tid, "t1");
        assert_eq!(
            *ts.state(),
            TransferState::Receiving {
                transfer_id: "t1".to_string()
            }
        );
    }

    #[test]
    fn b3_full_receive_lifecycle() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 5, 1, None).unwrap();
        ts.accept_current_offer().unwrap();

        let data = b"hello";
        ts.on_file_chunk("t1", 0, data).unwrap();
        ts.on_file_finish("t1").unwrap();

        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );
        assert_eq!(ts.completed_bytes(), Some(data.as_slice()));
    }

    #[test]
    fn b3_multi_chunk_reassembly() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 15, 3, None).unwrap();
        ts.accept_current_offer().unwrap();

        ts.on_file_chunk("t1", 0, b"aaaaa").unwrap();
        ts.on_file_chunk("t1", 1, b"bbbbb").unwrap();
        ts.on_file_chunk("t1", 2, b"ccccc").unwrap();
        ts.on_file_finish("t1").unwrap();

        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );
        assert_eq!(ts.completed_bytes(), Some(b"aaaaabbbbbccccc".as_slice()));
    }

    #[test]
    fn b3_chunk_before_offer_fails() {
        let mut ts = TransferSession::new();
        let err = ts.on_file_chunk("t1", 0, b"data").unwrap_err();
        assert!(
            err.to_string().contains("no active transfer"),
            "expected 'no active transfer', got: {err}"
        );
    }

    #[test]
    fn b3_chunk_wrong_transfer_id_fails() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 100, 1, None).unwrap();
        ts.accept_current_offer().unwrap();

        let err = ts.on_file_chunk("t2", 0, b"data").unwrap_err();
        assert!(
            err.to_string().contains("transfer_id mismatch"),
            "expected 'transfer_id mismatch', got: {err}"
        );
    }

    #[test]
    fn b3_chunk_wrong_index_fails() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 100, 3, None).unwrap();
        ts.accept_current_offer().unwrap();

        let err = ts.on_file_chunk("t1", 1, b"data").unwrap_err();
        assert!(
            err.to_string().contains("unexpected chunk index"),
            "expected 'unexpected chunk index', got: {err}"
        );
    }

    #[test]
    fn b3_offer_size_exceeded_fails() {
        let mut ts = TransferSession::new();
        let err = ts
            .on_file_offer("t1", MAX_TRANSFER_BYTES + 1, 1, None)
            .unwrap_err();
        assert!(
            err.to_string().contains("transfer size exceeded"),
            "expected 'transfer size exceeded', got: {err}"
        );
    }

    #[test]
    fn b3_finish_wrong_id_fails() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 100, 1, None).unwrap();
        ts.accept_current_offer().unwrap();

        let err = ts.on_file_finish("wrong_id").unwrap_err();
        assert!(
            err.to_string().contains("transfer_id mismatch"),
            "expected 'transfer_id mismatch', got: {err}"
        );
    }

    #[test]
    fn b3_second_offer_after_complete_fails() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 5, 1, None).unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, b"hello").unwrap();
        ts.on_file_finish("t1").unwrap();
        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );

        let err = ts.on_file_offer("t2", 200, 2, None).unwrap_err();
        assert!(
            err.to_string().contains("transfer session ended"),
            "expected 'transfer session ended', got: {err}"
        );
    }

    // ── B4: file hash verification tests ──

    #[test]
    fn b4_hash_verify_correct() {
        let data = b"hello";
        let hash = bolt_core::hash::sha256_hex(data);

        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", data.len() as u64, 1, Some(&hash))
            .unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, data).unwrap();
        ts.on_file_finish("t1").unwrap();

        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );
        assert_eq!(ts.completed_bytes(), Some(data.as_slice()));
    }

    #[test]
    fn b4_hash_verify_mismatch() {
        let data = b"hello";
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", data.len() as u64, 1, Some(wrong_hash))
            .unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, data).unwrap();

        let err = ts.on_file_finish("t1").unwrap_err();
        assert!(
            err.to_string().contains("file hash mismatch"),
            "expected 'file hash mismatch', got: {err}"
        );
    }

    #[test]
    fn b4_no_hash_skips_verify() {
        let data = b"hello";

        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", data.len() as u64, 1, None).unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, data).unwrap();
        ts.on_file_finish("t1").unwrap();

        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );
    }

    #[test]
    fn b4_hash_case_insensitive() {
        let data = b"hello";
        let hash_upper = bolt_core::hash::sha256_hex(data).to_uppercase();

        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", data.len() as u64, 1, Some(&hash_upper))
            .unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, data).unwrap();
        ts.on_file_finish("t1").unwrap();

        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );
    }

    // ── B4: hash_verified() evidence tests ──

    #[test]
    fn b4_hash_verified_true_after_hash_match() {
        let data = b"deterministic payload";
        let hash = bolt_core::hash::sha256_hex(data);
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", data.len() as u64, 1, Some(&hash))
            .unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, data).unwrap();
        ts.on_file_finish("t1").unwrap();
        assert!(ts.hash_verified());
    }

    #[test]
    fn b4_hash_verified_false_when_no_hash() {
        let data = b"no hash payload";
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", data.len() as u64, 1, None).unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, data).unwrap();
        ts.on_file_finish("t1").unwrap();
        assert!(!ts.hash_verified());
    }

    // ── B3-P3: send-side state machine tests ──

    #[test]
    fn b3p3_send_lifecycle_complete() {
        let mut ss = SendSession::new();
        assert_eq!(*ss.state(), SendState::Idle);

        let payload = b"hello world, this is a test payload for send lifecycle".to_vec();
        let offer = ss.begin_send(payload.clone(), "test.txt", true).unwrap();
        assert!(matches!(ss.state(), SendState::OfferSent { .. }));
        assert!(offer.file_hash.is_some());
        assert_eq!(offer.size, payload.len() as u64);

        ss.on_accept(&offer.transfer_id).unwrap();
        assert!(matches!(ss.state(), SendState::Sending { .. }));

        let mut reassembled = Vec::new();
        while let Some(chunk) = ss.next_chunk().unwrap() {
            reassembled.extend_from_slice(&chunk.data);
        }
        assert_eq!(reassembled, payload);

        let tid = ss.finish().unwrap();
        assert_eq!(tid, offer.transfer_id);
        assert!(matches!(ss.state(), SendState::Completed { .. }));
    }

    #[test]
    fn b3p3_send_lifecycle_no_hash() {
        let mut ss = SendSession::new();
        let payload = b"no hash test".to_vec();
        let offer = ss
            .begin_send(payload.clone(), "no_hash.txt", false)
            .unwrap();
        assert!(offer.file_hash.is_none());

        ss.on_accept(&offer.transfer_id).unwrap();
        let mut reassembled = Vec::new();
        while let Some(chunk) = ss.next_chunk().unwrap() {
            reassembled.extend_from_slice(&chunk.data);
        }
        assert_eq!(reassembled, payload);
        ss.finish().unwrap();
        assert!(matches!(ss.state(), SendState::Completed { .. }));
    }

    #[test]
    fn b3p3_send_cancel_before_accept() {
        let mut ss = SendSession::new();
        let offer = ss.begin_send(b"data".to_vec(), "f.txt", false).unwrap();
        ss.on_cancel(&offer.transfer_id).unwrap();
        assert!(matches!(ss.state(), SendState::Cancelled { .. }));
    }

    #[test]
    fn b3p3_send_cancel_during_send() {
        let mut ss = SendSession::new();
        let payload = vec![0u8; 32768]; // > 1 chunk
        let offer = ss.begin_send(payload, "big.bin", false).unwrap();
        ss.on_accept(&offer.transfer_id).unwrap();
        // Consume one chunk (partial)
        let chunk = ss.next_chunk().unwrap();
        assert!(chunk.is_some());
        ss.on_cancel(&offer.transfer_id).unwrap();
        assert!(matches!(ss.state(), SendState::Cancelled { .. }));
    }

    #[test]
    fn b3p3_accept_wrong_transfer_id() {
        let mut ss = SendSession::new();
        ss.begin_send(b"data".to_vec(), "f.txt", false).unwrap();
        let err = ss.on_accept("wrong-id").unwrap_err();
        assert!(
            err.to_string().contains("transfer_id mismatch"),
            "expected 'transfer_id mismatch', got: {err}"
        );
    }

    #[test]
    fn b3p3_cancel_wrong_transfer_id() {
        let mut ss = SendSession::new();
        ss.begin_send(b"data".to_vec(), "f.txt", false).unwrap();
        let err = ss.on_cancel("wrong-id").unwrap_err();
        assert!(
            err.to_string().contains("transfer_id mismatch"),
            "expected 'transfer_id mismatch', got: {err}"
        );
    }

    #[test]
    fn b3p3_send_while_not_idle() {
        let mut ss = SendSession::new();
        ss.begin_send(b"data".to_vec(), "f.txt", false).unwrap();
        let err = ss.begin_send(b"more".to_vec(), "g.txt", false).unwrap_err();
        assert!(
            err.to_string().contains("outbound transfer already active"),
            "expected 'outbound transfer already active', got: {err}"
        );
    }

    #[test]
    fn b3p3_next_chunk_before_accept() {
        let mut ss = SendSession::new();
        ss.begin_send(b"data".to_vec(), "f.txt", false).unwrap();
        let err = ss.next_chunk().unwrap_err();
        assert!(
            err.to_string().contains("not in sending state"),
            "expected 'not in sending state', got: {err}"
        );
    }

    #[test]
    fn b3p3_finish_before_all_chunks() {
        let mut ss = SendSession::new();
        let payload = vec![0u8; 32768]; // 2 chunks
        let offer = ss.begin_send(payload, "big.bin", false).unwrap();
        ss.on_accept(&offer.transfer_id).unwrap();
        // Consume only 1 chunk
        ss.next_chunk().unwrap();
        let err = ss.finish().unwrap_err();
        assert!(
            err.to_string().contains("not all chunks yielded"),
            "expected 'not all chunks yielded', got: {err}"
        );
    }

    #[test]
    fn b3p3_chunk_size_correctness() {
        let mut ss = SendSession::new();
        // Payload = 2.5 chunks (16384 * 2 + 8192 = 40960)
        let payload = vec![0xAB; 40960];
        let offer = ss.begin_send(payload.clone(), "multi.bin", false).unwrap();
        assert_eq!(offer.total_chunks, 3);
        assert_eq!(
            offer.chunk_size,
            bolt_core::constants::DEFAULT_CHUNK_SIZE as u32
        );

        ss.on_accept(&offer.transfer_id).unwrap();

        let mut reassembled = Vec::new();
        let mut chunk_count = 0u32;
        while let Some(chunk) = ss.next_chunk().unwrap() {
            assert!(chunk.data.len() <= bolt_core::constants::DEFAULT_CHUNK_SIZE);
            assert_eq!(chunk.chunk_index, chunk_count);
            assert_eq!(chunk.total_chunks, 3);
            reassembled.extend_from_slice(&chunk.data);
            chunk_count += 1;
        }
        assert_eq!(chunk_count, 3);
        assert_eq!(reassembled, payload);
        ss.finish().unwrap();
    }
}
