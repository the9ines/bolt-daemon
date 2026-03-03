//! Transfer state machine for post-HELLO file transfer control (B3-P2).
//!
//! Implements a deterministic transfer session tracker integrated into
//! `run_post_hello_loop`. Phase B3-P2 scope: FileOffer auto-accept,
//! chunk receive with in-memory reassembly, transfer completion.
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
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::InvalidTransition(detail) => write!(f, "{detail}"),
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
    pub fn on_file_offer(
        &mut self,
        transfer_id: &str,
        size: u64,
        total_chunks: u32,
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

        self.state = TransferState::Completed {
            transfer_id: active_tid,
        };
        Ok(())
    }

    /// Returns buffer contents if Completed, None otherwise.
    pub fn completed_bytes(&self) -> Option<&[u8]> {
        match &self.state {
            TransferState::Completed { .. } => Some(&self.buffer),
            _ => None,
        }
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
        ts.on_file_offer("t1", 100, 1).unwrap();
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
        ts.on_file_offer("t1", 100, 1).unwrap();

        let err = ts.on_file_offer("t2", 200, 2).unwrap_err();
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
        ts.on_file_offer("t1", 100, 1).unwrap();
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
        ts.on_file_offer("t1", 5, 1).unwrap();
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
        ts.on_file_offer("t1", 15, 3).unwrap();
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
        ts.on_file_offer("t1", 100, 1).unwrap();
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
        ts.on_file_offer("t1", 100, 3).unwrap();
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
            .on_file_offer("t1", MAX_TRANSFER_BYTES + 1, 1)
            .unwrap_err();
        assert!(
            err.to_string().contains("transfer size exceeded"),
            "expected 'transfer size exceeded', got: {err}"
        );
    }

    #[test]
    fn b3_finish_wrong_id_fails() {
        let mut ts = TransferSession::new();
        ts.on_file_offer("t1", 100, 1).unwrap();
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
        ts.on_file_offer("t1", 5, 1).unwrap();
        ts.accept_current_offer().unwrap();
        ts.on_file_chunk("t1", 0, b"hello").unwrap();
        ts.on_file_finish("t1").unwrap();
        assert_eq!(
            *ts.state(),
            TransferState::Completed {
                transfer_id: "t1".to_string()
            }
        );

        let err = ts.on_file_offer("t2", 200, 2).unwrap_err();
        assert!(
            err.to_string().contains("transfer session ended"),
            "expected 'transfer session ended', got: {err}"
        );
    }
}
