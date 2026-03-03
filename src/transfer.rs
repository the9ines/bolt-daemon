//! Transfer state machine for post-HELLO file transfer control (B3-P1).
//!
//! Implements a deterministic transfer session tracker integrated into
//! `run_post_hello_loop`. Phase B3-P1 scope: FileOffer interception and
//! reject via Cancel. No chunk streaming, no disk I/O, no concurrent transfers.

// ── State ────────────────────────────────────────────────────

/// Transfer session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    Idle,
    OfferReceived { transfer_id: String },
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
/// Enforces: Idle → OfferReceived → Rejected.
/// Second offer while not Idle is INVALID_STATE + disconnect.
pub struct TransferSession {
    state: TransferState,
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
        }
    }

    /// Current state (for test observability).
    pub fn state(&self) -> &TransferState {
        &self.state
    }

    /// Transition: Idle → OfferReceived.
    ///
    /// Errors if not Idle (locked detail strings per B3-P1 spec).
    pub fn on_file_offer(&mut self, transfer_id: &str) -> Result<(), TransferError> {
        match &self.state {
            TransferState::Idle => {
                self.state = TransferState::OfferReceived {
                    transfer_id: transfer_id.to_string(),
                };
                Ok(())
            }
            TransferState::OfferReceived { .. } => Err(TransferError::InvalidTransition(
                "offer already active".to_string(),
            )),
            TransferState::Rejected => Err(TransferError::InvalidTransition(
                "transfer session ended".to_string(),
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
            TransferState::Idle | TransferState::Rejected => Err(TransferError::InvalidTransition(
                "no active offer".to_string(),
            )),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b3_offer_then_reject_lifecycle() {
        let mut ts = TransferSession::new();
        assert_eq!(*ts.state(), TransferState::Idle);

        // Idle → OfferReceived
        ts.on_file_offer("t1").unwrap();
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
        ts.on_file_offer("t1").unwrap();

        let err = ts.on_file_offer("t2").unwrap_err();
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
}
