//! Transport-neutral session frame seam (TRANSPORT-UNIFY-1, Phase 1).
//!
//! The Bolt session protocol is JSON text over one framed transport. This module
//! is the single seam every transport plugs into, so the session lifecycle is
//! written once in `ws_endpoint::run_session_with_outbound` + `run_read_loop`
//! instead of copied per transport. WS and QUIC adapt here; WebTransport folds in
//! next (Phase 2).
//!
//! - Outbound: the `FrameSink` trait — every transport sends JSON text frames.
//! - Inbound: transports present a `Stream<Item = Result<Message, ..>>` so the
//!   verbatim read loop consumes them unchanged. `Message` is used purely as an
//!   in-memory frame carrier; the bytes each transport puts on the wire are
//!   unchanged. This is an internal seam, not a wire-format change.

use std::future::Future;

/// Outbound half of a session transport: send JSON text frames, then close.
///
/// `Send + 'static` because the writer task is `tokio::spawn`ed; the returned
/// futures are `+ Send` for the same reason.
pub trait FrameSink: Send + 'static {
    fn send_text(&mut self, text: String) -> impl Future<Output = Result<(), String>> + Send;
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

// ── WebSocket adapter ─────────────────────────────────────────
#[cfg(feature = "transport-ws")]
mod ws {
    use super::FrameSink;
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::{self, Message};

    /// Adapts a tungstenite sink half (`Sink<Message>`) to `FrameSink`.
    /// (WS inbound needs no adapter — the split stream is already `Stream<Message>`.)
    pub struct WsFrameSink<S>(pub S);

    impl<S> FrameSink for WsFrameSink<S>
    where
        S: SinkExt<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    {
        async fn send_text(&mut self, text: String) -> Result<(), String> {
            self.0
                .send(Message::Text(text))
                .await
                .map_err(|e| e.to_string())
        }
        async fn close(&mut self) {
            let _ = self.0.close().await;
        }
    }
}
#[cfg(feature = "transport-ws")]
pub use ws::WsFrameSink;

// ── QUIC adapters ─────────────────────────────────────────────
#[cfg(feature = "transport-quic")]
mod quic {
    use super::FrameSink;
    use crate::quic_transport::{QuicMessageReceiver, QuicMessageSender, QuicTransportError};
    use futures_util::Stream;
    use tokio_tungstenite::tungstenite::{self, Message};

    /// Adapts a QUIC framed-stream sender to `FrameSink`.
    pub struct QuicFrameSink(pub QuicMessageSender);

    impl FrameSink for QuicFrameSink {
        async fn send_text(&mut self, text: String) -> Result<(), String> {
            self.0
                .send_message(text.as_bytes())
                .await
                .map_err(|e| e.to_string())
        }
        async fn close(&mut self) {
            let _ = self.0.finish().await;
        }
    }

    /// Presents a QUIC receiver as a `Stream<Item = Result<Message, tungstenite::Error>>`
    /// so the shared read loop consumes it unchanged. QUIC data frames become
    /// `Message::Text`; a clean close ends the stream; other errors are surfaced as
    /// an I/O error (the read loop logs and breaks, matching the old QUIC path).
    pub fn quic_message_stream(
        receiver: QuicMessageReceiver,
    ) -> impl Stream<Item = Result<Message, tungstenite::Error>> + Unpin + Send {
        Box::pin(futures_util::stream::unfold(receiver, |mut r| async move {
            match r.recv_message().await {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    Some((Ok(Message::Text(text)), r))
                }
                Err(QuicTransportError::Closed) => None,
                Err(e) => Some((
                    Err(tungstenite::Error::Io(std::io::Error::other(e.to_string()))),
                    r,
                )),
            }
        }))
    }
}
#[cfg(feature = "transport-quic")]
pub use quic::{quic_message_stream, QuicFrameSink};
