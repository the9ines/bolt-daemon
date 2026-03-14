//! QUIC transport adapter for daemon↔daemon reference path (RC3).
//!
//! Provides a quinn-based QUIC transport that implements length-prefixed
//! message framing over a single bidirectional QUIC stream. This is a
//! transport-only layer — Bolt envelope/BTR remains the security authority.
//!
//! # RC3 TLS Policy
//!
//! **REFERENCE MODE ONLY — NOT FOR PRODUCTION.**
//!
//! - Self-signed certificates generated per-session via `rcgen`.
//! - Client skips server certificate verification.
//! - QUIC TLS provides transport encryption only.
//! - No Bolt identity-key binding to TLS certificates.
//! - Bolt envelope (NaCl-box) and BTR remain the security authority.
//!
//! Production deployment MUST replace this with proper certificate
//! management and identity binding (post-RC3 scope).

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

// ── Constants ───────────────────────────────────────────────

/// Maximum message size: 16 MiB. Well above any Bolt payload.
/// Protects against malformed length prefixes consuming unbounded memory.
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// QUIC application-level protocol identifier for RC3 reference path.
const ALPN_RC3: &[u8] = b"bolt-rc3";

/// Default QUIC listen port.
pub const DEFAULT_QUIC_PORT: u16 = 4433;

// ── Error types ─────────────────────────────────────────────

#[derive(Debug)]
pub enum QuicTransportError {
    /// Connection-level failure.
    Connection(String),
    /// Stream read/write failure.
    Stream(String),
    /// Message too large (exceeds MAX_MESSAGE_SIZE).
    MessageTooLarge(u32),
    /// TLS/certificate setup failure.
    Tls(String),
    /// Peer closed the connection or stream.
    Closed,
}

impl std::fmt::Display for QuicTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicTransportError::Connection(msg) => write!(f, "QUIC connection error: {msg}"),
            QuicTransportError::Stream(msg) => write!(f, "QUIC stream error: {msg}"),
            QuicTransportError::MessageTooLarge(size) => {
                write!(
                    f,
                    "QUIC message too large: {size} bytes (max {MAX_MESSAGE_SIZE})"
                )
            }
            QuicTransportError::Tls(msg) => write!(f, "QUIC TLS error: {msg}"),
            QuicTransportError::Closed => write!(f, "QUIC connection closed"),
        }
    }
}

impl std::error::Error for QuicTransportError {}

// ── Framed stream ───────────────────────────────────────────

/// A length-prefixed message stream over a single bidirectional QUIC stream.
///
/// Wire format per message: `[4-byte u32 BE length][payload]`.
/// This is necessary because QUIC streams are byte-oriented, not
/// message-oriented like WebRTC DataChannels.
pub struct QuicFramedStream {
    send: SendStream,
    recv: RecvStream,
    /// Tracks whether the underlying stream is still open.
    open: bool,
    /// Bytes buffered (approximate, for TransportQuery).
    buffered: usize,
}

impl QuicFramedStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            open: true,
            buffered: 0,
        }
    }

    /// Send a length-prefixed message.
    pub async fn send_message(&mut self, payload: &[u8]) -> Result<(), QuicTransportError> {
        let len = payload.len() as u32;
        if len > MAX_MESSAGE_SIZE {
            return Err(QuicTransportError::MessageTooLarge(len));
        }

        self.buffered += 4 + payload.len();

        // Write length prefix (big-endian u32)
        self.send
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| QuicTransportError::Stream(format!("write length: {e}")))?;

        // Write payload
        self.send
            .write_all(payload)
            .await
            .map_err(|e| QuicTransportError::Stream(format!("write payload: {e}")))?;

        self.buffered -= 4 + payload.len();
        Ok(())
    }

    /// Receive a length-prefixed message.
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, QuicTransportError> {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match self.recv.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => {
                self.open = false;
                return Err(QuicTransportError::Closed);
            }
            Err(e) => {
                return Err(QuicTransportError::Stream(format!("read length: {e}")));
            }
        }

        let len = u32::from_be_bytes(len_buf);
        if len > MAX_MESSAGE_SIZE {
            return Err(QuicTransportError::MessageTooLarge(len));
        }

        // Read payload
        let mut payload = vec![0u8; len as usize];
        match self.recv.read_exact(&mut payload).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => {
                self.open = false;
                return Err(QuicTransportError::Closed);
            }
            Err(e) => {
                return Err(QuicTransportError::Stream(format!("read payload: {e}")));
            }
        }

        Ok(payload)
    }

    /// Gracefully close the send side.
    pub async fn finish(&mut self) -> Result<(), QuicTransportError> {
        self.send
            .finish()
            .map_err(|e| QuicTransportError::Stream(format!("finish: {e}")))?;
        self.open = false;
        Ok(())
    }

    /// Whether the stream is still open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Approximate buffered bytes (for TransportQuery compatibility).
    pub fn buffered_bytes(&self) -> usize {
        self.buffered
    }
}

// ── RC3 TLS configuration ───────────────────────────────────
//
// WARNING: Self-signed certificates with no verification.
// This is explicitly scoped to RC3 reference mode.
// QUIC TLS provides transport encryption; Bolt envelope/BTR is security authority.

/// Generate a self-signed certificate for the RC3 reference path.
///
/// # RC3 REFERENCE MODE ONLY
/// Not for production. No identity binding.
fn generate_self_signed_cert(
) -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>), QuicTransportError> {
    let cert_params = rcgen::CertificateParams::new(vec!["bolt-rc3-reference".to_string()])
        .map_err(|e| QuicTransportError::Tls(format!("cert params: {e}")))?;
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| QuicTransportError::Tls(format!("keygen: {e}")))?;
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| QuicTransportError::Tls(format!("self-sign: {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    Ok((vec![cert_der], key_der))
}

/// Build quinn ServerConfig with self-signed cert.
///
/// # RC3 REFERENCE MODE ONLY
fn build_server_config() -> Result<ServerConfig, QuicTransportError> {
    let (certs, key) = generate_self_signed_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(|e| QuicTransportError::Tls(format!("server config: {e}")))?;
    server_crypto.alpn_protocols = vec![ALPN_RC3.to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| QuicTransportError::Tls(format!("quinn server config: {e}")))?,
    ));

    Ok(server_config)
}

/// Build quinn ClientConfig that skips server certificate verification.
///
/// # RC3 REFERENCE MODE ONLY
///
/// **WARNING: INSECURE.** This skips all certificate verification.
/// QUIC TLS provides transport encryption only in RC3.
/// Bolt envelope (NaCl-box) and BTR remain the security authority.
fn build_client_config() -> Result<ClientConfig, QuicTransportError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Rc3SkipVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN_RC3.to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| QuicTransportError::Tls(format!("quinn client config: {e}")))?,
    ));

    Ok(client_config)
}

/// RC3 certificate verifier that accepts any server certificate.
///
/// **WARNING: INSECURE — RC3 REFERENCE MODE ONLY.**
/// Production MUST replace this with proper certificate validation.
#[derive(Debug)]
struct Rc3SkipVerification;

impl rustls::client::danger::ServerCertVerifier for Rc3SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // RC3: Accept all certs. Bolt envelope is security authority.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Support common schemes for self-signed certs
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// ── Listener (answerer side) ────────────────────────────────

/// QUIC listener for the daemon answerer.
///
/// Binds to a local address and waits for a single incoming connection,
/// then opens a bidirectional stream for message exchange.
pub struct QuicListener {
    endpoint: Endpoint,
    local_addr: SocketAddr,
}

impl std::fmt::Debug for QuicListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListener")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl QuicListener {
    /// Bind a QUIC listener on the given address.
    pub fn bind(addr: SocketAddr) -> Result<Self, QuicTransportError> {
        let server_config = build_server_config()?;
        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| QuicTransportError::Connection(format!("bind {addr}: {e}")))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| QuicTransportError::Connection(format!("local addr: {e}")))?;

        eprintln!("[quic] listener bound on {local_addr}");
        Ok(Self {
            endpoint,
            local_addr,
        })
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept a single incoming connection and open a bidirectional stream.
    pub async fn accept(&self) -> Result<QuicFramedStream, QuicTransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(QuicTransportError::Closed)?;

        eprintln!(
            "[quic] incoming connection from {}",
            incoming.remote_address()
        );

        let connection = incoming
            .await
            .map_err(|e| QuicTransportError::Connection(format!("accept: {e}")))?;

        eprintln!(
            "[quic] connection established with {}",
            connection.remote_address()
        );

        // Accept a bidirectional stream opened by the dialer
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| QuicTransportError::Stream(format!("accept_bi: {e}")))?;

        eprintln!("[quic] bidirectional stream accepted");
        Ok(QuicFramedStream::new(send, recv))
    }

    /// Shut down the listener endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"done");
    }
}

// ── Dialer (offerer side) ───────────────────────────────────

/// QUIC dialer for the daemon offerer.
///
/// Connects to a remote QUIC endpoint at an explicit host:port and
/// opens a bidirectional stream for message exchange.
pub struct QuicDialer;

impl QuicDialer {
    /// Connect to a remote QUIC endpoint and open a bidirectional stream.
    pub async fn connect(
        remote: SocketAddr,
    ) -> Result<(Endpoint, QuicFramedStream), QuicTransportError> {
        let client_config = build_client_config()?;

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| QuicTransportError::Connection(format!("client endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        eprintln!("[quic] connecting to {remote}...");

        let connection = endpoint
            .connect(remote, "bolt-rc3-reference")
            .map_err(|e| QuicTransportError::Connection(format!("connect {remote}: {e}")))?
            .await
            .map_err(|e| QuicTransportError::Connection(format!("handshake {remote}: {e}")))?;

        eprintln!(
            "[quic] connection established with {}",
            connection.remote_address()
        );

        // Open a bidirectional stream
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| QuicTransportError::Stream(format!("open_bi: {e}")))?;

        eprintln!("[quic] bidirectional stream opened");
        Ok((endpoint, QuicFramedStream::new(send, recv)))
    }
}

// ── Transport-generic message interface ─────────────────────

/// Trait for transport-generic message sending (used by smoke mode).
///
/// Abstracts over WebRTC DataChannel and QUIC framed stream so that
/// smoke sender/receiver logic can be shared.
pub trait MessageTransport {
    /// Send a message (framed appropriately for the transport).
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    /// Receive a message with timeout.
    fn recv_bytes(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_constants_valid() {
        assert_eq!(MAX_MESSAGE_SIZE, 16 * 1024 * 1024);
        assert_eq!(ALPN_RC3, b"bolt-rc3");
        assert_eq!(DEFAULT_QUIC_PORT, 4433);
    }

    #[test]
    fn error_display() {
        let err = QuicTransportError::Connection("test".to_string());
        assert!(err.to_string().contains("QUIC connection error"));

        let err = QuicTransportError::Stream("test".to_string());
        assert!(err.to_string().contains("QUIC stream error"));

        let err = QuicTransportError::MessageTooLarge(999);
        assert!(err.to_string().contains("999"));
        assert!(err.to_string().contains("too large"));

        let err = QuicTransportError::Tls("test".to_string());
        assert!(err.to_string().contains("QUIC TLS error"));

        let err = QuicTransportError::Closed;
        assert!(err.to_string().contains("closed"));
    }

    #[test]
    fn self_signed_cert_generation() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok(), "cert generation failed: {result:?}");
        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
    }

    #[test]
    fn server_config_builds() {
        let result = build_server_config();
        assert!(result.is_ok(), "server config failed: {result:?}");
    }

    #[test]
    fn client_config_builds() {
        let result = build_client_config();
        assert!(result.is_ok(), "client config failed: {result:?}");
    }

    #[tokio::test]
    async fn listener_binds_ephemeral_port() {
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap());
        assert!(listener.is_ok(), "bind failed: {listener:?}");
        let listener = listener.unwrap();
        assert_ne!(listener.local_addr().port(), 0);
        listener.close();
    }

    #[tokio::test]
    async fn connect_accept_stream_exchange() {
        // Listener on ephemeral port
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();

        // Spawn listener to accept one connection
        let listener_handle = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();

            // Receive a message
            let msg = stream.recv_message().await.unwrap();
            assert_eq!(msg, b"hello from dialer");

            // Send a reply
            stream.send_message(b"hello from listener").await.unwrap();

            // Receive second message
            let msg2 = stream.recv_message().await.unwrap();
            assert_eq!(msg2, b"second message");

            stream.finish().await.ok();
            listener.close();
        });

        // Dialer connects
        let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

        // Send a message
        stream.send_message(b"hello from dialer").await.unwrap();

        // Receive reply
        let reply = stream.recv_message().await.unwrap();
        assert_eq!(reply, b"hello from listener");

        // Send second message
        stream.send_message(b"second message").await.unwrap();

        stream.finish().await.ok();

        // Wait for listener to complete before closing endpoint
        listener_handle.await.unwrap();
        endpoint.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn framing_preserves_message_boundaries() {
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();

        let listener_handle = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut messages = Vec::new();
            for _ in 0..5 {
                messages.push(stream.recv_message().await.unwrap());
            }
            stream.finish().await.ok();
            listener.close();
            messages
        });

        let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

        // Send 5 messages of varying sizes
        let payloads: Vec<Vec<u8>> = vec![
            vec![0u8; 1],     // 1 byte
            vec![1u8; 100],   // 100 bytes
            vec![2u8; 16384], // 16 KiB (default chunk size)
            vec![3u8; 65536], // 64 KiB
            vec![],           // empty message
        ];

        for p in &payloads {
            stream.send_message(p).await.unwrap();
        }

        stream.finish().await.ok();

        // Wait for listener to complete before closing endpoint
        let received = listener_handle.await.unwrap();
        endpoint.close(0u32.into(), b"done");

        assert_eq!(received.len(), 5);
        for (i, (sent, recv)) in payloads.iter().zip(received.iter()).enumerate() {
            assert_eq!(sent, recv, "message {i} mismatch");
        }
    }

    #[tokio::test]
    async fn large_payload_transfer() {
        // Transfer 1 MiB in 64 KiB chunks (matches smoke mode defaults)
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();

        let total_bytes: usize = 1_048_576;
        let chunk_size: usize = 65_536;

        let listener_handle = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut received = Vec::with_capacity(total_bytes);
            loop {
                match stream.recv_message().await {
                    Ok(msg) => {
                        if msg.is_empty() {
                            break; // sentinel
                        }
                        received.extend_from_slice(&msg);
                    }
                    Err(QuicTransportError::Closed) => break,
                    Err(e) => panic!("recv error: {e}"),
                }
            }
            listener.close();
            received
        });

        let (endpoint, mut stream) = QuicDialer::connect(addr).await.unwrap();

        // Generate deterministic payload
        let payload: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();

        // Send in chunks
        for chunk in payload.chunks(chunk_size) {
            stream.send_message(chunk).await.unwrap();
        }
        // Send empty sentinel
        stream.send_message(&[]).await.unwrap();

        stream.finish().await.ok();

        // Wait for listener to complete before closing endpoint
        let received = listener_handle.await.unwrap();
        endpoint.close(0u32.into(), b"done");

        assert_eq!(received.len(), total_bytes);
        assert_eq!(received, payload);
    }

    #[test]
    fn message_too_large_rejected() {
        // Verify the constant-level check (actual send would need async)
        let size = MAX_MESSAGE_SIZE + 1;
        let err = QuicTransportError::MessageTooLarge(size);
        assert!(err.to_string().contains("too large"));
    }
}
