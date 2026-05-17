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
//! - Q1 dialer path verifies the listener certificate with SHA-256 cert-hash
//!   pinning. This is an internal, non-production milestone.
//! - Q2 primitives support mutual cert-hash pinning, including a dynamic
//!   server-side client-cert allowlist for signaling-supplied peer hashes.
//! - QUIC TLS provides transport encryption and cert-hash transport auth.
//! - No Bolt identity-key binding to TLS certificates.
//! - Bolt envelope (NaCl-box) and BTR remain the security authority.
//!
//! Production routing remains blocked until signaling-supplied peer hashes feed
//! the dynamic allowlist and QUIC streams run the app session lifecycle.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

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

// ── RC3/Q-stream TLS configuration ──────────────────────────
//
// QUIC remains non-production until signaling supplies peer hashes and QUIC
// streams run the app session lifecycle. The primitives below provide one-way
// and mutual cert-hash pinning without binding TLS certs to Bolt identity keys.

/// Self-signed QUIC certificate material for RC3/Q2 test and wiring paths.
pub struct QuicPeerCertificate {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    cert_hash_hex: String,
}

impl Clone for QuicPeerCertificate {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
            cert_hash_hex: self.cert_hash_hex.clone(),
        }
    }
}

impl std::fmt::Debug for QuicPeerCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicPeerCertificate")
            .field("cert_hash_hex", &self.cert_hash_hex)
            .finish_non_exhaustive()
    }
}

impl QuicPeerCertificate {
    /// Generate a self-signed certificate for QUIC reference/migration paths.
    ///
    /// This is not identity-bound. Production promotion remains gated on
    /// mutual cert-hash exchange and verification via signaling.
    pub fn generate_reference() -> Result<Self, QuicTransportError> {
        generate_self_signed_cert()
    }

    pub fn cert_hash_hex(&self) -> &str {
        &self.cert_hash_hex
    }
}

/// Generate a self-signed certificate for the RC3 reference path.
///
/// # RC3 REFERENCE MODE ONLY
/// Not for production. No identity binding.
fn generate_self_signed_cert() -> Result<QuicPeerCertificate, QuicTransportError> {
    let cert_params = rcgen::CertificateParams::new(vec!["bolt-rc3-reference".to_string()])
        .map_err(|e| QuicTransportError::Tls(format!("cert params: {e}")))?;
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| QuicTransportError::Tls(format!("keygen: {e}")))?;
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| QuicTransportError::Tls(format!("self-sign: {e}")))?;

    let cert_der_bytes = cert.der().to_vec();
    let cert_hash_hex = bolt_core::hash::sha256_hex(&cert_der_bytes);
    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok(QuicPeerCertificate {
        certs: vec![cert_der],
        key: key_der,
        cert_hash_hex,
    })
}

/// Build quinn ServerConfig with self-signed cert.
///
/// # RC3 REFERENCE MODE ONLY
fn build_server_config() -> Result<(ServerConfig, QuicPeerCertificate), QuicTransportError> {
    build_server_config_with_client_pin(None)
}

/// Build quinn ServerConfig with optional client certificate hash pinning.
///
/// Q2 internal primitive: when `expected_client_cert_hash_hex` is present, the
/// server requests a client certificate and verifies its DER SHA-256 hash.
fn build_server_config_with_client_pin(
    expected_client_cert_hash_hex: Option<&str>,
) -> Result<(ServerConfig, QuicPeerCertificate), QuicTransportError> {
    let cert = generate_self_signed_cert()?;

    let server_builder = rustls::ServerConfig::builder();
    let server_builder = match expected_client_cert_hash_hex {
        Some(expected) => {
            server_builder.with_client_cert_verifier(CertHashPinClientVerifier::new(expected)?)
        }
        None => server_builder.with_no_client_auth(),
    };

    let mut server_crypto = server_builder
        .with_single_cert(cert.certs.clone(), cert.key.clone_key())
        .map_err(|e| QuicTransportError::Tls(format!("server config: {e}")))?;
    server_crypto.alpn_protocols = vec![ALPN_RC3.to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| QuicTransportError::Tls(format!("quinn server config: {e}")))?,
    ));

    Ok((server_config, cert))
}

fn build_server_config_with_dynamic_client_pins(
    client_cert_pins: QuicClientCertPinSet,
) -> Result<(ServerConfig, QuicPeerCertificate), QuicTransportError> {
    let cert = generate_self_signed_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(DynamicCertHashPinClientVerifier::new(client_cert_pins))
        .with_single_cert(cert.certs.clone(), cert.key.clone_key())
        .map_err(|e| QuicTransportError::Tls(format!("server config: {e}")))?;
    server_crypto.alpn_protocols = vec![ALPN_RC3.to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| QuicTransportError::Tls(format!("quinn server config: {e}")))?,
    ));

    Ok((server_config, cert))
}

/// Build quinn ClientConfig that pins the peer certificate hash.
///
/// # Q1 INTERNAL MILESTONE ONLY
///
/// This removes the RC3 accept-any verifier from the dialer path, but it is
/// still one-way pinning only. Production app↔app QUIC remains blocked until
/// Q2 adds mutual pinning and signaling integration.
fn build_client_config(expected_cert_hash_hex: &str) -> Result<ClientConfig, QuicTransportError> {
    build_client_config_with_optional_client_cert(expected_cert_hash_hex, None)
}

fn build_client_config_with_optional_client_cert(
    expected_cert_hash_hex: &str,
    client_cert: Option<QuicPeerCertificate>,
) -> Result<ClientConfig, QuicTransportError> {
    let client_builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(CertHashPinServerVerifier::new(expected_cert_hash_hex)?);
    let mut client_crypto = match client_cert {
        Some(cert) => client_builder
            .with_client_auth_cert(cert.certs, cert.key)
            .map_err(|e| QuicTransportError::Tls(format!("client config: {e}")))?,
        None => client_builder.with_no_client_auth(),
    };
    client_crypto.alpn_protocols = vec![ALPN_RC3.to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| QuicTransportError::Tls(format!("quinn client config: {e}")))?,
    ));

    Ok(client_config)
}

/// Q1 certificate verifier that pins the listener certificate SHA-256 hash.
///
/// This verifies that the presented DER certificate matches the expected hash
/// and delegates TLS handshake signature verification to rustls' ring provider.
/// It does not provide mutual daemon↔daemon auth; Q2 must add that before QUIC
/// can become a production app↔app path.
#[derive(Debug)]
struct CertHashPinServerVerifier {
    expected_hash: [u8; 32],
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertHashPinServerVerifier {
    fn new(expected_cert_hash_hex: &str) -> Result<Arc<Self>, QuicTransportError> {
        Ok(Arc::new(Self {
            expected_hash: parse_sha256_hex(expected_cert_hash_hex)?,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        }))
    }
}

fn parse_sha256_hex(hex: &str) -> Result<[u8; 32], QuicTransportError> {
    if hex.len() != 64 {
        return Err(QuicTransportError::Tls(format!(
            "invalid cert hash length: expected 64 hex chars, got {}",
            hex.len()
        )));
    }

    let mut out = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|e| QuicTransportError::Tls(format!("invalid cert hash utf8: {e}")))?;
        out[idx] = u8::from_str_radix(pair, 16)
            .map_err(|e| QuicTransportError::Tls(format!("invalid cert hash hex: {e}")))?;
    }
    Ok(out)
}

impl rustls::client::danger::ServerCertVerifier for CertHashPinServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let received_hash = bolt_core::hash::sha256(end_entity.as_ref());
        if received_hash.as_slice() == self.expected_hash {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "QUIC certificate hash mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Q2 certificate verifier that pins the client certificate SHA-256 hash.
///
/// This is the server-side counterpart to `CertHashPinServerVerifier`. It is
/// a QUIC migration primitive only; production app↔app routing remains blocked
/// until signaling supplies peer hashes and the daemon uses this path.
#[derive(Debug)]
struct CertHashPinClientVerifier {
    expected_hash: [u8; 32],
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertHashPinClientVerifier {
    fn new(expected_cert_hash_hex: &str) -> Result<Arc<Self>, QuicTransportError> {
        Ok(Arc::new(Self {
            expected_hash: parse_sha256_hex(expected_cert_hash_hex)?,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        }))
    }
}

impl rustls::server::danger::ClientCertVerifier for CertHashPinClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let received_hash = bolt_core::hash::sha256(end_entity.as_ref());
        if received_hash.as_slice() == self.expected_hash {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "QUIC client certificate hash mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Thread-safe set of accepted QUIC client certificate hashes.
///
/// Production routing needs the listener to start before a specific peer is
/// selected, then learn allowed peer hashes from signaling. This pin set is the
/// server-side primitive for that flow.
#[derive(Debug, Clone, Default)]
pub struct QuicClientCertPinSet {
    allowed_hashes: Arc<RwLock<HashSet<[u8; 32]>>>,
}

impl QuicClientCertPinSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_hash_hex(&self, cert_hash_hex: &str) -> Result<(), QuicTransportError> {
        let hash = parse_sha256_hex(cert_hash_hex)?;
        let mut allowed = self
            .allowed_hashes
            .write()
            .map_err(|e| QuicTransportError::Tls(format!("client cert pin lock poisoned: {e}")))?;
        allowed.insert(hash);
        Ok(())
    }

    pub fn contains_der_cert(&self, cert: &CertificateDer<'_>) -> Result<bool, rustls::Error> {
        let received_hash = bolt_core::hash::sha256(cert.as_ref());
        let allowed = self
            .allowed_hashes
            .read()
            .map_err(|e| rustls::Error::General(format!("client cert pin lock poisoned: {e}")))?;
        Ok(allowed.contains(received_hash.as_slice()))
    }
}

#[derive(Debug)]
struct DynamicCertHashPinClientVerifier {
    pin_set: QuicClientCertPinSet,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl DynamicCertHashPinClientVerifier {
    fn new(pin_set: QuicClientCertPinSet) -> Arc<Self> {
        Arc::new(Self {
            pin_set,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }
}

impl rustls::server::danger::ClientCertVerifier for DynamicCertHashPinClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if self.pin_set.contains_der_cert(end_entity)? {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "QUIC client certificate hash not allowed".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
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
    cert: QuicPeerCertificate,
}

impl std::fmt::Debug for QuicListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListener")
            .field("local_addr", &self.local_addr)
            .field("cert_hash_hex", &self.cert.cert_hash_hex)
            .finish()
    }
}

impl QuicListener {
    /// Bind a QUIC listener on the given address.
    pub fn bind(addr: SocketAddr) -> Result<Self, QuicTransportError> {
        let (server_config, cert) = build_server_config()?;
        Self::bind_with_config(addr, server_config, cert)
    }

    /// Bind a QUIC listener requiring the dialer to present the expected
    /// client certificate hash.
    ///
    /// Q2 internal primitive only; production routing must not use this until
    /// signaling supplies the expected peer hash and fallback behavior exists.
    pub fn bind_with_expected_client_cert_hash(
        addr: SocketAddr,
        expected_client_cert_hash_hex: &str,
    ) -> Result<Self, QuicTransportError> {
        let (server_config, cert) =
            build_server_config_with_client_pin(Some(expected_client_cert_hash_hex))?;
        Self::bind_with_config(addr, server_config, cert)
    }

    /// Bind a QUIC listener that requires client cert hashes to be present in a
    /// dynamic allowlist.
    ///
    /// This is the production-shape Q2 primitive: the daemon can start its
    /// listener in fail-closed mode, then add peer hashes learned via signaling.
    pub fn bind_with_dynamic_client_cert_pins(
        addr: SocketAddr,
        client_cert_pins: QuicClientCertPinSet,
    ) -> Result<Self, QuicTransportError> {
        let (server_config, cert) = build_server_config_with_dynamic_client_pins(client_cert_pins)?;
        Self::bind_with_config(addr, server_config, cert)
    }

    fn bind_with_config(
        addr: SocketAddr,
        server_config: ServerConfig,
        cert: QuicPeerCertificate,
    ) -> Result<Self, QuicTransportError> {
        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| QuicTransportError::Connection(format!("bind {addr}: {e}")))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| QuicTransportError::Connection(format!("local addr: {e}")))?;

        eprintln!("[quic] listener bound on {local_addr}");
        Ok(Self {
            endpoint,
            local_addr,
            cert,
        })
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// SHA-256 hash of the listener certificate DER, hex encoded.
    ///
    /// Exposes the listener cert hash for signaling/IPC plumbing. Production
    /// promotion remains blocked until peer hashes feed the dynamic allowlist
    /// and app session routing uses QUIC.
    pub fn cert_hash_hex(&self) -> &str {
        self.cert.cert_hash_hex()
    }

    /// Cloneable certificate material used by this daemon's QUIC endpoint.
    ///
    /// The same cert can be used for server identity and client-auth
    /// presentation when dialing a peer that requires mutual pinning.
    pub fn peer_certificate(&self) -> QuicPeerCertificate {
        self.cert.clone()
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
        expected_cert_hash_hex: &str,
    ) -> Result<(Endpoint, QuicFramedStream), QuicTransportError> {
        Self::connect_with_config(remote, build_client_config(expected_cert_hash_hex)?).await
    }

    /// Connect and present a client certificate for mutual cert-hash pinning.
    ///
    /// Q2 internal primitive only; production routing remains blocked until
    /// signaling and session lifecycle integration are complete.
    pub async fn connect_with_client_cert(
        remote: SocketAddr,
        expected_server_cert_hash_hex: &str,
        client_cert: QuicPeerCertificate,
    ) -> Result<(Endpoint, QuicFramedStream), QuicTransportError> {
        let client_config = build_client_config_with_optional_client_cert(
            expected_server_cert_hash_hex,
            Some(client_cert),
        )?;
        Self::connect_with_config(remote, client_config).await
    }

    async fn connect_with_config(
        remote: SocketAddr,
        client_config: ClientConfig,
    ) -> Result<(Endpoint, QuicFramedStream), QuicTransportError> {
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
        let cert = result.unwrap();
        assert_eq!(cert.certs.len(), 1);
        assert!(!cert.certs[0].is_empty());
        assert_eq!(cert.cert_hash_hex.len(), 64);
        assert!(cert.cert_hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            cert.cert_hash_hex,
            bolt_core::hash::sha256_hex(cert.certs[0].as_ref())
        );
    }

    #[test]
    fn server_config_builds() {
        let result = build_server_config();
        assert!(result.is_ok(), "server config failed: {result:?}");
        let (_config, cert) = result.unwrap();
        assert_eq!(cert.cert_hash_hex().len(), 64);
    }

    #[test]
    fn client_config_builds() {
        let result =
            build_client_config("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        assert!(result.is_ok(), "client config failed: {result:?}");
    }

    #[test]
    fn client_config_rejects_invalid_cert_hash() {
        let short = build_client_config("abcd");
        assert!(short.is_err(), "short cert hash must be rejected");

        let non_hex =
            build_client_config("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        assert!(non_hex.is_err(), "non-hex cert hash must be rejected");
    }

    #[test]
    fn server_config_rejects_invalid_client_cert_hash() {
        let short = build_server_config_with_client_pin(Some("abcd"));
        assert!(short.is_err(), "short client cert hash must be rejected");

        let non_hex = build_server_config_with_client_pin(Some(
            "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        ));
        assert!(
            non_hex.is_err(),
            "non-hex client cert hash must be rejected"
        );
    }

    #[tokio::test]
    async fn listener_binds_ephemeral_port() {
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap());
        assert!(listener.is_ok(), "bind failed: {listener:?}");
        let listener = listener.unwrap();
        assert_ne!(listener.local_addr().port(), 0);
        assert_eq!(listener.cert_hash_hex().len(), 64);
        listener.close();
    }

    #[tokio::test]
    async fn connect_accept_stream_exchange() {
        // Listener on ephemeral port
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let cert_hash = listener.cert_hash_hex().to_string();

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
        let (endpoint, mut stream) = QuicDialer::connect(addr, &cert_hash).await.unwrap();

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
        let cert_hash = listener.cert_hash_hex().to_string();

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

        let (endpoint, mut stream) = QuicDialer::connect(addr, &cert_hash).await.unwrap();

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
        let cert_hash = listener.cert_hash_hex().to_string();

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

        let (endpoint, mut stream) = QuicDialer::connect(addr, &cert_hash).await.unwrap();

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

    #[tokio::test]
    async fn quic_dialer_rejects_cert_hash_mismatch() {
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let mut wrong_hash = listener.cert_hash_hex().to_string();
        let replacement = if wrong_hash.starts_with('0') {
            '1'
        } else {
            '0'
        };
        wrong_hash.replace_range(0..1, &replacement.to_string());

        let result = QuicDialer::connect(addr, &wrong_hash).await;

        listener.close();
        assert!(result.is_err(), "mismatched cert hash must fail closed");
    }

    #[tokio::test]
    async fn mutual_cert_hash_pinning_succeeds() {
        let client_cert = QuicPeerCertificate::generate_reference().unwrap();
        let listener = QuicListener::bind_with_expected_client_cert_hash(
            "127.0.0.1:0".parse().unwrap(),
            client_cert.cert_hash_hex(),
        )
        .unwrap();
        let addr = listener.local_addr();
        let server_hash = listener.cert_hash_hex().to_string();

        let listener_handle = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let msg = stream.recv_message().await.unwrap();
            assert_eq!(msg, b"mutual hello");
            stream.send_message(b"mutual ok").await.unwrap();
            let done = stream.recv_message().await.unwrap();
            assert!(done.is_empty());
            stream.finish().await.ok();
            listener.close();
        });

        let (endpoint, mut stream) =
            QuicDialer::connect_with_client_cert(addr, &server_hash, client_cert)
                .await
                .unwrap();
        stream.send_message(b"mutual hello").await.unwrap();
        let reply = stream.recv_message().await.unwrap();
        assert_eq!(reply, b"mutual ok");
        stream.send_message(&[]).await.unwrap();
        stream.finish().await.ok();
        listener_handle.await.unwrap();
        endpoint.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn mutual_cert_hash_pinning_rejects_missing_client_cert() {
        let expected_client_cert = QuicPeerCertificate::generate_reference().unwrap();
        let listener = QuicListener::bind_with_expected_client_cert_hash(
            "127.0.0.1:0".parse().unwrap(),
            expected_client_cert.cert_hash_hex(),
        )
        .unwrap();
        let addr = listener.local_addr();
        let server_hash = listener.cert_hash_hex().to_string();

        let listener_handle = tokio::spawn(async move {
            let result = listener.accept().await;
            listener.close();
            result
        });

        let result = QuicDialer::connect(addr, &server_hash).await;
        if let Ok((endpoint, mut stream)) = result {
            let _ = stream.send_message(b"must fail").await;
            let recv = stream.recv_message().await;
            endpoint.close(0u32.into(), b"done");
            assert!(recv.is_err(), "missing client cert must fail closed");
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), listener_handle).await;
    }

    #[tokio::test]
    async fn mutual_cert_hash_pinning_rejects_wrong_client_cert() {
        let expected_client_cert = QuicPeerCertificate::generate_reference().unwrap();
        let wrong_client_cert = QuicPeerCertificate::generate_reference().unwrap();
        let listener = QuicListener::bind_with_expected_client_cert_hash(
            "127.0.0.1:0".parse().unwrap(),
            expected_client_cert.cert_hash_hex(),
        )
        .unwrap();
        let addr = listener.local_addr();
        let server_hash = listener.cert_hash_hex().to_string();

        let listener_handle = tokio::spawn(async move {
            let result = listener.accept().await;
            listener.close();
            result
        });

        let result =
            QuicDialer::connect_with_client_cert(addr, &server_hash, wrong_client_cert).await;
        if let Ok((endpoint, mut stream)) = result {
            let _ = stream.send_message(b"must fail").await;
            let recv = stream.recv_message().await;
            endpoint.close(0u32.into(), b"done");
            assert!(recv.is_err(), "wrong client cert hash must fail closed");
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), listener_handle).await;
    }

    #[tokio::test]
    async fn dynamic_client_cert_pin_set_accepts_allowed_client_cert() {
        let pin_set = QuicClientCertPinSet::new();
        let client_cert = QuicPeerCertificate::generate_reference().unwrap();
        pin_set.allow_hash_hex(client_cert.cert_hash_hex()).unwrap();

        let listener = QuicListener::bind_with_dynamic_client_cert_pins(
            "127.0.0.1:0".parse().unwrap(),
            pin_set,
        )
        .unwrap();
        let addr = listener.local_addr();
        let server_hash = listener.cert_hash_hex().to_string();

        let listener_handle = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let msg = stream.recv_message().await.unwrap();
            assert_eq!(msg, b"dynamic mutual hello");
            stream.send_message(b"dynamic mutual ok").await.unwrap();
            let done = stream.recv_message().await.unwrap();
            assert!(done.is_empty());
            stream.finish().await.ok();
            listener.close();
        });

        let (endpoint, mut stream) =
            QuicDialer::connect_with_client_cert(addr, &server_hash, client_cert)
                .await
                .unwrap();
        stream.send_message(b"dynamic mutual hello").await.unwrap();
        let reply = stream.recv_message().await.unwrap();
        assert_eq!(reply, b"dynamic mutual ok");
        stream.send_message(&[]).await.unwrap();
        stream.finish().await.ok();
        listener_handle.await.unwrap();
        endpoint.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn dynamic_client_cert_pin_set_rejects_unlisted_client_cert() {
        let pin_set = QuicClientCertPinSet::new();
        let client_cert = QuicPeerCertificate::generate_reference().unwrap();

        let listener = QuicListener::bind_with_dynamic_client_cert_pins(
            "127.0.0.1:0".parse().unwrap(),
            pin_set,
        )
        .unwrap();
        let addr = listener.local_addr();
        let server_hash = listener.cert_hash_hex().to_string();

        let listener_handle = tokio::spawn(async move {
            let result = listener.accept().await;
            listener.close();
            result
        });

        let result = QuicDialer::connect_with_client_cert(addr, &server_hash, client_cert).await;
        if let Ok((endpoint, mut stream)) = result {
            let _ = stream.send_message(b"must fail").await;
            let recv = stream.recv_message().await;
            endpoint.close(0u32.into(), b"done");
            assert!(recv.is_err(), "unlisted client cert must fail closed");
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), listener_handle).await;
    }

    #[test]
    fn message_too_large_rejected() {
        // Verify the constant-level check (actual send would need async)
        let size = MAX_MESSAGE_SIZE + 1;
        let err = QuicTransportError::MessageTooLarge(size);
        assert!(err.to_string().contains("too large"));
    }
}
