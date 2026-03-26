//! Ephemeral TLS certificate generation for WebTransport (SECURE-DIRECT-1, SD1).
//!
//! # Module Contract
//!
//! **Owner:** bolt-daemon
//! **Consumers:** main.rs (WsEndpoint mode startup)
//!
//! **Exports:**
//! - `EphemeralCert` — generated cert + key + hash, with PEM temp file paths
//! - `generate_ephemeral_cert()` — create a short-lived self-signed cert
//!
//! **Responsibilities:**
//! - Generate a self-signed TLS cert suitable for browser `serverCertificateHashes`
//! - Compute SHA-256 hash of the DER-encoded cert (for signaling advertisement)
//! - Write PEM files to a temp directory (for wtransport Identity loading)
//!
//! **Constraints:**
//! - Cert lifetime ≤14 days (browser requirement for cert-hash pinning)
//! - Cert is ephemeral — regenerated every daemon startup, never persisted
//! - SAN includes localhost + 127.0.0.1 + LAN IP (if resolvable)
//!
//! **Log tokens:**
//!   [WT_CERT] — cert generation events

use std::path::PathBuf;

/// An ephemeral self-signed TLS cert with its SHA-256 hash.
pub struct EphemeralCert {
    /// SHA-256 hash of the DER-encoded certificate, hex-encoded.
    pub cert_hash_hex: String,
    /// Path to the PEM-encoded certificate file.
    pub cert_pem_path: PathBuf,
    /// Path to the PEM-encoded private key file.
    pub key_pem_path: PathBuf,
    /// Temp directory holding the PEM files. Dropped when EphemeralCert is dropped.
    _tmp_dir: tempfile::TempDir,
}

/// Generate a short-lived self-signed TLS certificate for WebTransport.
///
/// The cert is valid for 13 days (under the 14-day browser limit for
/// `serverCertificateHashes`). SAN entries include localhost, 127.0.0.1,
/// and optionally the LAN IP.
///
/// Returns the cert hash (for signaling) and PEM file paths (for wtransport).
pub fn generate_ephemeral_cert() -> Result<EphemeralCert, String> {
    // Determine SAN entries: always localhost + 127.0.0.1, plus LAN IP if available
    let mut san_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if let Some(lan_ip) = detect_lan_ip() {
        if lan_ip != "127.0.0.1" {
            san_names.push(lan_ip.clone());
            eprintln!("[WT_CERT] SAN includes LAN IP: {lan_ip}");
        }
    }

    // Generate key pair and self-signed cert
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| format!("[WT_CERT] key generation failed: {e}"))?;

    let mut params = rcgen::CertificateParams::new(san_names)
        .map_err(|e| format!("[WT_CERT] cert params failed: {e}"))?;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(13);

    let cert = params.self_signed(&key_pair)
        .map_err(|e| format!("[WT_CERT] self-signed cert generation failed: {e}"))?;

    // Compute SHA-256 hash of DER-encoded cert
    let cert_der = cert.der().to_vec();
    let cert_hash = bolt_core::hash::sha256(&cert_der);
    let cert_hash_hex: String = cert_hash.iter().map(|b| format!("{b:02x}")).collect();

    // Write PEM to temp files
    let tmp_dir = tempfile::tempdir()
        .map_err(|e| format!("[WT_CERT] temp dir creation failed: {e}"))?;
    let cert_pem_path = tmp_dir.path().join("wt-cert.pem");
    let key_pem_path = tmp_dir.path().join("wt-key.pem");

    std::fs::write(&cert_pem_path, cert.pem())
        .map_err(|e| format!("[WT_CERT] failed to write cert PEM: {e}"))?;
    std::fs::write(&key_pem_path, key_pair.serialize_pem())
        .map_err(|e| format!("[WT_CERT] failed to write key PEM: {e}"))?;

    eprintln!("[WT_CERT] generated ephemeral cert (13 day, hash={cert_hash_hex})");

    Ok(EphemeralCert {
        cert_hash_hex,
        cert_pem_path,
        key_pem_path,
        _tmp_dir: tmp_dir,
    })
}

/// Detect the local LAN IP by connecting to a remote address (doesn't send data).
fn detect_lan_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ephemeral_cert_produces_valid_output() {
        let cert = generate_ephemeral_cert().expect("cert generation must succeed");

        // Hash is 64 hex chars (32 bytes SHA-256)
        assert_eq!(cert.cert_hash_hex.len(), 64, "cert hash must be 64 hex chars");
        assert!(cert.cert_hash_hex.chars().all(|c| c.is_ascii_hexdigit()));

        // PEM files exist
        assert!(cert.cert_pem_path.exists(), "cert PEM must exist");
        assert!(cert.key_pem_path.exists(), "key PEM must exist");

        // PEM files have content
        let cert_pem = std::fs::read_to_string(&cert.cert_pem_path).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        let key_pem = std::fs::read_to_string(&cert.key_pem_path).unwrap();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn each_generation_produces_unique_hash() {
        let cert1 = generate_ephemeral_cert().unwrap();
        let cert2 = generate_ephemeral_cert().unwrap();
        assert_ne!(cert1.cert_hash_hex, cert2.cert_hash_hex,
            "each generation must produce a unique cert/hash");
    }
}
