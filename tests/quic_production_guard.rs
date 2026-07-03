//! Static guard for the app-to-app QUIC production promotion blocker.
//!
//! Runtime tests prove mutual pinning succeeds and mismatches fail closed. This
//! guard prevents production QUIC source paths from reintroducing accept-any TLS
//! verification patterns while still allowing the pinned rustls verifier.

use std::path::Path;

fn read_source(repo: &Path, rel: &str) -> String {
    std::fs::read_to_string(repo.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

#[test]
fn app_to_app_quic_source_has_no_accept_any_tls_verifier() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let production_sources = [
        "src/quic_transport.rs",
        "src/session_loop.rs",
        "src/main.rs",
        "src/connect_signal.rs",
        "src/quic_endpoint_info.rs",
    ];

    let mut combined = String::new();
    for rel in production_sources {
        combined.push_str(&format!("\n// BEGIN {rel}\n"));
        combined.push_str(&read_source(repo, rel));
    }

    for forbidden in [
        "Rc3SkipVerification",
        "SkipServerVerification",
        "NoServerCertVerification",
        "NoCertificateVerification",
        "AcceptAny",
        "accept_any",
        "with_no_cert_validation",
    ] {
        assert!(
            !combined.contains(forbidden),
            "production app-to-app QUIC source must not contain accept-any verifier token {forbidden}"
        );
    }

    assert_eq!(
        count(&combined, "with_custom_certificate_verifier"),
        1,
        "production app-to-app QUIC should have exactly one custom verifier hook"
    );

    let quic_transport = read_source(repo, "src/quic_transport.rs");
    assert!(
        quic_transport.contains("with_custom_certificate_verifier(CertHashPinServerVerifier::new("),
        "the custom QUIC client verifier must be the cert-hash pin verifier"
    );
    assert!(
        quic_transport.contains("with_client_auth_cert("),
        "mutual QUIC production path must present a client certificate"
    );
    assert!(
        quic_transport.contains("with_client_cert_verifier("),
        "mutual QUIC production path must verify client certificates"
    );
}
