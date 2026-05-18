//! QUIC endpoint metadata written for native shell discovery plumbing.
//!
//! This is Q2 scaffolding only: metadata publication does not make QUIC the
//! active app-to-app transport. WS client mode remains the production path
//! until mutual cert-hash pinning and routing integration are complete.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

pub const QUIC_INFO_FILE: &str = "quic_info.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicEndpointInfo {
    pub quic_port: u16,
    pub quic_cert_hash: String,
}

pub fn ws_endpoint_quic_port(ws_port: u16) -> Option<u16> {
    ws_port.checked_add(2)
}

pub fn write_quic_info(data_dir: &Path, info: &QuicEndpointInfo) -> io::Result<PathBuf> {
    let path = data_dir.join(QUIC_INFO_FILE);
    let json = serde_json::to_string(info).map_err(io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_endpoint_quic_port_is_ws_plus_two() {
        assert_eq!(ws_endpoint_quic_port(9100), Some(9102));
        assert_eq!(ws_endpoint_quic_port(u16::MAX - 1), None);
    }

    #[test]
    fn write_quic_info_writes_expected_json() {
        let dir = tempfile::tempdir().unwrap();
        let info = QuicEndpointInfo {
            quic_port: 9102,
            quic_cert_hash: "a".repeat(64),
        };

        let path = write_quic_info(dir.path(), &info).unwrap();
        assert_eq!(path.file_name().unwrap(), QUIC_INFO_FILE);

        let raw = std::fs::read_to_string(path).unwrap();
        let parsed: QuicEndpointInfo = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, info);
    }
}
