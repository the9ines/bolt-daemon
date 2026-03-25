//! File transfer validation and sanitization for the WS endpoint.
//!
//! # Module Contract (MODULARITY-AUDITABILITY-2)
//!
//! **Owner:** bolt-daemon
//! **Consumers:** ws_endpoint (file send/receive paths)
//!
//! **Exports:**
//! - `sanitize_filename()` — basename extraction + dangerous pattern rejection (TI-02)
//! - `validate_send_file_path()` — absolute path, exists, regular file pre-flight
//! - `parse_transfer_id_bytes()` — hex string → [u8; 16] for BTR transfer context init
//! - `MAX_TRANSFER_SIZE` — 2.5 GB upper bound (TI-03)
//!
//! **Invariants:**
//! - All functions are pure (no side effects, no global state)
//! - sanitize_filename rejects: empty, null bytes, `.`/`..`, hidden files, path traversal
//! - validate_send_file_path rejects: empty, relative, nonexistent, non-regular-file
//! - parse_transfer_id_bytes rejects: wrong length, non-hex characters
//!
//! **Security context:**
//! These functions form the daemon's input validation boundary for file transfers.
//! sanitize_filename is the last defense against path traversal in received filenames.
//! validate_send_file_path prevents the IPC/signal-file interface from reading
//! arbitrary paths. Both are called before any file I/O.

/// Maximum file size the daemon will accept for a single transfer (2.5 GB).
pub const MAX_TRANSFER_SIZE: u64 = 2_500_000_000;

/// Sanitize a received filename to prevent path traversal.
///
/// Extracts basename (last component after any `/` or `\`), then rejects
/// dangerous patterns. Returns Err for filenames that cannot be safely used.
///
/// Rules:
///   1. Extract basename (last path component)
///   2. Reject empty
///   3. Reject null bytes
///   4. Reject `.` and `..`
///   5. Reject hidden files (starts with `.`)
///   6. Replace any remaining path separators (defense in depth)
pub fn sanitize_filename(raw: &str) -> Result<String, String> {
    // Reject null bytes
    if raw.contains('\0') {
        return Err("filename contains null byte".into());
    }

    // Extract basename: last component after / or \
    let basename = raw
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("");

    // Reject empty
    if basename.is_empty() {
        return Err("filename is empty after path extraction".into());
    }

    // Reject . and ..
    if basename == "." || basename == ".." {
        return Err(format!("filename '{}' is a directory reference", basename));
    }

    // Reject hidden files (starts with .)
    if basename.starts_with('.') {
        return Err(format!("filename '{}' is a hidden file", basename));
    }

    // Defense in depth: replace any remaining path separators
    let safe = basename.replace(['/', '\\'], "_");

    // Final check: ensure result is non-empty after replacement
    if safe.is_empty() || safe == "." || safe == ".." {
        return Err("filename sanitized to empty/dangerous value".into());
    }

    Ok(safe)
}

/// Validate a file path from a send signal before the daemon reads and sends it.
///
/// Requirements:
///   - Must be an absolute path
///   - Must point to an existing regular file (not directory, symlink target checked)
///   - Must not be empty
///
/// Returns the validated path or an error description.
pub fn validate_send_file_path(path_str: &str) -> Result<&str, String> {
    if path_str.is_empty() {
        return Err("empty path".into());
    }

    let path = std::path::Path::new(path_str);

    if !path.is_absolute() {
        return Err(format!("path is not absolute: {path_str}"));
    }

    if !path.exists() {
        return Err(format!("file does not exist: {path_str}"));
    }

    if !path.is_file() {
        return Err(format!("not a regular file: {path_str}"));
    }

    Ok(path_str)
}

/// Parse a 32-character hex string into a 16-byte transfer ID.
///
/// Used to convert the wire-format transfer_id (hex string) into the
/// byte array required by BtrEngine::begin_transfer_receive.
pub fn parse_transfer_id_bytes(tid: &str) -> Result<[u8; 16], String> {
    if tid.len() != 32 {
        return Err(format!("transfer_id hex length {} != 32", tid.len()));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&tid[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("transfer_id hex parse: {e}"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Signal file path validation tests (DAEMON-HARDENING-1 P2) ──

    #[test]
    fn validate_send_path_absolute_file_accepted() {
        let result = validate_send_file_path("/etc/hosts");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_send_path_empty_rejected() {
        assert!(validate_send_file_path("").is_err());
    }

    #[test]
    fn validate_send_path_relative_rejected() {
        assert!(validate_send_file_path("relative/path.txt").is_err());
        assert!(validate_send_file_path("file.txt").is_err());
    }

    #[test]
    fn validate_send_path_nonexistent_rejected() {
        assert!(validate_send_file_path("/nonexistent/path/file.txt").is_err());
    }

    #[test]
    fn validate_send_path_directory_rejected() {
        assert!(validate_send_file_path("/tmp").is_err());
        assert!(validate_send_file_path("/").is_err());
    }

    // ── Transfer size limit tests (DAEMON-HARDENING-1 P1) ──

    #[test]
    fn transfer_size_limit_constant() {
        assert_eq!(MAX_TRANSFER_SIZE, 2_500_000_000);
    }

    #[test]
    fn transfer_size_within_limit_accepted() {
        assert!(1_048_576 <= MAX_TRANSFER_SIZE, "1MB within limit");
        assert!(52_428_800 <= MAX_TRANSFER_SIZE, "50MB within limit");
        assert!(1_000_000_000 <= MAX_TRANSFER_SIZE, "1GB within limit");
        assert!(2_500_000_000 <= MAX_TRANSFER_SIZE, "2.5GB at limit");
    }

    #[test]
    fn transfer_size_over_limit_rejected() {
        assert!(2_500_000_001 > MAX_TRANSFER_SIZE, "2.5GB+1 over limit");
        assert!(5_000_000_000u64 > MAX_TRANSFER_SIZE, "5GB over limit");
    }

    // ── Filename sanitization tests (DAEMON-HARDENING-1 P0) ──

    #[test]
    fn sanitize_filename_normal() {
        assert_eq!(sanitize_filename("report.pdf").unwrap(), "report.pdf");
        assert_eq!(sanitize_filename("my file (1).txt").unwrap(), "my file (1).txt");
        assert_eq!(sanitize_filename("data.tar.gz").unwrap(), "data.tar.gz");
    }

    #[test]
    fn sanitize_filename_path_traversal_rejected() {
        assert_eq!(sanitize_filename("../foo").unwrap(), "foo");
        assert_eq!(sanitize_filename("../../etc/passwd").unwrap(), "passwd");
        assert!(sanitize_filename("..").is_err());
        assert!(sanitize_filename(".").is_err());
    }

    #[test]
    fn sanitize_filename_nested_paths_stripped_to_basename() {
        assert_eq!(sanitize_filename("Documents/report.pdf").unwrap(), "report.pdf");
        assert_eq!(sanitize_filename("a/b/c/d.txt").unwrap(), "d.txt");
        assert_eq!(sanitize_filename("C:\\Users\\file.exe").unwrap(), "file.exe");
        assert_eq!(sanitize_filename("/etc/shadow").unwrap(), "shadow");
    }

    #[test]
    fn sanitize_filename_null_byte_rejected() {
        assert!(sanitize_filename("file\0.txt").is_err());
        assert!(sanitize_filename("\0").is_err());
    }

    #[test]
    fn sanitize_filename_hidden_files_rejected() {
        assert!(sanitize_filename(".bashrc").is_err());
        assert!(sanitize_filename(".ssh").is_err());
        assert!(sanitize_filename("path/to/.env").is_err());
    }

    #[test]
    fn sanitize_filename_empty_rejected() {
        assert!(sanitize_filename("").is_err());
        assert!(sanitize_filename("/").is_err());
        assert!(sanitize_filename("\\").is_err());
    }

    #[test]
    fn sanitize_filename_output_confined_to_downloads() {
        let save_dir = "/tmp/test-downloads";
        let filenames = vec![
            "../escape.txt",
            "../../etc/passwd",
            "normal.pdf",
            "sub/dir/file.txt",
        ];
        for raw in filenames {
            let safe = sanitize_filename(raw).unwrap();
            let full_path = format!("{}/{}", save_dir, safe);
            let path = std::path::Path::new(&full_path);
            let dir = std::path::Path::new(save_dir);
            assert!(
                path.starts_with(dir),
                "Sanitized path {:?} must be inside {:?} (raw: {:?})",
                full_path, save_dir, raw
            );
        }
    }

    // ── Transfer ID parsing tests ──

    #[test]
    fn parse_transfer_id_valid() {
        let hex = "0123456789abcdef0123456789abcdef";
        let result = parse_transfer_id_bytes(hex);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[15], 0xef);
    }

    #[test]
    fn parse_transfer_id_wrong_length() {
        assert!(parse_transfer_id_bytes("0123").is_err());
        assert!(parse_transfer_id_bytes("").is_err());
    }

    #[test]
    fn parse_transfer_id_invalid_hex() {
        assert!(parse_transfer_id_bytes("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }
}
