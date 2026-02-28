//! Persistent identity key storage.
//!
//! Resolves, loads, or creates a long-lived X25519 identity keypair on disk.
//! The key file stores 64 raw bytes: `public_key (32) || secret_key (32)`.
//!
//! ## Security invariants
//! - Key file MUST be mode 0600. Too-permissive → abort.
//! - Parent directory MUST be mode 0700 (or stricter). Created if absent.
//! - Corrupted key file (wrong length) → abort, never regenerate.
//! - Secret key bytes are never logged.
//! - Temporary buffers are zeroized best-effort after use.
//!
//! ## Path resolution
//! 1. `BOLT_IDENTITY_PATH` env var (full path), or
//! 2. `$HOME/.bolt/identity.key`
//!
//! If neither `BOLT_IDENTITY_PATH` nor `HOME` is set → abort.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bolt_core::identity::IdentityKeyPair;

// ── Constants ───────────────────────────────────────────────

/// Expected key file length: 32-byte public key + 32-byte secret key.
const KEY_FILE_LEN: usize = 64;

/// Required file mode for the identity key file.
const KEY_FILE_MODE: u32 = 0o600;

/// Required directory mode for the parent directory when created.
const KEY_DIR_MODE: u32 = 0o700;

/// Maximum acceptable directory mode (owner-only permissions).
const KEY_DIR_MAX_MODE: u32 = 0o700;

/// Environment variable for custom identity path override.
const ENV_IDENTITY_PATH: &str = "BOLT_IDENTITY_PATH";

/// Default subdirectory under $HOME.
const DEFAULT_DIR_NAME: &str = ".bolt";

/// Default key file name.
const DEFAULT_FILE_NAME: &str = "identity.key";

// ── Error type ──────────────────────────────────────────────

/// Errors from identity key resolution, loading, or creation.
#[derive(Debug)]
pub enum IdentityStoreError {
    /// Neither BOLT_IDENTITY_PATH nor HOME is set.
    NoHomePath,
    /// Parent directory has too-permissive mode.
    DirTooPermissive { path: PathBuf, mode: u32 },
    /// Key file has wrong permissions (not 0600).
    FileTooPermissive { path: PathBuf, mode: u32 },
    /// Key file has unexpected size (corruption).
    CorruptKeyFile { path: PathBuf, actual_len: usize },
    /// Filesystem I/O error.
    Io(io::Error),
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHomePath => write!(
                f,
                "Cannot resolve identity path: neither {} nor HOME is set",
                ENV_IDENTITY_PATH
            ),
            Self::DirTooPermissive { path, mode } => write!(
                f,
                "Identity directory {:?} has mode {:04o}, expected {:04o} or stricter",
                path, mode, KEY_DIR_MAX_MODE
            ),
            Self::FileTooPermissive { path, mode } => write!(
                f,
                "Identity key file {:?} has mode {:04o}, expected {:04o}",
                path, mode, KEY_FILE_MODE
            ),
            Self::CorruptKeyFile { path, actual_len } => write!(
                f,
                "Identity key file {:?} has {} bytes, expected {} — refusing to start (possible corruption)",
                path, actual_len, KEY_FILE_LEN
            ),
            Self::Io(e) => write!(f, "Identity store I/O error: {}", e),
        }
    }
}

impl std::error::Error for IdentityStoreError {}

impl From<io::Error> for IdentityStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Public API ──────────────────────────────────────────────

/// Resolve the identity key file path.
///
/// Returns `BOLT_IDENTITY_PATH` if set, otherwise `$HOME/.bolt/identity.key`.
/// Returns error if neither variable is available.
pub fn resolve_identity_path() -> Result<PathBuf, IdentityStoreError> {
    if let Ok(custom) = std::env::var(ENV_IDENTITY_PATH) {
        if !custom.is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => {
            Ok(PathBuf::from(home).join(DEFAULT_DIR_NAME).join(DEFAULT_FILE_NAME))
        }
        _ => Err(IdentityStoreError::NoHomePath),
    }
}

/// Ensure the parent directory exists with secure permissions.
///
/// Creates it with mode 0700 if absent. If present, validates mode <= 0700.
pub fn ensure_parent_dir_secure(path: &Path) -> Result<(), IdentityStoreError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Err(IdentityStoreError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "identity key path has no parent directory",
        ))),
    };

    if parent.exists() {
        let meta = fs::metadata(parent)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & !KEY_DIR_MAX_MODE != 0 {
            return Err(IdentityStoreError::DirTooPermissive {
                path: parent.to_path_buf(),
                mode,
            });
        }
        Ok(())
    } else {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(KEY_DIR_MODE))?;
        eprintln!(
            "[IDENTITY] created directory {:?} (mode {:04o})",
            parent, KEY_DIR_MODE
        );
        Ok(())
    }
}

/// Validate that a key file has mode 0600.
pub fn validate_file_mode_0600(path: &Path) -> Result<(), IdentityStoreError> {
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != KEY_FILE_MODE {
        return Err(IdentityStoreError::FileTooPermissive {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Load an existing identity keypair or create a new one.
///
/// On load: validates file length (64 bytes) and mode (0600).
/// On create: generates keypair, writes atomically via temp file, sets 0600.
///
/// Fail-closed: corruption or permission violations are hard errors.
pub fn load_or_create_identity(path: &Path) -> Result<IdentityKeyPair, IdentityStoreError> {
    ensure_parent_dir_secure(path)?;

    if path.exists() {
        load_identity(path)
    } else {
        create_identity(path)
    }
}

// ── Internal helpers ────────────────────────────────────────

/// Load and validate an existing identity key file.
fn load_identity(path: &Path) -> Result<IdentityKeyPair, IdentityStoreError> {
    validate_file_mode_0600(path)?;

    let mut data = fs::read(path)?;
    if data.len() != KEY_FILE_LEN {
        let actual_len = data.len();
        // Zeroize buffer before returning error
        zeroize_buf(&mut data);
        return Err(IdentityStoreError::CorruptKeyFile {
            path: path.to_path_buf(),
            actual_len,
        });
    }

    let mut public_key = [0u8; 32];
    let mut secret_key = [0u8; 32];
    public_key.copy_from_slice(&data[..32]);
    secret_key.copy_from_slice(&data[32..64]);

    // Zeroize the read buffer
    zeroize_buf(&mut data);

    eprintln!("[IDENTITY] loaded persistent identity from {:?}", path);

    Ok(IdentityKeyPair { public_key, secret_key })
}

/// Generate a new identity keypair and write it atomically.
fn create_identity(path: &Path) -> Result<IdentityKeyPair, IdentityStoreError> {
    let kp = bolt_core::identity::generate_identity_keypair();

    // Build the 64-byte payload: public_key || secret_key
    let mut buf = [0u8; KEY_FILE_LEN];
    buf[..32].copy_from_slice(&kp.public_key);
    buf[32..64].copy_from_slice(&kp.secret_key);

    // Atomic write: temp file → set mode → rename
    let parent = path.parent().ok_or_else(|| {
        IdentityStoreError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "identity key path has no parent directory",
        ))
    })?;

    let tmp_name = format!(
        "{}.tmp.{}",
        DEFAULT_FILE_NAME,
        std::process::id()
    );
    let tmp_path = parent.join(&tmp_name);

    fs::write(&tmp_path, buf)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(KEY_FILE_MODE))?;
    fs::rename(&tmp_path, path)?;

    // Zeroize temp buffer
    zeroize_buf(&mut buf);

    // Validate final file mode
    validate_file_mode_0600(path)?;

    eprintln!("[IDENTITY] created new persistent identity at {:?}", path);

    Ok(kp)
}

/// Best-effort zeroization of a byte buffer.
fn zeroize_buf(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(byte as *mut u8, 0u8) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_uses_home() {
        // Save and restore
        let orig = std::env::var("BOLT_IDENTITY_PATH").ok();
        std::env::remove_var("BOLT_IDENTITY_PATH");

        let path = resolve_identity_path();
        // HOME should be set in test environment
        if let Ok(p) = path {
            assert!(p.to_string_lossy().ends_with(".bolt/identity.key"));
        }

        // Restore
        if let Some(v) = orig {
            std::env::set_var("BOLT_IDENTITY_PATH", v);
        }
    }

    #[test]
    fn resolve_path_uses_env_override() {
        let orig = std::env::var("BOLT_IDENTITY_PATH").ok();
        std::env::set_var("BOLT_IDENTITY_PATH", "/tmp/test-bolt-key");

        let path = resolve_identity_path();
        assert!(path.is_ok());
        assert_eq!(path.unwrap(), PathBuf::from("/tmp/test-bolt-key"));

        // Restore
        match orig {
            Some(v) => std::env::set_var("BOLT_IDENTITY_PATH", v),
            None => std::env::remove_var("BOLT_IDENTITY_PATH"),
        }
    }

    #[test]
    fn error_display_no_home() {
        let err = IdentityStoreError::NoHomePath;
        let msg = err.to_string();
        assert!(msg.contains("HOME"));
        assert!(msg.contains(ENV_IDENTITY_PATH));
    }

    #[test]
    fn error_display_corrupt() {
        let err = IdentityStoreError::CorruptKeyFile {
            path: PathBuf::from("/tmp/test"),
            actual_len: 32,
        };
        let msg = err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("64"));
        assert!(msg.contains("corruption"));
    }
}
