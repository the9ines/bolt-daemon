//! SA1 Phase A — Identity store integration tests.
//!
//! Validates: persistence, idempotency, permission hardening, corruption fail-closed.
//! Uses temp directories — no "~" expansion.

#![cfg(feature = "test-support")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use bolt_daemon::test_support::{
    ensure_parent_dir_secure, load_or_create_identity, validate_file_mode_0600,
    IdentityStoreError,
};

// ── Helpers ─────────────────────────────────────────────────

/// Build a key file path inside a temp dir.
fn key_path_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join(".bolt").join("identity.key")
}

/// Extract error from Result<KeyPair, _>, panicking if Ok.
fn expect_err(
    result: Result<bolt_core::identity::IdentityKeyPair, IdentityStoreError>,
) -> IdentityStoreError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// ── Test 1: First run creates identity ──────────────────────

#[test]
fn first_run_creates_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    // Precondition: no file or parent dir
    assert!(!path.exists());

    let kp = load_or_create_identity(&path).unwrap();

    // File exists and is 64 bytes
    assert!(path.exists());
    let data = fs::read(&path).unwrap();
    assert_eq!(data.len(), 64, "key file must be exactly 64 bytes");

    // File contents match returned keypair
    assert_eq!(&data[..32], &kp.public_key);
    assert_eq!(&data[32..64], &kp.secret_key);

    // File mode is 0600
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "key file mode must be 0600");

    // Parent dir mode is 0700
    let parent = path.parent().unwrap();
    let dir_mode = fs::metadata(parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "parent dir mode must be 0700");
}

// ── Test 2: Second run loads same identity ──────────────────

#[test]
fn second_run_loads_same_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    let kp1 = load_or_create_identity(&path).unwrap();
    let kp2 = load_or_create_identity(&path).unwrap();

    assert_eq!(
        kp1.public_key, kp2.public_key,
        "public key must be stable across runs"
    );
    assert_eq!(
        kp1.secret_key, kp2.secret_key,
        "secret key must be stable across runs"
    );
}

// ── Test 3: Permission hardening (file mode != 0600) ────────

#[test]
fn rejects_too_permissive_file_mode_0644() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    // First create a valid identity
    let _kp = load_or_create_identity(&path).unwrap();

    // Weaken file permissions to 0644
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    // Must refuse to load
    let err = expect_err(load_or_create_identity(&path));
    match err {
        IdentityStoreError::FileTooPermissive { mode, .. } => {
            assert_eq!(mode, 0o644);
        }
        other => panic!("expected FileTooPermissive, got: {:?}", other),
    }
}

#[test]
fn rejects_too_permissive_file_mode_0666() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    let _kp = load_or_create_identity(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

    let err = expect_err(load_or_create_identity(&path));
    match err {
        IdentityStoreError::FileTooPermissive { mode, .. } => {
            assert_eq!(mode, 0o666);
        }
        other => panic!("expected FileTooPermissive, got: {:?}", other),
    }
}

// ── Test 4: Corruption hardening (wrong file size) ──────────

#[test]
fn rejects_corrupt_file_32_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    // Create valid identity first to get the directory
    let _kp = load_or_create_identity(&path).unwrap();

    // Overwrite with 32 bytes (half the expected size)
    fs::write(&path, &[0xABu8; 32]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let err = expect_err(load_or_create_identity(&path));
    match err {
        IdentityStoreError::CorruptKeyFile { actual_len, .. } => {
            assert_eq!(actual_len, 32);
        }
        other => panic!("expected CorruptKeyFile, got: {:?}", other),
    }
}

#[test]
fn rejects_corrupt_file_0_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    let _kp = load_or_create_identity(&path).unwrap();

    // Overwrite with 0 bytes
    fs::write(&path, &[]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let err = expect_err(load_or_create_identity(&path));
    match err {
        IdentityStoreError::CorruptKeyFile { actual_len, .. } => {
            assert_eq!(actual_len, 0);
        }
        other => panic!("expected CorruptKeyFile, got: {:?}", other),
    }
}

#[test]
fn rejects_corrupt_file_65_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    let _kp = load_or_create_identity(&path).unwrap();

    // Overwrite with 65 bytes (one too many)
    fs::write(&path, &[0xCDu8; 65]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let err = expect_err(load_or_create_identity(&path));
    match err {
        IdentityStoreError::CorruptKeyFile { actual_len, .. } => {
            assert_eq!(actual_len, 65);
        }
        other => panic!("expected CorruptKeyFile, got: {:?}", other),
    }
}

// ── Test 5: Corruption must NOT regenerate ──────────────────

#[test]
fn corrupt_file_does_not_regenerate() {
    let tmp = tempfile::tempdir().unwrap();
    let path = key_path_in(&tmp);

    let _kp_original = load_or_create_identity(&path).unwrap();

    // Corrupt the file
    fs::write(&path, &[0xFFu8; 32]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    // Must fail, NOT regenerate
    assert!(load_or_create_identity(&path).is_err());

    // File must still be the corrupt 32-byte version (untouched)
    let data = fs::read(&path).unwrap();
    assert_eq!(data.len(), 32, "corrupt file must not be replaced");
    assert_eq!(data, vec![0xFFu8; 32]);
}

// ── Test 6: Directory permission enforcement ────────────────

#[test]
fn rejects_too_permissive_parent_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let bolt_dir = tmp.path().join(".bolt");
    fs::create_dir_all(&bolt_dir).unwrap();
    fs::set_permissions(&bolt_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let path = bolt_dir.join("identity.key");

    let err = expect_err(load_or_create_identity(&path));
    match err {
        IdentityStoreError::DirTooPermissive { mode, .. } => {
            assert_eq!(mode, 0o755);
        }
        other => panic!("expected DirTooPermissive, got: {:?}", other),
    }
}

// ── Test 7: validate_file_mode_0600 standalone ──────────────

#[test]
fn validate_file_mode_accepts_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.key");
    fs::write(&path, &[0u8; 64]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(validate_file_mode_0600(&path).is_ok());
}

#[test]
fn validate_file_mode_rejects_0644() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.key");
    fs::write(&path, &[0u8; 64]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    assert!(validate_file_mode_0600(&path).is_err());
}

// ── Test 8: ensure_parent_dir_secure creates with 0700 ─────

#[test]
fn ensure_parent_dir_creates_with_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("newdir").join("identity.key");

    ensure_parent_dir_secure(&path).unwrap();

    let parent = path.parent().unwrap();
    assert!(parent.exists());
    let mode = fs::metadata(parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn ensure_parent_dir_accepts_existing_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("existing");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    let path = dir.join("identity.key");
    assert!(ensure_parent_dir_secure(&path).is_ok());
}
