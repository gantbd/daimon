//! Bounded, durable owner-document transaction primitives.
//!
//! This crate owns filesystem mechanics only. Applications remain responsible
//! for parsing, validating, redacting, planning, confirming, and receipting
//! their domain documents.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentErrorV1 {
    Io,
    Invalid,
    Busy,
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    digest_value(Sha256::digest(bytes).into())
}

pub fn digest_value(bytes: [u8; 32]) -> String {
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub fn valid_operation_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn plan_digest(domain: &[u8], operation_id: &str, current: &str, candidate: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [
        domain,
        operation_id.as_bytes(),
        current.as_bytes(),
        candidate.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    digest_value(hasher.finalize().into())
}

pub fn read_bounded(path: &Path) -> Result<Vec<u8>, DocumentErrorV1> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DocumentErrorV1::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DOCUMENT_BYTES
    {
        return Err(DocumentErrorV1::Invalid);
    }
    let bytes = fs::read(path).map_err(|_| DocumentErrorV1::Io)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(DocumentErrorV1::Invalid);
    }
    Ok(bytes)
}

pub struct EditLockV1 {
    _file: File,
}

impl EditLockV1 {
    pub fn acquire(path: &Path, suffix: &str) -> Result<Self, DocumentErrorV1> {
        let lock_path = sibling_path(path, suffix)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)
            .map_err(|_| DocumentErrorV1::Io)?;
        file.try_lock().map_err(|_| DocumentErrorV1::Busy)?;
        Ok(Self { _file: file })
    }
}

pub fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), DocumentErrorV1> {
    let temporary_path = sibling_path(
        path,
        &format!(
            ".owner-document-{}-{}.tmp",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ),
    )?;
    let permissions = fs::metadata(path)
        .map_err(|_| DocumentErrorV1::Io)?
        .permissions()
        .mode();
    let result = (|| {
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(permissions)
            .open(&temporary_path)
            .map_err(|_| DocumentErrorV1::Io)?;
        temporary
            .write_all(bytes)
            .map_err(|_| DocumentErrorV1::Io)?;
        temporary.sync_all().map_err(|_| DocumentErrorV1::Io)?;
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(permissions))
            .map_err(|_| DocumentErrorV1::Io)?;
        fs::rename(&temporary_path, path).map_err(|_| DocumentErrorV1::Io)?;
        File::open(path.parent().ok_or(DocumentErrorV1::Invalid)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| DocumentErrorV1::Io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf, DocumentErrorV1> {
    let name = path.file_name().ok_or(DocumentErrorV1::Invalid)?;
    let mut sibling = OsString::from(name);
    sibling.push(suffix);
    Ok(path.with_file_name(sibling))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_and_identity_contracts_are_closed() {
        let digest = digest_bytes(b"owner document");
        assert!(valid_digest(&digest));
        assert!(!valid_digest("sha256:00"));
        assert!(valid_operation_id(&"11".repeat(16)));
        assert!(!valid_operation_id(&"11".repeat(15)));
        assert_ne!(
            plan_digest(b"domain-a", &"11".repeat(16), &digest, &digest),
            plan_digest(b"domain-b", &"11".repeat(16), &digest, &digest)
        );
    }

    #[test]
    fn lock_releases_and_atomic_replace_preserves_mode() {
        let root = std::env::temp_dir().join(format!(
            "daimon-owner-document-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("owner.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let lock = EditLockV1::acquire(&path, ".lock").unwrap();
        assert!(matches!(
            EditLockV1::acquire(&path, ".lock"),
            Err(DocumentErrorV1::Busy)
        ));
        drop(lock);
        let _reopened = EditLockV1::acquire(&path, ".lock").unwrap();
        atomic_replace(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        fs::remove_dir_all(root).unwrap();
    }
}
