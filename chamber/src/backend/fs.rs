use std::fs;
use std::path::{Path, PathBuf};

use super::Backend;
use crate::error::Result;

/// Backend that persists each key as `<dir>/<key>.json`.
///
/// Uses one entry per key plus a regenerable `index` cache entry.
///
/// ```text
/// <dir>/
///   <name>.json   # Key metadata file (encrypted key)
///   index.json    # Cache for list/lookup
/// ```
pub struct FsBackend {
    dir: PathBuf,
}

impl FsBackend {
    /// Open a backend rooted at `dir`, creating it if needed.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }
}

impl Backend for FsBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.path(key)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        fs::write(self.path(key), value)?;
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path(key).exists())
    }

    fn keys(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_backend_open_creates_missing_directory() {
        // Arrange
        let base = tempfile::tempdir().unwrap();
        let missing = base.path().join("nested/store");

        // Act
        FsBackend::open(&missing).unwrap();

        // Assert
        assert!(missing.is_dir());
    }

    #[test]
    fn fs_backend_open_is_idempotent_on_existing_directory() {
        //! Opening the same directory twice must not error or clobber
        //! anything already inside it.

        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let backend = FsBackend::open(dir.path()).unwrap();
        backend.set("alice", b"hello").unwrap();

        // Act
        let reopened = FsBackend::open(dir.path()).unwrap();

        // Assert
        assert_eq!(reopened.get("alice").unwrap().unwrap(), b"hello");
    }

    #[test]
    fn fs_backend_keys_ignores_stray_non_json_files() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let backend = FsBackend::open(dir.path()).unwrap();
        backend.set("alice", b"hello").unwrap();
        fs::write(dir.path().join("notes.txt"), b"not a record").unwrap();

        // Act
        let keys = backend.keys().unwrap();

        // Assert
        assert_eq!(keys, vec!["alice".to_string()]);
    }
}
