use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::{Backend, Record};
use crate::error::{Error, Result};

/// Name of the file used to store keys.
const KEYS_FILE: &str = "keys.json";

/// Name of the file coordinating writes between processes.
const LOCK_FILE: &str = "keys.json.lock";

/// Document stores all filesystem keys.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    keys: Vec<Record>,
}

/// Backend that persists every record of a store as one JSON file,
pub struct FsBackend {
    path: PathBuf,
    lock_path: PathBuf,
}

impl FsBackend {
    /// Open a backend rooted at `dir`, creating it if needed.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        restrict_keys_dir_access(dir)?;
        Ok(Self {
            path: dir.join(KEYS_FILE),
            lock_path: dir.join(LOCK_FILE),
        })
    }

    /// Create a lock file for exclusive modification of the keys file.
    /// Lock is released when the returned file is dropped.
    fn lock(&self) -> Result<File> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)?;
        file.lock()?;
        Ok(file)
    }

    fn read(&self) -> Result<Document> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::KeystoreFormat(format!("{}: {e}", self.path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Document::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, doc: &Document) -> Result<()> {
        let json = serde_json::to_vec_pretty(doc)?;
        let dir = self
            .path
            .parent()
            .expect("the keys file always has a parent directory");

        // Write document atomically to minimize file issues
        let mut tmp = NamedTempFile::new_in(dir)?;
        tmp.write_all(&json)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path).map_err(|e| Error::Io(e.error))?;
        Ok(())
    }
}

impl Backend for FsBackend {
    fn insert(&mut self, record: Record) -> Result<()> {
        let _lock = self.lock()?;
        let mut doc = self.read()?;
        if doc.keys.iter().any(|r| r.name == record.name) {
            return Err(Error::AlreadyExists(record.name));
        }

        doc.keys.push(record);
        self.write(&doc)
    }

    fn update(&mut self, record: Record) -> Result<()> {
        let _lock = self.lock()?;
        let mut doc = self.read()?;
        let key = doc
            .keys
            .iter_mut()
            .find(|r| r.name == record.name)
            .ok_or_else(|| Error::NotFound(record.name.clone()))?;
        *key = record;
        self.write(&doc)
    }

    fn get(&self, name: &str) -> Result<Option<Record>> {
        Ok(self.read()?.keys.into_iter().find(|r| r.name == name))
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut doc = self.read()?;
        let key_count = doc.keys.len();
        doc.keys.retain(|r| r.name != name);
        if doc.keys.len() == key_count {
            return Err(Error::NotFound(name.to_string()));
        }

        self.write(&doc)
    }

    fn list(&self) -> Result<Vec<Record>> {
        Ok(self.read()?.keys)
    }
}

#[cfg(unix)]
fn restrict_keys_dir_access(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_keys_dir_access(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn test_record(name: &str) -> Record {
        crate::backend::test_support::record(name)
    }

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
    #[cfg(unix)]
    fn fs_backend_open_restricts_directory_access() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("store");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        // Act
        FsBackend::open(&dir).unwrap();

        // Assert
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn fs_backend_open_is_idempotent_on_existing_directory() {
        //! Opening the same directory twice must not error or clobber
        //! anything already inside it.

        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();
        backend.insert(test_record("alice")).unwrap();

        // Act
        let reopened = FsBackend::open(dir.path()).unwrap();

        // Assert
        assert_eq!(
            reopened.get("alice").unwrap().unwrap().name,
            test_record("alice").name
        );
    }

    #[test]
    fn fs_backend_insert_rejects_duplicate_name() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();
        backend.insert(test_record("alice")).unwrap();

        // Act
        let err = backend.insert(test_record("alice")).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: alice");
    }

    #[test]
    fn fs_backend_update_replaces_existing_record() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();
        backend.insert(test_record("alice")).unwrap();

        let mut updated = test_record("alice");
        updated.address = "g1updated".to_string();

        // Act
        backend.update(updated).unwrap();

        // Assert
        assert_eq!(backend.get("alice").unwrap().unwrap().address, "g1updated");
    }

    #[test]
    fn fs_backend_update_not_found() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();

        // Act
        let err = backend.update(test_record("ghost")).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn fs_backend_remove_not_found() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();

        // Act
        let err = backend.remove("ghost").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn fs_backend_list_reflects_inserts_and_removes() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();
        backend.insert(test_record("alice")).unwrap();
        backend.insert(test_record("bob")).unwrap();

        // Act
        backend.remove("alice").unwrap();
        let names: Vec<String> = backend
            .list()
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();

        // Assert
        assert_eq!(names, vec!["bob".to_string()]);
    }

    #[test]
    fn fs_backend_list_rejects_corrupt_keys_file() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(KEYS_FILE), b"{ not json").unwrap();
        let backend = FsBackend::open(dir.path()).unwrap();

        // Act
        let err = backend.list().unwrap_err();

        // Assert
        assert!(err.to_string().starts_with("keystore format error:"));
    }

    #[test]
    fn fs_backend_writes_leave_no_stray_temp_file_behind() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let mut backend = FsBackend::open(dir.path()).unwrap();

        // Act
        backend.insert(test_record("alice")).unwrap();

        // Assert
        let mut entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![OsString::from(KEYS_FILE), OsString::from(LOCK_FILE)]
        );
    }

    #[test]
    fn concurrent_writers_do_not_lose_records() {
        //! Every mutation is a read-modify-write though a file lock, so multiple
        //! modifications to the keys file should succeed and not step on each other.

        use std::sync::Barrier;

        // Arrange
        let dir = tempfile::tempdir().unwrap();
        FsBackend::open(dir.path()).unwrap();

        let base = test_record("base");
        let create_record = |i: usize| {
            let mut record = base.clone();
            record.name = format!("key{i}");
            record
        };

        let barrier = &Barrier::new(2);
        let path = dir.path();

        // Act
        std::thread::scope(|scope| {
            for thread in 0..2 {
                let records: Vec<Record> = (0..5).map(|i| create_record(thread * 5 + i)).collect();

                // Start a thread that inserts 5 records
                scope.spawn(move || {
                    let mut backend = FsBackend::open(path).unwrap();

                    barrier.wait(); // Sync threads to start at the same time
                    for record in records {
                        backend.insert(record).unwrap();
                    }
                });
            }
        });

        // Assert
        let backend = FsBackend::open(dir.path()).unwrap();
        assert_eq!(backend.list().unwrap().len(), 10);
    }
}
