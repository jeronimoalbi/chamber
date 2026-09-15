use std::collections::HashMap;
use std::sync::Mutex;

use super::Backend;
use crate::error::Result;

/// In-memory backend.
#[derive(Default)]
pub struct MemoryBackend {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBackend {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for MemoryBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }

    fn keys(&self) -> Result<Vec<String>> {
        Ok(self.data.lock().unwrap().keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_backend_round_trips_and_reports_absence() {
        // Arrange
        let backend = MemoryBackend::new();

        // Act
        backend.set("alice", b"hello").unwrap();

        // Assert
        assert_eq!(backend.get("alice").unwrap().unwrap(), b"hello");
        assert!(backend.exists("alice").unwrap());
        assert_eq!(backend.get("ghost").unwrap(), None);
        assert!(!backend.exists("ghost").unwrap());
    }

    #[test]
    fn memory_backend_remove_is_a_no_op_when_absent() {
        // Act
        let backend = MemoryBackend::new();

        // Assert
        assert!(backend.remove("ghost").is_ok());
    }

    #[test]
    fn memory_backend_keys_reflects_set_and_remove() {
        // Arrange
        let backend = MemoryBackend::new();
        backend.set("alpha", b"a").unwrap();
        backend.set("zeta", b"z").unwrap();

        // Act
        backend.remove("alpha").unwrap();
        let keys = backend.keys().unwrap();

        // Assert
        assert_eq!(keys, vec!["zeta".to_string()]);
    }
}
