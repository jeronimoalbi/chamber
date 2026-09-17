use std::collections::HashMap;

use super::{Backend, Record};
use crate::error::{Error, Result};

/// In-memory backend, keyed by record name.
#[derive(Default)]
pub struct MemoryBackend {
    records: HashMap<String, Record>,
}

impl MemoryBackend {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for MemoryBackend {
    fn insert(&mut self, record: Record) -> Result<()> {
        if self.records.contains_key(&record.name) {
            return Err(Error::AlreadyExists(record.name));
        }

        self.records.insert(record.name.clone(), record);
        Ok(())
    }

    fn update(&mut self, record: Record) -> Result<()> {
        if !self.records.contains_key(&record.name) {
            return Err(Error::NotFound(record.name));
        }

        self.records.insert(record.name.clone(), record);
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Record>> {
        Ok(self.records.get(name).cloned())
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        self.records
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| Error::NotFound(name.to_string()))
    }

    fn list(&self) -> Result<Vec<Record>> {
        Ok(self.records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record(name: &str) -> Record {
        crate::backend::test_support::record(name)
    }

    #[test]
    fn memory_backend_round_trips_and_reports_absence() {
        // Arrange
        let mut backend = MemoryBackend::new();

        // Act
        backend.insert(test_record("alice")).unwrap();

        // Assert
        assert_eq!(backend.get("alice").unwrap().unwrap().name, "alice");
        assert!(backend.get("ghost").unwrap().is_none());
    }

    #[test]
    fn memory_backend_insert_rejects_duplicate_name() {
        // Arrange
        let mut backend = MemoryBackend::new();
        backend.insert(test_record("alice")).unwrap();

        // Act
        let err = backend.insert(test_record("alice")).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: alice");
    }

    #[test]
    fn memory_backend_update_replaces_existing_record() {
        // Arrange
        let mut backend = MemoryBackend::new();
        backend.insert(test_record("alice")).unwrap();
        let mut updated = test_record("alice");
        updated.address = "g1updated".to_string();

        // Act
        backend.update(updated).unwrap();

        // Assert
        assert_eq!(backend.get("alice").unwrap().unwrap().address, "g1updated");
    }

    #[test]
    fn memory_backend_update_not_found() {
        // Arrange
        let mut backend = MemoryBackend::new();

        // Act
        let err = backend.update(test_record("ghost")).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn memory_backend_remove_not_found() {
        // Act
        let mut backend = MemoryBackend::new();

        // Assert
        let err = backend.remove("ghost").unwrap_err();
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn memory_backend_list_reflects_insert_and_remove() {
        // Arrange
        let mut backend = MemoryBackend::new();
        backend.insert(test_record("alpha")).unwrap();
        backend.insert(test_record("zeta")).unwrap();

        // Act
        backend.remove("alpha").unwrap();
        let names: Vec<String> = backend
            .list()
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();

        // Assert
        assert_eq!(names, vec!["zeta".to_string()]);
    }
}
