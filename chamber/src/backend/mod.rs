//! Storage backends for [`crate::store::Store`].

#[cfg(not(target_arch = "wasm32"))]
mod fs;
mod memory;

#[cfg(not(target_arch = "wasm32"))]
pub use fs::FsBackend;
pub use memory::MemoryBackend;

use crate::error::Result;

/// A flat key/value byte storage backend.
pub trait Backend: Send + Sync {
    /// Fetch the raw bytes stored under `key`, or `None` if absent.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Store `value` under `key`, creating or overwriting it.
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Remove `key` or no-op if it doesn't exist.
    fn remove(&self, key: &str) -> Result<()>;

    /// Return every key currently stored, in any order.
    fn keys(&self) -> Result<Vec<String>>;

    /// Check whether `key` exists.
    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }
}
