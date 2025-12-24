// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! MVCC types and trait definitions.

use crate::time::Timestamp;

use super::error::StorageError;

/// Maximum key size in bytes.
pub const MAX_KEY_SIZE: usize = 8 * 1024; // 8KB

/// Maximum value size in bytes.
pub const MAX_VALUE_SIZE: usize = 64 * 1024 * 1024; // 64MB

/// A key in the MVCC store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key(pub Vec<u8>);

impl Key {
    /// Creates a new key from bytes.
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the key.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the key is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&[u8]> for Key {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<Vec<u8>> for Key {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<String> for Key {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A value in the MVCC store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value(pub Vec<u8>);

impl Value {
    /// Creates a new value from bytes.
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the value bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the value.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the value is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Value {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A versioned key-value entry.
#[derive(Debug, Clone)]
pub struct MvccEntry {
    pub key: Key,
    pub value: Option<Value>, // None = tombstone
    pub timestamp: Timestamp, // Interval timestamp
}

impl MvccEntry {
    /// Creates a new entry with a value.
    pub fn new(key: Key, value: Value, timestamp: Timestamp) -> Self {
        Self {
            key,
            value: Some(value),
            timestamp,
        }
    }

    /// Creates a tombstone entry (deletion marker).
    pub fn tombstone(key: Key, timestamp: Timestamp) -> Self {
        Self {
            key,
            value: None,
            timestamp,
        }
    }

    /// Returns true if this entry is a tombstone.
    #[inline]
    pub fn is_tombstone(&self) -> bool {
        self.value.is_none()
    }
}

/// Result of a read operation.
#[derive(Debug)]
pub enum ReadResult {
    /// Value definitely visible at read timestamp.
    Found(Value),
    /// No value exists for this key at read timestamp.
    NotFound,
    /// Cannot determine visibility - intervals overlap.
    Uncertain { version_ts: Timestamp },
}

/// Statistics from garbage collection.
#[derive(Debug, Default)]
pub struct GcStats {
    pub versions_scanned: u64,
    pub versions_deleted: u64,
    pub bytes_reclaimed: u64,
}

/// The MVCC storage engine trait.
///
/// Stores key-value pairs with uncertainty-interval timestamps.
/// Visibility is determined by comparing timestamp intervals:
/// - Definitely visible: `version.latest < read.earliest`
/// - Definitely NOT visible: `version.earliest > read.latest`
/// - Uncertain: intervals overlap
pub trait MvccStore: Send + Sync {
    /// Reads the value at key visible at the given timestamp.
    ///
    /// Returns:
    /// - `Found(value)` if a version is definitely visible
    /// - `NotFound` if no visible version exists (or tombstone)
    /// - `Uncertain` if visibility cannot be determined due to overlapping intervals
    fn read(&self, key: &Key, ts: &Timestamp) -> Result<ReadResult, StorageError>;

    /// Reads multiple keys at the same timestamp.
    fn batch_read(
        &self,
        keys: &[Key],
        ts: &Timestamp,
    ) -> Result<Vec<(Key, ReadResult)>, StorageError>;

    /// Writes a value at the given timestamp.
    fn write(&self, key: Key, value: Value, ts: Timestamp) -> Result<(), StorageError>;

    /// Writes a tombstone (deletion) at the given timestamp.
    fn delete(&self, key: Key, ts: Timestamp) -> Result<(), StorageError>;

    /// Atomically writes a batch of entries.
    fn batch_write(&self, entries: Vec<MvccEntry>) -> Result<(), StorageError>;

    /// Scans keys in range [start, end) visible at timestamp.
    fn scan(
        &self,
        start: &Key,
        end: &Key,
        ts: &Timestamp,
        limit: usize,
    ) -> Result<Vec<(Key, ReadResult)>, StorageError>;

    /// Runs garbage collection, removing versions older than safe_time.
    ///
    /// Preserves at least one version per key to maintain history.
    fn gc(&self, safe_time: &Timestamp) -> Result<GcStats, StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_from_bytes() {
        let key = Key::from(b"hello".as_slice());
        assert_eq!(key.as_bytes(), b"hello");
        assert_eq!(key.len(), 5);
    }

    #[test]
    fn test_key_from_str() {
        let key = Key::from("hello");
        assert_eq!(key.as_bytes(), b"hello");
    }

    #[test]
    fn test_value_from_bytes() {
        let value = Value::from(b"world".as_slice());
        assert_eq!(value.as_bytes(), b"world");
        assert_eq!(value.len(), 5);
    }

    #[test]
    fn test_mvcc_entry() {
        let key = Key::from("key");
        let value = Value::from("value");
        let ts = Timestamp::new(100, 200);

        let entry = MvccEntry::new(key.clone(), value, ts);
        assert!(!entry.is_tombstone());

        let tombstone = MvccEntry::tombstone(key, ts);
        assert!(tombstone.is_tombstone());
    }
}
