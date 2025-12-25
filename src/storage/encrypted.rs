// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Encrypted MVCC store wrapper.
//!
//! Provides transparent encryption for values stored in an underlying MvccStore.
//! Uses AES-256-GCM with per-range data encryption keys (DEKs).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    EncryptedMvccStore                   │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │            EncryptionProvider (DEK)             │   │
//! │  │              AES-256-GCM encrypt/decrypt        │   │
//! │  └─────────────────────────────────────────────────┘   │
//! │                          │                              │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │              Underlying MvccStore               │   │
//! │  │                  (RocksDB)                      │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;

use crate::security::{EncryptionProvider, SecurityError};
use crate::time::Timestamp;

use super::error::StorageError;
use super::mvcc::{GcStats, Key, MvccEntry, MvccStore, ReadResult, Value};

/// An encrypted wrapper around an MvccStore.
///
/// All values are transparently encrypted before being written to the
/// underlying store and decrypted when read. Keys and timestamps are
/// stored in plaintext to allow efficient range scans.
///
/// Each range can have its own EncryptionProvider with a unique DEK,
/// enabling per-tenant encryption isolation.
pub struct EncryptedMvccStore<S: MvccStore> {
    inner: S,
    provider: Arc<EncryptionProvider>,
}

impl<S: MvccStore> EncryptedMvccStore<S> {
    /// Creates a new encrypted store wrapping the given store.
    pub fn new(inner: S, provider: EncryptionProvider) -> Self {
        Self {
            inner,
            provider: Arc::new(provider),
        }
    }

    /// Returns the DEK ID used for encryption.
    pub fn dek_id(&self) -> &str {
        self.provider.dek_id()
    }

    /// Encrypts a value.
    fn encrypt_value(&self, value: &Value) -> Result<Value, StorageError> {
        let encrypted = self
            .provider
            .encrypt(value.as_bytes())
            .map_err(|e| StorageError::Corruption(format!("encryption failed: {}", e)))?;
        Ok(Value::new(encrypted))
    }

    /// Decrypts a value.
    fn decrypt_value(&self, value: &Value) -> Result<Value, StorageError> {
        let decrypted = self
            .provider
            .decrypt(value.as_bytes())
            .map_err(|e| StorageError::Corruption(format!("decryption failed: {}", e)))?;
        Ok(Value::new(decrypted))
    }

    /// Decrypts a ReadResult if it contains a value.
    fn decrypt_result(&self, result: ReadResult) -> Result<ReadResult, StorageError> {
        match result {
            ReadResult::Found(value) => {
                let decrypted = self.decrypt_value(&value)?;
                Ok(ReadResult::Found(decrypted))
            }
            other => Ok(other),
        }
    }
}

impl<S: MvccStore> MvccStore for EncryptedMvccStore<S> {
    fn read(&self, key: &Key, ts: &Timestamp) -> Result<ReadResult, StorageError> {
        let result = self.inner.read(key, ts)?;
        self.decrypt_result(result)
    }

    fn batch_read(
        &self,
        keys: &[Key],
        ts: &Timestamp,
    ) -> Result<Vec<(Key, ReadResult)>, StorageError> {
        let results = self.inner.batch_read(keys, ts)?;
        results
            .into_iter()
            .map(|(key, result)| {
                let decrypted = self.decrypt_result(result)?;
                Ok((key, decrypted))
            })
            .collect()
    }

    fn write(&self, key: Key, value: Value, ts: Timestamp) -> Result<(), StorageError> {
        let encrypted = self.encrypt_value(&value)?;
        self.inner.write(key, encrypted, ts)
    }

    fn delete(&self, key: Key, ts: Timestamp) -> Result<(), StorageError> {
        // Tombstones don't have values, so no encryption needed
        self.inner.delete(key, ts)
    }

    fn batch_write(&self, entries: Vec<MvccEntry>) -> Result<(), StorageError> {
        let encrypted_entries: Result<Vec<MvccEntry>, StorageError> = entries
            .into_iter()
            .map(|entry| {
                let encrypted_value = match entry.value {
                    Some(v) => Some(self.encrypt_value(&v)?),
                    None => None,
                };
                Ok(MvccEntry {
                    key: entry.key,
                    value: encrypted_value,
                    timestamp: entry.timestamp,
                })
            })
            .collect();

        self.inner.batch_write(encrypted_entries?)
    }

    fn scan(
        &self,
        start: &Key,
        end: &Key,
        ts: &Timestamp,
        limit: usize,
    ) -> Result<Vec<(Key, ReadResult)>, StorageError> {
        let results = self.inner.scan(start, end, ts, limit)?;
        results
            .into_iter()
            .map(|(key, result)| {
                let decrypted = self.decrypt_result(result)?;
                Ok((key, decrypted))
            })
            .collect()
    }

    fn gc(&self, safe_time: &Timestamp) -> Result<GcStats, StorageError> {
        // GC operates on encrypted data, no decryption needed
        self.inner.gc(safe_time)
    }
}

/// Error converting between security and storage errors.
impl From<SecurityError> for StorageError {
    fn from(err: SecurityError) -> Self {
        StorageError::Corruption(format!("security error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{KeyManagementService, LocalKms};
    use crate::storage::RocksMvccStore;
    use tempfile::TempDir;

    async fn create_test_store() -> (TempDir, EncryptedMvccStore<RocksMvccStore>) {
        let dir = TempDir::new().unwrap();
        let rocks = RocksMvccStore::open(dir.path()).unwrap();

        let kms = LocalKms::generate().unwrap();
        let dek = kms.generate_dek().await.unwrap();
        let provider = EncryptionProvider::new(dek);

        let encrypted = EncryptedMvccStore::new(rocks, provider);
        (dir, encrypted)
    }

    #[tokio::test]
    async fn test_write_read_encrypted() {
        let (_dir, store) = create_test_store().await;

        let key = Key::from("test-key");
        let value = Value::from("secret-data");
        let write_ts = Timestamp::new(100, 110);
        let read_ts = Timestamp::new(200, 210); // Definitely after write

        store.write(key.clone(), value.clone(), write_ts).unwrap();

        let result = store.read(&key, &read_ts).unwrap();
        match result {
            ReadResult::Found(v) => assert_eq!(v.as_bytes(), value.as_bytes()),
            _ => panic!("expected Found"),
        }
    }

    #[tokio::test]
    async fn test_batch_write_read() {
        let (_dir, store) = create_test_store().await;
        let write_ts = Timestamp::new(100, 110);
        let read_ts = Timestamp::new(200, 210);

        let entries = vec![
            MvccEntry::new(Key::from("key1"), Value::from("value1"), write_ts),
            MvccEntry::new(Key::from("key2"), Value::from("value2"), write_ts),
            MvccEntry::new(Key::from("key3"), Value::from("value3"), write_ts),
        ];

        store.batch_write(entries).unwrap();

        let keys = vec![Key::from("key1"), Key::from("key2"), Key::from("key3")];
        let results = store.batch_read(&keys, &read_ts).unwrap();

        assert_eq!(results.len(), 3);
        for (key, result) in results {
            match result {
                ReadResult::Found(v) => {
                    let expected = format!(
                        "value{}",
                        String::from_utf8_lossy(key.as_bytes())
                            .chars()
                            .last()
                            .unwrap()
                    );
                    assert_eq!(String::from_utf8_lossy(v.as_bytes()), expected);
                }
                _ => panic!("expected Found for {:?}", key),
            }
        }
    }

    #[tokio::test]
    async fn test_delete_creates_tombstone() {
        let (_dir, store) = create_test_store().await;

        let key = Key::from("delete-me");
        let value = Value::from("data");
        let ts1 = Timestamp::new(100, 110);
        let ts2 = Timestamp::new(200, 210);
        let ts3 = Timestamp::new(300, 310); // Read after delete

        store.write(key.clone(), value, ts1).unwrap();
        store.delete(key.clone(), ts2).unwrap();

        // Read at ts3 should see tombstone (NotFound)
        let result = store.read(&key, &ts3).unwrap();
        assert!(matches!(result, ReadResult::NotFound));
    }

    #[tokio::test]
    async fn test_scan_encrypted() {
        let (_dir, store) = create_test_store().await;
        let write_ts = Timestamp::new(100, 110);
        let read_ts = Timestamp::new(200, 210);

        for i in 0..5 {
            let key = Key::new(format!("scan-{:02}", i).into_bytes());
            let value = Value::new(format!("value-{}", i).into_bytes());
            store.write(key, value, write_ts).unwrap();
        }

        let start = Key::from("scan-00");
        let end = Key::from("scan-99");
        let results = store.scan(&start, &end, &read_ts, 10).unwrap();

        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn test_data_encrypted_at_rest() {
        let dir = TempDir::new().unwrap();
        let plaintext_value = b"super-secret-data-12345";
        let write_ts = Timestamp::new(100, 110);
        let read_ts = Timestamp::new(200, 210);

        // Write encrypted data
        {
            let rocks = RocksMvccStore::open(dir.path()).unwrap();
            let kms = LocalKms::generate().unwrap();
            let dek = kms.generate_dek().await.unwrap();
            let provider = EncryptionProvider::new(dek);
            let store = EncryptedMvccStore::new(rocks, provider);

            let key = Key::from("secret-key");
            let value = Value::from(plaintext_value.as_slice());
            store.write(key, value, write_ts).unwrap();
        }

        // Read raw RocksDB data - should NOT contain plaintext
        {
            let rocks = RocksMvccStore::open(dir.path()).unwrap();
            let key = Key::from("secret-key");

            let result = rocks.read(&key, &read_ts).unwrap();
            match result {
                ReadResult::Found(v) => {
                    // The stored value should be encrypted (different from plaintext)
                    assert_ne!(v.as_bytes(), plaintext_value);
                    // And longer due to nonce + tag
                    assert!(v.len() > plaintext_value.len());
                }
                _ => panic!("expected to find encrypted value"),
            }
        }
    }

    #[tokio::test]
    async fn test_different_deks_incompatible() {
        let dir = TempDir::new().unwrap();
        let write_ts = Timestamp::new(100, 110);
        let read_ts = Timestamp::new(200, 210);

        // Write with one DEK
        {
            let rocks = RocksMvccStore::open(dir.path()).unwrap();
            let kms = LocalKms::generate().unwrap();
            let dek = kms.generate_dek().await.unwrap();
            let provider = EncryptionProvider::new(dek);
            let store = EncryptedMvccStore::new(rocks, provider);

            let key = Key::from("key");
            let value = Value::from("value");
            store.write(key, value, write_ts).unwrap();
        }

        // Try to read with different DEK - should fail
        {
            let rocks = RocksMvccStore::open(dir.path()).unwrap();
            let kms = LocalKms::generate().unwrap();
            let different_dek = kms.generate_dek().await.unwrap();
            let provider = EncryptionProvider::new(different_dek);
            let store = EncryptedMvccStore::new(rocks, provider);

            let key = Key::from("key");

            let result = store.read(&key, &read_ts);
            assert!(result.is_err(), "decryption with wrong key should fail");
        }
    }
}
