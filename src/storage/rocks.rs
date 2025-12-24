// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! RocksDB-backed MVCC storage implementation.

use std::path::Path;

use rocksdb::{DBWithThreadMode, IteratorMode, MultiThreaded, Options, WriteBatch, WriteOptions};

use crate::time::Timestamp;

use super::{
    decode_mvcc_key, encode_mvcc_key, extract_user_key, user_key_prefix, GcStats, Key,
    MvccEntry, MvccStore, ReadResult, StorageError, Value, MAX_KEY_SIZE, MAX_VALUE_SIZE,
};

/// Durability mode for write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DurabilityMode {
    /// Writes are synced to WAL but not fsynced to disk.
    /// Durable against process crashes but not power failures.
    /// This is the default mode, balancing performance and safety.
    #[default]
    WalOnly,
    /// Writes are fsynced to disk on every operation.
    /// Durable against power failures but slower (~20μs per write).
    FsyncEveryWrite,
}

/// RocksDB-backed MVCC storage.
///
/// Stores key-value pairs with uncertainty-interval timestamps.
/// Versions are ordered newest-first within each user key.
pub struct RocksMvccStore {
    db: DBWithThreadMode<MultiThreaded>,
    write_opts: WriteOptions,
    sync_write_opts: WriteOptions,
}

impl RocksMvccStore {
    /// Opens or creates a RocksDB database at the given path.
    ///
    /// Uses `DurabilityMode::WalOnly` by default (fast, durable against process crash).
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_durability(path, DurabilityMode::default())
    }

    /// Opens or creates a RocksDB database with specified durability mode.
    pub fn open_with_durability(path: &Path, durability: DurabilityMode) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        // Optimize for our workload
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(4);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_level_compaction_dynamic_level_bytes(true);

        // Enable bloom filters for point lookups
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&block_opts);

        // Enable prefix extraction for efficient prefix scans
        opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(4));

        let db = DBWithThreadMode::open(&opts, path)?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(durability == DurabilityMode::FsyncEveryWrite);

        let mut sync_write_opts = WriteOptions::default();
        sync_write_opts.set_sync(true);

        Ok(Self { db, write_opts, sync_write_opts })
    }

    /// Opens a database with custom RocksDB options.
    pub fn open_with_options(path: &Path, opts: Options, durability: DurabilityMode) -> Result<Self, StorageError> {
        let db = DBWithThreadMode::open(&opts, path)?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(durability == DurabilityMode::FsyncEveryWrite);

        let mut sync_write_opts = WriteOptions::default();
        sync_write_opts.set_sync(true);

        Ok(Self { db, write_opts, sync_write_opts })
    }

    /// Forces a sync/flush to disk.
    /// Call this after a batch of writes to ensure durability.
    pub fn sync(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        Ok(())
    }

    /// Writes a value with explicit fsync, regardless of durability mode.
    ///
    /// Use this for critical writes that must survive power failure,
    /// even when the store is opened with `DurabilityMode::WalOnly`.
    pub fn write_sync(&self, key: Key, value: Value, ts: Timestamp) -> Result<(), StorageError> {
        self.validate_key(&key)?;
        self.validate_value(&value)?;

        let encoded_key = encode_mvcc_key(&key, &ts);
        self.db.put_opt(&encoded_key, value.as_bytes(), &self.sync_write_opts)?;

        Ok(())
    }

    /// Atomically writes a batch with explicit fsync, regardless of durability mode.
    ///
    /// Use this for critical writes that must survive power failure.
    pub fn batch_write_sync(&self, entries: Vec<MvccEntry>) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        for entry in entries {
            self.validate_key(&entry.key)?;
            if let Some(ref value) = entry.value {
                self.validate_value(value)?;
            }

            let encoded_key = encode_mvcc_key(&entry.key, &entry.timestamp);
            match entry.value {
                Some(value) => batch.put(&encoded_key, value.as_bytes()),
                None => batch.put(&encoded_key, []),
            }
        }

        self.db.write_opt(batch, &self.sync_write_opts)?;
        Ok(())
    }

    /// Creates an in-memory database for testing.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let temp_dir = tempfile::tempdir()?;
        Self::open(temp_dir.path())
    }

    /// Validates key size.
    fn validate_key(&self, key: &Key) -> Result<(), StorageError> {
        if key.len() > MAX_KEY_SIZE {
            return Err(StorageError::KeyTooLarge {
                size: key.len(),
                max: MAX_KEY_SIZE,
            });
        }
        Ok(())
    }

    /// Validates value size.
    fn validate_value(&self, value: &Value) -> Result<(), StorageError> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(StorageError::ValueTooLarge {
                size: value.len(),
                max: MAX_VALUE_SIZE,
            });
        }
        Ok(())
    }

    /// Checks visibility of a version at a given read timestamp.
    ///
    /// Returns:
    /// - `Some(true)` if definitely visible
    /// - `Some(false)` if definitely NOT visible
    /// - `None` if uncertain (intervals overlap)
    #[inline]
    fn check_visibility(version_ts: &Timestamp, read_ts: &Timestamp) -> Option<bool> {
        // Definitely visible: version.latest < read.earliest
        if version_ts.definitely_before(read_ts) {
            return Some(true);
        }

        // Definitely NOT visible: version.earliest > read.latest
        if version_ts.definitely_after(read_ts) {
            return Some(false);
        }

        // Intervals overlap - uncertain
        None
    }
}

impl MvccStore for RocksMvccStore {
    fn read(&self, key: &Key, ts: &Timestamp) -> Result<ReadResult, StorageError> {
        self.validate_key(key)?;

        let prefix = user_key_prefix(key);
        let iter = self.db.prefix_iterator(&prefix);

        for item in iter {
            let (encoded_key, value) = item?;

            // Verify this is still our key
            let user_key = extract_user_key(&encoded_key)?;
            if user_key != key.as_bytes() {
                break;
            }

            let (_, version_ts) = decode_mvcc_key(&encoded_key)?;

            match Self::check_visibility(&version_ts, ts) {
                Some(true) => {
                    // Definitely visible
                    if value.is_empty() {
                        return Ok(ReadResult::NotFound); // Tombstone
                    }
                    return Ok(ReadResult::Found(Value::new(value.to_vec())));
                }
                Some(false) => {
                    // Definitely not visible, try older versions
                    continue;
                }
                None => {
                    // Uncertain - intervals overlap
                    return Ok(ReadResult::Uncertain { version_ts });
                }
            }
        }

        Ok(ReadResult::NotFound)
    }

    fn batch_read(
        &self,
        keys: &[Key],
        ts: &Timestamp,
    ) -> Result<Vec<(Key, ReadResult)>, StorageError> {
        let mut results = Vec::with_capacity(keys.len());

        for key in keys {
            let result = self.read(key, ts)?;
            results.push((key.clone(), result));
        }

        Ok(results)
    }

    fn write(&self, key: Key, value: Value, ts: Timestamp) -> Result<(), StorageError> {
        self.validate_key(&key)?;
        self.validate_value(&value)?;

        let encoded_key = encode_mvcc_key(&key, &ts);
        self.db.put_opt(&encoded_key, value.as_bytes(), &self.write_opts)?;

        Ok(())
    }

    fn delete(&self, key: Key, ts: Timestamp) -> Result<(), StorageError> {
        self.validate_key(&key)?;

        let encoded_key = encode_mvcc_key(&key, &ts);
        // Empty value = tombstone
        self.db.put_opt(&encoded_key, [], &self.write_opts)?;

        Ok(())
    }

    fn batch_write(&self, entries: Vec<MvccEntry>) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        for entry in entries {
            self.validate_key(&entry.key)?;
            if let Some(ref value) = entry.value {
                self.validate_value(value)?;
            }

            let encoded_key = encode_mvcc_key(&entry.key, &entry.timestamp);
            match entry.value {
                Some(value) => batch.put(&encoded_key, value.as_bytes()),
                None => batch.put(&encoded_key, []), // Tombstone
            }
        }

        self.db.write_opt(batch, &self.write_opts)?;
        Ok(())
    }

    fn scan(
        &self,
        start: &Key,
        end: &Key,
        ts: &Timestamp,
        limit: usize,
    ) -> Result<Vec<(Key, ReadResult)>, StorageError> {
        self.validate_key(start)?;
        self.validate_key(end)?;

        let mut results = Vec::with_capacity(limit.min(1000));
        let mut current_user_key: Option<Vec<u8>> = None;

        // Start from the first possible version of start key
        let start_encoded = user_key_prefix(start);
        let iter = self.db.iterator(IteratorMode::From(&start_encoded, rocksdb::Direction::Forward));

        for item in iter {
            if results.len() >= limit {
                break;
            }

            let (encoded_key, value) = item?;

            // Extract user key
            let user_key = extract_user_key(&encoded_key)?;

            // Check if we've passed the end key
            if user_key >= end.as_bytes() {
                break;
            }

            // Skip if we already found a result for this key
            if current_user_key.as_deref() == Some(user_key) {
                continue;
            }

            let (key, version_ts) = decode_mvcc_key(&encoded_key)?;

            match Self::check_visibility(&version_ts, ts) {
                Some(true) => {
                    // Definitely visible
                    current_user_key = Some(user_key.to_vec());

                    if value.is_empty() {
                        // Tombstone - skip this key entirely
                        continue;
                    }

                    results.push((key, ReadResult::Found(Value::new(value.to_vec()))));
                }
                Some(false) => {
                    // Not visible yet, try older versions
                    continue;
                }
                None => {
                    // Uncertain
                    current_user_key = Some(user_key.to_vec());
                    results.push((key, ReadResult::Uncertain { version_ts }));
                }
            }
        }

        Ok(results)
    }

    fn gc(&self, safe_time: &Timestamp) -> Result<GcStats, StorageError> {
        let mut stats = GcStats::default();
        let mut to_delete = Vec::new();
        let mut current_user_key: Option<Vec<u8>> = None;
        let mut kept_version_for_current_key = false;

        let iter = self.db.iterator(IteratorMode::Start);

        for item in iter {
            stats.versions_scanned += 1;

            let (encoded_key, value) = item?;
            let user_key = extract_user_key(&encoded_key)?;
            let (_, version_ts) = decode_mvcc_key(&encoded_key)?;

            // Check if this is a new user key
            let is_new_key = current_user_key.as_deref() != Some(user_key);

            if is_new_key {
                current_user_key = Some(user_key.to_vec());
                kept_version_for_current_key = false;
            }

            // Always keep at least one version per key
            if !kept_version_for_current_key {
                kept_version_for_current_key = true;
                continue;
            }

            // Delete if definitely before safe_time
            if version_ts.definitely_before(safe_time) {
                stats.bytes_reclaimed += encoded_key.len() as u64 + value.len() as u64;
                to_delete.push(encoded_key.to_vec());
            }
        }

        // Delete in batches
        for chunk in to_delete.chunks(1000) {
            let mut batch = WriteBatch::default();
            for key in chunk {
                batch.delete(key);
                stats.versions_deleted += 1;
            }
            self.db.write(batch)?;
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_store() -> (RocksMvccStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = RocksMvccStore::open(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn test_write_read_basic() {
        let (store, _dir) = create_test_store();

        let key = Key::from("hello");
        let value = Value::from("world");
        let ts = Timestamp::new(100, 200);

        store.write(key.clone(), value.clone(), ts).unwrap();

        // Read at time definitely after write
        let read_ts = Timestamp::new(300, 400);
        match store.read(&key, &read_ts).unwrap() {
            ReadResult::Found(v) => assert_eq!(v, value),
            other => panic!("expected Found, got {:?}", other),
        }
    }

    #[test]
    fn test_read_not_found() {
        let (store, _dir) = create_test_store();

        let key = Key::from("nonexistent");
        let ts = Timestamp::new(100, 200);

        match store.read(&key, &ts).unwrap() {
            ReadResult::NotFound => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_read_uncertain() {
        let (store, _dir) = create_test_store();

        let key = Key::from("key");
        let value = Value::from("value");
        let write_ts = Timestamp::new(100, 200);

        store.write(key.clone(), value, write_ts).unwrap();

        // Read at overlapping time: [150, 250] overlaps with [100, 200]
        let read_ts = Timestamp::new(150, 250);
        match store.read(&key, &read_ts).unwrap() {
            ReadResult::Uncertain { version_ts } => {
                assert_eq!(version_ts.earliest(), 100);
                assert_eq!(version_ts.latest(), 200);
            }
            other => panic!("expected Uncertain, got {:?}", other),
        }
    }

    #[test]
    fn test_read_definitely_not_visible() {
        let (store, _dir) = create_test_store();

        let key = Key::from("key");
        let value = Value::from("value");
        let write_ts = Timestamp::new(300, 400);

        store.write(key.clone(), value, write_ts).unwrap();

        // Read at time before write: [100, 200] is before [300, 400]
        let read_ts = Timestamp::new(100, 200);
        match store.read(&key, &read_ts).unwrap() {
            ReadResult::NotFound => {}
            other => panic!("expected NotFound (version not visible), got {:?}", other),
        }
    }

    #[test]
    fn test_multiple_versions() {
        let (store, _dir) = create_test_store();

        let key = Key::from("key");

        // Write three versions at different times
        store.write(key.clone(), Value::from("v1"), Timestamp::new(100, 110)).unwrap();
        store.write(key.clone(), Value::from("v2"), Timestamp::new(200, 210)).unwrap();
        store.write(key.clone(), Value::from("v3"), Timestamp::new(300, 310)).unwrap();

        // Read at different times - should see appropriate versions
        let read_150 = store.read(&key, &Timestamp::new(150, 160)).unwrap();
        assert!(matches!(read_150, ReadResult::Found(v) if v.as_bytes() == b"v1"));

        let read_250 = store.read(&key, &Timestamp::new(250, 260)).unwrap();
        assert!(matches!(read_250, ReadResult::Found(v) if v.as_bytes() == b"v2"));

        let read_350 = store.read(&key, &Timestamp::new(350, 360)).unwrap();
        assert!(matches!(read_350, ReadResult::Found(v) if v.as_bytes() == b"v3"));
    }

    #[test]
    fn test_tombstone() {
        let (store, _dir) = create_test_store();

        let key = Key::from("key");
        store.write(key.clone(), Value::from("value"), Timestamp::new(100, 110)).unwrap();
        store.delete(key.clone(), Timestamp::new(200, 210)).unwrap();

        // Read before delete sees value
        let read_150 = store.read(&key, &Timestamp::new(150, 160)).unwrap();
        assert!(matches!(read_150, ReadResult::Found(_)));

        // Read after delete sees nothing
        let read_250 = store.read(&key, &Timestamp::new(250, 260)).unwrap();
        assert!(matches!(read_250, ReadResult::NotFound));
    }

    #[test]
    fn test_batch_write() {
        let (store, _dir) = create_test_store();

        let ts = Timestamp::new(100, 200);
        let entries = vec![
            MvccEntry::new(Key::from("key1"), Value::from("value1"), ts),
            MvccEntry::new(Key::from("key2"), Value::from("value2"), ts),
            MvccEntry::tombstone(Key::from("key3"), ts),
        ];

        store.batch_write(entries).unwrap();

        let read_ts = Timestamp::new(300, 400);

        match store.read(&Key::from("key1"), &read_ts).unwrap() {
            ReadResult::Found(v) => assert_eq!(v.as_bytes(), b"value1"),
            other => panic!("expected Found, got {:?}", other),
        }

        match store.read(&Key::from("key2"), &read_ts).unwrap() {
            ReadResult::Found(v) => assert_eq!(v.as_bytes(), b"value2"),
            other => panic!("expected Found, got {:?}", other),
        }

        match store.read(&Key::from("key3"), &read_ts).unwrap() {
            ReadResult::NotFound => {}
            other => panic!("expected NotFound (tombstone), got {:?}", other),
        }
    }

    #[test]
    fn test_scan() {
        let (store, _dir) = create_test_store();

        let ts = Timestamp::new(100, 110);
        store.write(Key::from("aaa"), Value::from("1"), ts).unwrap();
        store.write(Key::from("bbb"), Value::from("2"), ts).unwrap();
        store.write(Key::from("ccc"), Value::from("3"), ts).unwrap();
        store.write(Key::from("ddd"), Value::from("4"), ts).unwrap();

        let read_ts = Timestamp::new(200, 210);

        // Scan [bbb, ddd) - should get bbb and ccc
        let results = store.scan(&Key::from("bbb"), &Key::from("ddd"), &read_ts, 100).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0.as_bytes(), b"bbb");
        assert_eq!(results[1].0.as_bytes(), b"ccc");
    }

    #[test]
    fn test_scan_with_limit() {
        let (store, _dir) = create_test_store();

        let ts = Timestamp::new(100, 110);
        for i in 0..10 {
            let key = Key::from(format!("key{:02}", i));
            store.write(key, Value::from("value"), ts).unwrap();
        }

        let read_ts = Timestamp::new(200, 210);
        let results = store.scan(&Key::from("key00"), &Key::from("key99"), &read_ts, 3).unwrap();

        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_gc_preserves_newest() {
        let (store, _dir) = create_test_store();

        let key = Key::from("key");

        // Write three versions
        store.write(key.clone(), Value::from("v1"), Timestamp::new(100, 110)).unwrap();
        store.write(key.clone(), Value::from("v2"), Timestamp::new(200, 210)).unwrap();
        store.write(key.clone(), Value::from("v3"), Timestamp::new(300, 310)).unwrap();

        // GC with safe_time that would delete all versions
        let safe_time = Timestamp::new(500, 510);
        let stats = store.gc(&safe_time).unwrap();

        // Should have deleted 2 versions (keeping newest)
        assert_eq!(stats.versions_deleted, 2);

        // Should still be able to read newest version
        let read_ts = Timestamp::new(400, 410);
        match store.read(&key, &read_ts).unwrap() {
            ReadResult::Found(v) => assert_eq!(v.as_bytes(), b"v3"),
            other => panic!("expected to find v3, got {:?}", other),
        }
    }

    #[test]
    fn test_gc_stats() {
        let (store, _dir) = create_test_store();

        // Write multiple versions of multiple keys
        for i in 0..5 {
            let key = Key::from(format!("key{}", i));
            store.write(key.clone(), Value::from("v1"), Timestamp::new(100, 110)).unwrap();
            store.write(key.clone(), Value::from("v2"), Timestamp::new(200, 210)).unwrap();
        }

        let safe_time = Timestamp::new(300, 310);
        let stats = store.gc(&safe_time).unwrap();

        assert_eq!(stats.versions_scanned, 10); // 5 keys * 2 versions
        assert_eq!(stats.versions_deleted, 5);  // 5 old versions (one per key)
    }

    #[test]
    fn test_key_too_large() {
        let (store, _dir) = create_test_store();

        let large_key = Key::new(vec![0u8; MAX_KEY_SIZE + 1]);
        let value = Value::from("value");
        let ts = Timestamp::new(100, 200);

        let result = store.write(large_key, value, ts);
        assert!(matches!(result, Err(StorageError::KeyTooLarge { .. })));
    }

    #[test]
    fn test_value_too_large() {
        let (store, _dir) = create_test_store();

        let key = Key::from("key");
        let large_value = Value::new(vec![0u8; MAX_VALUE_SIZE + 1]);
        let ts = Timestamp::new(100, 200);

        let result = store.write(key, large_value, ts);
        assert!(matches!(result, Err(StorageError::ValueTooLarge { .. })));
    }

    #[test]
    fn test_batch_read() {
        let (store, _dir) = create_test_store();

        let ts = Timestamp::new(100, 110);
        store.write(Key::from("key1"), Value::from("value1"), ts).unwrap();
        store.write(Key::from("key2"), Value::from("value2"), ts).unwrap();

        let read_ts = Timestamp::new(200, 210);
        let keys = vec![Key::from("key1"), Key::from("key2"), Key::from("key3")];
        let results = store.batch_read(&keys, &read_ts).unwrap();

        assert_eq!(results.len(), 3);
        assert!(matches!(&results[0].1, ReadResult::Found(v) if v.as_bytes() == b"value1"));
        assert!(matches!(&results[1].1, ReadResult::Found(v) if v.as_bytes() == b"value2"));
        assert!(matches!(&results[2].1, ReadResult::NotFound));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

    proptest! {
        #[test]
        fn read_sees_earlier_writes(
            value_bytes in prop::collection::vec(any::<u8>(), 1..100),
            write_time in 100u64..1000,
            gap in 100u64..1000,
        ) {
            let (store, _dir) = create_test_store();

            let key = Key::from("test");
            let value = Value::new(value_bytes.clone());
            let write_ts = Timestamp::new(write_time, write_time + 10);

            store.write(key.clone(), value, write_ts).unwrap();

            // Read definitely after write
            let read_ts = Timestamp::new(write_time + 10 + gap, write_time + 20 + gap);
            let result = store.read(&key, &read_ts).unwrap();

            match result {
                ReadResult::Found(v) => prop_assert_eq!(v.as_bytes(), &value_bytes),
                other => prop_assert!(false, "expected Found, got {:?}", other),
            }
        }

        #[test]
        fn read_doesnt_see_later_writes(
            write_time in 1000u64..10000,
            gap in 100u64..500,
        ) {
            let (store, _dir) = create_test_store();

            let key = Key::from("test");
            let value = Value::from("value");
            let write_ts = Timestamp::new(write_time, write_time + 10);

            store.write(key.clone(), value, write_ts).unwrap();

            // Read definitely before write (with safe subtraction)
            let read_end = write_time.saturating_sub(gap).saturating_sub(10);
            let read_start = read_end.saturating_sub(10);
            let read_ts = Timestamp::new(read_start, read_end);
            let result = store.read(&key, &read_ts).unwrap();

            prop_assert!(matches!(result, ReadResult::NotFound));
        }
    }

    fn create_test_store() -> (RocksMvccStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = RocksMvccStore::open(dir.path()).unwrap();
        (store, dir)
    }
}
