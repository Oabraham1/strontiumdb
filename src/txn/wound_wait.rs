// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Wound-wait deadlock prevention lock table.
//!
//! Wound-wait is a deadlock prevention scheme where:
//! - If requesting transaction is OLDER (lower timestamp): WOUND (abort) the holder
//! - If requesting transaction is YOUNGER (higher timestamp): WAIT for the holder
//!
//! This guarantees no deadlocks because older transactions always win.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use parking_lot::RwLock;

use crate::storage::Key;
use crate::time::Timestamp;

use super::error::TxnError;
use super::lock::{Lock, LockMode, LockTable};
use super::TxnId;

const NUM_SHARDS: usize = 256;

/// A lock entry in the lock table.
struct LockEntry {
    /// Transaction holding the lock.
    holder: TxnId,
    /// Holder's timestamp (for wound-wait comparison).
    holder_ts: Timestamp,
    /// Lock mode.
    mode: LockMode,
}

/// A shard of the lock table.
struct LockShard {
    locks: HashMap<Key, LockEntry>,
}

impl LockShard {
    fn new() -> Self {
        Self {
            locks: HashMap::new(),
        }
    }
}

/// Wound-wait lock table implementation.
///
/// Uses sharding to reduce contention. Each shard is protected by a RwLock.
pub struct WoundWaitLockTable {
    shards: [RwLock<LockShard>; NUM_SHARDS],
}

impl WoundWaitLockTable {
    /// Creates a new wound-wait lock table.
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(LockShard::new())),
        }
    }

    /// Computes the shard index for a key.
    #[inline]
    fn shard_index(&self, key: &Key) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize % NUM_SHARDS
    }
}

impl Default for WoundWaitLockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LockTable for WoundWaitLockTable {
    fn acquire(
        &self,
        txn_id: TxnId,
        txn_ts: &Timestamp,
        key: &Key,
        mode: LockMode,
    ) -> Result<(), TxnError> {
        let shard_idx = self.shard_index(key);
        let mut shard = self.shards[shard_idx].write();

        match shard.locks.get_mut(key) {
            None => {
                // No lock exists, acquire it
                shard.locks.insert(
                    key.clone(),
                    LockEntry {
                        holder: txn_id,
                        holder_ts: *txn_ts,
                        mode,
                    },
                );
                Ok(())
            }
            Some(entry) if entry.holder == txn_id => {
                // We already hold this lock
                // Upgrade shared -> exclusive if needed
                if mode == LockMode::Exclusive && entry.mode == LockMode::Shared {
                    entry.mode = LockMode::Exclusive;
                }
                Ok(())
            }
            Some(entry) => {
                // Lock held by another transaction - apply wound-wait rule
                // Compare timestamps: lower latest() = older = higher priority
                let we_are_older = txn_ts.latest() < entry.holder_ts.latest();

                if we_are_older {
                    // WOUND: We are older, take over the lock
                    // The wounded transaction will detect this on its next operation
                    entry.holder = txn_id;
                    entry.holder_ts = *txn_ts;
                    entry.mode = mode;
                    Ok(())
                } else {
                    // WAIT: We are younger
                    // Check for shared lock compatibility first
                    if mode == LockMode::Shared && entry.mode == LockMode::Shared {
                        // Shared locks are compatible, we can also hold it
                        // For simplicity, we don't track multiple shared holders
                        // Instead, we allow the read to proceed
                        return Ok(());
                    }

                    // We should wait, but the older transaction wounded us
                    Err(TxnError::Wounded)
                }
            }
        }
    }

    fn release_all(&self, txn_id: TxnId) {
        for shard in &self.shards {
            let mut shard = shard.write();
            shard.locks.retain(|_, entry| entry.holder != txn_id);
        }
    }

    fn get_lock(&self, key: &Key) -> Option<Lock> {
        let shard_idx = self.shard_index(key);
        let shard = self.shards[shard_idx].read();

        shard.locks.get(key).map(|entry| Lock {
            txn_id: entry.holder,
            mode: entry.mode,
            key: key.clone(),
            acquired_at: entry.holder_ts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_free_lock() {
        let table = WoundWaitLockTable::new();
        let key = Key::from("key");
        let ts = Timestamp::new(100, 110);

        let result = table.acquire(TxnId(1), &ts, &key, LockMode::Exclusive);
        assert!(result.is_ok());

        let lock = table.get_lock(&key).unwrap();
        assert_eq!(lock.txn_id, TxnId(1));
        assert_eq!(lock.mode, LockMode::Exclusive);
    }

    #[test]
    fn test_acquire_same_txn() {
        let table = WoundWaitLockTable::new();
        let key = Key::from("key");
        let ts = Timestamp::new(100, 110);

        table
            .acquire(TxnId(1), &ts, &key, LockMode::Shared)
            .unwrap();
        // Same transaction can reacquire
        table
            .acquire(TxnId(1), &ts, &key, LockMode::Shared)
            .unwrap();
        // Same transaction can upgrade
        table
            .acquire(TxnId(1), &ts, &key, LockMode::Exclusive)
            .unwrap();

        let lock = table.get_lock(&key).unwrap();
        assert_eq!(lock.mode, LockMode::Exclusive);
    }

    #[test]
    fn test_wound_wait_older_wins() {
        let table = WoundWaitLockTable::new();
        let key = Key::from("key");

        let old_ts = Timestamp::new(100, 110);
        let young_ts = Timestamp::new(200, 210);

        // Young transaction acquires lock first
        table
            .acquire(TxnId(2), &young_ts, &key, LockMode::Exclusive)
            .unwrap();

        // Old transaction should wound young and get lock
        table
            .acquire(TxnId(1), &old_ts, &key, LockMode::Exclusive)
            .unwrap();

        // Verify old transaction now holds lock
        let lock = table.get_lock(&key).unwrap();
        assert_eq!(lock.txn_id, TxnId(1));
    }

    #[test]
    fn test_wound_wait_younger_waits() {
        let table = WoundWaitLockTable::new();
        let key = Key::from("key");

        let old_ts = Timestamp::new(100, 110);
        let young_ts = Timestamp::new(200, 210);

        // Old transaction acquires lock first
        table
            .acquire(TxnId(1), &old_ts, &key, LockMode::Exclusive)
            .unwrap();

        // Young transaction should be wounded (told to wait/abort)
        let result = table.acquire(TxnId(2), &young_ts, &key, LockMode::Exclusive);
        assert!(matches!(result, Err(TxnError::Wounded)));

        // Old transaction still holds lock
        let lock = table.get_lock(&key).unwrap();
        assert_eq!(lock.txn_id, TxnId(1));
    }

    #[test]
    fn test_shared_locks_compatible() {
        let table = WoundWaitLockTable::new();
        let key = Key::from("key");

        let ts1 = Timestamp::new(100, 110);
        let ts2 = Timestamp::new(200, 210);

        // Both can acquire shared locks (even different timestamps)
        table
            .acquire(TxnId(1), &ts1, &key, LockMode::Shared)
            .unwrap();
        table
            .acquire(TxnId(2), &ts2, &key, LockMode::Shared)
            .unwrap();
    }

    #[test]
    fn test_release_all() {
        let table = WoundWaitLockTable::new();
        let key1 = Key::from("key1");
        let key2 = Key::from("key2");
        let ts = Timestamp::new(100, 110);

        table
            .acquire(TxnId(1), &ts, &key1, LockMode::Exclusive)
            .unwrap();
        table
            .acquire(TxnId(1), &ts, &key2, LockMode::Exclusive)
            .unwrap();

        assert!(table.get_lock(&key1).is_some());
        assert!(table.get_lock(&key2).is_some());

        table.release_all(TxnId(1));

        assert!(table.get_lock(&key1).is_none());
        assert!(table.get_lock(&key2).is_none());
    }
}
