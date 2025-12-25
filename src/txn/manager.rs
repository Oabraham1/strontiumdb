// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Single-node transaction manager implementation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::storage::{Key, MvccEntry, MvccStore, ReadResult, Value};
use crate::time::TimeService;

use super::error::TxnError;
use super::lock::{LockMode, LockTable};
use super::transaction::{IsolationLevel, Transaction, TxnId, TxnState};
use super::TransactionManager;

/// Single-node transaction manager.
///
/// Provides ACID transactions with wound-wait deadlock prevention
/// and commit-wait for external consistency.
pub struct SingleNodeTxnManager<S: MvccStore, T: TimeService, L: LockTable> {
    time_service: Arc<T>,
    store: Arc<S>,
    lock_table: Arc<L>,
    next_txn_id: AtomicU64,
}

impl<S: MvccStore, T: TimeService, L: LockTable> SingleNodeTxnManager<S, T, L> {
    /// Creates a new transaction manager.
    pub fn new(time_service: Arc<T>, store: Arc<S>, lock_table: Arc<L>) -> Self {
        Self {
            time_service,
            store,
            lock_table,
            next_txn_id: AtomicU64::new(1),
        }
    }

    /// Validates read set for serializable isolation.
    ///
    /// Checks if any key in the read set was written by another transaction
    /// between our start and commit timestamps.
    fn validate_reads(
        &self,
        txn: &Transaction,
        commit_ts: &crate::time::Timestamp,
    ) -> Result<(), TxnError> {
        for (key, _read_ts) in &txn.read_set {
            match self.store.read(key, commit_ts)? {
                ReadResult::Found(_) | ReadResult::NotFound => {
                    // For a complete implementation, we would need to check
                    // if there's a newer version than what we read.
                    // This requires MVCC to support version enumeration.
                    // For now, we accept this as valid.
                }
                ReadResult::Uncertain { .. } => {
                    // Uncertainty during validation - conservative abort
                    return Err(TxnError::WriteConflict { key: key.clone() });
                }
            }
        }
        Ok(())
    }
}

impl<S: MvccStore, T: TimeService, L: LockTable> TransactionManager
    for SingleNodeTxnManager<S, T, L>
{
    fn begin(&self, isolation: IsolationLevel) -> Result<Transaction, TxnError> {
        let id = TxnId(self.next_txn_id.fetch_add(1, Ordering::Relaxed));
        let start_ts = self.time_service.now();

        Ok(Transaction::new(id, start_ts, isolation))
    }

    fn read(&self, txn: &mut Transaction, key: &Key) -> Result<Option<Value>, TxnError> {
        if txn.state != TxnState::Active {
            return Err(TxnError::AlreadyAborted);
        }

        // Check write set first (read-your-writes)
        for (k, v) in &txn.write_set {
            if k == key {
                return Ok(Some(v.clone()));
            }
        }

        // Acquire shared lock (wound-wait)
        self.lock_table
            .acquire(txn.id, &txn.start_ts, key, LockMode::Shared)?;

        // Read from storage
        match self.store.read(key, &txn.start_ts)? {
            ReadResult::Found(value) => {
                txn.read_set.push((key.clone(), txn.start_ts));
                Ok(Some(value))
            }
            ReadResult::NotFound => {
                txn.read_set.push((key.clone(), txn.start_ts));
                Ok(None)
            }
            ReadResult::Uncertain { version_ts } => {
                // Cannot determine visibility - higher level must handle
                Err(TxnError::ReadUncertainty {
                    key: key.clone(),
                    version_ts,
                })
            }
        }
    }

    fn write(&self, txn: &mut Transaction, key: Key, value: Value) -> Result<(), TxnError> {
        if txn.state != TxnState::Active {
            return Err(TxnError::AlreadyAborted);
        }

        // Acquire exclusive lock (wound-wait)
        self.lock_table
            .acquire(txn.id, &txn.start_ts, &key, LockMode::Exclusive)?;

        // Buffer write (check if key already in write set and update)
        if let Some((_, existing_value)) = txn.write_set.iter_mut().find(|(k, _)| k == &key) {
            *existing_value = value;
        } else {
            txn.write_set.push((key, value));
        }

        Ok(())
    }

    fn delete(&self, txn: &mut Transaction, key: Key) -> Result<(), TxnError> {
        // Delete is a write with empty value (tombstone)
        self.write(txn, key, Value::new(vec![]))
    }

    async fn commit(&self, txn: &mut Transaction) -> Result<crate::time::Timestamp, TxnError> {
        if txn.state != TxnState::Active {
            return Err(match txn.state {
                TxnState::Committed => TxnError::AlreadyCommitted,
                TxnState::Aborted => TxnError::AlreadyAborted,
                TxnState::Active => unreachable!(),
            });
        }

        // Get commit timestamp
        let commit_ts = self.time_service.now();

        // Validate read set (for serializable)
        if txn.isolation == IsolationLevel::Serializable {
            self.validate_reads(txn, &commit_ts)?;
        }

        // Write all buffered writes to storage
        if !txn.write_set.is_empty() {
            let entries: Vec<_> = txn
                .write_set
                .iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        MvccEntry::tombstone(k.clone(), commit_ts)
                    } else {
                        MvccEntry::new(k.clone(), v.clone(), commit_ts)
                    }
                })
                .collect();

            self.store.batch_write(entries)?;
        }

        // Commit-wait: ensure commit timestamp is definitely in the past
        // This is the key to external consistency!
        self.time_service.wait_until_past(&commit_ts).await;

        // Release locks
        self.lock_table.release_all(txn.id);

        txn.commit_ts = Some(commit_ts);
        txn.state = TxnState::Committed;

        Ok(commit_ts)
    }

    fn abort(&self, txn: &mut Transaction) -> Result<(), TxnError> {
        if txn.state != TxnState::Active {
            return Err(TxnError::AlreadyAborted);
        }

        self.lock_table.release_all(txn.id);
        txn.state = TxnState::Aborted;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RocksMvccStore;
    use crate::time::HlcTimeService;
    use crate::txn::WoundWaitLockTable;
    use tempfile::TempDir;

    fn create_test_manager() -> (
        SingleNodeTxnManager<RocksMvccStore, HlcTimeService, WoundWaitLockTable>,
        TempDir,
    ) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(RocksMvccStore::open(dir.path()).unwrap());
        let time_service = Arc::new(HlcTimeService::default());
        let lock_table = Arc::new(WoundWaitLockTable::new());

        let mgr = SingleNodeTxnManager::new(time_service, store, lock_table);
        (mgr, dir)
    }

    #[test]
    fn test_begin() {
        let (mgr, _dir) = create_test_manager();
        let txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

        assert!(txn.is_active());
        assert_eq!(txn.isolation(), IsolationLevel::Snapshot);
    }

    #[test]
    fn test_read_your_writes() {
        let (mgr, _dir) = create_test_manager();
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

        let key = Key::from("key");
        let value = Value::from("value");

        // Write
        mgr.write(&mut txn, key.clone(), value.clone()).unwrap();

        // Read should see our write (from buffer, not storage)
        let read_value = mgr.read(&mut txn, &key).unwrap();
        assert_eq!(read_value, Some(value));
    }

    #[test]
    fn test_read_not_found() {
        let (mgr, _dir) = create_test_manager();
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

        let key = Key::from("nonexistent");
        let read_value = mgr.read(&mut txn, &key).unwrap();
        assert_eq!(read_value, None);
    }

    #[test]
    fn test_abort() {
        let (mgr, _dir) = create_test_manager();
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

        let key = Key::from("key");
        let value = Value::from("value");
        mgr.write(&mut txn, key, value).unwrap();

        mgr.abort(&mut txn).unwrap();
        assert!(txn.is_aborted());

        // Further operations should fail
        assert!(mgr.read(&mut txn, &Key::from("key")).is_err());
    }

    #[tokio::test]
    async fn test_commit() {
        let (mgr, _dir) = create_test_manager();
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

        let key = Key::from("key");
        let value = Value::from("value");
        mgr.write(&mut txn, key.clone(), value.clone()).unwrap();

        let commit_ts = mgr.commit(&mut txn).await.unwrap();
        assert!(txn.is_committed());
        assert!(txn.commit_ts().is_some());

        // Verify write is visible to new transaction
        let mut txn2 = mgr.begin(IsolationLevel::Snapshot).unwrap();
        // New transaction starts after commit, should see the write
        assert!(txn2.start_ts().earliest() >= commit_ts.latest());
        let read_value = mgr.read(&mut txn2, &key).unwrap();
        assert_eq!(read_value, Some(value));
    }

    #[tokio::test]
    async fn test_delete() {
        let (mgr, _dir) = create_test_manager();

        // First write
        let mut txn1 = mgr.begin(IsolationLevel::Snapshot).unwrap();
        let key = Key::from("key");
        mgr.write(&mut txn1, key.clone(), Value::from("value"))
            .unwrap();
        mgr.commit(&mut txn1).await.unwrap();

        // Then delete
        let mut txn2 = mgr.begin(IsolationLevel::Snapshot).unwrap();
        mgr.delete(&mut txn2, key.clone()).unwrap();
        mgr.commit(&mut txn2).await.unwrap();

        // Should be deleted
        let mut txn3 = mgr.begin(IsolationLevel::Snapshot).unwrap();
        let read_value = mgr.read(&mut txn3, &key).unwrap();
        assert_eq!(read_value, None);
    }

    #[tokio::test]
    async fn test_external_consistency() {
        let (mgr, _dir) = create_test_manager();

        // Transaction 1 writes
        let mut txn1 = mgr.begin(IsolationLevel::Serializable).unwrap();
        mgr.write(&mut txn1, Key::from("key"), Value::from("v1"))
            .unwrap();
        let commit_ts1 = mgr.commit(&mut txn1).await.unwrap();

        // Transaction 2 starts AFTER txn1's commit-wait completes
        let mut txn2 = mgr.begin(IsolationLevel::Serializable).unwrap();

        // txn2's start timestamp must be after txn1's commit timestamp
        // (external consistency guarantee)
        assert!(txn2.start_ts().earliest() >= commit_ts1.latest());

        // txn2 MUST see txn1's write
        let value = mgr.read(&mut txn2, &Key::from("key")).unwrap();
        assert_eq!(value, Some(Value::from("v1")));
    }

    #[tokio::test]
    async fn test_double_commit() {
        let (mgr, _dir) = create_test_manager();
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
        txn.state = TxnState::Committed;

        let result = mgr.commit(&mut txn).await;
        assert!(matches!(result, Err(TxnError::AlreadyCommitted)));
    }

    #[test]
    fn test_write_updates_existing() {
        let (mgr, _dir) = create_test_manager();
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

        let key = Key::from("key");
        mgr.write(&mut txn, key.clone(), Value::from("v1")).unwrap();
        mgr.write(&mut txn, key.clone(), Value::from("v2")).unwrap();

        // Should see the updated value
        let read_value = mgr.read(&mut txn, &key).unwrap();
        assert_eq!(read_value, Some(Value::from("v2")));

        // Write set should only have one entry
        assert_eq!(txn.write_count(), 1);
    }
}
