// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Single-node transaction layer with wound-wait deadlock prevention.
//!
//! This module provides ACID transactions with:
//! - Wound-wait deadlock prevention (no deadlock detection needed)
//! - Commit-wait for external consistency
//! - Snapshot and serializable isolation levels
//!
//! # Key Concepts
//!
//! ## Wound-Wait Protocol
//!
//! Instead of detecting deadlocks, we prevent them using wound-wait:
//! - When a transaction requests a lock held by another:
//!   - If requester is OLDER (lower timestamp): it WOUNDS (aborts) the holder
//!   - If requester is YOUNGER (higher timestamp): it WAITS (is told to abort/retry)
//!
//! This guarantees no deadlocks because older transactions always win.
//!
//! ## Commit-Wait
//!
//! After writing to storage, we wait until the commit timestamp is definitely
//! in the past. This ensures external consistency: any transaction that starts
//! after our commit completes will see our writes.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use strontiumdb::storage::{Key, Value, RocksMvccStore};
//! use strontiumdb::time::HlcTimeService;
//! use strontiumdb::txn::{
//!     IsolationLevel, SingleNodeTxnManager, TransactionManager, WoundWaitLockTable,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Set up components
//! let store = Arc::new(RocksMvccStore::open(std::path::Path::new("/tmp/txn"))?);
//! let time_service = Arc::new(HlcTimeService::default());
//! let lock_table = Arc::new(WoundWaitLockTable::new());
//!
//! let mgr = SingleNodeTxnManager::new(time_service, store, lock_table);
//!
//! // Begin transaction
//! let mut txn = mgr.begin(IsolationLevel::Snapshot)?;
//!
//! // Read and write
//! let value = mgr.read(&mut txn, &Key::from("counter"))?;
//! let new_value = value.map_or(1, |v| {
//!     String::from_utf8_lossy(v.as_bytes()).parse::<i64>().unwrap_or(0) + 1
//! });
//! mgr.write(&mut txn, Key::from("counter"), Value::from(new_value.to_string().as_str()))?;
//!
//! // Commit with external consistency
//! let commit_ts = mgr.commit(&mut txn).await?;
//! println!("Committed at {:?}", commit_ts);
//! # Ok(())
//! # }
//! ```

mod error;
mod lock;
mod manager;
mod transaction;
mod wound_wait;

pub use error::TxnError;
pub use lock::{Lock, LockMode, LockTable};
pub use manager::SingleNodeTxnManager;
pub use transaction::{IsolationLevel, Transaction, TxnId, TxnState};
pub use wound_wait::WoundWaitLockTable;

use std::future::Future;

use crate::storage::{Key, Value};
use crate::time::Timestamp;

/// Transaction manager trait.
///
/// Provides methods to begin, read, write, commit, and abort transactions.
pub trait TransactionManager: Send + Sync {
    /// Begins a new transaction.
    fn begin(&self, isolation: IsolationLevel) -> Result<Transaction, TxnError>;

    /// Reads a key within the transaction.
    ///
    /// Returns the value if found, None if not found.
    /// Returns an error if there's a lock conflict or read uncertainty.
    fn read(&self, txn: &mut Transaction, key: &Key) -> Result<Option<Value>, TxnError>;

    /// Writes a key within the transaction.
    ///
    /// Writes are buffered until commit.
    fn write(&self, txn: &mut Transaction, key: Key, value: Value) -> Result<(), TxnError>;

    /// Deletes a key within the transaction.
    ///
    /// Implemented as a write with a tombstone value.
    fn delete(&self, txn: &mut Transaction, key: Key) -> Result<(), TxnError>;

    /// Commits the transaction.
    ///
    /// Writes buffered data to storage and performs commit-wait for external consistency.
    fn commit(
        &self,
        txn: &mut Transaction,
    ) -> impl Future<Output = Result<Timestamp, TxnError>> + Send;

    /// Aborts the transaction.
    ///
    /// Releases all locks and discards buffered writes.
    fn abort(&self, txn: &mut Transaction) -> Result<(), TxnError>;
}
