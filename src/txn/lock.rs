// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Lock table trait and types.

use crate::storage::Key;
use crate::time::Timestamp;

use super::error::TxnError;
use super::TxnId;

/// Lock modes for read/write access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Shared lock for reads (multiple readers allowed).
    Shared,
    /// Exclusive lock for writes (single writer, no readers).
    Exclusive,
}

/// A lock held by a transaction.
#[derive(Debug, Clone)]
pub struct Lock {
    /// Transaction holding this lock.
    pub txn_id: TxnId,
    /// Lock mode (shared or exclusive).
    pub mode: LockMode,
    /// Key being locked.
    pub key: Key,
    /// Timestamp when lock was acquired.
    pub acquired_at: Timestamp,
}

/// Lock table interface for managing key locks.
///
/// Implementations should provide deadlock prevention/detection.
pub trait LockTable: Send + Sync {
    /// Attempts to acquire a lock on a key.
    ///
    /// # Arguments
    /// - `txn_id`: Transaction requesting the lock
    /// - `txn_ts`: Transaction's timestamp (used for wound-wait ordering)
    /// - `key`: Key to lock
    /// - `mode`: Lock mode (shared or exclusive)
    ///
    /// # Returns
    /// - `Ok(())` if lock acquired successfully
    /// - `Err(TxnError::Wounded)` if this transaction should abort (wound-wait)
    /// - `Err(TxnError::Aborted)` if blocked and older transaction wound us
    fn acquire(
        &self,
        txn_id: TxnId,
        txn_ts: &Timestamp,
        key: &Key,
        mode: LockMode,
    ) -> Result<(), TxnError>;

    /// Releases all locks held by a transaction.
    ///
    /// Called on commit or abort.
    fn release_all(&self, txn_id: TxnId);

    /// Gets the current lock holder for a key (if any).
    fn get_lock(&self, key: &Key) -> Option<Lock>;
}
