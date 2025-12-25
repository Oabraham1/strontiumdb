// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Transaction types and state management.

use crate::storage::{Key, Value};
use crate::time::Timestamp;

/// Unique transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxnId(pub u64);

/// Transaction isolation levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// Snapshot isolation - reads see consistent snapshot, write-write conflicts detected.
    #[default]
    Snapshot,
    /// Serializable - full isolation, read-write conflicts also detected.
    Serializable,
}

/// Transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnState {
    Active,
    Committed,
    Aborted,
}

/// A transaction handle.
///
/// Transactions buffer writes locally until commit, and track reads
/// for conflict detection (serializable isolation).
#[derive(Debug)]
pub struct Transaction {
    /// Unique identifier for this transaction.
    pub(crate) id: TxnId,
    /// Timestamp when transaction started (used for MVCC visibility).
    pub(crate) start_ts: Timestamp,
    /// Timestamp when transaction committed (set after commit).
    pub(crate) commit_ts: Option<Timestamp>,
    /// Current state of the transaction.
    pub(crate) state: TxnState,
    /// Isolation level for this transaction.
    pub(crate) isolation: IsolationLevel,
    /// Keys read during transaction (for serializable validation).
    pub(crate) read_set: Vec<(Key, Timestamp)>,
    /// Buffered writes (applied atomically on commit).
    pub(crate) write_set: Vec<(Key, Value)>,
}

impl Transaction {
    /// Creates a new transaction.
    pub(crate) fn new(id: TxnId, start_ts: Timestamp, isolation: IsolationLevel) -> Self {
        Self {
            id,
            start_ts,
            commit_ts: None,
            state: TxnState::Active,
            isolation,
            read_set: Vec::new(),
            write_set: Vec::new(),
        }
    }

    /// Returns the transaction ID.
    #[inline]
    pub fn id(&self) -> TxnId {
        self.id
    }

    /// Returns the start timestamp.
    #[inline]
    pub fn start_ts(&self) -> &Timestamp {
        &self.start_ts
    }

    /// Returns the commit timestamp (if committed).
    #[inline]
    pub fn commit_ts(&self) -> Option<&Timestamp> {
        self.commit_ts.as_ref()
    }

    /// Returns the current state.
    #[inline]
    pub fn state(&self) -> TxnState {
        self.state
    }

    /// Returns the isolation level.
    #[inline]
    pub fn isolation(&self) -> IsolationLevel {
        self.isolation
    }

    /// Returns true if the transaction is active.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.state == TxnState::Active
    }

    /// Returns true if the transaction is committed.
    #[inline]
    pub fn is_committed(&self) -> bool {
        self.state == TxnState::Committed
    }

    /// Returns true if the transaction is aborted.
    #[inline]
    pub fn is_aborted(&self) -> bool {
        self.state == TxnState::Aborted
    }

    /// Returns the number of writes buffered.
    #[inline]
    pub fn write_count(&self) -> usize {
        self.write_set.len()
    }

    /// Returns the number of reads tracked.
    #[inline]
    pub fn read_count(&self) -> usize {
        self.read_set.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txn_new() {
        let ts = Timestamp::new(100, 110);
        let txn = Transaction::new(TxnId(1), ts, IsolationLevel::Snapshot);

        assert_eq!(txn.id(), TxnId(1));
        assert_eq!(txn.start_ts().earliest(), 100);
        assert_eq!(txn.start_ts().latest(), 110);
        assert!(txn.commit_ts().is_none());
        assert_eq!(txn.state(), TxnState::Active);
        assert_eq!(txn.isolation(), IsolationLevel::Snapshot);
        assert!(txn.is_active());
        assert!(!txn.is_committed());
        assert!(!txn.is_aborted());
    }

    #[test]
    fn test_txn_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TxnId(1));
        set.insert(TxnId(2));
        assert!(set.contains(&TxnId(1)));
        assert!(!set.contains(&TxnId(3)));
    }
}
