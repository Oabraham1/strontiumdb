// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! StrontiumDB: A globally-distributed SQL database with adaptive sub-microsecond clock synchronization for true external consistency
//!
//! This crate provides the core components for building a Spanner-class distributed
//! database with external consistency guarantees.

pub mod storage;
pub mod time;
pub mod txn;

pub use storage::{
    GcStats, Key, MvccEntry, MvccStore, ReadResult, RocksMvccStore, StorageError, Value,
};
pub use time::{
    create_time_service, ClockSource, HlcTimeService, TimeError, TimeService, TimeServiceConfig,
    Timestamp,
};
pub use txn::{
    IsolationLevel, Lock, LockMode, LockTable, SingleNodeTxnManager, Transaction,
    TransactionManager, TxnError, TxnId, TxnState, WoundWaitLockTable,
};
