// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! StrontiumDB: A globally-distributed SQL database with adaptive sub-microsecond clock synchronization for true external consistency
//!
//! This crate provides the core components for building a Spanner-class distributed
//! database with external consistency guarantees.

pub mod security;
pub mod storage;
pub mod time;
pub mod txn;

#[cfg(feature = "aws-kms")]
pub use security::AwsKms;
#[cfg(feature = "azure-kms")]
pub use security::AzureKms;
#[cfg(feature = "gcp-kms")]
pub use security::GcpKms;
pub use security::{
    create_tls_acceptor, create_tls_connector, DataEncryptionKey, EncryptedReader, EncryptedWriter,
    EncryptionProvider, KeyManagementService, LocalKms, SecurityError, TlsConfig, WrappedKey,
};
pub use storage::{
    EncryptedMvccStore, GcStats, Key, MvccEntry, MvccStore, ReadResult, RocksMvccStore,
    StorageError, Value,
};
pub use time::{
    create_time_service, ClockSource, HlcTimeService, TimeError, TimeService, TimeServiceConfig,
    Timestamp,
};
pub use txn::{
    IsolationLevel, Lock, LockMode, LockTable, SingleNodeTxnManager, Transaction,
    TransactionManager, TxnError, TxnId, TxnState, WoundWaitLockTable,
};
