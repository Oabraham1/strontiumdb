// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Transaction error types.

use crate::storage::{Key, StorageError};
use crate::time::Timestamp;

use super::TxnId;

/// Errors that can occur in transaction operations.
#[derive(Debug, thiserror::Error)]
pub enum TxnError {
    #[error("transaction aborted due to conflict with txn {winner:?}")]
    Aborted { winner: TxnId },

    #[error("transaction already committed")]
    AlreadyCommitted,

    #[error("transaction already aborted")]
    AlreadyAborted,

    #[error(
        "read uncertainty: cannot determine visibility for key {key:?} at version {version_ts:?}"
    )]
    ReadUncertainty { key: Key, version_ts: Timestamp },

    #[error("write conflict at key {key:?}")]
    WriteConflict { key: Key },

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("transaction wounded by older transaction")]
    Wounded,
}
