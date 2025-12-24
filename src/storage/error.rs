// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Storage error types.

use super::Key;

/// Errors that can occur in storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("key too large: {size} > {max}")]
    KeyTooLarge { size: usize, max: usize },

    #[error("value too large: {size} > {max}")]
    ValueTooLarge { size: usize, max: usize },

    #[error("write conflict at key {key:?}")]
    WriteConflict { key: Key },

    #[error("storage corruption: {0}")]
    Corruption(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("invalid key encoding: {0}")]
    InvalidKeyEncoding(String),
}
