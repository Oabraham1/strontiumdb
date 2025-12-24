// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! StrontiumDB: A globally-distributed SQL database with adaptive sub-microsecond clock synchronization for true external consistency
//!
//! This crate provides the core components for building a Spanner-class distributed
//! database with external consistency guarantees.

pub mod storage;
pub mod time;

pub use storage::{
    GcStats, Key, MvccEntry, MvccStore, ReadResult, RocksMvccStore, StorageError, Value,
};
pub use time::{
    create_time_service, ClockSource, TimeError, TimeService, TimeServiceConfig, Timestamp,
};
