// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! MVCC storage layer with uncertainty-interval timestamps.
//!
//! This module provides a multi-version concurrency control (MVCC) storage engine
//! that uses uncertainty-interval timestamps instead of point timestamps.
//!
//! # Key Concepts
//!
//! Unlike traditional MVCC that treats timestamps as single points in time,
//! this implementation uses intervals `[earliest, latest]` representing bounded
//! clock uncertainty. This enables correct visibility decisions:
//!
//! - **Definitely visible**: `version.latest < read.earliest`
//! - **Definitely NOT visible**: `version.earliest > read.latest`
//! - **Uncertain**: intervals overlap (caller must handle)
//!
//! # Example
//!
//! ```no_run
//! use strontiumdb::storage::{RocksMvccStore, MvccStore, Key, Value, ReadResult};
//! use strontiumdb::time::Timestamp;
//! use std::path::Path;
//!
//! let store = RocksMvccStore::open(Path::new("/tmp/mvcc")).unwrap();
//!
//! // Write with uncertainty interval [100, 110]
//! let write_ts = Timestamp::new(100, 110);
//! store.write(Key::from("key"), Value::from("value"), write_ts).unwrap();
//!
//! // Read at definitely-after timestamp
//! let read_ts = Timestamp::new(200, 210);
//! match store.read(&Key::from("key"), &read_ts).unwrap() {
//!     ReadResult::Found(value) => println!("Found: {:?}", value),
//!     ReadResult::NotFound => println!("Not found"),
//!     ReadResult::Uncertain { version_ts } => println!("Uncertain: {:?}", version_ts),
//! }
//! ```

mod error;
mod key;
mod mvcc;
mod rocks;

pub use error::StorageError;
pub use key::{decode_mvcc_key, encode_mvcc_key, extract_user_key, user_key_prefix};
pub use mvcc::{
    GcStats, Key, MvccEntry, MvccStore, ReadResult, Value, MAX_KEY_SIZE, MAX_VALUE_SIZE,
};
pub use rocks::{DurabilityMode, RocksMvccStore};
