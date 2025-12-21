// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! TimeService trait definition.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use super::{ClockSource, Timestamp};

/// A boxed future that is Send.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The time service trait - implemented by PHC, NTP, and HLC backends.
///
/// This is the core abstraction for obtaining timestamps with bounded uncertainty.
/// All timestamp generation in the database flows through this interface.
pub trait TimeService: Send + Sync {
    /// Returns the current time with uncertainty bounds.
    ///
    /// This is the hot path - implementations must complete in < 100ns with no allocations.
    fn now(&self) -> Timestamp;

    /// Returns the current uncertainty bound.
    ///
    /// The returned duration represents the maximum error between the local clock
    /// and true time. This may vary based on clock quality and synchronization state.
    fn uncertainty_bound(&self) -> Duration;

    /// Waits until the given timestamp is definitely in the past.
    ///
    /// This implements "commit-wait" for external consistency. After this method
    /// returns, any subsequent `now()` call on any node is guaranteed to return
    /// a timestamp that is `definitely_after` the input timestamp.
    fn wait_until_past<'a>(&'a self, ts: &'a Timestamp) -> BoxFuture<'a, ()>;

    /// Returns the clock source type for diagnostics.
    fn source_type(&self) -> ClockSource;
}
