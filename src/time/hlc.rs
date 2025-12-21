// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Hybrid Logical Clock (HLC) implementation.
//!
//! HLC combines physical time with a logical counter to provide monotonic timestamps
//! even when physical clocks are imperfect. This is the fallback when no better
//! clock source is available.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::traits::BoxFuture;
use super::{ClockSource, TimeService, Timestamp};

/// Hybrid Logical Clock time service.
///
/// Provides monotonic timestamps by combining physical time with a logical counter.
/// Guarantees that each call to `now()` returns a timestamp greater than all previous
/// calls, even under concurrent access.
pub struct HlcTimeService {
    last_timestamp: AtomicU64,
    max_drift: Duration,
}

impl HlcTimeService {
    /// Creates a new HLC time service with the given maximum drift assumption.
    ///
    /// The `max_drift` parameter represents the assumed maximum clock skew between
    /// nodes in the cluster. This is used as the uncertainty bound.
    pub fn new(max_drift: Duration) -> Self {
        Self {
            last_timestamp: AtomicU64::new(0),
            max_drift,
        }
    }

    fn physical_time_nanos() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

impl Default for HlcTimeService {
    fn default() -> Self {
        Self::new(Duration::from_millis(500))
    }
}

impl TimeService for HlcTimeService {
    fn now(&self) -> Timestamp {
        let uncertainty = self.max_drift.as_nanos() as u64;

        loop {
            let physical = Self::physical_time_nanos();
            let last = self.last_timestamp.load(Ordering::Acquire);
            let new_ts = physical.max(last.saturating_add(1));

            match self.last_timestamp.compare_exchange(
                last,
                new_ts,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Timestamp::with_uncertainty(new_ts, uncertainty),
                Err(_) => continue,
            }
        }
    }

    #[inline]
    fn uncertainty_bound(&self) -> Duration {
        self.max_drift
    }

    fn wait_until_past<'a>(&'a self, ts: &'a Timestamp) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            loop {
                let now = self.now();
                if now.earliest() > ts.latest() {
                    return;
                }

                let wait_nanos = ts.latest().saturating_sub(now.earliest());
                let wait_duration =
                    Duration::from_nanos(wait_nanos).max(Duration::from_micros(100));

                tokio::time::sleep(wait_duration).await;
            }
        })
    }

    #[inline]
    fn source_type(&self) -> ClockSource {
        ClockSource::Hlc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hlc_monotonic() {
        let hlc = HlcTimeService::new(Duration::from_millis(100));
        let mut last = hlc.now();

        for _ in 0..1000 {
            let current = hlc.now();
            assert!(
                current.midpoint() >= last.midpoint(),
                "HLC must be monotonic: {} >= {}",
                current.midpoint(),
                last.midpoint()
            );
            last = current;
        }
    }

    #[test]
    fn test_hlc_concurrent_monotonic() {
        use std::sync::Arc;
        use std::thread;

        let hlc = Arc::new(HlcTimeService::new(Duration::from_millis(100)));
        let mut handles = vec![];

        for _ in 0..4 {
            let hlc = Arc::clone(&hlc);
            handles.push(thread::spawn(move || {
                let mut last = hlc.now();
                for _ in 0..1000 {
                    let current = hlc.now();
                    assert!(
                        current.midpoint() >= last.midpoint(),
                        "per-thread monotonicity: {} >= {}",
                        current.midpoint(),
                        last.midpoint()
                    );
                    last = current;
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    #[test]
    fn test_hlc_strictly_increasing() {
        let hlc = HlcTimeService::new(Duration::from_millis(100));
        let t1 = hlc.now();
        let t2 = hlc.now();
        assert!(t2.midpoint() > t1.midpoint());
    }

    #[test]
    fn test_hlc_uncertainty() {
        let hlc = HlcTimeService::new(Duration::from_millis(50));
        assert_eq!(hlc.uncertainty_bound(), Duration::from_millis(50));
    }

    #[test]
    fn test_hlc_source_type() {
        let hlc = HlcTimeService::new(Duration::from_millis(100));
        assert_eq!(hlc.source_type(), ClockSource::Hlc);
    }

    #[test]
    fn stress_hlc_contention() {
        use std::sync::Arc;
        use std::thread;

        let hlc = Arc::new(HlcTimeService::new(Duration::from_millis(100)));
        let threads: Vec<_> = (0..100)
            .map(|_| {
                let hlc = Arc::clone(&hlc);
                thread::spawn(move || {
                    for _ in 0..100_000 {
                        let _ = hlc.now();
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    }
}
