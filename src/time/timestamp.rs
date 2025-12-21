// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Timestamp with bounded uncertainty interval.

use std::time::Duration;

/// A timestamp representing an interval `[earliest, latest]` within which the true time lies.
///
/// This is the core type for TrueTime-style reasoning about time. The uncertainty interval
/// allows the system to reason about causality even when clocks are not perfectly synchronized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp {
    earliest: u64,
    latest: u64,
}

impl Timestamp {
    /// Creates a new timestamp with the given bounds (nanoseconds since Unix epoch).
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `earliest > latest`.
    #[inline]
    pub fn new(earliest: u64, latest: u64) -> Self {
        debug_assert!(earliest <= latest, "earliest must be <= latest");
        Self { earliest, latest }
    }

    /// Creates a timestamp from a single point with zero uncertainty.
    #[inline]
    pub fn from_nanos(nanos: u64) -> Self {
        Self {
            earliest: nanos,
            latest: nanos,
        }
    }

    /// Creates a timestamp from a point with symmetric uncertainty.
    #[inline]
    pub fn with_uncertainty(point: u64, uncertainty_nanos: u64) -> Self {
        Self {
            earliest: point.saturating_sub(uncertainty_nanos),
            latest: point.saturating_add(uncertainty_nanos),
        }
    }

    /// Returns the earliest possible true time (nanoseconds since Unix epoch).
    #[inline]
    pub fn earliest(&self) -> u64 {
        self.earliest
    }

    /// Returns the latest possible true time (nanoseconds since Unix epoch).
    #[inline]
    pub fn latest(&self) -> u64 {
        self.latest
    }

    /// Returns the midpoint of the uncertainty interval.
    #[inline]
    pub fn midpoint(&self) -> u64 {
        self.earliest / 2 + self.latest / 2 + (self.earliest % 2 + self.latest % 2) / 2
    }

    /// Returns the uncertainty as a Duration (half-width of the interval).
    #[inline]
    pub fn uncertainty(&self) -> Duration {
        Duration::from_nanos((self.latest - self.earliest) / 2)
    }

    /// Returns true if this timestamp's interval is entirely before the other's.
    ///
    /// This is the key primitive for external consistency: if `a.definitely_before(b)`,
    /// then any event at time `a` causally precedes any event at time `b`.
    #[inline]
    pub fn definitely_before(&self, other: &Timestamp) -> bool {
        self.latest < other.earliest
    }

    /// Returns true if this timestamp's interval is entirely after the other's.
    #[inline]
    pub fn definitely_after(&self, other: &Timestamp) -> bool {
        self.earliest > other.latest
    }

    /// Returns true if the uncertainty intervals overlap.
    ///
    /// When intervals overlap, the causal ordering is ambiguous and commit-wait
    /// may be required to establish ordering.
    #[inline]
    pub fn overlaps(&self, other: &Timestamp) -> bool {
        self.earliest <= other.latest && other.earliest <= self.latest
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.midpoint().cmp(&other.midpoint())
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.earliest, self.latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_definitely_before() {
        let t1 = Timestamp::new(100, 200);
        let t2 = Timestamp::new(300, 400);
        assert!(t1.definitely_before(&t2));
        assert!(!t2.definitely_before(&t1));
    }

    #[test]
    fn test_definitely_after() {
        let t1 = Timestamp::new(300, 400);
        let t2 = Timestamp::new(100, 200);
        assert!(t1.definitely_after(&t2));
        assert!(!t2.definitely_after(&t1));
    }

    #[test]
    fn test_overlaps() {
        let t1 = Timestamp::new(100, 300);
        let t2 = Timestamp::new(200, 400);
        assert!(t1.overlaps(&t2));
        assert!(t2.overlaps(&t1));

        let t3 = Timestamp::new(400, 500);
        assert!(!t1.overlaps(&t3));
    }

    #[test]
    fn test_no_overlap_implies_ordering() {
        let t1 = Timestamp::new(100, 200);
        let t2 = Timestamp::new(300, 400);
        assert!(!t1.overlaps(&t2));
        assert!(t1.definitely_before(&t2));
    }

    #[test]
    fn test_midpoint() {
        let ts = Timestamp::new(100, 200);
        assert_eq!(ts.midpoint(), 150);

        let ts_odd = Timestamp::new(1, 2);
        assert_eq!(ts_odd.midpoint(), 1);
    }

    #[test]
    fn test_uncertainty() {
        let ts = Timestamp::new(100, 200);
        assert_eq!(ts.uncertainty(), Duration::from_nanos(50));
    }

    #[test]
    fn test_with_uncertainty() {
        let ts = Timestamp::with_uncertainty(1000, 50);
        assert_eq!(ts.earliest(), 950);
        assert_eq!(ts.latest(), 1050);
    }

    #[test]
    fn test_saturating_bounds() {
        let ts = Timestamp::with_uncertainty(10, 100);
        assert_eq!(ts.earliest(), 0);
        assert_eq!(ts.latest(), 110);
    }

    #[test]
    fn test_ordering() {
        let t1 = Timestamp::new(100, 200);
        let t2 = Timestamp::new(300, 400);
        assert!(t1 < t2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_timestamp() -> impl Strategy<Value = Timestamp> {
        (0u64..=u64::MAX / 2, 0u64..=1_000_000_000u64)
            .prop_map(|(base, uncertainty)| Timestamp::with_uncertainty(base, uncertainty))
    }

    proptest! {
        #[test]
        fn definitely_before_implies_not_overlaps(
            a in arb_timestamp(),
            b in arb_timestamp()
        ) {
            if a.definitely_before(&b) {
                prop_assert!(!a.overlaps(&b));
            }
        }

        #[test]
        fn definitely_after_implies_not_overlaps(
            a in arb_timestamp(),
            b in arb_timestamp()
        ) {
            if a.definitely_after(&b) {
                prop_assert!(!a.overlaps(&b));
            }
        }

        #[test]
        fn overlaps_is_symmetric(
            a in arb_timestamp(),
            b in arb_timestamp()
        ) {
            prop_assert_eq!(a.overlaps(&b), b.overlaps(&a));
        }

        #[test]
        fn midpoint_within_bounds(
            a in arb_timestamp()
        ) {
            let mid = a.midpoint();
            prop_assert!(mid >= a.earliest());
            prop_assert!(mid <= a.latest());
        }

        #[test]
        fn uncertainty_consistent_with_bounds(
            base in 0u64..=u64::MAX / 2,
            unc in 0u64..=1_000_000_000u64
        ) {
            let ts = Timestamp::with_uncertainty(base, unc);
            let width = ts.latest() - ts.earliest();
            prop_assert!(width <= 2 * unc);
        }

        #[test]
        fn no_overlap_means_ordered(
            a in arb_timestamp(),
            b in arb_timestamp()
        ) {
            if !a.overlaps(&b) {
                prop_assert!(a.definitely_before(&b) || a.definitely_after(&b));
            }
        }
    }
}
