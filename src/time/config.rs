// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the time service.

use std::path::PathBuf;
use std::time::Duration;

use super::ClockSource;

/// Configuration for TimeService initialization.
#[derive(Debug, Clone)]
pub struct TimeServiceConfig {
    /// Force a specific clock source (None = auto-detect).
    pub source: Option<ClockSource>,
    /// PTP device path (for PTP sources).
    pub ptp_device: Option<PathBuf>,
    /// PTP domain (default 0).
    pub ptp_domain: u8,
    /// GPS device path (for GPS source).
    pub gps_device: Option<PathBuf>,
    /// NTP servers (for NTP source).
    pub ntp_servers: Vec<String>,
    /// Additional safety margin to add to measured uncertainty.
    pub uncertainty_buffer: Duration,
    /// Interval for background uncertainty updates.
    pub update_interval: Duration,
}

impl Default for TimeServiceConfig {
    fn default() -> Self {
        Self {
            source: None,
            ptp_device: None,
            ptp_domain: 0,
            gps_device: None,
            ntp_servers: Vec::new(),
            uncertainty_buffer: Duration::from_micros(1),
            update_interval: Duration::from_secs(1),
        }
    }
}

impl TimeServiceConfig {
    /// Creates a new configuration with auto-detection enabled.
    pub fn auto() -> Self {
        Self::default()
    }

    /// Forces a specific clock source.
    pub fn with_source(mut self, source: ClockSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets the PTP device path.
    pub fn with_ptp_device(mut self, path: impl Into<PathBuf>) -> Self {
        self.ptp_device = Some(path.into());
        self
    }

    /// Sets the uncertainty buffer (additional safety margin).
    pub fn with_uncertainty_buffer(mut self, buffer: Duration) -> Self {
        self.uncertainty_buffer = buffer;
        self
    }

    /// Sets the update interval for background uncertainty updates.
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }
}
