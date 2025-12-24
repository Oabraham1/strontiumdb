// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Clock source identification and characteristics.

use std::time::Duration;

/// Identifies the type of clock source being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockSource {
    /// GPS-disciplined clock (on-prem, best possible).
    Gps,
    /// PTP with hardware timestamping (on-prem or enterprise).
    PtpHardware,
    /// AWS ENA PHC (cloud hardware).
    AwsPhc,
    /// Azure Hyper-V PHC (cloud hardware).
    AzurePhc,
    /// GCP VM PHC (cloud hardware).
    GcpPhc,
    /// Linux PTP software timestamping.
    PtpSoftware,
    /// NTP via chrony/ntpd.
    Ntp,
    /// Hybrid Logical Clock (fallback).
    Hlc,
}

impl ClockSource {
    /// Returns the typical uncertainty bound for this clock source.
    #[inline]
    pub fn typical_uncertainty(&self) -> Duration {
        match self {
            ClockSource::Gps => Duration::from_nanos(100),
            ClockSource::PtpHardware => Duration::from_nanos(1_000),
            ClockSource::AwsPhc => Duration::from_micros(18),
            ClockSource::AzurePhc => Duration::from_micros(10),
            ClockSource::GcpPhc => Duration::from_micros(100),
            ClockSource::PtpSoftware => Duration::from_micros(100),
            ClockSource::Ntp => Duration::from_millis(10),
            ClockSource::Hlc => Duration::from_millis(500),
        }
    }

    /// Returns a human-readable name for this clock source.
    #[inline]
    pub fn name(&self) -> &'static str {
        match self {
            ClockSource::Gps => "GPS",
            ClockSource::PtpHardware => "PTP (hardware)",
            ClockSource::AwsPhc => "AWS PHC",
            ClockSource::AzurePhc => "Azure PHC",
            ClockSource::GcpPhc => "GCP PHC",
            ClockSource::PtpSoftware => "PTP (software)",
            ClockSource::Ntp => "NTP",
            ClockSource::Hlc => "HLC",
        }
    }
}

impl std::fmt::Display for ClockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
