// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! NTP-based time service using chrony.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::traits::BoxFuture;
use super::{ClockSource, TimeError, TimeService, Timestamp};

/// NTP-based time service that queries chrony for clock offset and dispersion.
///
/// This service periodically queries `chronyc tracking` to get the current
/// clock offset and root dispersion, which are used to compute uncertainty bounds.
pub struct NtpTimeService {
    offset_nanos: AtomicI64,
    dispersion_nanos: AtomicU64,
    uncertainty_buffer: Duration,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    update_handle: Option<std::thread::JoinHandle<()>>,
}

impl NtpTimeService {
    /// Creates a new NTP time service.
    ///
    /// Spawns a background thread that periodically updates clock offset
    /// and dispersion from chrony.
    pub fn new(update_interval: Duration, uncertainty_buffer: Duration) -> Result<Self, TimeError> {
        let offset_nanos = Arc::new(AtomicI64::new(0));
        let dispersion_nanos = Arc::new(AtomicU64::new(10_000_000));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

        Self::update_from_chrony(&offset_nanos, &dispersion_nanos)?;

        let offset_clone = Arc::clone(&offset_nanos);
        let dispersion_clone = Arc::clone(&dispersion_nanos);
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                std::thread::sleep(update_interval);
                let _ = Self::update_from_chrony(&offset_clone, &dispersion_clone);
            }
        });

        Ok(Self {
            offset_nanos: AtomicI64::new(offset_nanos.load(Ordering::Relaxed)),
            dispersion_nanos: AtomicU64::new(dispersion_nanos.load(Ordering::Relaxed)),
            uncertainty_buffer,
            shutdown,
            update_handle: Some(handle),
        })
    }

    fn update_from_chrony(offset: &AtomicI64, dispersion: &AtomicU64) -> Result<(), TimeError> {
        let tracking_output = std::process::Command::new("chronyc")
            .arg("tracking")
            .output()
            .map_err(TimeError::ChronySpawn)?;

        if !tracking_output.status.success() {
            return Err(TimeError::ChronyUnavailable(
                String::from_utf8_lossy(&tracking_output.stderr).to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&tracking_output.stdout);
        let (parsed_offset, root_dispersion) = Self::parse_chrony_tracking(&stdout)?;

        let sources_uncertainty = std::process::Command::new("chronyc")
            .arg("sources")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    Self::parse_chrony_sources(&stdout)
                } else {
                    None
                }
            });

        let best_uncertainty = sources_uncertainty.unwrap_or(root_dispersion);

        offset.store(parsed_offset, Ordering::Release);
        dispersion.store(best_uncertainty, Ordering::Release);

        Ok(())
    }

    fn parse_chrony_tracking(output: &str) -> Result<(i64, u64), TimeError> {
        let mut offset_nanos: i64 = 0;
        let mut dispersion_nanos: u64 = 10_000_000;

        for line in output.lines() {
            if let Some(value) = line.strip_prefix("System time") {
                if let Some(offset) = Self::parse_seconds_value(value) {
                    offset_nanos = (offset * 1e9) as i64;
                }
            } else if let Some(value) = line.strip_prefix("Root dispersion") {
                if let Some(disp) = Self::parse_seconds_value(value) {
                    dispersion_nanos = (disp * 1e9) as u64;
                }
            }
        }

        Ok((offset_nanos, dispersion_nanos))
    }

    fn parse_chrony_sources(output: &str) -> Option<u64> {
        for line in output.lines() {
            if !line.starts_with('#') && !line.starts_with('^') && !line.starts_with('=') {
                continue;
            }
            if line.starts_with('=') {
                continue;
            }
            if let Some(pos) = line.find("+/-") {
                let uncertainty_str = line[pos + 3..].trim();
                return Self::parse_time_value(uncertainty_str);
            }
        }
        None
    }

    fn parse_time_value(s: &str) -> Option<u64> {
        let s = s.trim();
        let (num_str, multiplier) = if let Some(stripped) = s.strip_suffix("ns") {
            (stripped, 1u64)
        } else if let Some(stripped) = s.strip_suffix("us") {
            (stripped, 1_000u64)
        } else if let Some(stripped) = s.strip_suffix("ms") {
            (stripped, 1_000_000u64)
        } else if let Some(stripped) = s.strip_suffix('s') {
            (stripped, 1_000_000_000u64)
        } else {
            return None;
        };

        num_str
            .trim()
            .parse::<f64>()
            .ok()
            .map(|v| (v * multiplier as f64) as u64)
    }

    fn parse_seconds_value(line: &str) -> Option<f64> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if let Ok(val) = part.parse::<f64>() {
                if i + 1 < parts.len() && parts[i + 1].starts_with("second") {
                    return Some(val);
                }
                return Some(val);
            }
        }
        None
    }

    fn system_time_nanos() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

impl Drop for NtpTimeService {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.update_handle.take() {
            let _ = handle.join();
        }
    }
}

impl TimeService for NtpTimeService {
    fn now(&self) -> Timestamp {
        let system_time = Self::system_time_nanos();
        let offset = self.offset_nanos.load(Ordering::Acquire);
        let corrected = (system_time as i64).saturating_add(offset) as u64;

        let dispersion = self.dispersion_nanos.load(Ordering::Acquire);
        let uncertainty = dispersion + self.uncertainty_buffer.as_nanos() as u64;

        Timestamp::with_uncertainty(corrected, uncertainty)
    }

    fn uncertainty_bound(&self) -> Duration {
        let dispersion = self.dispersion_nanos.load(Ordering::Acquire);
        Duration::from_nanos(dispersion) + self.uncertainty_buffer
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
        ClockSource::Ntp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chrony_tracking() {
        let output = r#"
Reference ID    : A9FEA9FE (169.254.169.254)
Stratum         : 4
Ref time (UTC)  : Thu Jan 01 00:00:00 2025
System time     : 0.000001234 seconds fast of NTP time
Last offset     : +0.000000123 seconds
RMS offset      : 0.000000567 seconds
Root dispersion : 0.001234567 seconds
Root delay      : 0.000012345 seconds
"#;

        let (offset, dispersion) = NtpTimeService::parse_chrony_tracking(output).unwrap();
        assert!(offset > 0);
        assert!(dispersion > 0);
    }

    #[test]
    fn test_parse_chrony_sources_phc() {
        let output = r#"
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
#* PHC0                          0   3   377    11  -9802ns[  -17us] +/- 2316ns
"#;

        let uncertainty = NtpTimeService::parse_chrony_sources(output);
        assert_eq!(uncertainty, Some(2316));
    }

    #[test]
    fn test_parse_chrony_sources_ntp() {
        let output = r#"
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* metadata.google.internal      2   6   377     2  +9357ns[  +16us] +/-  237us
"#;

        let uncertainty = NtpTimeService::parse_chrony_sources(output);
        assert_eq!(uncertainty, Some(237_000));
    }

    #[test]
    fn test_parse_time_value() {
        assert_eq!(NtpTimeService::parse_time_value("2316ns"), Some(2316));
        assert_eq!(NtpTimeService::parse_time_value("237us"), Some(237_000));
        assert_eq!(NtpTimeService::parse_time_value("1.5ms"), Some(1_500_000));
        assert_eq!(NtpTimeService::parse_time_value("0.1s"), Some(100_000_000));
    }
}
