// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Adaptive time service with automatic clock source detection.
//!
//! This module provides a TrueTime-compatible time service that automatically
//! detects and uses the best available clock source:
//!
//! - **GPS**: PPS devices connected to GPS receivers (~100ns uncertainty)
//! - **AWS**: ENA PHC (~18μs uncertainty)
//! - **Azure**: Hyper-V PHC (~10μs uncertainty)
//! - **GCP**: VM PHC or NTP (~100μs uncertainty)
//! - **On-prem**: PTP with hardware timestamping (~1μs) or NTP
//! - **Fallback**: Hybrid Logical Clock (~500ms assumed drift)
//!
//! # Example
//!
//! ```no_run
//! use strontiumdb::time::{create_time_service, TimeService};
//!
//! let service = create_time_service();
//! let now = service.now();
//! println!("Time: [{}, {}]", now.earliest(), now.latest());
//! println!("Uncertainty: {:?}", service.uncertainty_bound());
//! println!("Source: {}", service.source_type());
//! ```

mod clock_source;
mod config;
mod detect;
mod error;
mod gps;
mod hlc;
mod ntp;
mod phc;
mod timestamp;
mod traits;

pub use clock_source::ClockSource;
pub use config::TimeServiceConfig;
pub use error::TimeError;
pub use gps::GpsTimeService;
pub use hlc::HlcTimeService;
pub use ntp::NtpTimeService;
pub use phc::PhcTimeService;
pub use timestamp::Timestamp;
pub use traits::TimeService;

/// Creates the best available TimeService for the current environment.
///
/// Detection order (best to worst):
/// 1. GPS via PPS devices (/dev/pps*)
/// 2. AWS ENA PHC (/dev/ptp* with "ena" clock_name)
/// 3. Azure Hyper-V PHC (/dev/ptp_hyperv)
/// 4. GCP VM PHC (if available)
/// 5. Generic PTP with hardware timestamping
/// 6. PTP software timestamping
/// 7. NTP via chrony/ntpd
/// 8. HLC fallback (always available)
pub fn create_time_service() -> Box<dyn TimeService> {
    create_time_service_with_config(TimeServiceConfig::default())
}

/// Creates a TimeService with the given configuration.
pub fn create_time_service_with_config(config: TimeServiceConfig) -> Box<dyn TimeService> {
    let source = config.source.unwrap_or_else(detect::detect_best_source);

    match source {
        ClockSource::AwsPhc | ClockSource::AzurePhc | ClockSource::GcpPhc => {
            if let Some(device) = detect::find_ptp_device(source) {
                if let Ok(service) =
                    PhcTimeService::new(device, config.update_interval, config.uncertainty_buffer)
                {
                    return Box::new(service);
                }
            }
            create_fallback_service(&config)
        }

        ClockSource::PtpHardware | ClockSource::PtpSoftware => {
            if let Some(device) = detect::find_ptp_device(source) {
                if let Ok(service) =
                    PhcTimeService::new(device, config.update_interval, config.uncertainty_buffer)
                {
                    return Box::new(service);
                }
            }
            create_fallback_service(&config)
        }

        ClockSource::Ntp => {
            if let Ok(service) =
                NtpTimeService::new(config.update_interval, config.uncertainty_buffer)
            {
                return Box::new(service);
            }
            Box::new(HlcTimeService::default())
        }

        ClockSource::Gps => {
            if let Some(pps_device) = detect::find_pps_device() {
                if let Ok(service) = GpsTimeService::new(pps_device.path, config.update_interval) {
                    return Box::new(service);
                }
            }
            create_fallback_service(&config)
        }

        ClockSource::Hlc => Box::new(HlcTimeService::default()),
    }
}

fn create_fallback_service(config: &TimeServiceConfig) -> Box<dyn TimeService> {
    if detect::is_chrony_available() || detect::is_ntpd_available() {
        if let Ok(service) = NtpTimeService::new(config.update_interval, config.uncertainty_buffer)
        {
            return Box::new(service);
        }
    }
    Box::new(HlcTimeService::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_time_service() {
        let service = create_time_service();
        let ts = service.now();
        assert!(ts.earliest() <= ts.latest());
    }

    #[test]
    fn test_time_service_monotonic() {
        let service = create_time_service();
        let ts1 = service.now();
        let ts2 = service.now();
        assert!(ts2.midpoint() >= ts1.midpoint());
    }

    #[test]
    fn test_uncertainty_bound_positive() {
        let service = create_time_service();
        assert!(service.uncertainty_bound() > std::time::Duration::ZERO);
    }

    #[tokio::test]
    async fn test_wait_until_past() {
        let service = create_time_service();
        let ts = service.now();
        service.wait_until_past(&ts).await;

        let after = service.now();
        assert!(
            after.earliest() > ts.latest(),
            "After wait_until_past, new timestamp should be definitely after"
        );
    }
}
