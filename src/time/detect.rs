// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Cloud and hardware clock source detection.

use std::fs;
use std::path::{Path, PathBuf};

use super::ClockSource;

/// Information about a detected PPS (Pulse Per Second) device.
#[derive(Debug, Clone)]
pub struct PpsDeviceInfo {
    pub path: PathBuf,
}

/// Information about a detected PTP device.
#[derive(Debug, Clone)]
pub struct PtpDeviceInfo {
    pub path: PathBuf,
    pub clock_name: String,
    pub source: ClockSource,
    pub error_bound_path: Option<PathBuf>,
}

/// Detects all available PTP devices and identifies their type.
pub fn detect_ptp_devices() -> Vec<PtpDeviceInfo> {
    let mut devices = Vec::new();

    for i in 0..8 {
        let ptp_path = PathBuf::from(format!("/dev/ptp{}", i));
        let sys_path = format!("/sys/class/ptp/ptp{}", i);

        if !ptp_path.exists() {
            continue;
        }

        let clock_name = match fs::read_to_string(format!("{}/clock_name", sys_path)) {
            Ok(name) => name.trim().to_string(),
            Err(_) => continue,
        };

        let (source, error_bound_path) = identify_ptp_source(&clock_name, &sys_path);

        devices.push(PtpDeviceInfo {
            path: ptp_path,
            clock_name,
            source,
            error_bound_path,
        });
    }

    if let Some(hyperv) = detect_hyperv_ptp() {
        devices.push(hyperv);
    }

    devices
}

fn identify_ptp_source(clock_name: &str, sys_path: &str) -> (ClockSource, Option<PathBuf>) {
    if clock_name.starts_with("ena") {
        let error_bound = find_ena_error_bound(sys_path);
        return (ClockSource::AwsPhc, error_bound);
    }

    if clock_name == "hyperv" || clock_name.contains("hyperv") {
        return (ClockSource::AzurePhc, None);
    }

    if clock_name.contains("gve") || clock_name.contains("gcp") {
        return (ClockSource::GcpPhc, None);
    }

    if has_hardware_timestamping(sys_path) {
        (ClockSource::PtpHardware, None)
    } else {
        (ClockSource::PtpSoftware, None)
    }
}

fn find_ena_error_bound(sys_path: &str) -> Option<PathBuf> {
    let candidates = [
        format!("{}/device/phc_error_bound", sys_path),
        "/sys/devices/pci0000:00/0000:00:05.0/phc_error_bound".to_string(),
    ];

    for candidate in candidates {
        let path = PathBuf::from(&candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

fn has_hardware_timestamping(sys_path: &str) -> bool {
    let caps_path = format!("{}/n_pins", sys_path);
    if let Ok(content) = fs::read_to_string(caps_path) {
        if let Ok(n) = content.trim().parse::<u32>() {
            return n > 0;
        }
    }
    false
}

fn detect_hyperv_ptp() -> Option<PtpDeviceInfo> {
    let hyperv_path = Path::new("/dev/ptp_hyperv");
    if !hyperv_path.exists() {
        return None;
    }

    let real_path = fs::read_link(hyperv_path).ok()?;

    Some(PtpDeviceInfo {
        path: real_path,
        clock_name: "hyperv".to_string(),
        source: ClockSource::AzurePhc,
        error_bound_path: None,
    })
}

/// Detects all available PPS (GPS) devices.
pub fn detect_pps_devices() -> Vec<PpsDeviceInfo> {
    let mut devices = Vec::new();

    for i in 0..4 {
        let pps_path = PathBuf::from(format!("/dev/pps{}", i));
        if pps_path.exists() {
            devices.push(PpsDeviceInfo { path: pps_path });
        }
    }

    devices
}

/// Finds the first available PPS device (typically GPS-connected).
pub fn find_pps_device() -> Option<PpsDeviceInfo> {
    detect_pps_devices().into_iter().next()
}

/// Checks if chrony is available and responding.
pub fn is_chrony_available() -> bool {
    std::process::Command::new("chronyc")
        .arg("tracking")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Checks if ntpd is running.
pub fn is_ntpd_available() -> bool {
    std::process::Command::new("ntpq")
        .arg("-p")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Detects the best available clock source.
pub fn detect_best_source() -> ClockSource {
    if find_pps_device().is_some() {
        return ClockSource::Gps;
    }

    let ptp_devices = detect_ptp_devices();
    let priority_order = [
        ClockSource::AwsPhc,
        ClockSource::AzurePhc,
        ClockSource::GcpPhc,
        ClockSource::PtpHardware,
        ClockSource::PtpSoftware,
    ];

    for source in priority_order {
        if ptp_devices.iter().any(|d| d.source == source) {
            return source;
        }
    }

    if is_chrony_available() || is_ntpd_available() {
        return ClockSource::Ntp;
    }

    ClockSource::Hlc
}

/// Finds the PTP device info for a given source type.
pub fn find_ptp_device(source: ClockSource) -> Option<PtpDeviceInfo> {
    detect_ptp_devices()
        .into_iter()
        .find(|d| d.source == source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_best_source_returns_valid_source() {
        let source = detect_best_source();
        assert!(matches!(
            source,
            ClockSource::Gps
                | ClockSource::AwsPhc
                | ClockSource::AzurePhc
                | ClockSource::GcpPhc
                | ClockSource::PtpHardware
                | ClockSource::PtpSoftware
                | ClockSource::Ntp
                | ClockSource::Hlc
        ));
    }
}
