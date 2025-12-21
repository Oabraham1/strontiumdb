// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! PTP Hardware Clock (PHC) based time service.
//!
//! Provides high-precision timestamps using Linux PTP hardware clocks,
//! with specific optimizations for AWS ENA and Azure Hyper-V PHC devices.

use std::fs::{self, File};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nix::libc;

use super::detect::PtpDeviceInfo;
use super::traits::BoxFuture;
use super::{ClockSource, TimeError, TimeService, Timestamp};

const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = 0xc0403d08;

#[repr(C)]
struct PtpSysOffsetPrecise {
    device: libc::timespec,
    sys_realtime: libc::timespec,
    sys_monoraw: libc::timespec,
    rsv: [libc::c_uint; 4],
}

impl PtpSysOffsetPrecise {
    fn new() -> Self {
        Self {
            device: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sys_realtime: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sys_monoraw: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            rsv: [0; 4],
        }
    }
}

/// PHC-based time service for hardware clocks.
///
/// Keeps the PHC file descriptor open for fast reads and caches the
/// error bound from sysfs with periodic background updates.
pub struct PhcTimeService {
    _phc_file: File,
    phc_fd: RawFd,
    uncertainty_nanos: AtomicU64,
    uncertainty_buffer: Duration,
    source: ClockSource,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    update_handle: Option<std::thread::JoinHandle<()>>,
}

impl PhcTimeService {
    /// Creates a new PHC time service from detected device info.
    pub fn new(
        device: PtpDeviceInfo,
        update_interval: Duration,
        uncertainty_buffer: Duration,
    ) -> Result<Self, TimeError> {
        let phc_file = File::open(&device.path).map_err(|e| TimeError::PtpDeviceOpen {
            path: device.path.clone(),
            source: e,
        })?;
        let phc_fd = phc_file.as_raw_fd();

        let initial_uncertainty = device.source.typical_uncertainty().as_nanos() as u64;
        let uncertainty_nanos = Arc::new(AtomicU64::new(initial_uncertainty));

        if let Some(ref path) = device.error_bound_path {
            if let Ok(bound) = Self::read_error_bound(path) {
                uncertainty_nanos.store(bound, Ordering::Release);
            }
        }

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let update_handle = if let Some(error_bound_path) = device.error_bound_path {
            let uncertainty_clone = Arc::clone(&uncertainty_nanos);
            let shutdown_clone = Arc::clone(&shutdown);

            Some(std::thread::spawn(move || {
                while !shutdown_clone.load(Ordering::Relaxed) {
                    std::thread::sleep(update_interval);
                    if let Ok(bound) = Self::read_error_bound(&error_bound_path) {
                        uncertainty_clone.store(bound, Ordering::Release);
                    }
                }
            }))
        } else {
            None
        };

        Ok(Self {
            _phc_file: phc_file,
            phc_fd,
            uncertainty_nanos: AtomicU64::new(uncertainty_nanos.load(Ordering::Relaxed)),
            uncertainty_buffer,
            source: device.source,
            shutdown,
            update_handle,
        })
    }

    fn read_error_bound(path: &PathBuf) -> Result<u64, TimeError> {
        let content = fs::read_to_string(path).map_err(|e| TimeError::SysfsRead {
            path: path.clone(),
            source: e,
        })?;

        content
            .trim()
            .parse::<u64>()
            .map(|micros| micros * 1000)
            .map_err(|_| TimeError::SysfsParse(content))
    }

    fn read_phc_time(&self) -> Result<u64, TimeError> {
        let mut offset = PtpSysOffsetPrecise::new();

        let result = unsafe {
            libc::ioctl(
                self.phc_fd,
                PTP_SYS_OFFSET_PRECISE,
                &mut offset as *mut PtpSysOffsetPrecise,
            )
        };

        if result < 0 {
            return Err(TimeError::PtpIoctl(nix::Error::last()));
        }

        let nanos = offset.device.tv_sec as u64 * 1_000_000_000 + offset.device.tv_nsec as u64;

        Ok(nanos)
    }
}

impl Drop for PhcTimeService {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.update_handle.take() {
            let _ = handle.join();
        }
    }
}

impl TimeService for PhcTimeService {
    fn now(&self) -> Timestamp {
        let phc_time = self.read_phc_time().unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        });

        let uncertainty = self.uncertainty_nanos.load(Ordering::Acquire)
            + self.uncertainty_buffer.as_nanos() as u64;

        Timestamp::with_uncertainty(phc_time, uncertainty)
    }

    fn uncertainty_bound(&self) -> Duration {
        Duration::from_nanos(self.uncertainty_nanos.load(Ordering::Acquire))
            + self.uncertainty_buffer
    }

    fn wait_until_past<'a>(&'a self, ts: &'a Timestamp) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            loop {
                let now = self.now();
                if now.earliest() > ts.latest() {
                    return;
                }

                let wait_nanos = ts.latest().saturating_sub(now.earliest());
                let wait_duration = Duration::from_nanos(wait_nanos).max(Duration::from_micros(10));

                tokio::time::sleep(wait_duration).await;
            }
        })
    }

    #[inline]
    fn source_type(&self) -> ClockSource {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptp_sys_offset_precise_size() {
        assert_eq!(
            std::mem::size_of::<PtpSysOffsetPrecise>(),
            std::mem::size_of::<libc::timespec>() * 3 + std::mem::size_of::<libc::c_uint>() * 4
        );
    }
}
