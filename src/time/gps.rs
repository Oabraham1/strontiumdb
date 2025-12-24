// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! GPS/PPS-based time service.
//!
//! Provides sub-microsecond timestamps using Linux PPS (Pulse Per Second) devices
//! connected to GPS receivers. This is the highest-accuracy time source available
//! on commodity hardware.

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nix::libc;

use super::traits::BoxFuture;
use super::{ClockSource, TimeError, TimeService, Timestamp};

const PPS_FETCH: libc::c_ulong = 0xc00870a4;

#[repr(C)]
#[derive(Clone, Copy)]
struct PpsKtime {
    sec: i64,
    nsec: i32,
    flags: u32,
}

impl PpsKtime {
    fn new() -> Self {
        Self {
            sec: 0,
            nsec: 0,
            flags: 0,
        }
    }

    fn to_nanos(self) -> u64 {
        (self.sec as u64) * 1_000_000_000 + (self.nsec as u64)
    }
}

#[repr(C)]
struct PpsFetchArgs {
    info: PpsKinfo,
    timeout: PpsKtime,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PpsKinfo {
    assert_sequence: u32,
    clear_sequence: u32,
    assert_tu: PpsKtime,
    clear_tu: PpsKtime,
    current_mode: i32,
    _padding: i32,
}

impl PpsKinfo {
    fn new() -> Self {
        Self {
            assert_sequence: 0,
            clear_sequence: 0,
            assert_tu: PpsKtime::new(),
            clear_tu: PpsKtime::new(),
            current_mode: 0,
            _padding: 0,
        }
    }
}

impl PpsFetchArgs {
    fn new() -> Self {
        Self {
            info: PpsKinfo::new(),
            timeout: PpsKtime {
                sec: 1,
                nsec: 0,
                flags: 0,
            },
        }
    }
}

/// GPS/PPS-based time service.
///
/// Uses Linux PPS devices to obtain high-precision timestamps from GPS receivers.
/// Typical uncertainty is 50-100ns with a good GPS antenna and clear sky view.
pub struct GpsTimeService {
    _pps_file: File,
    last_pps_time: AtomicU64,
    last_system_time: AtomicU64,
    uncertainty_nanos: AtomicU64,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    update_handle: Option<std::thread::JoinHandle<()>>,
}

impl GpsTimeService {
    /// Creates a new GPS time service from a PPS device path.
    pub fn new(pps_path: PathBuf, update_interval: Duration) -> Result<Self, TimeError> {
        let pps_file = File::open(&pps_path).map_err(|e| TimeError::PtpDeviceOpen {
            path: pps_path.clone(),
            source: e,
        })?;

        let last_pps_time = Arc::new(AtomicU64::new(0));
        let last_system_time = Arc::new(AtomicU64::new(0));
        let uncertainty_nanos = Arc::new(AtomicU64::new(100));

        if let Ok((pps_time, sys_time)) = Self::fetch_pps_time(pps_file.as_raw_fd()) {
            last_pps_time.store(pps_time, Ordering::Release);
            last_system_time.store(sys_time, Ordering::Release);
        }

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pps_time_clone = Arc::clone(&last_pps_time);
        let sys_time_clone = Arc::clone(&last_system_time);
        let uncertainty_clone = Arc::clone(&uncertainty_nanos);
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            let file = match File::open(&pps_path) {
                Ok(f) => f,
                Err(_) => return,
            };
            let fd = file.as_raw_fd();
            let mut jitter_samples: Vec<u64> = Vec::with_capacity(100);

            while !shutdown_clone.load(Ordering::Relaxed) {
                if let Ok((pps_time, sys_time)) = Self::fetch_pps_time(fd) {
                    let old_pps = pps_time_clone.load(Ordering::Acquire);
                    if pps_time > old_pps {
                        let jitter = sys_time.abs_diff(pps_time);
                        jitter_samples.push(jitter);
                        if jitter_samples.len() > 100 {
                            jitter_samples.remove(0);
                        }

                        let max_jitter = jitter_samples.iter().max().copied().unwrap_or(100);
                        uncertainty_clone.store(max_jitter.max(50), Ordering::Release);
                        pps_time_clone.store(pps_time, Ordering::Release);
                        sys_time_clone.store(sys_time, Ordering::Release);
                    }
                }
                std::thread::sleep(update_interval);
            }
        });

        Ok(Self {
            _pps_file: pps_file,
            last_pps_time: AtomicU64::new(last_pps_time.load(Ordering::Relaxed)),
            last_system_time: AtomicU64::new(last_system_time.load(Ordering::Relaxed)),
            uncertainty_nanos: AtomicU64::new(uncertainty_nanos.load(Ordering::Relaxed)),
            shutdown,
            update_handle: Some(handle),
        })
    }

    fn fetch_pps_time(fd: libc::c_int) -> Result<(u64, u64), TimeError> {
        let mut args = PpsFetchArgs::new();

        let result = unsafe { libc::ioctl(fd, PPS_FETCH, &mut args as *mut PpsFetchArgs) };

        if result < 0 {
            return Err(TimeError::PtpIoctl(nix::Error::last()));
        }

        let pps_time = args.info.assert_tu.to_nanos();

        let sys_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok((pps_time, sys_time))
    }

    fn system_time_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

impl Drop for GpsTimeService {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.update_handle.take() {
            let _ = handle.join();
        }
    }
}

impl TimeService for GpsTimeService {
    fn now(&self) -> Timestamp {
        let last_pps = self.last_pps_time.load(Ordering::Acquire);
        let last_sys = self.last_system_time.load(Ordering::Acquire);
        let current_sys = Self::system_time_nanos();

        let elapsed = current_sys.saturating_sub(last_sys);
        let estimated_time = last_pps.saturating_add(elapsed);

        let uncertainty = self.uncertainty_nanos.load(Ordering::Acquire);

        Timestamp::with_uncertainty(estimated_time, uncertainty)
    }

    fn uncertainty_bound(&self) -> Duration {
        Duration::from_nanos(self.uncertainty_nanos.load(Ordering::Acquire))
    }

    fn wait_until_past<'a>(&'a self, ts: &'a Timestamp) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            loop {
                let now = self.now();
                if now.earliest() > ts.latest() {
                    return;
                }

                let wait_nanos = ts.latest().saturating_sub(now.earliest());
                let wait_duration = Duration::from_nanos(wait_nanos).max(Duration::from_nanos(100));

                tokio::time::sleep(wait_duration).await;
            }
        })
    }

    #[inline]
    fn source_type(&self) -> ClockSource {
        ClockSource::Gps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_ktime_to_nanos() {
        let kt = PpsKtime {
            sec: 1,
            nsec: 500_000_000,
            flags: 0,
        };
        assert_eq!(kt.to_nanos(), 1_500_000_000);
    }

    #[test]
    fn test_pps_fetch_args_size() {
        assert!(std::mem::size_of::<PpsFetchArgs>() > 0);
    }
}
