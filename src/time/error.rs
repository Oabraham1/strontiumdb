// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Error types for the time service.

use std::path::PathBuf;

/// Errors that can occur in the time service.
#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    #[error("failed to open PTP device {path}: {source}")]
    PtpDeviceOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("PTP ioctl failed: {0}")]
    PtpIoctl(#[source] nix::Error),

    #[error("failed to read sysfs path {path}: {source}")]
    SysfsRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse sysfs value: {0}")]
    SysfsParse(String),

    #[error("chrony not available: {0}")]
    ChronyUnavailable(String),

    #[error("failed to spawn chronyc: {0}")]
    ChronySpawn(#[source] std::io::Error),

    #[error("failed to parse chrony output: {0}")]
    ChronyParse(String),

    #[error("no suitable time source detected")]
    NoTimeSource,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}
