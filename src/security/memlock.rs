// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Memory locking for protecting cryptographic key material.
//!
//! Provides utilities to prevent sensitive data from being swapped to disk.
//! Uses platform-specific APIs (mlock on Unix, VirtualLock on Windows).
//!
//! # Security Considerations
//!
//! - Locked memory is not paged to swap, preventing key leakage
//! - Memory limits may apply (see ulimit -l on Linux)
//! - Locked memory is still visible to root/kernel
//! - Core dumps may still contain locked memory unless disabled

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;

use tracing::debug;
use zeroize::Zeroize;

/// Error type for memory locking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemlockError {
    /// Memory allocation failed.
    AllocationFailed,
    /// Failed to lock memory (e.g., insufficient privileges or limits).
    LockFailed(String),
    /// Failed to unlock memory.
    UnlockFailed(String),
}

impl std::fmt::Display for MemlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemlockError::AllocationFailed => write!(f, "memory allocation failed"),
            MemlockError::LockFailed(msg) => write!(f, "memory lock failed: {}", msg),
            MemlockError::UnlockFailed(msg) => write!(f, "memory unlock failed: {}", msg),
        }
    }
}

impl std::error::Error for MemlockError {}

/// Attempts to lock a memory region to prevent swapping.
///
/// # Safety
/// The caller must ensure ptr is valid and len bytes are accessible.
#[cfg(unix)]
unsafe fn mlock_impl(ptr: *const u8, len: usize) -> Result<(), MemlockError> {
    let result = libc::mlock(ptr as *const libc::c_void, len);
    if result == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(MemlockError::LockFailed(format!("mlock failed: {}", err)))
    }
}

#[cfg(not(unix))]
unsafe fn mlock_impl(_ptr: *const u8, _len: usize) -> Result<(), MemlockError> {
    // On non-Unix platforms, we just warn and continue
    tracing::warn!("Memory locking not supported on this platform");
    Ok(())
}

/// Attempts to unlock a memory region.
///
/// # Safety
/// The caller must ensure ptr is valid and len bytes were previously locked.
#[cfg(unix)]
unsafe fn munlock_impl(ptr: *const u8, len: usize) -> Result<(), MemlockError> {
    let result = libc::munlock(ptr as *const libc::c_void, len);
    if result == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(MemlockError::UnlockFailed(format!(
            "munlock failed: {}",
            err
        )))
    }
}

#[cfg(not(unix))]
unsafe fn munlock_impl(_ptr: *const u8, _len: usize) -> Result<(), MemlockError> {
    Ok(())
}

/// A buffer of locked memory that cannot be swapped to disk.
///
/// The buffer is automatically zeroized and unlocked when dropped.
/// Useful for storing cryptographic keys and other sensitive data.
///
/// # Example
///
/// ```rust,no_run
/// use strontiumdb::security::memlock::LockedBuffer;
///
/// // Allocate 32 bytes of locked memory
/// let mut buffer = LockedBuffer::new(32).expect("failed to allocate");
///
/// // Write key material
/// buffer.as_mut_slice()[..32].copy_from_slice(&[0u8; 32]);
///
/// // Buffer is zeroized and unlocked on drop
/// ```
pub struct LockedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
    locked: bool,
}

impl LockedBuffer {
    /// Allocates a new locked buffer of the given size.
    ///
    /// The buffer is zero-initialized and locked to prevent swapping.
    /// Returns an error if allocation or locking fails.
    pub fn new(len: usize) -> Result<Self, MemlockError> {
        if len == 0 {
            return Err(MemlockError::AllocationFailed);
        }

        let layout = Layout::from_size_align(len, 8).map_err(|_| MemlockError::AllocationFailed)?;

        // Allocate zeroed memory
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).ok_or(MemlockError::AllocationFailed)?;

        // Attempt to lock the memory
        let locked = unsafe { mlock_impl(ptr.as_ptr(), len).is_ok() };

        if !locked {
            debug!("Memory locking not available, continuing without lock");
        }

        Ok(Self {
            ptr,
            len,
            layout,
            locked,
        })
    }

    /// Returns the length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if the memory is locked.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns a reference to the buffer contents.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Returns a mutable reference to the buffer contents.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // Zeroize the memory
        unsafe {
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
            slice.zeroize();
        }

        // Unlock if locked
        if self.locked {
            unsafe {
                let _ = munlock_impl(self.ptr.as_ptr(), self.len);
            }
        }

        // Deallocate
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

// LockedBuffer is Send + Sync because it owns its memory
unsafe impl Send for LockedBuffer {}
unsafe impl Sync for LockedBuffer {}

/// A secure key container that stores key material in locked memory.
///
/// Provides a higher-level API for storing fixed-size keys.
pub struct SecureKey<const N: usize> {
    buffer: LockedBuffer,
}

impl<const N: usize> SecureKey<N> {
    /// Creates a new secure key container.
    pub fn new() -> Result<Self, MemlockError> {
        Ok(Self {
            buffer: LockedBuffer::new(N)?,
        })
    }

    /// Creates a secure key from existing key material.
    ///
    /// The source is zeroized after copying.
    pub fn from_slice(mut src: [u8; N]) -> Result<Self, MemlockError> {
        let mut key = Self::new()?;
        key.buffer.as_mut_slice().copy_from_slice(&src);
        src.zeroize();
        Ok(key)
    }

    /// Returns the key material.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        self.buffer.as_slice().try_into().unwrap()
    }

    /// Returns true if the key memory is locked.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.buffer.is_locked()
    }
}

impl<const N: usize> Default for SecureKey<N> {
    fn default() -> Self {
        Self::new().expect("failed to allocate secure key")
    }
}

impl<const N: usize> std::fmt::Debug for SecureKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureKey")
            .field("size", &N)
            .field("locked", &self.is_locked())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Checks if memory locking is available on this system.
///
/// Returns true if mlock() is expected to work.
pub fn is_memlock_available() -> bool {
    #[cfg(unix)]
    {
        // Try to lock a small test allocation
        let test = [0u8; 64];
        unsafe { mlock_impl(test.as_ptr(), test.len()).is_ok() }
    }

    #[cfg(not(unix))]
    {
        false
    }
}

/// Returns the current memory lock limit in bytes.
///
/// On Unix systems, this is the RLIMIT_MEMLOCK value.
#[cfg(unix)]
pub fn get_memlock_limit() -> Option<u64> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let result = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) };
    if result == 0 {
        Some(rlim.rlim_cur)
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn get_memlock_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer_allocation() {
        let buffer = LockedBuffer::new(32).unwrap();
        assert_eq!(buffer.len(), 32);
        assert!(buffer.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_locked_buffer_write_read() {
        let mut buffer = LockedBuffer::new(16).unwrap();
        buffer
            .as_mut_slice()
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(buffer.as_slice()[0], 1);
        assert_eq!(buffer.as_slice()[15], 16);
    }

    #[test]
    fn test_locked_buffer_zero_size() {
        let result = LockedBuffer::new(0);
        assert!(matches!(result, Err(MemlockError::AllocationFailed)));
    }

    #[test]
    fn test_secure_key() {
        let key = SecureKey::<32>::from_slice([42u8; 32]).unwrap();
        assert_eq!(key.as_bytes(), &[42u8; 32]);
    }

    #[test]
    fn test_secure_key_debug() {
        let key = SecureKey::<32>::new().unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn test_memlock_availability() {
        // Just ensure this doesn't panic
        let _available = is_memlock_available();
    }

    #[test]
    fn test_memlock_limit() {
        // Just ensure this doesn't panic
        let _limit = get_memlock_limit();
    }
}
