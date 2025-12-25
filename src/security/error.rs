// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Security error types.

use std::path::PathBuf;

/// Errors that can occur in the security module.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Certificate loading failed.
    #[error("failed to load certificate from {path}: {reason}")]
    CertificateLoad { path: PathBuf, reason: String },

    /// Private key loading failed.
    #[error("failed to load private key from {path}: {reason}")]
    PrivateKeyLoad { path: PathBuf, reason: String },

    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Ring crypto error.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<ring::error::Unspecified> for SecurityError {
    fn from(_: ring::error::Unspecified) -> Self {
        SecurityError::Crypto("unspecified cryptographic error".to_string())
    }
}

impl From<rustls::Error> for SecurityError {
    fn from(err: rustls::Error) -> Self {
        SecurityError::TlsConfig(err.to_string())
    }
}
