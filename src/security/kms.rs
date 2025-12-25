// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Key Management Service trait and types.

use std::time::SystemTime;

use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::SecurityError;

/// Size of AES-256 keys in bytes.
pub const AES_256_KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes.
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Size of AES-GCM authentication tag in bytes.
pub const AES_GCM_TAG_SIZE: usize = 16;

/// A data encryption key (DEK) for encrypting data.
///
/// DEKs are 256-bit AES keys used for actual data encryption.
/// They are wrapped (encrypted) by Key Encryption Keys (KEKs)
/// when stored.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey {
    /// The raw 256-bit key material.
    key: [u8; AES_256_KEY_SIZE],
    /// Unique identifier for this DEK.
    #[zeroize(skip)]
    id: String,
    /// When this key was created.
    #[zeroize(skip)]
    created_at: SystemTime,
}

impl DataEncryptionKey {
    /// Creates a new DEK with the given key material and ID.
    pub fn new(key: [u8; AES_256_KEY_SIZE], id: String) -> Self {
        Self {
            key,
            id,
            created_at: SystemTime::now(),
        }
    }

    /// Returns the key material.
    ///
    /// # Security
    ///
    /// The returned slice references key material that will be
    /// zeroized when this DEK is dropped. Do not store copies.
    #[inline]
    pub fn key(&self) -> &[u8; AES_256_KEY_SIZE] {
        &self.key
    }

    /// Returns the key ID.
    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns when this key was created.
    #[inline]
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }
}

impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataEncryptionKey")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// A DEK that has been wrapped (encrypted) by a KEK.
#[derive(Debug, Clone)]
pub struct WrappedKey {
    /// The encrypted DEK ciphertext (includes nonce and tag).
    ciphertext: Vec<u8>,
    /// ID of the KEK used to wrap this DEK.
    kek_id: String,
    /// ID of the wrapped DEK.
    dek_id: String,
}

impl WrappedKey {
    /// Creates a new wrapped key.
    pub fn new(ciphertext: Vec<u8>, kek_id: String, dek_id: String) -> Self {
        Self {
            ciphertext,
            kek_id,
            dek_id,
        }
    }

    /// Returns the encrypted ciphertext.
    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the KEK ID used for wrapping.
    #[inline]
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    /// Returns the wrapped DEK's ID.
    #[inline]
    pub fn dek_id(&self) -> &str {
        &self.dek_id
    }
}

/// Key Management Service interface.
///
/// Provides operations for generating, wrapping, and unwrapping
/// data encryption keys. Implementations may use local storage,
/// cloud KMS services (AWS KMS, Azure Key Vault, GCP KMS), or
/// hardware security modules (HSMs).
///
/// All operations are async to support cloud KMS providers that
/// require network calls.
#[async_trait]
pub trait KeyManagementService: Send + Sync {
    /// Generates a new data encryption key (DEK).
    ///
    /// The returned DEK contains fresh cryptographically random
    /// key material and a unique identifier.
    async fn generate_dek(&self) -> Result<DataEncryptionKey, SecurityError>;

    /// Wraps (encrypts) a DEK with the specified key encryption key (KEK).
    ///
    /// The wrapped key can be safely stored and later unwrapped using
    /// the same KEK.
    async fn wrap_dek(
        &self,
        dek: &DataEncryptionKey,
        kek_id: &str,
    ) -> Result<WrappedKey, SecurityError>;

    /// Unwraps (decrypts) a wrapped DEK.
    ///
    /// Returns the original DEK that was wrapped.
    async fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey, SecurityError>;

    /// Rotates the KEK, re-wrapping all DEKs with the new key.
    ///
    /// This operation is atomic: either all DEKs are re-wrapped
    /// or none are.
    async fn rotate_kek(&self, old_kek_id: &str, new_kek_id: &str) -> Result<(), SecurityError>;

    /// Returns the ID of the currently active KEK.
    fn active_kek_id(&self) -> &str;
}
