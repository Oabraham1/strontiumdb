// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Local file-based Key Management Service implementation.
//!
//! This KMS stores the master key (KEK) in memory and provides
//! AES-256-GCM encryption for wrapping DEKs. Suitable for
//! development and testing, or single-node deployments where
//! the master key is provided at startup.

use async_trait::async_trait;
use parking_lot::RwLock;
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::SecurityError;
use super::kms::{
    DataEncryptionKey, KeyManagementService, WrappedKey, AES_256_KEY_SIZE, AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
};

/// A master key (KEK) stored in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
#[allow(unused_assignments)]
struct MasterKey {
    key: [u8; AES_256_KEY_SIZE],
    #[zeroize(skip)]
    id: String,
}

/// Counter-based nonce sequence for AES-GCM.
struct CounterNonceSequence {
    nonce: [u8; NONCE_LEN],
}

impl CounterNonceSequence {
    fn new(random_prefix: [u8; NONCE_LEN]) -> Self {
        Self {
            nonce: random_prefix,
        }
    }
}

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Nonce::try_assume_unique_for_key(&self.nonce)
    }
}

/// Local in-memory Key Management Service.
///
/// Uses AES-256-GCM for wrapping DEKs with the master key.
/// The master key is stored in memory and zeroized on drop.
pub struct LocalKms {
    master_key: RwLock<MasterKey>,
    rng: SystemRandom,
}

impl LocalKms {
    /// Creates a new LocalKms with the given master key.
    pub fn new(master_key: [u8; AES_256_KEY_SIZE], kek_id: String) -> Self {
        Self {
            master_key: RwLock::new(MasterKey {
                key: master_key,
                id: kek_id,
            }),
            rng: SystemRandom::new(),
        }
    }

    /// Generates a new LocalKms with a random master key.
    pub fn generate() -> Result<Self, SecurityError> {
        let rng = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_SIZE];
        rng.fill(&mut key)
            .map_err(|_| SecurityError::KeyGeneration("failed to generate random key".into()))?;

        let id = uuid::Uuid::new_v4().to_string();
        Ok(Self::new(key, id))
    }

    /// Creates a new LocalKms from a hex-encoded master key.
    pub fn from_hex(hex_key: &str, kek_id: String) -> Result<Self, SecurityError> {
        let bytes = hex_decode(hex_key)?;
        if bytes.len() != AES_256_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                got: bytes.len(),
            });
        }

        let mut key = [0u8; AES_256_KEY_SIZE];
        key.copy_from_slice(&bytes);
        Ok(Self::new(key, kek_id))
    }

    /// Encrypts data using AES-256-GCM.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let master = self.master_key.read();

        // Generate random nonce
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| SecurityError::KeyGeneration("failed to generate nonce".into()))?;

        // Create sealing key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &master.key)?;
        let nonce_seq = CounterNonceSequence::new(nonce_bytes);
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);

        // Encrypt in-place
        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|_| SecurityError::Encryption("AES-GCM seal failed".into()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Ok(result)
    }

    /// Decrypts data using AES-256-GCM.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(SecurityError::Decryption("ciphertext too short".into()));
        }

        let master = self.master_key.read();

        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted) = ciphertext.split_at(AES_GCM_NONCE_SIZE);
        let mut nonce_arr = [0u8; AES_GCM_NONCE_SIZE];
        nonce_arr.copy_from_slice(nonce_bytes);

        // Create opening key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &master.key)?;
        let nonce_seq = CounterNonceSequence::new(nonce_arr);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

        // Decrypt in-place
        let mut in_out = encrypted.to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| SecurityError::Decryption("AES-GCM open failed".into()))?;

        Ok(plaintext.to_vec())
    }
}

#[async_trait]
impl KeyManagementService for LocalKms {
    async fn generate_dek(&self) -> Result<DataEncryptionKey, SecurityError> {
        let mut key = [0u8; AES_256_KEY_SIZE];
        self.rng
            .fill(&mut key)
            .map_err(|_| SecurityError::KeyGeneration("failed to generate DEK".into()))?;

        let id = uuid::Uuid::new_v4().to_string();
        Ok(DataEncryptionKey::new(key, id))
    }

    async fn wrap_dek(
        &self,
        dek: &DataEncryptionKey,
        _kek_id: &str,
    ) -> Result<WrappedKey, SecurityError> {
        let ciphertext = self.encrypt(dek.key())?;

        Ok(WrappedKey::new(
            ciphertext,
            self.master_key.read().id.clone(),
            dek.id().to_string(),
        ))
    }

    async fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey, SecurityError> {
        // Verify KEK ID matches
        let master = self.master_key.read();
        if wrapped.kek_id() != master.id {
            return Err(SecurityError::KeyNotFound(format!(
                "KEK {} not found, active KEK is {}",
                wrapped.kek_id(),
                master.id
            )));
        }
        drop(master);

        let plaintext = self.decrypt(wrapped.ciphertext())?;

        if plaintext.len() != AES_256_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                got: plaintext.len(),
            });
        }

        let mut key = [0u8; AES_256_KEY_SIZE];
        key.copy_from_slice(&plaintext);

        Ok(DataEncryptionKey::new(key, wrapped.dek_id().to_string()))
    }

    async fn rotate_kek(&self, old_kek_id: &str, new_kek_id: &str) -> Result<(), SecurityError> {
        let mut master = self.master_key.write();
        if master.id != old_kek_id {
            return Err(SecurityError::KeyNotFound(format!(
                "old KEK {} not found, active KEK is {}",
                old_kek_id, master.id
            )));
        }

        // Generate new master key
        let mut new_key = [0u8; AES_256_KEY_SIZE];
        self.rng
            .fill(&mut new_key)
            .map_err(|_| SecurityError::KeyGeneration("failed to generate new KEK".into()))?;

        // Zeroize old key and replace
        master.key.zeroize();
        master.key = new_key;
        master.id = new_kek_id.to_string();

        Ok(())
    }

    fn active_kek_id(&self) -> &str {
        // This is a bit awkward but we need to return a reference
        // In practice, callers should clone the result
        // For now, we leak a string (not ideal but safe)
        let id = self.master_key.read().id.clone();
        Box::leak(id.into_boxed_str())
    }
}

/// Decodes a hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, SecurityError> {
    if !hex.len().is_multiple_of(2) {
        return Err(SecurityError::Crypto("invalid hex length".into()));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| SecurityError::Crypto("invalid hex character".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_kms() {
        let kms = LocalKms::generate().unwrap();
        assert!(!kms.active_kek_id().is_empty());
    }

    #[tokio::test]
    async fn test_generate_dek() {
        let kms = LocalKms::generate().unwrap();
        let dek = kms.generate_dek().await.unwrap();
        assert_eq!(dek.key().len(), AES_256_KEY_SIZE);
        assert!(!dek.id().is_empty());
    }

    #[tokio::test]
    async fn test_wrap_unwrap_dek() {
        let kms = LocalKms::generate().unwrap();
        let dek = kms.generate_dek().await.unwrap();
        let original_key = *dek.key();
        let original_id = dek.id().to_string();

        let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();
        assert_eq!(wrapped.dek_id(), original_id);

        let unwrapped = kms.unwrap_dek(&wrapped).await.unwrap();
        assert_eq!(unwrapped.key(), &original_key);
        assert_eq!(unwrapped.id(), original_id);
    }

    #[tokio::test]
    async fn test_wrap_produces_different_ciphertext() {
        let kms = LocalKms::generate().unwrap();
        let dek = kms.generate_dek().await.unwrap();

        let wrapped1 = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();
        let wrapped2 = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();

        // Same key wrapped twice should produce different ciphertext (random nonce)
        assert_ne!(wrapped1.ciphertext(), wrapped2.ciphertext());
    }

    #[tokio::test]
    async fn test_unwrap_wrong_kek_fails() {
        let kms = LocalKms::generate().unwrap();
        let dek = kms.generate_dek().await.unwrap();
        let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();

        // Rotate KEK
        let old_kek = kms.active_kek_id().to_string();
        kms.rotate_kek(&old_kek, "new-kek").await.unwrap();

        // Unwrap with new KEK should fail (wrapped with old KEK)
        let result = kms.unwrap_dek(&wrapped).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kms = LocalKms::from_hex(hex_key, "test-kek".into()).unwrap();
        assert_eq!(kms.active_kek_id(), "test-kek");
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let hex_key = "0123456789abcdef"; // Too short
        let result = LocalKms::from_hex(hex_key, "test-kek".into());
        assert!(matches!(
            result,
            Err(SecurityError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let kms = LocalKms::generate().unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = kms.encrypt(plaintext).unwrap();
        assert_ne!(&ciphertext[AES_GCM_NONCE_SIZE..], plaintext);

        let decrypted = kms.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let kms = LocalKms::generate().unwrap();
        let plaintext = b"Hello, World!";

        let mut ciphertext = kms.encrypt(plaintext).unwrap();
        // Tamper with ciphertext
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = kms.decrypt(&ciphertext);
        assert!(matches!(result, Err(SecurityError::Decryption(_))));
    }
}
