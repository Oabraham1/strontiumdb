// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS integration for production key management.
//!
//! Uses AWS KMS for KEK storage and DEK wrapping. The KEK never
//! leaves AWS KMS - all wrapping/unwrapping happens server-side.

use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::Client as KmsClient;
use parking_lot::RwLock;
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{info, instrument, warn};

use super::error::SecurityError;
use super::kms::{DataEncryptionKey, KeyManagementService, WrappedKey, AES_256_KEY_SIZE};

/// AWS KMS-backed Key Management Service.
///
/// Uses AWS KMS for key encryption key (KEK) management.
/// DEKs are generated locally and wrapped/unwrapped by AWS KMS.
pub struct AwsKms {
    client: KmsClient,
    key_id: String,
    rng: SystemRandom,
    /// Cache of unwrapped DEKs for performance
    dek_cache: RwLock<lru::LruCache<String, Arc<DataEncryptionKey>>>,
}

impl AwsKms {
    /// Creates a new AWS KMS client.
    ///
    /// # Arguments
    /// * `key_id` - The ARN or alias of the KMS key to use as KEK
    /// * `cache_size` - Number of DEKs to cache in memory
    pub async fn new(key_id: String, cache_size: usize) -> Result<Self, SecurityError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = KmsClient::new(&config);

        // Verify the key exists and we have access
        client
            .describe_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| SecurityError::KeyNotFound(format!("AWS KMS key {}: {}", key_id, e)))?;

        info!(key_id = %key_id, "Connected to AWS KMS");

        Ok(Self {
            client,
            key_id,
            rng: SystemRandom::new(),
            dek_cache: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
            )),
        })
    }

    /// Creates from an existing AWS SDK config.
    pub fn from_config(config: &aws_config::SdkConfig, key_id: String, cache_size: usize) -> Self {
        let client = KmsClient::new(config);
        Self {
            client,
            key_id,
            rng: SystemRandom::new(),
            dek_cache: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
            )),
        }
    }
}

#[async_trait]
impl KeyManagementService for AwsKms {
    #[instrument(skip(self), fields(kms = "aws"))]
    async fn generate_dek(&self) -> Result<DataEncryptionKey, SecurityError> {
        let mut key = [0u8; AES_256_KEY_SIZE];
        self.rng
            .fill(&mut key)
            .map_err(|_| SecurityError::KeyGeneration("RNG failure".into()))?;

        let id = uuid::Uuid::new_v4().to_string();
        info!(dek_id = %id, "Generated new DEK");

        Ok(DataEncryptionKey::new(key, id))
    }

    #[instrument(skip(self, dek), fields(kms = "aws", dek_id = %dek.id()))]
    async fn wrap_dek(
        &self,
        dek: &DataEncryptionKey,
        _kek_id: &str,
    ) -> Result<WrappedKey, SecurityError> {
        let plaintext = Blob::new(dek.key().to_vec());
        let dek_id = dek.id().to_string();

        let output = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(plaintext)
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "AWS KMS encrypt failed");
                SecurityError::Encryption(format!("AWS KMS encrypt: {}", e))
            })?;

        let ciphertext = output
            .ciphertext_blob()
            .ok_or_else(|| SecurityError::Encryption("No ciphertext from KMS".into()))?
            .as_ref()
            .to_vec();

        info!(dek_id = %dek_id, ciphertext_len = ciphertext.len(), "Wrapped DEK with AWS KMS");

        Ok(WrappedKey::new(ciphertext, self.key_id.clone(), dek_id))
    }

    #[instrument(skip(self, wrapped), fields(kms = "aws", dek_id = %wrapped.dek_id()))]
    async fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey, SecurityError> {
        // Check cache first
        {
            let cache = self.dek_cache.read();
            if let Some(dek) = cache.peek(wrapped.dek_id()) {
                info!(dek_id = %wrapped.dek_id(), "DEK cache hit");
                return Ok(DataEncryptionKey::new(*dek.key(), dek.id().to_string()));
            }
        }

        let ciphertext = Blob::new(wrapped.ciphertext().to_vec());

        let output = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(ciphertext)
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "AWS KMS decrypt failed");
                SecurityError::Decryption(format!("AWS KMS decrypt: {}", e))
            })?;

        let plaintext = output
            .plaintext()
            .ok_or_else(|| SecurityError::Decryption("No plaintext from KMS".into()))?
            .as_ref();

        if plaintext.len() != AES_256_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                got: plaintext.len(),
            });
        }

        let mut key = [0u8; AES_256_KEY_SIZE];
        key.copy_from_slice(plaintext);

        let dek = DataEncryptionKey::new(key, wrapped.dek_id().to_string());

        // Cache the unwrapped DEK
        {
            let mut cache = self.dek_cache.write();
            cache.put(wrapped.dek_id().to_string(), Arc::new(dek.clone()));
        }

        info!(dek_id = %wrapped.dek_id(), "Unwrapped DEK from AWS KMS");

        Ok(dek)
    }

    #[instrument(skip(self), fields(kms = "aws"))]
    async fn rotate_kek(&self, old_kek_id: &str, new_kek_id: &str) -> Result<(), SecurityError> {
        // AWS KMS handles key rotation automatically when enabled
        // This method would re-encrypt DEKs with a new key if needed

        if old_kek_id != self.key_id {
            return Err(SecurityError::KeyNotFound(format!(
                "Old KEK {} doesn't match current {}",
                old_kek_id, self.key_id
            )));
        }

        // For AWS KMS, key rotation is typically handled by enabling
        // automatic key rotation on the CMK, or by creating a new CMK
        // and re-wrapping all DEKs

        warn!(
            old_kek = %old_kek_id,
            new_kek = %new_kek_id,
            "KEK rotation requested - ensure AWS KMS key rotation is enabled"
        );

        // Clear DEK cache since KEK is rotating
        self.dek_cache.write().clear();

        Ok(())
    }

    fn active_kek_id(&self) -> &str {
        &self.key_id
    }
}

/// Generate a data key directly from AWS KMS.
///
/// This uses KMS GenerateDataKey which is more secure as the
/// plaintext key is generated inside the HSM and never exists
/// outside of AWS infrastructure until returned.
///
/// # Arguments
/// * `client` - The AWS KMS client
/// * `key_id` - The KMS key ID or alias to use for wrapping
///
/// # Returns
/// A tuple of (DEK, WrappedKey) where the DEK contains the plaintext
/// key and the WrappedKey contains the KMS-encrypted ciphertext.
pub async fn generate_data_key_from_kms(
    client: &KmsClient,
    key_id: &str,
) -> Result<(DataEncryptionKey, WrappedKey), SecurityError> {
    let output = client
        .generate_data_key()
        .key_id(key_id)
        .key_spec(DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| SecurityError::KeyGeneration(format!("AWS KMS GenerateDataKey: {}", e)))?;

    let plaintext = output
        .plaintext()
        .ok_or_else(|| SecurityError::KeyGeneration("No plaintext from KMS".into()))?
        .as_ref();

    let ciphertext = output
        .ciphertext_blob()
        .ok_or_else(|| SecurityError::KeyGeneration("No ciphertext from KMS".into()))?
        .as_ref()
        .to_vec();

    if plaintext.len() != AES_256_KEY_SIZE {
        return Err(SecurityError::InvalidKeyLength {
            expected: AES_256_KEY_SIZE,
            got: plaintext.len(),
        });
    }

    let mut key = [0u8; AES_256_KEY_SIZE];
    key.copy_from_slice(plaintext);

    let dek_id = uuid::Uuid::new_v4().to_string();
    let dek = DataEncryptionKey::new(key, dek_id.clone());
    let wrapped = WrappedKey::new(ciphertext, key_id.to_string(), dek_id);

    Ok((dek, wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests require AWS credentials and a KMS key
    // Run with: AWS_KMS_KEY_ID=alias/your-key cargo test aws_kms --features aws-kms-tests

    #[tokio::test]
    #[ignore = "requires AWS credentials"]
    async fn test_aws_kms_wrap_unwrap() {
        let key_id = std::env::var("AWS_KMS_KEY_ID").expect("Set AWS_KMS_KEY_ID to run this test");

        let kms = AwsKms::new(key_id, 100).await.unwrap();

        let dek = kms.generate_dek().await.unwrap();
        let original_key = *dek.key();

        let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();
        let unwrapped = kms.unwrap_dek(&wrapped).await.unwrap();

        assert_eq!(unwrapped.key(), &original_key);
    }

    #[tokio::test]
    #[ignore = "requires AWS credentials"]
    async fn test_aws_kms_generate_data_key() {
        let key_id = std::env::var("AWS_KMS_KEY_ID").expect("Set AWS_KMS_KEY_ID to run this test");

        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = KmsClient::new(&config);

        let (dek, wrapped) = generate_data_key_from_kms(&client, &key_id).await.unwrap();

        assert_eq!(dek.key().len(), AES_256_KEY_SIZE);
        assert!(!wrapped.ciphertext().is_empty());
        assert_eq!(wrapped.kek_id(), key_id);
    }
}
