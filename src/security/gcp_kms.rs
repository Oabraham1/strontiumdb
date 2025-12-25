// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! GCP Cloud KMS integration for production key management.
//!
//! Uses GCP Cloud KMS for KEK storage and DEK wrapping. The KEK never
//! leaves Cloud KMS - all wrapping/unwrapping happens server-side.

use std::sync::Arc;

use async_trait::async_trait;
use google_cloud_kms::client::Client;
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest};
use parking_lot::RwLock;
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{info, instrument, warn};

use super::error::SecurityError;
use super::kms::{DataEncryptionKey, KeyManagementService, WrappedKey, AES_256_KEY_SIZE};

/// GCP Cloud KMS-backed Key Management Service.
///
/// Uses GCP Cloud KMS for key encryption key (KEK) management.
/// DEKs are generated locally and encrypted/decrypted by Cloud KMS.
pub struct GcpKms {
    /// Shared client for KMS operations
    client: Arc<Client>,
    /// Full resource name: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}
    key_name: String,
    rng: SystemRandom,
    /// Cache of unwrapped DEKs for performance
    dek_cache: RwLock<lru::LruCache<String, Arc<DataEncryptionKey>>>,
}

impl GcpKms {
    /// Creates a new GCP Cloud KMS client.
    ///
    /// # Arguments
    /// * `key_name` - Full resource name of the crypto key:
    ///   `projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}`
    /// * `cache_size` - Number of DEKs to cache in memory
    ///
    /// # Environment
    /// Uses `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_APPLICATION_CREDENTIALS_JSON`
    /// for authentication, or the GCP metadata server if running on GCP.
    pub async fn new(key_name: String, cache_size: usize) -> Result<Self, SecurityError> {
        let config = google_cloud_kms::client::ClientConfig::default()
            .with_auth()
            .await
            .map_err(|e| SecurityError::KeyGeneration(format!("GCP auth error: {}", e)))?;

        // Create the client
        let client = Client::new(config)
            .await
            .map_err(|e| SecurityError::KeyGeneration(format!("GCP client error: {}", e)))?;

        // Verify the key exists by attempting to encrypt a small test value
        // This will fail if the key doesn't exist or we don't have permission
        let test_request = EncryptRequest {
            name: key_name.clone(),
            plaintext: vec![0u8; 16],
            additional_authenticated_data: vec![],
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        client.encrypt(test_request, None).await.map_err(|e| {
            SecurityError::KeyNotFound(format!("GCP Cloud KMS key {}: {}", key_name, e))
        })?;

        info!(key_name = %key_name, "Connected to GCP Cloud KMS");

        Ok(Self {
            client: Arc::new(client),
            key_name,
            rng: SystemRandom::new(),
            dek_cache: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
            )),
        })
    }

    /// Creates from an existing GCP client.
    pub fn from_client(client: Arc<Client>, key_name: String, cache_size: usize) -> Self {
        Self {
            client,
            key_name,
            rng: SystemRandom::new(),
            dek_cache: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
            )),
        }
    }

    /// Parse a full key resource name into components.
    pub fn parse_key_name(key_name: &str) -> Option<(String, String, String, String)> {
        // projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}
        let parts: Vec<&str> = key_name.split('/').collect();
        if parts.len() >= 8
            && parts[0] == "projects"
            && parts[2] == "locations"
            && parts[4] == "keyRings"
            && parts[6] == "cryptoKeys"
        {
            Some((
                parts[1].to_string(),
                parts[3].to_string(),
                parts[5].to_string(),
                parts[7].to_string(),
            ))
        } else {
            None
        }
    }
}

#[async_trait]
impl KeyManagementService for GcpKms {
    #[instrument(skip(self), fields(kms = "gcp"))]
    async fn generate_dek(&self) -> Result<DataEncryptionKey, SecurityError> {
        let mut key = [0u8; AES_256_KEY_SIZE];
        self.rng
            .fill(&mut key)
            .map_err(|_| SecurityError::KeyGeneration("RNG failure".into()))?;

        let id = uuid::Uuid::new_v4().to_string();
        info!(dek_id = %id, "Generated new DEK");

        Ok(DataEncryptionKey::new(key, id))
    }

    #[instrument(skip(self, dek), fields(kms = "gcp", dek_id = %dek.id()))]
    async fn wrap_dek(
        &self,
        dek: &DataEncryptionKey,
        _kek_id: &str,
    ) -> Result<WrappedKey, SecurityError> {
        let plaintext = dek.key().to_vec();
        let dek_id = dek.id().to_string();

        let request = EncryptRequest {
            name: self.key_name.clone(),
            plaintext,
            additional_authenticated_data: vec![],
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let output = self.client.encrypt(request, None).await.map_err(|e| {
            warn!(error = %e, "GCP Cloud KMS encrypt failed");
            SecurityError::Encryption(format!("GCP Cloud KMS encrypt: {}", e))
        })?;

        let ciphertext = output.ciphertext;

        info!(dek_id = %dek_id, ciphertext_len = ciphertext.len(), "Wrapped DEK with GCP Cloud KMS");

        Ok(WrappedKey::new(ciphertext, self.key_name.clone(), dek_id))
    }

    #[instrument(skip(self, wrapped), fields(kms = "gcp", dek_id = %wrapped.dek_id()))]
    async fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey, SecurityError> {
        // Check cache first
        {
            let cache = self.dek_cache.read();
            if let Some(dek) = cache.peek(wrapped.dek_id()) {
                info!(dek_id = %wrapped.dek_id(), "DEK cache hit");
                return Ok(DataEncryptionKey::new(*dek.key(), dek.id().to_string()));
            }
        }

        let ciphertext = wrapped.ciphertext().to_vec();

        let request = DecryptRequest {
            name: self.key_name.clone(),
            ciphertext,
            additional_authenticated_data: vec![],
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let output = self.client.decrypt(request, None).await.map_err(|e| {
            warn!(error = %e, "GCP Cloud KMS decrypt failed");
            SecurityError::Decryption(format!("GCP Cloud KMS decrypt: {}", e))
        })?;

        let plaintext = output.plaintext;

        if plaintext.len() != AES_256_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                got: plaintext.len(),
            });
        }

        let mut key = [0u8; AES_256_KEY_SIZE];
        key.copy_from_slice(&plaintext);

        let dek = DataEncryptionKey::new(key, wrapped.dek_id().to_string());

        // Cache the unwrapped DEK
        {
            let mut cache = self.dek_cache.write();
            cache.put(wrapped.dek_id().to_string(), Arc::new(dek.clone()));
        }

        info!(dek_id = %wrapped.dek_id(), "Unwrapped DEK from GCP Cloud KMS");

        Ok(dek)
    }

    #[instrument(skip(self), fields(kms = "gcp"))]
    async fn rotate_kek(&self, old_kek_id: &str, new_kek_id: &str) -> Result<(), SecurityError> {
        // GCP Cloud KMS handles key rotation through key versions
        // When automatic rotation is enabled, Cloud KMS automatically
        // creates new key versions on the specified schedule

        if old_kek_id != self.key_name {
            return Err(SecurityError::KeyNotFound(format!(
                "Old KEK {} doesn't match current {}",
                old_kek_id, self.key_name
            )));
        }

        // For GCP Cloud KMS, key rotation creates a new primary version
        // Old ciphertext can still be decrypted, but new encryption uses
        // the new primary version automatically

        warn!(
            old_kek = %old_kek_id,
            new_kek = %new_kek_id,
            "KEK rotation requested - ensure GCP Cloud KMS rotation is configured"
        );

        // Clear DEK cache since KEK is rotating
        self.dek_cache.write().clear();

        Ok(())
    }

    fn active_kek_id(&self) -> &str {
        &self.key_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests require GCP credentials and a Cloud KMS key
    // Run with:
    //   GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json \
    //   GCP_KMS_KEY_NAME=projects/myproject/locations/us-central1/keyRings/myring/cryptoKeys/mykey \
    //   cargo test gcp_kms --features gcp-kms

    #[tokio::test]
    #[ignore = "requires GCP credentials"]
    async fn test_gcp_kms_wrap_unwrap() {
        let key_name =
            std::env::var("GCP_KMS_KEY_NAME").expect("Set GCP_KMS_KEY_NAME to run this test");

        let kms = GcpKms::new(key_name, 100).await.unwrap();

        let dek = kms.generate_dek().await.unwrap();
        let original_key = *dek.key();

        let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();
        let unwrapped = kms.unwrap_dek(&wrapped).await.unwrap();

        assert_eq!(unwrapped.key(), &original_key);
    }

    #[test]
    fn test_parse_key_name() {
        let key_name = "projects/myproject/locations/us-central1/keyRings/myring/cryptoKeys/mykey";
        let (project, location, key_ring, key) = GcpKms::parse_key_name(key_name).unwrap();

        assert_eq!(project, "myproject");
        assert_eq!(location, "us-central1");
        assert_eq!(key_ring, "myring");
        assert_eq!(key, "mykey");
    }

    #[test]
    fn test_parse_invalid_key_name() {
        assert!(GcpKms::parse_key_name("invalid").is_none());
        assert!(GcpKms::parse_key_name("projects/foo").is_none());
    }
}
