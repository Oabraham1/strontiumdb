// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Azure Key Vault integration for production key management.
//!
//! Uses Azure Key Vault for KEK storage and DEK wrapping. The KEK never
//! leaves Azure Key Vault - all wrapping/unwrapping happens server-side.

use std::sync::Arc;

use async_trait::async_trait;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_keys::{
    models::{
        EncryptionAlgorithm, KeyClientUnwrapKeyOptions, KeyClientWrapKeyOptions,
        KeyOperationParameters,
    },
    KeyClient,
};
use parking_lot::RwLock;
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{info, instrument, warn};

use super::error::SecurityError;
use super::kms::{DataEncryptionKey, KeyManagementService, WrappedKey, AES_256_KEY_SIZE};

/// Azure Key Vault-backed Key Management Service.
///
/// Uses Azure Key Vault for key encryption key (KEK) management.
/// DEKs are generated locally and wrapped/unwrapped by Azure Key Vault.
pub struct AzureKms {
    /// Vault URL for creating new clients
    vault_url: String,
    key_name: String,
    key_version: Option<String>,
    rng: SystemRandom,
    /// Cache of unwrapped DEKs for performance
    dek_cache: RwLock<lru::LruCache<String, Arc<DataEncryptionKey>>>,
}

impl AzureKms {
    /// Creates a new Azure Key Vault client.
    ///
    /// # Arguments
    /// * `vault_url` - The URL of the Key Vault (e.g., `https://myvault.vault.azure.net`)
    /// * `key_name` - The name of the key to use as KEK
    /// * `key_version` - Optional specific key version (uses latest if None)
    /// * `cache_size` - Number of DEKs to cache in memory
    ///
    /// # Environment
    /// Uses Azure Developer Tools credentials (Azure CLI, Azure Developer CLI, etc.)
    pub async fn new(
        vault_url: String,
        key_name: String,
        key_version: Option<String>,
        cache_size: usize,
    ) -> Result<Self, SecurityError> {
        let credential = DeveloperToolsCredential::new(None)
            .map_err(|e| SecurityError::KeyGeneration(format!("Azure credential error: {}", e)))?;

        let client = KeyClient::new(&vault_url, credential, None).map_err(|e| {
            SecurityError::KeyNotFound(format!("Failed to create Key Vault client: {}", e))
        })?;

        // Verify the key exists by attempting to get it
        let get_options = azure_security_keyvault_keys::models::KeyClientGetKeyOptions {
            key_version: key_version.clone(),
            ..Default::default()
        };
        client
            .get_key(&key_name, Some(get_options))
            .await
            .map_err(|e| {
                SecurityError::KeyNotFound(format!("Azure Key Vault key {}: {}", key_name, e))
            })?;

        info!(vault_url = %vault_url, key_name = %key_name, "Connected to Azure Key Vault");

        Ok(Self {
            vault_url,
            key_name,
            key_version,
            rng: SystemRandom::new(),
            dek_cache: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
            )),
        })
    }

    /// Create a fresh KeyClient for operations
    fn create_client(&self) -> Result<KeyClient, SecurityError> {
        let credential = DeveloperToolsCredential::new(None)
            .map_err(|e| SecurityError::KeyGeneration(format!("Azure credential error: {}", e)))?;

        KeyClient::new(&self.vault_url, credential, None).map_err(|e| {
            SecurityError::Encryption(format!("Failed to create Key Vault client: {}", e))
        })
    }

    /// Get the Key Vault key identifier for this KMS instance.
    fn key_id(&self) -> String {
        match &self.key_version {
            Some(version) => format!("{}/{}", self.key_name, version),
            None => self.key_name.clone(),
        }
    }
}

#[async_trait]
impl KeyManagementService for AzureKms {
    #[instrument(skip(self), fields(kms = "azure"))]
    async fn generate_dek(&self) -> Result<DataEncryptionKey, SecurityError> {
        let mut key = [0u8; AES_256_KEY_SIZE];
        self.rng
            .fill(&mut key)
            .map_err(|_| SecurityError::KeyGeneration("RNG failure".into()))?;

        let id = uuid::Uuid::new_v4().to_string();
        info!(dek_id = %id, "Generated new DEK");

        Ok(DataEncryptionKey::new(key, id))
    }

    #[instrument(skip(self, dek), fields(kms = "azure", dek_id = %dek.id()))]
    async fn wrap_dek(
        &self,
        dek: &DataEncryptionKey,
        _kek_id: &str,
    ) -> Result<WrappedKey, SecurityError> {
        let client = self.create_client()?;
        let plaintext = dek.key().to_vec();
        let dek_id = dek.id().to_string();

        let parameters = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(plaintext),
            iv: None,
            additional_authenticated_data: None,
            authentication_tag: None,
        };

        let options = KeyClientWrapKeyOptions {
            key_version: self.key_version.clone(),
            ..Default::default()
        };

        let response = client
            .wrap_key(
                &self.key_name,
                parameters.try_into().map_err(|e: azure_core::Error| {
                    SecurityError::Encryption(format!("Azure Key Vault wrap_key params: {}", e))
                })?,
                Some(options),
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "Azure Key Vault wrap_key failed");
                SecurityError::Encryption(format!("Azure Key Vault wrap_key: {}", e))
            })?
            .into_model()
            .map_err(|e| {
                SecurityError::Encryption(format!("Azure Key Vault wrap_key response: {}", e))
            })?;

        let ciphertext = response.result.ok_or_else(|| {
            SecurityError::Encryption("No ciphertext from Azure Key Vault".into())
        })?;

        info!(dek_id = %dek_id, ciphertext_len = ciphertext.len(), "Wrapped DEK with Azure Key Vault");

        Ok(WrappedKey::new(ciphertext, self.key_id(), dek_id))
    }

    #[instrument(skip(self, wrapped), fields(kms = "azure", dek_id = %wrapped.dek_id()))]
    async fn unwrap_dek(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey, SecurityError> {
        // Check cache first
        {
            let cache = self.dek_cache.read();
            if let Some(dek) = cache.peek(wrapped.dek_id()) {
                info!(dek_id = %wrapped.dek_id(), "DEK cache hit");
                return Ok(DataEncryptionKey::new(*dek.key(), dek.id().to_string()));
            }
        }

        let client = self.create_client()?;
        let ciphertext = wrapped.ciphertext().to_vec();

        let parameters = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(ciphertext),
            iv: None,
            additional_authenticated_data: None,
            authentication_tag: None,
        };

        let options = KeyClientUnwrapKeyOptions {
            key_version: self.key_version.clone(),
            ..Default::default()
        };

        let response = client
            .unwrap_key(
                &self.key_name,
                parameters.try_into().map_err(|e: azure_core::Error| {
                    SecurityError::Decryption(format!("Azure Key Vault unwrap_key params: {}", e))
                })?,
                Some(options),
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "Azure Key Vault unwrap_key failed");
                SecurityError::Decryption(format!("Azure Key Vault unwrap_key: {}", e))
            })?
            .into_model()
            .map_err(|e| {
                SecurityError::Decryption(format!("Azure Key Vault unwrap_key response: {}", e))
            })?;

        let plaintext = response
            .result
            .ok_or_else(|| SecurityError::Decryption("No plaintext from Azure Key Vault".into()))?;

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

        info!(dek_id = %wrapped.dek_id(), "Unwrapped DEK from Azure Key Vault");

        Ok(dek)
    }

    #[instrument(skip(self), fields(kms = "azure"))]
    async fn rotate_kek(&self, old_kek_id: &str, new_kek_id: &str) -> Result<(), SecurityError> {
        // Azure Key Vault handles key rotation through key versions
        // This method would re-wrap DEKs with a new key version if needed

        if old_kek_id != self.key_id() {
            return Err(SecurityError::KeyNotFound(format!(
                "Old KEK {} doesn't match current {}",
                old_kek_id,
                self.key_id()
            )));
        }

        // For Azure Key Vault, key rotation is done by creating a new key version
        // and re-wrapping all DEKs with the new version

        warn!(
            old_kek = %old_kek_id,
            new_kek = %new_kek_id,
            "KEK rotation requested - ensure Azure Key Vault key version is updated"
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

    // Integration tests require Azure credentials and a Key Vault
    // Run with: AZURE_KEY_VAULT_URL=https://myvault.vault.azure.net AZURE_KEY_NAME=mykey cargo test azure_kms --features azure-kms

    #[tokio::test]
    #[ignore = "requires Azure credentials"]
    async fn test_azure_kms_wrap_unwrap() {
        let vault_url =
            std::env::var("AZURE_KEY_VAULT_URL").expect("Set AZURE_KEY_VAULT_URL to run this test");
        let key_name =
            std::env::var("AZURE_KEY_NAME").expect("Set AZURE_KEY_NAME to run this test");

        let kms = AzureKms::new(vault_url, key_name, None, 100).await.unwrap();

        let dek = kms.generate_dek().await.unwrap();
        let original_key = *dek.key();

        let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();
        let unwrapped = kms.unwrap_dek(&wrapped).await.unwrap();

        assert_eq!(unwrapped.key(), &original_key);
    }
}
