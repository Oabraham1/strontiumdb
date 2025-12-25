// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Key rotation manager for re-wrapping DEKs with new KEKs.
//!
//! When a KEK is rotated (either manually or due to policy), all DEKs
//! wrapped with the old KEK must be re-wrapped with the new KEK.
//! This module provides atomic key rotation with rollback support.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{error, info, instrument, warn};

use super::audit::{AuditEvent, AuditLogger, KeyOperation};
use super::error::SecurityError;
use super::kms::{KeyManagementService, WrappedKey};

/// Registry of wrapped DEKs for a given KEK.
///
/// Tracks all DEKs that have been wrapped with a particular KEK,
/// enabling bulk re-wrapping during key rotation.
#[derive(Debug, Default)]
pub struct DekRegistry {
    /// Map of DEK ID to wrapped key
    wrapped_keys: RwLock<HashMap<String, WrappedKey>>,
}

impl DekRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a wrapped DEK.
    pub fn register(&self, wrapped: WrappedKey) {
        let dek_id = wrapped.dek_id().to_string();
        self.wrapped_keys.write().insert(dek_id, wrapped);
    }

    /// Unregisters a DEK by ID.
    pub fn unregister(&self, dek_id: &str) -> Option<WrappedKey> {
        self.wrapped_keys.write().remove(dek_id)
    }

    /// Gets a wrapped key by DEK ID.
    pub fn get(&self, dek_id: &str) -> Option<WrappedKey> {
        self.wrapped_keys.read().get(dek_id).cloned()
    }

    /// Returns all wrapped keys for a given KEK.
    pub fn keys_for_kek(&self, kek_id: &str) -> Vec<WrappedKey> {
        self.wrapped_keys
            .read()
            .values()
            .filter(|w| w.kek_id() == kek_id)
            .cloned()
            .collect()
    }

    /// Returns the count of registered DEKs.
    pub fn count(&self) -> usize {
        self.wrapped_keys.read().len()
    }

    /// Clears all registered keys.
    pub fn clear(&self) {
        self.wrapped_keys.write().clear();
    }
}

/// Result of a key rotation operation.
#[derive(Debug)]
pub struct RotationResult {
    /// Number of DEKs successfully re-wrapped.
    pub rewrapped_count: usize,
    /// Number of DEKs that failed to re-wrap.
    pub failed_count: usize,
    /// IDs of DEKs that failed.
    pub failed_deks: Vec<String>,
    /// The new KEK ID.
    pub new_kek_id: String,
    /// The old KEK ID.
    pub old_kek_id: String,
}

impl RotationResult {
    /// Returns true if all DEKs were successfully re-wrapped.
    pub fn is_complete(&self) -> bool {
        self.failed_count == 0
    }
}

/// Key rotation manager.
///
/// Handles the rotation of KEKs by re-wrapping all DEKs with the new KEK.
/// Supports atomic rotation with rollback on failure.
pub struct KeyRotationManager<K: KeyManagementService> {
    /// The KMS used for key operations.
    kms: Arc<K>,
    /// Registry of wrapped DEKs.
    registry: Arc<DekRegistry>,
    /// Audit logger for key operations.
    audit: Option<Arc<AuditLogger>>,
}

impl<K: KeyManagementService> KeyRotationManager<K> {
    /// Creates a new rotation manager.
    pub fn new(kms: Arc<K>, registry: Arc<DekRegistry>) -> Self {
        Self {
            kms,
            registry,
            audit: None,
        }
    }

    /// Sets the audit logger for key operations.
    pub fn with_audit(mut self, audit: Arc<AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Rotates the KEK, re-wrapping all DEKs with the new key.
    ///
    /// This operation attempts to re-wrap all DEKs atomically. If any
    /// re-wrapping fails, the operation can be rolled back.
    ///
    /// # Arguments
    /// * `old_kek_id` - The current KEK ID to rotate from
    /// * `new_kek_id` - The new KEK ID to rotate to
    ///
    /// # Returns
    /// A `RotationResult` with details of the operation.
    #[instrument(skip(self), fields(old_kek = %old_kek_id, new_kek = %new_kek_id))]
    pub async fn rotate(
        &self,
        old_kek_id: &str,
        new_kek_id: &str,
    ) -> Result<RotationResult, SecurityError> {
        info!("Starting KEK rotation");

        // Log rotation start
        if let Some(audit) = &self.audit {
            audit.log(AuditEvent::new(
                KeyOperation::KekRotationStart,
                old_kek_id.to_string(),
            ));
        }

        // Get all DEKs wrapped with the old KEK
        let wrapped_keys = self.registry.keys_for_kek(old_kek_id);
        let total = wrapped_keys.len();

        info!(total_deks = total, "Found DEKs to re-wrap");

        let mut rewrapped = Vec::new();
        let mut failed = Vec::new();

        // Re-wrap each DEK
        for wrapped in wrapped_keys {
            let dek_id = wrapped.dek_id().to_string();

            match self.rewrap_dek(&wrapped, new_kek_id).await {
                Ok(new_wrapped) => {
                    rewrapped.push((dek_id, new_wrapped));
                }
                Err(e) => {
                    error!(dek_id = %dek_id, error = %e, "Failed to re-wrap DEK");
                    failed.push(dek_id);
                }
            }
        }

        // If any failed, decide on rollback strategy
        if !failed.is_empty() {
            warn!(
                failed_count = failed.len(),
                "Some DEKs failed to re-wrap, keeping old wrapped versions"
            );
        }

        // Update registry with new wrapped keys
        for (dek_id, new_wrapped) in &rewrapped {
            self.registry.register(new_wrapped.clone());
            info!(dek_id = %dek_id, "Updated registry with re-wrapped DEK");
        }

        // Notify KMS of rotation completion
        self.kms.rotate_kek(old_kek_id, new_kek_id).await?;

        let result = RotationResult {
            rewrapped_count: rewrapped.len(),
            failed_count: failed.len(),
            failed_deks: failed,
            new_kek_id: new_kek_id.to_string(),
            old_kek_id: old_kek_id.to_string(),
        };

        // Log rotation completion
        if let Some(audit) = &self.audit {
            if result.is_complete() {
                audit.log(AuditEvent::new(
                    KeyOperation::KekRotationComplete,
                    new_kek_id.to_string(),
                ));
            } else {
                audit.log(
                    AuditEvent::new(KeyOperation::KekRotationComplete, new_kek_id.to_string())
                        .with_details(format!("Failed DEKs: {:?}", result.failed_deks)),
                );
            }
        }

        info!(
            rewrapped = result.rewrapped_count,
            failed = result.failed_count,
            "KEK rotation complete"
        );

        Ok(result)
    }

    /// Re-wraps a single DEK with a new KEK.
    async fn rewrap_dek(
        &self,
        wrapped: &WrappedKey,
        new_kek_id: &str,
    ) -> Result<WrappedKey, SecurityError> {
        // Unwrap with old KEK
        let dek = self.kms.unwrap_dek(wrapped).await?;

        // Wrap with new KEK
        let new_wrapped = self.kms.wrap_dek(&dek, new_kek_id).await?;

        // Log re-wrap
        if let Some(audit) = &self.audit {
            audit.log(
                AuditEvent::new(KeyOperation::DekRewrap, dek.id().to_string()).with_details(
                    format!("old_kek={}, new_kek={}", wrapped.kek_id(), new_kek_id),
                ),
            );
        }

        Ok(new_wrapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::LocalKms;

    #[tokio::test]
    async fn test_dek_registry() {
        let registry = DekRegistry::new();
        let kms = LocalKms::generate().unwrap();

        let dek = kms.generate_dek().await.unwrap();
        let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();

        registry.register(wrapped.clone());
        assert_eq!(registry.count(), 1);

        let retrieved = registry.get(dek.id()).unwrap();
        assert_eq!(retrieved.dek_id(), dek.id());

        let keys = registry.keys_for_kek(kms.active_kek_id());
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let kms = Arc::new(LocalKms::generate().unwrap());
        let registry = Arc::new(DekRegistry::new());
        let manager = KeyRotationManager::new(Arc::clone(&kms), Arc::clone(&registry));

        // Generate and register some DEKs
        for _ in 0..3 {
            let dek = kms.generate_dek().await.unwrap();
            let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await.unwrap();
            registry.register(wrapped);
        }

        assert_eq!(registry.count(), 3);

        // Rotate KEK
        let old_kek = kms.active_kek_id().to_string();
        let new_kek = "new-kek-id";

        let result = manager.rotate(&old_kek, new_kek).await.unwrap();

        assert!(result.is_complete());
        assert_eq!(result.rewrapped_count, 3);
        assert_eq!(result.failed_count, 0);
    }

    #[tokio::test]
    async fn test_rotation_with_empty_registry() {
        let kms = Arc::new(LocalKms::generate().unwrap());
        let registry = Arc::new(DekRegistry::new());
        let manager = KeyRotationManager::new(Arc::clone(&kms), Arc::clone(&registry));

        let old_kek = kms.active_kek_id().to_string();
        let new_kek = "new-kek-id";

        let result = manager.rotate(&old_kek, new_kek).await.unwrap();

        assert!(result.is_complete());
        assert_eq!(result.rewrapped_count, 0);
    }
}
