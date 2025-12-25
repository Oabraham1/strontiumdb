// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Audit logging for security-sensitive key operations.
//!
//! Provides structured audit events for all KMS operations, enabling
//! compliance with security standards like SOC 2, PCI-DSS, and HIPAA.
//!
//! # Event Categories
//!
//! - **DEK Operations**: Generate, wrap, unwrap
//! - **KEK Operations**: Rotation start/complete
//! - **Access Events**: Key access attempts, failures
//!
//! # Example
//!
//! ```rust,no_run
//! use strontiumdb::security::audit::{AuditLogger, AuditEvent, KeyOperation};
//!
//! let logger = AuditLogger::new("strontiumdb-kms");
//! logger.log(AuditEvent::new(KeyOperation::DekGenerate, "dek-123".into()));
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use tracing::{info, warn};

/// Types of key operations that are audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOperation {
    /// A new DEK was generated.
    DekGenerate,
    /// A DEK was wrapped (encrypted) with a KEK.
    DekWrap,
    /// A DEK was unwrapped (decrypted) with a KEK.
    DekUnwrap,
    /// A DEK was re-wrapped with a new KEK during rotation.
    DekRewrap,
    /// A DEK was destroyed/deleted.
    DekDestroy,
    /// KEK rotation has started.
    KekRotationStart,
    /// KEK rotation has completed.
    KekRotationComplete,
    /// A key access was denied.
    AccessDenied,
    /// A key operation failed.
    OperationFailed,
}

impl KeyOperation {
    /// Returns the operation name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyOperation::DekGenerate => "dek_generate",
            KeyOperation::DekWrap => "dek_wrap",
            KeyOperation::DekUnwrap => "dek_unwrap",
            KeyOperation::DekRewrap => "dek_rewrap",
            KeyOperation::DekDestroy => "dek_destroy",
            KeyOperation::KekRotationStart => "kek_rotation_start",
            KeyOperation::KekRotationComplete => "kek_rotation_complete",
            KeyOperation::AccessDenied => "access_denied",
            KeyOperation::OperationFailed => "operation_failed",
        }
    }

    /// Returns the severity level for this operation.
    pub fn severity(&self) -> AuditSeverity {
        match self {
            KeyOperation::DekGenerate => AuditSeverity::Info,
            KeyOperation::DekWrap => AuditSeverity::Info,
            KeyOperation::DekUnwrap => AuditSeverity::Info,
            KeyOperation::DekRewrap => AuditSeverity::Info,
            KeyOperation::DekDestroy => AuditSeverity::Warning,
            KeyOperation::KekRotationStart => AuditSeverity::Warning,
            KeyOperation::KekRotationComplete => AuditSeverity::Warning,
            KeyOperation::AccessDenied => AuditSeverity::Critical,
            KeyOperation::OperationFailed => AuditSeverity::Error,
        }
    }
}

/// Severity levels for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditSeverity {
    /// Informational event.
    Info,
    /// Warning event - unusual but not critical.
    Warning,
    /// Error event - operation failed.
    Error,
    /// Critical event - security violation.
    Critical,
}

impl AuditSeverity {
    /// Returns the severity as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSeverity::Info => "INFO",
            AuditSeverity::Warning => "WARN",
            AuditSeverity::Error => "ERROR",
            AuditSeverity::Critical => "CRITICAL",
        }
    }
}

/// An audit event for a key operation.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Unique event ID.
    pub event_id: u64,
    /// Timestamp of the event.
    pub timestamp: SystemTime,
    /// The operation that occurred.
    pub operation: KeyOperation,
    /// The key ID involved (DEK or KEK).
    pub key_id: String,
    /// Optional additional details.
    pub details: Option<String>,
    /// Optional source IP or principal.
    pub principal: Option<String>,
    /// Optional error message if operation failed.
    pub error: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event.
    pub fn new(operation: KeyOperation, key_id: String) -> Self {
        static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

        Self {
            event_id: EVENT_COUNTER.fetch_add(1, Ordering::SeqCst),
            timestamp: SystemTime::now(),
            operation,
            key_id,
            details: None,
            principal: None,
            error: None,
        }
    }

    /// Adds details to the event.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Adds the principal (user/service) to the event.
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Adds an error message to the event.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Returns the severity of this event.
    pub fn severity(&self) -> AuditSeverity {
        if self.error.is_some() {
            AuditSeverity::Error
        } else {
            self.operation.severity()
        }
    }
}

/// Audit logger for key operations.
///
/// Thread-safe logger that emits structured audit events using tracing.
/// Can be configured to write to multiple destinations.
pub struct AuditLogger {
    /// Service name for log attribution.
    service_name: String,
    /// Minimum severity to log.
    min_severity: AuditSeverity,
}

impl AuditLogger {
    /// Creates a new audit logger.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            min_severity: AuditSeverity::Info,
        }
    }

    /// Sets the minimum severity level to log.
    pub fn with_min_severity(mut self, severity: AuditSeverity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Logs an audit event.
    pub fn log(&self, event: AuditEvent) {
        if event.severity() < self.min_severity {
            return;
        }

        let timestamp = event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Log using tracing with structured fields
        match event.severity() {
            AuditSeverity::Info => {
                info!(
                    target: "audit",
                    event_id = event.event_id,
                    timestamp = timestamp,
                    service = %self.service_name,
                    operation = event.operation.as_str(),
                    key_id = %event.key_id,
                    details = ?event.details,
                    principal = ?event.principal,
                    "Key operation completed"
                );
            }
            AuditSeverity::Warning => {
                warn!(
                    target: "audit",
                    event_id = event.event_id,
                    timestamp = timestamp,
                    service = %self.service_name,
                    operation = event.operation.as_str(),
                    key_id = %event.key_id,
                    details = ?event.details,
                    principal = ?event.principal,
                    "Key operation warning"
                );
            }
            AuditSeverity::Error | AuditSeverity::Critical => {
                tracing::error!(
                    target: "audit",
                    event_id = event.event_id,
                    timestamp = timestamp,
                    service = %self.service_name,
                    operation = event.operation.as_str(),
                    key_id = %event.key_id,
                    details = ?event.details,
                    principal = ?event.principal,
                    error = ?event.error,
                    severity = event.severity().as_str(),
                    "Key operation failed or denied"
                );
            }
        }
    }

    /// Creates an event and logs it immediately.
    pub fn log_operation(&self, operation: KeyOperation, key_id: impl Into<String>) {
        self.log(AuditEvent::new(operation, key_id.into()));
    }

    /// Logs a failed operation with an error.
    pub fn log_failure(
        &self,
        operation: KeyOperation,
        key_id: impl Into<String>,
        error: impl Into<String>,
    ) {
        self.log(AuditEvent::new(operation, key_id.into()).with_error(error));
    }
}

/// Wraps a KMS with audit logging.
///
/// All operations are logged before and after execution.
pub struct AuditedKms<K: super::kms::KeyManagementService> {
    inner: K,
    audit: AuditLogger,
}

impl<K: super::kms::KeyManagementService> AuditedKms<K> {
    /// Creates a new audited KMS wrapper.
    pub fn new(kms: K, service_name: impl Into<String>) -> Self {
        Self {
            inner: kms,
            audit: AuditLogger::new(service_name),
        }
    }

    /// Returns a reference to the inner KMS.
    pub fn inner(&self) -> &K {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<K: super::kms::KeyManagementService> super::kms::KeyManagementService for AuditedKms<K> {
    async fn generate_dek(
        &self,
    ) -> Result<super::kms::DataEncryptionKey, super::error::SecurityError> {
        let result = self.inner.generate_dek().await;
        match &result {
            Ok(dek) => {
                self.audit
                    .log_operation(KeyOperation::DekGenerate, dek.id());
            }
            Err(e) => {
                self.audit
                    .log_failure(KeyOperation::DekGenerate, "unknown", e.to_string());
            }
        }
        result
    }

    async fn wrap_dek(
        &self,
        dek: &super::kms::DataEncryptionKey,
        kek_id: &str,
    ) -> Result<super::kms::WrappedKey, super::error::SecurityError> {
        let result = self.inner.wrap_dek(dek, kek_id).await;
        match &result {
            Ok(_) => {
                self.audit.log(
                    AuditEvent::new(KeyOperation::DekWrap, dek.id().to_string())
                        .with_details(format!("kek_id={}", kek_id)),
                );
            }
            Err(e) => {
                self.audit
                    .log_failure(KeyOperation::DekWrap, dek.id(), e.to_string());
            }
        }
        result
    }

    async fn unwrap_dek(
        &self,
        wrapped: &super::kms::WrappedKey,
    ) -> Result<super::kms::DataEncryptionKey, super::error::SecurityError> {
        let result = self.inner.unwrap_dek(wrapped).await;
        match &result {
            Ok(dek) => {
                self.audit.log(
                    AuditEvent::new(KeyOperation::DekUnwrap, dek.id().to_string())
                        .with_details(format!("kek_id={}", wrapped.kek_id())),
                );
            }
            Err(e) => {
                self.audit
                    .log_failure(KeyOperation::DekUnwrap, wrapped.dek_id(), e.to_string());
            }
        }
        result
    }

    async fn rotate_kek(
        &self,
        old_kek_id: &str,
        new_kek_id: &str,
    ) -> Result<(), super::error::SecurityError> {
        self.audit.log(
            AuditEvent::new(KeyOperation::KekRotationStart, old_kek_id.to_string())
                .with_details(format!("new_kek_id={}", new_kek_id)),
        );

        let result = self.inner.rotate_kek(old_kek_id, new_kek_id).await;

        match &result {
            Ok(()) => {
                self.audit.log(
                    AuditEvent::new(KeyOperation::KekRotationComplete, new_kek_id.to_string())
                        .with_details(format!("old_kek_id={}", old_kek_id)),
                );
            }
            Err(e) => {
                self.audit.log_failure(
                    KeyOperation::KekRotationComplete,
                    old_kek_id,
                    e.to_string(),
                );
            }
        }
        result
    }

    fn active_kek_id(&self) -> &str {
        self.inner.active_kek_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(KeyOperation::DekGenerate, "dek-123".into());

        assert_eq!(event.operation, KeyOperation::DekGenerate);
        assert_eq!(event.key_id, "dek-123");
        assert!(event.details.is_none());
    }

    #[test]
    fn test_audit_event_with_details() {
        let event = AuditEvent::new(KeyOperation::DekWrap, "dek-456".into())
            .with_details("wrapped with kek-789")
            .with_principal("service-account");

        assert_eq!(event.details, Some("wrapped with kek-789".into()));
        assert_eq!(event.principal, Some("service-account".into()));
    }

    #[test]
    fn test_operation_severity() {
        assert_eq!(KeyOperation::DekGenerate.severity(), AuditSeverity::Info);
        assert_eq!(
            KeyOperation::AccessDenied.severity(),
            AuditSeverity::Critical
        );
        assert_eq!(
            KeyOperation::KekRotationStart.severity(),
            AuditSeverity::Warning
        );
    }

    #[test]
    fn test_event_ids_are_unique() {
        let event1 = AuditEvent::new(KeyOperation::DekGenerate, "dek-1".into());
        let event2 = AuditEvent::new(KeyOperation::DekGenerate, "dek-2".into());

        assert_ne!(event1.event_id, event2.event_id);
    }

    #[test]
    fn test_logger_creation() {
        let logger = AuditLogger::new("test-service").with_min_severity(AuditSeverity::Warning);

        // This should not panic
        logger.log_operation(KeyOperation::KekRotationStart, "kek-123");
    }
}
