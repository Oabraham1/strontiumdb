// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Security module for StrontiumDB.
//!
//! Provides encryption at rest, TLS for transport security, and
//! key management abstractions supporting pluggable KMS backends.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Security Layer                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │     KMS     │  │    TLS      │  │    Encryption       │ │
//! │  │  Interface  │  │   Config    │  │     Provider        │ │
//! │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
//! │         │                │                    │            │
//! │  ┌──────┴──────┐        │         ┌──────────┴──────────┐ │
//! │  │  LocalKms   │        │         │  RocksDB Encryption │ │
//! │  │  AWS KMS    │        │         │  (AES-256-GCM)      │ │
//! │  │  Azure KV   │        │         └─────────────────────┘ │
//! │  │  GCP KMS    │        │                                 │
//! │  └─────────────┘        │                                 │
//! └─────────────────────────┼─────────────────────────────────┘
//!                           │
//!                    ┌──────┴──────┐
//!                    │   rustls    │
//!                    │   TLS 1.3   │
//!                    └─────────────┘
//! ```
//!
//! # Key Hierarchy
//!
//! - **KEK (Key Encryption Key)**: Master key stored in KMS, used to wrap DEKs
//! - **DEK (Data Encryption Key)**: Per-range keys for encrypting data at rest
//!
//! This two-tier hierarchy allows key rotation without re-encrypting all data.
//!
//! # Example
//!
//! ```rust,no_run
//! use strontiumdb::security::{LocalKms, KeyManagementService};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Generate a new KMS with random master key
//!     let kms = LocalKms::generate().expect("failed to generate KMS");
//!
//!     // Generate a data encryption key
//!     let dek = kms.generate_dek().await.expect("failed to generate DEK");
//!
//!     // Wrap the DEK for storage
//!     let wrapped = kms.wrap_dek(&dek, kms.active_kek_id()).await
//!         .expect("failed to wrap DEK");
//!
//!     // Later, unwrap to use
//!     let unwrapped = kms.unwrap_dek(&wrapped).await
//!         .expect("failed to unwrap DEK");
//! }
//! ```

pub mod audit;
#[cfg(feature = "aws-kms")]
mod aws_kms;
#[cfg(feature = "azure-kms")]
mod azure_kms;
mod encryption;
mod error;
#[cfg(feature = "gcp-kms")]
mod gcp_kms;
mod kms;
mod local_kms;
pub mod memlock;
mod rotation;
mod tls;

// Re-export public types
pub use audit::{AuditEvent, AuditLogger, AuditSeverity, AuditedKms, KeyOperation};
#[cfg(feature = "aws-kms")]
pub use aws_kms::{generate_data_key_from_kms, AwsKms};
#[cfg(feature = "azure-kms")]
pub use azure_kms::AzureKms;
pub use encryption::{EncryptedReader, EncryptedWriter, EncryptionProvider};
pub use error::SecurityError;
#[cfg(feature = "gcp-kms")]
pub use gcp_kms::GcpKms;
pub use kms::{
    DataEncryptionKey, KeyManagementService, WrappedKey, AES_256_KEY_SIZE, AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
};
pub use local_kms::LocalKms;
pub use memlock::{LockedBuffer, MemlockError, SecureKey};
pub use rotation::{DekRegistry, KeyRotationManager, RotationResult};
pub use tls::{create_tls_acceptor, create_tls_connector, TlsConfig};
