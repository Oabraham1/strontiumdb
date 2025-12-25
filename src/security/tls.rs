// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! TLS configuration for secure client/server connections.
//!
//! Uses rustls for TLS 1.3 with modern cipher suites.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::error::SecurityError;

/// TLS configuration for client connections.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the certificate file (PEM format).
    pub cert_path: PathBuf,
    /// Path to the private key file (PEM format).
    pub key_path: PathBuf,
    /// Path to the CA certificate file for verifying peer certificates.
    pub ca_path: Option<PathBuf>,
    /// Whether to require client certificates (mutual TLS).
    pub require_client_cert: bool,
}

impl TlsConfig {
    /// Creates a new TLS configuration.
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cert_path,
            key_path,
            ca_path: None,
            require_client_cert: false,
        }
    }

    /// Sets the CA certificate path for verifying peer certificates.
    pub fn with_ca(mut self, ca_path: PathBuf) -> Self {
        self.ca_path = Some(ca_path);
        self
    }

    /// Enables mutual TLS (requires client certificates).
    pub fn with_client_auth(mut self, require: bool) -> Self {
        self.require_client_cert = require;
        self
    }
}

/// Creates a TLS acceptor for server connections.
///
/// The acceptor is configured for TLS 1.3 with modern cipher suites.
/// If `require_client_cert` is true, clients must present a valid
/// certificate signed by the CA.
pub fn create_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor, SecurityError> {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;

    let server_config = if config.require_client_cert {
        let ca_path = config.ca_path.as_ref().ok_or_else(|| {
            SecurityError::TlsConfig("CA path required for client authentication".into())
        })?;
        let roots = load_root_certs(ca_path)?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| SecurityError::TlsConfig(e.to_string()))?;

        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Creates a TLS connector for client connections.
///
/// If `ca_path` is provided, the server's certificate is verified
/// against the CA. Otherwise, system root certificates are used.
pub fn create_tls_connector(config: &TlsConfig) -> Result<TlsConnector, SecurityError> {
    let mut root_store = RootCertStore::empty();

    if let Some(ca_path) = &config.ca_path {
        let roots = load_root_certs(ca_path)?;
        root_store = roots;
    } else {
        // Use webpki-roots for system root certificates
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config_builder = ClientConfig::builder().with_root_certificates(root_store);

    let client_config = if config.require_client_cert {
        let certs = load_certs(&config.cert_path)?;
        let key = load_private_key(&config.key_path)?;
        config_builder.with_client_auth_cert(certs, key)?
    } else {
        config_builder.with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(client_config)))
}

/// Loads certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, SecurityError> {
    let file = File::open(path).map_err(|e| SecurityError::CertificateLoad {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SecurityError::CertificateLoad {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;

    if certs.is_empty() {
        return Err(SecurityError::CertificateLoad {
            path: path.to_path_buf(),
            reason: "no certificates found".into(),
        });
    }

    Ok(certs)
}

/// Loads a private key from a PEM file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, SecurityError> {
    let file = File::open(path).map_err(|e| SecurityError::PrivateKeyLoad {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(|e| SecurityError::PrivateKeyLoad {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            None => break,
            _ => continue,
        }
    }

    Err(SecurityError::PrivateKeyLoad {
        path: path.to_path_buf(),
        reason: "no private key found".into(),
    })
}

/// Loads root certificates from a PEM file.
fn load_root_certs(path: &Path) -> Result<RootCertStore, SecurityError> {
    let certs = load_certs(path)?;
    let mut root_store = RootCertStore::empty();

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| SecurityError::CertificateLoad {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
    }

    Ok(root_store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Once;
    use tempfile::TempDir;

    // Install crypto provider once for all tests
    static INIT: Once = Once::new();

    fn init_crypto_provider() {
        INIT.call_once(|| {
            // Install aws-lc-rs as the default crypto provider (rustls default)
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    // Self-signed EC P-256 test certificate and key (valid 2025-2035)
    // Generated with openssl
    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUU4RnMKSAMw400Xsd1yN6qxKkbTMwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNTEyMjUwNTA4MzhaFw0zNTEyMjMwNTA4Mzha
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQeuXGb
rv2mAZsHKtf1MR9+qvM3NF8NFOuV82l4dBxZckVeF1SCCfpYkkozul9X2+9OcXT9
eueMAuAgn39hFNHeo1MwUTAdBgNVHQ4EFgQUHcMNq3NVCxmJA99kDioy0ZENxpsw
HwYDVR0jBBgwFoAUHcMNq3NVCxmJA99kDioy0ZENxpswDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEA8/2beAsR/TkF9vQd9gYm+1mdU1XVxJl6kV71
1Ex4Dn8CIQD+lIGDQXmIXnMbcpVh02G5tbkjGJCyRxdbDeD6LdGvXQ==
-----END CERTIFICATE-----"#;

    // PKCS#8 encoded EC P-256 private key
    const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeyZZ2GTQGaDbFekS
hLTVFMYytEWeCXCEScN2mQILKwKhRANCAAQeuXGbrv2mAZsHKtf1MR9+qvM3NF8N
FOuV82l4dBxZckVeF1SCCfpYkkozul9X2+9OcXT9eueMAuAgn39hFNHe
-----END PRIVATE KEY-----"#;

    fn create_test_files(dir: &TempDir) -> (PathBuf, PathBuf) {
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let mut cert_file = File::create(&cert_path).unwrap();
        cert_file.write_all(TEST_CERT.as_bytes()).unwrap();

        let mut key_file = File::create(&key_path).unwrap();
        key_file.write_all(TEST_KEY.as_bytes()).unwrap();

        (cert_path, key_path)
    }

    #[test]
    fn test_load_certs() {
        let dir = TempDir::new().unwrap();
        let (cert_path, _) = create_test_files(&dir);

        let certs = load_certs(&cert_path).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_load_private_key() {
        let dir = TempDir::new().unwrap();
        let (_, key_path) = create_test_files(&dir);

        let key = load_private_key(&key_path).unwrap();
        // EC P-256 key in PKCS#8 format
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_tls_config() {
        let config = TlsConfig::new(PathBuf::from("/cert.pem"), PathBuf::from("/key.pem"))
            .with_ca(PathBuf::from("/ca.pem"))
            .with_client_auth(true);

        assert!(config.require_client_cert);
        assert!(config.ca_path.is_some());
    }

    #[test]
    fn test_create_tls_acceptor() {
        init_crypto_provider();

        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_files(&dir);

        let config = TlsConfig::new(cert_path, key_path);
        let acceptor = create_tls_acceptor(&config);

        assert!(
            acceptor.is_ok(),
            "TLS acceptor creation failed: {:?}",
            acceptor.err()
        );
    }

    #[test]
    fn test_create_tls_acceptor_missing_files() {
        let config = TlsConfig::new(
            PathBuf::from("/nonexistent/cert.pem"),
            PathBuf::from("/nonexistent/key.pem"),
        );
        let result = create_tls_acceptor(&config);
        assert!(result.is_err());
        assert!(matches!(result, Err(SecurityError::CertificateLoad { .. })));
    }

    #[test]
    fn test_create_tls_acceptor_with_client_auth() {
        init_crypto_provider();

        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_files(&dir);

        // Use the same cert as CA for testing
        let ca_path = dir.path().join("ca.pem");
        std::fs::copy(&cert_path, &ca_path).unwrap();

        let config = TlsConfig::new(cert_path, key_path)
            .with_ca(ca_path)
            .with_client_auth(true);

        let acceptor = create_tls_acceptor(&config);
        assert!(
            acceptor.is_ok(),
            "mTLS acceptor creation failed: {:?}",
            acceptor.err()
        );
    }

    #[test]
    fn test_create_tls_connector() {
        init_crypto_provider();

        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_files(&dir);

        let config = TlsConfig::new(cert_path, key_path);
        let connector = create_tls_connector(&config);

        assert!(
            connector.is_ok(),
            "TLS connector creation failed: {:?}",
            connector.err()
        );
    }

    #[test]
    fn test_create_tls_connector_with_system_roots() {
        init_crypto_provider();

        // Test connector with no custom CA (uses system roots)
        let config = TlsConfig::new(PathBuf::from("/unused"), PathBuf::from("/unused"));
        let connector = create_tls_connector(&config);

        assert!(
            connector.is_ok(),
            "TLS connector with system roots failed: {:?}",
            connector.err()
        );
    }

    #[test]
    fn test_load_nonexistent_cert() {
        let result = load_certs(Path::new("/nonexistent/cert.pem"));
        assert!(matches!(result, Err(SecurityError::CertificateLoad { .. })));
    }

    #[test]
    fn test_load_nonexistent_key() {
        let result = load_private_key(Path::new("/nonexistent/key.pem"));
        assert!(matches!(result, Err(SecurityError::PrivateKeyLoad { .. })));
    }
}
