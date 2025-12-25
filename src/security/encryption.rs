// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Encryption provider for data at rest.
//!
//! Provides AES-256-GCM encryption using DEKs from the KMS.
//! Each encrypted block includes a nonce and authentication tag.
//!
//! # Format
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ Encrypted Block                                          │
//! ├────────────┬─────────────────────────────┬───────────────┤
//! │ Nonce (12) │ Ciphertext (variable)       │ Tag (16)      │
//! └────────────┴─────────────────────────────┴───────────────┘
//! ```

use std::io::{self, Read, Write};
use std::sync::Arc;

use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

use super::error::SecurityError;
use super::kms::{DataEncryptionKey, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE};

/// Counter-based nonce sequence for AES-GCM.
struct CounterNonceSequence {
    nonce: [u8; NONCE_LEN],
}

impl CounterNonceSequence {
    fn new(nonce: [u8; NONCE_LEN]) -> Self {
        Self { nonce }
    }
}

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Nonce::try_assume_unique_for_key(&self.nonce)
    }
}

/// Encryption provider for data at rest.
///
/// Uses AES-256-GCM with a per-range DEK for encryption.
/// Thread-safe and cloneable for use across async tasks.
pub struct EncryptionProvider {
    dek: Arc<DataEncryptionKey>,
    rng: SystemRandom,
}

impl EncryptionProvider {
    /// Creates a new encryption provider with the given DEK.
    pub fn new(dek: DataEncryptionKey) -> Self {
        Self {
            dek: Arc::new(dek),
            rng: SystemRandom::new(),
        }
    }

    /// Returns the DEK ID.
    pub fn dek_id(&self) -> &str {
        self.dek.id()
    }

    /// Encrypts data using AES-256-GCM.
    ///
    /// Returns nonce || ciphertext || tag.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| SecurityError::KeyGeneration("failed to generate nonce".into()))?;

        self.encrypt_with_nonce(plaintext, nonce_bytes)
    }

    /// Encrypts data with a specific nonce (for testing).
    fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce_bytes: [u8; AES_GCM_NONCE_SIZE],
    ) -> Result<Vec<u8>, SecurityError> {
        // Create sealing key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, self.dek.key())?;
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

    /// Decrypts data encrypted with encrypt().
    ///
    /// Expects nonce || ciphertext || tag format.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(SecurityError::Decryption("ciphertext too short".into()));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted) = ciphertext.split_at(AES_GCM_NONCE_SIZE);
        let mut nonce_arr = [0u8; AES_GCM_NONCE_SIZE];
        nonce_arr.copy_from_slice(nonce_bytes);

        // Create opening key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, self.dek.key())?;
        let nonce_seq = CounterNonceSequence::new(nonce_arr);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

        // Decrypt in-place
        let mut in_out = encrypted.to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| SecurityError::Decryption("AES-GCM open failed".into()))?;

        Ok(plaintext.to_vec())
    }

    /// Creates an encrypting writer that wraps another writer.
    ///
    /// Data written to the returned writer is encrypted and written
    /// to the underlying writer.
    pub fn encrypting_writer<W: Write>(&self, writer: W) -> EncryptedWriter<W> {
        EncryptedWriter::new(writer, self.clone())
    }
}

impl Clone for EncryptionProvider {
    fn clone(&self) -> Self {
        Self {
            dek: Arc::clone(&self.dek),
            rng: SystemRandom::new(),
        }
    }
}

/// A writer that encrypts data before writing.
///
/// Buffers data and encrypts in blocks for efficiency.
pub struct EncryptedWriter<W: Write> {
    inner: W,
    provider: EncryptionProvider,
    buffer: Vec<u8>,
    block_size: usize,
}

impl<W: Write> EncryptedWriter<W> {
    /// Default block size for encryption (64 KB).
    pub const DEFAULT_BLOCK_SIZE: usize = 64 * 1024;

    /// Creates a new encrypted writer.
    pub fn new(inner: W, provider: EncryptionProvider) -> Self {
        Self {
            inner,
            provider,
            buffer: Vec::with_capacity(Self::DEFAULT_BLOCK_SIZE),
            block_size: Self::DEFAULT_BLOCK_SIZE,
        }
    }

    /// Sets the block size for encryption.
    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size;
        self.buffer = Vec::with_capacity(block_size);
        self
    }

    /// Flushes any buffered data, encrypting and writing it.
    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let encrypted = self
            .provider
            .encrypt(&self.buffer)
            .map_err(|e| io::Error::other(format!("encryption failed: {}", e)))?;

        // Write length prefix (4 bytes, big-endian)
        let len = encrypted.len() as u32;
        self.inner.write_all(&len.to_be_bytes())?;

        // Write encrypted block
        self.inner.write_all(&encrypted)?;

        self.buffer.clear();
        Ok(())
    }

    /// Finishes writing, flushing any remaining data.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush_buffer()?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;

        for chunk in buf.chunks(self.block_size - self.buffer.len()) {
            self.buffer.extend_from_slice(chunk);
            written += chunk.len();

            if self.buffer.len() >= self.block_size {
                self.flush_buffer()?;
            }
        }

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.inner.flush()
    }
}

/// A reader that decrypts data as it reads.
pub struct EncryptedReader<R: Read> {
    inner: R,
    provider: EncryptionProvider,
    buffer: Vec<u8>,
    position: usize,
}

impl<R: Read> EncryptedReader<R> {
    /// Creates a new encrypted reader.
    pub fn new(inner: R, provider: EncryptionProvider) -> Self {
        Self {
            inner,
            provider,
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Reads and decrypts the next block.
    fn read_block(&mut self) -> io::Result<bool> {
        // Read length prefix
        let mut len_bytes = [0u8; 4];
        match self.inner.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e),
        }

        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read encrypted block
        let mut encrypted = vec![0u8; len];
        self.inner.read_exact(&mut encrypted)?;

        // Decrypt
        self.buffer = self
            .provider
            .decrypt(&encrypted)
            .map_err(|e| io::Error::other(format!("decryption failed: {}", e)))?;
        self.position = 0;

        Ok(true)
    }
}

impl<R: Read> Read for EncryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.buffer.len() && !self.read_block()? {
            return Ok(0);
        }

        let available = &self.buffer[self.position..];
        let to_copy = std::cmp::min(available.len(), buf.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.position += to_copy;

        Ok(to_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::super::kms::AES_256_KEY_SIZE;
    use super::*;

    fn create_test_provider() -> EncryptionProvider {
        let mut key = [0u8; AES_256_KEY_SIZE];
        SystemRandom::new().fill(&mut key).unwrap();
        let dek = DataEncryptionKey::new(key, "test-dek".into());
        EncryptionProvider::new(dek)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let provider = create_test_provider();
        let plaintext = b"Hello, World!";

        let ciphertext = provider.encrypt(plaintext).unwrap();
        assert_ne!(&ciphertext[AES_GCM_NONCE_SIZE..], plaintext);

        let decrypted = provider.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let provider = create_test_provider();
        let plaintext = b"Hello, World!";

        let ct1 = provider.encrypt(plaintext).unwrap();
        let ct2 = provider.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertext (random nonce)
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_decrypt_tampered_fails() {
        let provider = create_test_provider();
        let plaintext = b"Hello, World!";

        let mut ciphertext = provider.encrypt(plaintext).unwrap();
        // Tamper with ciphertext
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = provider.decrypt(&ciphertext);
        assert!(matches!(result, Err(SecurityError::Decryption(_))));
    }

    #[test]
    fn test_decrypt_short_ciphertext_fails() {
        let provider = create_test_provider();
        let short = vec![0u8; AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE - 1];

        let result = provider.decrypt(&short);
        assert!(matches!(result, Err(SecurityError::Decryption(_))));
    }

    #[test]
    fn test_encrypted_writer_reader() {
        let provider = create_test_provider();
        let plaintext = b"Hello, World! This is a test of the encrypted writer.";

        // Write
        let mut output = Vec::new();
        {
            let mut writer = provider.encrypting_writer(&mut output);
            writer.write_all(plaintext).unwrap();
            writer.finish().unwrap();
        }

        // Read
        let mut reader = EncryptedReader::new(&output[..], provider);
        let mut decrypted = Vec::new();
        reader.read_to_end(&mut decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_writer_large_data() {
        let provider = create_test_provider();
        let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        // Write with small block size
        let mut output = Vec::new();
        {
            let mut writer = provider
                .encrypting_writer(&mut output)
                .with_block_size(1024);
            writer.write_all(&plaintext).unwrap();
            writer.finish().unwrap();
        }

        // Read
        let mut reader = EncryptedReader::new(&output[..], provider);
        let mut decrypted = Vec::new();
        reader.read_to_end(&mut decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_clone_provider() {
        let provider = create_test_provider();
        let cloned = provider.clone();

        let plaintext = b"Test data";

        // Encrypt with original
        let ciphertext = provider.encrypt(plaintext).unwrap();

        // Decrypt with clone
        let decrypted = cloned.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
