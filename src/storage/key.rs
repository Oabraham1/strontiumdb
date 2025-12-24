// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! MVCC key encoding and decoding.
//!
//! Encodes user keys with timestamps for RocksDB storage.
//! Format: `[key_len:u32 BE][key bytes][MAX-latest:u64 BE][MAX-earliest:u64 BE]`
//!
//! The timestamps are inverted (MAX - value) so that newer versions sort first
//! within the same user key when using RocksDB's default byte-order comparator.

use crate::time::Timestamp;

use super::{Key, StorageError};

/// Encodes a user key with timestamp into a RocksDB key.
///
/// Format: `[key_len:u32 BE][key bytes][MAX-latest:u64 BE][MAX-earliest:u64 BE]`
///
/// Using big-endian ensures proper lexicographic ordering.
/// Inverting timestamps (MAX - value) ensures newer versions sort first.
#[inline]
pub fn encode_mvcc_key(key: &Key, ts: &Timestamp) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut encoded = Vec::with_capacity(4 + key_bytes.len() + 16);

    // Key length (u32 big-endian)
    encoded.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());

    // Key bytes
    encoded.extend_from_slice(key_bytes);

    // Inverted timestamps (newer first)
    // We invert both latest and earliest so that:
    // - Keys are first ordered by user key
    // - Within same user key, ordered by timestamp (newest first)
    encoded.extend_from_slice(&(u64::MAX - ts.latest()).to_be_bytes());
    encoded.extend_from_slice(&(u64::MAX - ts.earliest()).to_be_bytes());

    encoded
}

/// Decodes a RocksDB key back into user key and timestamp.
pub fn decode_mvcc_key(encoded: &[u8]) -> Result<(Key, Timestamp), StorageError> {
    if encoded.len() < 4 {
        return Err(StorageError::InvalidKeyEncoding(
            "key too short for length prefix".to_string(),
        ));
    }

    // Read key length
    let key_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;

    let expected_len = 4 + key_len + 16;
    if encoded.len() != expected_len {
        return Err(StorageError::InvalidKeyEncoding(format!(
            "expected {} bytes, got {}",
            expected_len,
            encoded.len()
        )));
    }

    // Extract key bytes
    let key_bytes = &encoded[4..4 + key_len];
    let key = Key::new(key_bytes.to_vec());

    // Extract and invert timestamps
    let ts_offset = 4 + key_len;
    let inverted_latest = u64::from_be_bytes([
        encoded[ts_offset],
        encoded[ts_offset + 1],
        encoded[ts_offset + 2],
        encoded[ts_offset + 3],
        encoded[ts_offset + 4],
        encoded[ts_offset + 5],
        encoded[ts_offset + 6],
        encoded[ts_offset + 7],
    ]);
    let inverted_earliest = u64::from_be_bytes([
        encoded[ts_offset + 8],
        encoded[ts_offset + 9],
        encoded[ts_offset + 10],
        encoded[ts_offset + 11],
        encoded[ts_offset + 12],
        encoded[ts_offset + 13],
        encoded[ts_offset + 14],
        encoded[ts_offset + 15],
    ]);

    let latest = u64::MAX - inverted_latest;
    let earliest = u64::MAX - inverted_earliest;

    Ok((key, Timestamp::new(earliest, latest)))
}

/// Returns the prefix for scanning all versions of a user key.
///
/// This prefix can be used with RocksDB's prefix iterator to find
/// all versions of a specific key.
#[inline]
pub fn user_key_prefix(key: &Key) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut prefix = Vec::with_capacity(4 + key_bytes.len());
    prefix.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
    prefix.extend_from_slice(key_bytes);
    prefix
}

/// Extracts the user key from an encoded MVCC key without full decoding.
///
/// Returns an error if the encoded key is malformed.
#[inline]
pub fn extract_user_key(encoded: &[u8]) -> Result<&[u8], StorageError> {
    if encoded.len() < 4 {
        return Err(StorageError::InvalidKeyEncoding(
            "key too short for length prefix".to_string(),
        ));
    }

    let key_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;

    if encoded.len() < 4 + key_len {
        return Err(StorageError::InvalidKeyEncoding(
            "key too short for user key".to_string(),
        ));
    }

    Ok(&encoded[4..4 + key_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let key = Key::from("hello");
        let ts = Timestamp::new(100, 200);

        let encoded = encode_mvcc_key(&key, &ts);
        let (decoded_key, decoded_ts) = decode_mvcc_key(&encoded).unwrap();

        assert_eq!(key, decoded_key);
        assert_eq!(ts.earliest(), decoded_ts.earliest());
        assert_eq!(ts.latest(), decoded_ts.latest());
    }

    #[test]
    fn test_encode_decode_empty_key() {
        let key = Key::from(Vec::<u8>::new());
        let ts = Timestamp::new(0, 0);

        let encoded = encode_mvcc_key(&key, &ts);
        let (decoded_key, decoded_ts) = decode_mvcc_key(&encoded).unwrap();

        assert_eq!(key, decoded_key);
        assert_eq!(ts.earliest(), decoded_ts.earliest());
        assert_eq!(ts.latest(), decoded_ts.latest());
    }

    #[test]
    fn test_encode_decode_max_timestamp() {
        let key = Key::from("test");
        let ts = Timestamp::new(u64::MAX - 100, u64::MAX);

        let encoded = encode_mvcc_key(&key, &ts);
        let (decoded_key, decoded_ts) = decode_mvcc_key(&encoded).unwrap();

        assert_eq!(key, decoded_key);
        assert_eq!(ts.earliest(), decoded_ts.earliest());
        assert_eq!(ts.latest(), decoded_ts.latest());
    }

    #[test]
    fn test_newer_versions_sort_first() {
        let key = Key::from("key");

        let ts_old = Timestamp::new(100, 110);
        let ts_new = Timestamp::new(200, 210);

        let encoded_old = encode_mvcc_key(&key, &ts_old);
        let encoded_new = encode_mvcc_key(&key, &ts_new);

        // Newer version should sort BEFORE older version (smaller in byte order)
        assert!(encoded_new < encoded_old, "newer version should sort first");
    }

    #[test]
    fn test_different_keys_sort_correctly() {
        let key_a = Key::from("aaa");
        let key_b = Key::from("bbb");
        let ts = Timestamp::new(100, 200);

        let encoded_a = encode_mvcc_key(&key_a, &ts);
        let encoded_b = encode_mvcc_key(&key_b, &ts);

        // "aaa" should sort before "bbb"
        assert!(encoded_a < encoded_b);
    }

    #[test]
    fn test_user_key_prefix() {
        let key = Key::from("hello");
        let ts1 = Timestamp::new(100, 110);
        let ts2 = Timestamp::new(200, 210);

        let encoded1 = encode_mvcc_key(&key, &ts1);
        let encoded2 = encode_mvcc_key(&key, &ts2);
        let prefix = user_key_prefix(&key);

        assert!(encoded1.starts_with(&prefix));
        assert!(encoded2.starts_with(&prefix));
    }

    #[test]
    fn test_extract_user_key() {
        let key = Key::from("hello");
        let ts = Timestamp::new(100, 200);

        let encoded = encode_mvcc_key(&key, &ts);
        let extracted = extract_user_key(&encoded).unwrap();

        assert_eq!(extracted, b"hello");
    }

    #[test]
    fn test_decode_too_short() {
        let result = decode_mvcc_key(&[0, 0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_wrong_length() {
        let result = decode_mvcc_key(&[0, 0, 0, 5, 1, 2, 3]); // Says 5 bytes but only 3
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn mvcc_key_roundtrip(
            key_bytes in prop::collection::vec(any::<u8>(), 0..100),
            earliest in 0u64..u64::MAX/2,
            width in 0u64..1_000_000,
        ) {
            let key = Key::new(key_bytes);
            let ts = Timestamp::new(earliest, earliest.saturating_add(width));

            let encoded = encode_mvcc_key(&key, &ts);
            let (decoded_key, decoded_ts) = decode_mvcc_key(&encoded).unwrap();

            prop_assert_eq!(key, decoded_key);
            prop_assert_eq!(ts.earliest(), decoded_ts.earliest());
            prop_assert_eq!(ts.latest(), decoded_ts.latest());
        }

        #[test]
        fn newer_always_sorts_first(
            key_bytes in prop::collection::vec(any::<u8>(), 1..50),
            old_time in 0u64..1_000_000_000,
            gap in 100u64..1_000_000,
        ) {
            let key = Key::new(key_bytes);
            let ts_old = Timestamp::new(old_time, old_time + 10);
            let ts_new = Timestamp::new(old_time + gap, old_time + gap + 10);

            let encoded_old = encode_mvcc_key(&key, &ts_old);
            let encoded_new = encode_mvcc_key(&key, &ts_new);

            prop_assert!(encoded_new < encoded_old, "newer should sort first");
        }

        #[test]
        fn prefix_is_prefix(
            key_bytes in prop::collection::vec(any::<u8>(), 1..50),
            earliest in 0u64..u64::MAX/2,
            width in 0u64..1_000_000,
        ) {
            let key = Key::new(key_bytes);
            let ts = Timestamp::new(earliest, earliest.saturating_add(width));

            let encoded = encode_mvcc_key(&key, &ts);
            let prefix = user_key_prefix(&key);

            prop_assert!(encoded.starts_with(&prefix));
        }
    }
}
