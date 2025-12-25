// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks for the security module.
//!
//! Measures AES-256-GCM encryption/decryption performance and KMS operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use strontiumdb::security::{EncryptionProvider, KeyManagementService, LocalKms};
use tokio::runtime::Runtime;

fn bench_encryption(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let kms = LocalKms::generate().expect("failed to generate KMS");
    let dek = rt
        .block_on(kms.generate_dek())
        .expect("failed to generate DEK");
    let provider = EncryptionProvider::new(dek);

    let mut group = c.benchmark_group("encryption");

    // Benchmark different payload sizes
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                let ciphertext = provider.encrypt(black_box(data)).unwrap();
                black_box(ciphertext)
            })
        });

        // Pre-encrypt for decryption benchmark
        let ciphertext = provider.encrypt(&data).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt", size), &ciphertext, |b, ct| {
            b.iter(|| {
                let plaintext = provider.decrypt(black_box(ct)).unwrap();
                black_box(plaintext)
            })
        });
    }

    group.finish();
}

fn bench_kms_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let kms = LocalKms::generate().expect("failed to generate KMS");
    let dek = rt
        .block_on(kms.generate_dek())
        .expect("failed to generate DEK");
    let kek_id = kms.active_kek_id().to_string();
    let wrapped = rt
        .block_on(kms.wrap_dek(&dek, &kek_id))
        .expect("failed to wrap DEK");

    let mut group = c.benchmark_group("kms");

    group.bench_function("generate_dek", |b| {
        b.iter(|| {
            let dek = rt.block_on(kms.generate_dek()).unwrap();
            black_box(dek)
        })
    });

    group.bench_function("wrap_dek", |b| {
        b.iter(|| {
            let wrapped = rt.block_on(kms.wrap_dek(black_box(&dek), &kek_id)).unwrap();
            black_box(wrapped)
        })
    });

    group.bench_function("unwrap_dek", |b| {
        b.iter(|| {
            let unwrapped = rt.block_on(kms.unwrap_dek(black_box(&wrapped))).unwrap();
            black_box(unwrapped)
        })
    });

    group.finish();
}

fn bench_memlock(c: &mut Criterion) {
    use strontiumdb::security::memlock::{LockedBuffer, SecureKey};

    let mut group = c.benchmark_group("memlock");

    group.bench_function("locked_buffer_alloc_32", |b| {
        b.iter(|| {
            let buf = LockedBuffer::new(32).unwrap();
            black_box(buf)
        })
    });

    group.bench_function("locked_buffer_alloc_4096", |b| {
        b.iter(|| {
            let buf = LockedBuffer::new(4096).unwrap();
            black_box(buf)
        })
    });

    group.bench_function("secure_key_32", |b| {
        b.iter(|| {
            let key = SecureKey::<32>::new().unwrap();
            black_box(key)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encryption,
    bench_kms_operations,
    bench_memlock
);
criterion_main!(benches);
