// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks for MVCC storage operations.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use strontiumdb::storage::{Key, MvccStore, RocksMvccStore, Value};
use strontiumdb::time::Timestamp;
use tempfile::TempDir;

fn create_test_store() -> (RocksMvccStore, TempDir) {
    let dir = TempDir::new().unwrap();
    let store = RocksMvccStore::open(dir.path()).unwrap();
    (store, dir)
}

fn bench_point_read(c: &mut Criterion) {
    let (store, _dir) = create_test_store();

    // Pre-populate with 10000 keys
    for i in 0..10000 {
        let key = Key::from(format!("key{:05}", i));
        let value = Value::new(vec![0u8; 100]);
        let ts = Timestamp::new(i as u64 * 100, i as u64 * 100 + 10);
        store.write(key, value, ts).unwrap();
    }

    let mut group = c.benchmark_group("storage");
    group.throughput(Throughput::Elements(1));

    group.bench_function("point_read", |b| {
        b.iter_batched(
            || {
                let i = rand::random::<u32>() % 10000;
                let key = Key::from(format!("key{:05}", i));
                let ts = Timestamp::new(1_000_000, 1_000_010);
                (key, ts)
            },
            |(key, ts)| store.read(&key, &ts).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_point_write(c: &mut Criterion) {
    let (store, _dir) = create_test_store();

    let mut group = c.benchmark_group("storage");
    group.throughput(Throughput::Elements(1));

    let counter = std::sync::atomic::AtomicU64::new(0);

    group.bench_function("point_write", |b| {
        b.iter(|| {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let key = Key::from(format!("key{}", i));
            let value = Value::new(vec![0u8; 100]);
            let ts = Timestamp::new(i * 100, i * 100 + 10);
            store.write(key, value, ts).unwrap()
        })
    });

    group.finish();
}

fn bench_scan(c: &mut Criterion) {
    let (store, _dir) = create_test_store();

    // Pre-populate with 10000 keys
    for i in 0..10000 {
        let key = Key::from(format!("key{:05}", i));
        let value = Value::new(vec![0u8; 100]);
        let ts = Timestamp::new(i as u64 * 100, i as u64 * 100 + 10);
        store.write(key, value, ts).unwrap();
    }

    let mut group = c.benchmark_group("storage");

    group.bench_function("scan_100", |b| {
        let read_ts = Timestamp::new(1_000_000, 1_000_010);
        b.iter(|| {
            store
                .scan(
                    &Key::from("key00000"),
                    &Key::from("key99999"),
                    &read_ts,
                    100,
                )
                .unwrap()
        })
    });

    group.bench_function("scan_1000", |b| {
        let read_ts = Timestamp::new(1_000_000, 1_000_010);
        b.iter(|| {
            store
                .scan(
                    &Key::from("key00000"),
                    &Key::from("key99999"),
                    &read_ts,
                    1000,
                )
                .unwrap()
        })
    });

    group.finish();
}

fn bench_batch_write(c: &mut Criterion) {
    let (store, _dir) = create_test_store();

    let mut group = c.benchmark_group("storage");
    group.throughput(Throughput::Elements(100));

    let counter = std::sync::atomic::AtomicU64::new(0);

    group.bench_function("batch_write_100", |b| {
        b.iter(|| {
            let base = counter.fetch_add(100, std::sync::atomic::Ordering::Relaxed);
            let ts = Timestamp::new(base * 100, base * 100 + 10);

            let entries: Vec<_> = (0..100)
                .map(|i| {
                    strontiumdb::storage::MvccEntry::new(
                        Key::from(format!("key{}", base + i)),
                        Value::new(vec![0u8; 100]),
                        ts,
                    )
                })
                .collect();

            store.batch_write(entries).unwrap()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_point_read,
    bench_point_write,
    bench_scan,
    bench_batch_write,
);
criterion_main!(benches);
