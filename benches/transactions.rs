// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks for transaction operations.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::sync::Arc;
use strontiumdb::storage::{Key, RocksMvccStore, Value};
use strontiumdb::time::HlcTimeService;
use strontiumdb::txn::{
    IsolationLevel, LockMode, SingleNodeTxnManager, TransactionManager, WoundWaitLockTable,
};
use tempfile::TempDir;

fn create_test_manager() -> (
    SingleNodeTxnManager<RocksMvccStore, HlcTimeService, WoundWaitLockTable>,
    TempDir,
) {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(RocksMvccStore::open(dir.path()).unwrap());
    let time_service = Arc::new(HlcTimeService::default());
    let lock_table = Arc::new(WoundWaitLockTable::new());

    let mgr = SingleNodeTxnManager::new(time_service, store, lock_table);
    (mgr, dir)
}

fn bench_begin(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();

    c.bench_function("txn::begin", |b| {
        b.iter(|| {
            let txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
            black_box(txn)
        })
    });
}

fn bench_write(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();

    let counter = std::sync::atomic::AtomicU64::new(0);

    c.bench_function("txn::write", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
                let key = Key::from(format!("key{}", i));
                let value = Value::new(vec![0u8; 100]);
                (txn, key, value)
            },
            |(mut txn, key, value)| {
                mgr.write(&mut txn, key, value).unwrap();
                black_box(txn)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_read_buffered(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();
    let counter = std::sync::atomic::AtomicU64::new(0);

    c.bench_function("txn::read_buffered", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
                let key = Key::from(format!("bufkey{}", i));
                let value = Value::from("value");
                mgr.write(&mut txn, key.clone(), value).unwrap();
                (txn, key)
            },
            |(mut txn, key)| {
                let result = mgr.read(&mut txn, &key).unwrap();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_read_from_storage(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();

    // Pre-populate storage
    let rt = tokio::runtime::Runtime::new().unwrap();
    for i in 0..1000 {
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
        let key = Key::from(format!("prekey{:04}", i));
        let value = Value::new(vec![0u8; 100]);
        mgr.write(&mut txn, key, value).unwrap();
        rt.block_on(mgr.commit(&mut txn)).unwrap();
    }

    c.bench_function("txn::read_storage", |b| {
        b.iter_batched(
            || {
                let i = rand::random::<u32>() % 1000;
                let txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
                let key = Key::from(format!("prekey{:04}", i));
                (txn, key)
            },
            |(mut txn, key)| {
                let result = mgr.read(&mut txn, &key).unwrap();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_commit(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let counter = std::sync::atomic::AtomicU64::new(0);

    let mut group = c.benchmark_group("txn");
    group.throughput(Throughput::Elements(1));

    group.bench_function("commit_1_key", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
                let key = Key::from(format!("commitkey{}", i));
                let value = Value::new(vec![0u8; 100]);
                mgr.write(&mut txn, key, value).unwrap();
                txn
            },
            |mut txn| {
                let result = rt.block_on(mgr.commit(&mut txn));
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_commit_10_keys(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let counter = std::sync::atomic::AtomicU64::new(0);

    let mut group = c.benchmark_group("txn");
    group.throughput(Throughput::Elements(10));

    group.bench_function("commit_10_keys", |b| {
        b.iter_batched(
            || {
                let base = counter.fetch_add(10, std::sync::atomic::Ordering::Relaxed);
                let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
                for i in 0..10 {
                    let key = Key::from(format!("batchkey{}", base + i));
                    let value = Value::new(vec![0u8; 100]);
                    mgr.write(&mut txn, key, value).unwrap();
                }
                txn
            },
            |mut txn| {
                let result = rt.block_on(mgr.commit(&mut txn));
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_lock_acquire(c: &mut Criterion) {
    use strontiumdb::time::Timestamp;
    use strontiumdb::txn::{LockTable, TxnId};

    let lock_table = WoundWaitLockTable::new();
    let counter = std::sync::atomic::AtomicU64::new(0);

    c.bench_function("lock::acquire_no_conflict", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let key = Key::from(format!("lockkey{}", i));
                let ts = Timestamp::new(i * 100, i * 100 + 10);
                (TxnId(i), ts, key)
            },
            |(txn_id, ts, key)| {
                lock_table
                    .acquire(txn_id, &ts, &key, LockMode::Exclusive)
                    .unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_full_transaction(c: &mut Criterion) {
    let (mgr, _dir) = create_test_manager();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Pre-populate with some data
    for i in 0..100 {
        let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();
        let key = Key::from(format!("data{:03}", i));
        let value = Value::new(vec![0u8; 100]);
        mgr.write(&mut txn, key, value).unwrap();
        rt.block_on(mgr.commit(&mut txn)).unwrap();
    }

    let counter = std::sync::atomic::AtomicU64::new(0);

    c.bench_function("txn::full_read_write_commit", |b| {
        b.iter(|| {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut txn = mgr.begin(IsolationLevel::Snapshot).unwrap();

            // Read existing key
            let read_key = Key::from(format!("data{:03}", i % 100));
            let _ = mgr.read(&mut txn, &read_key);

            // Write new key
            let write_key = Key::from(format!("newdata{}", i));
            let value = Value::new(vec![0u8; 100]);
            mgr.write(&mut txn, write_key, value).unwrap();

            // Commit
            let result = rt.block_on(mgr.commit(&mut txn));
            black_box(result)
        })
    });
}

criterion_group!(
    benches,
    bench_begin,
    bench_write,
    bench_read_buffered,
    bench_read_from_storage,
    bench_commit,
    bench_commit_10_keys,
    bench_lock_acquire,
    bench_full_transaction,
);
criterion_main!(benches);
