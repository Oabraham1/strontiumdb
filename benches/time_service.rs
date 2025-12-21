// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks for the time service.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use strontiumdb::time::{create_time_service, HlcTimeService, TimeService};

fn bench_now(c: &mut Criterion) {
    let service = create_time_service();

    c.bench_function("TimeService::now", |b| b.iter(|| black_box(service.now())));
}

fn bench_uncertainty_bound(c: &mut Criterion) {
    let service = create_time_service();

    c.bench_function("TimeService::uncertainty_bound", |b| {
        b.iter(|| black_box(service.uncertainty_bound()))
    });
}

fn bench_hlc_now(c: &mut Criterion) {
    let hlc = HlcTimeService::new(Duration::from_millis(100));

    c.bench_function("HlcTimeService::now", |b| b.iter(|| black_box(hlc.now())));
}

fn bench_timestamp_operations(c: &mut Criterion) {
    use strontiumdb::Timestamp;

    let t1 = Timestamp::new(1_000_000_000, 1_000_000_100);
    let t2 = Timestamp::new(1_000_000_200, 1_000_000_300);

    c.bench_function("Timestamp::definitely_before", |b| {
        b.iter(|| black_box(t1.definitely_before(&t2)))
    });

    c.bench_function("Timestamp::overlaps", |b| {
        b.iter(|| black_box(t1.overlaps(&t2)))
    });

    c.bench_function("Timestamp::midpoint", |b| {
        b.iter(|| black_box(t1.midpoint()))
    });
}

criterion_group!(
    benches,
    bench_now,
    bench_uncertainty_bound,
    bench_hlc_now,
    bench_timestamp_operations
);
criterion_main!(benches);
