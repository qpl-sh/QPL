// SPDX-License-Identifier: MIT OR Apache-2.0
//! Benchmarks for ML-KEM (Kyber1024) operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qpl_crypto::ml_kem::{decapsulate, encapsulate, generate_keypair};

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("ml_kem_keypair_generation", |b| {
        b.iter(|| {
            let keypair = generate_keypair().expect("keypair generation should succeed");
            black_box(keypair)
        })
    });
}

fn bench_encapsulation(c: &mut Criterion) {
    let keypair = generate_keypair().expect("keypair generation should succeed");

    c.bench_function("ml_kem_encapsulation", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) =
                encapsulate(black_box(keypair.public_key())).expect("encapsulation should succeed");
            black_box((ciphertext, shared_secret))
        })
    });
}

fn bench_decapsulation(c: &mut Criterion) {
    let keypair = generate_keypair().expect("keypair generation should succeed");
    let (ciphertext, _) = encapsulate(keypair.public_key()).expect("encapsulation should succeed");

    c.bench_function("ml_kem_decapsulation", |b| {
        b.iter(|| {
            let shared_secret =
                decapsulate(black_box(&ciphertext), black_box(&keypair.secret_key))
                    .expect("decapsulation should succeed");
            black_box(shared_secret)
        })
    });
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_encapsulation,
    bench_decapsulation
);

criterion_main!(benches);
