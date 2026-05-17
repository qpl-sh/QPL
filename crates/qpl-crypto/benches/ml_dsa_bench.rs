// SPDX-License-Identifier: MIT OR Apache-2.0
//! Benchmarks for ML-DSA (Dilithium) operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qpl_crypto::ml_dsa::{generate_keypair, verify};

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("ml_dsa_keypair_generation", |b| {
        b.iter(|| {
            let keypair = generate_keypair().expect("Key generation should succeed");
            black_box(keypair)
        })
    });
}

fn bench_signing(c: &mut Criterion) {
    let keypair = generate_keypair().expect("Key generation should succeed");
    let message: Vec<u8> = vec![0x42; 1024]; // 1KB message

    c.bench_function("ml_dsa_sign_1kb", |b| {
        b.iter(|| {
            let signature = keypair.sign(black_box(&message)).expect("Signing should succeed");
            black_box(signature)
        })
    });
}

fn bench_verification(c: &mut Criterion) {
    let keypair = generate_keypair().expect("Key generation should succeed");
    let message: Vec<u8> = vec![0x42; 1024]; // 1KB message
    let signature = keypair.sign(&message).expect("Signing should succeed");

    c.bench_function("ml_dsa_verify_1kb", |b| {
        b.iter(|| {
            let result = verify(
                black_box(keypair.public_key()),
                black_box(&message),
                black_box(&signature),
            )
            .expect("Verification should not error");
            black_box(result)
        })
    });
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_signing,
    bench_verification
);

criterion_main!(benches);
