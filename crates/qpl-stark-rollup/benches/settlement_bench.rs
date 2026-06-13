// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement proof benchmarks.
//!
//! Benchmarks for measuring STARK proof generation and verification performance.
//!
//! ## Metrics
//!
//! - Proof generation time (varies with batch size)
//! - Proof verification time (should be constant)
//! - Proof size in bytes
//! - Trace building time
//! - Batch execution time
//!
//! ## Running Benchmarks
//!
//! ```bash
//! cargo bench -p qpl-stark-rollup
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use qpl_stark_rollup::air::SettlementPublicInputs;
use qpl_stark_rollup::executor::StateExecutor;
use qpl_stark_rollup::prover::{ProofConfig, SecurityLevel, SettlementProver};
use qpl_stark_rollup::trace::build_settlement_trace;
use qpl_stark_rollup::types::{AccountBalance, AccountId, RollupState, Transaction};
use qpl_stark_rollup::verifier::verify_proof;

/// Helper to create a test account ID from a seed
fn test_account_id(seed: u8) -> AccountId {
    AccountId::from_bytes([seed; 32])
}

/// Helper to create a test transaction
fn make_test_transaction(
    sender_seed: u8,
    receiver_seed: u8,
    amount: u64,
    nonce: u64,
) -> Transaction {
    Transaction::new(
        test_account_id(sender_seed),
        test_account_id(receiver_seed),
        amount,
        nonce,
        1234567890,
        vec![0u8; 64], // Dummy signature
    )
}

/// Generate N valid test transactions from account 1 to account 2
fn generate_test_transactions(count: usize, initial_balance: u64) -> Vec<Transaction> {
    let amount_per_tx = initial_balance / (count as u64 + 1); // Ensure enough balance
    (0..count)
        .map(|i| make_test_transaction(1, 2, amount_per_tx, i as u64))
        .collect()
}

/// Create an initial state with funded sender account
fn make_funded_state(sender_seed: u8, sender_balance: u64) -> RollupState {
    let mut state = RollupState::new();
    let sender_id = test_account_id(sender_seed);
    state.get_or_create_account(&sender_id).balance = sender_balance;
    state.compute_state_root();
    state
}

/// Benchmark proof generation for different batch sizes.
///
/// Uses small batch sizes (2, 4, 8) since STARK proving is computationally expensive.
fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");

    // Configure for longer running benchmarks
    group.sample_size(10);

    let prover = SettlementProver::new(ProofConfig::new(SecurityLevel::Standard96));

    for batch_size in [2, 4, 8].iter() {
        let initial_balance = 1_000_000u64;
        let txs = generate_test_transactions(*batch_size, initial_balance);
        let initial_state = make_funded_state(1, initial_balance);

        group.bench_with_input(BenchmarkId::new("prove", batch_size), batch_size, |b, _| {
            b.iter(|| {
                prover
                    .prove_batch(&txs, &initial_state)
                    .expect("Proof generation should succeed")
            });
        });
    }

    group.finish();
}

/// Benchmark proof verification.
///
/// Generates a proof once and benchmarks only the verification step.
/// Verification should be fast (< 10ms typically).
fn bench_proof_verification(c: &mut Criterion) {
    // Generate a proof once outside the benchmark loop
    let prover = SettlementProver::new(ProofConfig::new(SecurityLevel::Standard96));
    let initial_balance = 10_000u64;
    let initial_state = make_funded_state(1, initial_balance);
    let txs = vec![make_test_transaction(1, 2, 100, 0)];

    let proof = prover
        .prove_batch(&txs, &initial_state)
        .expect("Proof generation should succeed");

    // Get the sender/receiver initial balances for public inputs
    let sender = AccountBalance::new(initial_balance);
    let receiver = AccountBalance::new(0);
    let trace_result = build_settlement_trace(&txs, &sender, &receiver);

    let pub_inputs = SettlementPublicInputs::new(
        sender.balance,
        receiver.balance,
        sender.nonce,
        trace_result.final_sender_balance,
        trace_result.final_receiver_balance,
        trace_result.final_nonce,
    );

    c.bench_function("proof_verification", |b| {
        b.iter(|| verify_proof(&proof, &pub_inputs).expect("Verification should succeed"));
    });
}

/// Benchmark trace building step (no proving).
///
/// Measures the time to construct the execution trace from transactions.
fn bench_trace_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_building");

    for batch_size in [10, 50, 100, 500].iter() {
        let initial_balance = 10_000_000u64;
        let txs = generate_test_transactions(*batch_size, initial_balance);
        let sender = AccountBalance::new(initial_balance);
        let receiver = AccountBalance::new(0);

        group.bench_with_input(
            BenchmarkId::new("build_trace", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| build_settlement_trace(&txs, &sender, &receiver));
            },
        );
    }

    group.finish();
}

/// Benchmark batch execution (no proving).
///
/// Measures the time to execute transaction batches through the StateExecutor.
fn bench_batch_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_execution");

    for batch_size in [10, 100, 1000].iter() {
        let initial_balance = 100_000_000u64;
        let txs = generate_test_transactions(*batch_size, initial_balance);

        group.bench_with_input(
            BenchmarkId::new("execute_batch", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    let mut state = make_funded_state(1, initial_balance);
                    StateExecutor::execute_batch(&mut state, &txs)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark state root computation.
///
/// Measures the time to compute state roots for states with varying account counts.
fn bench_state_root_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root");

    for account_count in [10, 100, 1000].iter() {
        // Create a state with many accounts
        let mut state = RollupState::new();
        for i in 0..*account_count {
            let id = AccountId::from_bytes([i as u8; 32]);
            state.get_or_create_account(&id).balance = 1000;
        }

        group.bench_with_input(
            BenchmarkId::new("compute_root", account_count),
            account_count,
            |b, _| {
                b.iter(|| {
                    state.compute_state_root();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_proof_generation,
    bench_proof_verification,
    bench_trace_building,
    bench_batch_execution,
    bench_state_root_computation,
);

criterion_main!(benches);
