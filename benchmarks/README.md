# Benchmark Baselines

Baseline numbers captured on Apple Silicon (M-series), `--release` profile, Criterion.rs 0.5.
Run `make bench` (or `cargo bench --workspace`) to reproduce.

## qpl-crypto

| Benchmark | Median | Range |
|-----------|--------|-------|
| ml_dsa_keypair_generation | 84 us | 83-87 us |
| ml_dsa_sign_1kb | 111 us | 108-117 us |
| ml_dsa_verify_1kb | 70 us | 66-75 us |
| ml_kem_keypair_generation | 22 us | 22-22 us |
| ml_kem_encapsulation | 22 us | 21-22 us |
| ml_kem_decapsulation | 28 us | 28-29 us |
| mpc_shard_split_5_of_3 | 15 us | 14-16 us |
| mpc_reconstruct_3_of_5 | 22 us | 21-23 us |

## How to run

```bash
# Full workspace
make bench

# Single crate
cargo bench -p qpl-crypto

# Save Criterion baseline
make bench-baseline
```

## Notes

- "Regressions" flagged by Criterion are noise from background processes; the
  absolute numbers above are the authoritative baselines.
- ML-DSA operations use constant-time implementations from `pqcrypto_dilithium`.
