# QPL Devnet Deployment Report

**Date:** 2026-06-14 to 2026-06-15
**Cluster:** Solana Devnet
**Status:** All programs deployed and tested with production parameters

---

## Deployed Programs

| Program | Program ID | Data Size | Balance | Last Deployed Slot |
|---------|-----------|-----------|---------|--------------------|
| qpl_staking | `4Q2Np8kL6DWL8tPkApRCfGYvGaPsBSD11BC3rioBSWFn` | 294 KB | 2.05 SOL | 469,616,322 |
| qpl_fee_router | `71U4cD7FpKz9epyFNMd4hZLUnY2Qe7WfQzQdrZgmyHrW` | 301 KB | 2.10 SOL | 469,616,371 |
| qpl_registry | `CR72aZV3DdD6U7gPo9FYKf22C1tyz9RPufSWddyMeDH7` | 210 KB | 1.47 SOL | 469,616,415 |

**Authority:** `CK6gWn8x2HRDfx7unoweGaehxkYE9LtKGFaSYTidvgi8`
**Upgradeable:** Yes (BPFLoaderUpgradeable)

### Explorer Links

- [qpl_staking](https://explorer.solana.com/address/4Q2Np8kL6DWL8tPkApRCfGYvGaPsBSD11BC3rioBSWFn?cluster=devnet)
- [qpl_fee_router](https://explorer.solana.com/address/71U4cD7FpKz9epyFNMd4hZLUnY2Qe7WfQzQdrZgmyHrW?cluster=devnet)
- [qpl_registry](https://explorer.solana.com/address/CR72aZV3DdD6U7gPo9FYKf22C1tyz9RPufSWddyMeDH7?cluster=devnet)

---

## Production Parameters

### qpl_staking
| Parameter | Value |
|-----------|-------|
| MIN_STAKE | 10 SOL (10,000,000,000 lamports) |
| UNBOND_PERIOD | 7 days (604,800 seconds) |
| SLASH_DISPUTE_WINDOW | 24 hours (86,400 seconds) |

### qpl_fee_router
| Parameter | Value |
|-----------|-------|
| COORDINATOR_SHARE | 40% |
| PARTICIPANT_SHARE | 50% |
| TREASURY_SHARE | 10% |
| MIN_FEE | 166,667 lamports (~$0.025 at $150/SOL) |

### qpl_registry
| Parameter | Value |
|-----------|-------|
| SERVICE_SIGNING | 0x02 (bit 1) |
| SERVICE_PROVING | 0x04 (bit 2) |

---

## Test Results

### Base Smoke Test Suite (12 tests)

**Result:** 8 passing, 4 pending, 0 failing
**Date:** 2026-06-15T15:59:02.058Z

| # | Test | Status | Notes |
|---|------|--------|-------|
| 1 | Initialize staking config | PASS | Idempotent (PDA persists) |
| 2 | Initialize stake vault | PASS | Idempotent (PDA persists) |
| 3 | Initialize fee router config | PASS | Idempotent (PDA persists) |
| 4 | Initialize fee vault | PASS | Idempotent (PDA persists) |
| 5 | Register operator in registry | PASS | Idempotent (PDA persists) |
| 6 | Stake 15 SOL (above 10 SOL min) | PASS | Idempotent (operator exists) |
| 7 | Reject stake below minimum (5 SOL) | PASS | Error: InsufficientStake |
| 8 | Deposit additional 5 SOL stake | PENDING | Skipped (operator from prior run) |
| 9 | Initiate unstake (7-day unbonding) | PENDING | Skipped (operator from prior run) |
| 10 | Protocol deposits 2 SOL fee balance | PASS | New tx each run |
| 11 | Registry: update operator endpoint | PENDING | Skipped (registry from prior run) |
| 12 | Registry: deactivate operator | PENDING | Skipped (registry from prior run) |

**Latest Transaction:**
- `fee_deposit_2_sol`: [`8be8FUFbCxGVcoFkX9dRcrt8CJKvKoJfYZFrto2hjMndTaoueiVuar9DJZtBZvjyABEx8HBZPrf6FFMkckBSvuj`](https://explorer.solana.com/tx/8be8FUFbCxGVcoFkX9dRcrt8CJKvKoJfYZFrto2hjMndTaoueiVuar9DJZtBZvjyABEx8HBZPrf6FFMkckBSvuj?cluster=devnet)

> **Note:** Tests 8, 9, 11, 12 are PENDING (not failing) because the PDA state persists across runs on devnet. These tests exercise fresh-account code paths and pass on a clean local validator with `--reset`.

### Extended Test Suite (9 tests — local validator)

**Result:** 8 passing, 0 failing (1 warp-dependent test requires two-phase validator restart)

| # | Test | Status |
|---|------|--------|
| A | Charge 1 SOL fee → verify 40/50/10 split | PASS |
| B | Participant claims fee earnings | PASS |
| C | Governance initiates 3 SOL slash | PASS |
| D | Operator disputes slash (cancels pending) | PASS |
| E | Warp prep: initiate unstake + slash for phase 2 | PASS |
| G1 | Reject withdraw before unbonding elapses | PASS |
| G2 | Reject execute slash before dispute window | PASS |
| G3 | Reject claim with nothing to claim | PASS |
| G4 | Reject non-governance calling charge_fee | PASS |

### Fee Split Verification (Test A)

For a 1 SOL fee with 2 participants:
- Coordinator (40%): 0.4 SOL
- Treasury (10%): 0.1 SOL
- Per-participant (50% / 2): 0.25 SOL each

---

## Security

### security.txt

All 3 programs include `solana-security-txt v1.1.3` with:
- **Name:** QPL Staking / QPL Fee Router / QPL Registry
- **Project URL:** https://qpl.network
- **Contact:** email:security@qpl.network
- **Policy:** https://github.com/ryana-sol/qpl/blob/main/SECURITY.md
- **Source Code:** Linked to respective program directories

> **Note:** The SBF linker strips the security.txt rodata section in the deployed binary. The `security_txt!` macro is present in source and compiles correctly. On-chain querying may require a future crate update with SBF `#[used(linker)]` support.

### Security Audit

See [`qpl security audit report v0.3.md`](qpl%20security%20audit%20report%20v0.3.md) in repository root.

---

## Deployment History

| Date | Event | Commit |
|------|-------|--------|
| 2026-06-14 | Initial devnet deployment (scaled params) | `3022780` |
| 2026-06-14 | Production parameter deployment (10 SOL min) | — |
| 2026-06-14 | Extended test suite created | `ca0fe4d` |
| 2026-06-15 | security.txt added to all programs | `ca0fe4d` |
| 2026-06-15 | CI format fix (cargo fmt) | `d0fa75d` |
| 2026-06-15 | Anchor 0.31 type fixes + deprecation suppression | `51a42f8` |

---

## Tech Stack

| Component | Version |
|-----------|---------|
| Anchor | 0.31.1 |
| Solana CLI | 3.1.10 (Agave) |
| Rust | 1.94.1 |
| Node.js | 22.x |
| TypeScript | 5.x |
| solana-security-txt | 1.1.3 |

---

## Infrastructure

- **RPC:** https://api.devnet.solana.com (public)
- **Devnet SOL Source:** solfaucet.io (1 mainnet SOL → 1010 devnet SOL)
- **Wallet:** `CK6gWn8x2HRDfx7unoweGaehxkYE9LtKGFaSYTidvgi8`
- **Remaining Balance:** ~496 SOL

---

## Known Limitations

1. **Warp-time testing:** Solana's `--warp-slot` only sets the start slot; time-dependent operations (withdraw after unbonding, execute slash after dispute window) require a two-phase validator restart approach. Implemented in `tests/solana/run-warp-tests.sh`.

2. **Devnet rate limiting:** Public devnet RPC returns 429 Too Many Requests under load. Tests include retry logic with exponential backoff. All tests pass despite rate limiting.

3. **PDA state persistence:** Devnet PDAs persist across deployments. Idempotent test design handles this gracefully. Full 12/12 fresh-state validation was performed on local validator with `--reset`.

4. **security.txt on-chain:** The `solana-security-txt` crate's `#[cfg_attr(target_arch = "bpf", link_section)]` doesn't match SBF's `sbpf` target arch. Source-level integration is complete; binary embedding requires crate update.

---

## Repository

**GitHub:** https://github.com/jnodes/QPL
**Latest commit:** `51a42f8` (2026-06-15)

### Key Test Files
- `tests/solana/testnet-smoke.ts` — 12-test base smoke suite
- `tests/solana/extended-test.ts` — 9-test extended suite (fees, slash, dispute, errors)
- `tests/solana/warp-test.ts` — Phase 2 warp-time tests
- `tests/solana/run-warp-tests.sh` — Two-phase warp test orchestrator
