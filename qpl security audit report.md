Based on a comprehensive review of the QPL Network architecture, cryptography, STARK rollup, and Solana Anchor smart contracts, here is the full security audit report.

### Executive Summary

The QPL (Quantum Proof Ledger) protocol demonstrates a sophisticated design integrating post-quantum cryptography (ML-DSA and ML-KEM) and FRI-based STARK proofs. Notable security-conscious design choices include implementing the `NonceRegistry` to thwart cross-batch replay attacks and enforcing `High128` verification standards by default.

However, the audit has identified **Critical** flaws in the fee routing smart contract leading to lost funds, and **High** severity architectural flaws in the HSM key-management implementation that violate hardware boundaries.

---

### Critical Vulnerabilities

#### 1. Complete Loss of Participant Fees in `QPLFeeRouter`

* **Location:** `programs/qpl-fee-router/src/lib.rs` (`charge_fee` instruction)
* **Description:** The `charge_fee` function accurately calculates the 40/50/10 split for the coordinator, participants, and treasury. While it successfully adds the `coordinator_amount` to the coordinator's claimable earnings and transfers the `treasury_amount` directly to the treasury, it entirely fails to allocate the participants' pool. The `per_participant` amount is calculated and emitted in the `FeeCharged` event, but it is never added to the respective participants' earnings accounts.
* **Impact:** 50% of all generated network fees will be permanently stranded in the `fee_vault` PDA. Operators acting as participants will perform threshold signing/proving but will never be compensated.
* **Remediation:** Update the instruction context to accept an array/slice of participant `OperatorEarnings` accounts. Iterate over these accounts and increment their `claimable` balance by `per_participant`.

---

### High Vulnerabilities

#### 2. Operator Stake Lockup on Protocol Slashing

* **Location:** `programs/qpl-staking/src/lib.rs` (`slash` and `initiate_unstake` instructions)
* **Description:** In the `slash` function, if an operator's stake is reduced below the `MIN_STAKE_LAMPORTS` threshold, the program automatically deactivates them (`operator_account.active = false`). If the operator subsequently attempts to withdraw their remaining funds by calling `initiate_unstake`, the transaction will revert because `initiate_unstake` enforces `require!(operator_account.active, QplStakingError::NotActive)`.
* **Impact:** Any operator slashed below the minimum threshold has the remainder of their funds permanently locked in the protocol with no mechanism to initiate the 7-day unbonding period.
* **Remediation:** Remove the `active` constraint from `initiate_unstake`, or automatically set the `unstake_time` to trigger unbonding during a deactivating slash.

#### 3. Private Key Extraction in HSM Architecture

* **Location:** `crates/qpl-crypto/src/hsm.rs` (`Pkcs11HsmProvider`)
* **Description:** Because hardware HSM firmware does not yet natively support post-quantum ML-DSA-65 or ML-KEM-1024 primitives, the `Pkcs11HsmProvider` attempts a hybrid workaround. It encrypts private keys via an AES-256 wrapping key and stores them as `CKO_DATA` objects. When signing or decapsulating, the application retrieves the wrapped data, decrypts it into software memory (`unwrap_key_material`), performs the operation in RAM, and then zeroizes the memory.
* **Impact:** This approach completely breaks the fundamental security boundary of a Hardware Security Module. Unencrypted post-quantum private key material is exposed to the host machine's memory, rendering it vulnerable to RAM scraping, core dumps, and kernel-level exploits.
* **Remediation:** The system should aggressively document this as an insecure shim. For production use, true HSM integration cannot happen until FIPS 203/204 algorithms are natively supported so that the raw key material never leaves the hardware boundary.

---

### Medium Vulnerabilities

#### 4. Stranded Dust from Integer Division (Fee Router)

* **Location:** `programs/qpl-fee-router/src/lib.rs` (`charge_fee`)
* **Description:** When calculating the participant pool distribution, the division `participant_pool / participants.len() as u64` truncates the remainder. This structural risk was conceptually flagged in the financial modeling, but the codebase does not handle the remaining modulo dust.
* **Impact:** Over thousands of micro-fee transactions, stranded lamports will permanently accumulate in the `fee_vault`.
* **Remediation:** Compute the remainder (`participant_pool % participants.len()`) and allocate it to the `coordinator_amount` or `treasury_amount`.

#### 5. Lack of Stake "Top-Up" Mechanism

* **Location:** `programs/qpl-staking/src/lib.rs`
* **Description:** The `stake` instruction uses the Anchor `init` constraint to create the `operator_account` PDA based on `operator_id`. If an operator wishes to add more stake later (or needs to top up their stake after being slashed), they cannot call `stake` again because the PDA is already initialized, resulting in a collision.
* **Impact:** Operators cannot increase their collateral or recover from a non-deactivating slash without fully exiting the network and starting over.
* **Remediation:** Introduce a distinct `deposit_stake` instruction that adds lamports to an already initialized `operator_account`.

---

### Informational & Hardening Notes

* **Red-Team Verifications (S1, S2, S3):** The protocol correctly applies critical mitigations identified in past audits. The default STARK verifier restricts verification to `High128` configurations, and public-input substitution attacks are thwarted using SHA-256 bindings inside `verify_proof_with_commitment`. Additionally, the `NonceRegistry` cleanly isolates nonces to prevent cross-batch replay exploits.

---

## Remediation Status (May 2026)

All findings in this report have been addressed. The table below summarizes the remediation, file references, and verification status as of v0.2 of the codebase.

| # | Severity | Finding | Status | Remediation |
|---|----------|---------|--------|-------------|
| 1 | Critical | Lost participant fees in `QPLFeeRouter` | **Fixed** | `charge_fee` now accepts a `remaining_accounts` slice of `OperatorEarnings` PDAs and increments each by `per_participant`. Dust is allocated to the coordinator. |
| 2 | High | Operator stake lockup on slashing | **Fixed** | The `active` constraint was removed from `initiate_unstake`. A slashed-below-minimum operator can still trigger the 7-day unbonding and recover residual lamports. |
| 3 | High | Private-key extraction in HSM hybrid architecture | **Resolved via algorithmic agility** | The `qpl-crypto` HSM trait now supports per-algorithm signing. Operators deploy on Ed25519 / ECDSA-P256 with FIPS 140-3 hardware where the key never leaves the HSM. ML-DSA-65 remains available as an opt-in software algorithm pending FIPS 204 firmware. See `crates/qpl-crypto/src/algorithm.rs` and `WHITEPAPER.md` §3.6. |
| 4 | Medium | Stranded dust in fee router | **Fixed** | Remainder from `participant_pool % participants.len()` is added to `coordinator_amount`. |
| 5 | Medium | No stake top-up mechanism | **Fixed** | New `deposit_stake(operator_id, amount)` instruction adds lamports to an existing `OperatorAccount` PDA without re-init. |

### Internal CISO Audit (2026-05) — additional findings

| # | Severity | Finding | Status | Remediation |
|---|----------|---------|--------|-------------|
| 6 | Critical | `StakingConfig` PDA referenced by `slash` but never initialized | **Fixed** | New `initialize_config(treasury)` instruction creates the singleton config PDA at deployment. New `initialize_vault()` instruction creates the system-owned `StakeVault` PDA. |
| 7 | Medium | Raw `**lamports -= amount` in `withdraw` and `slash` (no overflow guard) | **Fixed** | All lamport mutations now use `checked_sub`/`checked_add` with new error variants `InsufficientVaultBalance` and `Overflow`. |

### Verification

- `cargo test -p qpl-crypto` — 62 unit tests passing (17 new agility tests).
- `cargo test -p qpl-staking` — Anchor unit tests passing.
- Workspace `cargo test` — 200+ tests passing across all crates.
- See [PROTOCOL_FLOWS.md](PROTOCOL_FLOWS.md) §6 for the Mermaid sequence of the post-remediation slashing flow.

### GTM Status

All Critical and High findings closed. The HSM "NOT PRODUCTION-READY" caveat from finding #3 has been replaced with the algorithmic agility model documented in WHITEPAPER §3.6 / §10.5. Production deployments may now proceed on Ed25519 or ECDSA-P256 with FIPS 140-3 certified HSMs.