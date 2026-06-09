**Deep Dive Security, Code, and Bloat Audit of https://github.com/jnodes/QPL (as of June 2026)**

### Project Overview (Context for Audit)
QPL is a **decentralized post-quantum signing and proving infrastructure** on Solana. It delivers quantum-resistant threshold signatures (ML-DSA-65 / FIPS 204) and FRI-based zk-STARK proofs via a permissionless operator network (no trusted setup). Operators stake SOL; the network uses on-chain coordination (staking, fee routing, registry) and off-chain Rust nodes for signing/proving. Clients integrate via SDK or JSON-RPC.

- **Tech stack**: Rust (98.9%) workspace + Solana Anchor programs. Key crates: `qpl-crypto` (PQC + classical + MPC + HSM), `qpl-stark-rollup` (Winterfell STARKs), `qpl-network`, `qpl-sdk`, `qpl-node` (operator binary), plus `proto/` (gRPC) and `programs/` (staking/fee/router/registry).
- **Maturity**: Extremely early (only **3 commits** on `main`, 0 stars/forks/watchers, no releases/packages). Version 0.1.0 in `Cargo.toml`. Dual MIT/Apache-2.0 license. Transparent docs include `WHITEPAPER.md`, `PROTOCOL_FLOWS.md`, self-audit, and flaw disclosure.
- **Build/Run**: Makefile-driven (`make build/test/lint/bench/testnet-up`). 200+ tests, Criterion benchmarks, Docker testnet. Anchor programs use `0.30`.

This is essentially an **alpha/prototype** with strong self-review but minimal external scrutiny.

### Bloat Audit
**Low source-level bloat; moderate-to-high dependency/runtime bloat (expected for the domain).**

- **Repository source**: Clean and minimal. Root has standard files (`.gitignore`, `Cargo.toml`/`Cargo.lock`, `Makefile`, `Anchor.toml`, `docker-compose.testnet.yml`, docs). No `node_modules`, vendor dirs, large binaries, data dumps, or `__pycache__`-style artifacts. Subdirs (`crates/`, `programs/`, `services/`, `tests/e2e/`, `proto/`, `benchmarks/`, `experts/`) are focused. No obvious cruft. Repo size appears tiny (consistent with 3 commits).
- **Dependencies (`Cargo.lock`)**: ~300+ unique transitive crates. Heavy but purposeful:
  - **Justified heavy hitters**: `tokio` + `tonic`/`prost` (async + gRPC/Protobuf for node comms/SDK), `winterfell` + winter-* suite (full STARK prover/verifier), `criterion` (benchmarks).
  - **Bloat signals**: Full async web stack (`hyper`, `axum`, `tower` in multiple versions), Protobuf codegen, ZK math libs. Multiple version conflicts (e.g., `getrandom` 0.2/0.3/0.4, `bitflags` 1/2, `tower` 0.4/0.5, `hashbrown` 0.12/0.15/0.17). These inflate build times, binary size, and potential incompatibility.
  - Off-chain crates pull the bulk; `programs/` (Solana) are lean (only `anchor-lang`/`anchor-spl` 0.30).
- **Runtime/Deploy**: `qpl-node` binary will be large due to ZK + crypto + async. Testnet uses Docker (reasonable). No embedded assets or unnecessary runtime deps.
- **Verdict**: No wasteful source bloat. Dependency bloat is typical for a crypto + ZK + networked Rust project but could be optimized (feature flags on `tonic`/`winterfell`, prune unused transitive crates, or reconsider gRPC if JSON-RPC is primary). `cargo tree --duplicates` would help clean conflicts. Overall **acceptable for scope**, but watch binary size on operator nodes.

### Code Audit
**High quality for an early-stage project; professional structure and transparency.**

- **Architecture & Practices**:
  - Clean workspace (`members` in root `Cargo.toml`: crypto, stark-rollup, network, sdk, common/*, node, e2e). Edition 2021.
  - Strong error handling (`thiserror`), serialization (`serde`), secure memory (`zeroize`), randomness (`rand` + `rand_core`).
  - Algorithmic agility layer in `qpl-crypto` (Ed25519/ECDSA-P256 native + ML-DSA-65 opt-in) — elegant and future-proof.
  - Solana programs use standard Anchor patterns (PDAs, `init` constraints, etc.) with recent fixes.
  - Thorough testing: unit (62+ in crypto), Anchor tests, e2e, testnet. Benchmarks reproducible.
- **Documentation & Maintainability**: Excellent. Self-audit report, explicit flaw disclosure, protocol flows, Makefile for everything. Contributing guidelines present. `experts/` dir suggests additional review materials.
- **Potential Weaknesses**:
  - No visible CI (no `.github/workflows`). Relies on manual `make lint/test` (likely `clippy` + tests).
  - Early code → limited peer review. 3 commits means rapid iteration possible but also untested edge cases.
  - gRPC/Protobuf in SDK/node (heavy for what README calls "JSON-RPC or SDK").
- **Verdict**: **Strong code quality**. Feels production-minded (tests, benchmarks, docs, fixes). Would benefit from CI, coverage reports, and more public eyes. No red flags like obvious dead code or poor structure.

### Security Audit
**Strong self-awareness and remediation; some lingering supply-chain and maturity risks.**

- **Self-Audit & Transparency (Big Positive)**:
  - Dedicated `qpl security audit report.md` (May 2026, internal + CISO) identified **Critical** (fee router lost 50% participant fees), **High** (stake lockup on slash, HSM key extraction breaking HW boundary), and Medium issues.
  - All **fixed** in v0.2: fee distribution + dust handling, unstake logic, `deposit_stake`, checked arithmetic (`checked_sub`/`checked_add`), config/vault init.
  - Separate `The Node-Level Implementation Flaw.md` openly documents prior HSM software shim (PQC keys in RAM via `pqcrypto` + `unwrap_key_material`). **Resolved** via algorithmic agility: production prefers FIPS 140-3 HSM-native algos (Ed25519/ECDSA-P256 — keys **never** leave hardware). ML-DSA-65 is transitional/software-only with threshold MPC as primary defense. Verified in 62+ tests.
  - Additional mitigations: `NonceRegistry` (replay protection), `High128` STARK verification, SHA-256 bindings vs. public-input attacks.

- **Cryptography**:
  - Excellent choices: NIST PQC (ML-DSA-65, ML-KEM-1024), threshold MPC, FRI zk-STARKs (no trusted setup), classical agility.
  - HSM via `cryptoki` (PKCS#11) + `zeroize`. Secure defaults.
  - **Caveats**: Relies on `pqcrypto-dilithium`/`pqcrypto-kyber` (reference implementations). Older versions (0.5.0/0.8.1-ish). STARKs via `winterfell` (Facebook/Novi research crate — **explicitly warns** it is unaudited and may contain bugs/security flaws).

- **Dependency Security (Supply Chain)**:
  - Core crates appear solid (`ed25519-dalek`, `p256`, `tokio` 1.52 recent, `rand` 0.8).
  - **Issues found**:
    - `pqcrypto-dilithium`: RUSTSEC-2024-0380 (replaced by `pqcrypto-mldsa` for proper FIPS 204/ML-DSA compliance). Recent advisories (RUSTSEC-2026-0164 / 0162) note PQClean (backend for pqcrypto crates) is archiving post-July 2026 — project must migrate soon.
    - `winterfell` 0.9.0: Research-grade; use with caution for production ZK.
    - `cryptoki` 0.7.0: No known vulns; actively maintained.
    - Multiple `getrandom` versions — minor but cargo-audit would flag for consistency.
  - No major active CVEs in core runtime deps, but no automated scanning (no Dependabot, no CI).
  - Programs: Lean Anchor 0.30 deps; fixes already applied (no reentrancy/common Solana pitfalls apparent from audit).

- **On-Chain / Network Security**:
  - Staking/slashing/fee routing now hardened (checked math, top-up support, no lockups).
  - Economic security via SOL staking + slashing. Coordinator + quorum logic on-chain.
  - Good replay/nonce handling per audit.

- **Other Risks**:
  - No CI → supply-chain and regression risks.
  - Early stage → untested attack surface (e.g., coordination layer, operator discovery).
  - RAM scraping / side-channels mitigated by agility + threshold, but software ML-DSA still carries theoretical risk if threshold is bypassed.
  - No formal third-party audit mentioned (self-audit only).

- **Verdict**: **Impressive security posture for alpha**. Transparent flaw disclosure + rapid fixes are rare and excellent. Core design (PQC + threshold + STARKs + on-chain settlement) is sound. Primary risks are **dependency freshness** (pqcrypto → mldsa migration), **winterfell research status**, and **lack of external/CI validation**. Not production-ready yet, but on a strong path.

### Overall Recommendations & Score
- **Security**: 8/10 (self-audit + fixes excellent; deps & maturity drag it down). Prioritize: `cargo audit`, update pqcrypto crates, add Dependabot/CI, consider third-party crypto/ZK audit.
- **Code**: 9/10 (clean, tested, documented).
- **Bloat**: 7/10 (source fine; deps heavy but justifiable — optimize versions/features).
- **Next Steps for Project**:
  1. Run `cargo audit` + `cargo tree` regularly.
  2. Add `.github/workflows` with tests, clippy, audit, and security scans.
  3. Migrate pqcrypto-dilithium → modern ML-DSA equivalent.
  4. Publish crates to crates.io + release tags.
  5. More activity / community review.

This project shows real thoughtfulness in post-quantum decentralization. The self-audit and flaw docs build trust. With CI, dep updates, and external review, it could be very solid. No critical unaddressed issues found in current state.