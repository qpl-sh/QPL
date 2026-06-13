# QPL Threat Model

**Version:** 1.0  
**Last Updated:** 2026-06-09  
**Classification:** Internal — Security Engineering  
**Scope:** QPL (Quantum Proof Layer) protocol infrastructure

---

## 1. System Overview & Trust Boundaries

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          UNTRUSTED ZONE (Internet)                           │
│                                                                             │
│  ┌─────────────┐          mTLS + JWT           ┌──────────────────────┐    │
│  │  Client SDK │ ─────────────────────────────► │   qpl-node (gRPC)   │    │
│  │  (qpl-sdk)  │   AuthEnvelope + ML-DSA sig   │   Rate-limited       │    │
│  └─────────────┘                                │   Per-operator auth  │    │
│                                                 └──────────┬───────────┘    │
│                                                            │                │
├────────────────────────────────────────────────────────────┼────────────────┤
│                    OPERATOR TRUST ZONE                      │                │
│                                                            ▼                │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Operator Network (qpl-network)                    │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐ │  │
│  │  │  Discovery  │  │ Coordination │  │   Threshold MPC (t-of-n)    │ │  │
│  │  │  & Routing  │  │   Protocol   │  │   DKG / Partial Signatures  │ │  │
│  │  └─────────────┘  └──────────────┘  └─────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│  ┌───────────────────────────┼──────────────────────────────────────────┐  │
│  │  HARDWARE TRUST ZONE      │                                           │  │
│  │  ┌────────────────────────▼──────────────────────────────────────┐   │  │
│  │  │              HSM (FIPS 140-3)                                  │   │  │
│  │  │  ┌─────────────────┐  ┌────────────────┐  ┌──────────────┐   │   │  │
│  │  │  │ Ed25519 Signing │  │ ECDSA-P256 Sig │  │ AES-256 Wrap │   │   │  │
│  │  │  │  (key in HW)    │  │  (key in HW)   │  │ (ML-DSA key) │   │   │  │
│  │  │  └─────────────────┘  └────────────────┘  └──────────────┘   │   │  │
│  │  └───────────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
├──────────────────────────────┼──────────────────────────────────────────────┤
│              SOLANA L1       │  (ON-CHAIN TRUST ZONE)                       │
│                              ▼                                              │
│  ┌─────────────────┐  ┌────────────────┐  ┌────────────────────────────┐  │
│  │  qpl-staking    │  │ qpl-fee-router │  │  qpl-registry              │  │
│  │  (10 SOL min,   │  │ (40/50/10 split│  │  (PDA-based operator       │  │
│  │   7d unbond,    │  │  min fee 6667  │  │   accounts, services       │  │
│  │   slashing)     │  │  lamports)     │  │   bitmask)                 │  │
│  └─────────────────┘  └────────────────┘  └────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  qpl-stark-rollup (FRI-based STARK proofs)                           │  │
│  │  Blake3-256 | 128-bit field | No trusted setup | Private Validium    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries Summary

| Boundary | Inner Trust Zone | Outer Zone | Enforcement |
|----------|-----------------|------------|-------------|
| HSM hardware envelope | Key material, signing operations | Operator process memory | PKCS#11 API, FIPS 140-3 physical tamper resistance |
| mTLS termination | Authenticated gRPC channel | Public internet | X.509 WebPKI client verification (rustls) |
| Per-request auth | Authorized operator with valid ML-DSA signature | Unauthenticated requests | `AuthEnvelope` with timestamp window (±30s past / +5s future) |
| Solana runtime | PDA-gated on-chain state | Off-chain operator logic | Anchor constraints, `has_one`, signer checks |
| Coordination quorum | Threshold-complete responses | Individual partial responses | t-of-n threshold requirement |

### On-Chain vs Off-Chain Trust Assumptions

- **On-chain (Solana L1):** Assumed to provide finality, atomic execution, and account model integrity. Solana validator set is trusted for liveness and ordering.
- **Off-chain (Operator Network):** Byzantine fault-tolerant via threshold cryptography. Any individual operator is untrusted; security requires t > n/2 honest participants.
- **Private Validium:** Transaction data remains off-chain; only STARK proofs and state commitments are posted. Data availability depends on operator cooperation.

---

## 2. Threat Actors

### 2.1 Quantum Adversary (TA-Q)

- **Profile:** Nation-state actor with access to a Cryptographically Relevant Quantum Computer (CRQC)
- **Capabilities:** Shor's algorithm for breaking ECDLP/RSA; Grover's for brute-forcing symmetric keys (quadratic speedup)
- **Motivation:** Decryption of harvested ciphertexts, signature forgery on classical algorithms
- **Timeline:** Estimated 2030–2040 for CRQC capable of breaking 256-bit ECC; harvest-now-decrypt-later is active today
- **Relevant assets:** Operator signing keys (Ed25519/ECDSA-P256), ML-KEM encapsulated sessions

### 2.2 Compromised Operator (TA-O)

- **Profile:** Single malicious or coerced node operator within the network
- **Capabilities:** Access to own HSM shard, operator private key, local process memory, network traffic to/from own node
- **Motivation:** Economic extraction, disruption of service, data exfiltration
- **Constraints:** Cannot produce valid threshold signatures alone (requires t-of-n); on-chain actions bounded by staking economics

### 2.3 Network Attacker (TA-N)

- **Profile:** Active man-in-the-middle on operator-to-operator or client-to-node links
- **Capabilities:** Traffic interception, replay, injection, connection reset
- **Motivation:** Credential theft, transaction manipulation, denial of service
- **Constraints:** Cannot forge mTLS certificates without CA compromise; timestamp windows limit replay utility

### 2.4 Malicious Coordinator (TA-C)

- **Profile:** Byzantine coordination node responsible for orchestrating multi-operator rounds
- **Capabilities:** Selective message routing, round stalling, false timeout declarations, split-brain attacks
- **Motivation:** Disruption, fee manipulation, censorship of specific operators
- **Constraints:** Bounded by per-operator round caps (1024) and global round cap (65,536); coordination rounds have 5-minute max age with automatic cleanup

### 2.5 Economic Attacker (TA-E)

- **Profile:** Actor exploiting protocol economic mechanisms for profit extraction
- **Capabilities:** Smart contract interaction, MEV strategies, Sybil operator registration
- **Motivation:** Fee extraction via dust attacks, griefing via mass slashing proposals, stake lockup manipulation
- **Constraints:** MIN_FEE_LAMPORTS (166,667 lamports ≈ $0.025) prevents dust; MIN_STAKE (10 SOL ≈ $680) raises Sybil cost; 7-day unbonding limits rapid withdrawal

### 2.6 Supply Chain Attacker (TA-S)

- **Profile:** Actor who compromises upstream dependencies or build toolchain
- **Capabilities:** Backdoored crates, compromised CI/CD, malicious PRs
- **Motivation:** Credential harvesting, cryptographic weakening, persistent backdoor
- **Relevant vectors:** `pqcrypto-mldsa` (FFI to C), `winterfell` (research-grade), `anchor-lang`, `rustls`

---

## 3. Attack Surfaces

### 3.1 Key Management

| Property | Detail |
|----------|--------|
| **Entry points** | Key generation (DKG/Shamir), HSM storage (PKCS#11), signing operations, key rotation |
| **Potential impact** | Complete signature forgery, threshold compromise if ≥t shards obtained |
| **Current mitigations** | HSM hardware boundary for Ed25519/ECDSA-P256 (key never leaves HW); AES-256 wrapping for ML-DSA software fallback; constant-time implementations; zeroize-on-drop for secret keys; threshold splitting (no single point of compromise) |
| **Residual risk** | ML-DSA software fallback exposes shard in process memory during signing; HSM firmware bugs could leak key material |

### 3.2 STARK Proof Generation / Verification

| Property | Detail |
|----------|--------|
| **Entry points** | Prover pipeline (batch construction, trace generation), verifier (proof deserialization, FRI verification) |
| **Potential impact** | Forged proof accepted → invalid state transition settled on L1; soundness break → asset theft |
| **Current mitigations** | 96-bit minimum security level (2^-96 soundness error); FRI-based (no trusted setup, no toxic waste); Blake3-256 collision resistance (128-bit post-quantum); `AcceptableOptions` enforcement in verifier; `is_proof_well_formed` structural validation |
| **Residual risk** | Winterfell library is research-grade and unaudited; implementation bugs in AIR constraint definition could weaken soundness |

### 3.3 Fee Router

| Property | Detail |
|----------|--------|
| **Entry points** | `deposit_balance`, `charge_fee`, `claim` instructions; `remaining_accounts` for participant distribution |
| **Potential impact** | Economic extraction (draining vault), fee manipulation, dust-attack DoS on participant PDAs |
| **Current mitigations** | `MIN_FEE_LAMPORTS` (6,667) prevents dust; fully checked arithmetic (overflow/underflow); PDA derivation validation for participant accounts; governance-only `charge_fee`; conservation-of-value invariant (coordinator + treasury + participants*N + remainder = amount) |
| **Residual risk** | Integer division dust awarded to coordinator (documented policy); governance key compromise enables arbitrary fee extraction |

### 3.4 Staking / Slashing

| Property | Detail |
|----------|--------|
| **Entry points** | `stake`, `initiate_unstake`, `withdraw`, `slash`, `deposit_stake` instructions |
| **Potential impact** | Griefing (unjust slashing), stake lockup attacks, draining vault |
| **Current mitigations** | 10 SOL minimum stake (~$680); 7-day unbonding period; `has_one` authority checks; governance-only slashing; checked arithmetic on all lamport transfers; auto-deactivation when stake drops below minimum |
| **Residual risk** | Governance key compromise enables arbitrary slashing; no on-chain dispute mechanism for contested slashes; no progressive slashing (full amount or nothing) |

### 3.5 gRPC Endpoints

| Property | Detail |
|----------|--------|
| **Entry points** | TCP listener, TLS handshake, JSON-RPC dispatch, `AuthEnvelope` verification |
| **Potential impact** | DoS (resource exhaustion), authentication bypass, unauthorized operations |
| **Current mitigations** | mTLS with WebPKI client verification (rustls); per-operator token-bucket rate limiting (DashMap, configurable burst/refill); ML-DSA signature verification on every request; timestamp window enforcement (30s past, 5s future); canonical pre-image prevents signature transplant; generic error codes prevent oracle attacks (all auth failures map to single `AuthenticationFailed`) |
| **Residual risk** | Dev-mode SHA-256 signature stub (must never ship to production); health endpoint is unauthenticated (information disclosure); no connection-level rate limiting (pre-TLS DoS) |

### 3.6 Protocol Coordination

| Property | Detail |
|----------|--------|
| **Entry points** | `start_round`, `submit_partial`, round timeout/cleanup |
| **Potential impact** | Split-brain (conflicting quorums), memory exhaustion, round stalling, censorship |
| **Current mitigations** | Per-operator concurrent round cap (1,024); global round cap (65,536); soft cleanup threshold (2,048 rounds triggers GC); 5-minute max round age with automatic eviction; deterministic round IDs prevent replay |
| **Residual risk** | No formal BFT consensus (relies on threshold property only); coordinator censorship of specific operator partials is possible but detectable |

### 3.7 Client SDK

| Property | Detail |
|----------|--------|
| **Entry points** | Configuration loading, TLS connection establishment, request signing, response parsing |
| **Potential impact** | Credential theft, MITM (if TLS misconfigured), transaction manipulation |
| **Current mitigations** | mTLS channel binding; canonical JSON pre-image prevents malleability; timestamp-bound signatures prevent replay; hex-encoded public key identity (SHA-256 of ML-DSA pubkey) |
| **Residual risk** | Client-side key storage is application-dependent (outside QPL control); no certificate pinning in SDK (relies on system trust store) |

---

## 4. Mitigations Matrix

| # | Threat | Mitigation | Component | Status |
|---|--------|-----------|-----------|--------|
| M-1 | Quantum key compromise (TA-Q) | PQC algorithmic agility — operators select Ed25519/ECDSA-P256 today, hot-swap to ML-DSA-65 when HSM firmware ships FIPS 204 | `qpl-crypto::algorithm` | **Implemented** |
| M-2 | Key extraction from memory (TA-O) | HSM hardware boundary — Ed25519/ECDSA-P256 keys never leave PKCS#11 hardware | `qpl-crypto::hsm` | **Implemented** |
| M-3 | Single-operator compromise (TA-O) | Threshold MPC — t-of-n key splitting via DKG/Shamir; no single shard is sufficient | `qpl-network::coordination` | **Implemented** |
| M-4 | Forged settlement proofs (TA-O, TA-Q) | STARK transparency — FRI-based proofs with no trusted setup; hash-based security (quantum-safe) | `qpl-stark-rollup` | **Implemented** |
| M-5 | Replay attacks (TA-N) | Nonce registry + timestamp window — per-request timestamps with ±30s/+5s clock-skew bounds | `qpl-node::auth` | **Implemented** |
| M-6 | Network interception (TA-N) | mTLS — mutual TLS with WebPKI client certificate verification via rustls | `qpl-node::tls` | **Implemented** |
| M-7 | Per-operator DoS (TA-N, TA-E) | Token-bucket rate limiting — per-operator buckets with configurable burst capacity and refill rate | `qpl-node::rate_limit` | **Implemented** |
| M-8 | Arithmetic overflow/underflow (TA-E) | Checked arithmetic — all lamport operations use `checked_add`/`checked_sub`/`checked_mul` | `qpl-staking`, `qpl-fee-router` | **Implemented** |
| M-9 | Operator accountability (TA-O) | Slashing economics — governance can slash stake; auto-deactivation below minimum; 7-day unbonding | `qpl-staking` | **Implemented** |
| M-10 | Dust attacks (TA-E) | Minimum fee threshold — `MIN_FEE_LAMPORTS = 6,667` (~$0.001) rejects sub-economic transactions | `qpl-fee-router` | **Implemented** |
| M-11 | Coordination memory exhaustion (TA-C) | Bounded state — per-operator (1,024) and global (65,536) round caps with TTL-based eviction | `qpl-network::coordination` | **Implemented** |
| M-12 | ML-DSA shard at rest (TA-O) | AES-256 wrapping — software-fallback ML-DSA keys wrapped at rest, zeroized after use | `qpl-crypto::hsm` | **Implemented** |
| M-13 | Auth failure oracle (TA-N) | Generic error codes — all authentication failures return single `AuthenticationFailed` code | `qpl-node::auth` | **Implemented** |
| M-14 | PQC key encapsulation (TA-Q) | ML-KEM-1024 (FIPS 203) — quantum-safe session key establishment | `qpl-crypto::ml_kem` | **Implemented** |
| M-15 | Connection-level DoS (TA-N) | Pre-TLS connection rate limiting / SYN cookies | Infrastructure | **Planned** |
| M-16 | Formal STARK verification (TA-S) | Formal verification of AIR constraints and prover/verifier equivalence | `qpl-stark-rollup` | **Planned** |
| M-17 | Supply chain integrity (TA-S) | Dependency auditing, SBOM generation, reproducible builds | CI/CD | **Partial** |
| M-18 | On-chain dispute resolution (TA-O) | Challenge period for contested slashing decisions | `qpl-staking` | **Planned** |
| M-19 | Certificate pinning (TA-N) | SDK-side certificate pinning to prevent rogue CA attacks | `qpl-sdk` | **Planned** |
| M-20 | Nonce registry on-chain (TA-N) | On-chain nonce tracking for cross-session replay prevention | `qpl-stark-rollup::executor` | **Implemented** |

---

## 5. Quantum Threat Timeline

### Current State (2026)

```
┌───────────────────────────────────────────────────────────────────┐
│  PRIMARY: Classical algorithms (Ed25519, ECDSA-P256) via HSM      │
│  FALLBACK: ML-DSA-65 (FIPS 204) in software with AES-256 wrap    │
│  SETTLEMENT: FRI/STARK (hash-based, quantum-safe by construction) │
│  KEX: ML-KEM-1024 (FIPS 203) available for session establishment  │
└───────────────────────────────────────────────────────────────────┘
```

### NIST Standardization Status

| Standard | Algorithm | Status | QPL Integration |
|----------|-----------|--------|-----------------|
| FIPS 203 | ML-KEM (Kyber) | Standardized (2024) | `qpl-crypto::ml_kem` — ML-KEM-1024 |
| FIPS 204 | ML-DSA (Dilithium) | Standardized (2024) | `qpl-crypto::ml_dsa` — ML-DSA-65 |
| FIPS 205 | SLH-DSA (SPHINCS+) | Standardized (2024) | Not yet integrated (stateless hash-based backup) |

### Migration Triggers

The following conditions trigger transition from classical-primary to PQC-primary mode:

1. **HSM firmware availability:** Major HSM vendors (Thales Luna, AWS CloudHSM, Marvell LiquidSecurity) ship native FIPS 204 mechanisms
2. **CRQC milestone:** Public demonstration of factoring RSA-2048 equivalent or ECDLP on secp256k1/Ed25519 curves
3. **NIST advisory:** NIST or NSA issues "harvest urgency" guidance mandating PQC for new deployments
4. **Regulatory mandate:** Financial regulators (OCC, FINMA, MAS) mandate PQC for digital asset infrastructure
5. **Threshold:** When ≥50% of active operators have ML-DSA-capable HSMs, governance may vote to require PQC-only

### Harvest-Now-Decrypt-Later (HNDL) Considerations

| Asset Type | Sensitivity Lifetime | HNDL Risk | Mitigation |
|-----------|---------------------|-----------|------------|
| Operator signing keys | Indefinite (until rotated) | **HIGH** — forged signatures enable arbitrary operations | Algorithmic agility allows hot-rotation to ML-DSA without protocol changes |
| ML-KEM session keys | Ephemeral (single session) | **MEDIUM** — past sessions could be decrypted | Forward secrecy via ephemeral KEM; long-term secrets should use ML-KEM-1024 |
| STARK proofs | Permanent (on-chain) | **LOW** — STARKs are hash-based and quantum-safe | No action required; already resistant |
| Transaction data (Validium) | Long-lived (financial records) | **HIGH** — off-chain data if encrypted with classical KEX | Mandate ML-KEM for any long-term data-at-rest encryption |

### Recommended Migration Timeline

```
2024-2025: NIST standards finalized ✓ (FIPS 203/204/205 published)
2025-2026: QPL implements ML-DSA/ML-KEM integration ✓ (current state)
2026-2028: HSM vendors ship native FIPS 204 firmware (monitor)
2027-2029: Operator rotation to PQC-primary mode (when HSMs ready)
2030+:     Deprecate classical-only operator registration
```

---

## 6. Residual Risks & Assumptions

### 6.1 Third-Party Library Risks

| Dependency | Risk Level | Concern |
|-----------|-----------|---------|
| `winterfell` | **HIGH** | Research-grade STARK library; no formal audit; soundness depends on correct AIR implementation |
| `pqcrypto-mldsa` | **MEDIUM** | FFI binding to PQClean C reference implementation; C code surface for memory safety issues |
| `rustls` | **LOW** | Well-audited TLS implementation, but any TLS library is a critical security boundary |
| `anchor-lang` | **LOW** | Widely used Solana framework; Anchor constraint system is mature but upgrades may introduce breaking changes |
| `dashmap` | **LOW** | Lock-free concurrent map; correctness bugs could cause rate-limiter bypass |

### 6.2 Cryptographic Assumptions

- **Threshold MPC assumes honest majority:** Security requires t > n/2 honest operators. If an adversary compromises t shards across operators on independent infrastructure, they can forge signatures. The threshold parameter must be chosen such that compromising t distinct HSMs on separate networks is infeasible.
- **FRI soundness:** Relies on the conjecture that Reed-Solomon codes with random evaluation points have no low-degree polynomials passing through more than the expected number of points. This is well-studied but not formally proven for all parameter regimes.
- **Blake3 collision resistance:** 128-bit post-quantum security assumes Grover's provides at most quadratic speedup. If a better-than-Grover quantum algorithm for hash collisions is found, security level degrades.

### 6.3 Infrastructure Assumptions

- **HSM vendor trust:** We assume FIPS 140-3 Level 3 certified HSMs correctly implement their security boundary. Firmware vulnerabilities (e.g., side-channel leaks, key extraction via debug interfaces) are outside our threat model but within nation-state actor capabilities.
- **Solana runtime correctness:** On-chain programs assume the Solana runtime correctly enforces account ownership, signer verification, and PDA derivation. A Solana consensus failure or runtime bug could invalidate on-chain security invariants.
- **Clock accuracy:** Authentication timestamp validation assumes operator system clocks are synchronized to within 30 seconds of true time (NTP). Clock manipulation could enable replay or premature request expiry.
- **DNS/PKI infrastructure:** mTLS relies on the Web PKI trust model. CA compromise or DNS hijacking could enable MITM despite certificate verification.

### 6.4 Operational Assumptions

- **Governance key security:** Slashing and fee configuration operations are governance-gated. Compromise of the governance key enables arbitrary slashing, treasury drain, and operator deactivation with no on-chain dispute mechanism.
- **Data availability (Validium):** Private Validium mode assumes designated operators maintain off-chain data availability. Coordinated data withholding by a majority of operators could make state irrecoverable (proofs remain verifiable but state cannot be reconstructed).
- **Dev-mode signature stub:** The `dev_signature` function (SHA-256-based HMAC-style stub) exists in production code paths gated by key length. Accidental registration of a 32-byte placeholder key would bypass ML-DSA verification entirely.

---

## 7. Recommendations & Future Work

### 7.1 Critical Priority

| # | Recommendation | Rationale | Target |
|---|---------------|-----------|--------|
| R-1 | **External cryptographic audit** of `qpl-crypto` and `qpl-stark-rollup` | Winterfell AIR constraints and ML-DSA integration are unaudited; soundness bugs enable asset theft | Q3 2026 |
| R-2 | **Remove dev-mode signature stub** or enforce compile-time gate | `dev_signature` in production binary enables auth bypass if misconfigured | Immediate |
| R-3 | **Formal verification of STARK AIR constraints** | Prove that `SettlementAir` constraints correctly encode the intended state transition function | Q4 2026 |

### 7.2 High Priority

| # | Recommendation | Rationale | Target |
|---|---------------|-----------|--------|
| R-4 | **Fuzzing campaign** for proof deserialization and `canonical_json` parsing | Malformed proofs and JSON inputs are attacker-controlled entry points | Q3 2026 |
| R-5 | **On-chain dispute mechanism** for contested slashing | Current model has no recourse for unjustly slashed operators | Q4 2026 |
| R-6 | **Connection-level rate limiting** (pre-TLS) | Current rate limiting occurs post-authentication; TCP SYN floods can exhaust resources | Q3 2026 |
| R-7 | **HSM certification tracking** | Maintain registry of certified HSM firmware versions; alert on CVEs affecting deployed models | Ongoing |

### 7.3 Medium Priority

| # | Recommendation | Rationale | Target |
|---|---------------|-----------|--------|
| R-8 | **Certificate pinning in qpl-sdk** | Prevent rogue CA attacks on client-to-node channel | Q1 2027 |
| R-9 | **SLH-DSA (FIPS 205) as stateless backup** | Hash-based signatures provide diversity against lattice cryptanalysis breakthroughs | Q1 2027 |
| R-10 | **Reproducible builds + SBOM** | Supply chain attestation for all deployed binaries | Q4 2026 |
| R-11 | **Progressive slashing** | Graduated penalties proportional to offense severity | Q1 2027 |
| R-12 | **Operator key rotation protocol** | Defined procedure for rotating HSM-bound keys without downtime | Q4 2026 |

### 7.4 Incident Response Plan (Outline)

1. **Detection:** Anomalous proof verification failures, rate-limit saturation alerts, slashing event spikes
2. **Containment:** Operator deactivation via governance, coordination round suspension, emergency fee-router pause
3. **Recovery:** Threshold re-keying (DKG with excluded compromised operators), state rollback to last valid proof
4. **Post-incident:** Root cause analysis, threshold parameter adjustment, dependency audit

### 7.5 Security Testing Roadmap

- [ ] Property-based testing for fee-split conservation invariant
- [ ] Differential fuzzing: `winterfell::verify` vs independent verifier implementation
- [ ] Chaos testing: Byzantine coordination node behavior under network partitions
- [ ] Red-team exercise: Attempt threshold compromise with t-1 colluding operators
- [ ] Penetration testing: gRPC endpoint authentication bypass attempts

---

## Appendix A: Acronyms

| Acronym | Meaning |
|---------|---------|
| AIR | Algebraic Intermediate Representation |
| CRQC | Cryptographically Relevant Quantum Computer |
| DKG | Distributed Key Generation |
| FRI | Fast Reed-Solomon Interactive Oracle Proofs |
| HNDL | Harvest-Now-Decrypt-Later |
| HSM | Hardware Security Module |
| KEX | Key Exchange |
| ML-DSA | Module-Lattice Digital Signature Algorithm (FIPS 204) |
| ML-KEM | Module-Lattice Key Encapsulation Mechanism (FIPS 203) |
| MPC | Multi-Party Computation |
| mTLS | Mutual Transport Layer Security |
| PDA | Program Derived Address |
| PQC | Post-Quantum Cryptography |
| SLH-DSA | Stateless Hash-Based Digital Signature Algorithm (FIPS 205) |
| STARK | Scalable Transparent Argument of Knowledge |

---

## Appendix B: Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-06-09 | Security Engineering | Initial threat model |
