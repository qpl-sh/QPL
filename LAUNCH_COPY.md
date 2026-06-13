# QPL Launch Copy — futard.io

---

## Tagline

**Quantum-proof DeFi signing. 50 genesis seats. No second chance.**

---

## Project Description

### The Clock Is Already Running

Every ECDSA key protecting a cross-chain bridge, DAO treasury, or multisig wallet today is already being harvested. State-level adversaries are capturing encrypted traffic *now*, banking it for the day a cryptographically-relevant quantum computer comes online — a scenario NIST, NSA, and CISA have independently assessed as arriving within 10–15 years. When that day comes, every signature scheme DeFi relies on — Ed25519, secp256k1, ECDSA-P256 — breaks simultaneously.

By then, it's too late. The keys are already in the archive.

**QPL exists because re-keying an entire protocol after quantum break is a fantasy.** The migration must happen before the threat materializes — and the infrastructure to do it must be live, tested, and integrated *today*.

---

### What QPL Does

QPL (Quantum Proof Ledger) is a decentralized post-quantum signing and proving network on Solana. It replaces legacy cryptographic primitives with NIST-standardized post-quantum algorithms, delivered as infrastructure any protocol can integrate via SDK or JSON-RPC:

- **PQC-MPC Threshold Signing** — ML-DSA-65 (NIST FIPS 204) threshold signatures with PKCS#11 HSM enforcement. Private keys never leave tamper-resistant hardware. Protocols get quantum-resistant custody without rewriting their stack.

- **Algorithmic Agility** — Operators serve Ed25519, ECDSA-P256, or ML-DSA-65, negotiated per request. Protocols migrate at their own pace; QPL handles the cryptographic transition seamlessly.

- **Native FRI-based zk-STARK Rollup** — Zero-knowledge batch proving with no trusted setup (Winterfell). Private Validium mode for settlement that reveals nothing. Proof generation and verification fully decentralized across the operator set.

- **ML-KEM-1024 Key Encapsulation** — NIST FIPS 203 compliant key exchange for secure inter-operator coordination. Every channel between nodes is quantum-hardened at the transport layer.

---

### Why DeFi Cannot Wait

The numbers speak:

- **$2B+ lost** to bridge exploits in 2022–2024 alone — compromised signing keys were the vector in Ronin ($625M), Wormhole ($320M), and Horizon ($100M).
- **DAO treasuries** holding billions rely on multisig keys that a single quantum decryption pass could drain.
- **Governance key theft** is not theoretical — it's the final unsolved single-point-of-failure in decentralized protocols.

Every protocol that delays quantum-safe key rotation is making a bet: that adversaries haven't already harvested their signing traffic. That bet gets worse every day the keys remain classical.

---

### Technical Credibility

QPL is not a wrapper or a whitepaper promise. The protocol is built, tested, and open-source:

- **NIST FIPS 203 + FIPS 204 compliant** — ML-KEM-1024 and ML-DSA-65 implemented in Rust, fully tested against official NIST test vectors
- **62+ cryptographic unit tests** covering key generation, signing, verification, encapsulation, decapsulation, threshold MPC, and HSM integration
- **Internal security audit passed** — threat model documented, red-team scenarios exercised, fuzz targets active on critical paths
- **STARK prover/verifier operational** — AIR constraint system, FRI commitment scheme, and execution engine all functional with benchmarks
- **Three Anchor programs deployed** — `qpl-staking`, `qpl-fee-router`, `qpl-registry` live on Solana devnet
- **Full operator node binary** — serves signing and proving over JSON-RPC with mTLS, rate limiting, and identity attestation
- **Open source** — every line auditable at [github.com/jnodes/QPL](https://github.com/jnodes/QPL)

---

### Genesis Operator Program

**50 seats. Permanent. Non-transferable.**

The Genesis Operator cohort represents the founding validator set of the QPL network. This is not a rewards program — it is a permanent, soulbound designation that marks the operators who stood up quantum-safe infrastructure before the market understood the threat.

Genesis Operators receive:

- **Soulbound on-chain attestation** — cryptographic proof of founding participation, permanently inscribed, never reproducible
- **Permanent protocol-level designation** — Genesis status is embedded in the operator registry contract. It cannot be purchased, earned, or replicated after this window closes.
- **Priority coordination rights** — Genesis operators are first in quorum selection during the network's critical early months
- **Invite-only expansion authority** — only Genesis operators can nominate the next cohort

There will never be another Genesis round. The 50 seats exist once.

---

### The Window

- **Raise:** $500K USDC
- **Duration:** 7 days
- **Platform:** futard.io

This is a single, time-bound infrastructure funding round. When the 7 days close or the cap fills — whichever comes first — the Genesis window is permanently sealed. There is no waitlist, no extension, no second tranche.

The quantum threat does not negotiate timelines. Neither does this raise.

---

### Links

- **GitHub:** [github.com/jnodes/QPL](https://github.com/jnodes/QPL)
- **Documentation:** Coming soon
- **Threat Model:** Published in repository (`THREAT_MODEL.md`)
- **Security Policy:** Published in repository (`SECURITY.md`)
