# Security Policy

The QPL (Quantum Proof Layer) project takes security seriously. As post-quantum cryptographic infrastructure for DeFi, we hold ourselves to the highest standards of security engineering. We appreciate the security community's efforts in helping us maintain a secure protocol.

## Supported Versions

| Version | Supported          | Notes                        |
| ------- | ------------------ | ---------------------------- |
| 0.1.x   | :white_check_mark: | Current alpha release        |
| < 0.1.0 | :x:                | No longer supported          |

> **Note:** QPL is pre-production alpha software (v0.1.0). APIs, cryptographic parameter choices, and on-chain program interfaces are subject to change. Do not use in production with real funds.

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

We follow a responsible disclosure process to protect our users and operators.

### How to Report

1. **Email:** Send your report to **security@qpl.network**
2. **GitHub:** Use [GitHub's private vulnerability reporting](https://github.com/ryana-sol/qpl/security/advisories/new)

### What to Include

- **Description:** Clear explanation of the vulnerability
- **Reproduction steps:** Minimal steps to reproduce the issue
- **Impact assessment:** What an attacker could achieve (e.g., fund theft, key extraction, proof forgery)
- **Affected components:** Specific crate, program, or service (e.g., `qpl-crypto`, `qpl-staking`, `qpl-node`)
- **Suggested fix:** Optional, but appreciated

### Encryption

For sensitive disclosures, a GPG key is available on request. Email security@qpl.network with subject line "GPG Key Request" to receive our public key.

## Response Timeline

| Stage               | Timeframe                          |
| ------------------- | ---------------------------------- |
| Acknowledgment      | Within 48 hours                    |
| Initial assessment  | Within 7 days                      |
| Fix (Critical)      | 72 hours from confirmation         |
| Fix (High)          | 14 days from confirmation          |
| Fix (Medium)        | 30 days from confirmation          |
| Fix (Low)           | Next scheduled release             |

We will keep reporters informed of progress throughout the resolution process.

## Bug Bounty Program

### In Scope

| Component            | Areas of Interest                                      |
| -------------------- | ------------------------------------------------------ |
| `qpl-crypto`         | HSM/PKCS#11 integration, MPC key splitting, PQC primitives (ML-DSA, ML-KEM), key generation/signing |
| Solana Programs      | `qpl-staking`, `qpl-fee-router`, `qpl-registry` — access control, fund handling, state manipulation |
| `qpl-stark-rollup`   | Proof verification, AIR constraints, executor state transitions, validium data availability |
| `qpl-node`           | Authentication bypass, mTLS/TLS vulnerabilities, rate limiting bypass, gRPC handler exploits |

### Out of Scope

- Test files and test utilities (`tests/`, `benches/`)
- Documentation and configuration examples
- Third-party dependencies (please report vulnerabilities upstream to the respective maintainers)
- Issues already identified in published security audit reports
- Denial-of-service attacks requiring unrealistic resources
- Social engineering attacks

### Severity Classification

| Severity     | Examples                                                                 |
| ------------ | ------------------------------------------------------------------------ |
| **Critical** | Private key extraction, proof forgery allowing invalid state transitions, unauthorized fund movement |
| **High**     | Authentication bypass, MPC threshold circumvention, nonce replay enabling double-spend |
| **Medium**   | Information disclosure of operator metadata, partial denial of service on proving pipeline |
| **Low**      | Non-exploitable cryptographic implementation deviations, timing side-channels with impractical prerequisites |

### Rewards

Formal bug bounty rewards are **TBD pending mainnet launch**. During the current alpha phase:

- Confirmed vulnerabilities receive **public recognition and attribution** in release notes and the security advisory
- Critical/High reporters will be credited in project documentation
- Early reporters will be eligible for retroactive rewards once the formal program launches

## Security Audit History

| Audit                          | Date | Status                              |
| ------------------------------ | ---- | ----------------------------------- |
| Internal CISO audit (v0.3)     | 2026 | Complete — all critical/high findings resolved |
| External third-party audit     | TBD  | Planned — not yet completed         |

Full audit reports are available in the repository (`qpl security audit report v0.3.md`).

## Security Design Principles

QPL's security architecture is built on the following core principles:

- **Post-quantum cryptographic agility** — Primary use of ML-DSA-65 (FIPS 204) with classical fallback mechanisms, enabling algorithm migration without protocol-breaking changes.

- **Hardware security module (PKCS#11)** — Production key material is stored in HSMs via the PKCS#11 interface, ensuring private keys never exist in process memory.

- **Threshold MPC for key splitting** — Operator signing keys are split across multiple parties using threshold cryptography, eliminating single points of compromise.

- **Transparent ZK-STARKs** — Zero-knowledge proofs use STARKs (no trusted setup), removing ceremony-related trust assumptions and providing post-quantum proof security.

- **On-chain nonce registry** — Replay protection enforced at the protocol level through an on-chain nonce registry, preventing transaction replay across all settlement paths.

---

For general (non-security) bug reports, please use [GitHub Issues](https://github.com/ryana-sol/qpl/issues).
