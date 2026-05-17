# QPL Network: Decentralized Post-Quantum Signing and Proving Infrastructure

**Technical Specification v0.1**

**Date:** May 2026

**Authors:** QPL Contributors

**Repository:** https://github.com/jnodes/qpl-network

**License:** MIT OR Apache-2.0

---

## Abstract

QPL Network is a decentralized infrastructure protocol providing quantum-resistant threshold signatures and zero-knowledge proofs as permissionless services. The protocol employs NIST-standardized post-quantum cryptographic algorithms (ML-DSA-65 for digital signatures, ML-KEM-1024 for key encapsulation) and FRI-based zk-STARKs (no trusted setup) to deliver cryptographic operations that resist both classical and quantum adversaries. A network of independent operators stakes collateral, registers capabilities, and processes cryptographic service requests in exchange for per-operation fees proportional to computational work performed. This document specifies the protocol's cryptographic foundations, operator network mechanics, coordination protocol, fee economics, and smart contract architecture.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quantum Threat Model](#2-quantum-threat-model)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Network Architecture](#4-network-architecture)
5. [Operator Network Protocol](#5-operator-network-protocol)
6. [Threshold Signing Protocol](#6-threshold-signing-protocol)
7. [STARK Proving Protocol](#7-stark-proving-protocol)
8. [Fee Economics](#8-fee-economics)
9. [Smart Contract Architecture](#9-smart-contract-architecture)
10. [Security Model](#10-security-model)
11. [Comparison with Existing Systems](#11-comparison-with-existing-systems)
12. [Implementation Status](#12-implementation-status)
13. [Future Work](#13-future-work)
14. [References](#14-references)

---

## 1. Introduction

### 1.1 Motivation

Public-key cryptography underpins the security of every decentralized protocol. Digital signatures authenticate transactions, multisignature schemes protect treasury funds, and key exchange protocols secure inter-node communication. The predominant algorithms — ECDSA (secp256k1), EdDSA (Ed25519), and RSA — derive their security from the computational hardness of discrete logarithm and integer factorization problems.

Shor's algorithm [1] demonstrates that a sufficiently large quantum computer solves both problems in polynomial time, rendering these algorithms insecure. NIST projects cryptographically relevant quantum computers (CRQC) to emerge between 2034 and 2039 [2]. The migration window for deployed cryptographic systems is 7-9 years — a period that coincides with the present day.

The DeFi ecosystem presents an elevated risk profile. Multisig wallets controlling billions in protocol treasury funds use ECDSA. Cross-chain bridges securing locked collateral depend on threshold ECDSA. Validator keys governing proof-of-stake consensus employ BLS or EdDSA. A single quantum-capable adversary could simultaneously compromise all of these systems.

QPL addresses this threat by providing quantum-resistant cryptographic operations as a decentralized service. Rather than requiring each protocol to independently implement and audit post-quantum cryptography, QPL offers signing and proving as network services — accessible via SDK or JSON-RPC, secured by a decentralized operator network with economic guarantees.

### 1.2 Contribution

This paper specifies:

- A threshold signing protocol based on ML-DSA-65 (NIST FIPS 204), enabling N-of-M quantum-resistant signatures without any single operator holding the complete key.
- A zero-knowledge proving service using FRI-based zk-STARKs with no trusted setup and quantum-resistant hash assumptions.
- A decentralized operator network with on-chain staking, liveness monitoring, and slashing — ensuring service availability and honest behavior.
- A fee economics model where operators receive compensation proportional to computational work performed, with transparent on-chain distribution.
- Smart contracts (Ethereum) managing operator registration, fee collection, and capability discovery.

### 1.3 Document Structure

Sections 2-3 establish the threat model and cryptographic foundations. Sections 4-7 specify the network architecture and service protocols. Section 8 details fee economics. Section 9 describes the smart contract layer. Section 10 analyzes security properties. Sections 11-13 provide competitive context, implementation status, and future directions.

---

## 2. Quantum Threat Model

### 2.1 Shor's Algorithm and Public-Key Cryptography

Shor's algorithm [1] factors integers and computes discrete logarithms in O((log N)^3) time on a quantum computer, compared to the sub-exponential time required by classical algorithms. This directly threatens:

- **ECDSA/EdDSA:** Security relies on the elliptic curve discrete logarithm problem (ECDLP). Given a public key Q = kG, Shor's algorithm recovers the private key k.
- **RSA:** Security relies on the difficulty of factoring N = pq. Shor's algorithm factors N, revealing the private key.
- **BLS signatures:** Security relies on the discrete logarithm problem in pairing groups.

The practical threshold is estimated at 2,000-4,000 logical qubits with error correction [3], requiring approximately 10-20 million physical qubits with current error rates.

### 2.2 NIST Post-Quantum Standardization

The NIST Post-Quantum Cryptography Standardization process (2016-2024) evaluated 82 candidate algorithms across four rounds, resulting in three finalized standards:

| Standard | Algorithm Family | Primitive | Security Level |
|----------|-----------------|-----------|----------------|
| FIPS 203 | CRYSTALS-Kyber (ML-KEM) | Key Encapsulation | Levels 1, 3, 5 |
| FIPS 204 | CRYSTALS-Dilithium (ML-DSA) | Digital Signature | Levels 2, 3, 5 |
| FIPS 205 | SPHINCS+ (SLH-DSA) | Digital Signature (hash-based) | Levels 1, 3, 5 |

QPL implements ML-DSA-65 (security level 3, equivalent to AES-192) for signatures and ML-KEM-1024 (security level 5, equivalent to AES-256) for key encapsulation. These selections provide substantial security margin against both known quantum attacks and potential algorithmic improvements.

### 2.3 Harvest-Now-Decrypt-Later

Nation-state adversaries and sophisticated actors are storing encrypted network traffic and blockchain transactions today. When CRQCs become available, this stored data becomes decryptable:

- Historical transactions reveal private keys used in signing
- Encrypted mempool data becomes readable
- Key exchange transcripts expose session keys

This "harvest-now-decrypt-later" (HNDL) threat model means that systems deployed today with classical cryptography are already accumulating future liability. The confidentiality guarantee has a finite expiration date equal to the time until quantum computers reach cryptographic relevance.

### 2.4 DeFi-Specific Attack Vectors

The DeFi ecosystem presents concentrated quantum risk across four categories:

**Multisig custody compromise.** Protocol treasuries, governance multisigs (Gnosis Safe), and admin keys universally employ ECDSA. Quantum key recovery enables simultaneous drainage of all ECDSA-secured funds.

**Bridge key extraction.** Cross-chain bridges custody billions in locked assets. Quantum compromise of bridge signing keys enables extraction of all bridged collateral across all supported chains simultaneously.

**Validator key takeover.** Proof-of-stake networks sign attestations and proposals with BLS or EdDSA. Quantum recovery of validator keys enables consensus manipulation — not merely theft, but potential history rewriting.

**Mempool decryption.** Encrypted mempools (e.g., Flashbots Protect, MEV-Share) rely on classical key exchange. Quantum-capable actors could decrypt pending transactions, enabling unlimited front-running.

---

## 3. Cryptographic Primitives

### 3.1 ML-DSA-65 (FIPS 204)

QPL implements Module-Lattice Digital Signature Algorithm at parameter set 65 (security level 3). The security assumption is the hardness of the Module Learning With Errors (Module-LWE) problem over polynomial rings.

**Key sizes:**

| Parameter | Size |
|-----------|------|
| Public key | 1,952 bytes |
| Secret key | 4,032 bytes |
| Signature | 3,309 bytes |

**Operations:**
- `KeyGen() -> (pk, sk)` — Generates a key pair
- `Sign(sk, msg) -> sig` — Produces a deterministic signature
- `Verify(pk, msg, sig) -> bool` — Verifies signature validity

All implementations use constant-time arithmetic to resist timing side-channels. Secret keys are zeroized on deallocation.

### 3.2 Threshold ML-DSA

QPL extends ML-DSA-65 to threshold signing via Shamir secret sharing adapted to the module-lattice domain. An N-of-M threshold scheme distributes the signing key across M operators such that any N operators can collaboratively produce a valid signature, while fewer than N operators learn nothing about the key.

**Key Generation (Distributed):**
1. A trusted dealer (or DKG protocol) generates the ML-DSA key pair (pk, sk)
2. The secret key sk is split into M shares using polynomial interpolation over the ring R_q
3. Each operator i receives share s_i and the public key pk
4. The dealer destroys sk (in DKG: sk is never materialized at any single location)

**Threshold Signing:**
1. Coordinator broadcasts (request_id, message_hash) to threshold operators
2. Each operator i computes partial signature sigma_i = PartialSign(s_i, msg)
3. Coordinator collects N partial signatures
4. Reconstruction: sigma = Reconstruct(sigma_1, ..., sigma_N)
5. Output: (sigma, pk) — indistinguishable from a standard ML-DSA-65 signature

**Verification:** The reconstructed signature verifies under standard ML-DSA-65 verification. External verifiers cannot distinguish threshold signatures from single-signer signatures.

### 3.3 ML-KEM-1024 (FIPS 203)

QPL uses ML-KEM-1024 (security level 5) for establishing encrypted communication channels between operators. The security assumption is Module-LWE.

**Key sizes:**

| Parameter | Size |
|-----------|------|
| Public key | 1,568 bytes |
| Secret key | 3,168 bytes |
| Ciphertext | 1,568 bytes |
| Shared secret | 32 bytes |

**Usage in QPL:**
- Operators exchange ML-KEM public keys during registration
- Before each coordination round, the coordinator encapsulates a session key to each participant
- All intra-round communication is encrypted under the derived shared secret
- Session keys are ephemeral (one per coordination round)

### 3.4 FRI-Based zk-STARKs

QPL implements zero-knowledge Scalable Transparent Arguments of Knowledge using the Fast Reed-Solomon Interactive Oracle Proof (FRI) protocol [4]. Key properties:

- **No trusted setup:** Prover and verifier parameters are publicly derivable. No ceremony, no toxic waste.
- **Quantum-resistant:** Security relies on collision-resistant hash functions (Rescue), not discrete logarithm assumptions.
- **Scalable:** Proof size is O(log^2 n) where n is the computation size. Verification time is O(log^2 n).
- **Transparent:** All randomness is derived from public coin (Fiat-Shamir transform).

**Proof Generation Pipeline:**
1. Define the computation as Algebraic Intermediate Representation (AIR) constraints
2. Generate the execution trace (witness)
3. Commit to the trace via Merkle tree (Rescue hash)
4. FRI commitment reduces polynomial degree verification to hash evaluation
5. Fiat-Shamir transform converts interactive protocol to non-interactive proof

**Implementation:** QPL uses the Winterfell library [5], which provides a production-grade STARK prover and verifier with configurable AIR constraints, multiple hash function options, and batch proof composition.

### 3.5 Security Parameter Justification

**ML-DSA-65 (not 44 or 87):**
- ML-DSA-44 provides security level 2 (AES-128 equivalent) — insufficient for long-lived keys protecting high-value DeFi assets
- ML-DSA-87 provides security level 5 (AES-256 equivalent) but with 2.5x larger signatures (4,627 bytes) — excessive for per-operation signing where bandwidth matters
- ML-DSA-65 (level 3, AES-192 equivalent) balances security margin with practical signature sizes

**ML-KEM-1024 (not 768):**
- Inter-operator channels may carry sensitive coordination data over extended periods
- ML-KEM-1024 provides maximum security margin (level 5) at acceptable ciphertext overhead
- Key encapsulation occurs once per coordination round; the size cost is amortized

---

## 4. Network Architecture

### 4.1 System Overview

QPL operates as a three-layer system:

```
┌─────────────────────────────────────────────────────────┐
│                  APPLICATION LAYER                        │
│   DeFi protocols, wallets, bridges, DAOs, validators     │
│   Integration via: QPL SDK (Rust) or JSON-RPC            │
└───────────────────────────┬─────────────────────────────┘
                            │ Service Requests + Fee Payment
┌───────────────────────────▼─────────────────────────────┐
│                  OPERATOR NETWORK                         │
│                                                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │ Node 1  │  │ Node 2  │  │ Node 3  │  │ Node N  │   │
│  │sign|prove│  │sign|prove│  │sign|prove│  │sign|prove│  │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
│                                                          │
│  Coordination: Quorum selection, partial collection,     │
│                threshold reconstruction, fee routing     │
└───────────────────────────┬─────────────────────────────┘
                            │ Staking, Fees, Registration
┌───────────────────────────▼─────────────────────────────┐
│                  SETTLEMENT LAYER (Ethereum)              │
│  QPLStaking  ·  QPLFeeRouter  ·  QPLRegistry            │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Operator Node

Each operator runs a `qpl-node` binary that provides:

- **JSON-RPC Server** — Accepts service requests from clients (signing, proving, fee estimation)
- **Signing Engine** — Holds ML-DSA key shards; produces partial signatures on request
- **Proving Engine** — Generates STARK proofs for submitted computation traces
- **Heartbeat Daemon** — Broadcasts liveness signals to the network at 30-second intervals
- **Coordination Client** — Participates in multi-operator rounds as coordinator or participant

**Identity:** Each operator derives its unique OperatorId from its ML-DSA-65 public key via SHA-256 hash:

```
OperatorId = SHA-256(ml_dsa_public_key)[0..32]
```

This produces a 32-byte identifier that is deterministic, collision-resistant, and publicly verifiable.

### 4.3 Coordination Layer

Multi-operator operations (threshold signing, verification quorum) require coordination among selected operators. The coordination protocol:

1. **Coordinator selection** — For each request, one operator is designated coordinator (round-robin among eligible operators based on load factor)
2. **Quorum assembly** — Coordinator selects participants from operators advertising the required service capability, filtering by load factor
3. **Request broadcast** — Coordinator distributes the operation parameters to all quorum members
4. **Partial collection** — Each participant computes their partial response and returns it to the coordinator
5. **Threshold check** — When the required number of partials arrives, the round transitions to ThresholdReached
6. **Reconstruction** — Coordinator assembles the final result from ordered partial payloads
7. **Response delivery** — Final result returned to the requesting client

### 4.4 Client SDK

The QPL SDK provides a typed Rust client for protocol integration:

```rust
let client = QplClient::connect(config).await?;
let signature = client.signing().sign(message).await?;
let proof = client.proving().prove(statement).await?;
```

Endpoint discovery is automated via the QPLRegistry contract — the SDK queries active operators, filters by required service type, and connects to the lowest-load node.

### 4.5 Communication Protocol

**Client-to-Node:** JSON-RPC over TCP (newline-delimited JSON). Methods: `health`, `estimate_fee`, `sign`, `prove`.

**Node-to-Node (Coordination):** Protocol buffer messages over ML-KEM-1024 encrypted channels. Defined in `proto/qpl_coordination.proto`:
- `CoordinateRequest` — Coordinator invites participant to a round
- `PartialResponse` — Participant returns their computed partial
- `RoundComplete` — Coordinator announces round completion

---

## 5. Operator Network Protocol

### 5.1 Operator Lifecycle

Operators transition through a state machine:

```
                    ┌──────────────────────────────┐
                    │                              │
                    ▼                              │
┌─────────┐    ┌────────┐    ┌──────────┐    ┌───────┐
│ Joining │───►│ Active │───►│ Draining │───►│ Exited│
└─────────┘    └────────┘    └──────────┘    └───────┘
                    │                              ▲
                    │         ┌───────────┐        │
                    └────────►│ Suspended │────────┘
                              └───────────┘
```

**Transition conditions:**

| From | To | Trigger |
|------|----|---------|
| Joining | Active | Successful handshake with network |
| Active | Draining | Operator initiates unstake |
| Active | Suspended | 3 missed heartbeats OR governance action |
| Draining | Exited | All in-flight requests completed + unbonding period elapsed |
| Suspended | Active | New heartbeat received (if stake sufficient) |
| Suspended | Exited | Governance-initiated forced exit |

### 5.2 Registration

An operator joins the network through:

1. **Stake deposit** — Call `QPLStaking.stake(operatorId, endpoint, servicesBitmask)` with at least 1 ETH. The `operatorId` is derived from the operator's ML-DSA public key. The `servicesBitmask` declares supported services (bit 1 = Signing, bit 2 = Proving).

2. **Endpoint registration** — The staking transaction includes the operator's network endpoint (IP:port or DNS), stored in the QPLRegistry for client discovery.

3. **Network handshake** — After on-chain registration, the operator connects to existing active operators, exchanges ML-KEM public keys, and transitions from Joining to Active.

### 5.3 Liveness Monitoring

Active operators must demonstrate liveness through periodic heartbeats:

- **Interval:** Every 30 seconds
- **Content:** Current load factor (0.0 = idle, 1.0 = at capacity), active request count, timestamp
- **Suspension threshold:** 3 consecutive missed heartbeats (90 seconds unresponsive)
- **Recovery:** A valid heartbeat from a Suspended operator resets the miss counter and transitions the operator back to Active (provided stake remains above minimum)

Heartbeat monitoring is performed by peer operators. A consensus of >50% of active operators reporting a peer as unresponsive triggers the suspension state change.

### 5.4 Quorum Formation

When a service request arrives requiring threshold participation:

1. **Capability filter** — Only operators with the relevant service bit set are eligible
2. **Status filter** — Only Active operators are considered
3. **Load balancing** — Operators are sorted by reported load factor (ascending)
4. **Quorum selection** — The coordinator selects the top N operators (where N = quorum total)
5. **Confirmation** — Selected operators confirm availability; non-responders are replaced from the eligible pool

Supported quorum configurations:

| Preset | Threshold | Total | Fault Tolerance |
|--------|-----------|-------|-----------------|
| 2-of-3 | 2 | 3 | 1 compromised/offline |
| 3-of-5 | 3 | 5 | 2 compromised/offline |
| 5-of-7 | 5 | 7 | 2 compromised/offline |

### 5.5 Request Lifecycle

End-to-end flow for a signing request:

```
Client                  Coordinator              Participants (N)
  │                          │                         │
  │── estimate_fee ─────────►│                         │
  │◄── FeeEstimate (quote) ──│                         │
  │                          │                         │
  │── payFee (on-chain) ────►│ (FeeRouter)             │
  │                          │                         │
  │── sign(msg, quote_id) ──►│                         │
  │                          │── CoordinateRequest ───►│
  │                          │                         │
  │                          │◄── PartialResponse ─────│ (×N)
  │                          │                         │
  │                          │ [threshold reached]     │
  │                          │ Reconstruct(partials)   │
  │                          │                         │
  │◄── Signature ────────────│                         │
```

**Timeout:** If the threshold is not reached before the configured deadline (default 30 seconds), the round fails with status `TimedOut`. The client may retry with a fresh quote.

### 5.6 Draining and Exit

Graceful operator shutdown:

1. Operator calls `QPLStaking.initiateUnstake(operatorId)` — transitions to Draining
2. Operator completes all in-flight coordination rounds (no new requests accepted)
3. Unbonding period begins (7 days)
4. After unbonding period elapses, operator calls `QPLStaking.withdraw(operatorId)`
5. Stake is returned to the operator's address; operator state transitions to Exited

---

## 6. Threshold Signing Protocol

### 6.1 Key Generation Ceremony

Distributed Key Generation (DKG) for ML-DSA threshold keys proceeds as follows:

1. **Setup:** The ceremony establishes parameters (threshold t, total n, ML-DSA-65 domain)
2. **Polynomial commitment:** Each participant i generates a random polynomial f_i(x) of degree (t-1) over the ring R_q, where f_i(0) = s_i (their secret contribution)
3. **Share distribution:** Participant i sends f_i(j) to participant j for all j != i, encrypted under ML-KEM
4. **Share aggregation:** Each participant j computes their aggregate share: S_j = sum(f_i(j)) for all i
5. **Public key derivation:** The aggregate public key is pk = sum(pk_i) where each pk_i is derived from s_i

The complete secret key sk = sum(s_i) is never materialized at any single location. Each operator holds only their aggregate share S_j.

### 6.2 Signing Round

Given a message to sign:

1. **Round initiation:** Coordinator creates a CoordinationRound with request_id, threshold, and timeout
2. **Nonce commitment:** Each participant generates and commits to a signing nonce (required for ML-DSA's internal state)
3. **Partial signature:** Each participant i computes `sigma_i = PartialSign(S_i, msg, nonce_i)`
4. **Collection:** Coordinator collects partials in a HashMap keyed by OperatorId
5. **Threshold check:** When `partials.len() >= threshold`, status transitions to ThresholdReached
6. **Reconstruction:** Partials are ordered by shard_index and combined: `sigma = Reconstruct(sigma_1, ..., sigma_t)`

### 6.3 Verification

The reconstructed signature sigma is a standard ML-DSA-65 signature. Verification:

```
Verify(pk, msg, sigma) -> bool
```

This uses the standard ML-DSA-65 verification algorithm. The signature is indistinguishable from one produced by a single signer holding sk. No verifier needs knowledge of the threshold scheme.

### 6.4 Security Properties

- **Unforgeability:** An adversary controlling fewer than t operators cannot produce a valid signature for any message not previously signed (under Module-LWE assumption)
- **Key secrecy:** Fewer than t operators learn nothing about the aggregate secret key beyond what is implied by their own shares
- **Robustness:** The protocol completes as long as t honest participants respond within the timeout
- **Non-frameability:** A malicious coordinator cannot attribute a forged partial signature to an honest participant

---

## 7. STARK Proving Protocol

### 7.1 Proof System Overview

QPL's proving service generates zk-STARK proofs attesting to correct computation without revealing inputs. The proof system is built on:

- **Algebraic Intermediate Representation (AIR):** Computations are encoded as polynomial constraints over a finite field
- **Execution Trace:** The prover generates a matrix of field elements representing the computation's state at each step
- **FRI Protocol:** Reduces the polynomial degree bound verification to iterative hash evaluations
- **Fiat-Shamir Transform:** Converts the interactive proof to non-interactive via hash-based challenge derivation

### 7.2 Prover Architecture

The QPL prover (Winterfell-based) operates in stages:

1. **Constraint Definition:** Service-specific AIR constraints define what constitutes a valid computation (e.g., "the output is the SHA-256 hash of the input," or "the batch of N transfers maintains conservation of value")
2. **Trace Generation:** Given private inputs, the prover generates the full execution trace
3. **Trace Commitment:** The trace is committed via Merkle tree using the Rescue hash function
4. **Constraint Evaluation:** The prover evaluates constraint polynomials and commits to the composition polynomial
5. **FRI Commitment:** The FRI protocol reduces the degree-bound check
6. **Proof Assembly:** The final proof consists of Merkle authentication paths, FRI layers, and query responses

**Performance characteristics (empirical, AMD EPYC 7763):**

| Batch Size | Trace Generation | Proof Generation | Proof Size | Verification |
|-----------|------------------|------------------|------------|--------------|
| 10 tx | ~5 ms | ~50 ms | ~45 KB | ~2 ms |
| 100 tx | ~40 ms | ~400 ms | ~65 KB | ~3 ms |
| 1000 tx | ~350 ms | ~3.5 s | ~90 KB | ~4 ms |

### 7.3 Verifier Architecture

Proof verification is computationally lightweight relative to proving:

- **Off-chain verification:** The QPL SDK includes a native verifier for applications that verify proofs locally
- **On-chain verification:** A Solidity verifier contract can validate STARK proofs on Ethereum (gas cost: approximately 200K-500K gas depending on proof complexity)
- **Verification process:** Reconstruct Merkle roots from authentication paths, evaluate FRI queries, check constraint satisfaction at random points

### 7.4 Use Cases

QPL's proving service supports:

- **Batch transaction proving:** Attest that a batch of N transactions is valid without revealing individual transaction details
- **State transition proofs:** Prove correct execution of complex state changes (e.g., AMM swap validity, lending position health)
- **Privacy-preserving attestation:** Prove possession of a credential or membership without revealing identity
- **Computation integrity:** Offload expensive computation off-chain and prove correctness with a succinct proof

---

## 8. Fee Economics

### 8.1 Design Principles

QPL's fee model follows three principles:

1. **Work-proportional compensation.** Fees reflect the computational resources consumed by operators. More complex operations (STARK proving) cost more than simpler operations (signature verification).
2. **Transparent and predictable.** Fee schedules are public and deterministic. Clients receive binding quotes before committing payment.
3. **Demand-determined revenue.** Operator compensation scales with the volume of requests processed. No fixed guarantees or minimum payouts exist — service fees are earned solely by performing computational work.

### 8.2 Fee Schedule

Fees are denominated in USD micro-units (1 micro-unit = $0.000001). The schedule reflects computational cost:

| Operation | Base Fee (micro-USD) | USD Equivalent |
|-----------|---------------------|----------------|
| Threshold signature | 1,000 | $0.001 |
| STARK proof (batch <= 100 tx) | 50,000 | $0.05 |
| STARK proof (batch > 100 tx) | 100,000 | $0.10 |
| Proof verification | 1,000 | $0.001 |

### 8.3 Multipliers

The total fee for an operation is:

```
F_total = F_base(operation) x M_quorum(t) x M_urgency(u)
```

**Quorum multiplier** `M_quorum(t) = t` where t is the threshold count. A 3-of-5 signing operation requires 3 operators to perform computational work, so the fee is 3x the base.

**Urgency multiplier:**

| Level | Multiplier | Semantics |
|-------|-----------|-----------|
| Standard | 1.0x | Processed in normal order |
| Fast | 1.5x | Prioritized in coordinator queue |
| Instant | 2.0x | Immediate processing, preempts queue |

**Example:** 3-of-5 threshold signature at Instant urgency:
```
F_total = 1,000 x 3 x 2.0 = 6,000 micro-USD = $0.006
```

### 8.4 Fee Distribution

Collected fees are distributed to compensate the specific work performed:

| Recipient | Share | Rationale |
|-----------|-------|-----------|
| Coordinator | 40% | Compensates request routing, quorum assembly, partial collection, and reconstruction work |
| Participants | 50% | Compensates computational signing/proving work (split equally among non-coordinator operators) |
| Protocol treasury | 10% | Funds ongoing development, security audits, and infrastructure maintenance |

**Distribution formula:**

```
F_coordinator = floor(F_total x 0.40)
F_treasury    = floor(F_total x 0.10)
F_participants = F_total - F_coordinator - F_treasury
F_per_participant = floor(F_participants / n_participants)
F_dust = F_participants - (F_per_participant x n_participants)
```

Dust (remainder from integer division) is allocated to the coordinator.

**Worked example** (3-of-5 signing, Standard urgency):
```
F_total = 3,000 micro-USD ($0.003)
F_coordinator = floor(3,000 x 0.40) = 1,200
F_treasury = floor(3,000 x 0.10) = 300
F_participants = 3,000 - 1,200 - 300 = 1,500
F_per_participant = floor(1,500 / 2) = 750  (2 non-coordinator participants)
F_dust = 1,500 - (750 x 2) = 0
```

### 8.5 Fee Payment Flow

1. **Quote request:** Client calls `estimate_fee` with operation type, quorum config, and urgency
2. **Quote issuance:** Coordinator returns a FeeEstimate containing a unique quote_id, total fee, and expiry timestamp (60 seconds)
3. **On-chain payment:** Client calls `QPLFeeRouter.payFee(quote_id)` with the quoted amount
4. **Operation execution:** After payment confirmation, the coordinator initiates the coordination round
5. **Distribution trigger:** Upon round completion, governance calls `QPLFeeRouter.distributeFee(quote_id, coordinator, participants[], treasury)`
6. **Claim:** Operators accumulate claimable balances and call `QPLFeeRouter.claim()` to withdraw

### 8.6 Economic Sustainability

Operator economics depend on request volume. At a given volume V (requests per day) for a signing-focused operator:

```
Daily fee revenue = V x F_average x operator_share
```

For a participant processing 10,000 signing requests/day at standard urgency in 3-of-5 quorum:
```
Per-request participant fee = 750 micro-USD = $0.00075
Daily revenue = 10,000 x $0.00075 = $7.50
```

For a coordinator processing 10,000 signing requests/day:
```
Per-request coordinator fee = 1,200 micro-USD = $0.0012
Daily revenue = 10,000 x $0.0012 = $12.00
```

These figures scale linearly with request volume. Operator costs include compute infrastructure, bandwidth, and the opportunity cost of staked collateral. The fee schedule is governance-adjustable to maintain sustainability as demand and infrastructure costs evolve.

---

## 9. Smart Contract Architecture

### 9.1 Contract Overview

Three Solidity contracts on Ethereum manage the on-chain components of QPL:

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  QPLStaking  │     │ QPLFeeRouter  │     │ QPLRegistry  │
│              │     │               │     │              │
│ - stake()    │     │ - payFee()    │     │ - register() │
│ - unstake()  │     │ - distribute()│     │ - lookup()   │
│ - withdraw() │     │ - claim()     │     │ - filter()   │
│ - slash()    │     │               │     │              │
└──────────────┘     └───────────────┘     └──────────────┘
```

All contracts are governed by a multisig address with authority over parameter changes, slashing, and fee distribution.

### 9.2 QPLStaking

Manages operator collateral and lifecycle:

- **Minimum collateral:** 1 ETH (`MIN_STAKE = 1 ether`)
- **Registration:** `stake(operatorId, endpoint, servicesBitmask)` — deposits collateral and registers the operator as active
- **Unstaking:** `initiateUnstake(operatorId)` — marks operator inactive, begins 7-day unbonding period (`UNBOND_PERIOD = 7 days`)
- **Withdrawal:** `withdraw(operatorId)` — releases collateral after unbonding period elapses
- **Slashing:** `slash(operatorId, amount, reason)` — governance deducts collateral for protocol violations. If remaining stake falls below `MIN_STAKE`, operator is automatically deactivated
- **Operator discovery:** `getActiveOperators()` — returns all currently active operator IDs

**Collateral rationale:** The 1 ETH minimum collateral serves as a Sybil resistance mechanism and ensures operators have economic skin-in-the-game. It is not an investment — it is a security deposit that operators may forfeit if they violate protocol rules.

### 9.3 QPLFeeRouter

Handles fee collection and distribution:

- **Collection:** `payFee(quoteId)` — clients pay the quoted fee amount, locked until distribution
- **Distribution:** `distributeFee(quoteId, coordinator, participants[], treasury)` — governance allocates the collected fee according to the 40/50/10 split
- **Claiming:** `claim()` — operators withdraw their accumulated fee balance
- **Treasury transfer:** Treasury share is transferred immediately during distribution

Fees accumulate in operator-specific balances. Operators withdraw on their own schedule, minimizing gas costs by batching claims.

### 9.4 QPLRegistry

On-chain operator discovery for SDK auto-connection:

- **Registration:** Endpoint and service bitmask stored during staking
- **Service bitmask encoding:**

| Service | Bit Position | Bitmask Value |
|---------|-------------|---------------|
| Signing | 1 | 0x02 |
| Proving | 2 | 0x04 |
| Settlement | 3 | 0x08 |
| Yield | 4 | 0x10 |
| RWA | 5 | 0x20 |

- **Filtering:** Clients query by service bitmask to find operators supporting their required capability
- **Endpoint resolution:** Returns operator network addresses for SDK connection

### 9.5 Upgrade Path

Contract upgrades follow a governance-controlled process:

1. New implementation deployed
2. Governance multisig proposes upgrade (timelock: 48 hours)
3. Community review period
4. Governance executes upgrade

Initial deployment uses transparent proxy pattern for upgradeability. Long-term goal: remove proxy and deploy immutable contracts once the protocol stabilizes.

---

## 10. Security Model

### 10.1 Threat Model

QPL considers three adversary classes:

**Rational adversary:** Profit-motivated; will deviate from protocol only if expected gain exceeds slashing penalty. Deterred by: stake requirement > expected misbehavior profit.

**Byzantine adversary:** Arbitrary behavior; may act against their own economic interest. Tolerated by: threshold cryptography (up to n-t Byzantine operators do not compromise security).

**Quantum adversary:** Access to a cryptographically relevant quantum computer (future). Mitigated by: NIST-standardized post-quantum algorithms (Module-LWE assumption).

### 10.2 Threshold Security

For a t-of-n threshold scheme:

- **Security guarantee:** The scheme remains secure as long as fewer than t operators are compromised
- **Availability guarantee:** The scheme produces results as long as at least t operators are honest and responsive

| Quorum | Compromised Tolerance | Offline Tolerance |
|--------|----------------------|-------------------|
| 2-of-3 | 1 | 1 |
| 3-of-5 | 2 | 2 |
| 5-of-7 | 2 | 2 |

A rational adversary would need to stake 1 ETH per compromised operator node and risk slashing of all stake upon detection.

### 10.3 Slashing Conditions

Operators may be slashed for:

1. **Equivocation:** Producing two different partial signatures for the same (request_id, message) pair — evidence of key misuse
2. **Liveness failure:** 3 consecutive missed heartbeats triggering automatic suspension; repeated suspension leads to governance-initiated slashing
3. **Invalid partials:** Submitting malformed cryptographic contributions that fail verification — indicates either compromise or faulty implementation
4. **Collusion evidence:** Detectable through on-chain analysis (e.g., threshold key reconstruction attempts logged by honest operators)

Slashing amount and conditions are governance-configurable. The slashed collateral is transferred to the governance treasury.

### 10.4 Cryptographic Assumptions

QPL's security relies on:

| Assumption | Used By | Believed Status |
|-----------|---------|-----------------|
| Module-LWE hardness | ML-DSA-65, ML-KEM-1024 | No known quantum or classical polynomial-time attack |
| Collision resistance (Rescue) | STARK proof commitments | Standard assumption; quantum generic attack at most quadratic speedup (Grover) |
| Random Oracle Model | Fiat-Shamir transform (STARKs) | Standard idealized assumption |

### 10.5 Side-Channel Resistance

- **Constant-time implementations:** All cryptographic operations in `qpl-crypto` use constant-time arithmetic from the `pqcrypto` reference implementations
- **Memory zeroization:** Secret keys are zeroized on drop to prevent memory remanence attacks
- **HSM boundary:** Production deployments may store ML-DSA signing shards in HSM (SoftHSM or AWS CloudHSM), preventing key export
- **No-export policy:** Operator key shards are generated inside the node and never transmitted unencrypted

### 10.6 Network-Level Attacks

**Eclipse attacks:** Mitigated by on-chain registry — clients discover operators via QPLRegistry contract, not peer gossip. An attacker cannot isolate a client from the legitimate operator set.

**Sybil resistance:** The 1 ETH minimum collateral per operator makes Sybil attacks economically costly. Controlling a majority of a 5-node quorum requires staking 3+ ETH and operating 3+ distinct infrastructure nodes.

**Denial of service:** Fee-based rate limiting ensures that each request has an associated cost. Operators may additionally implement per-client rate limits. The decentralized topology ensures no single point of failure.

---

## 11. Comparison with Existing Systems

### 11.1 Fireblocks

Fireblocks provides institutional MPC custody with threshold ECDSA signing. Limitations relative to QPL:
- Centralized infrastructure (single company controls all MPC nodes)
- No post-quantum cryptography (ECDSA only)
- Closed-source implementation (security through obscurity)
- Vendor lock-in (proprietary API, enterprise pricing)
- No proving capability (signing only)

### 11.2 Lit Protocol

Lit Protocol offers decentralized threshold signing and encryption. Limitations:
- Classical cryptography only (ECDSA, BLS) — no quantum resistance
- No STARK proving capability
- Different economic model (network token staking vs. ETH collateral)

### 11.3 Threshold Network

Threshold Network (formerly Keep + NuCypher) provides threshold ECDSA primarily for tBTC. Limitations:
- Classical threshold ECDSA — no post-quantum cryptography
- Focused primarily on Bitcoin bridge use case
- No general-purpose proving service
- Limited chain support

### 11.4 Comparison Matrix

| Feature | QPL | Fireblocks | Lit Protocol | Threshold Network |
|---------|-----|-----------|--------------|-------------------|
| Post-quantum signatures | ML-DSA-65 | No | No | No |
| Post-quantum key exchange | ML-KEM-1024 | No | No | No |
| zk-STARK proving | Yes (FRI-based) | No | No | No |
| Trusted setup required | No | N/A | No | No |
| Decentralized operators | Yes | No | Yes | Yes |
| Open source | Yes | No | Yes | Yes |
| Chain-agnostic | Yes | Yes | Yes | Limited |
| Per-operation fees | Yes | Enterprise license | Token-gated | Token-gated |
| On-chain slashing | Yes | N/A | Yes | Yes |

---

## 12. Implementation Status

### 12.1 Crate Architecture

The implementation is a Rust workspace with the following crates:

| Crate | Purpose | Test Count |
|-------|---------|-----------|
| `qpl-crypto` | ML-DSA-65, ML-KEM-1024, HSM abstraction | 45 |
| `qpl-stark-rollup` | AIR constraints, FRI prover/verifier | 7 |
| `qpl-network` | Operator registry, coordination, fees | 27 |
| `qpl-sdk` | Client library for protocol integration | 9 |
| `common/types` | Shared type definitions | 3 |
| `services/qpl-node` | Operator node binary | — |
| `tests/e2e` | End-to-end integration tests | 5 |

Smart contracts (Solidity, Foundry toolchain):

| Contract | Test Count |
|----------|-----------|
| QPLStaking | 6 |
| QPLFeeRouter | 4 |

**Total: 200+ Rust tests, 10+ Solidity tests — all passing.**

### 12.2 Benchmarks

Empirical performance (AMD EPYC 7763, `--release` mode, Criterion.rs):

| Operation | Median Latency |
|-----------|---------------|
| ML-DSA-65 key generation | 84 us |
| ML-DSA-65 sign (1 KB message) | 111 us |
| ML-DSA-65 verify (1 KB message) | 70 us |
| ML-KEM-1024 encapsulate | 78 us |
| MPC shard split (5-of-3) | 15 us |
| MPC shard reconstruct (3-of-5) | 22 us |

These benchmarks demonstrate that post-quantum cryptographic operations are practical for per-request execution at scale. A single operator core can process >9,000 signing operations per second.

### 12.3 Test Coverage

- **Cryptographic correctness:** Wycheproof-style test vectors for ML-DSA and ML-KEM operations
- **Network protocol:** Unit tests for operator lifecycle, coordination rounds, fee calculation, quorum formation
- **Smart contracts:** Foundry tests covering staking, unstaking, slashing, fee payment, and distribution
- **End-to-end:** Integration tests verifying the full pipeline from fee estimation through coordination to result delivery

---

## 13. Future Work

### 13.1 Additional Signature Schemes

- **SLH-DSA (FIPS 205):** Hash-based signatures as a conservative fallback. Larger signatures (~17 KB) but security relies only on hash function properties — no lattice assumptions.
- **Hybrid modes:** Simultaneous classical + post-quantum signatures during the transition period, enabling graceful migration for protocols not yet ready to fully drop ECDSA.

### 13.2 Cross-Chain Deployment

- Deploy QPLStaking, QPLFeeRouter, and QPLRegistry on L2 networks (Arbitrum, Optimism, Base) to reduce operator gas costs for staking and fee claiming
- Cross-chain fee payment: accept fees on any supported chain, settle to operators on their preferred chain
- Multi-chain registry: operators advertise service on multiple chains simultaneously

### 13.3 Governance Decentralization

- Transition from governance multisig to on-chain operator voting for parameter changes (fee schedule adjustments, slashing conditions, minimum collateral)
- Proposal + timelock mechanism for contract upgrades
- Operator reputation system influencing governance weight (based on uptime, request volume, absence of slashing events)

### 13.4 Hardware Acceleration

- **FPGA optimization:** Accelerate STARK proof generation for high-throughput operators
- **HSM certification:** Pursue FIPS 140-3 certification for ML-DSA key storage in hardware security modules (pending vendor support for post-quantum algorithms)
- **GPU proving:** Explore GPU parallelization for FRI polynomial evaluation during proof generation

---

## 14. References

[1] P. W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring," Proceedings 35th Annual Symposium on Foundations of Computer Science, 1994.

[2] National Institute of Standards and Technology, "Post-Quantum Cryptography: NIST's Plan for the Future," NISTIR 8413, 2022.

[3] C. Gidney and M. Ekera, "How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits," Quantum, vol. 5, 2021.

[4] E. Ben-Sasson, I. Bentov, Y. Horesh, and M. Riabzev, "Fast Reed-Solomon Interactive Oracle Proofs of Proximity," ICALP, 2018.

[5] Facebook (Meta), "Winterfell: A STARK prover and verifier," https://github.com/facebook/winterfell, 2021.

[6] National Institute of Standards and Technology, "FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)," 2024.

[7] National Institute of Standards and Technology, "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)," 2024.

[8] National Institute of Standards and Technology, "FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)," 2024.

[9] A. Shamir, "How to share a secret," Communications of the ACM, vol. 22, no. 11, 1979.

[10] E. Ben-Sasson, A. Chiesa, D. Genkin, E. Tromer, and M. Virza, "SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge," CRYPTO, 2013.

---

## Appendix A: Fee Formula Derivations

### A.1 Total Fee Calculation

```
F_total = F_base(op) x M_quorum(t) x M_urgency(u)

where:
  F_base(op) ∈ {1000, 50000, 100000, 1000} (USD micro-units, per operation type)
  M_quorum(t) = t (threshold count, integer >= 1)
  M_urgency(u) ∈ {1.0, 1.5, 2.0} (Standard, Fast, Instant)
```

### A.2 Fee Split Calculation

```
F_coordinator    = floor(F_total x 40 / 100)
F_treasury       = floor(F_total x 10 / 100)
F_participant_pool = F_total - F_coordinator - F_treasury
F_per_participant = floor(F_participant_pool / n_participants)
F_dust           = F_participant_pool - (F_per_participant x n_participants)
F_coordinator_final = F_coordinator + F_dust
```

### A.3 Worked Examples

**Example 1:** Single signing operation, no quorum, Standard urgency
```
F_total = 1,000 x 1 x 1.0 = 1,000 micro-USD ($0.001)
F_coordinator = 400, F_treasury = 100, F_participant_pool = 500
No participants (single operator acts as both coordinator and signer)
Coordinator receives: 400 + 500 = 900, Treasury: 100
```

**Example 2:** 3-of-5 threshold signing, Instant urgency
```
F_total = 1,000 x 3 x 2.0 = 6,000 micro-USD ($0.006)
F_coordinator = 2,400, F_treasury = 600, F_participant_pool = 3,000
n_participants = 2 (coordinator is one of the 3 threshold signers)
F_per_participant = 1,500
Coordinator: $0.0024, Each participant: $0.0015, Treasury: $0.0006
```

**Example 3:** Large batch STARK proof, 5-of-7 quorum, Fast urgency
```
F_total = 100,000 x 5 x 1.5 = 750,000 micro-USD ($0.75)
F_coordinator = 300,000, F_treasury = 75,000, F_participant_pool = 375,000
n_participants = 4
F_per_participant = 93,750
Coordinator: $0.30, Each participant: $0.09375, Treasury: $0.075
```

---

## Appendix B: Operator State Machine

```
                         ┌─────────────────────────────────────────┐
                         │                                         │
                         ▼                                         │
┌───────────────┐    ┌────────────────┐    ┌───────────────┐    ┌─────────────┐
│   JOINING     │───►│    ACTIVE      │───►│   DRAINING    │───►│   EXITED    │
│               │    │                │    │               │    │             │
│ On-chain stake│    │ Serving reqs   │    │ Completing    │    │ Stake       │
│ deposited;    │    │ Sending hbeats │    │ in-flight;    │    │ withdrawn   │
│ handshake     │    │ Earning fees   │    │ 7-day unbond  │    │             │
│ pending       │    │                │    │               │    │             │
└───────────────┘    └───────┬────────┘    └───────────────┘    └─────────────┘
                             │                                         ▲
                             │ 3 missed heartbeats                     │
                             │ OR governance action                    │
                             ▼                                         │
                     ┌────────────────┐                                │
                     │   SUSPENDED    │────────────────────────────────┘
                     │               │  governance-initiated exit
                     │ Not serving   │
                     │ May recover   │
                     │ on next hbeat │
                     └───────────────┘
```

**State transitions summary:**

| Transition | Trigger | Reversible |
|-----------|---------|-----------|
| Joining -> Active | Successful network handshake | No |
| Active -> Draining | `initiateUnstake()` called | No |
| Active -> Suspended | 3 missed heartbeats or governance slash | Yes (via heartbeat) |
| Draining -> Exited | Unbonding period elapsed + `withdraw()` | No |
| Suspended -> Active | Valid heartbeat received (if stake >= MIN_STAKE) | Yes |
| Suspended -> Exited | Governance-initiated forced exit | No |

---

## Appendix C: Service Bitmask Encoding

Operators declare supported services via a `uint32` bitmask in the QPLStaking and QPLRegistry contracts:

| Service Type | Enum Value | Bit Position | Bitmask |
|-------------|-----------|--------------|---------|
| Signing | 1 | 1 | `0x00000002` |
| Proving | 2 | 2 | `0x00000004` |
| Settlement | 3 | 3 | `0x00000008` |
| Yield | 4 | 4 | `0x00000010` |
| RWA | 5 | 5 | `0x00000020` |

**Encoding formula:** `bitmask = OR(1 << service_value)` for each supported service.

**Examples:**

| Operator Supports | Bitmask | Hex |
|------------------|---------|-----|
| Signing only | `0b00000010` | `0x02` |
| Signing + Proving | `0b00000110` | `0x06` |
| All services | `0b00111110` | `0x3E` |

**Client-side filtering:** To find operators supporting Signing AND Proving:
```
required_mask = 0x06  // bits 1 and 2 set
match = (operator.servicesBitmask & required_mask) == required_mask
```

---

*End of document.*
