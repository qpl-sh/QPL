# QPL Landing Page — Content Outline (Draft)

**Platform:** Emergent  
**Version:** 0.1 — Draft for Review  
**Tone:** DeFi-native, urgent, technically credible. No banking language. No investment promises.  
**Howey Filter:** Every section passes the four-prong test — no returns, no common enterprise, no investment framing, no dependency on team efforts.

---

## Section 1: Hero

**Headline:**  
> Quantum-Proof Your Protocol

**Subheadline:**  
> Post-quantum threshold signatures and STARK proofs as permissionless infrastructure. Open-source. Chain-agnostic. Live on Solana.

**Primary CTA:**  
`[Integrate Now →]` — links to docs/SDK

**Secondary CTA:**  
`[Apply for Genesis Operator Slot →]` — links to operator application

**Supporting Visual:**  
Animated network diagram showing 5 operators forming a threshold quorum, signing a request. Dark background, terminal-green/blue palette.

---

## Section 2: The Threat (Urgency Driver)

**Section Title:** Your Keys Have an Expiration Date

**Copy Direction (3 short blocks):**

1. **Every multisig is ECDSA.** Protocol treasuries, bridge custody keys, governance multisigs — all classical. When CRQCs arrive (NIST projects 2034-2039), every ECDSA key is recoverable. Every treasury is drainable simultaneously.

2. **Harvest-now-decrypt-later is already happening.** Nation-state adversaries are storing encrypted transactions today. Your mempool data, your key exchanges, your signed messages — all being archived for future decryption.

3. **The migration window is 7-9 years.** Protocols that integrate now are protected. Protocols that wait face emergency migration under adversarial conditions — while their keys are already compromised.

**Visual:** Countdown-style graphic or timeline showing "2026 → 2034" with a narrowing window.

---

## Section 3: What QPL Does (Product)

**Section Title:** Quantum-Resistant Infrastructure as a Service

**Three capability cards:**

### Card 1: Threshold Signatures
> **ML-DSA-65 (FIPS 204)** — N-of-M quantum-resistant threshold signing. No single operator holds the complete key. 3-of-5 quorum, HSM-wrapped shards, zero-knowledge key shares.
>
> *Replaces ECDSA multisigs for treasuries, bridges, and validator key management.*

### Card 2: STARK Proofs
> **FRI-based zk-STARKs** — Zero-knowledge proofs with no trusted setup and quantum-resistant hash assumptions (Blake3-256). High128 security level.
>
> *Private settlement, MEV-resistant execution, computation integrity verification.*

### Card 3: Algorithmic Agility
> **Dynamic algorithm negotiation** — Operators serve Ed25519, ECDSA-P256, or ML-DSA-65 per request. Clean migration path as FIPS 204 firmware ships to HSMs.
>
> *Today's compatibility. Tomorrow's quantum resistance. No hard fork required.*

**CTA:** `[Read the Technical Specification →]` — links to whitepaper

---

## Section 4: How It Works (Protocol Flow)

**Section Title:** 3 Steps to Quantum-Proof Your Protocol

**Visual flow diagram:**

```
1. Protocol submits request → 2. Coordinator forms quorum → 3. Threshold signature returned
```

**Step 1: Submit**  
Protocol sends a signing or proving request via SDK. Specifies algorithm preference, urgency tier, and quorum size.

**Step 2: Coordinate**  
Deterministic coordinator selection via consistent hashing. Coordinator assembles quorum (3-of-5), routes partial signing tasks, aggregates partial signatures.

**Step 3: Verify**  
Combined signature returned to protocol. Verifiable on-chain. Quantum-resistant. Completed in ~200ms off-chain latency.

**Fee callout (small, transparent):**  
Per-operation network fee: $0.025/signature · $1.00-$2.50/STARK proof. 40% coordinator / 50% participants / 10% treasury. No subscriptions. No licenses.

---

## Section 5: For Protocol Integrators

**Section Title:** Bolt-On Quantum Security in Minutes

**Key points (icon grid):**

- **Open-source SDK** — Rust crate, gRPC API, Solana-native. Import and start signing.
- **Chain-agnostic** — Serves Ethereum, Solana, Cosmos, Move-based chains. Quantum risk is universal.
- **No sales team** — Read the docs, import the SDK, integrate. The code sells itself.
- **Transparent pricing** — Per-operation fee. No enterprise tiers. No negotiated contracts.
- **NIST-standardized** — ML-DSA-65 (FIPS 204), ML-KEM-1024 (FIPS 203). Not experimental. Not proprietary.

**Target use cases (tag pills):**  
`Bridge Custody` · `Protocol Treasury` · `Validator Key Management` · `Governance Multisig` · `Private Settlement` · `MEV Protection`

**CTA:** `[View Integration Docs →]` · `[SDK Quickstart →]`

---

## Section 6: For Operators (Scarcity + FOMO)

**Section Title:** Genesis Operator Program — 50 Seats

**Copy direction:**

> The QPL operator network is intentionally constrained at launch. The Genesis cohort is limited to **50 operator slots**. Once full, the next cohort waits.

> Operators are independent service providers who run quantum-resistant infrastructure and earn service fees for computational work performed. You provide the HSM, the compute, and the uptime. The network routes requests to you.

**What you need:**
- Dedicated HSM (PKCS#11 compatible)
- VPS with <50ms latency to Solana validators
- 1 SOL security deposit (collateral for honest behavior)
- 99.5% uptime commitment

**What you get:**
- Service fee revenue for every signature and proof you process
- Priority request routing during the highest-demand period
- Genesis operator badge — permanent recognition in the protocol
- Achievement-based unlocks: testnet participation and uptime milestones unlock mainnet priority

**Live counter (if available):**  
`[XX / 50 Genesis slots filled]`

**CTA:** `[Apply for Genesis Slot →]`

**Compliance note (small text):**  
*Operator fees are compensation for computational services rendered. Revenue varies with network demand. Staking SOL is a security deposit for network access, not an investment. QPL does not guarantee earnings.*

---

## Section 7: Security & Trust

**Section Title:** The Code Is the Credibility

**Trust signals (grid):**

| Signal | Detail |
|--------|--------|
| **Open Source** | MIT / Apache-2.0 licensed. Full source on GitHub. |
| **NIST Standardized** | ML-DSA-65 (FIPS 204), ML-KEM-1024 (FIPS 203) — not experimental |
| **200+ Test Suite** | Unit, integration, fuzz, e2e, red team vectors |
| **HSM-Backed** | PKCS#11 hardware security modules. Keys never leave the HSM boundary. |
| **Threshold Security** | t-1 compromised operators learn nothing about the signing key |
| **No Trusted Setup** | STARK proofs use FRI with public randomness. No ceremony. No trust assumption. |
| **Solana Programs** | Anchor framework. Checked arithmetic. PDA isolation. Full test coverage. |
| **Threat Model** | Public threat model covering nation-state, criminal, opportunistic, and insider adversaries |

**CTA:** `[View Security Policy →]` · `[Read Threat Model →]` · `[Audit Report →]`

---

## Section 8: Competitive Positioning

**Section Title:** Why QPL Exists

**Comparison table (honest, no strawmen):**

| | QPL | Fireblocks | Lit Protocol | AWS KMS |
|---|---|---|---|---|
| Quantum Resistance | ✅ ML-DSA-65 | ❌ Classical MPC | ❌ Classical threshold | ❌ ECDSA/RSA |
| Open Source | ✅ MIT/Apache | ❌ Closed | ✅ Partial | ❌ Proprietary |
| Threshold Signing | ✅ 3-of-5 N-of-M | ✅ MPC-CMP | ✅ ECDSA threshold | ❌ Single-key |
| Zero-Knowledge Proofs | ✅ STARK (no setup) | ❌ | ❌ | ❌ |
| Chain-Agnostic | ✅ Any chain | ⚠️ 80+ chains | ⚠️ EVM-focused | ⚠️ AWS-only |
| Trusted Setup Required | ❌ None | N/A | N/A | N/A |
| Per-Op Pricing | ✅ Transparent | ❌ Enterprise license | ⚠️ Token-gated | ⚠️ Hourly HSM |

**One-liner:**  
> QPL is the only open-source, quantum-proof, chain-agnostic signing and proving infrastructure with transparent per-operation pricing.

---

## Section 9: Timeline & Roadmap

**Section Title:** The Path to Mainnet

**Visual timeline:**

```
Q3 2026        Q4 2026        Q1 2027        Q2 2027
Testnet   →   Audits    →   Formal     →   Mainnet
Genesis         3rd party     Verification   Public
Operators       security      STARK proofs   availability
                audits
```

**Current status badge:** `🟢 Testnet — Genesis Operator Applications Open`

---

## Section 10: Footer

**Links:**
- GitHub (source code)
- Documentation / SDK
- Whitepaper (technical specification)
- Security Policy
- Threat Model
- Discord / Community

**Compliance footer text:**  
> QPL is open-source decentralized infrastructure. Operators are independent service providers. Network fees are compensation for computational work performed — not investment returns. Staking SOL is a security deposit for network access. QPL does not guarantee operator revenue. All projections are estimates based on computational work performed at projected request volumes.

---

## Design Notes for Emergent

- **Color palette:** Dark background (#0a0a0a), terminal green (#00ff88), electric blue (#3b82f6), white text
- **Typography:** Monospace for code/technical elements, clean sans-serif for body
- **Animations:** Subtle — network node connections, threshold quorum formation, countdown timer
- **Mobile-first:** All sections must collapse cleanly to single column
- **No stock photos** — use diagrams, code snippets, and protocol flow visualizations
- **Performance:** Lazy-load below-fold sections, optimize hero animation

---

## Howey Compliance Checklist (Pre-Publish)

- [x] No "investment" language anywhere
- [x] No "returns," "APY," "APR," "passive income," "yield on stake"
- [x] No "common enterprise" framing
- [x] No "efforts of others" dependency implied
- [x] Staking framed as "security deposit" / "collateral" — not investment
- [x] Operator fees framed as "compensation for computational work" — not returns
- [x] Explicit compliance disclaimer in operator section and footer
- [x] No airdrops, token incentives, or liquidity mining mentioned
- [x] Scarcity claims (50 Genesis slots) reflect actual protocol constraints
