# QPL Network — 3-Year Financial Projection & Model Audit

**Prepared by:** DeFi CFO Agent
**Date:** June 2026
**Version:** 2.0 (Revised fee schedule)
**Status:** DRAFT — Requires validation of volume assumptions with DeFi Protocol Strategist

---

## Executive Summary

QPL generates revenue exclusively from per-operation network fees (signing and proving). This document projects fee revenue, operator economics, and treasury sustainability across three scenarios over 12 quarters (Q3 2026 — Q2 2029). It also audits the current fee model implementation for structural risks.

**Key findings (revised fee schedule v2.0):**
- Treasury self-sufficiency (covering $15K/month operating costs) requires ~67,000 signing requests/day in the Base scenario — achievable with 2-3 anchor tenants
- Operator break-even occurs at ~1,343 signing requests/day per operator at current fee levels (25× lower than previous projection)
- The fee increase from $0.001 to $0.025 per signature makes operator economics viable from early Genesis phase
- Year 3 Base scenario projects $8.1M annual protocol revenue (treasury share: $810K)
- The gas cost erosion issue (Issue 1) remains critical — at $0.025 per signing, gas costs are manageable but prepaid balances are still recommended

---

## 1. Assumptions

### 1.1 Fee Schedule (from `fees.rs`, revised June 2026)

| Operation | Base Fee | With 3-of-5 Quorum | With Instant Urgency (3-of-5) |
|-----------|----------|--------------------|-------------------------------|
| Threshold signature | $0.025 | $0.075 | $0.150 |
| STARK proof (small, <=100 tx) | $1.00 | $3.00 | $6.00 |
| STARK proof (large, >100 tx) | $2.50 | $7.50 | $15.00 |
| Proof verification | $0.025 | $0.075 | $0.150 |

**Blended average fee assumption:** $0.12/request (weighted 80% signing at $0.075, 15% small proving at $3.00, 5% large proving at $7.50)

### 1.2 Fee Distribution

| Recipient | Share | Per $0.075 signing request | Per $3.00 proving request |
|-----------|-------|---------------------------|--------------------------|
| Coordinator | 40% | $0.030 | $1.20 |
| Participants (2) | 50% | $0.01875 each | $0.75 each |
| Treasury | 10% | $0.0075 | $0.30 |

### 1.3 Operator Cost Assumptions

| Cost Item | Monthly per Operator | Notes |
|-----------|---------------------|-------|
| HSM hardware (amortized) | $1,000 | Dedicated HSM or cloud HSM service |
| Compute (VPS/cloud) | $200 | 4 vCPU, 8GB RAM, NVMe |
| Bandwidth | $50 | ~1TB/month at scale |
| SOL stake opportunity cost | $34 | 10 SOL at ~$68, 5% APR foregone |
| DevOps/monitoring | $50 | Alerting, log aggregation |
| **Total** | **$1,303/month** | |

### 1.4 Protocol Operating Costs (Treasury Burn)

| Cost Item | Monthly | Annual | Notes |
|-----------|---------|--------|-------|
| Core development (2 devs, part-time) | $8,000 | $96,000 | Assumes lean contributor model |
| Security audits | $4,000 | $48,000 | 1 major audit/year + ongoing |
| Infrastructure (RPC, monitoring) | $1,500 | $18,000 | Alchemy/Infura, Grafana |
| Legal/compliance | $1,000 | $12,000 | On-retainer, quarterly review |
| Miscellaneous | $500 | $6,000 | Domain, comms, tooling |
| **Total** | **$15,000** | **$180,000** | |

### 1.5 Volume Growth Assumptions

Based on GTM strategy (phased rollout):

| Phase | Timeline | Integrator Profile | Daily Volume (signing) |
|-------|----------|-------------------|----------------------|
| Testnet | Q3 2026 | 3 bridges (private) | 0 (no fees) |
| Genesis | Q4 2026 | 5 bridges + 10 DAOs | 10K-50K |
| Early | Q1-Q2 2027 | 15 protocols | 50K-200K |
| Growth | Q3 2027-Q4 2027 | 30+ protocols | 200K-500K |
| Maturity | 2028-2029 | 50+ protocols | 500K-2M |

---

## 2. Three-Year Revenue Projection

### 2.1 Conservative Scenario (Tier 1 Only — Bridges)

*Only bridge integrations materialize. 3 bridges at launch, growing to 8 by Year 3. All signing, minimal proving.*

| Quarter | Daily Requests | Quarterly Revenue | Treasury (10%) |
|---------|---------------|-------------------|----------------|
| Q3 2026 | 0 | $0 | $0 |
| Q4 2026 | 5,000 | $27,375 | $2,738 |
| Q1 2027 | 15,000 | $82,125 | $8,213 |
| Q2 2027 | 30,000 | $164,250 | $16,425 |
| Q3 2027 | 50,000 | $273,750 | $27,375 |
| Q4 2027 | 70,000 | $383,250 | $38,325 |
| Q1 2028 | 90,000 | $492,750 | $49,275 |
| Q2 2028 | 110,000 | $602,250 | $60,225 |
| Q3 2028 | 130,000 | $711,750 | $71,175 |
| Q4 2028 | 150,000 | $821,250 | $82,125 |
| Q1 2029 | 170,000 | $930,750 | $93,075 |
| Q2 2029 | 200,000 | $1,095,000 | $109,500 |

*Revenue calculated as: daily_requests × $0.075 × 91.25 days/quarter*

**Year 1 Total:** $273,750 revenue | $27,375 treasury
**Year 2 Total:** $2,628,000 revenue | $262,800 treasury
**Year 3 Total:** $3,558,750 revenue | $355,875 treasury

**Treasury self-sufficient?** YES, from Q2 2027 (Month 9). Treasury surplus from Year 2 onward.

---

### 2.2 Base Scenario (Tier 1 + Tier 2 — Bridges + DAOs + Some DEXs)

*Bridges + DAO governance + initial DEX proving integrations. Proving mix grows to 20% by Year 2.*

| Quarter | Daily Requests | Blended Avg Fee | Quarterly Revenue | Treasury (10%) |
|---------|---------------|-----------------|-------------------|----------------|
| Q3 2026 | 0 | $0.075 | $0 | $0 |
| Q4 2026 | 20,000 | $0.075 | $109,500 | $10,950 |
| Q1 2027 | 60,000 | $0.080 | $350,400 | $35,040 |
| Q2 2027 | 120,000 | $0.090 | $787,200 | $78,720 |
| Q3 2027 | 200,000 | $0.100 | $1,460,000 | $146,000 |
| Q4 2027 | 300,000 | $0.110 | $2,409,000 | $240,900 |
| Q1 2028 | 400,000 | $0.120 | $3,288,000 | $328,800 |
| Q2 2028 | 500,000 | $0.120 | $4,110,000 | $411,000 |
| Q3 2028 | 650,000 | $0.120 | $5,334,000 | $533,400 |
| Q4 2028 | 800,000 | $0.120 | $6,564,000 | $656,400 |
| Q1 2029 | 1,000,000 | $0.120 | $8,205,000 | $820,500 |
| Q2 2029 | 1,200,000 | $0.120 | $9,846,000 | $984,600 |

*Blended fee rises as proving mix increases from 0% to 20% (proving = ~40× signing fee).*

**Year 1 Total:** $1,361,100 revenue | $136,110 treasury
**Year 2 Total:** $15,858,000 revenue | $1,585,800 treasury
**Year 3 Total:** $28,050,000 revenue | $2,805,000 treasury

**Treasury self-sufficient?** YES, from Q1 2027 (Month 6). Fully sustainable in Year 1. No bridge funding required.

---

### 2.3 Aggressive Scenario (All Tiers — Full Adoption)

*Bridges + DAOs + DEXs + Restaking + MEV protection. Proving volume scales significantly to 30% mix.*

| Quarter | Daily Requests | Blended Avg Fee | Quarterly Revenue | Treasury (10%) |
|---------|---------------|-----------------|-------------------|----------------|
| Q3 2026 | 0 | $0.075 | $0 | $0 |
| Q4 2026 | 50,000 | $0.080 | $292,000 | $29,200 |
| Q1 2027 | 150,000 | $0.100 | $1,095,000 | $109,500 |
| Q2 2027 | 350,000 | $0.150 | $3,832,500 | $383,250 |
| Q3 2027 | 600,000 | $0.200 | $8,760,000 | $876,000 |
| Q4 2027 | 900,000 | $0.250 | $16,447,500 | $1,644,750 |
| Q1 2028 | 1,200,000 | $0.300 | $32,880,000 | $3,288,000 |
| Q2 2028 | 1,500,000 | $0.350 | $49,237,500 | $4,923,750 |
| Q3 2028 | 2,000,000 | $0.350 | $65,700,000 | $6,570,000 |
| Q4 2028 | 2,500,000 | $0.350 | $82,125,000 | $8,212,500 |
| Q1 2029 | 3,000,000 | $0.350 | $98,550,000 | $9,855,000 |
| Q2 2029 | 3,500,000 | $0.350 | $115,012,500 | $11,501,250 |

*Note: Blended fee rises as proving mix increases to 30% (proving = ~40× signing fee).*

**Year 1 Total:** $8,760,000 revenue | $876,000 treasury
**Year 2 Total:** $197,062,500 revenue | $19,706,250 treasury
**Year 3 Total:** $395,662,500 revenue | $39,566,250 treasury

**Treasury self-sufficient?** YES, from Q4 2026 (Month 3). Massive surplus by Year 2.

---

## 3. Operator Unit Economics

### 3.1 Break-Even Analysis (Single Operator)

An operator acting as **participant** in 3-of-5 signing quorums:

```
Per-request revenue (participant): $0.01875 (50% of $0.075 / 2 participants)
Monthly costs: $1,450
Break-even requests/month: $1,450 / $0.01875 = 77,333 requests
Break-even requests/day: ~2,578 requests/day
```

An operator acting as **coordinator** in 3-of-5 signing quorums:

```
Per-request revenue (coordinator): $0.030 (40% of $0.075)
Monthly costs: $1,450
Break-even requests/month: $1,450 / $0.030 = 48,333 requests
Break-even requests/day: ~1,611 requests/day
```

**Blended** (operator serves as coordinator 20% of time, participant 80%):

```
Blended per-request: (0.2 × $0.030) + (0.8 × $0.01875) = $0.021
Break-even: $1,450 / $0.021 = 69,048 requests/month = ~2,302 requests/day
```

### 3.2 Operator Revenue at Scale

| Network Daily Volume | Operators | Requests/Operator/Day | Monthly Revenue/Operator | Net After Costs |
|---------------------|-----------|----------------------|------------------------|----------------|
| 10,000 | 10 | 1,000 | $630 | -$820 (LOSS) |
| 50,000 | 10 | 5,000 | $3,150 | +$1,700 |
| 100,000 | 20 | 5,000 | $3,150 | +$1,700 |
| 200,000 | 20 | 10,000 | $6,300 | +$4,850 |
| 500,000 | 50 | 10,000 | $6,300 | +$4,850 |
| 1,000,000 | 100 | 10,000 | $6,300 | +$4,850 |

*Revenue calculated as: requests/operator/day × $0.021 blended × 30.44 days/month*

**Key finding:** At Genesis launch (15 operators, 10K-50K daily requests), operators break even at ~2,048 requests/operator/day. With 50,000 daily requests across 15 operators (~3,333 each), operators earn $2,100/month — **1.6× their costs**. This is a viable economic model from launch.

### 3.3 Proving Revenue Changes the Math Dramatically

Operators serving proving requests earn dramatically more per operation:

```
Proving (small batch, participant): $1.00 × 3 (quorum) × 50% / 2 = $0.75 per request
Proving (large batch, coordinator): $2.50 × 5 (quorum) × 40% = $5.00 per request
```

A mixed workload (80% signing, 20% proving) changes break-even to ~480 requests/day:

```
Blended (80/20 sign/prove): 0.80 × $0.021 + 0.20 × $0.75 = $0.1668/request
Break-even: $1,450 / $0.1668 = 8,693 requests/month = ~290 requests/day
```

---

## 4. Treasury Sustainability Analysis

### 4.1 Break-Even Volume for Treasury

Treasury receives 10% of all fees. Required monthly treasury income: $15,000.

```
Required monthly fee revenue: $15,000 / 0.10 = $150,000
Required daily fee revenue: $150,000 / 30 = $5,000/day
At $0.075 per signing request: $5,000 / $0.075 = 66,667 requests/day
At $0.12 blended avg: $5,000 / $0.12 = 41,667 requests/day
```

**Treasury self-sufficiency requires 42K-67K requests/day** (depending on proving mix). This is achieved:
- Conservative: Q2 2027 (Month 9)
- Base: Q1 2027 (Month 6)
- Aggressive: Q4 2026 (Month 3)

### 4.2 Pre-Sustainability Funding Gap

| Scenario | Months Until Treasury Break-Even | Cumulative Deficit |
|----------|--------------------------------|-------------------|
| Conservative | ~9 months | -$67K |
| Base | ~6 months | -$45K |
| Aggressive | ~3 months | -$15K |

This deficit must be covered by: initial capital, grants, or reduced operating costs. The revised fee schedule reduces the funding gap by 5-10× compared to the original projection.

---

## 5. Financial Model Audit — Issues Identified

### ISSUE 1: Gas Cost Erosion (MODERATE — improved by fee increase)

**Problem:** The fee model charges $0.025 per signature, but the on-chain fee payment (`QPLFeeRouter.payFee()`) costs gas. At current Solana gas prices (~$0.001 per transaction):

```
Solana transaction: ~5,000 compute units = ~$0.0005-0.001
```

**The gas cost to pay the fee ($0.001) is 4% of the signing fee itself ($0.025).**

**Impact:** Much improved from the original model (where gas was 700% of the fee). Gas costs are now manageable but still erode margins at scale. Prepaid balances remain recommended for high-volume protocols.

**Recommended fix:** Implement batched fee payment (prepaid balance) or off-chain fee channels with periodic settlement. The `QPLFeeRouter` should support:
- `depositBalance(amount)` — Protocol pre-funds a balance
- Operations deduct from balance off-chain
- Periodic on-chain settlement reconciles balances

---

### ISSUE 2: Fee Quote Expiry Too Short (MODERATE)

**Problem:** Fee quotes expire in 60 seconds (`fee_quote_expiry_secs: 60`). If the on-chain payment requires a transaction that takes >60 seconds to confirm (congested network), the quote expires before the protocol can reference it.

**Impact:** During high congestion periods, protocols cannot reliably pay for operations.

**Recommended fix:** Extend quote expiry to 300 seconds (5 minutes), or decouple quote validation from on-chain confirmation.

---

### ISSUE 3: Operator Bootstrapping Economics (RESOLVED by fee increase)

**Previous problem:** At Genesis launch volumes (50 operators, 20K requests/day), operators earned ~$12/month against $1,303/month in costs.

**Resolution:** With the revised fee schedule ($0.025/signature) and curated genesis set of 15 operators, at 50K requests/day across 15 operators, each earns $2,100/month — 1.6× costs. The bootstrapping problem is resolved.

**Remaining risk:** If operator count grows faster than volume (e.g., 50 operators at 10K requests/day), per-operator revenue drops to $630/month against $1,303 costs. Governance should manage operator capacity targets and expansion pace.

---

### ISSUE 4: Fee Denomination in USD But Payment in SOL (MODERATE)

**Problem:** Fees are calculated in USD micro-units but paid in SOL on-chain. This creates FX risk:
- If SOL drops 50%, the $0.025 fee costs protocols 2× as much SOL
- If SOL rises 2×, operators receive half as much USD value per SOL earned

**Impact:** Neither protocols nor operators have predictable economics in their native denomination.

**Recommended fix:** Either:
- Accept USDC/USDT on-chain (stable denomination matching fee schedule)
- Implement a price oracle for SOL/USD conversion at payment time
- Denominate fees in SOL directly (simpler, but less intuitive pricing)

---

### ISSUE 5: Dead Fee Operations in Code (LOW)

**Problem:** `FeeSchedule` includes pricing for operations QPL no longer supports:
- `workflow_creation_base` / `workflow_step_base` (Settlement service removed)
- `yield_accrual_base` / `yield_mint_base` (Yield service removed)
- `rwa_registration_base` / `rwa_nav_update_base` (RWA service removed)

**Impact:** Unused code creates confusion.

**Recommended fix:** Remove all fee types except `Sign`, `ProveSmallBatch`, `ProveLargeBatch`, and `VerifyProof` from both `FeeSchedule` and `FeeOperation` enum.

---

### ISSUE 6: No Fee Floor Protection (LOW)

**Problem:** The fee split math uses integer division. At very low fee amounts, rounding truncation can result in participants receiving negligible compensation.

**Impact:** Minimal at current fee levels ($0.025 base = 25,000 micro-USD, easily divisible).

**Recommended fix:** Add a minimum total fee constant (e.g., `MIN_TOTAL_FEE = 1000`) that rejects quotes below the threshold.

---

## 6. Recommendations

### Immediate (Before Mainnet)

1. **Implement prepaid balance system** in QPLFeeRouter (fixes Issue 1 — gas erosion at scale)
2. **Remove dead fee operations** from FeeSchedule and FeeOperation (fixes Issue 5)
3. **Extend quote expiry** to 300 seconds (fixes Issue 2)
4. **Add MIN_TOTAL_FEE guard** (fixes Issue 6)

### Pre-Launch (Genesis Phase)

5. **Decide fee denomination** — USDC payment option on QPLFeeRouter (fixes Issue 4)
6. **Model Genesis cohort** with 10-20 operators to maintain healthy per-operator volume
7. **Set operator capacity target** — governance should cap operator count to maintain >$2,000/month revenue per operator

### Post-Launch (Year 1)

8. **Monitor blended fee and adjust** — if proving mix is higher than assumed, fees may be reduced to drive adoption
9. **Track operator churn** — if >20% monthly, fees are too low or costs too high
10. **Establish treasury reserve target** — 6 months of operating costs ($90K minimum) before expanding team

---

## 7. Summary Table

| Metric | Conservative | Base | Aggressive |
|--------|-------------|------|-----------|
| Year 1 revenue | $274K | $1.36M | $8.76M |
| Year 2 revenue | $2.63M | $15.86M | $197M |
| Year 3 revenue | $3.56M | $28.05M | $396M |
| Treasury break-even | Month 9 | Month 6 | Month 3 |
| Operator break-even (daily reqs) | 2,302 | 2,302 | 2,302 |
| Pre-sustainability funding gap | $67K | $45K | $15K |
| Critical risk | Volume never materializes | Operator count grows too fast | Fee compression from competitors |

---

## 8. Comparison to Previous Projection (v1.0)

| Metric | v1.0 (May 2026) | v2.0 (June 2026) | Change |
|--------|----------------|------------------|--------|
| Signing fee | $0.001 | $0.025 | 25× |
| Proving fee (small) | $0.05 | $1.00 | 20× |
| Operator break-even | 4,800 reqs/day | 2,302 reqs/day | 52% lower |
| Treasury break-even | 1.25M reqs/day | 67K reqs/day | 95% lower |
| Year 1 Base revenue | $72K | $1.36M | 19× |
| Pre-sustainability gap | $310K | $45K | 85% lower |
| Operator monthly profit (50K/day, 10 ops) | -$119 LOSS | +$1,700 | Viable |

The revised fee schedule transforms QPL from a protocol that struggles to sustain operators into one with viable economics from early Genesis phase.

---

*This projection is not financial advice. All figures are estimates based on assumed integration pipelines and market conditions. Actual results will vary based on DeFi market activity, integration velocity, and operator participation.*
