# QPL Network — 3-Year Financial Projection & Model Audit

**Prepared by:** DeFi CFO Agent
**Date:** May 2026
**Version:** 1.0
**Status:** DRAFT — Requires validation of volume assumptions with DeFi Protocol Strategist

---

## Executive Summary

QPL generates revenue exclusively from per-operation network fees (signing and proving). This document projects fee revenue, operator economics, and treasury sustainability across three scenarios over 12 quarters (Q3 2026 — Q2 2029). It also audits the current fee model implementation for structural risks.

**Key findings:**
- Treasury self-sufficiency (covering $15K/month operating costs) requires ~50K signing requests/day in the Base scenario
- Operator break-even occurs at ~330 signing requests/day per operator at current fee levels
- The fee model has 4 structural risks requiring mitigation (detailed in Audit section)
- Year 3 Base scenario projects $1.8M annual protocol revenue (treasury share: $180K)

---

## 1. Assumptions

### 1.1 Fee Schedule (from `fees.rs`)

| Operation | Base Fee | With 3-of-5 Quorum | With Instant Urgency |
|-----------|----------|--------------------|--------------------|
| Threshold signature | $0.001 | $0.003 | $0.006 |
| STARK proof (small) | $0.05 | $0.15 | $0.30 |
| STARK proof (large) | $0.10 | $0.30 | $0.60 |

**Blended average fee assumption:** $0.004/request (weighted 80% signing at $0.003, 20% proving at $0.08)

### 1.2 Fee Distribution

| Recipient | Share | Per $0.004 request |
|-----------|-------|-------------------|
| Coordinator | 40% | $0.0016 |
| Participants (2) | 50% | $0.0010 each |
| Treasury | 10% | $0.0004 |

### 1.3 Operator Cost Assumptions

| Cost Item | Monthly per Operator | Notes |
|-----------|---------------------|-------|
| Compute (VPS/cloud) | $100 | 4 vCPU, 8GB RAM, NVMe |
| Bandwidth | $20 | ~1TB/month at scale |
| Stake opportunity cost | $15 | 1 ETH at 5% APR / 12 months (at $3,600/ETH) |
| DevOps/monitoring | $15 | Alerting, log aggregation |
| **Total** | **$150/month** | |

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

*Only bridge integrations materialize. 3 bridges at launch, growing to 8 by Year 3.*

| Quarter | Daily Requests | Quarterly Revenue | Treasury (10%) |
|---------|---------------|-------------------|----------------|
| Q3 2026 | 0 | $0 | $0 |
| Q4 2026 | 5,000 | $1,800 | $180 |
| Q1 2027 | 15,000 | $5,400 | $540 |
| Q2 2027 | 30,000 | $10,800 | $1,080 |
| Q3 2027 | 50,000 | $18,000 | $1,800 |
| Q4 2027 | 70,000 | $25,200 | $2,520 |
| Q1 2028 | 90,000 | $32,400 | $3,240 |
| Q2 2028 | 110,000 | $39,600 | $3,960 |
| Q3 2028 | 130,000 | $46,800 | $4,680 |
| Q4 2028 | 150,000 | $54,000 | $5,400 |
| Q1 2029 | 170,000 | $61,200 | $6,120 |
| Q2 2029 | 200,000 | $72,000 | $7,200 |

**Year 1 Total:** $18,000 revenue | $1,800 treasury
**Year 2 Total:** $151,200 revenue | $15,120 treasury
**Year 3 Total:** $234,000 revenue | $23,400 treasury

**Treasury self-sufficient?** NO. Conservative scenario never covers $180K/year operating costs from treasury alone. Requires supplemental funding or cost reduction.

---

### 2.2 Base Scenario (Tier 1 + Tier 2 — Bridges + DAOs + Some DEXs)

*Bridges + DAO governance + initial DEX proving integrations.*

| Quarter | Daily Requests | Quarterly Revenue | Treasury (10%) |
|---------|---------------|-------------------|----------------|
| Q3 2026 | 0 | $0 | $0 |
| Q4 2026 | 20,000 | $7,200 | $720 |
| Q1 2027 | 60,000 | $21,600 | $2,160 |
| Q2 2027 | 120,000 | $43,200 | $4,320 |
| Q3 2027 | 200,000 | $72,000 | $7,200 |
| Q4 2027 | 300,000 | $108,000 | $10,800 |
| Q1 2028 | 400,000 | $144,000 | $14,400 |
| Q2 2028 | 500,000 | $180,000 | $18,000 |
| Q3 2028 | 650,000 | $234,000 | $23,400 |
| Q4 2028 | 800,000 | $288,000 | $28,800 |
| Q1 2029 | 1,000,000 | $360,000 | $36,000 |
| Q2 2029 | 1,200,000 | $432,000 | $43,200 |

**Year 1 Total:** $72,000 revenue | $7,200 treasury
**Year 2 Total:** $744,000 revenue | $74,400 treasury
**Year 3 Total:** $1,314,000 revenue | $131,400 treasury

**Treasury self-sufficient?** Approaches break-even in Q2 2028 (18 months). Fully sustainable in Year 3. Requires bridge funding of ~$130K for first 18 months.

---

### 2.3 Aggressive Scenario (All Tiers — Full Adoption)

*Bridges + DAOs + DEXs + Restaking + MEV protection. Proving volume scales significantly.*

| Quarter | Daily Requests | Blended Avg Fee | Quarterly Revenue | Treasury (10%) |
|---------|---------------|-----------------|-------------------|----------------|
| Q3 2026 | 0 | $0.004 | $0 | $0 |
| Q4 2026 | 50,000 | $0.004 | $18,000 | $1,800 |
| Q1 2027 | 150,000 | $0.005 | $67,500 | $6,750 |
| Q2 2027 | 350,000 | $0.006 | $189,000 | $18,900 |
| Q3 2027 | 600,000 | $0.007 | $378,000 | $37,800 |
| Q4 2027 | 900,000 | $0.008 | $648,000 | $64,800 |
| Q1 2028 | 1,200,000 | $0.009 | $972,000 | $97,200 |
| Q2 2028 | 1,500,000 | $0.010 | $1,350,000 | $135,000 |
| Q3 2028 | 2,000,000 | $0.010 | $1,800,000 | $180,000 |
| Q4 2028 | 2,500,000 | $0.010 | $2,250,000 | $225,000 |
| Q1 2029 | 3,000,000 | $0.010 | $2,700,000 | $270,000 |
| Q2 2029 | 3,500,000 | $0.010 | $3,150,000 | $315,000 |

*Note: Blended fee rises as proving mix increases (proving = 50-100x signing fee).*

**Year 1 Total:** $274,500 revenue | $27,450 treasury
**Year 2 Total:** $5,148,000 revenue | $514,800 treasury
**Year 3 Total:** $9,900,000 revenue | $990,000 treasury

**Treasury self-sufficient?** YES, from Q2 2027 (9 months). Significant treasury surplus by Year 2.

---

## 3. Operator Unit Economics

### 3.1 Break-Even Analysis (Single Operator)

An operator acting as **participant** in 3-of-5 signing quorums:

```
Per-request revenue (participant): $0.001 (50% of $0.003 / 2 participants)
Monthly costs: $150
Break-even requests/month: $150 / $0.001 = 150,000 requests
Break-even requests/day: ~5,000 requests/day
```

An operator acting as **coordinator** in 3-of-5 signing quorums:

```
Per-request revenue (coordinator): $0.0012 (40% of $0.003)
Monthly costs: $150
Break-even requests/month: $150 / $0.0012 = 125,000 requests
Break-even requests/day: ~4,200 requests/day
```

**Blended** (operator serves as coordinator 20% of time, participant 80%):

```
Blended per-request: (0.2 x $0.0012) + (0.8 x $0.001) = $0.00104
Break-even: $150 / $0.00104 = 144,230 requests/month = ~4,800 requests/day
```

### 3.2 Operator Revenue at Scale

| Network Daily Volume | Operators | Requests/Operator/Day | Monthly Revenue/Operator | Net After Costs |
|---------------------|-----------|----------------------|------------------------|----------------|
| 50,000 | 50 | 1,000 | $31 | -$119 (LOSS) |
| 200,000 | 50 | 4,000 | $125 | -$25 (LOSS) |
| 500,000 | 50 | 10,000 | $312 | +$162 |
| 1,000,000 | 100 | 10,000 | $312 | +$162 |
| 2,000,000 | 200 | 10,000 | $312 | +$162 |

**Critical finding:** At the Genesis launch (50 operators, 20K-50K daily requests), operators will NOT break even. This is an economic bootstrapping problem.

### 3.3 Proving Revenue Changes the Math

Operators serving proving requests earn dramatically more per operation:

```
Proving (small batch, participant): $0.05 x 3 (quorum) x 50% / 2 = $0.0375 per request
Proving (large batch, coordinator): $0.10 x 5 (quorum) x 40% = $0.20 per request
```

A mixed workload (50% signing, 50% proving) changes break-even to ~330 requests/day.

---

## 4. Treasury Sustainability Analysis

### 4.1 Break-Even Volume for Treasury

Treasury receives 10% of all fees. Required monthly treasury income: $15,000.

```
Required monthly fee revenue: $15,000 / 0.10 = $150,000
Required daily fee revenue: $150,000 / 30 = $5,000/day
At $0.004 blended avg: $5,000 / $0.004 = 1,250,000 requests/day
```

**Treasury self-sufficiency requires 1.25M requests/day.** This is achieved:
- Conservative: Never (within 3 years)
- Base: Q1 2029 (Month 30)
- Aggressive: Q3 2027 (Month 12)

### 4.2 Pre-Sustainability Funding Gap

| Scenario | Months Until Treasury Break-Even | Cumulative Deficit |
|----------|--------------------------------|-------------------|
| Conservative | >36 months | -$540K+ |
| Base | ~30 months | -$310K |
| Aggressive | ~12 months | -$95K |

This deficit must be covered by: initial capital, grants, or reduced operating costs.

---

## 5. Financial Model Audit — Issues Identified

### ISSUE 1: Gas Cost Erosion (CRITICAL)

**Problem:** The fee model charges $0.001 per signature, but the on-chain fee payment (`QPLFeeRouter.payFee()`) costs gas. At $3,600 ETH and 30 gwei base fee:

```
Simple ERC-20 transfer: ~65K gas = 65,000 x 30 gwei = 1,950,000 gwei = $0.007
```

**The gas cost to pay the fee ($0.007) is 7x the signing fee itself ($0.001).**

**Impact:** Protocols will not make per-operation on-chain payments. The entire micro-fee model collapses if each operation requires an individual on-chain transaction.

**Recommended fix:** Implement batched fee payment (prepaid balance) or off-chain fee channels with periodic settlement. The `QPLFeeRouter` should support:
- `depositBalance(amount)` — Protocol pre-funds a balance
- Operations deduct from balance off-chain
- Periodic on-chain settlement reconciles balances

---

### ISSUE 2: Fee Quote Expiry Too Short (MODERATE)

**Problem:** Fee quotes expire in 60 seconds (`fee_quote_expiry_secs: 60`). If the on-chain payment requires a transaction that takes >60 seconds to confirm (congested mempool), the quote expires before the protocol can reference it.

**Impact:** During high gas periods, protocols cannot reliably pay for operations. Creates a window where the service is effectively unavailable.

**Recommended fix:** Extend quote expiry to 300 seconds (5 minutes), or decouple quote validation from on-chain confirmation (validate at fee payment submission time, not confirmation time).

---

### ISSUE 3: Operator Bootstrapping Economics (HIGH)

**Problem:** At Genesis launch volumes (50 operators, 20K requests/day), each operator earns ~$12/month against $150/month in costs. Operators lose $138/month for the first 6-12 months.

**Impact:** Rational operators will not join if expected near-term service fees don't cover costs. The network cannot bootstrap.

**Recommended fix options:**
1. **Fee subsidy from treasury:** Treasury covers operator infrastructure costs during bootstrap (grants, not investment)
2. **Reduced minimum operators:** Start with 10-20 operators (higher per-operator volume)
3. **Tiered fee schedule:** Higher fees during low-volume periods (scarcity pricing)
4. **Infrastructure partnerships:** Negotiate cloud credits for Genesis operators

---

### ISSUE 4: Fee Denomination in USD But Payment in ETH (MODERATE)

**Problem:** Fees are calculated in USD micro-units but paid in ETH on-chain. This creates FX risk:
- If ETH drops 50%, the $0.001 fee costs protocols 2x as much ETH
- If ETH rises 2x, operators receive half as much USD value per ETH earned

**Impact:** Neither protocols nor operators have predictable economics in their native denomination.

**Recommended fix:** Either:
- Accept USDC/USDT on-chain (stable denomination matching fee schedule)
- Implement a price oracle for ETH/USD conversion at payment time
- Denominate fees in ETH directly (simpler, but less intuitive pricing)

---

### ISSUE 5: Dead Fee Operations in Code (LOW)

**Problem:** `FeeSchedule` includes pricing for operations QPL no longer supports:
- `workflow_creation_base` / `workflow_step_base` (Settlement service removed)
- `yield_accrual_base` / `yield_mint_base` (Yield service removed)
- `rwa_registration_base` / `rwa_nav_update_base` (RWA service removed)

**Impact:** Unused code creates confusion. If these fee types are accidentally invoked, they charge for services that don't exist.

**Recommended fix:** Remove all fee types except `Sign`, `ProveSmallBatch`, `ProveLargeBatch`, and `VerifyProof` from both `FeeSchedule` and `FeeOperation` enum.

---

### ISSUE 6: No Fee Floor Protection (LOW)

**Problem:** The fee split math uses integer division:
```rust
let per_participant = participant_pool / participant_count as u64;
```

At very low fee amounts (e.g., 1,000 micro-USD split among 4 participants after coordinator/treasury shares), rounding truncation can result in participants receiving 0.

**Example:** Fee = 1,000, coordinator = 400, treasury = 100, pool = 500, split 4 ways = 125 each. This works. But at fee = 100 (hypothetical minimum): coordinator = 40, treasury = 10, pool = 50, split 4 ways = 12 each (with 2 dust). Below any meaningful compensation.

**Impact:** At minimum fee levels, participant compensation becomes negligible.

**Recommended fix:** Add a minimum total fee constant (e.g., `MIN_TOTAL_FEE = 1000`) that rejects quotes below the threshold.

---

## 6. Recommendations

### Immediate (Before Mainnet)

1. **Implement prepaid balance system** in QPLFeeRouter (fixes Issue 1 — gas erosion)
2. **Remove dead fee operations** from FeeSchedule and FeeOperation (fixes Issue 5)
3. **Extend quote expiry** to 300 seconds (fixes Issue 2)
4. **Add MIN_TOTAL_FEE guard** (fixes Issue 6)

### Pre-Launch (Genesis Phase)

5. **Define operator subsidy program** — quantify treasury outlay for 50 operators x 6 months of cost gap (~$41K)
6. **Decide fee denomination** — USDC payment option on QPLFeeRouter (fixes Issue 4)
7. **Model Genesis cohort** with reduced operator count (20-30) to improve unit economics

### Post-Launch (Year 1)

8. **Monitor blended fee and adjust** — if proving mix is lower than assumed, signing fees may need to increase to $0.002-$0.005
9. **Track operator churn** — if >20% monthly, fees are too low or costs too high
10. **Establish treasury reserve target** — 6 months of operating costs ($90K minimum) before expanding team

---

## 7. Summary Table

| Metric | Conservative | Base | Aggressive |
|--------|-------------|------|-----------|
| Year 1 revenue | $18K | $72K | $275K |
| Year 2 revenue | $151K | $744K | $5.1M |
| Year 3 revenue | $234K | $1.3M | $9.9M |
| Treasury break-even | Never | Month 30 | Month 12 |
| Operator break-even (daily reqs) | 4,800 | 4,800 | 4,800 |
| Pre-sustainability funding gap | $540K+ | $310K | $95K |
| Critical risk | Volume never materializes | Gas cost erosion | Fee compression from competitors |

---

*This projection is not financial advice. All figures are estimates based on assumed integration pipelines and market conditions. Actual results will vary based on DeFi market activity, integration velocity, and operator participation.*
