# QPL Operator Economics

Overview of operator economics, fee distribution, and profitability analysis.

---

## Fee Schedule

| Operation | Base Fee | With 3-of-5 Quorum | With Instant Urgency |
|-----------|----------|--------------------|----------------------|
| Threshold signature | $0.025 | $0.075 | $0.150 |
| STARK proof (small, ≤100 tx) | $1.00 | $3.00 | $6.00 |
| STARK proof (large, >100 tx) | $2.50 | $7.50 | $15.00 |
| Proof verification | $0.025 | $0.075 | $0.150 |

## Fee Distribution

| Recipient | Share | Per $0.075 signing | Per $3.00 proving |
|-----------|-------|--------------------|--------------------|
| Coordinator | 40% | $0.030 | $1.20 |
| Participants (2) | 50% | $0.01875 each | $0.75 each |
| Treasury | 10% | $0.0075 | $0.30 |

## Operator Costs

| Cost Item | Monthly per Operator |
|-----------|---------------------|
| HSM hardware (amortized) | $1,000 |
| Compute (VPS/cloud) | $200 |
| Bandwidth | $50 |
| SOL stake opportunity cost (10 SOL) | $34 |
| DevOps/monitoring | $50 |
| **Total** | **$1,334/month** |

## Break-Even Analysis

**As participant** (50% of signing fee split 2 ways):
- Per-request revenue: $0.01875
- Break-even: ~71,147 requests/month = **~2,371 requests/day**

**As coordinator** (40% of signing fee):
- Per-request revenue: $0.030
- Break-even: ~44,467 requests/month = **~1,482 requests/day**

**Blended** (20% coordinator, 80% participant):
- Blended per-request: $0.021
- Break-even: ~63,524 requests/month = **~2,118 requests/day**

**With proving mix** (80% signing, 20% proving):
- Blended per-request: $0.1668
- Break-even: ~7,986 requests/month = **~266 requests/day**

## Operator Revenue at Scale

| Network Daily Volume | Operators | Requests/Operator/Day | Monthly Revenue | Net After Costs |
|---------------------|-----------|----------------------|-----------------|-----------------|
| 10,000 | 10 | 1,000 | $630 | -$704 (LOSS) |
| 50,000 | 15 | 3,333 | $2,100 | +$766 |
| 100,000 | 20 | 5,000 | $3,150 | +$1,816 |
| 200,000 | 25 | 8,000 | $5,040 | +$3,706 |
| 500,000 | 50 | 10,000 | $6,300 | +$4,966 |

## Staking Requirements

- **Minimum stake:** 10 SOL (~$680 at $68/SOL)
- **Unbonding period:** 7 days
- **Slashable offenses:** equivocation, invalid signatures, invalid proofs, liveness failure
- **Slash dispute window:** 24 hours

## Genesis Operator Program

- **Curated set:** 15-20 operators at launch
- **Target:** Maintain >$2,000/month revenue per operator
- **Governance:** Operator count managed to ensure economic viability

## Key Insights

1. **Operator economics are viable from early Genesis phase** at 50K+ daily requests across 15 operators
2. **Proving dramatically improves economics** — even 20% proving mix reduces break-even to ~266 requests/day
3. **Fee increase from $0.001 to $0.025** (25×) made operator economics sustainable
4. **Treasury self-sufficiency** requires ~67K requests/day (10% treasury share covers $15K/month operating costs)

---

*For detailed financial projections, see the [QPL Whitepaper](./WHITEPAPER.md) Section 8: Fee Economics.*
