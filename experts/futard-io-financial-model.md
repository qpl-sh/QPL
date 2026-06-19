# QPL Financial Model — Futard.io Launch Optimization

**Date:** June 2026  
**Version:** 3.0 (Futard.io-optimized)  
**Status:** FINAL — Ready for launch structuring

---

## Executive Summary

**Optimal raise: $500K–$750K USDC on Futard.io**  
**Monthly budget: $42K–$62K**  
**Runway: 12–18 months to treasury self-sufficiency**  
**Path to profitability: Month 9–12 (Base scenario)**

This model optimizes for:
1. **Futard.io mechanics** — onchain monthly spending limits, futarchy governance
2. **1-year runway** — sufficient to hit treasury break-even + buffer
3. **Credible economics** — demonstrates clear path to sustainability for backers
4. **Operator viability** — ensures Genesis operators are profitable from day one

---

## 1. Futard.io Mechanism Analysis

### How Futard.io Works

**Key features:**
- **Raise range:** $10K – $2M USDC
- **Monthly spending limits:** Enforced onchain (team cannot drain treasury)
- **ICO window:** 1 hour – 7 days (time-weighted allocation rewards early backers)
- **Cost to launch:** 0.5 SOL (~$35)
- **Legal entity:** Cayman Islands via MetaLeX (5 minutes, automated)
- **Governance:** Turnkey DAO on metadao.fi with futarchy decision markets
- **Rug protection:** Spending limits + market-based governance (not team control)

**Critical constraint:** Monthly spending limits are set by the team at launch and enforced onchain. Once the raise completes, the team can only access funds up to the monthly limit. Excess spending requires market approval via futarchy.

**Implication for QPL:**
- Set monthly limit to match operating budget ($42K–$62K)
- Raise enough to cover 12–18 months at that burn rate
- Demonstrates fiscal discipline to backers (can't rug, can't overspend)

---

## 2. Optimal Raise Amount

### Scenario Analysis

| Raise Amount | Monthly Budget | Runway | Risk Profile | Backer Perception |
|--------------|----------------|--------|--------------|-------------------|
| $250K | $21K/mo | 12 months | Too lean — no buffer | "Underfunded, might fail" |
| $500K | $42K/mo | 12 months | Tight but viable | "Lean, disciplined" |
| $750K | $62K/mo | 12 months | Comfortable | "Well-capitalized" |
| $1M | $83K/mo | 12 months | Overfunded | "Why do they need this much?" |
| $500K | $28K/mo | 18 months | Conservative | "Slow burn, low risk" |
| $750K | $42K/mo | 18 months | **Optimal** | "Right-sized" |

### Recommendation: **$500K–$750K USDC**

**Why not $1M?**
- Futard.io backers are sophisticated — they'll question why you need $1M when your financial model shows $45K funding gap
- Higher raise = higher monthly spend expectation from community
- Diminishing returns: $750K gives you 18 months runway, $1M only gives you 24 months (6 more months for 33% more dilution)
- Futard.io's $2M max is a ceiling, not a target

**Why not $250K?**
- Too close to the $45K funding gap — no room for error
- If testnet deployment slips 2-3 months, you're insolvent before treasury break-even
- Signals undercapitalization to backers

**Sweet spot: $750K at $42K/month = 18 months runway**

This gives you:
- 12 months to hit treasury break-even (Base scenario)
- 6 months buffer for delays, market downturns, or slower adoption
- Credible story: "We're raising 18 months of runway to reach self-sufficiency"

---

## 3. Monthly Budget Breakdown

### Lean Budget ($42K/month) — Conservative

| Category | Monthly | Annual | Notes |
|----------|---------|--------|-------|
| **Team (2 founders, part-time)** | $16,000 | $192,000 | $8K each — below-market, skin-in-the-game |
| **Infrastructure** | $5,000 | $60,000 | RPC nodes, monitoring, testnet SOL, CI/CD |
| **Security audits** | $4,000 | $48,000 | 1 major audit/year + quarterly reviews |
| **Legal/compliance** | $3,000 | $36,000 | On-retainer counsel, regulatory filings |
| **Marketing/BD** | $8,000 | $96,000 | Content, partnerships, conference travel |
| **Miscellaneous** | $6,000 | $72,000 | Tooling, domains, unexpected costs |
| **Total** | **$42,000** | **$504,000** | |

**Runway at $42K/month:**
- $500K raise → 12 months
- $750K raise → 18 months

### Growth Budget ($62K/month) — Aggressive

| Category | Monthly | Annual | Notes |
|----------|---------|--------|-------|
| **Team (2 founders + 1 contractor)** | $28,000 | $336,000 | $10K each + $8K contractor |
| **Infrastructure** | $8,000 | $96,000 | Production nodes, redundancy, monitoring |
| **Security audits** | $5,000 | $60,000 | 2 major audits/year + continuous |
| **Legal/compliance** | $4,000 | $48,000 | Enhanced regulatory work |
| **Marketing/BD** | $12,000 | $144,000 | Aggressive BD, sponsorships, events |
| **Miscellaneous** | $5,000 | $60,000 | Buffer |
| **Total** | **$62,000** | **$744,000** | |

**Runway at $62K/month:**
- $750K raise → 12 months
- $1M raise → 16 months

### Recommendation: **Start at $42K/month, scale to $62K after first 3 anchor clients**

This demonstrates fiscal discipline early, then ramps spend once revenue validates the model.

---

## 4. Path to Profitability

### Treasury Break-Even Analysis

From the existing financial model (`financial-projection-3yr.md`):

**Treasury receives 10% of all fees.**  
**Monthly operating cost: $42K (lean) or $62K (growth)**

**Required monthly fee volume:**
- Lean: $42K / 0.10 = $420K/month in fees
- Growth: $62K / 0.10 = $620K/month in fees

**Required daily volume (at $0.12 blended avg fee):**
- Lean: $420K / 30 / $0.12 = **117K requests/day**
- Growth: $620K / 30 / $0.12 = **172K requests/day**

### Timeline to Break-Even

| Scenario | Month | Daily Volume | Treasury Income | Operating Cost | Net |
|----------|-------|--------------|-----------------|----------------|-----|
| **Conservative** | 6 | 30K | $67.5K | $42K | +$25.5K |
| **Conservative** | 9 | 67K | $150K | $42K | +$108K |
| **Base** | 6 | 120K | $270K | $42K | +$228K |
| **Base** | 9 | 300K | $675K | $42K | +$633K |
| **Aggressive** | 3 | 150K | $337K | $42K | +$295K |
| **Aggressive** | 6 | 600K | $1.35M | $42K | +$1.31M |

**Key insight:** In the Base scenario, treasury is self-sufficient by **Month 6** (120K requests/day). In Conservative, by **Month 9** (67K requests/day).

### Cumulative Cash Flow (Lean Budget, $750K Raise)

| Month | Treasury Income | Operating Cost | Net Cash Flow | Cumulative |
|-------|-----------------|----------------|---------------|------------|
| 0 | $0 | $0 | $0 | $750,000 |
| 1 | $0 | $42K | -$42K | $708,000 |
| 2 | $0 | $42K | -$42K | $666,000 |
| 3 | $27K | $42K | -$15K | $651,000 |
| 4 | $67K | $42K | +$25K | $676,000 |
| 5 | $135K | $42K | +$93K | $769,000 |
| 6 | $270K | $42K | +$228K | $997,000 |
| 7 | $405K | $42K | +$363K | $1,360,000 |
| 8 | $540K | $42K | +$498K | $1,858,000 |
| 9 | $675K | $42K | +$633K | $2,491,000 |
| 10 | $810K | $42K | +$768K | $3,259,000 |
| 11 | $945K | $42K | +$903K | $4,162,000 |
| 12 | $1,080K | $42K | +$1,038K | $5,200,000 |

*Assumes Base scenario volume growth (20K → 1.2M requests/day over 12 months)*

**Result:** By Month 12, treasury has **$5.2M cumulative** — far exceeding the initial $750K raise. The protocol is profitable and self-sustaining.

---

## 5. Futard.io Launch Structure

### Recommended Tokenomics

**Total token supply:** 100M QPL  
**ICO allocation:** 15M tokens (15%)  
**Performance package:** 5M tokens (5%) — rewards for hitting milestones  
**Liquidity:** 3M tokens (3%) — initial DEX liquidity  
**Team:** 20M tokens (20%) — 2-year vest, 6-month cliff  
**Treasury/DAO:** 57M tokens (57%) — governed by token holders

**Raise amount:** $750K USDC  
**ICO price:** $0.05/token  
**FDV at ICO:** $5M (100M tokens × $0.05)  
**Performance package:** 5M tokens released on milestone achievement

### Monthly Spending Limit

**Set at launch:** $42,000/month (lean budget)  
**Enforced onchain:** Team cannot exceed this without market approval  
**Duration:** 18 months (covers full runway)

**After 18 months:**
- If treasury is self-sufficient, spending limit can be increased via governance
- If not, team must demonstrate progress or seek additional funding

### Milestone-Based Performance Package

The 5M performance tokens are released on milestone achievement:

| Milestone | Tokens Released | Trigger |
|-----------|----------------|---------|
| Testnet deployment + 3 anchor clients | 1M tokens | 3 protocols integrated on testnet |
| Mainnet launch + 10 protocols | 1.5M tokens | 10 protocols live on mainnet |
| $100K/month treasury income | 1.5M tokens | Treasury generating $100K/month |
| 50 active operators | 1M tokens | 50 operators staked and active |

**Total:** 5M tokens over 12–18 months

---

## 6. Risk Analysis

### What Could Go Wrong

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Slow adoption** — only 1-2 protocols integrate in Year 1 | 30% | High — treasury never breaks even | Focus on 3 anchor clients pre-launch, offer free integration support |
| **Operator churn** — operators leave because economics don't work | 20% | Medium — network reliability suffers | Curated Genesis (15 operators), ensure 2,300+ requests/operator/day |
| **Competitor entry** — Fireblocks/Lit launch post-quantum product | 40% | Medium — fee compression | First-mover advantage, open-source trust, NIST standards alignment |
| **Regulatory action** — SEC classifies QPL as security | 10% | High — legal costs explode, raise fails | Cayman entity, utility token framing, no profit promises |
| **Technical failure** — critical bug in staking/fee router | 15% | High — loss of funds, reputation damage | 3 audits before mainnet, bug bounty program, insurance fund |

### Worst-Case Scenario

**Assumptions:**
- Only 1 protocol integrates in Year 1 (10K requests/day)
- Operator churn at 30% (15 → 10 operators)
- Monthly burn at $42K
- No additional funding

**Outcome:**
- Month 12 cumulative: $750K - ($42K × 12) + $22.5K treasury = **$278.5K remaining**
- Month 18 cumulative: $750K - ($42K × 18) + $67.5K treasury = **$58.5K remaining**
- Month 24: **Insolvent** unless additional funding raised

**Mitigation:**
- $750K raise at $42K/month gives 18 months runway
- If only 1 protocol integrates by Month 12, pivot to service model (consulting, custom integrations)
- Raise bridge round at Month 12 if traction but not yet profitable

---

## 7. Comparison to Alternatives

### Futard.io vs. Traditional VC

| Factor | Futard.io ($750K) | Seed VC ($2M @ $10M cap) |
|--------|-------------------|--------------------------|
| **Dilution** | 15% (ICO tokens) | 20% (equity) |
| **Control** | DAO governance (team still controls development) | Board seat, veto rights |
| **Speed** | 1-2 weeks (permissionless) | 3-6 months (due diligence) |
| **Reporting** | Onchain transparency (automatic) | Quarterly board decks |
| **Community** | Instant token holder base (aligned) | No community benefit |
| **Risk** | Monthly spending limits (can't overspend) | Full control, but pressure to over-hire |
| **Reputation** | "Crypto-native, decentralized" | "TradFi validated" |

**Recommendation:** Futard.io is the right choice for QPL because:
1. **Aligned incentives** — token holders want the protocol to succeed, not an exit
2. **Onchain discipline** — spending limits prevent over-hiring/burn
3. **Instant community** — 100-500 token holders become evangelists
4. **Speed** — raise in weeks, not months
5. **Narrative** — "Permissionless infrastructure raised permissionlessly"

### Futard.io vs. Pump.fun

| Factor | Futard.io | Pump.fun |
|--------|-----------|----------|
| **Raise size** | $10K – $2M | Typically $50K – $500K |
| **Governance** | Futarchy (market-based) | None (pure speculation) |
| **Spending controls** | Onchain monthly limits | None |
| **Legal entity** | Cayman Islands via MetaLeX | None |
| **Target** | Real projects with utility | Memecoins, speculation |
| **Reputation** | "Serious infrastructure" | "Degen casino" |

**Recommendation:** Futard.io is the only viable option for QPL. Pump.fun is for memecoins, not post-quantum infrastructure.

---

## 8. Final Recommendation

### Raise: **$750K USDC on Futard.io**

**Token allocation:**
- ICO: 15M tokens (15%) at $0.05/token
- Performance: 5M tokens (5%) on milestones
- Liquidity: 3M tokens (3%)
- Team: 20M tokens (20%) — 2-year vest, 6-month cliff
- Treasury: 57M tokens (57%)

**Monthly budget:** $42,000/month (lean)  
**Monthly spending limit:** $42,000 (onchain enforced)  
**Runway:** 18 months

**Path to profitability:**
- Month 6: Treasury break-even (Base scenario, 120K requests/day)
- Month 12: $5.2M cumulative treasury (Base scenario)
- Month 18: Self-sustaining, can increase spend via governance

**Use of funds:**
- 40% — Team (founders + contractors)
- 20% — Infrastructure (nodes, monitoring, testnet)
- 15% — Security (audits, bug bounty)
- 15% — Marketing/BD (content, partnerships, events)
- 10% — Legal/compliance

**Success criteria:**
- 3 anchor protocols integrated by Month 6
- 10 protocols live by Month 12
- 50 active operators by Month 12
- $100K/month treasury income by Month 9

---

## 9. Next Steps

1. **Finalize tokenomics** — confirm 100M supply, 15% ICO, 5% performance
2. **Set up Cayman entity** — via MetaLeX on Futard.io (5 minutes)
3. **Build landing page** — already live at https://nice-euclid-6.preview.emergentagent.com/
4. **Deploy to testnet** — use `scripts/testnet-deploy.sh` + `yarn test:testnet`
5. **Launch on Futard.io** — pay 0.5 SOL, fill out 7-step form, go live
6. **Market the raise** — leverage token holder community, crypto Twitter, DeFi forums

**Timeline:**
- Week 1: Testnet deployment + smoke tests
- Week 2: Entity setup + Futard.io launch prep
- Week 3: Launch on Futard.io, 7-day ICO window
- Week 4: Funds released, begin execution

---

*This model is not financial advice. All figures are estimates based on assumed integration pipelines and market conditions. Actual results will vary based on DeFi market activity, integration velocity, and operator participation.*
