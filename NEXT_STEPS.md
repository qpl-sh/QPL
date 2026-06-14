# QPL Next Steps — Testnet Deployment Handoff

**Date:** 2026-06-14  
**Status:** Repo audit complete, testnet infrastructure ready, awaiting Mac deployment

---

## What's Been Completed (Windows Session)

### Repo Audit & Cleanup
- ✅ Removed 5 bloat docs (42KB, 964 lines of historical/meta content)
- ✅ Updated CISO security checklist — all 16 items verified for testnet
- ✅ Fixed cargo-deny v2 schema (licenses, advisories, unmaintained deps)
- ✅ All 255 tests passing, cargo fmt/clippy clean

### CI/CD Pipeline
- ✅ Fixed protoc fallback (pre-generated proto code committed)
- ✅ Fixed cargo-deny config (v2 migration, license allow list)
- ✅ Fixed cargo fmt issues in generated code
- ✅ All CI checks passing (build, test, fmt, deny)

### Testnet Infrastructure
- ✅ Created `scripts/testnet-deploy.sh` — automated deployment script
- ✅ Created `tests/solana/testnet-smoke.ts` — 12-step smoke test suite
- ✅ Added npm scripts: `yarn test:testnet`, `yarn deploy:testnet`
- ✅ Gitignored `program-keypairs/` and deploy logs

---

## What Needs to Happen (Mac Session)

### Prerequisites Check
```bash
# Verify tools installed
solana --version      # Should be 1.18+ or latest
anchor --version      # Should be 0.30+
cargo --version       # Should be 1.70+
node --version        # Should be 18+
yarn --version        # Should be 1.22+
```

If missing:
```bash
# Install Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --force

# Install Node/Yarn (if needed)
brew install node
npm install -g yarn
```

### Step 1: Clone Repo on Mac
```bash
git clone https://github.com/jnodes/QPL.git
cd QPL/qpl
```

### Step 2: Configure for Testnet
```bash
solana config set --url https://api.testnet.solana.com
solana config get  # Verify RPC URL is testnet
```

### Step 3: Fund Wallet
```bash
# Check current balance
solana balance

# Request airdrops (repeat until you have 12+ SOL)
solana airdrop 2
solana airdrop 2
solana airdrop 2
# ... continue as needed (rate-limited, may need to wait)

# Alternative: Use testnet faucet
# https://faucet.solana.com/
```

**SOL Requirements:**
- Single operator test: ~12 SOL
- 3-operator test (realistic): ~35 SOL
- All SOL is free on testnet via airdrops

### Step 4: Deploy Programs
```bash
chmod +x scripts/testnet-deploy.sh
./scripts/testnet-deploy.sh
```

This will:
- Generate program keypairs (stored in `program-keypairs/`, gitignored)
- Update program IDs in source code
- Build all 3 programs (~5-10 min first build)
- Deploy to testnet
- Output explorer links for verification

**Expected output:**
```
Program IDs:
  qpl-staking:    <address>
  qpl-fee-router: <address>
  qpl-registry:   <address>

Verify on explorer:
  https://explorer.solana.com/address/<address>?cluster=testnet
```

### Step 5: Install Dependencies
```bash
yarn install
```

### Step 6: Run Smoke Tests
```bash
yarn test:testnet
```

Or with anchor directly:
```bash
anchor test --provider.cluster testnet -- tests/solana/testnet-smoke.ts
```

**Expected:** 12 tests passing, each logging a transaction signature.

### Step 7: Verify on Explorer
Copy any tx signature from the test output and verify at:
```
https://explorer.solana.com/tx/<signature>?cluster=testnet
```

---

## Troubleshooting

### "Airdrop failed"
Testnet rate-limits airdrops. Wait 5-10 minutes and retry, or use the web faucet:
https://faucet.solana.com/

### "Program ID mismatch"
If you get "Account not found" errors, the program IDs in source don't match deployed programs. Re-run:
```bash
./scripts/testnet-deploy.sh
```

### "Build failed"
First build takes 5-10 minutes. If it fails:
```bash
cargo clean
anchor build
```

### "Insufficient SOL"
Check balance and airdrop more:
```bash
solana balance
solana airdrop 2
```

---

## Success Criteria

After completing all steps, you should have:

1. ✅ 3 programs deployed to Solana testnet
2. ✅ 12 transaction signatures from smoke tests
3. ✅ Verified txs on Solana Explorer
4. ✅ Proof-of-life for Futard.io launch page

**Save these tx signatures** — they're your verifiable proof that QPL is live and tested on Solana testnet.

---

## After Testnet Success

### For Futard.io
- Screenshot the explorer links showing deployed programs
- List the tx signatures as "verified testnet transactions"
- Reference the audit report (`qpl security audit report v0.3.md`)

### For Genesis Operators
- Share the testnet program addresses
- Point to OPERATOR_ONBOARDING.md for setup instructions
- Genesis slots: 7/15 filled (update as needed)

### Next Development Phase
- Implement real ML-DSA threshold signing (currently software-only)
- Add HSM integration for Ed25519/ECDSA (PKCS#11)
- Build operator node binary with gRPC services
- Create SDK documentation and integration guides

---

## Quick Reference

**Repo:** https://github.com/jnodes/QPL  
**Testnet Explorer:** https://explorer.solana.com/?cluster=testnet  
**Solana Faucet:** https://faucet.solana.com/  
**Anchor Docs:** https://www.anchor-lang.com/

**Key Files:**
- `scripts/testnet-deploy.sh` — Deployment automation
- `tests/solana/testnet-smoke.ts` — Smoke test suite
- `experts/ciso-security-officer.md` — Security checklist
- `OPERATOR_ONBOARDING.md` — Operator setup guide
- `WHITEPAPER.md` — Technical documentation

---

**Last updated:** 2026-06-14  
**Next action:** Deploy to testnet on Mac
