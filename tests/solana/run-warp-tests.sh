#!/bin/bash
# QPL Warp-Time Test Orchestrator
# =============================================================================
# Phase 1: Run extended-test.ts on normal validator (setup + initiate unstake/slash)
# Phase 2: Restart validator with --warp-slot and run warp-test.ts (execute slash + withdraw)
# =============================================================================

# Don't use set -e: mocha returns non-zero on test failures which we handle

QPL_DIR="/Users/evangelinachumaceiro/Downloads/qpl/QPL"
WALLET="$HOME/.config/solana/id.json"
LOCAL_URL="http://localhost:8899"
MOCHA_CMD="$QPL_DIR/node_modules/.bin/ts-mocha -p ./tsconfig.json -t 1000000"

echo "============================================================"
echo "  QPL WARP-TIME TEST ORCHESTRATOR"
echo "============================================================"

# Kill any existing validator
pkill -f solana-test-validator 2>/dev/null || true
sleep 1

# ── PHASE 1 ────────────────────────────────────────────────────────────────
echo ""
echo "▸ Phase 1: Starting fresh validator..."
solana-test-validator --reset --quiet &
VALIDATOR_PID=$!
sleep 5

solana config set --url localhost > /dev/null 2>&1
echo "  Validator running (PID: $VALIDATOR_PID)"

echo ""
echo "▸ Deploying programs..."
cd "$QPL_DIR"
cp programs/qpl-staking/target/deploy/qpl_staking.so target/deploy/
cp programs/qpl-fee-router/target/deploy/qpl_fee_router.so target/deploy/
cp programs/qpl-registry/target/deploy/qpl_registry.so target/deploy/
anchor deploy --provider.cluster localnet 2>&1 | grep -E "(Deploy success|Error)"

echo ""
echo "▸ Running extended test suite (Phase 1)..."
ANCHOR_PROVIDER_URL=$LOCAL_URL ANCHOR_WALLET=$WALLET \
  $MOCHA_CMD tests/solana/extended-test.ts 2>&1

PHASE1_EXIT=$?
if [ $PHASE1_EXIT -ne 0 ]; then
  echo "✗ Phase 1 failed with exit code $PHASE1_EXIT"
  kill $VALIDATOR_PID 2>/dev/null || true
  exit $PHASE1_EXIT
fi

# Verify state file was written
if [ ! -f /tmp/qpl-warp-state.json ]; then
  echo "✗ State file not found at /tmp/qpl-warp-state.json"
  kill $VALIDATOR_PID 2>/dev/null || true
  exit 1
fi

echo ""
echo "▸ Phase 1 complete. Stopping validator..."
kill $VALIDATOR_PID 2>/dev/null || true
wait $VALIDATOR_PID 2>/dev/null || true
sleep 2

# ── PHASE 2 ────────────────────────────────────────────────────────────────
echo ""
echo "▸ Phase 2: Starting warped validator (slot +3,000,000 ~14 days)..."
solana-test-validator --reset --quiet --warp-slot 3000000 &
VALIDATOR_PID=$!
sleep 6

solana config set --url localhost > /dev/null 2>&1
echo "  Validator running (PID: $VALIDATOR_PID, slot: $(solana slot --url localhost 2>/dev/null))"

echo ""
echo "▸ Deploying programs..."
anchor deploy --provider.cluster localnet 2>&1 | grep -E "(Deploy success|Error)"

# Re-run extended-test.ts to recreate state (init config, stake, initiate unstake+slash)
echo ""
echo "▸ Re-creating state on warped validator..."
ANCHOR_PROVIDER_URL=$LOCAL_URL ANCHOR_WALLET=$WALLET \
  $MOCHA_CMD tests/solana/extended-test.ts 2>&1

echo ""
echo "▸ Running warp-time tests (Phase 2)..."
ANCHOR_PROVIDER_URL=$LOCAL_URL ANCHOR_WALLET=$WALLET \
  $MOCHA_CMD tests/solana/warp-test.ts 2>&1

PHASE2_EXIT=$?

echo ""
echo "▸ Cleaning up..."
kill $VALIDATOR_PID 2>/dev/null || true
solana config set --url devnet > /dev/null 2>&1

if [ $PHASE2_EXIT -eq 0 ]; then
  echo ""
  echo "============================================================"
  echo "  ✓ ALL TESTS PASSED (Phase 1 + Phase 2)"
  echo "============================================================"
else
  echo ""
  echo "✗ Phase 2 failed with exit code $PHASE2_EXIT"
fi

exit $PHASE2_EXIT
