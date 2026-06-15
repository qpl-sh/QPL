#!/bin/bash
# =============================================================================
# QPL Testnet Deployment Script
# =============================================================================
# Deploys all 3 Anchor programs to Solana testnet.
#
# Prerequisites:
#   - solana CLI installed and configured for testnet
#   - Anchor CLI installed
#   - Funded wallet at ~/.config/solana/id.json (needs ~2 SOL for deployment)
#   - Rust toolchain (for building programs)
#
# Usage:
#   chmod +x scripts/testnet-deploy.sh
#   ./scripts/testnet-deploy.sh
#
# What it does:
#   1. Generates program keypairs (if not already present)
#   2. Builds all programs
#   3. Updates program IDs in source and Anchor.toml
#   4. Deploys to Solana testnet
#   5. Logs deployment tx signatures for proof-of-life
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KEYPAIRS_DIR="$PROJECT_DIR/program-keypairs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[QPL DEPLOY]${NC} $1"; }
success() { echo -e "${GREEN}[QPL DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[QPL DEPLOY]${NC} $1"; }
error() { echo -e "${RED}[QPL DEPLOY]${NC} $1"; exit 1; }

# -----------------------------------------------------------------------------
# Step 0: Pre-flight checks
# -----------------------------------------------------------------------------
log "Running pre-flight checks..."

command -v solana >/dev/null 2>&1 || error "solana CLI not found. Install: sh -c \"\$(curl -sSfL https://release.anza.xyz/stable/install)\""
command -v anchor >/dev/null 2>&1 || error "anchor CLI not found. Install: cargo install --git https://github.com/coral-xyz/anchor avm --force && avm install latest && avm use latest"
command -v cargo >/dev/null 2>&1 || error "cargo not found. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"

# Ensure testnet cluster
solana config set --url https://api.testnet.solana.com 2>/dev/null
CLUSTER=$(solana config get | grep "RPC URL" | awk '{print $3}')
log "Cluster: $CLUSTER"

# Check wallet balance
WALLET=$(solana config get | grep "Keypair Path" | awk '{print $3}')
WALLET="${WALLET/#\~/$HOME}"
if [ ! -f "$WALLET" ]; then
    warn "No wallet found at $WALLET. Generating new keypair..."
    solana-keygen new --outfile "$WALLET" --no-passphrase
fi

BALANCE=$(solana balance | awk '{print $1}')
log "Wallet: $(solana address)"
log "Balance: ${BALANCE} SOL"

# Check minimum balance (need ~2 SOL for 3 program deployments)
BALANCE_LAMPORTS=$(solana balance --lamports | awk '{print $1}')
if [ "$BALANCE_LAMPORTS" -lt 2000000000 ]; then
    warn "Balance below 2 SOL. Requesting airdrop..."
    solana airdrop 2 2>/dev/null || warn "Airdrop failed (testnet rate-limited?). Fund wallet manually."
fi

# -----------------------------------------------------------------------------
# Step 1: Generate program keypairs
# -----------------------------------------------------------------------------
log "Checking program keypairs..."
mkdir -p "$KEYPAIRS_DIR"

for prog in qpl-staking qpl-fee-router qpl-registry; do
    KEYFILE="$KEYPAIRS_DIR/${prog}.json"
    if [ ! -f "$KEYFILE" ]; then
        log "Generating keypair for $prog..."
        solana-keygen new --outfile "$KEYFILE" --no-passphrase
        success "  Created $KEYFILE"
    else
        success "  $prog keypair exists"
    fi
done

# -----------------------------------------------------------------------------
# Step 2: Extract program IDs and update source
# -----------------------------------------------------------------------------
log "Updating program IDs in source code..."

STAKING_ID=$(solana-keygen pubkey "$KEYPAIRS_DIR/qpl-staking.json")
FEE_ID=$(solana-keygen pubkey "$KEYPAIRS_DIR/qpl-fee-router.json")
REGISTRY_ID=$(solana-keygen pubkey "$KEYPAIRS_DIR/qpl-registry.json")

success "  qpl-staking:    $STAKING_ID"
success "  qpl-fee-router: $FEE_ID"
success "  qpl-registry:   $REGISTRY_ID"

# Update declare_id! in each program
sed -i '' "s/declare_id!(\"[^\"]*\")/declare_id!(\"$STAKING_ID\")/" "$PROJECT_DIR/programs/qpl-staking/src/lib.rs"
sed -i '' "s/declare_id!(\"[^\"]*\")/declare_id!(\"$FEE_ID\")/" "$PROJECT_DIR/programs/qpl-fee-router/src/lib.rs"
sed -i '' "s/declare_id!(\"[^\"]*\")/declare_id!(\"$REGISTRY_ID\")/" "$PROJECT_DIR/programs/qpl-registry/src/lib.rs"

# Update Anchor.toml
cd "$PROJECT_DIR"
# Use python for reliable TOML update (sed is fragile with TOML sections)
python3 -c "
import re
with open('Anchor.toml', 'r') as f:
    content = f.read()
content = re.sub(
    r'(\[programs\.testnet\]\n)(qpl_staking = \")[^\"]*(\")\n(qpl_fee_router = \")[^\"]*(\")\n(qpl_registry = \")[^\"]*(\")',
    r'\1\2${STAKING_ID}\3\n\4${FEE_ID}\5\n\6${REGISTRY_ID}\7',
    content
)
with open('Anchor.toml', 'w') as f:
    f.write(content)
" 2>/dev/null || warn "Could not auto-update Anchor.toml — update [programs.testnet] section manually"

# -----------------------------------------------------------------------------
# Step 3: Build programs
# -----------------------------------------------------------------------------
log "Building programs (this may take a few minutes)..."
cd "$PROJECT_DIR"
anchor build
success "Build complete"

# -----------------------------------------------------------------------------
# Step 4: Deploy to testnet
# -----------------------------------------------------------------------------
log "Deploying to Solana testnet..."
DEPLOY_LOG="$PROJECT_DIR/scripts/deploy-$(date +%Y%m%d-%H%M%S).log"

anchor deploy --provider.cluster testnet 2>&1 | tee "$DEPLOY_LOG"

# Extract program IDs from deploy output
success ""
success "============================================"
success "  DEPLOYMENT COMPLETE"
success "============================================"
success ""
success "Program IDs:"
success "  qpl-staking:    $STAKING_ID"
success "  qpl-fee-router: $FEE_ID"
success "  qpl-registry:   $REGISTRY_ID"
success ""
success "Verify on explorer:"
success "  https://explorer.solana.com/address/$STAKING_ID?cluster=testnet"
success "  https://explorer.solana.com/address/$FEE_ID?cluster=testnet"
success "  https://explorer.solana.com/address/$REGISTRY_ID?cluster=testnet"
success ""
success "Deploy log: $DEPLOY_LOG"
success ""
success "Next step: Run smoke tests"
success "  yarn install (if not done)"
success "  anchor test --provider.cluster testnet -- tests/solana/testnet-smoke.ts"
