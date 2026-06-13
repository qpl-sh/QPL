# QPL Operator Onboarding Guide

This guide walks you through setting up and running a QPL operator node. Operators provide quantum-resistant signing and proving infrastructure to the network and earn service fees for computational work performed.

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Storage | 50 GB SSD | 100 GB NVMe SSD |
| Network | 100 Mbps, <50ms to Solana validators | 1 Gbps, <10ms |
| HSM | PKCS#11 compatible (SoftHSM2 for testing) | Thales Luna 7, AWS CloudHSM |

### Software Requirements

- **OS:** Ubuntu 22.04 LTS or Debian 12 (other Linux distros may work)
- **Rust:** 1.78+ (install via [rustup](https://rustup.rs))
- **Solana CLI:** 1.18+ (for staking and program interaction)
- **Docker:** 24.0+ (if running via containers)
- **Git:** 2.30+

---

## Step 1: Build the QPL Node

```bash
git clone https://github.com/jnodes/QPL.git
cd QPL

# Build the release binary
cargo build --release -p qpl-node

# The binary will be at: target/release/qpl-node
```

Or use Docker:

```bash
docker build -f services/qpl-node/Dockerfile -t qpl-node .
```

---

## Step 2: Generate Operator Identity

Each operator needs a unique identity keypair. Generate one with:

```bash
./target/release/qpl-node --generate-identity
```

This outputs:
```
Operator identity generated:
  ID:         <hex-encoded operator ID>
  Public key: 32 bytes

Save the identity file and configure qpl-node.toml with the path.
```

**Important:** Back up the identity file securely. Loss of this file means loss of your operator identity and staked funds.

---

## Step 3: Stake SOL

Operators must stake a minimum of **10 SOL** (~$680 at $68/SOL) as a security deposit. This collateral ensures honest behavior — operators who violate protocol rules (downtime, malformed responses) can be slashed.

### Using Solana CLI

```bash
# Ensure you have at least 11 SOL (10 SOL stake + fees)
solana balance

# Transfer to the staking program
# (Use the QPL SDK or CLI once available, or interact with the program directly)
```

### Staking Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Minimum stake | 10 SOL (~$680 at $68/SOL) | Security deposit |
| Unbonding period | 7 days | After initiating unstake |
| Slashing | Governance-controlled | For protocol violations |

---

## Step 4: Configure the Node

Edit `qpl-node.toml` (or create one from the template):

```toml
# Node identity
name = "my-qpl-operator"
listen_addr = "0.0.0.0:9000"
identity_path = "/path/to/identity.json"

# Solana RPC endpoint
solana_rpc = "http://localhost:8899"  # or https://api.mainnet-beta.solana.com

# gRPC configuration
[grpc]
max_concurrent_streams = 100
max_message_size = 4_194_304
keepalive_interval_secs = 30

# TLS configuration (REQUIRED for production)
[tls]
server_cert = "/path/to/server.crt"
server_key = "/path/to/server.key"
# client_ca_path = "/path/to/ca.crt"  # Enable for mTLS

# Operator configuration
[operator]
heartbeat_interval_secs = 30
max_missed_heartbeats = 3
supported_signing_algorithms = ["Ed25519", "ECDSA-P256", "ML-DSA-65"]

# Fee configuration (in USD micro-units)
[fees]
signing_base = 25_000              # $0.025
proving_small_base = 1_000_000     # $1.00
proving_large_base = 2_500_000     # $2.50
verification_base = 25_000         # $0.025

# Rate limiting
[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
```

---

## Step 5: Configure HSM (Optional but Recommended)

For production, signing keys should be wrapped inside an HSM. QPL supports PKCS#11-compatible HSMs.

### SoftHSM2 (Testing)

```bash
# Install SoftHSM2
sudo apt-get install softhsm2

# Initialize a token
softhsm2-util --init-token --slot 0 --label "qpl-operator" --pin 1234 --so-pin 5678

# Configure the PKCS#11 module path in qpl-node.toml
# [hsm]
# pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so"
# slot = 0
# pin = "1234"
```

### Production HSMs

| HSM | PKCS#11 Module | Notes |
|-----|----------------|-------|
| Thales Luna 7 | `/usr/safenet/protecttoolkit5/ptkcs11/lib/libcryptoki.so` | FIPS 140-2 Level 3 |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | Cloud-based, FIPS 140-2 Level 3 |
| YubiHSM 2 | `/usr/lib/libykp11.so` | Low-cost, FIPS 140-2 Level 3 |

---

## Step 6: Start the Node

### Direct Binary

```bash
./target/release/qpl-node --config /path/to/qpl-node.toml
```

### Docker

```bash
docker run -d \
  --name qpl-operator \
  -p 9000:9000 \
  -v /path/to/qpl-node.toml:/qpl/qpl-node.toml:ro \
  -v /path/to/identity.json:/qpl/data/identity.json:ro \
  -v /path/to/tls:/qpl/tls:ro \
  qpl-node
```

### Docker Compose (5-Node Testnet)

```bash
# Start the full testnet
make testnet-up

# View logs
make testnet-logs

# Stop
make testnet-down
```

---

## Step 7: Verify Operation

### Health Check

```bash
# TLS health check
wget --ca-certificate=/path/to/ca.crt \
  --post-data='{"method":"health"}' \
  -O - https://localhost:9000/

# Expected response: {"jsonrpc":"2.0","result":{"status":"healthy"},"id":1}
```

### Check On-Chain Registration

```bash
# Verify your operator is registered
solana program show <QPL_REGISTRY_PROGRAM_ID>
```

### Monitor Metrics

The node exposes metrics via the gRPC `health` endpoint:
- `requests_processed_total` — Total requests handled
- `requests_failed_total` — Failed requests
- `rate_limited_total` — Rate-limited requests
- `heartbeat_missed_total` — Missed heartbeats
- `uptime_seconds` — Time since node start

---

## Fee Economics

### Revenue Model

Operators earn service fees for computational work performed:

| Operation | Base Fee | USD |
|-----------|----------|-----|
| Threshold signature | 25,000 micro-USD | $0.025 |
| STARK proof (≤100 tx) | 1,000,000 micro-USD | $1.00 |
| STARK proof (>100 tx) | 2,500,000 micro-USD | $2.50 |
| Proof verification | 25,000 micro-USD | $0.025 |

### Fee Distribution

- **40%** — Coordinator (assembles quorum, routes tasks)
- **50%** — Participants (provide partial signatures/proofs)
- **10%** — Treasury (protocol development, audits)

### Break-Even Analysis

| Metric | Value |
|--------|-------|
| Daily operating cost | ~$43/day |
| Blended revenue per signature | ~$0.021 (with 20% coordinator rotation) |
| Break-even volume | ~2,048 signatures/day |
| Profitable at 5,000+ sigs/day | ~$105/day (59% margin) |

### Cost Structure

| Cost | Monthly |
|------|---------|
| HSM (cloud or physical) | $1,000 |
| VPS / bare metal | $200 |
| SOL stake opportunity cost | $3 |
| DevOps / monitoring | $100 |
| **Total** | **~$1,303/month** |

---

## Operator Responsibilities

1. **Maintain 99.5%+ uptime** — Missed heartbeats (30s interval, 3 max missed) result in suspension
2. **Respond to requests within SLA** — Threshold signing should complete in <200ms off-chain
3. **Keep HSM firmware updated** — Security patches are critical
4. **Monitor for slashing events** — Governance can slash for protocol violations
5. **Participate in governance** — Vote on protocol upgrades and parameter changes

---

## Troubleshooting

### Node won't start

- Check `qpl-node.toml` path and syntax
- Verify identity file exists and is valid
- Ensure Solana RPC endpoint is reachable

### Missed heartbeats

- Check network connectivity to Solana validators
- Verify `heartbeat_interval_secs` is set correctly (default: 30s)
- Check system clock synchronization (NTP)

### HSM connection errors

- Verify PKCS#11 module path
- Check HSM slot and PIN configuration
- Ensure HSM firmware supports required algorithms

### Fee collection issues

- Verify on-chain staking is active
- Check that operator account is registered
- Ensure fee vault is initialized

---

## Support

- **GitHub Issues:** https://github.com/jnodes/QPL/issues
- **Discord:** [QPL Operator Community](https://discord.gg/qpl)
- **Documentation:** https://docs.qpl.network

---

## Compliance Notice

QPL operator fees are **compensation for computational services rendered**. They are not investment returns, not guaranteed, and not passive income. Revenue varies with network demand and operator performance.

Staking SOL is a **security deposit** for network access — collateral ensuring honest behavior. It is not an investment, not capital deployed seeking returns, and not a "staking reward."

Operators are **independent service providers**. QPL does not pool operator funds, does not determine individual earnings, and does not operate as a common enterprise.
