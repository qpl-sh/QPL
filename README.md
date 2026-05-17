# QPL Network

Decentralized post-quantum signing and proving infrastructure. QPL provides quantum-resistant threshold signatures (ML-DSA-65) and zero-knowledge proofs (FRI-based zk-STARKs) as a permissionless operator network — no trusted setup required.

## Why QPL

Quantum computers will break ECDSA and RSA within the decade. QPL replaces legacy cryptography with NIST-standardized post-quantum algorithms, delivered as a decentralized service that any protocol can integrate via SDK or JSON-RPC.

- **ML-DSA-65** threshold signing (NIST FIPS 204)
- **ML-KEM-1024** key encapsulation (NIST FIPS 203)
- **FRI-based zk-STARKs** with no trusted setup (Winterfell)
- **Decentralized operator network** with on-chain staking and slashing

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Applications                       │
│         (DeFi protocols, wallets, bridges)           │
└────────────────────────┬────────────────────────────┘
                         │ JSON-RPC / SDK
┌────────────────────────▼────────────────────────────┐
│              QPL Operator Network                     │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │  Node 1  │  │  Node 2  │  │  Node N  │  ...     │
│  │ sign+prove│  │ sign+prove│  │ sign+prove│         │
│  └──────────┘  └──────────┘  └──────────┘          │
│                                                      │
│  Coordination Layer (quorum selection, fee routing)  │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│              Ethereum (Settlement)                    │
│  QPLStaking · QPLFeeRouter · QPLRegistry            │
└─────────────────────────────────────────────────────┘
```

## Components

| Crate / Service | Description |
|---|---|
| `crates/qpl-crypto` | Post-quantum primitives — ML-DSA-65, ML-KEM-1024, threshold MPC |
| `crates/qpl-stark-rollup` | STARK prover/verifier — AIR constraints, FRI, execution engine |
| `crates/qpl-network` | Operator lifecycle, coordination, fee calculation, quorum logic |
| `crates/qpl-sdk` | Client SDK for integrating QPL signing and proving |
| `services/qpl-node` | Operator node binary — serves signing and proving over JSON-RPC |
| `contracts/` | Solidity contracts — staking, fee routing, operator registry |

## Fee Model

Every signing or proving operation incurs a micro-fee (~$0.001), split automatically by the on-chain fee router:

| Recipient | Share |
|-----------|-------|
| Coordinator (request router) | 40% |
| Participating operators | 50% |
| Protocol treasury | 10% |

Operators stake ETH to join the network. Misbehavior triggers slashing; honest participation earns fees proportional to work performed.

## Getting Started

### Prerequisites

- **Rust** stable toolchain (1.75+)
- **Foundry** (forge, anvil, cast) for Solidity contracts
- **Docker** (optional) for multi-node testnet

### Build

```bash
# Build everything (Rust workspace + Solidity contracts)
make build

# Build only the operator node (release mode)
make build-node

# Build only contracts
make build-contracts
```

### Test

```bash
# Run all tests (200 Rust + 10 Solidity)
make test

# Individual test suites
cargo test -p qpl-crypto
cargo test -p qpl-stark-rollup
cargo test -p qpl-network
cd contracts && forge test -v
```

### Run a Local Node

```bash
# Generate an operator identity
cargo run -p qpl-node -- --generate-identity

# Start a node
cargo run -p qpl-node -- --listen 0.0.0.0:9000 --name my-node
```

### Deploy a 5-Node Testnet

```bash
# Spin up 5 operator nodes + Anvil (local Ethereum)
make testnet-up

# View logs
make testnet-logs

# Tear down
make testnet-down
```

### Deploy Contracts (Local)

```bash
# Requires Anvil running on localhost:8545
make deploy-local
```

## SDK Usage

```rust
use qpl_sdk::{QplClient, SdkConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SdkConfig::default();
    let client = QplClient::connect(config).await?;

    // Request a quantum-resistant signature
    let sig = client.signing().sign(b"message").await?;

    // Request a STARK proof
    let proof = client.proving().prove(b"statement").await?;

    Ok(())
}
```

## Operator Lifecycle

```
Stake ──► Join ──► Active ──► Drain ──► Exit
                     │                    ▲
                     └── Slash ───────────┘
```

1. **Stake** — Deposit minimum 1 ETH to `QPLStaking` contract
2. **Join** — Register endpoint and supported services in `QPLRegistry`
3. **Active** — Serve signing/proving requests, earn fees
4. **Drain** — Signal intent to leave, stop accepting new requests
5. **Exit** — Unbond after 7-day cooldown, withdraw stake

## Project Structure

```
qpl/
├── crates/
│   ├── qpl-crypto/          # Post-quantum cryptographic primitives
│   ├── qpl-stark-rollup/    # STARK prover and verifier
│   ├── qpl-network/         # Operator coordination and fees
│   ├── qpl-sdk/             # Client SDK
│   └── common/              # Shared types and utilities
├── services/
│   └── qpl-node/            # Operator node binary
├── contracts/
│   ├── src/                  # Solidity: Staking, FeeRouter, Registry
│   ├── test/                 # Foundry tests
│   └── script/               # Deployment scripts
├── proto/                    # gRPC protocol definitions
├── tests/e2e/               # End-to-end integration tests
├── docker-compose.testnet.yml
└── Makefile
```

## Benchmarks

Run `make bench` to reproduce (AMD EPYC 7763, `--release`, Criterion.rs):

| Operation | Median |
|-----------|--------|
| ML-DSA-65 keygen | 84 us |
| ML-DSA-65 sign (1 KB) | 111 us |
| ML-DSA-65 verify (1 KB) | 70 us |
| ML-KEM-1024 encapsulate | 78 us |
| MPC shard split (5-of-3) | 15 us |
| MPC reconstruct (3-of-5) | 22 us |

## Contributing

QPL is open source. Contributions welcome.

1. Fork the repository
2. Create a feature branch
3. Ensure `make test` and `make lint` pass
4. Open a pull request

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
