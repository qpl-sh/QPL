.PHONY: build test lint clean bench

# Build all components
build:
	cargo build --workspace
	cd contracts && forge build

# Run all tests
test:
	cargo test --workspace
	cd contracts && forge test

# Run all benchmarks
bench:
	cargo bench --workspace

# Save a named Criterion baseline (default: "baseline")
bench-baseline:
	cargo bench --workspace -- --save-baseline baseline

# Lint all code
lint:
	cargo clippy --workspace -- -D warnings

# Clean build artifacts
clean:
	cargo clean
	cd contracts && forge clean

# ─── QPL Network Targets ───────────────────────────────────────────────

# Build the QPL network components
build-network:
	cargo build -p qpl-network -p qpl-sdk -p qpl-node

# Build qpl-node release binary
build-node:
	cargo build --release -p qpl-node

# Run all QPL network tests
test-network:
	cargo test -p qpl-network

# Build & test Solidity contracts
build-contracts:
	cd contracts && forge build

test-contracts:
	cd contracts && forge test -v

# Deploy contracts to local Anvil
deploy-local:
	cd contracts && forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast

# Start the 5-node testnet (Docker)
testnet-up:
	docker compose -f docker-compose.testnet.yml up --build -d

# Stop testnet
testnet-down:
	docker compose -f docker-compose.testnet.yml down -v

# View testnet logs
testnet-logs:
	docker compose -f docker-compose.testnet.yml logs -f

# Run a single QPL node locally (for development)
run-node:
	cargo run -p qpl-node -- --listen 0.0.0.0:9000 --name dev-node

# ─── Individual Crate Targets ──────────────────────────────────────────

build-crypto:
	cargo build -p qpl-crypto

build-rollup:
	cargo build -p qpl-stark-rollup

test-crypto:
	cargo test -p qpl-crypto

test-rollup:
	cargo test -p qpl-stark-rollup
