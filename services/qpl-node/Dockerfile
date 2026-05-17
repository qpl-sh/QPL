# QPL Node — Multi-stage build
FROM rust:1.78-slim as builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for caching
COPY Cargo.toml Cargo.lock ./
COPY crates/qpl-crypto/Cargo.toml crates/qpl-crypto/
COPY crates/qpl-governance/Cargo.toml crates/qpl-governance/
COPY crates/qpl-stark-rollup/Cargo.toml crates/qpl-stark-rollup/
COPY crates/qpl-custody/Cargo.toml crates/qpl-custody/
COPY crates/qpl-yield/Cargo.toml crates/qpl-yield/
COPY crates/qpl-rwa/Cargo.toml crates/qpl-rwa/
COPY crates/qpl-programmable/Cargo.toml crates/qpl-programmable/
COPY crates/qpl-network/Cargo.toml crates/qpl-network/
COPY crates/qpl-sdk/Cargo.toml crates/qpl-sdk/
COPY crates/common/types/Cargo.toml crates/common/types/
COPY crates/common/utils/Cargo.toml crates/common/utils/
COPY services/qpl-node/Cargo.toml services/qpl-node/
COPY tests/e2e/Cargo.toml tests/e2e/

# Create dummy source files for dependency caching
RUN mkdir -p crates/qpl-crypto/src && echo "" > crates/qpl-crypto/src/lib.rs && \
    mkdir -p crates/qpl-governance/src && echo "" > crates/qpl-governance/src/lib.rs && \
    mkdir -p crates/qpl-stark-rollup/src && echo "" > crates/qpl-stark-rollup/src/lib.rs && \
    mkdir -p crates/qpl-custody/src && echo "" > crates/qpl-custody/src/lib.rs && \
    mkdir -p crates/qpl-yield/src && echo "" > crates/qpl-yield/src/lib.rs && \
    mkdir -p crates/qpl-rwa/src && echo "" > crates/qpl-rwa/src/lib.rs && \
    mkdir -p crates/qpl-programmable/src && echo "" > crates/qpl-programmable/src/lib.rs && \
    mkdir -p crates/qpl-network/src && echo "" > crates/qpl-network/src/lib.rs && \
    mkdir -p crates/qpl-sdk/src && echo "" > crates/qpl-sdk/src/lib.rs && \
    mkdir -p crates/common/types/src && echo "" > crates/common/types/src/lib.rs && \
    mkdir -p crates/common/utils/src && echo "" > crates/common/utils/src/lib.rs && \
    mkdir -p services/qpl-node/src && echo "fn main() {}" > services/qpl-node/src/main.rs && \
    mkdir -p tests/e2e/src && echo "" > tests/e2e/src/lib.rs

# Cache dependencies
RUN cargo build --release -p qpl-node 2>/dev/null || true

# Copy real source code
COPY crates/ crates/
COPY services/qpl-node/ services/qpl-node/
COPY proto/ proto/

# Build the actual binary
RUN cargo build --release -p qpl-node

# ─── Runtime image ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/qpl-node /usr/local/bin/qpl-node

# Default config location
WORKDIR /qpl
VOLUME ["/qpl/data"]

EXPOSE 9000

ENTRYPOINT ["qpl-node"]
CMD ["--config", "/qpl/qpl-node.toml"]
