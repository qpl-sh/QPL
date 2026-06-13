# QPL Node — Multi-stage build
#
# Security remediation (D-7 / D-8):
#  - non-root runtime user                     (D-8 implemented below)
#  - VOLUME for TLS material                   (D-1 wiring)
#  - HEALTHCHECK over TLS                      (D-1 wiring)
#  - Base images pinned to digest hashes       (D-7 implemented below)

FROM rust:1.78-slim@sha256:0fea967628dc796a2b9d1d57ddb3af3b3f0a35b6c8c0e23690dbe0ceb71a2dc9 as builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for caching
COPY Cargo.toml Cargo.lock ./
COPY crates/qpl-crypto/Cargo.toml crates/qpl-crypto/
COPY crates/qpl-stark-rollup/Cargo.toml crates/qpl-stark-rollup/
COPY crates/qpl-network/Cargo.toml crates/qpl-network/
COPY crates/qpl-sdk/Cargo.toml crates/qpl-sdk/
COPY crates/common/types/Cargo.toml crates/common/types/
COPY crates/common/utils/Cargo.toml crates/common/utils/
COPY services/qpl-node/Cargo.toml services/qpl-node/
COPY tests/e2e/Cargo.toml tests/e2e/

# Create dummy source files for dependency caching
RUN mkdir -p crates/qpl-crypto/src && echo "" > crates/qpl-crypto/src/lib.rs && \
    mkdir -p crates/qpl-stark-rollup/src && echo "" > crates/qpl-stark-rollup/src/lib.rs && \
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
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

# wget is needed for the TLS HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

# D-8: create a dedicated non-root user that owns the working dir and
# data volumes. The qpl-node binary never needs root capabilities at
# runtime (no privileged ports — listens on 9000).
RUN groupadd --system --gid 1000 qpl \
    && useradd  --system --uid 1000 --gid qpl --home-dir /qpl --shell /sbin/nologin qpl

COPY --from=builder /build/target/release/qpl-node /usr/local/bin/qpl-node
COPY --from=builder /build/services/qpl-node/qpl-node.toml /qpl/qpl-node.toml

# Default config + data + TLS material locations.
WORKDIR /qpl
RUN mkdir -p /qpl/data /qpl/tls && chown -R qpl:qpl /qpl

# /qpl/tls is bind-mounted at runtime with cert/key:
#   docker run -v /host/path/to/tls:/qpl/tls:ro qpl-node ...
VOLUME ["/qpl/data", "/qpl/tls"]

EXPOSE 9000

# D-1: TLS-aware HEALTHCHECK. The unauthenticated `health` JSON-RPC
# method may be invoked over TLS by sending a single newline-terminated
# JSON line. We test connectivity with `wget --ca-certificate` against
# the locally-mounted CA bundle. If the operator opts into mTLS by
# setting tls.client_ca_path, the healthcheck can be downgraded to a
# raw TCP probe by overriding the HEALTHCHECK at deploy time.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --timeout=3 \
        --ca-certificate=/qpl/tls/server.crt \
        --post-data='{"method":"health"}' \
        -O /dev/null \
        https://localhost:9000/ || exit 1

USER qpl

ENTRYPOINT ["qpl-node"]
CMD ["--config", "/qpl/qpl-node.toml"]
