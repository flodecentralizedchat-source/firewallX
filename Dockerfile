# FirewallX — Dockerfile (Railway auto-detect)
# This is the primary file Railway looks for when no railway.toml is present.
# Uses the same multi-stage build as Dockerfile.railway.
#
# ROOT CAUSE OF ORIGINAL ERROR:
#   rustlang/rust:1.75-slim  ← does NOT exist (wrong namespace)
#   rust:1.75-slim           ← correct official Docker Hub image

# ── Stage 1: Builder ─────────────────────────────────────────
FROM rust:1.75-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency caching layer
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src tests && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'pub fn placeholder() {}' > src/lib.rs && \
    cargo build --release && \
    rm -rf src tests

# Real build
COPY src ./src
COPY tests ./tests
RUN touch src/main.rs src/lib.rs && \
    cargo build --release

# ── Stage 2: Minimal runtime image ───────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 firewallx && \
    useradd  --uid 1001 --gid firewallx --shell /bin/sh --create-home firewallx

WORKDIR /app
COPY --from=builder /app/target/release/firewallx ./firewallx
RUN chmod +x ./firewallx

USER firewallx
EXPOSE 8080

ENV RUST_LOG=info
ENV FIREWALLX_MODE=userspace

CMD ["./firewallx"]
