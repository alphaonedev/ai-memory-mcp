# syntax=docker/dockerfile:1

# ---- Build stage ----
# Pin to bookworm so the produced binary's glibc matches the runtime
# stage (debian:bookworm-slim, glibc 2.36). Without the explicit
# bookworm tag, rust:1.96-slim resolves to a trixie-based image
# (glibc 2.41) and the binary fails at startup with
# `version GLIBC_2.39 not found` — caught by the dockerfile-validate
# CI job (PR #465 retrospective; v0.6.5 bake).
FROM rust:1.96-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY benches/ benches/
# v0.6.3 added include_str! references to migration SQL files
# (Streams A-C schema v15: migrations/sqlite/0010_v063_hierarchy_kg.sql).
# Without the migrations/ directory in the build context, cargo build
# fails at compile time. Pre-existing Dockerfile gap that v0.6.2 did
# not surface (no new migrations).
COPY migrations/ migrations/
# #2050 — the `paste` proc-macro dependency is vendored in-tree
# (vendor/paste, path dep in Cargo.toml) after the upstream
# alphaonedev/paste fork was deleted. The build context MUST include it
# or `cargo build` fails: "failed to read /build/vendor/paste/Cargo.toml".
COPY vendor/ vendor/
# #2676 packaging residual — ship the federation surface operators expect.
# Default cargo features are only `sqlite-bundled`; without `sal`, SAL store
# paths and several daemon federation workers stay compiled out. Gate3 cert
# measured an asserted feature build; GHCR/deb must not silently ship less.
COPY scripts/assert-compiled-features.sh scripts/assert-compiled-features.sh
RUN cargo build --release --features sal \
    && strip target/release/ai-memory \
    && bash scripts/assert-compiled-features.sh target/release/ai-memory \
         --require sqlite-bundled --require sal

# ---- Runtime stage ----
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="ai-memory" \
      org.opencontainers.image.description="AI-agnostic persistent memory system — MCP server, HTTP API, and CLI" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://github.com/alphaonedev/ai-memory-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="AlphaOne LLC" \
      io.modelcontextprotocol.server.name="io.github.alphaonedev/ai-memory"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system aimem \
    && useradd --system --gid aimem --create-home aimem \
    && mkdir -p /data && chown aimem:aimem /data

COPY --from=builder /build/target/release/ai-memory /usr/local/bin/ai-memory

ENV AI_MEMORY_DB=/data/ai-memory.db

VOLUME /data
EXPOSE 9077

USER aimem

ENTRYPOINT ["ai-memory"]
CMD ["serve", "--host", "0.0.0.0"]
