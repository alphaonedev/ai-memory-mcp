# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# infra/bench-mesh — runtime image for the #2921 N-node federation
# capacity mesh.
#
# WHY THIS IS NOT `Dockerfile.plan-c` / `Dockerfile.tier2-trackb`:
# both of those compile the crate INSIDE the image. This stack brings up
# N = 2..50 daemons in a stepped ramp and re-runs the ramp several times,
# so the binary must be built ONCE on the measurement host and reused
# byte-identically by every node — otherwise "the ramp" would be measuring
# a set of binaries rather than a set of mesh sizes. The host build is
# also the binary whose CPU / RAM / storage facts the results doc cites
# (`scripts/bench/host-facts.sh`), so baking a second, differently-built
# binary into the image would break the "every number carries its
# producer + hardware" discipline this whole issue exists to restore
# (docs/enterprise-deployment.md §11.1).
#
# Consequence: the build context MUST contain a prebuilt `ai-memory`
# release binary at `.build/ai-memory`. `run-mesh-scaling.sh` stages it
# there. A bare `docker build` without that staging step fails loudly at
# the COPY rather than silently producing a node that cannot serve.
#
# Base image is `ubuntu:24.04` (NOT debian:bookworm-slim, which the
# in-image-build Dockerfiles use): the binary is dynamically linked
# against the measurement host's glibc/libssl, so the runtime base must
# match that host's ABI. Bookworm's glibc 2.36 cannot load a binary built
# against Ubuntu 24.04's glibc 2.39 — it fails at exec with a version
# error that looks like a crash-loop. Pinned by digest so a ramp re-run
# months later is the same substrate.
FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# ca-certificates: outbound TLS trust store (unused on a plaintext bridge,
#   present so the image is not silently un-TLS-able).
# curl: the compose healthcheck probe.
# libssl3: the binary's dynamic OpenSSL dependency.
# ubuntu:24.04 ships no `curl`; `--no-install-recommends` keeps the image
# small enough that 50 containers of it are cheap to schedule.
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY .build/ai-memory /usr/local/bin/ai-memory
COPY entrypoint.sh /usr/local/bin/bench-entrypoint.sh
RUN chmod 0755 /usr/local/bin/ai-memory /usr/local/bin/bench-entrypoint.sh

# The node runs as uid/gid 1000 so every file it writes into the
# bind-mounted per-node data + key directories is owned by the
# measurement user on the host. The alternative (root-in-container) makes
# the raw evidence unreadable without sudo and leaves root-owned
# droppings under `.local-runs/` after teardown.
USER 1000:1000

EXPOSE 19077
ENTRYPOINT ["/usr/local/bin/bench-entrypoint.sh"]
