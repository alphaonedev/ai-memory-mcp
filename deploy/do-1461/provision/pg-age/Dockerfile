# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2 image for the
# do-1461 SHARED substrate (one pg droplet; every peer keyed to its own
# search_path schema ic_peer_<N>). Mirrors deploy/docker-1461/Dockerfile.pg-age-vector
# EXACTLY so the DO fleet and the local Docker mesh assert the SAME upstream
# versions.
#
# The upstream apache/age image ships AGE compiled into the PG18 tree
# (age.so + age--<ver>.sql + age.control) but the server at the image's minor
# (18.1 for the release_PG18_1.7.0 digest). Two adjustments, both from
# precompiled pgdg .debs already configured in the AGE base — no source build:
#
#   1. Bump the server to the EXACT target minor (PG_APT_VERSION) via
#      `apt --only-upgrade postgresql-<major>`. ABI-safe within a major: AGE's
#      age.so (compiled against the major's extension API) loads unchanged
#      across PG minors, and the apt upgrade replaces only dpkg-tracked server
#      binaries — AGE's make-install'd extension files persist.
#   2. Install the pinned pgvector .deb — the ai-memory sal-postgres adapter
#      maps Rust embedding vectors to the server-side `vector` type.
#
# Every version literal lives in ONE place (provision/lib.sh) and arrives here
# as a --build-arg; this Dockerfile carries no hardcoded version.

ARG AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0
FROM ${AGE_BASE_IMAGE}

# Re-declare post-FROM so the build args are in scope for the RUN layer.
ARG PG_MAJOR=18
ARG PG_APT_VERSION
ARG PGVECTOR_APT_VERSION

USER root

# Pinned, reproducible: exact minor for the server + client, exact pgvector.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade \
      "postgresql-${PG_MAJOR}=${PG_APT_VERSION}" \
      "postgresql-client-${PG_MAJOR}=${PG_APT_VERSION}" \
 && apt-get install -y --no-install-recommends \
      "postgresql-${PG_MAJOR}-pgvector=${PGVECTOR_APT_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

# Base image entrypoint + USER state preserved; AGE auto-installs via its own
# /docker-entrypoint-initdb.d/00-create-extension-age.sql.
