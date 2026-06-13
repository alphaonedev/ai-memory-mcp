# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible PostgreSQL 16 + Apache AGE + pgvector image for the federated
# peer substrate. AGE ships in the base image; pgvector is added here because
# the apache/age image does NOT bundle it (ai-memory's `CREATE EXTENSION vector`
# fails fast without it). Both the base tag and the pgvector ref are pinned.
ARG AGE_IMAGE=apache/age:PG16_latest
FROM ${AGE_IMAGE}

ARG PGVECTOR_REF=v0.8.0
USER root

RUN set -eux; \
    apt-get update; \
    if apt-get install -y --no-install-recommends postgresql-16-pgvector; then \
        echo "pgvector from PGDG apt"; \
    else \
        apt-get install -y --no-install-recommends build-essential git postgresql-server-dev-16; \
        git clone --depth 1 --branch "${PGVECTOR_REF}" https://github.com/pgvector/pgvector.git /usr/src/pgvector; \
        cd /usr/src/pgvector && make && make install; \
        rm -rf /usr/src/pgvector; \
    fi; \
    rm -rf /var/lib/apt/lists/*
