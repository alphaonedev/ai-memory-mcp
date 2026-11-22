# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible PostgreSQL 19.0 + Apache AGE 1.7.0 + pgvector 0.8.7 image for the
# do-1461 SHARED substrate (one pg droplet; every peer keyed to its own
# search_path schema ic_peer_<N>). Mirrors deploy/docker-1461/Dockerfile.pg-age-vector
# EXACTLY so the DO fleet and the local Docker mesh assert the SAME upstream
# versions.
#
# Apache AGE 1.7.0, built from upstream PG19 branch commit c6b043d plus
# upstream fix commit 06ce678d (apache/age#2581) (not a tagged Apache
# release; upstream has no 1.7.0 release for PostgreSQL 19).
# pgdg ships no AGE package for this major and apache/age publishes no image
# for it, so:
#
#   Stage `age-build`: the official PostgreSQL image, server + server-dev at
#     the EXACT pgdg minor (PG_APT_VERSION), the AGE source fetched at
#     AGE_SOURCE_COMMIT and checked with `git rev-parse HEAD` (a mismatch
#     fails the build), then `make install` into a staging DESTDIR.
#   Final stage: the same base, server + client at PG_APT_VERSION, the pinned
#     pgvector .deb, and the staged AGE files plus AGE's initdb script.
#
# Every version literal lives in ONE place (provision/lib.sh) and arrives here
# as a --build-arg; this Dockerfile carries no hardcoded version, and a missing
# build arg fails the build. The one upstream AGE fix (#9965) comes from the
# named build context `age-provision` (pass
# `--build-context age-provision=deploy/docker-1461/provision`), whose
# apply_age_patch.py refuses any other source, patch or result.

ARG PG_BASE_IMAGE
FROM ${PG_BASE_IMAGE} AS age-build

ARG PG_MAJOR
ARG PG_APT_VERSION
ARG AGE_SOURCE_REPO
ARG AGE_SOURCE_COMMIT

USER root

COPY --from=age-provision lib.sh apply_age_patch.py /age-provision/
COPY --from=age-provision patches/ /age-provision/patches/

RUN : "${PG_MAJOR:?}" "${PG_APT_VERSION:?}" "${AGE_SOURCE_REPO:?}" "${AGE_SOURCE_COMMIT:?}" \
 && apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade \
      "postgresql-${PG_MAJOR}=${PG_APT_VERSION}" \
      "postgresql-client-${PG_MAJOR}=${PG_APT_VERSION}" \
 && apt-get install -y --no-install-recommends \
      "postgresql-server-dev-${PG_MAJOR}=${PG_APT_VERSION}" \
      bison build-essential ca-certificates flex git python3 \
 && git init -q /src/age \
 && git -C /src/age remote add origin "${AGE_SOURCE_REPO}" \
 && git -C /src/age fetch -q --depth 1 origin "${AGE_SOURCE_COMMIT}" \
 && git -C /src/age checkout -q --detach FETCH_HEAD \
 && test "$(git -C /src/age rev-parse HEAD)" = "${AGE_SOURCE_COMMIT}" \
 && python3 /age-provision/apply_age_patch.py --ssot /age-provision/lib.sh --src /src/age \
 && make -C /src/age -j"$(nproc)" PG_CONFIG="/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config" \
 && make -C /src/age install DESTDIR=/age-dist PG_CONFIG="/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config" \
 && python3 /age-provision/apply_age_patch.py --ssot /age-provision/lib.sh --src /src/age --verify \
 && install -D -m 0644 /src/age/docker/docker-entrypoint-initdb.d/00-create-extension-age.sql \
      /age-dist/docker-entrypoint-initdb.d/00-create-extension-age.sql

ARG PG_BASE_IMAGE
FROM ${PG_BASE_IMAGE}

# Re-declare post-FROM so the build args are in scope for the RUN layer.
ARG PG_MAJOR
ARG PG_APT_VERSION
ARG PGVECTOR_APT_VERSION

USER root

# Pinned, reproducible: exact minor for the server + client, exact pgvector.
RUN : "${PG_MAJOR:?}" "${PG_APT_VERSION:?}" "${PGVECTOR_APT_VERSION:?}" \
 && apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade \
      "postgresql-${PG_MAJOR}=${PG_APT_VERSION}" \
      "postgresql-client-${PG_MAJOR}=${PG_APT_VERSION}" \
 && apt-get install -y --no-install-recommends \
      "postgresql-${PG_MAJOR}-pgvector=${PGVECTOR_APT_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

COPY --from=age-build /age-dist/ /

# Official postgres entrypoint + USER state preserved; AGE is preloaded and
# auto-created via /docker-entrypoint-initdb.d/00-create-extension-age.sql.
CMD ["postgres", "-c", "shared_preload_libraries=age"]
