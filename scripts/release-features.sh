#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/release-features.sh - the ONE declaration of the cargo feature set
# every release artifact is built with (#4480). release.yml builds with it,
# release.yml's assert step requires it, and the release-shape CI job builds
# and proves it, so the build, the assertion and the proof cannot drift (the
# #2676 / #2728 class: a binary shipped without a capability its docs claim).
#
#   scripts/release-features.sh                  # sal,sal-postgres
#   scripts/release-features.sh --require-flags  # --require sqlite-bundled --require sal ...
#
# `sqlite-bundled` is the Cargo default feature, always compiled in. `sal` is
# the SAL/federation surface (#2676). `sal-postgres` is the PostgreSQL + AGE +
# pgvector tier (#4480): sqlx on rustls, pure Rust - no libpq, no system OpenSSL.
set -euo pipefail

# Features passed to `cargo build --features`.
BUILD_FEATURES=(sal sal-postgres)
# Features the artifact must REPORT (`ai-memory features`): the defaults too.
REPORTED_FEATURES=(sqlite-bundled "${BUILD_FEATURES[@]}")

case "${1:-}" in
  "")
    (IFS=,; printf '%s\n' "${BUILD_FEATURES[*]}")
    ;;
  --require-flags)
    out=()
    for f in "${REPORTED_FEATURES[@]}"; do out+=(--require "$f"); done
    printf '%s\n' "${out[*]}"
    ;;
  *)
    echo "usage: $0 [--require-flags]" >&2
    exit 2
    ;;
esac
