#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-release-features.sh - release feature-set guard (#4480).
#
# THE DEFECT CLASS. A shipped artifact lacks a capability its docs advertise:
# release.yml built `--features sal` only, so the advertised PostgreSQL + AGE +
# pgvector tier was absent from every release binary (#4480, the #2676 /
# #2728 / #3996 class). The durable control is one declaration and checks that
# the build, the assertion, the proof job and the docs all follow it.
#
# Fails (exit 1) when ANY of:
#   1. scripts/release-features.sh does not declare `sal-postgres`;
#   2. release.yml's `cargo build ... --release --target` step does not take
#      its `--features` from scripts/release-features.sh (a hard-coded list
#      is how the pin and the build drift);
#   3. release.yml's assert step does not take its `--require` flags from
#      `release-features.sh --require-flags`;
#   4. .github/workflows/release-shape.yml (the release-shaped proof) is
#      missing or does not build from release-features.sh and run
#      scripts/release-shape-pg-proof.sh;
#   5. the Dockerfile (the published GHCR image) builds with
#      `release-features.sh` and asserts `release-features.sh --require-flags`;
#   6. docs/INSTALL.md "Pre-built Binaries" does not name sal-postgres, or
#      still says the postgres daemon path needs a source build.
#
# Usage: scripts/check-release-features.sh [repo-root]
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
rel="$root/.github/workflows/release.yml"
shape="$root/.github/workflows/release-shape.yml"
feat="$root/scripts/release-features.sh"
install="$root/docs/INSTALL.md"
fail=0
bad() { echo "check-release-features: FAIL: $*" >&2; fail=1; }

[[ -f "$feat" ]] || bad "scripts/release-features.sh is missing"
[[ -f "$rel" ]] || bad ".github/workflows/release.yml is missing"
[[ $fail -eq 0 ]] || exit 1

declared="$(bash "$feat")"
case ",$declared," in
  *,sal-postgres,*) ;;
  *) bad "release-features.sh declares [$declared], without sal-postgres" ;;
esac

# 2. the release build step takes its features from the declaration.
build_lines="$(grep -E '^[[:space:]]*run:[[:space:]]*cargo build .*--release .*--target' "$rel" || true)"
if [[ -z "$build_lines" ]]; then
  bad "release.yml has no 'cargo build --release --target' run line"
else
  while IFS= read -r line; do
    case "$line" in
      *'scripts/release-features.sh'*) ;;
      *) bad "release.yml build step does not read scripts/release-features.sh: $line" ;;
    esac
  done <<<"$build_lines"
fi

# 3. the assert step takes its --require flags from the declaration.
if ! grep -q 'release-features.sh --require-flags' "$rel"; then
  bad "release.yml assert step does not use 'release-features.sh --require-flags'"
fi

# 4. the release-shaped proof exists and follows the declaration.
if [[ ! -f "$shape" ]]; then
  bad ".github/workflows/release-shape.yml is missing (no release-shaped proof)"
else
  grep -q 'scripts/release-features.sh' "$shape" \
    || bad "release-shape.yml does not build from scripts/release-features.sh"
  grep -q 'scripts/release-shape-pg-proof.sh' "$shape" \
    || bad "release-shape.yml does not run scripts/release-shape-pg-proof.sh"
fi

# 5. the Dockerfile follows the same declaration (the image ships the tier too).
dockerfile="$root/Dockerfile"
if [[ ! -f "$dockerfile" ]]; then
  bad "Dockerfile is missing"
else
  grep -E 'cargo build' "$dockerfile" | grep -q 'scripts/release-features.sh' \
    || bad "Dockerfile cargo build does not read scripts/release-features.sh"
  grep -q 'release-features.sh --require-flags' "$dockerfile" \
    || bad "Dockerfile assert step does not use 'release-features.sh --require-flags'"
  grep -q 'COPY scripts/release-features.sh' "$dockerfile" \
    || bad "Dockerfile does not COPY scripts/release-features.sh into the build stage"
fi

# 6. the install docs state the shipped feature set.
section="$(sed -n '/^## Pre-built Binaries/,/^## /p' "$install" 2>/dev/null || true)"
case "$section" in
  *sal-postgres*) ;;
  *) bad "docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres" ;;
esac
# shellcheck disable=SC2016 # the backticks are literal doc text
case "$section" in
  *'daemon path is NOT'*|*'requires a `--features sal,sal-postgres` source build'*)
    bad "docs/INSTALL.md still says the postgres path needs a source build" ;;
esac

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "check-release-features: OK (release features: $declared)"
