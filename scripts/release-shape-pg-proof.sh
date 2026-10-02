#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/release-shape-pg-proof.sh - release-shaped PostgreSQL proof (#4480).
#
# Drives a binary built EXACTLY as release.yml builds it
# (`--features "$(scripts/release-features.sh)"`) and proves, end to end, that
# the shipped PostgreSQL tier is real:
#   1. the binary reports every release feature (`ai-memory features`),
#      including sal-postgres;
#   2. it opens a PostgreSQL store over sslmode=verify-full and round-trips a
#      memory: sqlite -> migrate -> PostgreSQL -> migrate -> sqlite -> list;
#   3. it REFUSES the same server with a weaker sslmode (fail closed, no
#      session opened);
#   4. `doctor` reports the verify-full store as pinned.
#
# Usage: scripts/release-shape-pg-proof.sh <binary> <verify-full-postgres-url>
#
# NEVER vacuous: a missing binary, a missing URL, an unreachable server or an
# absent TLS posture is a FAILURE (exit 1/2), never a skip. The URL must pin
# sslmode=verify-full; the script never prints it (it carries a credential).
set -euo pipefail

bin="${1:-}"
url="${2:-}"
here="$(cd "$(dirname "$0")" && pwd)"

die() { echo "release-shape-pg-proof: FAIL: $*" >&2; exit 1; }

[[ -n "$bin" && -x "$bin" ]] || { echo "release-shape-pg-proof: binary not executable: ${bin:-<none>}" >&2; exit 2; }
[[ -n "$url" ]] || { echo "release-shape-pg-proof: no PostgreSQL URL - refusing to pass vacuously" >&2; exit 2; }
case "$url" in
  postgres://*|postgresql://*) ;;
  *) echo "release-shape-pg-proof: URL is not postgres://" >&2; exit 2 ;;
esac
case "$url" in
  *sslmode=verify-full*) ;;
  *) echo "release-shape-pg-proof: URL does not pin sslmode=verify-full" >&2; exit 2 ;;
esac

work="$(mktemp -d "${TMPDIR:-/tmp}/release-shape-pg.XXXXXX")"
trap 'rm -rf "$work"' EXIT
export HOME="$work/home"; mkdir -p "$HOME"
export AI_MEMORY_NO_CONFIG=1
unset AI_MEMORY_STORE_URL AI_MEMORY_STORE_URL_FILE PGSSLMODE PGHOST PGHOSTADDR PGPORT PGSSLROOTCERT PGSERVICE
marker="release-shape-proof-$$-$(date +%s)"

# 1. the artifact reports the shipped feature set.
# shellcheck disable=SC2046 # word-splitting the --require flags is intended
bash "$here/assert-compiled-features.sh" "$bin" $(bash "$here/release-features.sh" --require-flags) \
  || die "the artifact does not report the release feature set"

# 2. a real round trip through PostgreSQL over verify-full.
src="$work/src.db"; dst="$work/dst.db"
"$bin" --db "$src" store -n "$marker" -T "release shape proof" -c "$marker" >/dev/null 2>"$work/store.err" \
  || { cat "$work/store.err" >&2; die "could not seed the sqlite source store"; }
"$bin" migrate --from "sqlite://$src" --to "$url" >"$work/up.out" 2>&1 \
  || { sed -e 's#postgres[a-z]*://[^ ]*#<postgres-url>#g' "$work/up.out" >&2; die "migrate sqlite -> postgres failed (the shipped binary could not open the verify-full store)"; }
"$bin" migrate --from "$url" --to "sqlite://$dst" --namespace "$marker" >"$work/down.out" 2>&1 \
  || { sed -e 's#postgres[a-z]*://[^ ]*#<postgres-url>#g' "$work/down.out" >&2; die "migrate postgres -> sqlite failed"; }
"$bin" --db "$dst" list -n "$marker" >"$work/list.out" 2>&1 || die "listing the round-tripped store failed"
grep -q "$marker" "$work/list.out" || die "the memory did not survive the PostgreSQL round trip"
echo "release-shape-pg-proof: round trip OK (sqlite -> postgres verify-full -> sqlite)"

# 3. fail closed: the same server with a weaker sslmode must be REFUSED.
weak="$(printf '%s' "$url" | sed -e 's/sslmode=verify-full/sslmode=disable/')"
if "$bin" migrate --from "sqlite://$src" --to "$weak" >"$work/weak.out" 2>&1; then
  die "a sslmode=disable URL was accepted (fail-open)"
fi
grep -q "refusing the PostgreSQL store DSN" "$work/weak.out" \
  || { sed -e 's#postgres[a-z]*://[^ ]*#<postgres-url>#g' "$work/weak.out" >&2; die "the weak-sslmode refusal did not come from the transit-encryption floor"; }
echo "release-shape-pg-proof: weak sslmode refused (fail closed)"

# 4. doctor reports the verify-full store as pinned.
AI_MEMORY_STORE_URL="$url" "$bin" doctor --json >"$work/doctor.json" 2>/dev/null || true
grep -q "sslmode=verify-full pinned" "$work/doctor.json" \
  || die "doctor did not report the verify-full store as pinned"
echo "release-shape-pg-proof: OK"
