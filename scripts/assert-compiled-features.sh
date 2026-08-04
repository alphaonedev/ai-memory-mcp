#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/assert-compiled-features.sh — Gate 3 / #2676
#
# Assert that a binary's `ai-memory features` self-report includes every
# required feature name. Exit 0 only when all required features are present.
#
# Usage:
#   scripts/assert-compiled-features.sh [binary] [--require feat ...]
# Defaults: binary=ai-memory (PATH), required=sqlite-bundled
#
# Examples:
#   scripts/assert-compiled-features.sh ./target/release/ai-memory
#   scripts/assert-compiled-features.sh ./ai-memory --require sqlite-bundled --require sal-postgres

set -euo pipefail

bin="ai-memory"
required=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --require)
      shift
      required+=("${1:?--require needs a feature name}")
      ;;
    -*)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
    *)
      bin="$1"
      ;;
  esac
  shift || true
done

if [[ ${#required[@]} -eq 0 ]]; then
  required=(sqlite-bundled)
fi

if ! command -v "$bin" >/dev/null 2>&1 && [[ ! -x "$bin" ]]; then
  echo "assert-compiled-features: binary not found: $bin" >&2
  exit 2
fi

report="$("$bin" features 2>/dev/null || true)"
if [[ -z "$report" ]]; then
  echo "assert-compiled-features: empty report from: $bin features" >&2
  exit 1
fi

# Parse "features: a,b,c" line
feat_line="$(printf '%s\n' "$report" | sed -n 's/^features: //p' | head -1)"
if [[ -z "$feat_line" ]]; then
  echo "assert-compiled-features: no features: line in report:" >&2
  printf '%s\n' "$report" >&2
  exit 1
fi

missing=0
for r in "${required[@]}"; do
  # exact token match in comma list
  if ! printf '%s' ",${feat_line}," | grep -q ",${r},"; then
    echo "assert-compiled-features: MISSING required feature: $r" >&2
    echo "  report: $feat_line" >&2
    missing=1
  fi
done

if [[ $missing -ne 0 ]]; then
  exit 1
fi

echo "assert-compiled-features: OK ($bin) features=[$feat_line] required=[${required[*]}]"
