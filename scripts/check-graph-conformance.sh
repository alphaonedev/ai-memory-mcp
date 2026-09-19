#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
# #3573: dedicated cert leg; absence is FAILURE when this leg is selected.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .local-runs/graph-conformance
out=.local-runs/graph-conformance
echo "GRAPH_COMMIT=$(git rev-parse HEAD)"
timer="$(command -v timeout || command -v gtimeout)"
export AI_MEMORY_NO_CONFIG=1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
if [ "${1:-}" = --self-test ]; then
  "$timer" 30 python3 scripts/check_graph_conformance_log.py --self-test
  "$timer" 1800 cargo test --features sal-postgres --lib graph_conformance::inventory -- --nocapture
  exit "$?"
fi
"$timer" 1800 cargo test --features sal-postgres --lib graph_conformance --no-run
"$timer" 60 cargo test --features sal-postgres --lib graph_conformance -- --include-ignored --list > "$out/list.log" 2>&1
set +e
"$timer" 300 cargo test --features sal-postgres --lib graph_conformance -- --include-ignored --test-threads=1 --nocapture > "$out/run.log" 2>&1
rc=$?
set -e
cat "$out/run.log"
echo "GRAPH_EXIT=$rc"
if [ "$rc" -ne 0 ]; then exit "$rc"; fi
python3 scripts/check_graph_conformance_log.py "$out"
