#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# write-bundle.sh — emit a §1-minimum evidence record with COMPUTED bindings.
#
# Required:
#   --out FILE            destination JSON
#   --producer ID         producer-map.json id
# Either --pid N (hash the live process) or --binary PATH (hash that file).
# Optional: --run-id, --verdict, --oracle-kind, --p99-method
#
# Never accepts a caller-typed daemon_binary_sha256. The hash is always
# computed from the process or file the harness addressed (#3547 binding).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

OUT="" PRODUCER="" PID="" BINARY="" RUN_ID=""
VERDICT="NOT_APPLICABLE"
ORACLE="not-applicable"
P99_METHOD="pooled_raw"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

usage() {
  sed -n '2,16p' "$0"
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --producer) PRODUCER="$2"; shift 2 ;;
    --pid) PID="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --verdict) VERDICT="$2"; shift 2 ;;
    --oracle-kind) ORACLE="$2"; shift 2 ;;
    --p99-method) P99_METHOD="$2"; shift 2 ;;
    --started-at) STARTED="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$OUT" && -n "$PRODUCER" ]] || { echo "FATAL: --out and --producer required" >&2; exit 2; }
[[ -n "$PID" || -n "$BINARY" ]] || { echo "FATAL: --pid or --binary required (hash is computed, never typed)" >&2; exit 2; }

if [[ -n "$PID" ]]; then
  ADDRESSED="$(evidence_sha256_of_pid "$PID")"
else
  ADDRESSED="$(evidence_sha256_of_file "$BINARY")"
fi

RUN_ID="${RUN_ID:-$(evidence_new_run_id)}"
FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(evidence_source_commit)"
TREE="$(evidence_source_tree_sha)"

python3 -c '
import json, sys
out, producer, run_id, started, finished, commit, tree, addressed, verdict, oracle, p99 = sys.argv[1:12]
doc = {
    "artifact_kind": "daemon",
    "producer_id": producer,
    "run_id": run_id,
    "supersedes_run_id": None,
    "started_at_utc": started,
    "finished_at_utc": finished,
    "source_commit": commit,
    "source_tree_sha": tree,
    "daemon_binary_sha256": addressed,
    "addressed_exe_sha256": addressed,
    "verdict": verdict,
    "oracle_kind": oracle,
    "capacity": {"p99_method": p99},
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
print("[write-bundle] %s run_id=%s sha256=%s commit=%s" % (out, run_id, addressed, commit[:12]))
' "$OUT" "$PRODUCER" "$RUN_ID" "$STARTED" "$FINISHED" "$COMMIT" "$TREE" "$ADDRESSED" "$VERDICT" "$ORACLE" "$P99_METHOD"
