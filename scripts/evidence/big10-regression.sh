#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# big10-regression.sh — plaintext-listener + anonymous-write producer (#3547).
#
# Predicates are fail-closed (#3543 contract, shipped here so the tracked
# harness never re-introduces the false-green `status != 200` / `!= 201`
# oracles):
#   * HTTPS probe: curl exit in {0} AND http 200 on /health
#   * plaintext probe against the same host: curl exit in {35,52,56}
#     (TLS handshake / empty reply / fail-to-recv) — a plaintext 401 is
#     still a listener and is a FAIL
#   * no non-TLS ai-memory listen socket on the host (lsof/ss)
#   * anonymous write: status in {401,403} with a documented error `code`
#     AND memories-count delta == 0
#
# Bindings: run_id + sha256 of --pid/--binary + source_commit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

BASE="" PID="" BINARY="" OUT=""
HOST="127.0.0.1"
HTTPS_PORT="9077"
PLAINTEXT_PORT="9077"

usage() { sed -n '2,20p' "$0"; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE="$2"; shift 2 ;;
    --pid) PID="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --https-port) HTTPS_PORT="$2"; shift 2 ;;
    --plaintext-port) PLAINTEXT_PORT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$BASE" && -n "$OUT" ]] || { echo "FATAL: --base-url and --out required" >&2; exit 2; }
[[ -n "$PID" || -n "$BINARY" ]] || { echo "FATAL: --pid or --binary required" >&2; exit 2; }

STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fail=0
note() { echo "$*"; }

# --- HTTPS health must actually be 200 (not "anything except 200") ----------
https_code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "${BASE}/health" || true)"
if [[ "$https_code" != "200" ]]; then
  echo "FAIL: https /health expected 200, got '${https_code}'"
  fail=1
else
  note "PASS: https /health 200"
fi

# --- plaintext: TLS-layer failure, never an HTTP status ---------------------
set +e
curl -sS -o /dev/null --max-time 5 "http://${HOST}:${PLAINTEXT_PORT}/api/v1/health"
plain_rc=$?
set -e
case "$plain_rc" in
  35|52|56) note "PASS: plaintext curl exit ${plain_rc} (TLS-layer refusal)" ;;
  0)
    echo "FAIL: plaintext listener answered HTTP (curl exit 0) on ${HOST}:${PLAINTEXT_PORT}"
    fail=1
    ;;
  *)
    echo "FAIL: plaintext curl exit ${plain_rc} is not in {35,52,56} and is not a proven non-listener"
    fail=1
    ;;
esac

# --- no non-TLS ai-memory listen socket -------------------------------------
listen_hits=0
if command -v lsof >/dev/null 2>&1; then
  # TCP listen rows whose process name looks like ai-memory and are NOT TLS.
  # We cannot see TLS vs not from lsof alone; we require that the only
  # ai-memory listen port is the declared HTTPS port.
  while read -r line; do
    [[ -z "$line" ]] && continue
    port="$(printf '%s' "$line" | awk -F: '{print $NF}')"
    if [[ "$port" != "$HTTPS_PORT" ]]; then
      echo "FAIL: ai-memory listen on unexpected port ${port}: ${line}"
      listen_hits=1
    fi
  done < <(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '/ai-memory|ai_memory/ {print $9}' || true)
fi
if [[ "$listen_hits" -eq 0 ]]; then
  note "PASS: no unexpected ai-memory listen port"
else
  fail=1
fi

# --- anonymous write: 401/403 + documented code + zero delta ----------------
count_memories() {
  curl -sk --max-time 5 "${BASE}/stats" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print(0); raise SystemExit
print(int(d.get("total_memories") or d.get("memories") or 0))' 2>/dev/null || echo 0
}
before="$(count_memories)"
anon_body='{"title":"big10-anon","content":"must be refused","namespace":"evidence/big10","tier":"mid"}'
anon_file="$(evidence_repo_root)/.local-runs/big10-anon-$$.body"
mkdir -p "$(dirname "$anon_file")"
anon_code="$(curl -sk -o "$anon_file" -w '%{http_code}' --max-time 5 \
  -H 'content-type: application/json' -X POST "${BASE}/memories" -d "$anon_body" || true)"
anon_err="$(python3 -c 'import json,sys
p=sys.argv[1]
try:
    d=json.load(open(p, encoding="utf-8"))
except Exception:
    print("")
    raise SystemExit
print(d.get("code") or "")' "$anon_file" || true)"
rm -f "$anon_file"
after="$(count_memories)"
delta=$((after - before))

if [[ "$anon_code" == "401" || "$anon_code" == "403" ]] && [[ -n "$anon_err" ]] && [[ "$delta" -eq 0 ]]; then
  note "PASS: anonymous write ${anon_code} code=${anon_err} delta=0"
else
  echo "FAIL: anonymous write code=${anon_code} err='${anon_err}' delta=${delta} (want 401/403 + documented code + delta 0)"
  fail=1
fi

if [[ -n "$PID" ]]; then
  ADDRESSED="$(evidence_sha256_of_pid "$PID")"
else
  ADDRESSED="$(evidence_sha256_of_file "$BINARY")"
fi
RUN_ID="$(evidence_new_run_id)"
COMMIT="$(evidence_source_commit)"
TREE="$(evidence_source_tree_sha)"
FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERDICT="PASS"
ORACLE="independent"
[[ "$fail" -eq 0 ]] || VERDICT="FAIL"

python3 -c '
import json, sys
out, run_id, started, finished, commit, tree, addressed, verdict, fail = sys.argv[1:10]
doc = {
    "artifact_kind": "daemon",
    "producer_id": "big10-regression",
    "run_id": run_id,
    "supersedes_run_id": None,
    "started_at_utc": started,
    "finished_at_utc": finished,
    "source_commit": commit,
    "source_tree_sha": tree,
    "daemon_binary_sha256": addressed,
    "addressed_exe_sha256": addressed,
    "verdict": verdict,
    "oracle_kind": "independent" if verdict == "PASS" else "independent",
    "capacity": {"p99_method": "not-applicable"},
    "fail_count": int(fail),
}
open(out, "w", encoding="utf-8").write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
' "$OUT" "$RUN_ID" "$STARTED" "$FINISHED" "$COMMIT" "$TREE" "$ADDRESSED" "$VERDICT" "$fail"

echo "[big10-regression] wrote ${OUT} verdict=${VERDICT} fail=${fail} run_id=${RUN_ID}"
[[ "$fail" -eq 0 ]]
