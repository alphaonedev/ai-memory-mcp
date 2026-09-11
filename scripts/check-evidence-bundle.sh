#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-evidence-bundle.sh — trusted-evidence contract (#3547 / N7).
#
# 1. producer-map.json is parseable; every producer.script is git-tracked
#    and exists on disk (the untracked-harness class).
# 2. Optional --bundle FILE validates a §1-minimum record:
#      - run_id present
#      - daemon_binary_sha256 == addressed_exe_sha256 (run→binary binding)
#      - PASS requires oracle_kind == independent (self-report PASS refused)
#      - capacity.p99_method is pooled_raw (mean-of-p99 refused)
#      - verdict is a closed-set enum (prose-parsed verdict refused)
#
# Usage:
#   scripts/check-evidence-bundle.sh
#   scripts/check-evidence-bundle.sh --bundle path/to/record.json
#   scripts/check-evidence-bundle.sh --self-test
#
# Scratch for --self-test lives under <repo>/.local-runs/ (never system /tmp).
# Exit: 0 clean · 1 violation · 2 usage / self-test fail.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAP="$ROOT/scripts/evidence/producer-map.json"
CLOSED_VERDICTS='PASS|PASS_ON_RETRY|EXPECTED_REFUSAL|FAIL|SKIPPED|NOT_APPLICABLE|^BLOCKED'

die() { echo "FATAL: $*" >&2; exit 1; }
usage() { echo "usage: $(basename "$0") [--bundle FILE] [--self-test]" >&2; exit 2; }

check_map() {
  local root="$1" map="$2" script tracked missing=0
  [[ -f "$map" ]] || die "producer map missing: $map"
  python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$map" \
    || die "producer map is not JSON: $map"

  while IFS= read -r script; do
    [[ -n "$script" ]] || continue
    if [[ ! -e "$root/$script" ]]; then
      echo "UNTRACKED-PRODUCER (missing on disk): $script" >&2
      missing=1
      continue
    fi
    tracked="$(git -C "$root" ls-files --error-unmatch "$script" 2>/dev/null || true)"
    if [[ -z "$tracked" ]]; then
      echo "UNTRACKED-PRODUCER (not in git ls-files): $script" >&2
      missing=1
    fi
  done < <(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
for p in doc.get("producers", []):
    print(p["script"])
' "$map")

  if [[ "$missing" -ne 0 ]]; then
    echo "FATAL: producer-map names a script that is not git-tracked" >&2
    return 1
  fi
  echo "PASS: producer-map ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["producers"]))' "$map") producers) all git-tracked"
}

# validate_bundle FILE — 0 clean, 1 violation. Prints the reason on stderr.
validate_bundle() {
  local file="$1"
  python3 - "$file" <<'PY'
import json, re, sys
path = sys.argv[1]
try:
    doc = json.load(open(path, encoding="utf-8"))
except json.JSONDecodeError as e:
    print("BUNDLE: not JSON: %s" % e, file=sys.stderr)
    sys.exit(1)
if not isinstance(doc, dict):
    print("BUNDLE: top-level must be an object", file=sys.stderr)
    sys.exit(1)

def fail(msg):
    print("BUNDLE: %s" % msg, file=sys.stderr)
    sys.exit(1)

run_id = doc.get("run_id")
if not run_id or not str(run_id).strip():
    fail("missing run_id")

daemon = str(doc.get("daemon_binary_sha256") or "")
addressed = str(doc.get("addressed_exe_sha256") or "")
hex64 = re.compile(r"^[0-9a-f]{64}$")
if not hex64.match(daemon):
    fail("daemon_binary_sha256 is not a 64-char lowercase hex digest")
if not hex64.match(addressed):
    fail("addressed_exe_sha256 is not a 64-char lowercase hex digest")
if daemon != addressed:
    fail("run→binary binding mismatch: daemon_binary_sha256 != addressed_exe_sha256")

verdict = str(doc.get("verdict") or "")
closed = re.compile(r"^(PASS|PASS_ON_RETRY|EXPECTED_REFUSAL|FAIL|SKIPPED|NOT_APPLICABLE|BLOCKED(\{.*\})?)$")
if not closed.match(verdict):
    fail("prose-parsed verdict refused: %r (closed set only)" % verdict)

oracle = str(doc.get("oracle_kind") or "")
if verdict == "PASS" and oracle != "independent":
    fail("self-report PASS refused (oracle_kind=%r, PASS requires independent)" % oracle)

capacity = doc.get("capacity") or {}
method = str(capacity.get("p99_method") or "")
if method in ("mean_of_p99", "mean-of-p99", "average_of_p99s"):
    fail("mean-of-p99 refused (p99_method=%r; use pooled_raw)" % method)
if method and method not in ("pooled_raw", "not-applicable"):
    fail("unrecognised p99_method=%r" % method)

commit = str(doc.get("source_commit") or "")
if not re.compile(r"^[0-9a-f]{40}$").match(commit):
    fail("source_commit is not a 40-char lowercase git sha")

print("PASS: bundle %s run_id=%s bound sha256=%s" % (path, run_id, daemon[:12]))
PY
}

run_self_test() {
  local tmp="$ROOT/.local-runs/evidence-bundle-selftest-$$"
  mkdir -p "$tmp"
  # RETURN, not EXIT: EXIT fires after the function's locals are gone (set -u).
  trap 'rm -rf "'"$tmp"'"' RETURN

  # (1) Live map on this tree must pass (the scripts we just added will be
  # untracked until the commit — so self-test uses a fixture map of files
  # that ARE already tracked, plus a planted untracked producer).
  local fixture_map="$tmp/producer-map.json"
  python3 -c '
import json, sys
json.dump({
    "schema_version": 1,
    "producers": [
        {"id": "collect-evidence-2921", "script": "scripts/bench/collect-evidence.sh"},
        {"id": "test-attestation", "script": "infra/do-hive/crypto/test-attestation.sh"},
        {"id": "swarm-coverage", "script": "sdk/python/swarm/coverage.py"},
    ],
}, open(sys.argv[1], "w"), indent=2)
' "$fixture_map"
  check_map "$ROOT" "$fixture_map"

  # (2) Untracked producer fails.
  python3 -c '
import json, sys
json.dump({
    "schema_version": 1,
    "producers": [
        {"id": "ghost", "script": "scripts/evidence/does-not-exist.sh"},
    ],
}, open(sys.argv[1], "w"), indent=2)
' "$tmp/ghost-map.json"
  if check_map "$ROOT" "$tmp/ghost-map.json" >/dev/null 2>"$tmp/ghost.err"; then
    echo "FAIL: self-test — untracked producer was accepted" >&2
    exit 2
  fi
  grep -q 'UNTRACKED-PRODUCER' "$tmp/ghost.err" || {
    echo "FAIL: self-test — missing UNTRACKED-PRODUCER in: $(cat "$tmp/ghost.err")" >&2
    exit 2
  }

  local sha_a sha_b
  sha_a="$(printf 'a' | shasum -a 256 | awk '{print $1}')"
  sha_b="$(printf 'b' | shasum -a 256 | awk '{print $1}')"
  local commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  write_ok() {
    python3 -c '
import json, sys
json.dump({
    "artifact_kind": "daemon",
    "producer_id": "continuity-cycle",
    "run_id": "00000000-0000-0000-0000-000000000001",
    "supersedes_run_id": None,
    "started_at_utc": "2026-09-11T00:00:00Z",
    "finished_at_utc": "2026-09-11T00:01:00Z",
    "source_commit": sys.argv[1],
    "source_tree_sha": sys.argv[1],
    "daemon_binary_sha256": sys.argv[2],
    "addressed_exe_sha256": sys.argv[2],
    "verdict": "PASS",
    "oracle_kind": "independent",
    "capacity": {"p99_method": "pooled_raw"},
}, open(sys.argv[3], "w"), indent=2)
' "$commit" "$sha_a" "$1"
  }

  write_ok "$tmp/ok.json"
  validate_bundle "$tmp/ok.json"

  # Four committed negative classes (also planted here so --self-test does
  # not depend on git add of the fixtures).
  python3 -c '
import json, sys
base = json.load(open(sys.argv[1], encoding="utf-8"))
# self-report PASS
d = dict(base); d["oracle_kind"] = "self-report"
json.dump(d, open(sys.argv[2], "w"), indent=2)
# binary mismatch
d = dict(base); d["addressed_exe_sha256"] = sys.argv[5]
json.dump(d, open(sys.argv[3], "w"), indent=2)
# mean-of-p99
d = dict(base); d["capacity"] = {"p99_method": "mean_of_p99"}
json.dump(d, open(sys.argv[4], "w"), indent=2)
# prose verdict
d = dict(base); d["verdict"] = "looks good, ship it"
json.dump(d, open(sys.argv[6], "w"), indent=2)
' "$tmp/ok.json" \
    "$tmp/neg-self-report-pass.json" \
    "$tmp/neg-binary-mismatch.json" \
    "$tmp/neg-mean-of-p99.json" \
    "$sha_b" \
    "$tmp/neg-prose-verdict.json"

  expect_fail() {
    local f="$1" needle="$2"
    if validate_bundle "$f" >/dev/null 2>"$tmp/err"; then
      echo "FAIL: self-test — $f was accepted" >&2
      exit 2
    fi
    grep -q "$needle" "$tmp/err" || {
      echo "FAIL: self-test — $f missing '$needle' in: $(cat "$tmp/err")" >&2
      exit 2
    }
  }
  expect_fail "$tmp/neg-self-report-pass.json" "self-report PASS"
  expect_fail "$tmp/neg-binary-mismatch.json" "binding mismatch"
  expect_fail "$tmp/neg-mean-of-p99.json" "mean-of-p99"
  expect_fail "$tmp/neg-prose-verdict.json" "prose-parsed verdict"

  # Committed fixtures (on-disk copies of the same four classes).
  local fx="$ROOT/scripts/evidence/fixtures"
  if [[ -d "$fx" ]]; then
    expect_fail "$fx/neg-self-report-pass.json" "self-report PASS"
    expect_fail "$fx/neg-binary-mismatch.json" "binding mismatch"
    expect_fail "$fx/neg-mean-of-p99.json" "mean-of-p99"
    expect_fail "$fx/neg-prose-verdict.json" "prose-parsed verdict"
  fi

  echo "PASS: self-test — map clean, untracked producer refused, four negative bundles refused"

  # #3543 — five fail-closed predicate fixtures (old oracle greened the
  # defect; new oracle FAILs it). Lives in predicates.py so a producer
  # and this gate cannot drift.
  python3 "$ROOT/scripts/evidence/predicates.py" --self-test
}

BUNDLE=""
SELFTEST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --self-test) SELFTEST=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [[ "$SELFTEST" -eq 1 ]]; then
  run_self_test
  exit 0
fi

check_map "$ROOT" "$MAP" || exit 1
if [[ -n "$BUNDLE" ]]; then
  validate_bundle "$BUNDLE" || exit 1
fi
