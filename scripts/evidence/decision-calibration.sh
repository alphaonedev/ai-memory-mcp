#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# decision-calibration.sh — evidence producer for the `[decision]` provider
# calibration harness (#3806 W5; folds into the #3564 / #3570 harness family).
#
# What it does, in order:
#   1. INDEPENDENTLY verifies the preregistered held-out sets against
#      `MANIFEST.sha256` with the system sha256 tool — a second reader of the
#      same preregistration that does not share a line of code with the Rust
#      harness, so a bug in one cannot certify the other.
#   2. Runs the harness (`cargo test --test decision_calibration_gate`), which
#      renders the report from a CLOSED VOCABULARY into --out.
#   3. Writes a §1-minimum evidence bundle with COMPUTED bindings via
#      scripts/evidence/write-bundle.sh --binary <the test binary that ran>.
#   4. Validates that bundle with scripts/check-evidence-bundle.sh.
#
# The report carries `source_commit` and `fixture_manifest_sha256`, so every
# figure names both the tree and the held-out set that produced it.
#
# Usage:
#   scripts/evidence/decision-calibration.sh [--out DIR] [--fixture-dir DIR]
#   scripts/evidence/decision-calibration.sh --self-test
#
# --fixture-dir points the harness at an OPERATOR's own preregistered corpus
# (their `<seam>.heldout.jsonl` files plus their own `MANIFEST.sha256`); the
# report then records `fixture_dir_kind: operator_supplied`, so a customer's
# numbers are never mistaken for the in-repo synthetic controls.
#
# Outputs (default `<repo>/.local-runs/decision-calibration/`, gitignored):
#   decision-calibration.json   the report
#   bundle.json                 the evidence bundle
#
# Exit: 0 clean · 1 the harness or the bundle check refused · 2 usage.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
ROOT="$(evidence_repo_root)"

PRODUCER_ID="decision-calibration"
TEST_TARGET="decision_calibration_gate"
FIXTURES_DEFAULT="$ROOT/tests/fixtures/decision-calibration"
OUT_DIR="$ROOT/.local-runs/decision-calibration"
FIXTURE_DIR=""
SELF_TEST=0

usage() { sed -n '2,30p' "$0" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2 ;;
    --fixture-dir) FIXTURE_DIR="$2"; shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

# --- 1. independent preregistration check ----------------------------------
# Re-hash every listed fixture with the system tool. Refuses on drift in either
# direction: a listed file whose bytes moved, a listed file that vanished, or a
# `.jsonl` on disk that nobody preregistered.
verify_manifest_independently() {
  local dir="$1" manifest="$1/MANIFEST.sha256" rc=0 name digest actual listed
  if [[ ! -f "$manifest" ]]; then
    echo "REFUSED: no MANIFEST.sha256 in $dir (held-out sets must be preregistered)" >&2
    return 1
  fi
  listed=""
  while read -r digest name; do
    [[ -n "${digest:-}" ]] || continue
    if [[ ! -f "$dir/$name" ]]; then
      echo "REFUSED: MANIFEST.sha256 names $name, which is not on disk" >&2
      rc=1
      continue
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum -b "$dir/$name" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "$dir/$name" | awk '{print $1}')"
    fi
    if [[ "$actual" != "$digest" ]]; then
      echo "REFUSED: $name does not match its preregistered sha256" >&2
      rc=1
    fi
    listed="$listed $name"
  done < "$manifest"
  for path in "$dir"/*.jsonl; do
    [[ -e "$path" ]] || continue
    name="$(basename "$path")"
    case " $listed " in
      *" $name "*) ;;
      *) echo "REFUSED: $name is present but not preregistered" >&2; rc=1 ;;
    esac
  done
  return "$rc"
}

# --- --self-test: prove the independent check is load-bearing ---------------
if [[ "$SELF_TEST" -eq 1 ]]; then
  scratch="$ROOT/.local-runs/decision-calibration-selftest-$$"
  # RETURN would not fire here (top level); clean up on EXIT instead.
  trap 'rm -rf "$scratch"' EXIT
  mkdir -p "$scratch"
  cp "$FIXTURES_DEFAULT"/* "$scratch/"
  verify_manifest_independently "$scratch" >/dev/null \
    || { echo "FAIL: self-test — a clean copy did not verify" >&2; exit 2; }
  printf '\n' >> "$scratch/classify_kind.heldout.jsonl"
  if verify_manifest_independently "$scratch" >/dev/null 2>&1; then
    echo "FAIL: self-test — a mutated held-out set was accepted" >&2
    exit 2
  fi
  cp "$FIXTURES_DEFAULT/classify_kind.heldout.jsonl" "$scratch/"
  cp "$FIXTURES_DEFAULT/classify_kind.heldout.jsonl" "$scratch/extra.jsonl"
  if verify_manifest_independently "$scratch" >/dev/null 2>&1; then
    echo "FAIL: self-test — an unpreregistered held-out set was accepted" >&2
    exit 2
  fi
  echo "PASS: self-test — mutated and unpreregistered held-out sets both refused"
  exit 0
fi

CORPUS="${FIXTURE_DIR:-$FIXTURES_DEFAULT}"
verify_manifest_independently "$CORPUS"
echo "PASS: preregistration verified independently ($CORPUS)"

# --- 2. run the harness -----------------------------------------------------
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/decision-calibration.json"
BUNDLE="$OUT_DIR/bundle.json"
COMMIT="$(evidence_source_commit)"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

export AI_MEMORY_CALIBRATION_REPORT_OUT="$REPORT"
export AI_MEMORY_CALIBRATION_SOURCE_COMMIT="$COMMIT"
[[ -n "$FIXTURE_DIR" ]] && export AI_MEMORY_CALIBRATION_FIXTURE_DIR="$FIXTURE_DIR"

# Build first so the binary path can be read from cargo, not guessed.
BIN="$(cargo test --test "$TEST_TARGET" --no-run --message-format=json 2>/dev/null \
  | python3 -c '
import json, sys
path = ""
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
        path = msg["executable"]
print(path)
')"
[[ -n "$BIN" && -x "$BIN" ]] || { echo "FATAL: could not resolve the harness binary" >&2; exit 1; }

cargo test --test "$TEST_TARGET" -- --nocapture
[[ -f "$REPORT" ]] || { echo "FATAL: the harness produced no report" >&2; exit 1; }

VERDICT="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["verdict"])
' "$REPORT")"

# --- 3 + 4. bind and validate ----------------------------------------------
"$HERE/write-bundle.sh" \
  --out "$BUNDLE" \
  --producer "$PRODUCER_ID" \
  --binary "$BIN" \
  --verdict "$VERDICT" \
  --oracle-kind independent \
  --p99-method not-applicable \
  --started-at "$STARTED"

"$ROOT/scripts/check-evidence-bundle.sh" --bundle "$BUNDLE"

python3 -c '
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
print("report  commit=%s manifest=%s seed=%s verdict=%s"
      % (doc["source_commit"][:12], doc["fixture_manifest_sha256"][:12],
         doc["seed"], doc["verdict"]))
for s in doc["seams"]:
    print("  %-40s brier=%-10s ece=%-10s p95=%-10s cov=%-9s gate=%s (%s)"
          % (s["fixture_file"], s["provider"]["brier"], s["provider"]["ece"],
             s["provider"]["ece_bootstrap_p95"], s["coverage"],
             s["gate"]["verdict"], s["expectation"]))
' "$REPORT"
