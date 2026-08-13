#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# collect-evidence.sh -- sanitise #2921 bench run artifacts into the committed
# evidence tree (`docs/bench/evidence-2921/`).
#
# Raw run output is written under a scratch directory that is NOT part of the
# repository. This script is the ONE path by which any of it becomes a
# committed artifact, and it is a FILTER, not a copy:
#
#   * absolute paths under the measurement user's home are rewritten to
#     `<repo-root>` / `<scratch>` -- a published evidence file must not carry
#     an operator's directory layout;
#   * anything that looks like a credential is refused OUTRIGHT (the run is
#     not published) rather than being redacted, because a redaction that
#     silently succeeds teaches the next person that the scan is decorative;
#   * only an explicit allowlist of artifact SHAPES is copied (results JSON,
#     rung JSON, the summary, host facts, and the entry node + first peer's
#     container logs) -- never a key directory, never a database, never a
#     signed-body pool, and never all 50 nodes' logs (see the line budget
#     below).
#
# The refusal list is deliberately broad: `.priv` / `api-key` / `pool*.ndjson`
# are all present in a run directory and none of them belongs in git.
#
#   scripts/bench/collect-evidence.sh --run-dir <scratch>/mesh-2921 \
#       --dest docs/bench/evidence-2921/mesh --label mesh
set -euo pipefail

RUN_DIR=""; DEST=""; LABEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$RUN_DIR" ] && [ -n "$DEST" ] && [ -n "$LABEL" ] || {
  echo "FATAL: --run-dir, --dest and --label are all required" >&2; exit 2; }
[ -d "$RUN_DIR" ] || { echo "FATAL: $RUN_DIR is not a directory" >&2; exit 2; }
mkdir -p "$DEST"

# Per-log line budget. A daemon log from a 1000-write rung with 49 peers at
# `RUST_LOG=info` runs to tens of MB, and 50 of them per rung is ~74 MB --
# which does not belong in a git tree. The HEAD carries the boot banner (the
# resolved config, the fail-closed federation WARNs, the peer count) and the
# TAIL carries the end state; the elided middle is regenerable by re-running
# the ramp, and the elision is announced in the file rather than silent.
LOG_HEAD="${EVIDENCE_LOG_HEAD:-300}"
LOG_TAIL="${EVIDENCE_LOG_TAIL:-300}"

scrub() {
  # Path scrub: home-rooted absolute paths become placeholders. Applied to
  # every published byte, JSON and log alike.
  sed -e "s#${HOME}/[^\"' ]*#<scratch>#g" \
      -e "s#/home/[A-Za-z0-9_.-]*/[^\"' ]*#<scratch>#g" \
      -e "s#/Users/[A-Za-z0-9_.-]*/[^\"' ]*#<scratch>#g"
}

# Copy the allowlisted shapes only.
copied=0
while IFS= read -r -d '' f; do
  rel="${f#"$RUN_DIR"/}"
  out="${DEST}/$(printf '%s' "$rel" | tr '/' '_')"
  case "$f" in
    *.log)
      total="$(wc -l <"$f")"
      if [ "$total" -gt $((LOG_HEAD + LOG_TAIL)) ]; then
        {
          head -n "$LOG_HEAD" "$f"
          printf '\n... [%d line(s) elided by collect-evidence.sh; head=%d tail=%d; re-run the ramp for the full log] ...\n\n' \
            "$((total - LOG_HEAD - LOG_TAIL))" "$LOG_HEAD" "$LOG_TAIL"
          tail -n "$LOG_TAIL" "$f"
        } | scrub >"$out"
      else
        scrub <"$f" >"$out"
      fi
      ;;
    *) scrub <"$f" >"$out" ;;
  esac
  copied=$((copied + 1))
done < <(find "$RUN_DIR" -maxdepth 2 \
           \( -name 'ops-*.json' -o -name 'rung-N*.json' -o -name 'summary.json' \
              -o -name 'host-facts.json' \
              -o -name 'am2921-node-01.log' -o -name 'am2921-node-02.log' \
              -o -name 'gen-mesh.json' -o -name 'mesh-manifest.json' \
              -o -name 'usl-*.txt' \) -print0)

[ "$copied" -gt 0 ] || { echo "FATAL: no allowlisted artifacts found under $RUN_DIR" >&2; exit 3; }

# Secret scan -- REFUSE, never redact. Runs over what is about to be
# committed, not over the source, so a new artifact shape cannot smuggle a
# credential past by not matching the copy allowlist's expectations.
if grep -rInE \
  'BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|Bearer [A-Za-z0-9._-]{20,}|eyJ[A-Za-z0-9._-]{30,}|"?api[_-]?key"?\s*[:=]\s*"?[A-Za-z0-9]{24,}' \
  "$DEST" ; then
  echo "FATAL: credential-shaped content in the staged evidence -- REFUSING to publish." >&2
  echo "       Nothing was deleted; inspect ${DEST} and remove the offending run." >&2
  exit 4
fi

# Residual home-path scan. The scrub above is a regex; this asserts it worked.
if grep -rIn -E '/home/[A-Za-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/' "$DEST"; then
  echo "FATAL: an absolute home path survived the scrub -- REFUSING to publish." >&2
  exit 5
fi

echo "[collect-evidence] ${copied} artifact(s) -> ${DEST} (label=${LABEL}); secret scan clean"
