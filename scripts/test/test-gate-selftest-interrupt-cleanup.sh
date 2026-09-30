#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #4292 — an INTERRUPTED gate self-test must leave nothing behind.
#
# Several scripts/check-*.sh self-tests write probe files INTO the tree (the
# gate under test scans src/ or tests/, so that is where a probe has to be).
# Without a cleanup trap, one interrupted run (a disk that fills, ^C, a
# `timeout` SIGTERM) strands the probes, and a stranded probe in src/ then
# fails OTHER gates: on 2026-09-30 it turned the #3838 landing gate's
# check-cert-removal-proof.sh --self-test red on a clean change.
#
# For each gate and each signal this starts `--self-test`, waits until a probe
# appears in `git status`, interrupts it the way it is interrupted in practice
# (SIGINT to the whole process group, like ^C; SIGTERM to the script alone,
# like timeout(1)), and asserts `git status` is exactly what it was before.
# A run in which no probe was ever seen FAILS: it interrupted nothing, so it
# proved nothing. Every in-tree path a run writes must be one the gate
# DECLARES as a probe (its "${ROOT}/...probe..." literals).
#
# Then, for every declared probe path, a file planted there first must make
# the self-test refuse (exit 2) and survive byte-identical: a probe-planting
# self-test must never overwrite or delete a file it did not create.
#
# Anything a failing gate strands is removed afterwards (only paths that
# appeared during that run), so a red run leaves the tree as it found it.
#
# Usage: scripts/test/test-gate-selftest-interrupt-cleanup.sh [gate.sh ...]
# LINUX (setsid).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

GATES=("$@")
if ((${#GATES[@]} == 0)); then
  GATES=(
    check-test-env-lock.sh
    check-test-stdin-reads.sh
    check-create-extension-allowlist.sh
    check-vendor-literals.sh
    check-const-name-literals.sh
    check-hardcoded-literals.sh
  )
fi

LOGDIR="${ROOT}/.local-runs/gate-interrupt-4292-$$"
mkdir -p "$LOGDIR"
PROBE_WAIT_SECS=120
EXIT_WAIT_SECS=${GATE_INTERRUPT_EXIT_WAIT_SECS:-30}
failures=0
n=0

porcelain() { git status --porcelain --untracked-files=all; }

# Paths in $2 (porcelain) that are not in $1.
new_paths() {
  comm -13 <(printf '%s\n' "$1" | sort) <(printf '%s\n' "$2" | sort) |
    sed -n 's/^?? //p'
}

# The in-tree probe paths a gate's self-test declares, from its source:
# every "${ROOT}/...probe..." / "...selftest..." literal, minus the shared
# helper it sources.
probe_paths() {
  grep -oE '"\$\{ROOT\}/[^"]*(probe|selftest)[^"]*"' "scripts/$1" |
    tr -d '"' | sed 's#^\${ROOT}/##' | grep -v '^scripts/lib/' | sort -u
}

run_one() {
  local gate=$1 sig=$2
  n=$((n + 1))
  local before log pid appeared="" deadline now
  before=$(porcelain)
  log="${LOGDIR}/${gate%.sh}-${sig}.log"
  # A shell starts `&` jobs with SIGINT and SIGQUIT IGNORED, and bash cannot
  # trap a signal that was ignored when it started. So restore the default
  # dispositions before exec'ing the gate, as a terminal ^C or a CI cancel
  # delivers them; otherwise SIGINT would silently test nothing.
  setsid python3 -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGQUIT, signal.SIG_DFL)
os.execvp("bash", ["bash", sys.argv[1], "--self-test"])' "scripts/${gate}" >"$log" 2>&1 &
  pid=$!
  deadline=$((SECONDS + PROBE_WAIT_SECS))
  while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do
    now=$(porcelain)
    if [[ "$now" != "$before" ]]; then
      appeared=$(new_paths "$before" "$now" | head -3 | tr '\n' ' ')
      break
    fi
    sleep 0.02
  done
  local undeclared
  undeclared=$(comm -23 <(new_paths "$before" "$(porcelain)" | sort -u) <(probe_paths "$gate"))
  if [[ -n "$undeclared" ]]; then
    echo "not ok ${n} - ${gate} ${sig}: wrote in-tree path(s) its probe list does not declare, so its guard cannot cover them: $(echo $undeclared)"
    failures=$((failures + 1))
  fi
  if [[ -z "$appeared" ]]; then
    kill -KILL -- "-$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    echo "not ok ${n} - ${gate} ${sig}: no probe ever appeared, nothing was interrupted (log: ${log})"
    failures=$((failures + 1))
    return
  fi
  if [[ "$sig" == INT ]]; then
    kill -INT -- "-$pid" 2>/dev/null
  else
    kill -TERM "$pid" 2>/dev/null
  fi
  deadline=$((SECONDS + EXIT_WAIT_SECS))
  while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.05; done
  kill -KILL -- "-$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  local rc=$?
  local after stranded
  after=$(porcelain)
  stranded=$(new_paths "$before" "$after")
  if [[ -z "$stranded" && "$after" == "$before" ]]; then
    if ((rc == 0)); then
      echo "not ok ${n} - ${gate} ${sig}: tree unchanged, but the interrupted self-test exited 0 (an interrupted run must never read as a pass)"
      failures=$((failures + 1))
      return
    fi
    echo "ok ${n} - ${gate} ${sig}: interrupted after ${appeared}; tree unchanged (rc=${rc})"
    return
  fi
  echo "not ok ${n} - ${gate} ${sig}: interrupted after ${appeared}; left behind:"
  printf '%s\n' "$stranded" | sed 's/^/    /'
  [[ "$after" == "$before" ]] || [[ -n "$stranded" ]] || echo "    (tracked files changed)"
  failures=$((failures + 1))
  # Leave the tree as it was found: remove only what this run created.
  while IFS= read -r p; do
    [[ -n "$p" ]] && rm -f -- "$p"
  done <<<"$stranded"
}

# A file ALREADY at a probe path is not the run's to touch: the self-test
# must refuse (exit 2) before planting anything and leave it byte-identical.
# One run per declared probe path, so no path's guard can be missing.
sentinel_one() {
  local gate=$1 path=$2
  n=$((n + 1))
  if [[ -e "$path" ]]; then
    echo "not ok ${n} - ${gate}: ${path} exists before the sentinel run; refusing to touch it"
    failures=$((failures + 1))
    return
  fi
  mkdir -p "$(dirname "$path")"
  printf 'SENTINEL #4292 %s %s\n' "$gate" "$$" >"$path"
  local want got rc=0 log="${LOGDIR}/${gate%.sh}-sentinel-$(basename "$path").log"
  want=$(sha256sum "$path")
  timeout 120 bash "scripts/${gate}" --self-test >"$log" 2>&1 || rc=$?
  got=$(sha256sum "$path" 2>/dev/null || echo MISSING)
  rm -f -- "$path"
  if ((rc == 2)) && [[ "$got" == "$want" ]]; then
    echo "ok ${n} - ${gate}: refuses a pre-existing ${path} (exit 2) and leaves it byte-identical"
  else
    echo "not ok ${n} - ${gate}: pre-existing ${path}: exit ${rc} (want 2), file ${got%% *} (want ${want%% *}) (log: ${log})"
    failures=$((failures + 1))
  fi
}

for g in "${GATES[@]}"; do
  [[ -f "scripts/${g}" ]] || { echo "not ok - scripts/${g} does not exist"; failures=$((failures + 1)); continue; }
  mapfile -t declared < <(probe_paths "$g")
  if ((${#declared[@]} == 0)); then
    echo "not ok - scripts/${g}: no declared probe paths found"
    failures=$((failures + 1))
    continue
  fi
  run_one "$g" INT
  run_one "$g" TERM
  for path in "${declared[@]}"; do
    sentinel_one "$g" "$path"
  done
done

echo "1..${n}"
if ((failures > 0)); then
  echo "FAIL: ${failures} of ${n} check(s) failed: an interrupted self-test left the tree changed or exited 0, or a self-test touched a file it did not create (#4292); logs: ${LOGDIR}" >&2
  exit 1
fi
rm -rf "$LOGDIR"
echo "PASS: ${n} check(s): every interrupted self-test left the tree unchanged and exited non-zero, and every pre-existing probe-path file was refused and left intact (#4292)"
