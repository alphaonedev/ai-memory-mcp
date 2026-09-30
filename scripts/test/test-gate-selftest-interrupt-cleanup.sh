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
# Anything a failing gate strands is removed afterwards, but ONLY paths that
# appeared during that run AND are declared probe paths of that gate. Any
# other new path is reported and left in place: it may be someone else's
# work in the same tree (r9 F1 on #4292).
#
# The harness applies the same rule to itself (r9 F2): if IT is interrupted
# (^C, a CI cancel, timeout), it stops the self-test it started and removes
# the sentinel file it planted, then dies of the signal, so an interrupted
# harness never strands a file at a real probe path.
#
# Usage: scripts/test/test-gate-selftest-interrupt-cleanup.sh [gate.sh ...]
#        scripts/test/test-gate-selftest-interrupt-cleanup.sh --harness-self-test
# LINUX (setsid).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# What this harness has running or planted right now, so an interrupt can
# undo exactly that and nothing else.
CHILD_SESSION=""   # a setsid'd self-test: its pid is its process group id
CHILD_PID=""       # a sentinel-phase self-test (not setsid'd)
CUR_SENTINEL=""    # a sentinel file this harness planted

harness_cleanup() {
  if [[ -n "$CHILD_SESSION" ]]; then
    kill -TERM -- "-$CHILD_SESSION" 2>/dev/null
    local i
    for i in $(seq 1 100); do kill -0 "$CHILD_SESSION" 2>/dev/null || break; sleep 0.05; done
    kill -KILL -- "-$CHILD_SESSION" 2>/dev/null
    wait "$CHILD_SESSION" 2>/dev/null
    CHILD_SESSION=""
  fi
  if [[ -n "$CHILD_PID" ]]; then
    kill -TERM "$CHILD_PID" 2>/dev/null
    wait "$CHILD_PID" 2>/dev/null
    CHILD_PID=""
  fi
  if [[ -n "$CUR_SENTINEL" ]]; then
    rm -f -- "$CUR_SENTINEL"
    CUR_SENTINEL=""
  fi
}
trap harness_cleanup EXIT
trap 'harness_cleanup; trap - INT; kill -INT $$' INT
trap 'harness_cleanup; trap - TERM; kill -TERM $$' TERM

if [[ "${1:-}" == --harness-self-test ]]; then
  HARNESS_SELF_TEST=1
  shift
else
  HARNESS_SELF_TEST=0
fi

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
  CHILD_SESSION=$pid
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
    CHILD_SESSION=""
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
  CHILD_SESSION=""
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
  # Remove only what the GATE stranded: a new path that is also one of its
  # declared probe paths. Any other new path is not provably the run's (it
  # may be someone's work in this tree), so it is reported and left (r9 F1).
  local declared kept
  declared=$(probe_paths "$gate")
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if grep -qxF -- "$p" <<<"$declared"; then
      rm -f -- "$p"
    else
      kept="${kept:-}    ${p}"$'\n'
    fi
  done <<<"$stranded"
  if [[ -n "${kept:-}" ]]; then
    echo "    left in place (not a declared probe path of ${gate}, so not provably this run's):"
    printf '%s' "$kept"
  fi
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
  # Registered BEFORE it exists, so an interrupt at any point removes it.
  CUR_SENTINEL=$path
  printf 'SENTINEL #4292 %s %s\n' "$gate" "$$" >"$path"
  local want got rc=0 log="${LOGDIR}/${gate%.sh}-sentinel-$(basename "$path").log"
  want=$(sha256sum "$path")
  # In the background and waited for: bash defers a trap until a FOREGROUND
  # command returns, which would hold an interrupt for up to 120 s.
  timeout 120 bash "scripts/${gate}" --self-test >"$log" 2>&1 &
  CHILD_PID=$!
  wait "$CHILD_PID" || rc=$?
  CHILD_PID=""
  got=$(sha256sum "$path" 2>/dev/null || echo MISSING)
  rm -f -- "$path"
  CUR_SENTINEL=""
  if ((rc == 2)) && [[ "$got" == "$want" ]]; then
    echo "ok ${n} - ${gate}: refuses a pre-existing ${path} (exit 2) and leaves it byte-identical"
  else
    echo "not ok ${n} - ${gate}: pre-existing ${path}: exit ${rc} (want 2), file ${got%% *} (want ${want%% *}) (log: ${log})"
    failures=$((failures + 1))
  fi
}

# --harness-self-test: the harness's OWN two properties (r9 on #4292), run
# against HARNESS_UNDER_TEST (default: this file) on one real gate.
#   F1: a file someone creates in the tree mid-run is reported, never deleted.
#   F2: a harness killed by SIGTERM in its sentinel phase leaves no sentinel.
if ((HARNESS_SELF_TEST)); then
  H="${HARNESS_UNDER_TEST:-scripts/test/test-gate-selftest-interrupt-cleanup.sh}"
  G=check-vendor-literals.sh
  mapfile -t gdecl < <(probe_paths "$G")
  st_fail=0
  st_n=0
  st_log="${LOGDIR}/harness-self-test.log"

  # F1. The user file must appear AFTER the harness's baseline snapshot, so
  # the cell retries with a longer delay until the harness's output shows it
  # saw the file; a run where it did not is not counted either way.
  st_n=$((st_n + 1))
  user="src/.harness-4292-user-file-$$.rs"
  exercised=0 survived=0
  for delay in 0.3 0.6 1.0 1.5; do
    [[ -e "$user" ]] && { echo "not ok ${st_n} - F1: ${user} already exists"; st_fail=$((st_fail + 1)); break; }
    bash "$H" "$G" >"$st_log" 2>&1 &
    hp=$!
    sleep "$delay"
    printf 'user work, not the harness %s\n' "$$" >"$user"
    wait "$hp"
    if grep -qF -- "$user" "$st_log"; then
      exercised=1
      [[ -f "$user" ]] && grep -q 'user work, not the harness' "$user" && survived=1
      rm -f -- "$user"
      break
    fi
    rm -f -- "$user"
  done
  if ((exercised && survived)); then
    echo "ok ${st_n} - F1: a file created mid-run by someone else was reported and left in place"
  elif ((exercised)); then
    echo "not ok ${st_n} - F1: the harness DELETED a file it did not create (${user})"
    st_fail=$((st_fail + 1))
  else
    echo "not ok ${st_n} - F1: never exercised (the harness never saw the file; log: ${st_log})"
    st_fail=$((st_fail + 1))
  fi

  # F2. Wait until a sentinel is planted, then SIGTERM the harness.
  st_n=$((st_n + 1))
  st_before=$(porcelain)
  bash "$H" "$G" >"$st_log" 2>&1 &
  hp=$!
  planted=""
  deadline=$((SECONDS + 300))
  while kill -0 "$hp" 2>/dev/null && ((SECONDS < deadline)) && [[ -z "$planted" ]]; do
    for q in "${gdecl[@]}"; do
      if [[ -f "$q" ]] && grep -q '^SENTINEL #4292' "$q" 2>/dev/null; then planted=$q; break; fi
    done
    sleep 0.01
  done
  if [[ -z "$planted" ]]; then
    kill -TERM "$hp" 2>/dev/null
    wait "$hp" 2>/dev/null
    echo "not ok ${st_n} - F2: no sentinel was ever planted, nothing was interrupted (log: ${st_log})"
    st_fail=$((st_fail + 1))
  else
    kill -TERM "$hp" 2>/dev/null
    deadline=$((SECONDS + 30))
    while kill -0 "$hp" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.05; done
    wait "$hp" 2>/dev/null
    hrc=$?
    left=""
    for q in "${gdecl[@]}"; do [[ -e "$q" ]] && left="${left} ${q}"; done
    if [[ -z "$left" && "$(porcelain)" == "$st_before" ]] && ((hrc != 0)); then
      echo "ok ${st_n} - F2: SIGTERM during the sentinel phase (${planted}) left the tree unchanged (rc=${hrc})"
    else
      echo "not ok ${st_n} - F2: SIGTERM during the sentinel phase stranded:${left:- (tree changed)} (rc=${hrc})"
      st_fail=$((st_fail + 1))
      # Leave the tree as found: only files carrying the harness's sentinel mark.
      for q in "${gdecl[@]}"; do
        [[ -f "$q" ]] && grep -q '^SENTINEL #4292' "$q" 2>/dev/null && rm -f -- "$q"
      done
    fi
  fi

  echo "1..${st_n}"
  if ((st_fail > 0)); then
    echo "FAIL: ${st_fail} of ${st_n} harness self-test(s) failed (#4292 r9); logs: ${LOGDIR}" >&2
    exit 1
  fi
  rm -rf "$LOGDIR"
  echo "PASS: the harness never deletes a file it did not create, and never strands its own sentinel (#4292 r9)"
  exit 0
fi

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
