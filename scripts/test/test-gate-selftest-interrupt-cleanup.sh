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
# Anything a failing gate strands is removed afterwards, but ONLY a path the
# gate DECLARES as a probe: any other untracked file that appears during a run
# (an operator's or another agent's work in the same tree) is reported as
# unexpected and left in place. This harness never deletes a file it did not
# create.
#
# The harness must not commit the #4292 sin itself: it traps EXIT/INT/TERM,
# stops the self-test child it started, removes the sentinel it planted, and
# re-raises INT/TERM so it dies of the signal (130 / 143).
#
# Two meta cases run this script as a child (default gate list only) to prove
# both properties: a foreign untracked file created mid-run survives and is
# reported, and a TERM during the sentinel phase leaves no sentinel and exits
# 143. Test seams, used only by those cases: GATE_INTERRUPT_PHASES (run,
# sentinel, meta), GATE_INTERRUPT_HOOK (shell run once a probe has appeared,
# before the signal) and GATE_INTERRUPT_SENTINEL_HOOK (shell run after the
# sentinel is planted, before the self-test starts); GATE_INTERRUPT_CHILD
# names the script the meta cases run as the child (default: this one).
#
# Usage: scripts/test/test-gate-selftest-interrupt-cleanup.sh [gate.sh ...]
# LINUX (setsid).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

GATES=("$@")
GATES_ARGS=("$@")
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
PHASES=${GATE_INTERRUPT_PHASES:-run,sentinel,meta}
failures=0
n=0

# Everything this harness has started or planted, so EXIT/INT/TERM can undo it.
CHILD_PGIDS=()
SENTINEL_PATH=""
META_FILES=()

stop_children() {
  local g
  for g in "${CHILD_PGIDS[@]}"; do
    kill -TERM -- "-$g" 2>/dev/null
    kill -TERM "$g" 2>/dev/null
  done
  local i
  for ((i = 0; i < 100; i++)); do
    local alive=0
    for g in "${CHILD_PGIDS[@]}"; do kill -0 "$g" 2>/dev/null && alive=1; done
    ((alive)) || break
    sleep 0.05
  done
  for g in "${CHILD_PGIDS[@]}"; do
    kill -KILL -- "-$g" 2>/dev/null
    kill -KILL "$g" 2>/dev/null
  done
  CHILD_PGIDS=()
}
undo_plants() {
  stop_children
  if [[ -n "$SENTINEL_PATH" ]]; then
    rm -f -- "$SENTINEL_PATH"
    SENTINEL_PATH=""
  fi
  local f
  for f in "${META_FILES[@]}"; do rm -f -- "$f"; done
  META_FILES=()
}
on_signal() {
  local sig=$1
  trap - EXIT INT TERM
  undo_plants
  kill -"$sig" $$
}
trap undo_plants EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

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
  CHILD_PGIDS+=("$pid")
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
    echo "not ok ${n} - ${gate} ${sig}: wrote in-tree path(s) its probe list does not declare, so its guard cannot cover them (left in place): $(echo $undeclared)"
    failures=$((failures + 1))
  fi
  if [[ -z "$appeared" ]]; then
    kill -KILL -- "-$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    echo "not ok ${n} - ${gate} ${sig}: no probe ever appeared, nothing was interrupted (log: ${log})"
    failures=$((failures + 1))
    return
  fi
  [[ -n "${GATE_INTERRUPT_HOOK:-}" ]] && bash -c "$GATE_INTERRUPT_HOOK"
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
  CHILD_PGIDS=()
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
  # Split what appeared into the gate's declared probes (its to strand, ours
  # to remove) and everything else (not ours to touch).
  local declared p stranded_probes="" unexpected=""
  declared=$(probe_paths "$gate")
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if grep -qxF -- "$p" <<<"$declared"; then
      stranded_probes+="${p}"$'\n'
    else
      unexpected+="${p}"$'\n'
    fi
  done <<<"$stranded"
  if [[ -n "$stranded_probes" ]]; then
    echo "not ok ${n} - ${gate} ${sig}: interrupted after ${appeared}; left behind:"
    printf '%s' "$stranded_probes" | sed 's/^/    /'
    failures=$((failures + 1))
  fi
  if [[ -n "$unexpected" ]]; then
    echo "not ok ${n} - ${gate} ${sig}: untracked path(s) this run did not create and the gate does not declare (left in place, not deleted):"
    printf '%s' "$unexpected" | sed 's/^/    /'
    # The early undeclared check already counted this cell.
    [[ -n "$stranded_probes" || -n "$undeclared" ]] || failures=$((failures + 1))
  fi
  if [[ -z "$stranded_probes" && -z "$unexpected" ]]; then
    echo "not ok ${n} - ${gate} ${sig}: interrupted after ${appeared}; left behind:"
    echo "    (tracked files changed)"
    failures=$((failures + 1))
  fi
  # Leave the tree as it was found: remove only the gate's own declared probes.
  while IFS= read -r p; do
    [[ -n "$p" ]] && rm -f -- "$p"
  done <<<"$stranded_probes"
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
  # Armed BEFORE the file exists: an INT/TERM from here on removes it.
  SENTINEL_PATH="$path"
  printf 'SENTINEL #4292 %s %s\n' "$gate" "$$" >"$path"
  local want got rc=0 log="${LOGDIR}/${gate%.sh}-sentinel-$(basename "$path").log"
  want=$(sha256sum "$path")
  if [[ -n "${GATE_INTERRUPT_SENTINEL_HOOK:-}" ]]; then
    setsid bash -c "$GATE_INTERRUPT_SENTINEL_HOOK" &
    CHILD_PGIDS+=("$!")
    wait "$!" 2>/dev/null
    CHILD_PGIDS=()
  fi
  # Backgrounded and waited for: bash runs a trap only after a FOREGROUND
  # command ends, so a foreground self-test would delay TERM by its whole run.
  setsid timeout 120 bash "scripts/${gate}" --self-test >"$log" 2>&1 &
  CHILD_PGIDS+=("$!")
  wait "$!" 2>/dev/null
  rc=$?
  CHILD_PGIDS=()
  got=$(sha256sum "$path" 2>/dev/null || echo MISSING)
  rm -f -- "$path"
  SENTINEL_PATH=""
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
  if [[ ",${PHASES}," == *,run,* ]]; then
    run_one "$g" INT
    run_one "$g" TERM
  fi
  if [[ ",${PHASES}," == *,sentinel,* ]]; then
    for path in "${declared[@]}"; do
      sentinel_one "$g" "$path"
    done
  fi
done

# Meta cases: this script, run as a child, must itself be safe. Default gate
# list only (a child is always given explicit gates, so it cannot recurse).
META_GATE=check-create-extension-allowlist.sh
META_CHILD=${GATE_INTERRUPT_CHILD:-${BASH_SOURCE[0]}}
meta_launch() { # log, then env assignments and args
  local log=$1
  shift
  setsid env "$@" python3 -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGQUIT, signal.SIG_DFL)
os.execvp("bash", ["bash"] + sys.argv[1:])' "$META_CHILD" "$META_GATE" >"$log" 2>&1 &
}
if ((${#GATES_ARGS[@]} == 0)) && [[ ",${PHASES}," == *,meta,* ]]; then
  # M1 (r9 F1): a foreign untracked file created mid-run must survive and be
  # reported, never deleted.
  n=$((n + 1))
  foreign="tests/.foreign_4292_meta_$$.rs"
  if [[ -e "$foreign" ]]; then
    echo "not ok ${n} - meta foreign-file: ${foreign} exists before the run; refusing to touch it"
    failures=$((failures + 1))
  else
    META_FILES+=("$foreign")
    mlog="${LOGDIR}/meta-foreign.log"
    meta_launch "$mlog" GATE_INTERRUPT_PHASES=run \
      "GATE_INTERRUPT_HOOK=echo operator-work > ${foreign}"
    mpid=$!
    CHILD_PGIDS+=("$mpid")
    wait "$mpid" 2>/dev/null
    mrc=$?
    CHILD_PGIDS=()
    if [[ -f "$foreign" ]] && [[ "$(cat "$foreign")" == operator-work ]] &&
      grep -q 'left in place, not deleted' "$mlog" && ((mrc == 1)); then
      echo "ok ${n} - meta foreign-file: a foreign untracked file created mid-run survived, byte-identical, and was reported (child rc=${mrc})"
    else
      echo "not ok ${n} - meta foreign-file: file $([[ -f "$foreign" ]] && echo present || echo DELETED), child rc=${mrc} (want 1), reported=$(grep -c 'left in place, not deleted' "$mlog") (log: ${mlog})"
      failures=$((failures + 1))
    fi
    rm -f -- "$foreign"
    META_FILES=()
  fi

  # M2 (r9 F2): TERM during the sentinel phase must leave no sentinel and
  # exit 143.
  n=$((n + 1))
  mapfile -t mdecl < <(probe_paths "$META_GATE")
  msent="${mdecl[0]}"
  if [[ -e "$msent" ]]; then
    echo "not ok ${n} - meta sentinel-TERM: ${msent} exists before the run; refusing to touch it"
    failures=$((failures + 1))
  else
    mlog="${LOGDIR}/meta-sentinel-term.log"
    meta_launch "$mlog" GATE_INTERRUPT_PHASES=sentinel "GATE_INTERRUPT_SENTINEL_HOOK=sleep 20"
    mpid=$!
    CHILD_PGIDS+=("$mpid")
    mdeadline=$((SECONDS + 60))
    while [[ ! -e "$msent" ]] && kill -0 "$mpid" 2>/dev/null && ((SECONDS < mdeadline)); do sleep 0.02; done
    # Let the harness reach its hook (the sentinel is written just before it).
    sleep 0.3
    planted=no
    [[ -e "$msent" ]] && planted=yes
    kill -TERM "$mpid" 2>/dev/null
    mdeadline=$((SECONDS + 30))
    while kill -0 "$mpid" 2>/dev/null && ((SECONDS < mdeadline)); do sleep 0.05; done
    wait "$mpid" 2>/dev/null
    mrc=$?
    CHILD_PGIDS=()
    left=no
    [[ -e "$msent" ]] && left=yes
    if [[ "$planted" == yes && "$left" == no ]] && ((mrc == 143)); then
      echo "ok ${n} - meta sentinel-TERM: TERM during the sentinel phase left no sentinel and exited 143"
    else
      echo "not ok ${n} - meta sentinel-TERM: sentinel planted=${planted}, stranded after TERM=${left}, child rc=${mrc} (want 143) (log: ${mlog})"
      failures=$((failures + 1))
    fi
    rm -f -- "$msent"
  fi
fi

echo "1..${n}"
if ((failures > 0)); then
  echo "FAIL: ${failures} of ${n} check(s) failed: an interrupted self-test left the tree changed or exited 0, or a self-test touched a file it did not create (#4292); logs: ${LOGDIR}" >&2
  exit 1
fi
rm -rf "$LOGDIR"
echo "PASS: ${n} check(s): every interrupted self-test left the tree unchanged and exited non-zero, and every pre-existing probe-path file was refused and left intact (#4292)"
