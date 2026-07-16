#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# guarded-lib-test.sh — bound + self-diagnose the intermittent full-suite
# wedge tracked in issue #1989.
#
# THE PROBLEM (#1989). `AI_MEMORY_NO_CONFIG=1 cargo test --lib` (parallel,
# default threads) intermittently NEVER completes: the test process spins
# at ~130% CPU with a stuck thread set (handlers::tests + llm wiremock/perf9
# among them), ~1-in-4 on a loaded-or-idle host, invisible to CI (CI
# serialises the postgres suites on fresh runners). Deterministic serial
# runs are green; the wedge only bites *repeated local full-suite runs* —
# exactly what the Gate-3 review rounds depend on. Left unguarded it is a
# silent infinite hang with no artifact to root-cause from.
#
# THE MITIGATION (this script — the "libtest timeout wrapper" #1989 names as
# an acceptable outcome). Run the lib suite under a hard wall-clock deadline.
# On a clean finish, propagate the real exit code (byte-for-byte a normal
# `cargo test --lib` from the caller's perspective). On a wedge (deadline
# exceeded), CAPTURE the diagnostic the issue's repro recipe asks for BEFORE
# killing anything — the alive thread `comm` set (`/proc/<pid>/task/*/comm`),
# `/proc/<pid>/status`, and, when `gdb` is present, `thread apply all bt` —
# into a timestamped dir under `.local-runs/` (the project's no-/tmp scratch
# home), then reap the process group and exit 124. That converts a silent
# hang into a bounded, self-diagnosing failure and preserves the exact stack
# needed to finally root-cause #1989 on the next natural wedge.
#
# This script MITIGATES; it does not root-cause. #1989 stays OPEN until the
# captured stacks pin the deadlock. It is a diagnostic instrument, not a fix.
#
# USAGE
#   scripts/guarded-lib-test.sh [--deadline SECS] [-- <extra cargo args>]
#   scripts/guarded-lib-test.sh --self-test   # load-bearing proof (no cargo)
#
# Env:
#   GUARDED_LIB_TEST_DEADLINE   deadline seconds (default 700; --deadline wins)
#   CARGO_TEST_JOBS             value for `cargo test -j` (default: unset)
#
# Exit codes: the suite's own code on clean finish; 124 on a captured wedge;
# 2 on usage error. Mirrors the `timeout(1)` 124 convention so callers/CI can
# branch on "wedged" vs "failed".

set -uo pipefail

DEADLINE="${GUARDED_LIB_TEST_DEADLINE:-700}"
SELF_TEST=0
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --deadline)
      shift
      DEADLINE="${1:-}"
      [ -n "$DEADLINE" ] || { echo "guarded-lib-test: --deadline needs a value" >&2; exit 2; }
      shift
      ;;
    --self-test)
      SELF_TEST=1
      shift
      ;;
    --)
      shift
      EXTRA_ARGS=("$@")
      break
      ;;
    *)
      echo "guarded-lib-test: unknown arg '$1' (use --deadline SECS | --self-test | -- <cargo args>)" >&2
      exit 2
      ;;
  esac
done

case "$DEADLINE" in
  ''|*[!0-9]*) echo "guarded-lib-test: deadline must be a positive integer, got '$DEADLINE'" >&2; exit 2 ;;
esac

# Resolve the project-local scratch root (no /tmp — project hard rule).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH_ROOT="$REPO_ROOT/.local-runs"

# Capture the diagnostic for a wedged process group. $1 = the child PID
# (the process the deadline waiter is watching); $2 = the capture dir.
# Walks the child's whole descendant tree so the real libtest binary
# (`ai_memory-<hash>` under target/*/deps) is captured even when it sits a
# couple of `cargo`/shell hops below the launched PID.
capture_wedge() {
  local root_pid="$1" outdir="$2"
  mkdir -p "$outdir"

  # Breadth-first descendant walk via /proc, dependency-free (no pstree).
  local -a frontier=("$root_pid") pids=()
  while [ "${#frontier[@]}" -gt 0 ]; do
    local -a next=()
    local p
    for p in "${frontier[@]}"; do
      pids+=("$p")
      local kids
      kids="$(pgrep -P "$p" 2>/dev/null || true)"
      local k
      for k in $kids; do next+=("$k"); done
    done
    # Reassign frontier from `next`. Guard the empty case explicitly: on
    # bash < 4.4, expanding an empty array as `("${next[@]}")` under `set -u`
    # errors ("unbound variable"); bash >= 4.4 is fine, but the explicit
    # branch is portable and self-documenting.
    if [ "${#next[@]}" -gt 0 ]; then
      frontier=("${next[@]}")
    else
      frontier=()
    fi
  done

  {
    echo "# guarded-lib-test wedge capture (issue #1989)"
    echo "# deadline_secs=$DEADLINE  root_pid=$root_pid  captured_at=$(date -u +%FT%TZ 2>/dev/null || echo unknown)"
    echo "# descendant pids: ${pids[*]}"
  } > "$outdir/summary.txt"

  local pid
  for pid in "${pids[@]}"; do
    [ -d "/proc/$pid" ] || continue
    local comm; comm="$(cat "/proc/$pid/comm" 2>/dev/null || echo '?')"
    # The wedged libtest binary is the high-value target: dump its per-thread
    # comm set (the exact "alive thread" inventory #1989's recipe requests).
    {
      echo "=== pid $pid ($comm) ==="
      echo "--- /proc/$pid/task/*/comm (alive threads) ---"
      local t
      for t in /proc/"$pid"/task/*/comm; do
        [ -r "$t" ] && printf '  %s\t%s\n' "$(basename "$(dirname "$t")")" "$(cat "$t" 2>/dev/null)"
      done
      echo "--- wchan / state per thread ---"
      for t in /proc/"$pid"/task/*/stat; do
        [ -r "$t" ] || continue
        local tid; tid="$(basename "$(dirname "$t")")"
        local st; st="$(awk '{print $3}' "$t" 2>/dev/null)"
        printf '  tid=%s state=%s wchan=%s\n' "$tid" "$st" "$(cat "/proc/$pid/task/$tid/wchan" 2>/dev/null || echo '?')"
      done
    } >> "$outdir/threads.txt"
  done

  # Full native backtraces when gdb is available — this is what actually
  # pins the deadlock (which futures/locks each spinning thread is parked
  # or busy-polling on). Best-effort; absence is not a failure.
  if command -v gdb >/dev/null 2>&1; then
    # Prefer the libtest binary (comm starts with the crate name) over the
    # cargo/shell wrappers.
    local target_pid=""
    for pid in "${pids[@]}"; do
      [ -d "/proc/$pid" ] || continue
      case "$(cat "/proc/$pid/comm" 2>/dev/null || true)" in
        ai_memory-*|ai-memory-*) target_pid="$pid"; break ;;
      esac
    done
    [ -n "$target_pid" ] || target_pid="${pids[-1]}"
    echo "guarded-lib-test: dumping gdb stacks for pid $target_pid → $outdir/gdb-backtrace.txt" >&2
    gdb -batch -p "$target_pid" \
        -ex "set pagination off" \
        -ex "thread apply all bt" \
        > "$outdir/gdb-backtrace.txt" 2>&1 || \
        echo "guarded-lib-test: gdb attach failed (ptrace scope?) — thread comm set still captured" >&2
  else
    echo "guarded-lib-test: gdb not installed — captured /proc thread set only (install gdb for native stacks)" >&2
  fi
}

# Launch a command under the deadline in its own process group, capture on
# wedge, propagate its exit code on a clean finish. $1 = capture-dir label;
# rest = command to run.
run_guarded() {
  local label="$1"; shift
  # New session so we can signal the whole tree; run in background to poll.
  setsid "$@" &
  local child=$!

  local waited=0
  while kill -0 "$child" 2>/dev/null; do
    if [ "$waited" -ge "$DEADLINE" ]; then
      local outdir="$SCRATCH_ROOT/wedge-${label}-$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo now)"
      echo "guarded-lib-test: DEADLINE ${DEADLINE}s exceeded — WEDGE suspected (#1989). Capturing diagnostics → $outdir" >&2
      capture_wedge "$child" "$outdir"
      # Reap the whole group (negative pid = process group of the session leader).
      kill -TERM -"$child" 2>/dev/null || kill -TERM "$child" 2>/dev/null || true
      sleep 2
      kill -KILL -"$child" 2>/dev/null || kill -KILL "$child" 2>/dev/null || true
      wait "$child" 2>/dev/null || true
      echo "guarded-lib-test: wedge captured. Inspect $outdir/threads.txt (+ gdb-backtrace.txt) and attach to #1989." >&2
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$child"
  return $?
}

if [ "$SELF_TEST" -eq 1 ]; then
  # Load-bearing proof (mirrors the --self-test discipline of the repo's
  # other gate scripts): a deliberately-hanging child under a 3s deadline
  # must be bounded to 124 AND leave a capture with a thread dump — WITHOUT
  # touching cargo, so the proof is fast + deterministic (never needs the
  # real 1-in-4 wedge).
  echo "guarded-lib-test --self-test: bounding a synthetic hang…" >&2
  DEADLINE=3
  st=0
  run_guarded "selftest" bash -c 'exec sleep 600' || st=$?
  if [ "$st" -ne 124 ]; then
    echo "SELF-TEST FAIL: expected exit 124 on the synthetic hang, got $st" >&2
    exit 1
  fi
  latest="$(ls -1dt "$SCRATCH_ROOT"/wedge-selftest-* 2>/dev/null | head -1)"
  if [ -z "$latest" ] || [ ! -s "$latest/threads.txt" ]; then
    echo "SELF-TEST FAIL: no thread-capture artifact produced" >&2
    exit 1
  fi
  echo "guarded-lib-test --self-test: PASS (bounded to 124; captured $latest/threads.txt)" >&2
  # Clean up the synthetic artifact so it doesn't masquerade as a real wedge.
  rm -rf "$latest"
  exit 0
fi

# Real run: guard `cargo test --lib` under the deadline.
echo "guarded-lib-test: running 'cargo test --lib' under a ${DEADLINE}s wedge guard (#1989 mitigation)…" >&2
CARGO_CMD=(cargo test --lib)
[ -n "${CARGO_TEST_JOBS:-}" ] && CARGO_CMD+=(-j "$CARGO_TEST_JOBS")
[ "${#EXTRA_ARGS[@]}" -gt 0 ] && CARGO_CMD+=("${EXTRA_ARGS[@]}")

run_guarded "libtest" env AI_MEMORY_NO_CONFIG="${AI_MEMORY_NO_CONFIG:-1}" "${CARGO_CMD[@]}"
exit $?
