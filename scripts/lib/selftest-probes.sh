# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #4292 — probe hygiene for gate self-tests that must plant files INSIDE the
# tree (the gate under test scans src/ or tests/, so a probe has to be there).
#
# A probe stranded by an interrupted self-test (a disk that fills, ^C, a
# timeout or CI-cancel SIGTERM) is not harmless: a stray file in src/ fails
# OTHER gates. On 2026-09-30 one turned the #3838 landing gate's
# check-cert-removal-proof.sh --self-test red on a clean change.
#
# Usage, after the self-test's own "probe already exists" refusal (so a file
# the run did not create is never deleted):
#
#   source "${ROOT}/scripts/lib/selftest-probes.sh"
#   selftest_probes_arm "$probe_a" "$probe_b"
#   ... write probes ...
#   selftest_run gate_output gate_exit "$0"   # the long gate run
#   selftest_probes_disarm                     # normal-path cleanup
#
# On EXIT, INT or TERM every registered probe is removed and a running gate
# child is stopped. INT and TERM are then RE-RAISED, so an interrupted
# self-test dies of the signal (130 / 143) and never reads as a pass.
# The gate child runs in the background and is waited for, because bash
# defers a trap until a FOREGROUND command returns: under `$("$0")` a SIGTERM
# would wait out the whole gate run, long past a CI cancel's SIGKILL.
#
# Residual: SIGKILL cannot be trapped, so a SIGKILLed self-test (an OOM kill,
# or a CI runner that escalates past SIGTERM) still strands its probes. The
# refusal above then makes the NEXT self-test exit 2 instead of silently
# overwriting them; remove the named probe file by hand.

_selftest_probes=()
_selftest_child=""
_selftest_out=""

selftest_cleanup () {
    if [[ -n "$_selftest_child" ]]; then
        kill -TERM "$_selftest_child" 2>/dev/null
        wait "$_selftest_child" 2>/dev/null
        _selftest_child=""
    fi
    if ((${#_selftest_probes[@]} > 0)); then
        rm -f -- "${_selftest_probes[@]}"
    fi
    if [[ -n "$_selftest_out" ]]; then
        rm -f -- "$_selftest_out"
        _selftest_out=""
    fi
}

# selftest_probes_arm <path>... — register probes and install the traps.
selftest_probes_arm () {
    _selftest_probes+=("$@")
    trap selftest_cleanup EXIT
    trap 'selftest_cleanup; trap - INT; kill -INT $$' INT
    trap 'selftest_cleanup; trap - TERM; kill -TERM $$' TERM
}

# selftest_run <out-var> <rc-var> <cmd> [args...] — run <cmd> in the
# background with stdout+stderr captured, wait for it interruptibly, then set
# <out-var> to its output and <rc-var> to its exit status. Safe under set -e.
selftest_run () {
    local _out_var=$1 _rc_var=$2
    shift 2
    local _dir
    _dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.local-runs"
    mkdir -p "$_dir"
    _selftest_out="$(mktemp "${_dir}/selftest-out.XXXXXX")"
    "$@" >"$_selftest_out" 2>&1 &
    _selftest_child=$!
    local _rc=0
    wait "$_selftest_child" || _rc=$?
    _selftest_child=""
    printf -v "$_out_var" '%s' "$(cat "$_selftest_out")"
    printf -v "$_rc_var" '%s' "$_rc"
    rm -f -- "$_selftest_out"
    _selftest_out=""
}

# selftest_probes_disarm — normal-path cleanup, then drop the traps.
selftest_probes_disarm () {
    selftest_cleanup
    _selftest_probes=()
    trap - EXIT INT TERM
}
