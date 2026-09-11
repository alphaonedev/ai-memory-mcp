#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-cert-leg-nonvacuity.sh — certified-pin executed-vs-listed ratchet
# (#3552 / N24). FAIL-CLOSED.
#
# THE DEFECT CLASS. `cert-postgres-age.yml` and `postgres-ignored.yml`
# ran the claimed cargo invocation and went green when that invocation
# executed 0 tests (or when every live_pg() cell soft-skipped on
# connect failure). A merge-blocking context that reports success
# while doing nothing is the #2444 shape.
#
# THIS SCRIPT is the non-vacuity half of #3552 (the other half is
# declaring those job names as required contexts). It reads a cargo
# test log and:
#
#   1. Sums executed = passed + failed across every `test result:` line.
#   2. FAILS if any line carries the house `skip:` token (live_pg()
#      connect-failure / #3247 item 3 / #3298 silent-PASS). In a cert
#      leg the URL is set; a skip is a broken tier, not an opt-out.
#   3. FAILS if executed < --listed (cargo test -- --list under the
#      same features/filters). Tests that were advertised did not run.
#   4. FAILS if executed < the committed ratchet floor for --leg.
#      Lowering the floor requires cert-leg-executed-allow.txt with
#      an issue link.
#
# Usage:
#   scripts/check-cert-leg-nonvacuity.sh --leg NAME --log FILE [--listed N]
#   scripts/check-cert-leg-nonvacuity.sh --self-test
#
# Exit: 0 clean · 1 vacuous / skip / under-ratchet · 2 usage / self-test.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RATCHET_FILE="${CERT_LEG_RATCHET_FILE:-$ROOT/scripts/qc-allowlists/cert-leg-executed-ratchet.txt}"
ALLOW_FILE="${CERT_LEG_ALLOW_FILE:-$ROOT/scripts/qc-allowlists/cert-leg-executed-allow.txt}"

strip_csi() {
    # GitHub Actions colourises cargo even when piped.
    sed $'s/\x1b\\[[0-9;]*m//g'
}

read_list() {
    local file="$1" line
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//')" in
            '' | '#'*) continue ;;
        esac
        printf '%s\n' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
    done < "$file"
}

ratchet_floor() {
    local leg="$1" id floor
    while read -r id floor _; do
        [ "$id" = "$leg" ] || continue
        printf '%s' "$floor"
        return 0
    done < <(read_list "$RATCHET_FILE")
    return 1
}

allow_floor() {
    local leg="$1" id new date ref
    while read -r id new date ref _; do
        [ "$id" = "$leg" ] || continue
        printf '%s %s %s' "$new" "$date" "$ref"
        return 0
    done < <(read_list "$ALLOW_FILE")
    return 1
}

count_listed_from_list_output() {
    # `cargo test -- --list` prints `<path>: test` per unit.
    local n=0
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(printf '%s' "$line" | strip_csi)"
        case "$line" in
            *': test') n=$((n + 1)) ;;
        esac
    done
    printf '%s' "$n"
}

parse_log() {
    # Sets: EXECUTED SKIP_COUNT SKIP_SAMPLE
    local log="$1" line passed failed
    EXECUTED=0
    SKIP_COUNT=0
    SKIP_SAMPLE=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(printf '%s' "$line" | strip_csi | tr -d '\r')"
        case "$line" in
            *skip:*)
                SKIP_COUNT=$((SKIP_COUNT + 1))
                [ -n "$SKIP_SAMPLE" ] || SKIP_SAMPLE="$line"
                ;;
        esac
        case "$line" in
            *'test result:'*)
                passed="$(printf '%s' "$line" | sed -n 's/.*test result:.* \([0-9][0-9]*\) passed;.*/\1/p')"
                failed="$(printf '%s' "$line" | sed -n 's/.* \([0-9][0-9]*\) failed;.*/\1/p')"
                [ -n "$passed" ] || passed=0
                [ -n "$failed" ] || failed=0
                EXECUTED=$((EXECUTED + passed + failed))
                ;;
        esac
    done < "$log"
}

check_allow_ledger() {
    local line id new date ref
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        read -r id new date ref _ <<< "$line"
        if [ -z "$id" ] || [ -z "$new" ] \
            || [[ ! "$new" =~ ^[0-9]+$ ]] \
            || [[ ! "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
            || [[ ! "$ref" =~ ^#[0-9]+$ ]]; then
            echo "❌ cert-leg-nonvacuity: ALLOW LEDGER MALFORMED — '$line' in $ALLOW_FILE." >&2
            echo "     Every entry MUST be '<leg-id> <new-floor> YYYY-MM-DD #<issue>'." >&2
            return 1
        fi
        local floor=""
        floor="$(ratchet_floor "$id" || true)"
        if [ -z "$floor" ]; then
            echo "❌ cert-leg-nonvacuity: ALLOW LEDGER STALE — '$id' is not a ratchet leg." >&2
            return 1
        fi
        if [ "$new" -ge "$floor" ]; then
            echo "❌ cert-leg-nonvacuity: ALLOW LEDGER STALE — '$id' new-floor $new is not below ratchet $floor. Delete the entry after the ratchet drop lands." >&2
            return 1
        fi
    done < <(read_list "$ALLOW_FILE")
    return 0
}

run_gate() {
    local leg="$1" log="$2" listed="${3:-}"
    local floor effective allow_line allow_new allow_date allow_ref

    if [ ! -f "$log" ]; then
        echo "❌ cert-leg-nonvacuity: log missing: $log" >&2
        return 1
    fi
    if ! floor="$(ratchet_floor "$leg")"; then
        echo "❌ cert-leg-nonvacuity: unknown --leg '$leg' (not in $RATCHET_FILE)." >&2
        return 1
    fi
    if ! [[ "$floor" =~ ^[0-9]+$ ]]; then
        echo "❌ cert-leg-nonvacuity: ratchet floor for '$leg' is not an integer: '$floor'" >&2
        return 1
    fi
    check_allow_ledger || return 1

    effective="$floor"
    if allow_line="$(allow_floor "$leg")"; then
        read -r allow_new allow_date allow_ref <<< "$allow_line"
        effective="$allow_new"
        echo "⚠️  cert-leg-nonvacuity: '$leg' floor lowered $floor → $effective by $ALLOW_FILE ($allow_date $allow_ref)" >&2
    fi

    parse_log "$log"

    local fail=0
    if [ "$SKIP_COUNT" -gt 0 ]; then
        echo "❌ cert-leg-nonvacuity: $SKIP_COUNT skip: line(s) in $leg (live_pg-style connect failure / silent PASS is FAIL in a cert leg; #3247 item 3 / #3298)." >&2
        echo "     first: $SKIP_SAMPLE" >&2
        fail=1
    fi
    if [ -n "$listed" ]; then
        if ! [[ "$listed" =~ ^[0-9]+$ ]]; then
            echo "❌ cert-leg-nonvacuity: --listed is not an integer: '$listed'" >&2
            return 2
        fi
        if [ "$EXECUTED" -lt "$listed" ]; then
            echo "❌ cert-leg-nonvacuity: $leg executed $EXECUTED < listed $listed (cargo test -- --list under the claimed features)." >&2
            fail=1
        fi
    fi
    if [ "$EXECUTED" -lt "$effective" ]; then
        echo "❌ cert-leg-nonvacuity: $leg executed $EXECUTED < ratchet floor $effective (committed $floor in $RATCHET_FILE)." >&2
        echo "     A cert leg that executes fewer tests than the floor is the pre-#3552 silent-green class. Lowering the floor requires an allowlist entry with an issue link." >&2
        fail=1
    fi
    if [ "$fail" -ne 0 ]; then
        return 1
    fi
    echo "check-cert-leg-nonvacuity: OK ($leg executed=$EXECUTED listed=${listed:-n/a} floor=$effective skip=0)"
    return 0
}

self_test() {
    local scratch
    scratch="$ROOT/.local-runs/cert-leg-nonvacuity-selftest-$$"
    mkdir -p "$scratch"
    # shellcheck disable=SC2064
    trap "rm -rf '$scratch'" EXIT

    local saved_r="$RATCHET_FILE" saved_a="$ALLOW_FILE"
    RATCHET_FILE="$scratch/ratchet.txt"
    ALLOW_FILE="$scratch/allow.txt"
    printf 'demo-leg 10\n' >"$RATCHET_FILE"
    : >"$ALLOW_FILE"

    printf 'test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' >"$scratch/ok.log"
    if ! run_gate demo-leg "$scratch/ok.log" 10 >/dev/null; then
        echo "SELF-TEST FAIL: equal executed/listed/floor should pass" >&2
        return 2
    fi
    echo "SELF-TEST PASS: equal executed/listed/floor"

    printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out\n' >"$scratch/zero.log"
    if run_gate demo-leg "$scratch/zero.log" 0 >/dev/null 2>"$scratch/zero.err"; then
        echo "SELF-TEST FAIL: 0 executed under a floor of 10 passed" >&2
        return 2
    fi
    grep -q 'executed 0 < ratchet floor 10' "$scratch/zero.err" || {
        echo "SELF-TEST FAIL: 0-exec rejection did not name the ratchet. Was:" >&2
        cat "$scratch/zero.err" >&2
        return 2
    }
    echo "SELF-TEST PASS: 0 executed under floor is FAIL"

    printf 'skip: AI_MEMORY_TEST_POSTGRES_URL not set\ntest result: ok. 10 passed; 0 failed; 0 ignored\n' >"$scratch/skip.log"
    if run_gate demo-leg "$scratch/skip.log" 10 >/dev/null 2>"$scratch/skip.err"; then
        echo "SELF-TEST FAIL: skip: line passed" >&2
        return 2
    fi
    grep -q 'skip: line' "$scratch/skip.err" || {
        echo "SELF-TEST FAIL: skip rejection did not name skip:. Was:" >&2
        cat "$scratch/skip.err" >&2
        return 2
    }
    echo "SELF-TEST PASS: skip: token is FAIL"

    printf 'test result: ok. 4 passed; 0 failed; 0 ignored\n' >"$scratch/under-listed.log"
    if run_gate demo-leg "$scratch/under-listed.log" 10 >/dev/null 2>"$scratch/under-listed.err"; then
        echo "SELF-TEST FAIL: executed < listed passed" >&2
        return 2
    fi
    grep -q 'executed 4 < listed 10' "$scratch/under-listed.err" || {
        echo "SELF-TEST FAIL: listed rejection did not name both counts. Was:" >&2
        cat "$scratch/under-listed.err" >&2
        return 2
    }
    echo "SELF-TEST PASS: executed < listed is FAIL"

    printf 'demo-leg 3 2026-09-11 #3552 deliberate drop for self-test\n' >"$ALLOW_FILE"
    printf 'test result: ok. 4 passed; 0 failed; 0 ignored\n' >"$scratch/allowed.log"
    if ! run_gate demo-leg "$scratch/allowed.log" 4 >/dev/null 2>"$scratch/allowed.err"; then
        echo "SELF-TEST FAIL: allowlisted drop should pass. Was:" >&2
        cat "$scratch/allowed.err" >&2
        return 2
    fi
    echo "SELF-TEST PASS: allowlisted floor drop"

    printf 'demo-leg 3 not-a-date #3552\n' >"$ALLOW_FILE"
    if run_gate demo-leg "$scratch/ok.log" 10 >/dev/null 2>"$scratch/malformed.err"; then
        echo "SELF-TEST FAIL: malformed allow entry passed" >&2
        return 2
    fi
    grep -q 'ALLOW LEDGER MALFORMED' "$scratch/malformed.err" || {
        echo "SELF-TEST FAIL: malformed allow did not name MALFORMED. Was:" >&2
        cat "$scratch/malformed.err" >&2
        return 2
    }
    echo "SELF-TEST PASS: malformed allow entry is FAIL"

    printf 'demo-leg 99 2026-09-11 #3552\n' >"$ALLOW_FILE"
    if run_gate demo-leg "$scratch/ok.log" 10 >/dev/null 2>"$scratch/stale.err"; then
        echo "SELF-TEST FAIL: stale allow (new-floor >= ratchet) passed" >&2
        return 2
    fi
    grep -q 'ALLOW LEDGER STALE' "$scratch/stale.err" || {
        echo "SELF-TEST FAIL: stale allow did not name STALE. Was:" >&2
        cat "$scratch/stale.err" >&2
        return 2
    }
    echo "SELF-TEST PASS: stale allow entry is FAIL"

    : >"$ALLOW_FILE"
    printf '\x1b[32mtest result: ok. 10 passed; 0 failed; 0 ignored\x1b[0m\n' >"$scratch/ansi.log"
    if ! run_gate demo-leg "$scratch/ansi.log" 10 >/dev/null; then
        echo "SELF-TEST FAIL: ANSI-coloured cargo log should parse" >&2
        return 2
    fi
    echo "SELF-TEST PASS: ANSI-stripped cargo log"

    RATCHET_FILE="$saved_r"
    ALLOW_FILE="$saved_a"
    echo "check-cert-leg-nonvacuity self-test OK"
    return 0
}

usage() {
    echo "usage: $0 --leg NAME --log FILE [--listed N]" >&2
    echo "       $0 --self-test" >&2
    exit 2
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit $?
fi

LEG=""
LOG=""
LISTED=""
while [ $# -gt 0 ]; do
    case "$1" in
        --leg) LEG="${2:-}"; shift 2 ;;
        --log) LOG="${2:-}"; shift 2 ;;
        --listed) LISTED="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done
[ -n "$LEG" ] && [ -n "$LOG" ] || usage
run_gate "$LEG" "$LOG" "$LISTED"
