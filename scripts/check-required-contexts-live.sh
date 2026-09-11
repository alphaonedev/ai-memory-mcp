#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-required-contexts-live.sh — declared vs LIVE branch-protection drift
# (#3554, recurrence of #2712). FAIL-CLOSED.
#
# THE DEFECT CLASS. `scripts/check-required-contexts.sh` proves the
# hand-authored declaration (`required-contexts-release.txt`) is SOUND
# against the workflows. It has no API access by design: the Actions
# `GITHUB_TOKEN` is not administration-scoped. That left declared-vs-LIVE
# drift structurally undetectable.
#
#   * #2712 (2026-08-04): declaration 32, live 3 (drain-window leftover).
#     Closed by restoring live to 32. The coder half — compare live, not
#     only the mirror — did not land. The class remained open.
#   * #3554 (2026-09-09): declaration 38, live 35. `comm` diff was exactly
#     `Benchmark-claim canon gate (#2879)`, `Capacity-claim ceiling gate
#     (#2869)`, `Enterprise-federation cert-expiry gate (cert §7 / F7)`.
#     All three jobs existed; none was in the not-required ledger; the
#     companion protection API call never landed. Recurrence of #2712.
#
# THIS SCRIPT never writes the declaration from live (the #2473
# laundering class: a truncated check-run name copied off the API would
# become "intent"). It compares three sets:
#
#   declaration  scripts/qc-allowlists/required-contexts-release.txt
#   live-pin     scripts/qc-allowlists/required-contexts-live-pin.txt
#                (regenerated ONLY by --pin-from-live; never hand-edit)
#   live API     GET /branches/<protected>/protection/required_status_checks
#
# When the token can read protection: all three must be equal, and
# `enforce_admins=true` + `strict=true` must hold. When the token cannot
# (GitHub-hosted `GITHUB_TOKEN` → 401/403): declaration must equal the
# pin, and a WARN names the degrade. That is the CI stand-in that still
# catches a declaration growing without a pin update — the #3554 shape —
# without wedging every PR behind an unreadable Administration API.
#
# THE RATCHET (supersedes the silent "mirror-first over-claim window"
# that let #3554 happen). A required-context ADDITION lands in ONE
# commit that updates declaration AND the pin, and the pin is produced
# by --pin-from-live AFTER the protection API call. Sequence for a new
# gating job:
#
#   1. Land the job. Rule (f) of check-required-contexts.sh requires it
#      in the declaration OR the not-required ledger — use the ledger
#      until the job has reported on the protected base.
#   2. Add the context to live protection (jobs already reporting).
#   3. `bash scripts/check-required-contexts-live.sh --pin-from-live`
#   4. Move the name from the not-required ledger to the declaration
#      in the same commit as the pin. CI: declaration == pin.
#
# A REMOVAL inverts: drop from protection first, --pin-from-live, then
# drop from the declaration (the original ORDER doctrine, unchanged).
#
# CLI:
#   scripts/check-required-contexts-live.sh              run the gate
#   scripts/check-required-contexts-live.sh --self-test  fixture proof
#   scripts/check-required-contexts-live.sh --pin-from-live
#       fetch live (admin token) and rewrite the pin; fail-closed on
#       unreadability. Does NOT edit the declaration.
#
# Env:
#   RQC_MIRROR_FILE, RQC_PIN_FILE, RQC_PROTECTED_BRANCH, RQC_GITHUB_REPO
#   RQC_LIVE_CONTEXTS_FILE   fixture live names (one per line); skips API
#   RQC_LIVE_ENFORCE_ADMINS  fixture enforce_admins (true/false)
#   RQC_LIVE_STRICT          fixture strict (true/false)
#   RQC_LIVE_REQUIRE_API=1   401/403 is a hard fail (no pin fallback)
#
# Exit: 0 clean · 1 drift / unreadability-when-required · 2 usage / self-test.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MIRROR_FILE="${RQC_MIRROR_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-release.txt}"
PIN_FILE="${RQC_PIN_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-live-pin.txt}"
PROTECTED_BRANCH="${RQC_PROTECTED_BRANCH:-release/v1.0.0}"
GITHUB_REPO="${RQC_GITHUB_REPO:-alphaonedev/ai-memory-mcp}"

FAILURES=0

fail() {
    printf '%s\n' "❌ required-contexts-live: $*" >&2
    FAILURES=$((FAILURES + 1))
}

warn() {
    printf '%s\n' "⚠️  required-contexts-live: $*" >&2
}

read_list() {
    # Whole-line `#` comments and blanks only. Inline `#` is NOT a comment:
    # several required context names legitimately contain one.
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

sorted_unique() {
    LC_ALL=C sort -u
}

branch_api_path() {
    # GitHub encodes a literal '/' in a branch name as %2F.
    printf '%s' "repos/${GITHUB_REPO}/branches/${PROTECTED_BRANCH//\//%2F}/protection"
}

fetch_live() {
    # Prints: first line enforce_admins (true/false)
    #         second line strict (true/false)
    #         remaining lines: context names
    # Returns 0 on success, 3 on 401/403, 1 on any other failure.
    # Uses `gh api --jq` (no `-i`): `gh api -i` colourises the JSON body
    # even when piped (`\x1b[...m{`), which is not parseable.
    local path raw rc
    path="$(branch_api_path)"
    if ! command -v gh >/dev/null 2>&1; then
        echo "gh CLI not found" >&2
        return 1
    fi
    # gh colourises `--jq` output even under GH_NO_COLOR=1 (ANSI around
    # `{` / keys). Strip CSI sequences; never feed colourised JSON to a
    # parser. Do not `set -e` in this function (caller may have disabled
    # errexit around the call).
    raw="$(TERM=dumb NO_COLOR=1 CLICOLOR=0 GH_NO_COLOR=1 GH_PAGER=cat \
        gh api "$path" --jq \
        '(if .enforce_admins.enabled then "true" else "false" end),
         (if .required_status_checks.strict then "true" else "false" end),
         (.required_status_checks.contexts[])' 2>&1)"
    rc=$?
    raw="$(printf '%s' "$raw" | tr -d '\r' | sed $'s/\x1b\\[[0-9;]*m//g')"
    if [ "$rc" -ne 0 ]; then
        local msg
        msg="$(printf '%s' "$raw" | tr '\n' ' ')"
        case "$msg" in
            *401* | *403* | *'Must have admin'* | *'Resource not accessible'* | *'Requires authentication'*)
                echo "HTTP 401/403 reading branch protection (token is not administration-scoped): $msg" >&2
                return 3
                ;;
            *)
                echo "gh api failed reading branch protection: $msg" >&2
                return 1
                ;;
        esac
    fi
    if [ -z "$raw" ]; then
        echo "empty payload from gh api $path" >&2
        return 1
    fi
    printf '%s\n' "$raw"
}

load_fixture_live() {
    local f="$1"
    if [ ! -f "$f" ]; then
        echo "RQC_LIVE_CONTEXTS_FILE missing: $f" >&2
        return 1
    fi
    printf '%s\n' "${RQC_LIVE_ENFORCE_ADMINS:-true}"
    printf '%s\n' "${RQC_LIVE_STRICT:-true}"
    read_list "$f"
}

compare_files() {
    local a_file="$1" a_label="$2" b_file="$3" b_label="$4"
    local only_a only_b
    only_a="$(comm -23 "$a_file" "$b_file" || true)"
    only_b="$(comm -13 "$a_file" "$b_file" || true)"
    if [ -n "$only_a" ]; then
        fail "$a_label has contexts not in $b_label:"
        printf '%s\n' "$only_a" | sed 's/^/     - /' >&2
    fi
    if [ -n "$only_b" ]; then
        fail "$b_label has contexts not in $a_label:"
        printf '%s\n' "$only_b" | sed 's/^/     - /' >&2
    fi
}

count_lines() {
    local n=0
    while IFS= read -r _; do
        n=$((n + 1))
    done
    printf '%s' "$n"
}

run_gate() {
    local tmp declared_f pin_f live_f
    tmp="$ROOT/.local-runs/required-contexts-live-run-$$"
    mkdir -p "$tmp"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    if [ ! -f "$MIRROR_FILE" ]; then
        fail "declaration missing: $MIRROR_FILE (fail-closed)"
        return 1
    fi
    if [ ! -f "$PIN_FILE" ]; then
        fail "live-pin missing: $PIN_FILE (fail-closed — regenerate with --pin-from-live)"
        return 1
    fi

    declared_f="$tmp/declared"
    pin_f="$tmp/pin"
    live_f="$tmp/live"
    read_list "$MIRROR_FILE" | sorted_unique >"$declared_f"
    read_list "$PIN_FILE" | sorted_unique >"$pin_f"

    local n_decl n_pin
    n_decl="$(count_lines <"$declared_f")"
    n_pin="$(count_lines <"$pin_f")"
    if [ "$n_decl" -eq 0 ]; then
        fail "declaration $MIRROR_FILE is empty — refusing a vacuous required set"
        return 1
    fi
    if [ "$n_pin" -eq 0 ]; then
        fail "live-pin $PIN_FILE is empty — refusing a vacuous pin"
        return 1
    fi

    compare_files "$declared_f" "declaration ($MIRROR_FILE)" "$pin_f" "live-pin ($PIN_FILE)"

    local enforce=true strict=true rc=0
    local live_src=""
    if [ -n "${RQC_LIVE_CONTEXTS_FILE:-}" ]; then
        live_src="fixture $RQC_LIVE_CONTEXTS_FILE"
        if ! load_fixture_live "$RQC_LIVE_CONTEXTS_FILE" >"$tmp/live_raw"; then
            fail "failed to load live fixture $RQC_LIVE_CONTEXTS_FILE"
            return 1
        fi
    else
        live_src="GET ${GITHUB_REPO} ${PROTECTED_BRANCH}"
        set +e
        fetch_live >"$tmp/live_raw" 2>"$tmp/live_err"
        rc=$?
        set -e
        if [ "$rc" -eq 3 ]; then
            if [ "${RQC_LIVE_REQUIRE_API:-0}" = "1" ]; then
                fail "branch protection unreadable and RQC_LIVE_REQUIRE_API=1 ($(cat "$tmp/live_err"))"
                return 1
            fi
            warn "branch protection unreadable ($(tr '\n' ' ' <"$tmp/live_err")). Comparing declaration to live-pin only. This is the GitHub-hosted GITHUB_TOKEN degrade; run --pin-from-live with an admin token to refresh the pin, and run this script locally to compare against live."
            if [ "$FAILURES" -eq 0 ]; then
                echo "check-required-contexts-live: OK (declaration == live-pin, ${n_decl} contexts; live API unread — pin stand-in)"
                return 0
            fi
            return 1
        fi
        if [ "$rc" -ne 0 ]; then
            fail "failed to read live protection ($(tr '\n' ' ' <"$tmp/live_err"))"
            return 1
        fi
    fi

    enforce="$(sed -n '1p' "$tmp/live_raw")"
    strict="$(sed -n '2p' "$tmp/live_raw")"
    sed -n '3,$p' "$tmp/live_raw" | sorted_unique >"$live_f"
    local n_live
    n_live="$(count_lines <"$live_f")"
    if [ "$n_live" -eq 0 ]; then
        fail "live required-status-check set is empty ($live_src) — refuse a vacuous live set (the #2712 3-context drain window is the class, empty is worse)"
        return 1
    fi
    if [ "$enforce" != "true" ]; then
        fail "enforce_admins is ${enforce:-unset} on ${PROTECTED_BRANCH}; required true (ruling #3308 / #3554)"
    fi
    if [ "$strict" != "true" ]; then
        fail "required_status_checks.strict is ${strict:-unset} on ${PROTECTED_BRANCH}; required true"
    fi

    compare_files "$declared_f" "declaration ($MIRROR_FILE)" "$live_f" "live ($live_src)"
    compare_files "$pin_f" "live-pin ($PIN_FILE)" "$live_f" "live ($live_src)"

    if [ "$FAILURES" -eq 0 ]; then
        echo "check-required-contexts-live: OK (${PROTECTED_BRANCH}: declaration == live-pin == live, ${n_decl} contexts; enforce_admins=true strict=true)"
        return 0
    fi
    echo "" >&2
    echo "FAIL (#3554 / #2712): declared required-context set drifts from live branch protection." >&2
    echo "Declaration: $MIRROR_FILE" >&2
    echo "Live-pin:    $PIN_FILE  (regenerate with --pin-from-live; NEVER hand-edit, NEVER copy live into the declaration)" >&2
    echo "Live:        $live_src" >&2
    echo "Self-test:   scripts/check-required-contexts-live.sh --self-test" >&2
    return 1
}

pin_from_live() {
    local tmp rc
    tmp="$ROOT/.local-runs/required-contexts-live-pin-$$"
    mkdir -p "$tmp"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT

    set +e
    fetch_live >"$tmp/live_raw" 2>"$tmp/live_err"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "check-required-contexts-live --pin-from-live: cannot read protection ($(tr '\n' ' ' <"$tmp/live_err"))" >&2
        exit 1
    fi
    local enforce strict
    enforce="$(sed -n '1p' "$tmp/live_raw")"
    strict="$(sed -n '2p' "$tmp/live_raw")"
    sed -n '3,$p' "$tmp/live_raw" | sorted_unique >"$tmp/contexts"
    local n
    n="$(count_lines <"$tmp/contexts")"
    if [ "$n" -eq 0 ]; then
        echo "check-required-contexts-live --pin-from-live: refusing to write an empty pin" >&2
        exit 1
    fi
    if [ "$enforce" != "true" ] || [ "$strict" != "true" ]; then
        echo "check-required-contexts-live --pin-from-live: live enforce_admins=$enforce strict=$strict; both must be true before pinning (ruling #3308 / #3554)" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$PIN_FILE")"
    {
        echo "# required-contexts-live-pin.txt — last-fetched LIVE required-status-check"
        echo "# set for \`${PROTECTED_BRANCH}\`. Regenerated ONLY by"
        echo "# \`scripts/check-required-contexts-live.sh --pin-from-live\`."
        echo "#"
        echo "# ============================================================================ "
        echo "# *** NEVER HAND-EDIT. NEVER COPY THIS FILE INTO THE DECLARATION."
        echo "# *** The declaration is required-contexts-release.txt (intent)."
        echo "# *** This pin is the CI stand-in for live protection when the"
        echo "# *** Actions GITHUB_TOKEN cannot read the Administration API."
        echo "# ============================================================================ "
        echo "#"
        echo "# fetched-from: ${GITHUB_REPO} ${PROTECTED_BRANCH}"
        echo "# fetched-at:   $(date -u +%Y-%m-%dT%H:%MZ)"
        echo "# count:        ${n}"
        echo "# enforce_admins: ${enforce}"
        echo "# strict:         ${strict}"
        echo "#"
        cat "$tmp/contexts"
    } >"$PIN_FILE"
    echo "check-required-contexts-live: pinned ${n} live contexts from ${PROTECTED_BRANCH} -> $PIN_FILE"
}

self_test() {
    local scratch
    scratch="$ROOT/.local-runs/required-contexts-live-selftest-$$"
    mkdir -p "$scratch"
    # shellcheck disable=SC2064
    trap "rm -rf '$scratch'" EXIT

    # Minimal declaration / pin / live sharing three names, including one
    # with an inline `#` so the comment rule is load-bearing.
    local trio
    trio="$scratch/trio.txt"
    cat >"$trio" <<'TXT'
Classify changes
Capacity-claim ceiling gate (#2869)
Benchmark-claim canon gate (#2879)
TXT

    # (1) Clean equal sets MUST PASS.
    if ! RQC_MIRROR_FILE="$trio" RQC_PIN_FILE="$trio" RQC_LIVE_CONTEXTS_FILE="$trio" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null; then
        echo "self-test FAILED: equal declaration/pin/live was rejected" >&2
        exit 2
    fi

    # (2) The exact #3554 shape: declaration has three, live/pin missing the
    #     two claim gates + cert-expiry analogue. MUST FAIL.
    cat >"$scratch/decl38.txt" <<'TXT'
Classify changes
Capacity-claim ceiling gate (#2869)
Benchmark-claim canon gate (#2879)
Enterprise-federation cert-expiry gate (cert §7 / F7)
TXT
    cat >"$scratch/live35.txt" <<'TXT'
Classify changes
TXT
    if RQC_MIRROR_FILE="$scratch/decl38.txt" RQC_PIN_FILE="$scratch/live35.txt" \
        RQC_LIVE_CONTEXTS_FILE="$scratch/live35.txt" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/err3554"; then
        echo "self-test FAILED: the #3554 38-vs-35 shape was NOT rejected" >&2
        exit 2
    fi
    if ! grep -q "Capacity-claim ceiling gate" "$scratch/err3554"; then
        echo "self-test FAILED: #3554 rejection did not name the missing claim gate" >&2
        cat "$scratch/err3554" >&2
        exit 2
    fi

    # (3) Extra live context (declaration lagging live) MUST FAIL.
    if RQC_MIRROR_FILE="$scratch/live35.txt" RQC_PIN_FILE="$scratch/live35.txt" \
        RQC_LIVE_CONTEXTS_FILE="$scratch/decl38.txt" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/errextra"; then
        echo "self-test FAILED: extra live context was NOT rejected" >&2
        exit 2
    fi

    # (4) enforce_admins false MUST FAIL even when the name sets match.
    if RQC_MIRROR_FILE="$trio" RQC_PIN_FILE="$trio" RQC_LIVE_CONTEXTS_FILE="$trio" \
        RQC_LIVE_ENFORCE_ADMINS=false RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/erradm"; then
        echo "self-test FAILED: enforce_admins=false was NOT rejected" >&2
        exit 2
    fi
    if ! grep -q "enforce_admins" "$scratch/erradm"; then
        echo "self-test FAILED: enforce_admins=false rejection did not name the knob" >&2
        exit 2
    fi

    # (5) strict false MUST FAIL.
    if RQC_MIRROR_FILE="$trio" RQC_PIN_FILE="$trio" RQC_LIVE_CONTEXTS_FILE="$trio" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=false \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/errstrict"; then
        echo "self-test FAILED: strict=false was NOT rejected" >&2
        exit 2
    fi

    # (6) Empty live MUST FAIL (vacuous live set).
    : >"$scratch/empty.txt"
    if RQC_MIRROR_FILE="$trio" RQC_PIN_FILE="$trio" RQC_LIVE_CONTEXTS_FILE="$scratch/empty.txt" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/errempty"; then
        echo "self-test FAILED: empty live set was NOT rejected" >&2
        exit 2
    fi

    # (7) Missing declaration MUST FAIL.
    if RQC_MIRROR_FILE="$scratch/no-such-decl.txt" RQC_PIN_FILE="$trio" \
        RQC_LIVE_CONTEXTS_FILE="$trio" \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/errmiss"; then
        echo "self-test FAILED: missing declaration was NOT rejected" >&2
        exit 2
    fi

    # (8) Missing pin MUST FAIL.
    if RQC_MIRROR_FILE="$trio" RQC_PIN_FILE="$scratch/no-such-pin.txt" \
        RQC_LIVE_CONTEXTS_FILE="$trio" \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/errpin"; then
        echo "self-test FAILED: missing pin was NOT rejected" >&2
        exit 2
    fi

    # (9) Pin/declaration mismatch with live matching declaration MUST FAIL
    #     (stale pin).
    if RQC_MIRROR_FILE="$scratch/decl38.txt" RQC_PIN_FILE="$scratch/live35.txt" \
        RQC_LIVE_CONTEXTS_FILE="$scratch/decl38.txt" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null 2>"$scratch/errstale"; then
        echo "self-test FAILED: stale pin matching neither side was NOT rejected" >&2
        exit 2
    fi

    # (10) Inline `#` in a context name is NOT stripped (comment rule).
    echo "Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10)" >"$scratch/hash.txt"
    if ! RQC_MIRROR_FILE="$scratch/hash.txt" RQC_PIN_FILE="$scratch/hash.txt" \
        RQC_LIVE_CONTEXTS_FILE="$scratch/hash.txt" \
        RQC_LIVE_ENFORCE_ADMINS=true RQC_LIVE_STRICT=true \
        "$ROOT/scripts/check-required-contexts-live.sh" >/dev/null; then
        echo "self-test FAILED: a legitimate inline-# context name was rejected" >&2
        exit 2
    fi

    echo "required-contexts-live self-test: PASS (load-bearing — catches the #3554 38-vs-35 shape, extra live context, enforce_admins=false, strict=false, empty live, missing declaration, missing pin, stale pin; spares equal sets and an inline-# context name)"
}

case "${1:-}" in
    --self-test)
        self_test
        ;;
    --pin-from-live)
        pin_from_live
        ;;
    "")
        run_gate
        ;;
    *)
        echo "usage: $0 [--self-test|--pin-from-live]" >&2
        exit 2
        ;;
esac
