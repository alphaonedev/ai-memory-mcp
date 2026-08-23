#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 (#3119) — CERT REMOVAL-PROOF MUTATION MARKER perma-ban gate.
#
# WHY THIS EXISTS. `scripts/check-cert-removal-proof.sh` is a mutation-testing
# harness: for each cited security control it REWRITES the production source
# in place to an always-allow disposition, runs the control's lane test, and
# asserts the test goes RED. Every such rewrite is stamped with a single
# marker comment. On 2026-08-22 (#3118, never merged) an aborted run — killed
# at a two-minute timeout — left one of those rewrites in the working tree:
# `inbound_write_namespace_authorized` short-circuited to always-allow, i.e. a
# cross-tenant inbound federated-write authorization BYPASS. A later
# `git add -A` swept it into a pushed commit, where it sat on a PR branch for
# ~25 minutes. Nothing in `git status` reads as "a security control is off".
#
# #3119 fixed the harness (it now restores under an EXIT/INT/TERM/HUP trap and
# refuses to start on a stale marker). THIS GATE IS THE INDEPENDENT SECOND
# LINE: whatever leaves a mutation in the tree — a crash the trap could not
# catch, a `git add -A`, a hand-edited cherry-pick, a rebase that resurrects a
# dropped hunk — the marker can never reach a merged commit under `src/`.
# Defence in depth, per the North Star: a disabled security control is a
# WRONG-RESULT posture, not a degraded one, so this fails CLOSED and loudly.
#
# WHY IT DOES NOT TRIP ITSELF. The gate scans `src/` ONLY. The marker string
# lives exclusively OUTSIDE `src/` — in this script, in the harness under
# `scripts/`, and in the archived evidence logs under `docs/compliance/` — so
# the gate can name what it bans without banning itself. (Same construction as
# `scripts/check-l3-boundary.sh`, whose pattern likewise lives only in the
# script + workflow.) A self-test fixture is staged under `.local-runs/`,
# never under the real `src/`.
#
# CLI:
#   ./scripts/check-mutation-marker.sh              — run the gate
#   ./scripts/check-mutation-marker.sh --self-test  — prove the gate is live
set -euo pipefail

# The banned marker. SSOT for this gate; the harness carries the same literal
# in its payloads (both files are outside src/, so neither trips this gate).
MARKER='CERT-REMOVAL-PROOF-MUTATION'

repo_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

# Scan production + test surfaces for the marker. Returns 0 = clean,
# 1 = marker found, 2 = could not scan (fail CLOSED: an unscannable
# tree is never "clean"). `grep` as an `if` condition used to treat
# rc=2 (unreadable file) as PASS — capture rc instead. Scan set is
# src/ tests/ conformance/ examples/ sdk/ (scripts/ is excluded so
# this gate and the harness can name the marker).
SCAN_REL=(src tests conformance examples sdk)
run_gate() {
    local root="$1"
    if [[ ! -d "$root/src" ]]; then
        echo "❌ mutation-marker gate: no src/ under $root — refusing to report clean" >&2
        return 2
    fi
    local paths=() p
    for p in "${SCAN_REL[@]}"; do
        [[ -e "$root/$p" ]] && paths+=("$root/$p")
    done
    local rc=0
    grep -rIl --exclude-dir=.git -e "$MARKER" "${paths[@]}" >/dev/null 2>&1 || rc=$?
    case $rc in
        0)
            echo "" >&2
            echo "══════════════════════════════════════════════════════════════════════" >&2
            echo "SECURITY: cert removal-proof mutation marker found" >&2
            echo "" >&2
            grep -rIn --exclude-dir=.git -e "$MARKER" "${paths[@]}" >&2 || true
            echo "" >&2
            echo "A marked line is a DELIBERATELY DISABLED security control left behind" >&2
            echo "by scripts/check-cert-removal-proof.sh (see #3118/#3119). It must" >&2
            echo "never be committed. Restore the tree with:" >&2
            echo "" >&2
            echo "    scripts/check-cert-removal-proof.sh --force-restore" >&2
            echo "" >&2
            echo "then re-stage EXPLICITLY (never 'git add -A' after a gate script)." >&2
            echo "══════════════════════════════════════════════════════════════════════" >&2
            return 1
            ;;
        1) return 0 ;;
        *)
            echo "❌ mutation-marker gate: scan failed (grep rc=$rc) — refusing to report clean" >&2
            return 2
            ;;
    esac
}

run_self_test() {
    local root
    root="$(repo_root)"
    local dir
    mkdir -p "$root/.local-runs"
    dir="$(mktemp -d "$root/.local-runs/mutation-marker-gate-selftest.XXXXXX")"
    trap 'rm -rf "$dir"' RETURN
    mkdir -p "$dir/src/federation"

    # (1) A clean tree PASSES — including near-miss text that names the harness
    #     and the concept without carrying the literal marker.
    cat >"$dir/src/federation/clean.rs" <<'RS'
// Proven load-bearing by the cert removal-proof harness (scripts/).
pub fn inbound_write_namespace_authorized(ok: bool) -> bool {
    ok
}
RS
    if ! run_gate "$dir" >/dev/null 2>&1; then
        echo "FAIL: self-test — gate wrongly flagged a clean tree" >&2
        exit 1
    fi

    # (2) The EXACT #3118 artefact FAILS: an always-allow first statement
    #     carrying the marker comment, in the real file's real function.
    printf 'pub fn inbound_write_namespace_authorized() -> bool {\n    return true; // %s\n}\n' \
        "$MARKER" >"$dir/src/federation/receive_auth.rs"
    if run_gate "$dir" >/dev/null 2>&1; then
        echo "FAIL: self-test — gate did NOT catch the planted #3118 mutation" >&2
        exit 1
    fi

    # (3) FAIL CLOSED on an unscannable tree — an empty scan set must never
    #     green a no-op (the #2839 fail-closed discipline).
    rm -rf "$dir/src"
    if run_gate "$dir" >/dev/null 2>&1; then
        echo "FAIL: self-test — gate reported clean with no src/ to scan" >&2
        exit 1
    fi

    # (4) grep rc=2 (unreadable file) must fail CLOSED, not PASS.
    mkdir -p "$dir/src"
    printf 'fn ok() {}\n' >"$dir/src/unreadable.rs"
    chmod 000 "$dir/src/unreadable.rs"
    local urc=0
    run_gate "$dir" >/dev/null 2>&1 || urc=$?
    chmod u+r "$dir/src/unreadable.rs" || true
    if [[ $urc -ne 2 ]]; then
        echo "FAIL: self-test — unreadable file must exit 2, got $urc" >&2
        exit 1
    fi

    # (5) the banned MARKER literal still appears in the harness (so this
    #     gate and the harness cannot drift apart).
    if ! grep -qF "$MARKER" "$root/scripts/check-cert-removal-proof.sh"; then
        echo "FAIL: self-test — MARKER literal missing from the harness" >&2
        exit 1
    fi

    echo "PASS: self-test — clean tree passes, planted #3118 mutation fails, missing src/ fails closed, unreadable file fails closed, harness still names the marker"
}

main() {
    if [[ "${1:-}" == "--self-test" ]]; then
        run_self_test
        exit 0
    fi
    local root
    root="$(repo_root)"
    local rc=0
    run_gate "$root" || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "✅ cert removal-proof mutation-marker gate: PASS (0 hits in src/)"
        exit 0
    fi
    exit "$rc"
}

main "$@"
