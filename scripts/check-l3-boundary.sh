#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v0.9.0 §25.3 S5 (RQ-10, #1853) — L3 BOUNDARY perma-ban gate.
#
# The §25.2/§25.3 epoch-closure lane ships a VERIFY-ONLY consumer under
# strictly RULED public identifiers. Certain internal design-doc
# identifiers are PERMANENTLY BANNED from src/ (any src/ string literal —
# clap help, error messages, tracing text — and any comment): they must
# never leak into the shipped binary's symbol/string surface.
#
# This gate HARD-BLOCKS any occurrence in src/ of the case-insensitive
# pattern below. The ruled public identifiers are gate-clean by
# construction (verified in the design proof table): `SignableEpochManifest`
# (no underscore), `epoch.manifest_applied` (dot, not underscore),
# `EpochAdvance`, `EPOCH_APPLIED`, `epoch_seq`, `prior_epoch_id`.
#
# The banned pattern is intentionally identical to the one the impl agent
# runs pre-commit every pass. The pattern string lives ONLY in this
# script + the CI workflow (both OUTSIDE src/), so the gate can name what
# it bans without tripping itself.
#
# CLI:
#   ./scripts/check-l3-boundary.sh              — run the gate
#   ./scripts/check-l3-boundary.sh --self-test  — prove the gate is live
set -euo pipefail

# The ruled perma-ban pattern (byte-identical to the pre-commit grep).
PATTERN='rqgm|epoch_manifest|red.?queen'

repo_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

run_gate() {
    local root="$1"
    if rg --version >/dev/null 2>&1; then
        if rg -i "$PATTERN" "$root/src/" >/dev/null 2>&1; then
            echo "❌ L3-boundary gate: banned identifier found in src/:" >&2
            rg -i -n "$PATTERN" "$root/src/" >&2 || true
            return 1
        fi
    else
        # Fallback to grep -rEi when ripgrep is unavailable.
        if grep -rEil "$PATTERN" "$root/src/" >/dev/null 2>&1; then
            echo "❌ L3-boundary gate: banned identifier found in src/:" >&2
            grep -rEin "$PATTERN" "$root/src/" >&2 || true
            return 1
        fi
    fi
    return 0
}

run_self_test() {
    local root
    root="$(repo_root)"
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN
    mkdir -p "$tmpdir/src/subdir"

    # (1) Clean tree passes.
    printf 'fn ok() { let epoch_seq = 1; let _ = epoch_seq; }\n' > "$tmpdir/src/clean.rs"
    if ! run_gate "$tmpdir" >/dev/null 2>&1; then
        echo "FAIL: self-test — gate wrongly flagged a clean tree"
        exit 1
    fi

    # (2) Planted violation fails.
    printf '// this comment mentions epoch_manifest and must trip the gate\n' \
        > "$tmpdir/src/subdir/violation.rs"
    if run_gate "$tmpdir" >/dev/null 2>&1; then
        echo "FAIL: self-test — gate did NOT catch the planted violation"
        exit 1
    fi

    echo "PASS: self-test — gate passes clean, fails on a planted violation"
}

main() {
    if [[ "${1:-}" == "--self-test" ]]; then
        run_self_test
        exit 0
    fi
    local root
    root="$(repo_root)"
    if run_gate "$root"; then
        echo "✅ L3-boundary perma-ban gate: PASS (0 hits in src/)"
    else
        echo "" >&2
        echo "The §25.2/§25.3 ruled identifiers are gate-clean by construction;" >&2
        echo "cite \"ROADMAP §25.2/§25.3\" or an issue number in src/ comments" >&2
        echo "instead of a banned identifier." >&2
        exit 1
    fi
}

main "$@"
