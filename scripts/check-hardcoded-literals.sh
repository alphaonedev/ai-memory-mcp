#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v0.7.x — pm-v3.1 hardcoded-literal lint-gate (operator directive,
# in force ~6mo, escalated 2026-06-09: "use proper variable + constant
# scoping; DO NOT hardcode literal values; DO NOT bake literals into
# variable/constant names"). Companion to scripts/check-vendor-literals.sh.
#
# WHY THIS EXISTS: repeating instructions to the agent did not stop the
# regression — a scattered magic string (e.g. `format!("anonymous:req-{}", …)`
# ~8x, `"memory not found"` ~6x) gets reproduced every time the agent
# pattern-matches surrounding (already-rotten) code. The proven fix is a
# mechanical HARD-BLOCK in CI, exactly like the vendor-literal gate that
# stopped that class of regression. See ai-memory memory
# `no-hardcoded-literals-enforcement` + b1abcedb-… (this session).
#
# WHAT IT BLOCKS: a string literal of length >= MIN_LEN that appears on
# >= DUP_THRESHOLD distinct PRODUCTION sites is a magic value that should
# be a single named `const` referenced by name (or an existing helper
# reused). Such a duplicated literal is a HARD-BLOCK *when its current
# site-count exceeds the frozen baseline* — i.e. the gate is a ratchet:
#   - existing duplications are grandfathered in the baseline file;
#   - ADDING an occurrence (count rises above baseline) FAILS;
#   - a brand-new duplicated literal (absent from baseline) FAILS;
#   - REMOVING occurrences never fails (burn-down is always allowed);
#   - the baseline can only shrink — "thresholds rise, never fall".
#
# Deliberately NOT flagged (low-false-positive scope):
#   - literals shorter than MIN_LEN (short JSON keys like "id"/"error");
#   - a literal that lives in exactly one place (incl. its const def);
#   - comments / doc-comments, `use` paths, `#[attr(...)]` lines, and
#     `const`/`static` definition lines (those ARE the good pattern);
#   - test code (per the shared production-vs-test heuristic).
#
# Magic NUMBERS are intentionally out of scope here: the SECS_PER_* class
# is already gated by check-vendor-literals.sh, and a general numeric-
# literal gate is too noisy to be load-bearing. String duplication is the
# high-signal class the operator's examples fall into.
#
# Usage:
#   scripts/check-hardcoded-literals.sh
#     - exit 0 clean, exit 1 on any over-baseline duplicated literal.
#   scripts/check-hardcoded-literals.sh --update-baseline
#     - regenerate the baseline from the current tree (operator-gated;
#       run deliberately when intentionally changing the duplicated set).
#   scripts/check-hardcoded-literals.sh --self-test
#     - inject a contrived NEW triplicated literal, verify HARD-BLOCK,
#       clean up. Proves the gate is load-bearing (pm-v3.2).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${ROOT}/scripts/qc-allowlists/hardcoded-literals-baseline.txt"

# Minimum literal length to consider (chars between the quotes). 10 keeps
# short structural JSON keys out while catching real magic strings
# ("anonymous:req-{}", "memory not found", URLs, namespaces, …).
MIN_LEN=10
# Distinct production sites at/above which a literal is "duplicated".
DUP_THRESHOLD=3

# find_test_boundary <file> — first `mod tests {` line OR first
# `#[cfg(test)]` attribute that introduces a MODULE (attr line whose
# next line starts a `mod`), whichever comes first; huge sentinel when
# neither exists. The attr+mod pairing catches test modules with
# non-standard names (e.g. `#[cfg(test)] mod l2_2_audit_tests` in
# src/storage/reflect.rs) that leaked test literals into the baseline
# (#1561), while a `#[cfg(test)]` on a single mid-file item does NOT
# truncate the production region below it.
find_test_boundary () {
    local f="$1" line_mod line_cfg
    # #1564 — a file-level `#![cfg(test)]` inner attribute makes the
    # WHOLE file test code (e.g. src/mcp/tools/d1_4_985_helpers.rs);
    # boundary 0 excludes every line.
    if grep -qE '^[[:space:]]*#!\[cfg\(test\)\]' "$f" 2>/dev/null; then
        echo 0
        return
    fi
    line_mod=$(grep -nE '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+tests?[[:space:]]*\{' "$f" 2>/dev/null | head -1 | cut -d: -f1)
    line_cfg=$(awk '/^[[:space:]]*#\[cfg\(test\)\]/{attr=NR; next}
                    attr && /^[[:space:]]*(pub([(][^)]*[)])?[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]+/{print attr; exit}
                    {attr=0}' "$f" 2>/dev/null)
    [[ -z "$line_mod" ]] && line_mod=999999999
    [[ -z "$line_cfg" ]] && line_cfg=999999999
    if (( line_cfg < line_mod )); then echo "$line_cfg"; else echo "$line_mod"; fi
}

# emit_literals <file> — print one `<literal>` per production occurrence
# site (a site = one literal on one production line; multiple distinct
# literals on a line each count). Skips test region + comment/use/attr/
# const-def lines. Literals are emitted raw (no surrounding quotes).
emit_literals () {
    local f="$1" bn
    bn="$(basename "$f")"
    case "$bn" in
        *test*.rs|tests.rs) return 0 ;;
    esac
    local boundary
    boundary=$(find_test_boundary "$f")
    awk -v boundary="$boundary" -v minlen="$MIN_LEN" '
        NR >= boundary { exit }
        {
            line = $0
            # strip leading whitespace for the prefix tests
            s = line; sub(/^[[:space:]]+/, "", s)
            # skip comments / doc-comments / block-comment continuations
            if (s ~ /^\/\//) next
            if (s ~ /^\*/) next
            # skip use-paths and attributes (literal is a path/attr arg, not a magic value)
            if (s ~ /^use /) next
            if (s ~ /^#\[/) next
            # skip const / static definitions — that IS the good pattern
            if (s ~ /^pub[ ]+const /) next
            if (s ~ /^const /) next
            if (s ~ /^pub\([a-z]+\)[ ]+const /) next
            if (s ~ /^static / || s ~ /^pub[ ]+static /) next
            # extract simple double-quoted string literals (no embedded quote)
            rest = line
            while (match(rest, /"[^"]*"/)) {
                lit = substr(rest, RSTART + 1, RLENGTH - 2)
                rest = substr(rest, RSTART + RLENGTH)
                if (length(lit) < minlen) continue
                # ignore pure format-placeholder / whitespace-only noise
                print lit
            }
        }
    ' "$f"
}

# compute_current_counts — emit sorted `COUNT<TAB>LITERAL` for every
# literal duplicated on >= DUP_THRESHOLD production sites across src/+tools/.
compute_current_counts () {
    local f
    while IFS= read -r -d '' f; do
        emit_literals "$f"
    done < <(find "${ROOT}/src" "${ROOT}/tools" -type f -name '*.rs' -print0 2>/dev/null) \
    | sort | uniq -c \
    | awk -v thr="$DUP_THRESHOLD" '$1 >= thr {
        # reassemble the literal (may contain spaces) after the count field
        cnt = $1; $1 = ""; sub(/^[[:space:]]+/, "")
        printf "%d\t%s\n", cnt, $0
    }' | sort -t'	' -k2
}

# --- update-baseline ---------------------------------------------------
if [[ "${1:-}" == "--update-baseline" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    {
        echo "# hardcoded-literal duplication baseline (ratchet; counts may only DECREASE)."
        echo "# Regenerate with: scripts/check-hardcoded-literals.sh --update-baseline"
        echo "# Format: <site-count><TAB><literal>. Burn this down; never grow it."
        compute_current_counts
    } > "$BASELINE"
    echo "Wrote baseline: ${BASELINE#"${ROOT}/"} ($(grep -cvE '^#' "$BASELINE" 2>/dev/null || echo 0) duplicated literals frozen)"
    exit 0
fi

# --- self-test ---------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Hardcoded-literal gate: self-test (contrived NEW triplicated literal -> expect HARD-BLOCK -> cleanup)"
    contrived="${ROOT}/src/.hardcoded_literal_gate_probe.rs"
    if [[ -e "$contrived" ]]; then
        echo "ERROR: self-test scratch already exists: $contrived" >&2
        exit 2
    fi
    # A brand-new magic string on 3 production sites (absent from baseline).
    cat > "$contrived" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-hardcoded-literals.sh --self-test.
// Deleted by the self-test; if it persists, the run was killed — remove it.
pub fn a() -> &'static str { "gate-probe-magic-string-xyz" }
pub fn b() -> &'static str { "gate-probe-magic-string-xyz" }
pub fn c() -> &'static str { "gate-probe-magic-string-xyz" }
EOF
    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e
    rm -f "$contrived"
    printf '%s\n' "$gate_output"
    if (( gate_exit != 0 )) && printf '%s' "$gate_output" | grep -q 'gate-probe-magic-string-xyz'; then
        echo ""
        echo "Hardcoded-literal gate self-test: PASS (caught the contrived violation; exit=${gate_exit})"
        exit 0
    fi
    echo "" >&2
    echo "Hardcoded-literal gate self-test: FAIL (did not catch the contrived violation; exit=${gate_exit})" >&2
    exit 1
fi

# --- main check --------------------------------------------------------
cd "$ROOT"
if [[ ! -f "$BASELINE" ]]; then
    echo "Hardcoded-literal gate: no baseline at ${BASELINE#"${ROOT}/"} — run --update-baseline once to freeze the current set." >&2
    exit 1
fi

current="$(compute_current_counts)"

# Build an associative lookup of baseline counts.
declare -A base_count
while IFS=$'\t' read -r cnt lit; do
    [[ -z "${cnt:-}" ]] && continue
    case "$cnt" in \#*) continue ;; esac
    base_count["$lit"]="$cnt"
done < <(grep -vE '^[[:space:]]*#' "$BASELINE" 2>/dev/null || true)

violations=""
while IFS=$'\t' read -r cnt lit; do
    [[ -z "${cnt:-}" ]] && continue
    b="${base_count["$lit"]:-0}"
    if (( cnt > b )); then
        violations+="  +${cnt} (baseline ${b})  \"${lit}\""$'\n'
    fi
done <<< "$current"

if [[ -n "${violations//[[:space:]]/}" ]]; then
    {
        echo "Hardcoded-literal duplication over baseline (pm-v3.1 lint-gate):"
        printf '%s' "$violations"
        echo ""
        echo "Each literal above is a magic value repeated on >= ${DUP_THRESHOLD} production sites,"
        echo "and its count rose above the frozen baseline. Fix by EITHER:"
        echo "  - defining ONE named \`const\` (or reusing an existing one / helper) and"
        echo "    referencing it by name at every site; OR"
        echo "  - if the repetition is genuinely irreducible, run"
        echo "    \`scripts/check-hardcoded-literals.sh --update-baseline\` (operator-gated)"
        echo "    and justify the bump in the commit message."
        echo ""
        echo "Do NOT scatter the literal. Per the operator directive (~6mo): no hardcoded"
        echo "literal values, no literals embedded in variable/constant names."
    } >&2
    echo "" >&2
    echo "Hardcoded-literal gate: FAIL" >&2
    exit 1
fi

echo "Hardcoded-literal gate: PASS (no duplicated string literal rose above baseline)"
