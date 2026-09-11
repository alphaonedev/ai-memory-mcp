#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 #3200 — ONE boolean env-token grammar: a ratchet gate.
#
# WHY THIS EXISTS: before #3200 the binary carried more than fifty
# hand-written boolean parsers in seven shapes. Two readers of one knob could
# disagree, and an `asi-hard` floor could accept a token its live reader
# ignored: under `asi-hard`, `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=yes` met the
# floor and still let an unsigned CLI store land (#3618). #3200 moved every
# MANDATE and HATCH reader onto `src/env_flag.rs`. This gate keeps it there.
#
# WHAT IT BLOCKS: a PRODUCTION line outside `src/env_flag.rs` that spells a
# boolean token comparison — `== "1"`, `eq_ignore_ascii_case("true")`, a
# `"yes" | "on"` match arm, `Some("1")`, and the like — inside a function
# that has no row in the NEUTRAL ledger
# (scripts/qc-allowlists/truthy-grammar-neutral-ledger.txt). A reader added
# later without the shared parser FAILS; it cannot land in the ledger
# silently, because a ledger row is a reviewed diff with a date, an issue and
# a reason.
#
# THE LEDGER ONLY SHRINKS: a row whose function no longer holds a grammar hit
# is STALE and FAILS (the gate-9 burn-down discipline), so a migrated reader
# must also leave the ledger. A malformed row FAILS.
#
# Row format:  <src-path> <fn-name> <YYYY-MM-DD> #<issue> <CLASS> <reason...>
#   CLASS is one of:
#     NEUTRAL  a boolean env reader not migrated yet (#3622 burns these down)
#     ENUM     a multi-valued parser that happens to share a boolean token
#     PROMPT   an interactive y/n confirmation, not an env knob
#     QUERY    an HTTP query-parameter boolean, not an env knob
#
# TEST CODE is out of scope. Unlike the older first-`#[cfg(test)]` boundary
# heuristic, this scan skips each test ITEM's extent only — from a
# `#[cfg(test)]` item (or a bare `mod tests {`) to its closing brace at the
# same indentation, which `cargo fmt --check` guarantees — so production code
# BELOW a mid-file test module is still scanned. Files whose basename carries
# `test`/`tests` as a whole `_`-delimited word, and files carrying
# `#![cfg(test)]`, are skipped whole (`attest.rs` is NOT a test file).
#
# Usage:
#   scripts/check-truthy-grammar.sh              exit 0 clean, 1 on violation
#   scripts/check-truthy-grammar.sh --list       print the current hit units
#   scripts/check-truthy-grammar.sh --self-test  prove the gate is load-bearing
#
# Environment overrides (self-test only): TRUTHY_SRC_ROOT, TRUTHY_LEDGER.
#
# Requires bash >= 4 (associative arrays).

if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "check-truthy-grammar.sh: requires bash >= 4 (found ${BASH_VERSION:-unknown}); run it with a modern bash, e.g. '/opt/homebrew/bin/bash $0'." >&2
    exit 1
fi

set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_ROOT="${TRUTHY_SRC_ROOT:-${ROOT}/src}"
LEDGER="${TRUTHY_LEDGER:-${ROOT}/scripts/qc-allowlists/truthy-grammar-neutral-ledger.txt}"
SSOT_REL="env_flag.rs"

# scan_file <path> <label> — one `<label>\t<fn>\t<line>\t<text>` per hit.
scan_file () {
    awk -v file="$2" '
    function indent_of(x) { match(x, /^[ ]*/); return RLENGTH }
    BEGIN { skip_until = -1; pending_cfg = 0; fn = "<top-level>" }
    {
        line = $0
        if (skip_until >= 0) {
            if (line ~ /^[ ]*\}[ ]*$/ && indent_of(line) == skip_until) skip_until = -1
            next
        }
        s = line; sub(/^[ \t]+/, "", s)
        if (s ~ /^#\[cfg\((all\()?test[,)]/) { pending_cfg = 1; next }
        if (pending_cfg) {
            if (s ~ /^#\[/) next
            pending_cfg = 0
            if (s ~ /\{[ ]*$/) skip_until = indent_of(line)
            next
        }
        if (s ~ /^(pub[ ]+)?mod[ ]+tests?[ ]*\{[ ]*$/) { skip_until = indent_of(line); next }
        if (s ~ /^\/\//) next
        if (s ~ /^\*/) next
        if (match(s, /(^|[^A-Za-z0-9_])fn[ ]+[A-Za-z_][A-Za-z0-9_]*/)) {
            t = substr(s, RSTART, RLENGTH); sub(/.*fn[ ]+/, "", t); fn = t
        }
        tok = "\"(1|0|true|false|yes|no|on|off)\""
        if (line ~ ("eq_ignore_ascii_case\\(" tok "\\)") ||
            line ~ ("[=!]= *" tok) ||
            line ~ (tok " *\\|") ||
            line ~ ("\\| *" tok) ||
            line ~ ("(Ok|Some)\\(" tok "\\)")) {
            printf "%s\t%s\t%d\t%s\n", file, fn, NR, s
        }
    }' "$1"
}

# scan_tree — every production hit under SRC_ROOT, sorted.
scan_tree () {
    local f rel
    while IFS= read -r -d '' f; do
        rel="src/${f#"${SRC_ROOT}/"}"
        # A test file is one whose basename carries `test`/`tests` as a whole
        # `_`-delimited word (`tests.rs`, `*_tests.rs`, `test_*.rs`). The older
        # `*test*.rs` glob also skipped `attest.rs`, `attest_v2.rs`,
        # `peer_attestation.rs` and `model_attest.rs`: the attestation code
        # this gate exists to protect.
        [[ "$(basename "$f" .rs)" =~ (^|_)tests?(_|$) ]] && continue
        [[ "${f#"${SRC_ROOT}/"}" == "$SSOT_REL" ]] && continue
        grep -qE '^[[:space:]]*#!\[cfg\(test\)\]' "$f" && continue
        scan_file "$f" "$rel"
    done < <(find "$SRC_ROOT" -type f -name '*.rs' -print0 | sort -z)
}

if [[ "${1:-}" == "--list" ]]; then
    scan_tree | cut -f1,2 | sort -u
    exit 0
fi

# ---------------------------------------------------------------- self-test
if [[ "${1:-}" == "--self-test" ]]; then
    scratch="${ROOT}/.local-runs/truthy-grammar-selftest"
    rm -rf "$scratch"
    mkdir -p "$scratch/src/sub"
    cleanup () { rm -rf "$scratch"; }
    trap cleanup EXIT INT TERM
    cat > "$scratch/src/sub/probe.rs" <<'EOF'
// CONTRIVED fixture for scripts/check-truthy-grammar.sh --self-test.
pub fn ledgered() -> bool {
    std::env::var("AI_MEMORY_PROBE_A").is_ok_and(|v| v == "1")
}
/// A comment that says v == "1" is not code.
pub fn clean() -> bool {
    crate::env_flag::neutral_enabled("AI_MEMORY_PROBE_B")
}
#[cfg(test)]
mod helpers {
    pub fn in_test(v: &str) -> bool {
        v.eq_ignore_ascii_case("true")
    }
}
pub fn below_test_module(v: &str) -> bool {
    matches!(v, "yes" | "on")
}
EOF
    printf '%s\n' 'pub fn ok() -> bool { true }' > "$scratch/src/env_flag.rs"
    printf '%s\n' 'pub fn ssot(v: &str) -> bool { v == "1" }' >> "$scratch/src/env_flag.rs"
    good_ledger="$scratch/ledger-good.txt"
    printf '%s\n' '# fixture ledger' \
        'src/sub/probe.rs ledgered 2026-09-11 #3200 NEUTRAL fixture row' \
        'src/sub/probe.rs below_test_module 2026-09-11 #3200 ENUM fixture row' > "$good_ledger"
    run () { TRUTHY_SRC_ROOT="$scratch/src" TRUTHY_LEDGER="$1" "$BASH" "$0" > "$scratch/out.txt" 2>&1; }
    fail=0
    # 1. Clean fixture passes: ledgered hits only, test-module hit skipped,
    #    comment ignored, the SSOT file exempt.
    if ! run "$good_ledger"; then
        echo "SELF-TEST FAIL: the clean fixture must pass"; cat "$scratch/out.txt"; fail=1
    fi
    # 2. A production reader BELOW a mid-file test module is still scanned:
    #    drop its ledger row and the gate must name it.
    grep -v below_test_module "$good_ledger" > "$scratch/ledger-missing.txt"
    if run "$scratch/ledger-missing.txt" || ! grep -q 'src/sub/probe.rs below_test_module' "$scratch/out.txt"; then
        echo "SELF-TEST FAIL: an unledgered reader below a test module must fail"; cat "$scratch/out.txt"; fail=1
    fi
    # 3. A NEW inline grammar (the #3200 regression) fails.
    printf '%s\n' 'pub fn new_reader() -> bool { std::env::var("AI_MEMORY_X").as_deref() == Ok("1") }' \
        > "$scratch/src/sub/new.rs"
    if run "$good_ledger" || ! grep -q 'src/sub/new.rs new_reader' "$scratch/out.txt"; then
        echo "SELF-TEST FAIL: a new inline grammar must fail"; cat "$scratch/out.txt"; fail=1
    fi
    rm "$scratch/src/sub/new.rs"
    # 3b. A file whose name merely CONTAINS "test" (attest.rs) is scanned.
    printf '%s\n' 'pub fn attested() -> bool { std::env::var("AI_MEMORY_Y").as_deref() == Ok("1") }' \
        > "$scratch/src/sub/attest.rs"
    if run "$good_ledger" || ! grep -q 'src/sub/attest.rs attested' "$scratch/out.txt"; then
        echo "SELF-TEST FAIL: attest.rs must be scanned (it is not a test file)"; cat "$scratch/out.txt"; fail=1
    fi
    rm "$scratch/src/sub/attest.rs"
    # 4. A STALE row (its function holds no hit) fails.
    cp "$good_ledger" "$scratch/ledger-stale.txt"
    printf '%s\n' 'src/sub/probe.rs clean 2026-09-11 #3200 NEUTRAL stale fixture row' >> "$scratch/ledger-stale.txt"
    if run "$scratch/ledger-stale.txt" || ! grep -q 'STALE' "$scratch/out.txt"; then
        echo "SELF-TEST FAIL: a stale ledger row must fail"; cat "$scratch/out.txt"; fail=1
    fi
    # 5. A MALFORMED row fails.
    cp "$good_ledger" "$scratch/ledger-bad.txt"
    printf '%s\n' 'src/sub/probe.rs ledgered yesterday NEUTRAL' >> "$scratch/ledger-bad.txt"
    if run "$scratch/ledger-bad.txt" || ! grep -q 'MALFORMED' "$scratch/out.txt"; then
        echo "SELF-TEST FAIL: a malformed ledger row must fail"; cat "$scratch/out.txt"; fail=1
    fi
    if [[ $fail -ne 0 ]]; then
        exit 1
    fi
    echo "Truthy-grammar gate self-test: PASS (clean fixture, below-test-module scan, new reader, attest.rs scanned, stale row, malformed row)"
    exit 0
fi

# -------------------------------------------------------------------- check
if [[ ! -f "$LEDGER" ]]; then
    echo "FAIL: ledger not found: ${LEDGER#"${ROOT}/"}" >&2
    exit 1
fi

declare -A ledgered=()
violations=0
while IFS= read -r row || [[ -n "$row" ]]; do
    [[ -z "${row// }" || "$row" =~ ^[[:space:]]*# ]] && continue
    if [[ ! "$row" =~ ^(src/[^[:space:]]+\.rs)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*|\<top-level\>)[[:space:]]+([0-9]{4}-[0-9]{2}-[0-9]{2})[[:space:]]+#([0-9]+)[[:space:]]+(NEUTRAL|ENUM|PROMPT|QUERY)[[:space:]]+[^[:space:]].*$ ]]; then
        echo "MALFORMED ledger row: $row"
        echo "  expected: <src-path> <fn> <YYYY-MM-DD> #<issue> <NEUTRAL|ENUM|PROMPT|QUERY> <reason>"
        violations=$((violations + 1))
        continue
    fi
    ledgered["${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"]=1
done < "$LEDGER"

declare -A seen=()
while IFS=$'\t' read -r file fn lineno text; do
    key="$file $fn"
    seen["$key"]=1
    if [[ -z "${ledgered[$key]:-}" ]]; then
        echo "UNLEDGERED inline boolean grammar: $key (line $lineno)"
        echo "  $text"
        echo "  Read the knob through crate::env_flag (a registered BoolKnob for a security"
        echo "  MANDATE/HATCH, env_flag::neutral_enabled otherwise). #3200"
        violations=$((violations + 1))
    fi
done < <(scan_tree)

for key in "${!ledgered[@]}"; do
    if [[ -z "${seen[$key]:-}" ]]; then
        echo "STALE ledger row (no grammar hit left in that function): $key"
        echo "  Remove the row from ${LEDGER#"${ROOT}/"}: the ledger only shrinks."
        violations=$((violations + 1))
    fi
done

if [[ $violations -ne 0 ]]; then
    echo "Truthy-grammar gate: FAIL ($violations violation(s))"
    exit 1
fi
echo "Truthy-grammar gate: PASS (${#seen[@]} ledgered unit(s); every other boolean reader goes through src/env_flag.rs)"
