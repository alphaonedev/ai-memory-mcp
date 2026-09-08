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
#
# PORTABILITY / DETERMINISM CONTRACT (#3537). This gate is run on both a
# Linux push gate (GNU coreutils + gawk + GNU grep) and a macOS gate host
# (BSD coreutils + one-true-awk + ugrep/BSD grep). It MUST return the same
# verdict on both, because a single frozen baseline is shared by both.
#
# The whole pipeline therefore runs under `LC_ALL=C`, and the length test
# below is BYTE length. Why, precisely:
#
#   - GROUPING (the actual #3537 false FAIL): the literal key identity is
#     decided by `sort | uniq -c`. BSD/macOS `uniq` compares lines with the
#     LOCALE COLLATION, and in en_US.UTF-8 a run of U+2500 BOX DRAWINGS
#     LIGHT HORIZONTAL collates as ignorable — so the 89-, 81- and 109-char
#     box rules in src/bench.rs / src/bench_relevance.rs (three DISTINCT
#     literals, one site each) folded into ONE group with count 3 and were
#     reported as `+3 (baseline 0)`. GNU `uniq` compares bytes, so on Linux
#     they stayed three count-1 entries, below DUP_THRESHOLD, and never
#     entered the baseline. `LC_ALL=C` makes `uniq` byte-exact everywhere,
#     which is the semantics the shipped baseline encodes.
#
#   - LENGTH (latent, same class): one-true-awk `length()` counts BYTES
#     (243 for that 81-char rule) while gawk in a UTF-8 locale counts
#     CHARACTERS (81), so MIN_LEN meant two different things per host.
#     Under `LC_ALL=C` every awk (gawk, mawk, one-true-awk, BSD awk) makes
#     `length()` byte length, so MIN_LEN has ONE meaning. Byte length is
#     also the fail-closed choice: bytes >= chars, so the byte test admits
#     a SUPERSET of the char test — the gate can only ever catch more, never
#     fewer, duplicated magic strings. On the tree this baseline was frozen
#     from, the two measures select an identical literal set, so pinning
#     bytes does not reinterpret any existing baseline entry.
#
# `--self-test` re-proves both properties against every awk on the host.
# Override the awk with AWK_BIN=/path/to/awk (the self-test uses this).
#
# Requires bash >= 4 (Grok W2-bash3): this gate uses an associative array
# (`declare -A base_count`), absent from bash 3.2 (stock on macOS — Apple
# has shipped no post-3.2 bash since the GPLv3 switch). Running under 3.2
# previously died with an opaque syntax error deep in the script; the
# guard below fails fast with an actionable message instead.

if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "check-hardcoded-literals.sh: requires bash >= 4 (found ${BASH_VERSION:-unknown}) — this gate uses an associative array that stock macOS bash 3.2 cannot run. Install a modern bash (e.g. 'brew install bash') and re-run explicitly, e.g. '/opt/homebrew/bin/bash $0 --self-test'." >&2
    exit 1
fi

set -euo pipefail

# #3537 — pin the collation/character semantics for the ENTIRE pipeline
# (grep, awk, sort, uniq and bash's own pattern matching). See the
# PORTABILITY / DETERMINISM CONTRACT above. LC_ALL has the highest
# precedence of the locale variables, so this one export is sufficient.
export LC_ALL=C

# The awk used for extraction. Overridable so --self-test can re-run the
# extraction under every awk installed on the host and prove they agree.
AWK="${AWK_BIN:-awk}"

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
    # #1577 — the attr+mod pairing must only fire on an INLINE module
    # body (`mod x {`), never a `mod x;` declaration whose body lives
    # in another file (e.g. mcp/mod.rs's `#[cfg(test)] pub(super) mod
    # parity_test_helpers;` made the gate skip 13.9k production lines).
    # Attr pattern also widened to catch `#[cfg(all(test, ...))]`.
    line_cfg=$("$AWK" '/^[[:space:]]*#\[cfg\((all\()?test[,)]/{attr=NR; next}
                    attr && /^[[:space:]]*(pub([(][^)]*[)])?[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\{/{print attr; exit}
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
    "$AWK" -v boundary="$boundary" -v minlen="$MIN_LEN" '
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
                # BYTE length: LC_ALL=C above makes length() byte length on
                # gawk, mawk, one-true-awk and BSD awk alike (#3537).
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
    | "$AWK" -v thr="$DUP_THRESHOLD" '$1 >= thr {
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
# Three planted probes, run once per awk installed on the host (#3537):
#   A  gate-probe-magic-string-xyz x3   -> MUST be reported (gate is load-bearing)
#   B  three U+2500 rules of DIFFERENT  -> MUST NOT be reported (three DISTINCT
#      lengths, one site each              literals; folding them into one count-3
#                                          group was the #3537 false FAIL)
#   C  a 4-char / 12-byte multibyte     -> MUST be reported (pins BYTE length
#      literal x3                          semantics for MIN_LEN)
# Every awk must produce a BYTE-IDENTICAL violation set, or the gate is not
# portable and the shared baseline cannot be trusted.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Hardcoded-literal gate: self-test (planted probes A/B/C, once per awk on this host; #3537)"

    probe_dup="${ROOT}/src/.hardcoded_literal_gate_probe.rs"
    probe_mb="${ROOT}/src/.hardcoded_literal_gate_probe_mb.rs"
    for probe in "$probe_dup" "$probe_mb"; do
        if [[ -e "$probe" ]]; then
            echo "ERROR: self-test scratch already exists: $probe" >&2
            exit 2
        fi
    done
    # Always remove the planted files, including on a kill: a leftover
    # contrived .rs under src/ would break the build for everyone.
    self_test_cleanup () { rm -f "$probe_dup" "$probe_mb"; }
    trap self_test_cleanup EXIT INT TERM

    # Probe A — a brand-new magic string on 3 production sites (absent from baseline).
    cat > "$probe_dup" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-hardcoded-literals.sh --self-test.
// Deleted by the self-test; if it persists, the run was killed — remove it.
pub fn a() -> &'static str { "gate-probe-magic-string-xyz" }
pub fn b() -> &'static str { "gate-probe-magic-string-xyz" }
pub fn c() -> &'static str { "gate-probe-magic-string-xyz" }
EOF

    # Probes B and C. Built from octal BYTE escapes so the planted bytes are
    # exact regardless of the locale this script runs under.
    mb_rule_char="$(printf '\342\224\200')"                              # U+2500
    mb_short="$(printf '\343\202\254\343\202\254\343\202\254\343\202\254')" # 4 chars / 12 bytes
    mb_rule () {
        local n="$1" out="" i
        for (( i = 0; i < n; i++ )); do out+="$mb_rule_char"; done
        printf '%s' "$out"
    }
    {
        echo "// CONTRIVED VIOLATION for scripts/check-hardcoded-literals.sh --self-test (#3537)."
        echo "// Deleted by the self-test; if it persists, the run was killed — remove it."
        echo "pub fn r1() -> &'static str { \"$(mb_rule 12)\" }"
        echo "pub fn r2() -> &'static str { \"$(mb_rule 15)\" }"
        echo "pub fn r3() -> &'static str { \"$(mb_rule 18)\" }"
        echo "pub fn m1() -> &'static str { \"${mb_short}\" }"
        echo "pub fn m2() -> &'static str { \"${mb_short}\" }"
        echo "pub fn m3() -> &'static str { \"${mb_short}\" }"
    } > "$probe_mb"

    # Enumerate the awks present, de-duplicating by resolved path.
    awk_bins=()
    awk_labels=()
    for cand in awk gawk mawk nawk /usr/bin/awk /usr/bin/gawk /usr/bin/mawk; do
        cand_path="$(command -v "$cand" 2>/dev/null || true)"
        if [[ -z "$cand_path" || ! -x "$cand_path" ]]; then
            echo "  awk candidate '${cand}': ABSENT — skipped"
            continue
        fi
        cand_path="$( (cd "$(dirname "$cand_path")" && pwd -P) || dirname "$cand_path" )/$(basename "$cand_path")"
        already=0
        for seen in ${awk_bins[@]+"${awk_bins[@]}"}; do
            [[ "$seen" == "$cand_path" ]] && already=1
        done
        if (( already )); then
            echo "  awk candidate '${cand}': same binary as one already listed (${cand_path}) — skipped"
            continue
        fi
        awk_bins+=("$cand_path")
        # `set -o pipefail` is on, so an awk that errors on --version would
        # make this append non-zero and `set -e` would kill the self-test.
        cand_ver="$("$cand_path" --version </dev/null 2>&1 | head -1 || true)"
        awk_labels+=("${cand} -> ${cand_path} [${cand_ver:-version unknown}]")
    done
    if (( ${#awk_bins[@]} == 0 )); then
        echo "Hardcoded-literal gate self-test: FAIL (no awk found on PATH)" >&2
        exit 1
    fi
    echo "  awks under test (${#awk_bins[@]}):"
    for label in "${awk_labels[@]}"; do echo "    - ${label}"; done

    st_status=0
    ref_violations=""
    ref_awk=""
    for awk_bin in "${awk_bins[@]}"; do
        set +e
        # Re-enter through the INTERPRETER WE ARE RUNNING UNDER, never the
        # shebang: `#!/usr/bin/env bash` resolves to whatever bash is first on
        # PATH, which on macOS with /usr/bin ahead of the homebrew prefix is
        # stock bash 3.2 — the child would then die on the bash>=4 guard and
        # the self-test would report a phantom failure (#3537).
        gate_output="$(AWK_BIN="$awk_bin" "${BASH:-bash}" "$0" 2>&1)"
        gate_exit=$?
        set -e
        violations="$(printf '%s\n' "$gate_output" | grep -E '^[[:space:]]*\+[0-9]+ \(baseline ' || true)"

        echo ""
        echo "  --- ${awk_bin} (exit=${gate_exit}) ---"
        printf '%s\n' "${violations:-    (no violations reported)}"

        # A: the contrived triplicated literal must be caught.
        if (( gate_exit == 0 )) || ! printf '%s' "$violations" | grep -qF 'gate-probe-magic-string-xyz'; then
            echo "  probe A (triplicated magic string): FAIL — not reported by ${awk_bin}" >&2
            st_status=1
        else
            echo "  probe A (triplicated magic string): reported — OK"
        fi
        # B: three DISTINCT multibyte rules, one site each, must NOT be reported.
        if printf '%s' "$violations" | grep -qF "$mb_rule_char"; then
            echo "  probe B (#3537 distinct multibyte rules): FAIL — folded into a duplicate group by ${awk_bin}" >&2
            st_status=1
        else
            echo "  probe B (#3537 distinct multibyte rules): not folded — OK"
        fi
        # C: the short-in-chars / long-in-bytes literal must be caught (BYTE MIN_LEN).
        if ! printf '%s' "$violations" | grep -qF "$mb_short"; then
            echo "  probe C (multibyte byte-length MIN_LEN): FAIL — not reported by ${awk_bin}" >&2
            st_status=1
        else
            echo "  probe C (multibyte byte-length MIN_LEN): reported — OK"
        fi
        # Cross-awk agreement: identical violation sets, byte for byte.
        if [[ -z "$ref_awk" ]]; then
            ref_awk="$awk_bin"
            ref_violations="$violations"
        elif [[ "$violations" != "$ref_violations" ]]; then
            echo "  cross-awk agreement: FAIL — ${awk_bin} disagrees with ${ref_awk}" >&2
            st_status=1
        else
            echo "  cross-awk agreement with ${ref_awk}: identical — OK"
        fi
    done

    self_test_cleanup
    trap - EXIT INT TERM

    echo ""
    if (( st_status == 0 )); then
        echo "Hardcoded-literal gate self-test: PASS (probes A/B/C correct and byte-identical across ${#awk_bins[@]} awk(s))"
        exit 0
    fi
    echo "Hardcoded-literal gate self-test: FAIL" >&2
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
