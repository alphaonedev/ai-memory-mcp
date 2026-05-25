#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v0.7.x (issue #1174 PR10 — pm-v3.1 lint-gate).
#
# HARD-BLOCK any new vendor-identifier literal outside the allowed
# substrate locations, AND any new magic-number SECS_PER_* literal
# passed to `Duration::from_secs()`. Enforced in CI per the pm-v3.1
# prime-directive addendum (ai-memory global/policies memory
# f5334545-c1f5-4f5c-9efb-a0ec3a0c1fcd).
#
# Two checks:
#
#   (A) Vendor-monoculture gate. Every `"claude" | "openai" | "xai" |
#       "anthropic" | "gemini" | "deepseek" | "groq" | "ollama" |
#       "grok" | "mistral" | "cohere" | "huggingface"` literal outside
#       the 6-file substrate allowlist is a HARD-BLOCK. Vendor strings
#       are legitimate only in:
#         - `src/llm.rs`        (canonical alias tables, default URLs)
#         - `src/config.rs`     (per-vendor URL/key/model defaults)
#         - `src/mine.rs`       (Format::Claude conversation-mining enum)
#         - `src/validate.rs`   (VALID_SOURCES back-compat allowlist)
#         - `src/cli/wrap.rs`   (per-vendor CLI-binary WrapStrategy)
#         - `src/harness.rs`    (harness vendor-variant enum)
#
#   (B) SECS_PER_* regression gate. PR3 (#1188 lineage) extracted
#       named constants `SECS_PER_HOUR` / `SECS_PER_DAY` / `SECS_PER_WEEK`
#       in `src/lib.rs` so duration computations carry semantic intent
#       at the call site. Any new `Duration::from_secs(3600)` /
#       `Duration::from_secs(86400)` / `Duration::from_secs(604800)`
#       (with or without underscore separators) is a HARD-BLOCK.
#
# Production-vs-test boundary heuristic (mirrors
# `scripts/qc-codegraph-precheck.sh`):
#   - Test files (basename `*test*.rs` or `tests.rs`) are skipped entirely.
#   - Per-file, the first occurrence of `mod tests {` (or
#     `pub mod tests {`) starts the test region; lines at or below that
#     are skipped. The `#[cfg(test)]` attribute alone is too noisy
#     because it also guards single-item test-helper declarations near
#     the top of files.
#   - Single-line comments (`//` and `///`) and block-comment lines
#     (`*`) are skipped.
#
# Why no codegraph dependency: codegraph indexes live under .codegraph/
# (gitignored, per-developer; not available in CI). `grep` works on
# every checkout and is sufficient for literal-site enumeration.
#
# Usage:
#   scripts/check-vendor-literals.sh
#     - exit 0 on clean, exit 1 on any violation
#   scripts/check-vendor-literals.sh --self-test
#     - injects a contrived violation, verifies the gate catches it,
#       removes the violation. Proves the gate is load-bearing
#       (pm-v3.2 NO FAIL MISSION closure discipline). Exit 0 on
#       PASS, exit 1 on FAIL.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 6-file allowlist. Repo-root-relative paths.
ALLOWED_FILES=(
    "src/llm.rs"
    "src/config.rs"
    "src/mine.rs"
    "src/validate.rs"
    "src/cli/wrap.rs"
    "src/harness.rs"
)

# Vendor identifiers to gate. Keep this list narrow — over-broad gates
# create reviewer friction. Add a new vendor only when an actual
# alias-table entry lands in `src/llm.rs`.
VENDOR_PATTERN='(claude|openai|xai|anthropic|gemini|deepseek|groq|ollama|grok|mistral|cohere|huggingface)'

# SECS_PER_* magic numbers. Catches the literal forms PR3 extracted
# named constants for — both unseparated (`3600`) and underscore-
# separated (`3_600`) variants, plus the common hour multiples
# (`7200`, `21600`).
SECS_LITERAL_PATTERN='Duration::from_secs\((3600|86400|604800|3_600|86_400|604_800|7200|21600|172800|172_800)\)'

# is_allowed_file <repo-root-relative-path>
is_allowed_file () {
    local f="$1"
    local allowed
    for allowed in "${ALLOWED_FILES[@]}"; do
        if [[ "$f" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

# find_test_boundary <file>
# Echoes the line number of the first `mod tests {` (or `pub mod tests {`,
# or attribute-prefixed variants like `#[cfg(test)] mod tests {`); echoes
# `999999999` if no test module is found in the file.
find_test_boundary () {
    local f="$1"
    local line
    line=$(grep -nE '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+tests?[[:space:]]*\{' "$f" 2>/dev/null | head -1 | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo 999999999
    else
        echo "$line"
    fi
}

# scan_production_lines <file> <regex>
# Emits "<repo-relative-file>:<lineno>:<content>" for matches in
# production code. Skips test files by basename + skips lines at or
# below the file's first `mod tests {` boundary + skips comment lines.
scan_production_lines () {
    local f="$1"
    local pattern="$2"
    local bn
    bn="$(basename "$f")"
    case "$bn" in
        *test*.rs|tests.rs) return 0 ;;
    esac
    local boundary
    boundary=$(find_test_boundary "$f")
    local rel="${f#"${ROOT}/"}"
    while IFS=: read -r lineno content; do
        [[ -z "$lineno" ]] && continue
        if (( lineno >= boundary )); then
            continue
        fi
        # Skip comments and doc-comment lines.
        local stripped
        stripped=$(printf '%s' "$content" | sed -E 's/^[[:space:]]+//')
        case "$stripped" in
            //*|/\**|\**) continue ;;
        esac
        printf '%s:%s:%s\n' "$rel" "$lineno" "$content"
    done < <(grep -En "$pattern" "$f" 2>/dev/null || true)
}

# Self-test mode — inject a contrived violation, run the gate, confirm
# it catches the violation, then clean up.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Vendor-literal gate: self-test mode (contrived violation -> expect HARD-BLOCK -> cleanup)"
    # Use a name that does NOT match `*test*.rs` (the production-vs-test
    # filename heuristic skips those) so the self-test's contrived
    # violation actually reaches the scanner.
    contrived="${ROOT}/src/.vendor_literal_gate_probe.rs"
    if [[ -e "$contrived" ]]; then
        echo "ERROR: self-test scratch file already exists: $contrived" >&2
        echo "(cleanup may have failed in a prior run — remove manually)" >&2
        exit 2
    fi
    # Deliberately write a vendor literal at a "production" line (no
    # tests boundary above it) outside the allowlist.
    cat > "$contrived" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-vendor-literals.sh --self-test.
// This file is created + deleted by the self-test; if it persists,
// the self-test was killed mid-run — remove it manually.
pub const BACKEND_PROBE: &str = "anthropic";
EOF
    # Run the gate. Expect non-zero exit + a violation message. Capture
    # the combined output so we can pattern-match on it deterministically
    # (a piped `tee /dev/stderr | grep -q` would race + drop status).
    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e
    rm -f "$contrived"
    printf '%s\n' "$gate_output"
    if (( gate_exit != 0 )) && printf '%s' "$gate_output" | grep -q 'Vendor monoculture violation'; then
        echo ""
        echo "Vendor-literal gate self-test: PASS (gate caught the contrived violation; exit=${gate_exit})"
        exit 0
    else
        echo "" >&2
        echo "Vendor-literal gate self-test: FAIL (gate did not catch the contrived violation; exit=${gate_exit})" >&2
        exit 1
    fi
fi

# Main check.
cd "$ROOT"

vendor_violations=""
secs_violations=""

while IFS= read -r -d '' f; do
    rel="${f#"${ROOT}/"}"
    # Vendor scan: skip files in the allowlist; the file itself is the
    # carve-out, not individual line entries.
    if ! is_allowed_file "$rel"; then
        v=$(scan_production_lines "$f" "\"${VENDOR_PATTERN}\"")
        if [[ -n "$v" ]]; then
            vendor_violations+="$v"$'\n'
        fi
    fi
    # SECS_PER_* scan: applies to every file (no per-file carve-out).
    # PR3 cleaned up every production site; any new one is a regression.
    s=$(scan_production_lines "$f" "$SECS_LITERAL_PATTERN")
    if [[ -n "$s" ]]; then
        secs_violations+="$s"$'\n'
    fi
done < <(find "${ROOT}/src" -type f -name '*.rs' -print0)

violations=0

if [[ -n "${vendor_violations//[[:space:]]/}" ]]; then
    {
        echo "Vendor monoculture violation (issue #1174 PR10 pm-v3.1 lint-gate):"
        # `vendor_violations` is a multi-line "file:line:content" payload;
        # print each line as-is with a two-space indent.
        printf '%s' "$vendor_violations" | sed -E 's/^/  /'
        echo ""
        echo "Vendor identifiers are only allowed in:"
        echo "  - src/llm.rs       (canonical alias tables)"
        echo "  - src/config.rs    (per-vendor URL/key/model defaults)"
        echo "  - src/mine.rs      (Format::Claude conversation-mining enum)"
        echo "  - src/validate.rs  (VALID_SOURCES back-compat allowlist)"
        echo "  - src/cli/wrap.rs  (per-vendor CLI-binary WrapStrategy)"
        echo "  - src/harness.rs   (harness vendor-variant enum)"
        echo ""
        echo "Per pm-v3.1 (ai-memory global/policies memory f5334545-c1f5-4f5c-9efb-a0ec3a0c1fcd):"
        echo "vendor identifiers in substrate/wire code violate the heterogeneous-NHI design."
        echo "Move new vendor-specific code into one of the allowed locations, or refactor"
        echo "the call site to read the vendor string from \`crate::llm::*\` / \`crate::config::*\`"
        echo "(e.g. \`crate::llm::BACKEND_OLLAMA\` instead of the literal \"ollama\")."
    } >&2
    violations=$(( violations + 1 ))
fi

if [[ -n "${secs_violations//[[:space:]]/}" ]]; then
    {
        echo "SECS_PER_* magic-number regression (issue #1174 PR3 / PR10 pm-v3.1 lint-gate):"
        printf '%s' "$secs_violations" | sed -E 's/^/  /'
        echo ""
        echo "Use a named const from src/lib.rs instead of a magic number:"
        echo "  - SECS_PER_HOUR = 3_600"
        echo "  - SECS_PER_DAY  = 86_400"
        echo "  - SECS_PER_WEEK = 604_800"
        echo ""
        echo "Example: \`Duration::from_secs(SECS_PER_HOUR as u64)\`."
    } >&2
    violations=$(( violations + 1 ))
fi

if (( violations > 0 )); then
    echo "" >&2
    echo "Vendor-literal gate: FAIL (${violations} category/categories of violation)" >&2
    exit 1
fi

echo "Vendor-literal gate: PASS (no vendor-monoculture or SECS_PER_* regressions detected)"
