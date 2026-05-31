#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/ci-test-impact.sh
#
# v0.7.0 Task #12 (#1399) — Test-impact selection without the codegraph
# runtime dep in CI. Uses `git diff` + a static foundational-fallback
# list + token-overlap matching against `tests/*.rs` binary names to
# compute the minimum integration-test set that proves the diff.
#
# The consumer (CI yaml) ALWAYS runs `cargo test --lib` regardless of
# this script's output — that catches every inline `#[cfg(test)]` mod
# tests under src/ in a single compile-once / link-once pass. This
# script optimises only the slow `tests/*.rs` integration binaries
# (each one compiles + links separately, ~5-15s setup per binary).
#
# Output (writes to $GITHUB_OUTPUT and to stdout, ALL via key=value):
#   test_impact=__SKIP__         # docs-only diff (caller short-circuits)
#   test_impact=__ALL__          # foundational change OR fallback
#   test_impact=<sp-sep names>   # impact-selected (e.g. "memories_query http_form4")
#   test_impact_count=<N>        # number of impacted binaries
#   test_impact_total=<N>        # total tests/*.rs binary count
#   test_impact_reason=<string>  # human-readable explanation
#
# CLI:
#   ci-test-impact.sh <base-sha> [head-sha]
#
# Discipline (mandatory — do NOT relax without operator approval):
#   1. PREFER false-positive (run too many tests) over false-negative
#      (skip a test that would have caught a bug). Every ambiguous
#      case defaults to __ALL__.
#   2. Foundational files force __ALL__. The list is intentionally
#      broad; trim ONLY when a concrete drift case justifies it.
#   3. Parity-test invariants ALWAYS run (route_count_invariant,
#      cli_subcommand_count_invariant, memory_link_relation_count_invariant,
#      etc.) — they are mechanical, millisecond-fast, and exist
#      specifically to catch cross-cutting drift the heuristic might miss.
#   4. When the impact set would be empty for a non-docs / non-foundational
#      diff, fall back to __ALL__ — empty almost certainly means the
#      heuristic missed something.
#
# Self-test:
#   ci-test-impact.sh --self-test
#     (exercises the foundational-list logic, the token-overlap matcher,
#     and the SKIP/ALL/IMPACT triage tree end-to-end against synthetic
#     diff inputs; no git state required)

set -euo pipefail

# --------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------

emit() {
    # $1 = key, $2 = value
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
    fi
    printf '%s=%s\n' "$1" "$2"
}

note() {
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf '::notice::%s\n' "$*"
    else
        printf '[note] %s\n' "$*" >&2
    fi
}

# --------------------------------------------------------------------
# Foundational file list — any match forces __ALL__
# --------------------------------------------------------------------
# Patterns are bash globs evaluated via `case`. Keep this list audited
# against the architecture surface; every entry is load-bearing.

is_foundational() {
    local f="$1"
    case "$f" in
        # Build / toolchain / dependency manifests
        Cargo.toml|Cargo.lock|rust-toolchain|rust-toolchain.toml|build.rs|deny.toml|rustfmt.toml|clippy.toml|.cargo/*) return 0 ;;
        # Library / dispatch root + cross-cutting validation
        src/lib.rs|src/main.rs|src/validate.rs|src/profile.rs|src/errors.rs|src/identity.rs|src/identity/*) return 0 ;;
        # Configuration + boot
        src/config.rs|src/config/*|src/daemon_runtime.rs|src/bootloader.rs) return 0 ;;
        # Schema migrations (every test touching the DB depends on these)
        src/storage/migrations.rs|src/storage/migration_meta.rs|src/storage/mod.rs) return 0 ;;
        migrations/*|migrations/**) return 0 ;;
        # SAL trait surface (touches every store consumer)
        src/store/mod.rs) return 0 ;;
        # MCP dispatch surface (touches every MCP tool)
        src/mcp/mod.rs|src/mcp/registry.rs|src/mcp/profile.rs) return 0 ;;
        # Core data model (every test depends on Memory shape)
        src/models/memory.rs|src/models/link.rs|src/models/mod.rs) return 0 ;;
        # HTTP topology (every handler depends on transport)
        src/handlers/transport.rs|src/handlers/mod.rs|src/handlers/http.rs) return 0 ;;
        # CI + gate scripts (changes to CI itself need full validation)
        .github/workflows/ci.yml|.github/workflows/c8-precheck.yml) return 0 ;;
        scripts/check-vendor-literals.sh|scripts/qc-codegraph-precheck.sh|scripts/ci-test-impact.sh) return 0 ;;
        # Recall + governance + signed events (cross-cutting subsystems)
        src/reranker.rs|src/hnsw.rs|src/embeddings.rs|src/signed_events.rs) return 0 ;;
        src/governance/mod.rs|src/governance/audit.rs|src/governance/rules.rs) return 0 ;;
        *) return 1 ;;
    esac
}

# --------------------------------------------------------------------
# Always-run parity tests — load-bearing drift blockers
# --------------------------------------------------------------------
# These tests are cheap (millisecond runtime) and catch cross-cutting
# drift the heuristic might otherwise miss. Add a test here when it is
# (a) mechanical, (b) fast, (c) load-bearing for a substrate-wide
# invariant.

ALWAYS_RUN_PARITY_TESTS=(
    route_count_invariant
    cli_subcommand_count_invariant
    memory_link_relation_count_invariant
    mcp_input_schema_no_false_strict_1052
    token_budget_guard
    config_precedence
)

# --------------------------------------------------------------------
# Tokenise a path into 3+ char identifiers
# --------------------------------------------------------------------
# Splits on /, _, ., -; drops fragments shorter than 3 chars and a
# stoplist of noise tokens (rs, src, mod, tests, lib, etc.).

tokenise() {
    local path="$1"
    # Strip extension + directory prefix tokens, then split on _-./
    local stem="${path##*/}"          # basename
    stem="${stem%.*}"                 # strip extension
    # Walk the full path so module names matter (handlers, mcp, etc.)
    local full="${path//\//_}"
    full="${full%.*}"
    # Emit unique non-stopword tokens >=3 chars
    {
        printf '%s\n' "$stem"
        printf '%s\n' "$full"
    } | tr '_-./' '\n' | awk '
        length($0) >= 3 \
        && $0 !~ /^(rs|src|lib|mod|tests|test|the|and|for|use|with|core|util|utils|main)$/ {
            print tolower($0)
        }
    ' | sort -u
}

# --------------------------------------------------------------------
# Compute impacted tests/*.rs binaries from a list of changed files
# --------------------------------------------------------------------

compute_impact() {
    # Stdin-and-tmpfile based — works on macOS bash 3 + ubuntu bash 5
    # without requiring associative arrays.
    local repo_root="$1"; shift
    local tmp_tokens
    local tmp_direct
    local tmp_impacted
    tmp_tokens="$(mktemp)"
    tmp_direct="$(mktemp)"
    tmp_impacted="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp_tokens' '$tmp_direct' '$tmp_impacted'" RETURN

    # 1. Collect tokens from every changed src/ + tests/ file
    local f
    for f in "$@"; do
        case "$f" in
            tests/*.rs)
                # Direct test-file change → include it by basename
                basename "$f" .rs >> "$tmp_direct"
                ;;
            src/*|tests/*)
                tokenise "$f" >> "$tmp_tokens"
                ;;
        esac
    done
    # Dedup token + direct lists
    sort -u -o "$tmp_tokens" "$tmp_tokens"
    sort -u -o "$tmp_direct" "$tmp_direct"

    # 2. Match each tests/*.rs basename against the token set
    local t name
    while IFS= read -r t; do
        name="$(basename "$t" .rs)"
        # Direct-include path
        if grep -qxF -- "$name" "$tmp_direct"; then
            printf '%s\n' "$name" >> "$tmp_impacted"
            continue
        fi
        # Token-overlap match: any of THIS test's tokens in the wanted set
        if tokenise "$name.rs" | grep -qxFf "$tmp_tokens" -; then
            printf '%s\n' "$name" >> "$tmp_impacted"
        fi
    done < <(find "$repo_root/tests" -maxdepth 1 -type f -name '*.rs' 2>/dev/null | sort)

    # 3. ALWAYS include the parity invariants (existence-gated)
    for t in "${ALWAYS_RUN_PARITY_TESTS[@]}"; do
        if [[ -f "$repo_root/tests/$t.rs" ]]; then
            printf '%s\n' "$t" >> "$tmp_impacted"
        fi
    done

    # 4. Emit sorted unique list
    [[ -s "$tmp_impacted" ]] && sort -u "$tmp_impacted"
}

# --------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------

run_self_test() {
    local pass=0 fail=0
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_root
    repo_root="$(cd "$script_dir/.." && pwd)"

    check() {
        local name="$1" expected="$2" got="$3"
        if [[ "$expected" == "$got" ]]; then
            printf '  PASS  %s\n' "$name"
            pass=$((pass + 1))
        else
            printf '  FAIL  %s\n        expected: %s\n        got:      %s\n' "$name" "$expected" "$got"
            fail=$((fail + 1))
        fi
    }

    # 1. Foundational detection
    is_foundational "Cargo.toml" && check "Cargo.toml is foundational" "yes" "yes" || check "Cargo.toml is foundational" "yes" "no"
    is_foundational "src/lib.rs" && check "src/lib.rs is foundational" "yes" "yes" || check "src/lib.rs is foundational" "yes" "no"
    is_foundational "src/validate.rs" && check "src/validate.rs is foundational" "yes" "yes" || check "src/validate.rs is foundational" "yes" "no"
    is_foundational "src/storage/migrations.rs" && check "migrations.rs is foundational" "yes" "yes" || check "migrations.rs is foundational" "yes" "no"
    is_foundational "src/handlers/memories.rs" && check "handlers/memories.rs is NOT foundational" "no" "yes" || check "handlers/memories.rs is NOT foundational" "no" "no"
    is_foundational "src/handlers/admin.rs" && check "handlers/admin.rs is NOT foundational" "no" "yes" || check "handlers/admin.rs is NOT foundational" "no" "no"
    is_foundational "tests/foo.rs" && check "tests/foo.rs is NOT foundational" "no" "yes" || check "tests/foo.rs is NOT foundational" "no" "no"
    is_foundational ".github/workflows/ci.yml" && check ".github/workflows/ci.yml IS foundational" "yes" "yes" || check ".github/workflows/ci.yml IS foundational" "yes" "no"

    # 2. Tokenisation — splits compound paths into 3+ char tokens,
    # dropping noise (rs/src/lib/mod/tests/the/...). The split
    # convention drops the compound `memories_query` form because the
    # tokeniser splits on `_`; the components live in the output as
    # separate tokens. This is intentional — it matches more tests
    # (e.g. anything mentioning either "memories" OR "query").
    local toks
    toks=$(tokenise "src/handlers/memories_query.rs" | tr '\n' ' ' | sed 's/ *$//')
    check "tokenise(memories_query) → split + denoised" "handlers memories query" "$toks"

    toks=$(tokenise "src/handlers/admin.rs" | tr '\n' ' ' | sed 's/ *$//')
    check "tokenise(admin) → denoised" "admin handlers" "$toks"

    # 3. Impact computation (smoke — uses real repo state)
    if [[ -d "$repo_root/tests" ]]; then
        local out
        out=$(compute_impact "$repo_root" "src/handlers/admin.rs" | tr '\n' ' ' | sed 's/ $//')
        # Expect at least one admin_* test in there
        if printf '%s\n' "$out" | grep -q 'admin_'; then
            check "compute_impact(handlers/admin.rs) includes admin_*" "yes" "yes"
        else
            check "compute_impact(handlers/admin.rs) includes admin_*" "yes" "no — got: $out"
        fi
        # Parity tests always present
        if printf '%s\n' "$out" | grep -q 'route_count_invariant'; then
            check "compute_impact always includes route_count_invariant" "yes" "yes"
        else
            check "compute_impact always includes route_count_invariant" "yes" "no"
        fi
    fi

    printf '\n[self-test] %d passed / %d failed\n' "$pass" "$fail"
    [[ "$fail" -eq 0 ]] || exit 1
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

if [[ "${1:-}" == "--self-test" ]]; then
    run_self_test
    exit 0
fi

BASE="${1:-}"
HEAD="${2:-HEAD}"

if [[ -z "$BASE" ]]; then
    note "no base SHA supplied — running FULL suite"
    emit "test_impact" "__ALL__"
    emit "test_impact_count" "ALL"
    emit "test_impact_total" "ALL"
    emit "test_impact_reason" "no-base-sha"
    exit 0
fi

if ! git rev-parse "$BASE" >/dev/null 2>&1; then
    note "base SHA $BASE not in repo — running FULL suite"
    emit "test_impact" "__ALL__"
    emit "test_impact_count" "ALL"
    emit "test_impact_total" "ALL"
    emit "test_impact_reason" "base-unreachable"
    exit 0
fi

# Compute changed file list (portable read-loop — bash 3 lacks mapfile)
CHANGED=()
while IFS= read -r _line; do
    [[ -n "$_line" ]] && CHANGED+=("$_line")
done < <(git diff --name-only "$BASE" "$HEAD" 2>/dev/null || true)

if [[ ${#CHANGED[@]} -eq 0 ]]; then
    note "no diff vs base — treating as docs-only no-op"
    emit "test_impact" "__SKIP__"
    emit "test_impact_count" "0"
    emit "test_impact_total" "0"
    emit "test_impact_reason" "empty-diff"
    exit 0
fi

# docs-only check (mirrors the existing classify job's logic)
docs_only=true
for f in "${CHANGED[@]}"; do
    case "$f" in
        docs/*|*.md) ;;
        *) docs_only=false; break ;;
    esac
done
if [[ "$docs_only" == "true" ]]; then
    emit "test_impact" "__SKIP__"
    emit "test_impact_count" "0"
    emit "test_impact_total" "0"
    emit "test_impact_reason" "docs-only"
    exit 0
fi

# Foundational check
for f in "${CHANGED[@]}"; do
    if is_foundational "$f"; then
        note "foundational change detected ($f) — running FULL suite"
        emit "test_impact" "__ALL__"
        emit "test_impact_count" "ALL"
        emit "test_impact_total" "ALL"
        emit "test_impact_reason" "foundational:$f"
        exit 0
    fi
done

# Compute the impact set
REPO_ROOT="$(git rev-parse --show-toplevel)"
IMPACTED=()
while IFS= read -r _line; do
    [[ -n "$_line" ]] && IMPACTED+=("$_line")
done < <(compute_impact "$REPO_ROOT" "${CHANGED[@]}")

TOTAL_TESTS=$(find "$REPO_ROOT/tests" -maxdepth 1 -type f -name '*.rs' 2>/dev/null | wc -l | tr -d ' ')

if [[ ${#IMPACTED[@]} -eq 0 ]]; then
    # Empty impact for non-docs / non-foundational diff is suspicious.
    # Fall back to FULL suite per discipline rule #4.
    note "empty impact set for non-foundational diff — falling back to FULL suite"
    emit "test_impact" "__ALL__"
    emit "test_impact_count" "ALL"
    emit "test_impact_total" "$TOTAL_TESTS"
    emit "test_impact_reason" "empty-impact-fallback"
    exit 0
fi

IMPACT_STRING="$(printf '%s ' "${IMPACTED[@]}" | sed 's/ $//')"
IMPACT_COUNT="${#IMPACTED[@]}"
REDUCTION_PCT=$(( (TOTAL_TESTS - IMPACT_COUNT) * 100 / (TOTAL_TESTS > 0 ? TOTAL_TESTS : 1) ))

emit "test_impact" "$IMPACT_STRING"
emit "test_impact_count" "$IMPACT_COUNT"
emit "test_impact_total" "$TOTAL_TESTS"
emit "test_impact_reason" "impact-selected:${IMPACT_COUNT}/${TOTAL_TESTS} (${REDUCTION_PCT}%-skip)"

note "test-impact: ${IMPACT_COUNT}/${TOTAL_TESTS} integration binaries (${REDUCTION_PCT}% skip)"
