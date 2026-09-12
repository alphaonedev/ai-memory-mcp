#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# C8 orchestrator safeguard (per CLAUDE.md §"Enforceable Orchestrator
# Safeguards", added under #923 + #953). HARD-BLOCK any new
# `CallerContext::for_agent("<literal>")` site outside the allowlist,
# and any new `CallerContext::for_admin("<literal>")` privacy-bypass
# site outside its allowlist.
#
# Usage:
#   scripts/qc-codegraph-precheck.sh            # check (exit 1 on violation)
#   scripts/qc-codegraph-precheck.sh --update   # regenerate allowlists from current state
#
# What it checks:
#   - Every line in src/ matching `CallerContext::for_agent("<lit>")`
#     OR `for_agent("<lit>")` where the literal is a static string
#     (not a variable reference). Test code is excluded — see
#     `is_production_site` below.
#   - Same scan for `for_admin("<lit>")`.
#   - Each surviving site must appear in the corresponding allowlist.
#
# What it deliberately does NOT do (out of scope for v0.7.0):
#   - Symbol removal / dangling-caller detection. Codegraph indexes
#     are per-developer and not available in CI; this script uses
#     `grep` as the load-bearing detector. The deeper codegraph
#     integration is tracked separately and can layer on top of the
#     allowlist contract this script enforces.
#
# Why grep (not codegraph): CodeGraph indexes live under .codegraph/
# (gitignored, per-developer; not in CI). For a CI-grade pre-PR gate
# we need a tool every checkout already has. `grep` is sufficient for
# the literal-site enumeration; the rest of the C8 contract (rationale
# for each site) lives in the allowlist files' comments.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${ROOT}/scripts/lib/production-lines.sh"
ALLOW_DIR="${ROOT}/scripts/qc-codegraph-allowlists"
ALLOW_FOR_AGENT="${ALLOW_DIR}/caller-context-literals.txt"
ALLOW_FOR_ADMIN="${ALLOW_DIR}/for-admin-bypass.txt"

if [[ ! -d "${ALLOW_DIR}" ]]; then
    echo "ERROR: allowlist dir missing: ${ALLOW_DIR}" >&2
    exit 2
fi

UPDATE=0
if [[ "${1:-}" == "--update" ]]; then
    UPDATE=1
fi

# --self-test (#1651): prove the for_admin detector is load-bearing for
# the SENTINEL-CONST call form (the #1558 refactor moved every
# production site off string literals, which silently collapsed the
# literal-only detector's coverage to zero). Injects a transient
# production file containing a sentinel-form for_admin call, expects
# the main check to HARD-BLOCK, then cleans up.
if [[ "${1:-}" == "--self-test" ]]; then
    python3 "${ROOT}/scripts/tests/gate-production-3623.py" "$(basename "$0")"
    PROBE="${ROOT}/src/c8_probe_1651.rs"
    trap 'rm -f "${PROBE}"' EXIT
    cat > "${PROBE}" <<'PROBE_EOF'
// C8 --self-test probe (transient; created + removed by qc-codegraph-precheck.sh --self-test)
pub fn probe() {
    let _ = CallerContext::for_admin(sentinels::C8_SELF_TEST_PROBE);
}
PROBE_EOF
    if "$0" >/dev/null 2>&1; then
        echo "C8 SELF-TEST FAIL: sentinel-form for_admin injection was NOT detected" >&2
        exit 1
    fi
    echo "C8 SELF-TEST PASS: sentinel-form for_admin injection HARD-BLOCKed as expected"
    exit 0
fi

# Enumerate production sites through the shared #3623 item filter.
collect_sites () {
    local pattern="$1"
    local mode="${2:-literal}"
    local out=""
    # Find src files; production_lines applies the test exclusions.
    while IFS= read -r -d '' f; do
        local production
        production="$(production_lines "$f")"
        # Find matching lines with original source line numbers.
        # Pattern format: `for_agent("LIT")` or `for_admin("LIT")`.
        #
        # NOTE: the inner match list is captured into a variable and fed
        # to the loop via a here-string (`<<<`) rather than a second
        # process substitution. A process substitution nested inside the
        # outer `< <(find ...)` one reliably SIGTRAPs (exit 133) under
        # macOS system bash 3.2 on arm64; the here-string is behaviour-
        # identical and runs the loop in the current shell so `out`
        # still accumulates.
        local matches
        if [[ "${mode}" == "any-arg" ]]; then
            # #1651 — for_admin is a privacy-bypass CONSTRUCTION; the
            # bypass is the call itself, in ANY argument form. The
            # pre-#1651 literal-only grep went blind when #1558 moved
            # every site onto sentinel consts.
            matches="$(printf '%s\n' "$production" | grep -n "${pattern}(" || true)"
        else
            matches="$(printf '%s\n' "$production" | grep -n "${pattern}(\"" || true)"
        fi
        [[ -z "${matches}" ]] && continue
        while IFS=: read -r lineno content; do
            # Skip blank/no-match
            [[ -z "${lineno}" ]] && continue
            # Skip comment lines (//, ///, block-comment continuations) —
            # prose mentioning the call is not a call site (#1651).
            if printf '%s\n' "$content" | grep -qE '^[[:space:]]*(//|\*)'; then
                continue
            fi
            # Extract the literal between `${pattern}("` and `")`.
            local literal
            literal=$(printf '%s\n' "$content" | sed -nE "s/.*${pattern}\(\"([^\"]+)\"\).*/\1/p" | head -1)
            if [[ -z "${literal}" && "${mode}" == "any-arg" ]]; then
                # #1651 — non-literal argument: key on the argument
                # expression (identifier / sentinel path / variable),
                # normalized to its last `::` segment so the allowlist
                # stays stable across import-style refactors.
                literal=$(printf '%s\n' "$content" \
                    | sed -nE "s/.*${pattern}\(([^\")(,]+)[,)].*/\1/p" \
                    | head -1 | tr -d ' &')
                if [[ -z "${literal}" ]] \
                    && printf '%s\n' "$content" | grep -qE "${pattern}\($"; then
                    # Call split across lines (rustfmt reflow): take
                    # the first token of the next source line.
                    local nextline
                    nextline=$(sed -n "$((lineno + 1))p" "$f")
                    literal=$(printf '%s\n' "$nextline" | sed -nE 's/^[[:space:]]*"([^"]+)".*/\1/p')
                    [[ -z "${literal}" ]] && literal=$(printf '%s\n' "$nextline" \
                        | sed -nE 's/^[[:space:]]*([A-Za-z0-9_:&]+).*/\1/p' | tr -d '&')
                fi
                literal="${literal##*::}"
            fi
            if [[ -n "${literal}" ]]; then
                # Strip the absolute prefix so the allowlist is
                # repo-root-relative (and stable across checkouts).
                local rel="${f#"${ROOT}/"}"
                # #3623 Conductor ruling: this one tenant-reachable governance
                # read is adjudicated separately by #3638 (policy disclosure
                # redaction). It is NOT an approved system-internal bypass.
                # Re-pinned at release e8d8eb67a after the authorized rebase.
                # Pin the exact release-base site, not the file/principal: a
                # moved, changed, or additional call must be reviewed again.
                if [[ "$mode" == "any-arg" && "$rel" == "src/store/postgres.rs" \
                    && "$lineno" == 31500 \
                    && "$content" == '            let ctx = CallerContext::for_admin(crate::identity::sentinels::GOVERNANCE_INTERNAL);' ]]; then
                    continue
                fi
                out+="${rel}:${lineno}:${literal}"$'\n'
            fi
        done <<< "${matches}"
    done < <(find "${ROOT}/src" -type f -name '*.rs' -print0)
    # Sort + dedup so the diff against the allowlist is order-stable.
    printf '%s' "$out" | LC_ALL=C sort -u
}

CURRENT_FOR_AGENT="$(collect_sites 'CallerContext::for_agent')"
CURRENT_FOR_ADMIN="$(collect_sites 'CallerContext::for_admin' any-arg)"

# Strip the line-number column from a "file:line:literal" stream so
# the allowlist contract is `file:literal` only — line numbers drift
# on every unrelated edit and would otherwise flood the diff.
# Literals can contain `:` (e.g. `ai:seed`, `ai:http-internal`), so
# we use sed with a regex that requires the second column to be
# digits — preserves the rest of the line verbatim.
strip_line () {
    sed -E 's/^([^:]+):[0-9]+:(.*)$/\1:\2/'
}

CURRENT_FOR_AGENT_NORM="$(printf '%s' "$CURRENT_FOR_AGENT" | strip_line | LC_ALL=C sort -u)"
CURRENT_FOR_ADMIN_NORM="$(printf '%s' "$CURRENT_FOR_ADMIN" | strip_line | LC_ALL=C sort -u)"

write_allowlist () {
    local out="$1"
    local payload="$2"
    local title="$3"
    {
        printf '# %s\n' "$title"
        printf '# Auto-generated by scripts/qc-codegraph-precheck.sh --update.\n'
        printf '# Format: <repo-root-relative-file>:<literal>\n'
        printf '# Edit deliberately — every entry should be a reviewed exception.\n'
        printf '# See CLAUDE.md §"Enforceable Orchestrator Safeguards" (C8).\n'
        printf '\n'
        printf '%s\n' "$payload"
    } > "$out"
}

if (( UPDATE )); then
    write_allowlist "$ALLOW_FOR_AGENT" "$CURRENT_FOR_AGENT_NORM" \
        "CallerContext::for_agent(\"<literal>\") allowlist (C8 safeguard)."
    write_allowlist "$ALLOW_FOR_ADMIN" "$CURRENT_FOR_ADMIN_NORM" \
        "CallerContext::for_admin(\"<literal>\") privacy-bypass allowlist (C8 safeguard)."
    echo "Allowlists regenerated:"
    echo "  ${ALLOW_FOR_AGENT}"
    echo "  ${ALLOW_FOR_ADMIN}"
    exit 0
fi

if [[ ! -f "$ALLOW_FOR_AGENT" || ! -f "$ALLOW_FOR_ADMIN" ]]; then
    echo "ERROR: allowlist file(s) missing. Run \`scripts/qc-codegraph-precheck.sh --update\` to seed." >&2
    exit 2
fi

# The allowlist files carry a comment header (lines starting with `#`)
# + a blank line; the payload is `<file>:<literal>` pairs. Strip
# comments + blanks before diffing.
strip_comments () {
    # `grep -v` returns 1 when its input is empty after filtering;
    # that triggers `set -e` + `pipefail` and aborts the script. The
    # `|| true` swallows the non-zero so an empty allowlist body
    # (e.g. the for_agent file post-#955) is treated as legitimate.
    { grep -v '^#' "$1" | grep -v '^$' | LC_ALL=C sort -u; } || true
}

ALLOW_FOR_AGENT_BODY="$(strip_comments "$ALLOW_FOR_AGENT")"
ALLOW_FOR_ADMIN_BODY="$(strip_comments "$ALLOW_FOR_ADMIN")"

violations=0

check_diff () {
    local label="$1"
    local current="$2"
    local allow="$3"
    # New sites = lines in current not in allow.
    local new_sites
    new_sites="$(LC_ALL=C comm -23 \
        <(printf '%s\n' "$current") \
        <(printf '%s\n' "$allow") || true)"
    if [[ -n "${new_sites//[[:space:]]/}" ]]; then
        echo "C8 HARD-BLOCK: new ${label} site(s) not in allowlist:" >&2
        printf '  %s\n' "${new_sites}" >&2
        echo "" >&2
        echo "If these are deliberate exceptions, run:" >&2
        echo "  scripts/qc-codegraph-precheck.sh --update" >&2
        echo "and review the diff to ${ALLOW_DIR%/}/*.txt before committing." >&2
        violations=$(( violations + 1 ))
    fi
    # Stale entries = lines in allow not in current. Surface as a
    # WARN — not a hard block — so unrelated refactors that delete a
    # site don't fail unrelated PRs.
    local stale
    stale="$(LC_ALL=C comm -13 \
        <(printf '%s\n' "$current") \
        <(printf '%s\n' "$allow") || true)"
    if [[ -n "${stale//[[:space:]]/}" ]]; then
        echo "C8 WARN: stale ${label} allowlist entries (no longer present in source):" >&2
        printf '  %s\n' "${stale}" >&2
        echo "  → run \`scripts/qc-codegraph-precheck.sh --update\` to prune." >&2
    fi
}

check_diff "CallerContext::for_agent" "$CURRENT_FOR_AGENT_NORM" "$ALLOW_FOR_AGENT_BODY"
check_diff "CallerContext::for_admin" "$CURRENT_FOR_ADMIN_NORM" "$ALLOW_FOR_ADMIN_BODY"

if (( violations > 0 )); then
    echo "" >&2
    echo "C8 precheck FAILED with ${violations} category/categories of violation." >&2
    exit 1
fi

echo "C8 precheck OK (for_agent: $(printf '%s\n' "$CURRENT_FOR_AGENT_NORM" | grep -c . || true) sites, for_admin: $(printf '%s\n' "$CURRENT_FOR_ADMIN_NORM" | grep -c . || true) sites)."
