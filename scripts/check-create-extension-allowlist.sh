#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 supply-chain gate (issue #2648) — CREATE EXTENSION allowlist.
# FAIL-CLOSED.
#
# WHY THIS GATE EXISTS. A PostgreSQL extension installs AS SUPERUSER,
# inside the process that owns the substrate — below the SAL, below
# governance, below the signed audit chain — and persists into
# `pg_dump`. It is not a dependency in the ordinary sense; it is code
# executing beneath every control this release has spent its audit
# verifying. `migrations/`, `deploy/`, Dockerfiles, cloud-init
# templates, the bundled `src/store/postgres_schema.sql` and the psql
# invocations in CI/scripts may therefore only `CREATE EXTENSION` a name
# on a CLOSED allowlist. Anything else is a HARD-BLOCK.
#
# WHY AN ALLOWLIST, NOT A DENYLIST (issue #2648). A denylist would have
# to name the specific thing being excluded, writing that name
# permanently into git history. An allowlist covers the entire class,
# names nothing external, and is the same shape as the controls this
# repo already trusts (`scripts/check-vendor-literals.sh`,
# `scripts/check-cloud-init-ascii.sh`, the required-contexts mirror).
#
# THE ALLOWLIST. Enumerated from every `CREATE EXTENSION` the codebase
# legitimately issues at HEAD (src/store/postgres_schema.sql, the
# deploy/infra provisioners, the CI psql steps, the postgres AGE
# fallback test). Exactly two extensions are issued:
#
#   * vector  — pgvector; the ANN / embedding column type. Issued by
#               `src/store/postgres_schema.sql:22`
#               (`CREATE EXTENSION IF NOT EXISTS vector;`), the
#               deploy/infra provisioners and the coverage.yml PG step.
#   * age     — Apache AGE; the knowledge-graph backend. Issued by the
#               deploy/infra AGE bootstrap and `tests/kg_age_fallback.rs`.
#
# `pgcrypto` appears in issue #2648's illustrative set but NO DDL issues
# it at HEAD (the sole repo reference is a comment noting it is *not*
# available on the droplet nodes). It is therefore DELIBERATELY OMITTED:
# the allowlist is kept equal to the actual closure of issued DDL
# (fail-closed minimalism). A future migration that legitimately needs
# pgcrypto adds it to this list in the SAME PR that first issues the DDL
# — the gate then blocks the DDL until the allowlist is updated, which
# is precisely the reviewer checkpoint this control exists to force.
#
# HOW IT MATCHES. The gate extracts the extension NAME from every
# `CREATE EXTENSION [IF NOT EXISTS] <name>` occurrence in the repo —
# in .sql files, shell `printf`/`psql -c` strings, Rust string literals,
# cloud-init `.tpl` templates and Markdown alike — and asserts each name
# is on the allowlist. The name is only recognised in canonical DDL
# position (immediately followed by `;`, a closing quote/backtick/paren,
# or whitespace-then-`WITH`/`SCHEMA`/`CASCADE`), so English prose that
# merely contains the words "CREATE EXTENSION" (e.g. "...forgets CREATE
# EXTENSION gets a graph-less deployment") is structurally NEVER matched
# — it names no DDL. That keeps the gate honest about references without
# false-positiving on documentation.
#
# FAIL-CLOSED on an empty allowlist (issue #2648 req 2, the #2504
# class): an allowlist that admits everything when it is empty or
# unparseable is worse than no gate. If the allowlist array is empty the
# gate exits non-zero WITHOUT scanning.
#
# Why no codegraph / compiler dependency: this is a supply-chain
# property of the source text, checkable on every checkout with `grep`;
# CI has no `.codegraph/` index. Mirrors scripts/check-vendor-literals.sh.
#
# Usage:
#   scripts/check-create-extension-allowlist.sh
#     - exit 0 on clean, exit 1 on any off-allowlist CREATE EXTENSION.
#   scripts/check-create-extension-allowlist.sh --self-test
#     - plants an off-allowlist `CREATE EXTENSION foo;`, asserts the gate
#       HARD-BLOCKS it (non-zero exit, names the offender), then plants
#       an allowlisted `CREATE EXTENSION vector;` and asserts the gate
#       PASSES it (R-203 near-miss control: proves the gate blocks the
#       off-allowlist NAME, not the mere presence of a CREATE EXTENSION).
#       Exit 0 on PASS, exit 1 on FAIL. Per #2635 a supply-chain gate
#       without a self-test has never been shown to be load-bearing, and
#       per #2641 a gate can print a block and still exit 0.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# THE CLOSED ALLOWLIST. Lowercase, unquoted PostgreSQL extension names.
# Keep this list equal to the extensions the repo actually issues DDL for.
# ---------------------------------------------------------------------------
ALLOWLIST=(
    vector
    age
)

# Basename of this script — excluded from the scan so the self-test's own
# `CREATE EXTENSION foo` example and this header never trip the gate.
SELF_BASENAME="$(basename "$0")"

# Canonical DDL matcher. Case-insensitive (applied via `grep -i`). Matches
# `CREATE EXTENSION [IF NOT EXISTS] <name>` where <name> is a PG identifier
# in canonical DDL position: immediately followed by a statement terminator
# (`;`), a closing quote/backtick/paren, or whitespace-then-a-DDL-keyword
# (`WITH`/`SCHEMA`/`CASCADE`). The punctuation terminators must be IMMEDIATE
# (no intervening whitespace) so prose like `CREATE EXTENSION since \`role\``
# — a word followed by a space then a backtick — is NOT mistaken for DDL.
DDL_PATTERN='create[[:space:]]+extension[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?"?[a-z_][a-z0-9_]*([;"`'"'"')]|[[:space:]]+(with|schema|cascade)([[:space:]]|;|$))'

# extract_name <matched-ddl-substring>  ->  lowercase extension name
extract_name () {
    printf '%s' "$1" \
        | tr 'A-Z' 'a-z' \
        | sed -E 's/^create[[:space:]]+extension[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?"?([a-z_][a-z0-9_]*).*/\2/'
}

# is_allowed <name>
is_allowed () {
    local n="$1" a
    for a in "${ALLOWLIST[@]}"; do
        [[ "$n" == "$a" ]] && return 0
    done
    return 1
}

# run_check — the main scan. Echoes "<file>:<line>:<name>" for every
# off-allowlist CREATE EXTENSION found. Returns 0 with no output on clean,
# 2 (fail-closed) if the allowlist is empty.
run_check () {
    # FAIL-CLOSED: an empty allowlist must never wave everything through.
    if (( ${#ALLOWLIST[@]} == 0 )); then
        echo "FATAL: CREATE EXTENSION allowlist is EMPTY — refusing to run (fail-closed, #2648 req 2 / #2504 class)." >&2
        return 2
    fi

    local grep_out
    # -r recurse, -I skip binary, -o each match, -n line number,
    # -i case-insensitive, -E ERE. Exclude .git, build/vendored trees,
    # local worktrees and this script itself.
    grep_out="$(
        grep -rIoniE "$DDL_PATTERN" "$ROOT" \
            --exclude-dir=.git \
            --exclude-dir=.local-runs \
            --exclude-dir=.codegraph \
            --exclude-dir=target \
            --exclude-dir=node_modules \
            --exclude="$SELF_BASENAME" \
            2>/dev/null || true
    )"

    [[ -z "$grep_out" ]] && return 0

    local line rel_line rest name
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # `grep -rn -o` emits `<path>:<lineno>:<match>`. Strip the leading
        # ROOT/ prefix for a repo-relative report; keep path:line intact.
        rel_line="${line#"${ROOT}/"}"
        # Split off the match (everything after the SECOND colon). Path
        # segments never contain the pattern, and lineno is numeric, so
        # the first two colons are the field separators.
        rest="${rel_line#*:}"          # lineno:match
        rest="${rest#*:}"              # match
        name="$(extract_name "$rest")"
        if ! is_allowed "$name"; then
            # Report path:line (drop the raw match tail after the 2nd colon).
            local loc="${rel_line%%:"$rest"}"
            loc="${loc%:}"
            echo "${loc}: CREATE EXTENSION '${name}'"
        fi
    done <<< "$grep_out"

    return 0
}

# ---------------------------------------------------------------------------
# Self-test mode.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    echo "CREATE EXTENSION allowlist gate: self-test (off-allowlist -> HARD-BLOCK; allowlisted near-miss -> PASS; R-203)"

    probe="${ROOT}/.create_extension_gate_probe.sql"
    if [[ -e "$probe" ]]; then
        echo "ERROR: self-test scratch file already exists: $probe" >&2
        echo "(cleanup may have failed in a prior run — remove manually)" >&2
        exit 2
    fi

    # --- Leg 1: an OFF-allowlist extension must be HARD-BLOCKED ------------
    cat > "$probe" <<'EOF'
-- CONTRIVED VIOLATION for scripts/check-create-extension-allowlist.sh --self-test.
-- Created + deleted by the self-test; if it persists, the self-test was
-- killed mid-run — remove it manually.
CREATE EXTENSION IF NOT EXISTS foo;
EOF
    set +e
    block_out="$("$0" 2>&1)"
    block_exit=$?
    set -e
    rm -f "$probe"
    printf '%s\n' "$block_out"

    if (( block_exit == 0 )); then
        echo "" >&2
        echo "CREATE EXTENSION allowlist gate self-test: FAIL (off-allowlist 'foo' NOT blocked; exit=0)" >&2
        exit 1
    fi
    if ! printf '%s' "$block_out" | grep -q "CREATE EXTENSION 'foo'"; then
        echo "" >&2
        echo "CREATE EXTENSION allowlist gate self-test: FAIL (gate exited ${block_exit} but did not name the 'foo' offender)" >&2
        exit 1
    fi

    # --- Leg 2 (R-203 near-miss): an ALLOWLISTED extension must PASS -------
    # Proves the gate blocks the off-allowlist NAME specifically, not the
    # mere presence of a `CREATE EXTENSION` statement. The tree is clean at
    # HEAD, so a lone allowlisted probe must leave the gate GREEN.
    cat > "$probe" <<'EOF'
-- R-203 near-miss control for the CREATE EXTENSION allowlist self-test.
CREATE EXTENSION IF NOT EXISTS vector;
EOF
    set +e
    pass_out="$("$0" 2>&1)"
    pass_exit=$?
    set -e
    rm -f "$probe"

    if (( pass_exit != 0 )); then
        printf '%s\n' "$pass_out" >&2
        echo "" >&2
        echo "CREATE EXTENSION allowlist gate self-test: FAIL (allowlisted near-miss 'vector' was rejected; exit=${pass_exit} — the gate blocks any CREATE EXTENSION, not the off-allowlist name)" >&2
        exit 1
    fi

    echo ""
    echo "CREATE EXTENSION allowlist gate self-test: PASS (off-allowlist 'foo' HARD-BLOCKED exit=${block_exit}; allowlisted 'vector' near-miss PASSED; R-203 satisfied)"
    exit 0
fi

# ---------------------------------------------------------------------------
# Main check.
# ---------------------------------------------------------------------------
set +e
violations="$(run_check)"
check_rc=$?
set -e

if (( check_rc == 2 )); then
    # Fail-closed (empty/unparseable allowlist). Message already emitted.
    exit 1
fi

if [[ -n "${violations//[[:space:]]/}" ]]; then
    {
        echo "CREATE EXTENSION allowlist violation (issue #2648 supply-chain gate):"
        printf '%s\n' "$violations" | sed -E 's/^/  /'
        echo ""
        echo "A PostgreSQL extension installs AS SUPERUSER, beneath the SAL,"
        echo "governance and the signed audit chain, and persists into pg_dump."
        echo "Only these extensions are on the closed allowlist:"
        printf '  - %s\n' "${ALLOWLIST[@]}"
        echo ""
        echo "If this extension is genuinely required, add its name to the"
        echo "ALLOWLIST array in scripts/check-create-extension-allowlist.sh in"
        echo "the SAME change that introduces the DDL — that edit is the"
        echo "reviewer checkpoint this gate exists to force. Otherwise, remove"
        echo "the CREATE EXTENSION statement."
    } >&2
    echo "" >&2
    echo "CREATE EXTENSION allowlist gate: FAIL" >&2
    exit 1
fi

echo "CREATE EXTENSION allowlist gate: PASS (every CREATE EXTENSION names an allowlisted extension: ${ALLOWLIST[*]})"
