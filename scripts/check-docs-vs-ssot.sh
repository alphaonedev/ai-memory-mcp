#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-docs-vs-ssot.sh
#
# v0.7.0 operator directive 2026-05-31 — "can we use variables in
# documentation for versions instead of literals?"
#
# Markdown doesn't have native variables; the canonical Rust consts
# (`CURRENT_SCHEMA_VERSION`, `EXPECTED_*`, `Memory::FIELD_COUNT`, etc.)
# aren't accessible from `.md` files at render time. This gate is the
# minimal-infra answer: instead of templating + rendering, we
# DETECT drift between the canonical SSOTs (in Rust source) and any
# narrative-counted value cited in the operator-facing docs.
#
# When a Rust const changes, the gate fails on the next CI run if any
# doc file still cites the old value, telling the contributor exactly
# which lines to update. A template-render pipeline can land at v0.8;
# this gate gives us the safety property today without the build
# infra cost.
#
# # What it checks
#
# Each rule below pairs a CANONICAL SSOT (where the value lives in
# Rust source) with the patterns the operator-facing docs use to
# narrate that value. The gate parses the SSOT, walks the docs for
# matching patterns, and asserts every captured value matches the
# canonical.
#
# Rules:
#  - CURRENT_SCHEMA_VERSION → docs claims of "schema v<N>",
#    "CURRENT_SCHEMA_VERSION = <N>", "schema_version=<N>",
#    "schema_version = <N>", the release-notes.md markdown-table row
#    "| Schema | **v<N>** (`CURRENT_SCHEMA_VERSION`", and ROADMAP's
#    scoped plain-prose "the current substrate has advanced to schema
#    <N>" phrasing (#2282). Historical "v52 added X" / "v51 added X"
#    narrative refs are LEFT ALONE (they describe past ladder events,
#    not the current canonical state).
#  - EXPECTED_PRODUCTION_ROUTES_COUNT → docs claims of
#    "<N> production HTTP routes" / "<N> .route(" / "<N> production
#    route registrations".
#  - EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT → docs claims of "<N>
#    unique URL paths".
#  - EXPECTED_CLI_SUBCOMMANDS_DEFAULT / _SAL → docs claims of "<N> CLI
#    subcommands" + "<N> in default build" / "<N> under --features sal".
#  - Profile::full().expected_tool_count() (=74) → docs claims of
#    "74 advertised entries", "74 MCP tools", etc. The 73-vs-74
#    disambiguation (73 callable tools + 1 memory_capabilities
#    bootstrap) is the documented exception and is allowlisted.
#  - Cargo.toml `version` (current release) → the "<N> advertised
#    entries at `--profile full`** at v<X>" narrative form must
#    attribute the CURRENT release, never a stale prior one (#12
#    doc-drift finding: CLAUDE.md cited the v1.0.0 103/102 split but
#    attributed it "at v0.9.0").
#  - Memory::FIELD_COUNT → docs claims of "<N>-field struct".
#  - HookEvent variant count (=25) → docs claims of "<N> hook lifecycle
#    events".
#  - MemoryLinkRelation::COUNT (=6) → docs claims of "<N> variants" /
#    "<N> typed link relations".
#  - MemoryScope::COUNT (=5) → docs claims of "<N> visibility scopes".
#
# # Output
#
# Exit 0 on success. Exit 1 on any drift, with one stderr line per
# offending file:line emitting `FAIL: <file>:<line> claims <count> but
# canonical is <count>`. The CI workflow consumes the exit code +
# stderr to produce a clear annotation.
#
# # CLI
#
#   ./scripts/check-docs-vs-ssot.sh                — run the gate
#   ./scripts/check-docs-vs-ssot.sh --self-test    — exercise each rule

set -euo pipefail

# Discover repo root.
# Honor AI_MEMORY_DOCS_GATE_ROOT env override for the self-test, which
# stages a contrived fixture tree in a tmpdir and needs the gate to
# resolve canonical SSOTs + doc files against the fixture rather than
# the real checkout.
if [[ -n "${AI_MEMORY_DOCS_GATE_ROOT:-}" ]]; then
    REPO_ROOT="$AI_MEMORY_DOCS_GATE_ROOT"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$REPO_ROOT"

# --------------------------------------------------------------------
# Resolve canonical SSOT values from Rust source
# --------------------------------------------------------------------

extract_const_value() {
    # $1 = file, $2 = const name, $3 = pattern (e.g. "i64|usize|i32")
    local file="$1" name="$2" types="$3"
    grep -oE "(pub )?const ${name}: *(${types}) *= *[0-9_]+" "$file" 2>/dev/null \
        | head -1 \
        | grep -oE '[0-9_]+$' \
        | tr -d '_'
}

# Current release version (#12 doc-drift finding) — the SSOT for any
# doc claim that attributes a count "at v<X>". Docs must never narrate
# a count against a stale prior-release attribution (e.g. citing the
# v1.0.0 103/102 full-tool-count split but attributing it "at v0.9.0",
# the release that actually shipped 101/100).
CANONICAL_RELEASE_VERSION=$(grep -oE '^version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml \
    | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

CANONICAL_SCHEMA_VERSION=$(extract_const_value src/storage/migrations.rs CURRENT_SCHEMA_VERSION 'i64|usize|i32')
CANONICAL_ROUTES_COUNT=$(extract_const_value src/lib.rs EXPECTED_PRODUCTION_ROUTES_COUNT 'usize')
CANONICAL_UNIQUE_PATHS_COUNT=$(extract_const_value src/lib.rs EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT 'usize')
CANONICAL_CLI_DEFAULT=$(extract_const_value src/lib.rs EXPECTED_CLI_SUBCOMMANDS_DEFAULT 'usize')
CANONICAL_CLI_SAL=$(extract_const_value src/lib.rs EXPECTED_CLI_SUBCOMMANDS_SAL 'usize')
CANONICAL_MEMORY_FIELDS=$(extract_const_value src/models/memory.rs FIELD_COUNT 'usize')
CANONICAL_LINK_COUNT=$(extract_const_value src/models/link.rs COUNT 'usize')
CANONICAL_SCOPE_COUNT=$(extract_const_value src/models/namespace.rs COUNT 'usize')

# Profile::full().expected_tool_count() — count of RegisteredTool::of::<>() entries
CANONICAL_FULL_TOOL_COUNT=$(grep -cE '^\s*RegisteredTool::of::<' src/mcp/registry.rs 2>/dev/null || echo 0)

# Profile::core().expected_tool_count() — count of tn::* refs in the
# `Self::Core => &[ ... ]` arm of Profile::tool_names(). 7 at v0.7.0.
CANONICAL_CORE_TOOL_COUNT=$(
    awk '/Self::Core => &\[/,/\]/' src/profile.rs 2>/dev/null \
        | grep -cE '^\s+tn::'
)

# HookEvent variants — count `pub enum HookEvent` body lines
CANONICAL_HOOK_EVENTS=$(
    awk '/^pub enum HookEvent/,/^}/' src/hooks/events.rs 2>/dev/null \
        | grep -cE '^    [A-Z][a-zA-Z0-9]*,$'
)

# --------------------------------------------------------------------
# Doc surfaces to scan
# --------------------------------------------------------------------

DOC_FILES=(
    CLAUDE.md
    README.md
    ROADMAP.md
    docs/spec/PORTABILITY-V2.md
    docs/MIGRATION_QUICKSTART.md
    docs/API_REFERENCE.md
    docs/DEVELOPER_GUIDE.md
    docs/a2a-harness-integration.md
    docs/compliance/_inventory/v0.7.x-code-changes-test-plan.md
    docs/compliance/nsa-csi-mcp-security-mapping.md
    docs/integrations/README.md
    docs/integrations/claude-code.md
    docs/v1.0.0/release-notes.md
)

# CHANGELOG.md is intentionally excluded — every entry is a historical
# snapshot at landing time, so claims like "Both adapters now at
# CURRENT_SCHEMA_VERSION = 50" are CORRECT historical state, not drift.
# RFC files (docs/rfc/RFC-0001-*.md) similarly narrate past schema bumps.
# The heterogeneous-AI-NHI assessment reports are historical analysis
# artifacts.
#
# The three v0.7 migration guides — docs/MIGRATION_v0.7.md (the v20→v57
# ladder), docs/migration-v0.7.0-postgres.md (schema_version=57 end
# state), and docs/migration-v064-to-v070.md (schema_version=57 ladder
# complete) — are likewise excluded: each describes the v0.7 migration
# ENDING at schema 57, a TRUE historical end-state. Re-pointing them at
# the live CURRENT_SCHEMA_VERSION (61 at v0.8.0-dev) would falsify the
# v0.7 migration story, so they are frozen-doc snapshots like CHANGELOG.

# --------------------------------------------------------------------
# Rule executor
# --------------------------------------------------------------------

fail_count=0

emit_fail() {
    local rule="$1" file="$2" line="$3" claim="$4" canonical="$5" context="$6"
    printf 'FAIL: %s: %s:%s claims "%s" but canonical %s is %s\n' \
        "$rule" "$file" "$line" "$claim" "$rule" "$canonical" >&2
    if [[ -n "${context:-}" ]]; then
        printf '       context: %s\n' "$context" >&2
    fi
    fail_count=$((fail_count + 1))
}

# CURRENT_SCHEMA_VERSION rule.
# Patterns (current-state claims):
#   - "Current schema = v<N>"
#   - "current `CURRENT_SCHEMA_VERSION = <N>"
#   - "CURRENT_SCHEMA_VERSION = <N>"
#   - "schema_version=<N> — ladder complete"
#   - "schema **v<N>** sqlite + postgres lockstep"
#   - "logical schema **v<N>** — `CURRENT_SCHEMA_VERSION = <N>"
#   - "backends sit at **schema_version=<N>"
# Patterns INTENTIONALLY EXCLUDED (historical, not current-state):
#   - "v52 added X" / "schema v52 (added X)"
#   - changelog headers like "### schema v52 — table"
#   - RFC doc references like "schema v52, see #1389"
check_schema_version_rule() {
    local rule_name="CURRENT_SCHEMA_VERSION"
    for f in "${DOC_FILES[@]}"; do
        [[ -f "$f" ]] || continue
        while IFS=$'\t' read -r ln val context; do
            [[ -z "$val" ]] && continue
            if [[ "$val" != "$CANONICAL_SCHEMA_VERSION" ]]; then
                emit_fail "$rule_name" "$f" "$ln" "$val" "$CANONICAL_SCHEMA_VERSION" "$context"
            fi
        done < <(
            python3 -c "
import re
patterns = [
    re.compile(r'Current schema = v([0-9]+)'),
    re.compile(r'CURRENT_SCHEMA_VERSION *= *([0-9]+)'),
    re.compile(r'schema_version=([0-9]+) — ladder complete'),
    re.compile(r'schema \*\*v([0-9]+)\*\* sqlite'),
    re.compile(r'backends sit at \*\*schema_version=([0-9]+)'),
    re.compile(r'logical schema \*\*v([0-9]+)\*\*'),
    # Markdown table form (release-notes.md Surface-at-vX.Y.Z table row):
    #   | Schema | **v86** (CURRENT_SCHEMA_VERSION, both adapters) |
    # \x60 is the backtick code-span delimiter, spelled as a hex escape
    # rather than a literal backtick character -- this whole block is
    # interpolated inside a double-quoted python3 -c string, and a
    # literal backtick there would trigger bash command substitution.
    re.compile(r'\| *Schema *\| *\*\*v([0-9]+)\*\* *\(\x60CURRENT_SCHEMA_VERSION'),
    # ROADMAPs plain-prose current-state phrasing. Scoped to the exact
    # phrase the current substrate has advanced to schema N (issue
    # #2282) rather than a bare schema-([0-9]+) pattern -- a generic
    # word-boundary pattern false-positives on legitimate HISTORICAL
    # narrative mentions elsewhere in ROADMAP.md, e.g. advanced to
    # schema 78 anchored to a past release, or schema 45 in ladder
    # history, which are correct historical state, not drift.
    re.compile(r'the current substrate has advanced to schema ([0-9]+)'),
]
for ln, line in enumerate(open('$f').read().splitlines(), 1):
    for p in patterns:
        m = p.search(line)
        if m:
            ctx = line.strip()[:160]
            print(f'{ln}\t{m.group(1)}\t{ctx}')
            break
"
        )
    done
}

# Generic narrative-count rule.
# $1 = rule name, $2 = canonical value, $3 = regex pattern (must contain
# one capture group `([0-9]+)`), $4..N = doc files (defaults to DOC_FILES)
check_narrative_count_rule() {
    local rule_name="$1" canonical="$2" pattern="$3"
    shift 3
    local files=("${DOC_FILES[@]}")
    if [[ $# -gt 0 ]]; then
        files=("$@")
    fi
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        # Use python for robust regex with capture groups
        while IFS=$'\t' read -r ln val context; do
            [[ -z "$val" ]] && continue
            if [[ "$val" != "$canonical" ]]; then
                emit_fail "$rule_name" "$f" "$ln" "$val" "$canonical" "$context"
            fi
        done < <(
            python3 -c "
import re, sys
pat = re.compile(r'''$pattern''')
for ln, line in enumerate(open('$f').read().splitlines(), 1):
    for m in pat.finditer(line):
        # Alternation groups: take the FIRST non-None capture
        val = next((g for g in m.groups() if g is not None), '')
        if not val:
            continue
        ctx = line.strip()[:160]
        print(f'{ln}\t{val}\t{ctx}')
"
        )
    done
}

# Env-var census rule (#836 3B / 2026-06-09 GA drive). Every
# AI_MEMORY_* env var READ by production code must appear somewhere in
# CLAUDE.md (the env-var table is the operator-facing contract; 13
# missing rows were found by hand on 2026-06-09 — this makes the class
# mechanical). Production boundary: skip *test* files and lines below
# the first `mod tests {`. Intentionally one-directional — extra rows
# in CLAUDE.md for removed vars are caught by the symbol census, and
# vars only set (not read) by code are not operator knobs.
check_env_var_census_rule() {
    local rule_name="ENV_VAR_CENSUS" var
    local code_vars
    # Two read shapes: direct env::var("AI_MEMORY_X") literals, and
    # const-indirected reads where the spelling lives on an `ENV_*`
    # const definition (e.g. `pub const ENV_ADMIN_HEADER_TRUST: &str =
    # "AI_MEMORY_ADMIN_HEADER_TRUST";`) — the post-#1558 house style.
    # `|| true` guards against `set -e`/`pipefail`: when the scanned tree
    # has ZERO matches (e.g. the --self-test fixture's tiny src/ tree),
    # every grep stage in the pipe exits 1 (no-match), which under
    # pipefail propagates as the assignment's exit status and silently
    # aborts the whole gate before any later rule runs. Zero matches is a
    # legitimate (if rare) state, not a script error.
    code_vars=$( { grep -rhoE 'env::var(_os)?\("(AI_MEMORY_[A-Z0-9_]+)"' "$REPO_ROOT/src" \
        --include='*.rs' 2>/dev/null; \
        grep -rhoE 'const ENV_[A-Z0-9_]+: *&str *= *"AI_MEMORY_[A-Z0-9_]+"' "$REPO_ROOT/src" \
        --include='*.rs' 2>/dev/null; } \
        | grep -oE 'AI_MEMORY_[A-Z0-9_]+' | sort -u) || true
    for var in $code_vars; do
        if ! grep -q "$var" "$REPO_ROOT/CLAUDE.md"; then
            printf 'FAIL: %s: src reads %s but CLAUDE.md never mentions it (env-var table drift)\n' \
                "$rule_name" "$var" >&2
            fail_count=$((fail_count + 1))
        fi
    done
}

run_all_rules() {
    fail_count=0
    check_schema_version_rule
    check_env_var_census_rule
    # MCP tool count at --profile full
    check_narrative_count_rule \
        "Profile::full().expected_tool_count() (registry tools)" \
        "$CANONICAL_FULL_TOOL_COUNT" \
        '\*\*([0-9]+) MCP tools at `--profile full`\*\*|([0-9]+) advertised entries at `--profile full`|\(([0-9]+) at `full`, [0-9]+ at `core`\)|Tool count remains ([0-9]+) at full|([0-9]+) MCP tools at `--profile full`;'
    # MCP tool count at --profile core
    check_narrative_count_rule \
        "Profile::core().expected_tool_count()" \
        "$CANONICAL_CORE_TOOL_COUNT" \
        '([0-9]+) at `--profile core`|\([0-9]+ at `full`, ([0-9]+) at `core`\)|Tool count remains [0-9]+ at full / ([0-9]+) at core'
    # Full-tool-count VERSION ATTRIBUTION (#12 doc-drift finding): the
    # "<N> advertised entries at `--profile full`** at v<X>" narrative
    # form must attribute the CURRENT release, never a stale prior one
    # (e.g. citing the v1.0.0 103/102 split but attributing "at v0.9.0",
    # the release that actually shipped 101/100 — CLAUDE.md's own
    # architecture section carried this exact drift).
    check_narrative_count_rule \
        "release-version attribution (full-tool-count)" \
        "$CANONICAL_RELEASE_VERSION" \
        'advertised entries at `--profile full`\*\* at v([0-9]+\.[0-9]+\.[0-9]+)'
    # Memory::FIELD_COUNT
    # Matches the CLAUDE.md narrative form ("**26-field struct at v0.7.0**")
    # AND the normative docs/spec/PORTABILITY-V2.md field-count contract
    # citations ("Memory::FIELD_COUNT = 30", "the 30-field Memory record",
    # "The 30 fields, in struct order", "all 30 struct fields"). The
    # PORTABILITY-V2 field list is a data-integrity contract: an importer
    # coded to a stale count silently drops the #1834 valid_from/valid_until
    # claim-validity interval, so the gate must police it (this citation
    # was previously invisible — the gate did not scan the spec file).
    check_narrative_count_rule \
        "Memory::FIELD_COUNT" \
        "$CANONICAL_MEMORY_FIELDS" \
        '\*\*([0-9]+)-field struct at v0\.7\.0\*\*|Memory::FIELD_COUNT *= *([0-9]+)|the ([0-9]+)-field Memory record|The ([0-9]+) fields, in struct order|all ([0-9]+) struct fields'
    # MemoryLinkRelation::COUNT
    check_narrative_count_rule \
        "MemoryLinkRelation::COUNT" \
        "$CANONICAL_LINK_COUNT" \
        '\*\*([0-9]+) variants at v0\.7\.0\*\* \(was four at v0\.6\.x\)'
    # HookEvent count
    check_narrative_count_rule \
        "HookEvent variants" \
        "$CANONICAL_HOOK_EVENTS" \
        '\*\*([0-9]+) hook lifecycle events\*\*|([0-9]+) lifecycle events\) — A programmable'
    # Routes count
    check_narrative_count_rule \
        "EXPECTED_PRODUCTION_ROUTES_COUNT" \
        "$CANONICAL_ROUTES_COUNT" \
        '\*\*([0-9]+) production `\.route\(\.\.\.\)` registrations\*\*|\*\*([0-9]+) production HTTP route registrations\*\*'
    # Unique paths count
    check_narrative_count_rule \
        "EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT" \
        "$CANONICAL_UNIQUE_PATHS_COUNT" \
        '([0-9]+) unique URL paths'
    # CLI subcommand counts (default + sal)
    check_narrative_count_rule \
        "EXPECTED_CLI_SUBCOMMANDS_DEFAULT" \
        "$CANONICAL_CLI_DEFAULT" \
        '\*\*([0-9]+) top-level subcommands in the default build\*\*|([0-9]+) in the default build —'
    check_narrative_count_rule \
        "EXPECTED_CLI_SUBCOMMANDS_SAL" \
        "$CANONICAL_CLI_SAL" \
        'yields \*\*([0-9]+)\*\* by unlocking|([0-9]+) CLI subcommands\*\* under `--features sal`'

    if [[ "$fail_count" -gt 0 ]]; then
        printf '\n❌ docs-vs-SSOT drift gate: %d violation(s)\n' "$fail_count" >&2
        printf '   Canonical values resolved from source:\n' >&2
        printf '     CURRENT_SCHEMA_VERSION = %s (src/storage/migrations.rs)\n' "$CANONICAL_SCHEMA_VERSION" >&2
        printf '     Profile::full() tool count = %s (registry RegisteredTool::of entries)\n' "$CANONICAL_FULL_TOOL_COUNT" >&2
        printf '     EXPECTED_PRODUCTION_ROUTES_COUNT = %s\n' "$CANONICAL_ROUTES_COUNT" >&2
        printf '     EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT = %s\n' "$CANONICAL_UNIQUE_PATHS_COUNT" >&2
        printf '     EXPECTED_CLI_SUBCOMMANDS_DEFAULT = %s\n' "$CANONICAL_CLI_DEFAULT" >&2
        printf '     EXPECTED_CLI_SUBCOMMANDS_SAL = %s\n' "$CANONICAL_CLI_SAL" >&2
        printf '     Memory::FIELD_COUNT = %s\n' "$CANONICAL_MEMORY_FIELDS" >&2
        printf '     MemoryLinkRelation::COUNT = %s\n' "$CANONICAL_LINK_COUNT" >&2
        printf '     MemoryScope::COUNT = %s\n' "$CANONICAL_SCOPE_COUNT" >&2
        printf '     HookEvent variants = %s\n' "$CANONICAL_HOOK_EVENTS" >&2
        printf '     Current release version (Cargo.toml) = %s\n' "$CANONICAL_RELEASE_VERSION" >&2
        exit 1
    fi
    printf '✅ docs-vs-SSOT drift gate: PASS\n'
    printf '   Canonical values: schema=%s, full_tools=%s, core_tools=%s, routes=%s, paths=%s, cli_default=%s, cli_sal=%s, mem_fields=%s, link=%s, scope=%s, hooks=%s, release=%s\n' \
        "$CANONICAL_SCHEMA_VERSION" \
        "$CANONICAL_FULL_TOOL_COUNT" \
        "$CANONICAL_CORE_TOOL_COUNT" \
        "$CANONICAL_ROUTES_COUNT" \
        "$CANONICAL_UNIQUE_PATHS_COUNT" \
        "$CANONICAL_CLI_DEFAULT" \
        "$CANONICAL_CLI_SAL" \
        "$CANONICAL_MEMORY_FIELDS" \
        "$CANONICAL_LINK_COUNT" \
        "$CANONICAL_SCOPE_COUNT" \
        "$CANONICAL_HOOK_EVENTS" \
        "$CANONICAL_RELEASE_VERSION"
}

# --------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------
# Inject a contrived stale claim into a temp file + run gate; verify
# it surfaces the violation; clean up. Mirrors the
# scripts/check-vendor-literals.sh self-test convention.

run_self_test() {
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN

    cd "$tmpdir"
    mkdir -p src/storage src/lib src/models src/mcp src/hooks
    # Minimal canonical fixture: CURRENT_SCHEMA_VERSION = 53
    cat > src/storage/migrations.rs <<EOF
const CURRENT_SCHEMA_VERSION: i64 = 53;
EOF
    cat > src/lib.rs <<EOF
pub const EXPECTED_PRODUCTION_ROUTES_COUNT: usize = 87;
pub const EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT: usize = 73;
pub const EXPECTED_CLI_SUBCOMMANDS_DEFAULT: usize = 78;
pub const EXPECTED_CLI_SUBCOMMANDS_SAL: usize = 80;
EOF
    mkdir -p src/models src/mcp src/hooks
    echo 'pub const FIELD_COUNT: usize = 26;' > src/models/memory.rs
    echo 'pub const COUNT: usize = 6;' > src/models/link.rs
    echo 'pub const COUNT: usize = 5;' > src/models/namespace.rs
    # Same latent-abort class as the HookEvent fix below: CANONICAL_CORE_TOOL_COUNT
    # greps `Self::Core => &[ ... tn::* ... ]` out of src/profile.rs. An absent
    # file made `awk ... src/profile.rs 2>/dev/null | grep -cE '^\s+tn::'` match
    # zero lines — grep -c's no-match exit 1 silently aborted the whole gate
    # under `set -e`/`pipefail`, before CANONICAL_HOOK_EVENTS or any narrative
    # rule ever ran.
    cat > src/profile.rs <<'PROFILEEOF'
        Self::Core => &[
            tn::A,
            tn::B,
            tn::C,
            tn::D,
            tn::E,
            tn::F,
            tn::G,
        ],
PROFILEEOF
    # One variant per line (matching the real src/hooks/events.rs shape) so
    # the CANONICAL_HOOK_EVENTS `awk | grep -c '^    [A-Z]...,$'` extraction
    # actually matches >0 lines. A single joined line here (the pre-#12
    # fixture shape) makes that grep -c return zero matches; grep exits 1
    # on no-match, and under `set -e` that silently aborts the whole gate
    # BEFORE any narrative rule ever runs — the self-test was then only
    # "passing" because a nonzero exit from that unrelated abort looked
    # identical to "the gate caught the contrived drift".
    cat > src/hooks/events.rs <<'HOOKEOF'
pub enum HookEvent {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
}
HOOKEOF
    : > src/mcp/registry.rs
    # ~12 RegisteredTool::of entries → tool count = 12
    for i in $(seq 1 12); do
        echo "        RegisteredTool::of::<Tool$i>()," >> src/mcp/registry.rs
    done
    # Fixture "current release" = 9.9.9 (#12 doc-drift version-attribution rule)
    cat > Cargo.toml <<EOF
[package]
name = "fixture"
version = "9.9.9"
EOF

    # Contrived BAD docs (claims wrong values). The last line isolates the
    # release-version-attribution rule: the count (12) matches the fixture
    # canonical tool count exactly (so the pre-existing tool-count rule does
    # NOT also fire), but the "at v0.9.0" attribution does not match the
    # fixture's Cargo.toml version (9.9.9) — the #12 doc-drift shape.
    cat > CLAUDE.md <<EOF
**Current schema = v99** (would-be-stale-claim test).
**74 MCP tools at \`--profile full\`** — this should fail because fixture is 12.
**12 advertised entries at \`--profile full\`** at v0.9.0 (contrived stale-version-attribution test).
EOF

    # Run the gate as a subprocess with the tmpdir as the root, so it
    # resolves SSOTs + doc files against the fixture (not the real
    # checkout).
    local gate_output
    if gate_output=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — gate did NOT catch the contrived drift"
        cd "$REPO_ROOT"
        exit 1
    elif ! grep -q "release-version attribution (full-tool-count)" <<<"$gate_output"; then
        echo "FAIL: self-test — gate did not specifically flag the contrived release-version-attribution drift"
        cd "$REPO_ROOT"
        exit 1
    else
        echo "PASS: self-test — gate correctly caught the contrived drift"
    fi
    cd "$REPO_ROOT"
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

if [[ "${1:-}" == "--self-test" ]]; then
    run_self_test
    exit 0
fi

run_all_rules
