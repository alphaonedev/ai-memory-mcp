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
#  - pgvector certified PATCH (deploy/docker-1461/provision/lib.sh
#    DOCKER_1461_PGVECTOR_APT_VERSION, reduced x.y.z — the SAME SSOT
#    tests/provisioning_pgvector_pin_parity.rs reads) → current-cert doc
#    claims of "pgvector | **X.Y.Z**", "pgvector X.Y.Z",
#    "PGVECTOR_APT_VERSION=X.Y.Z-". The alternate PG16/AGE1.6 tested-matrix
#    mentions (pgvector 0.8.2/0.8.4) and the SHIPPED-record docs
#    (release-notes.md, CHANGELOG) are LEFT ALONE.
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

# Certified pgvector PATCH — the single fleet-wide provisioning pin. It
# lives ONCE, in the docker-1461 lane's `DOCKER_1461_PGVECTOR_APT_VERSION`
# default in deploy/docker-1461/provision/lib.sh, reduced to its bare
# upstream x.y.z (`0.8.6-1.pgdg13+1` -> `0.8.6`). This is the SAME SSOT
# default tests/provisioning_pgvector_pin_parity.rs reads (and asserts the
# do-1461 lane agrees on), so the gate introduces NO third source of
# truth — it reuses the parity test's extraction shape (first live
# `${var:-<default>}`, take everything before the first `-`). Trailing
# `|| true` keeps a genuinely-absent SSOT file from aborting the whole
# gate under `set -euo pipefail`; an empty result FAILS CLOSED inside the
# rule (never a silent pass) when a pgvector doc is present to validate.
CANONICAL_PGVECTOR_PATCH="$(
    grep -oE '\$\{DOCKER_1461_PGVECTOR_APT_VERSION:-[0-9][0-9.]*[^}]*\}' \
        deploy/docker-1461/provision/lib.sh 2>/dev/null \
    | head -1 \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
    | head -1 || true
)"

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
    docs/CONFIG_SCHEMA.md
    docs/production-deployment.md
    docs/enterprise-deployment.md
    # #2796 — the committed NHI dogfood playbook opens with an explicit
    # "v1.0.0 SSOT values used below" block (schema, tool counts, Memory
    # fields, link relations, route/CLI counts, HookEvent variants) that a
    # tester reads as the pass/fail bar. It was not walked, so its
    # `--profile core` count drifted unnoticed. It is a CURRENT-release
    # doc, not a frozen snapshot, so it belongs in the gate.
    docs/v1.0.0/nhi-playbook-P0-P11.md
)

# #2839 (3x7 lane-2 register §E) — WIDEN the scan set. #2492 correctly
# generalised the PATTERN set from hand-written regexes to noun-phrase
# anchors but did NOT widen DOC_FILES, so ~130 wrong live counts shipped in
# CURRENT operator-facing reference docs this gate never opened. The split
# was the file set, not authorship: files at/near canon were IN the curated
# list, files a full release behind were not. This widening is an EXPLICIT
# additive list of the CURRENT reference docs #2839 enumerated (plus the
# already-canon CLI_REFERENCE.md, whose tool/route/CLI counts belong under
# this gate) — NOT a blanket `docs/**/*.md` glob. A blanket glob drags in the
# historical "when-added schema vN" ladder references (docs/coordination.md's
# "lifecycle_state column (schema v64)"), v0.7.0-scoped verification
# statements (docs/cli-design-rationale.md "at release/v0.7.0 HEAD ... 79
# subcommands"), frozen per-release summaries (docs/compliance/_inventory/
# v0.7.0-summary.md), analysis/adjudication artifacts (docs/reviews/,
# docs/design/ — 3x7 / TRACT / RED-QUEEN), and the v0.7-scoped ADMIN_GUIDE /
# migration guides — all of which carry TRUE HISTORICAL numbers whose
# phrasings the gate's current-state historical guards do not all recognise,
# so a blanket walk would false-positive on legitimate history. Closing the
# blanket-glob path cleanly needs the CURRENT_SCHEMA_VERSION rule's
# "vN added X" historical guard broadened to the "(schema **vN**; Feature)"
# phrasing first (a follow-up on the gate's core rule logic, deliberately not
# bundled into this doc-perfection wave). The list below is de-duped against
# the curated entries above so their inline rationale survives.
for _wf in \
    docs/USER_GUIDE.md \
    docs/CLI_REFERENCE.md \
    docs/GLOSSARY.md \
    docs/SECURITY.md \
    docs/INSTALL.md \
    docs/install-quickstart.md \
    docs/integration-guide.md \
    docs/postgres-age-guide.md \
    docs/hook-pipeline.md \
    docs/agent-skills.md \
    docs/batman-active-mode.md \
    docs/governance.md
do
    [[ -f "$_wf" ]] || continue
    _dup=0
    for _e in "${DOC_FILES[@]}"; do [[ "$_e" == "$_wf" ]] && { _dup=1; break; }; done
    [[ "$_dup" == 0 ]] && DOC_FILES+=("$_wf")
done

# Operator-facing HTML surfaces (rendered compliance pages). Markdown is
# the primary narrative form, but procurement-facing .html pages restate
# the same mechanically-pinned SSOT counts and drift INDEPENDENTLY of
# their .md siblings when an SSOT moves — #2729 / CB-32: nsa-csi-mcp.html
# shipped stale 89/91 CLI counts vs SSOT 90/92 while
# nsa-csi-mcp-security-mapping.md was already correct at 90/92. The gate
# had ZERO html references (same class as #2668 E-20 for benchmark.svg),
# so the rendered surface was invisible. These files are walked by the
# html-aware CLI-count rules in run_all_rules below. Kept as an explicit
# allowlist (not a `**/*.html` glob) so a historical/archived HTML page
# cannot silently enroll a legitimate past-release count into the gate.
HTML_DOC_FILES=(
    docs/compliance/nsa-csi-mcp.html
)

# Additional surfaces walked ONLY by the HookEvent rule (3x7 lane-3,
# 2026-08-09). The HookEvent rule was the last legacy hand-regex left
# behind when #2492 generalised the other SSOT rules, and it was ALSO
# scoped to DOC_FILES/HTML_DOC_FILES -- so it missed the class twice.
# At f7399cfb the gate reported hooks=22 and PASSED while five live
# surfaces published 25 or 27, two of them naming pre_recall, an event
# #2758 REMOVED precisely because advertising a hook that never fires
# is a false enforcement claim.
#
# Deliberately a SEPARATE list, not an extension of DOC_FILES /
# HTML_DOC_FILES: those are shared by the route / tool / CLI-count
# rules, and widening them here would enroll pages whose OTHER counts
# belong to a different correction lane, redding this gate on drift it
# is not the subject of. One rule, one scan set.
HOOK_DOC_FILES=(
    "${DOC_FILES[@]}"
    "${HTML_DOC_FILES[@]}"
    docs/production-deployment.md
    docs/strategy/coala-mapping.md
    docs/audience/developer.html
    docs/essays/brass-tacks-3-why.html
)

# Doc surfaces the pgvector-certified-patch rule walks. Its own EXPLICIT
# allowlist (the "one rule, one scan set" discipline the HookEvent /
# HTML rules follow), NOT a shared list — the current-cert docs that cite
# the certified pgvector pin as a PRESENT fact. Deliberately EXCLUDES the
# history surfaces the coordinator called out: CHANGELOG.md (never in any
# scan set), docs/v1.0.0/release-notes.md (the SHIPPED v1.0.0 stack was
# pgvector 0.8.5 — a true past-release record), the v1.0.0 test-campaign
# artifacts, docs/audit/* (the frozen 2026-08-01 claims register), and
# docs/architectures-t3.html (a frozen 0.8.2 mention). Those describe a
# past-shipped or alternate stack, not the current provisioning pin.
PGVECTOR_DOC_FILES=(
    docs/CONFIG_SCHEMA.md
    docs/enterprise-deployment.md
    docs/postgres-age-guide.md
    docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md
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
        # Capture-then-check rather than `done < <(python3 …)`: under
        # `set -euo pipefail` a process-substitution's exit status is NOT
        # observed, so a crashing engine (a non-UTF-8 byte → the unguarded
        # `open('$f')` raises UnicodeDecodeError) yielded an EMPTY row set
        # and the rule silently passed — the #2713 swallowed-error shape.
        local schema_rows
        schema_rows="$(
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
        )" || {
            printf 'FAIL: check-docs-vs-ssot: CURRENT_SCHEMA_VERSION analysis engine errored on %s (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' "$f" >&2
            exit 2
        }
        while IFS=$'\t' read -r ln val context; do
            [[ -z "$val" ]] && continue
            if [[ "$val" != "$CANONICAL_SCHEMA_VERSION" ]]; then
                emit_fail "$rule_name" "$f" "$ln" "$val" "$CANONICAL_SCHEMA_VERSION" "$context"
            fi
        done <<< "$schema_rows"
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
        # Use python for robust regex with capture groups. Capture-then-
        # check, not `done < <(python3 …)`: a process-substitution's exit
        # status is unobserved under `set -euo pipefail`, so a crashing
        # engine (a non-UTF-8 byte → the unguarded `open('$f')`) silently
        # yielded no rows and the rule passed — the #2713 fail-open shape.
        local narrative_rows
        narrative_rows="$(
            python3 -c "
import re, sys
pat = re.compile(r'''$pattern''')
# HISTORICAL GUARD -- 3x7 lane-3, 2026-08-09. Mirrors is_historical in
# the #2492 generalised scanner below. Principle: a TRUE statement about
# a PAST release must never be re-pointed at the canonical, or the gate
# destroys the record it exists to protect. This legacy per-rule function
# never had the guard -- harmless only while every rule regex was narrow
# enough to miss history by accident. Generalising the HookEvent anchors
# made that accident stop holding: the README prior-release paragraph and
# the ROADMAP frozen v0.7.1 baseline both legitimately say 25.
# NOTE: single-quoted regexes only -- this python is embedded in a
# double-quoted shell string, so a double quote here closes it.
_PARA_LEAD = re.compile(r'^\s*\*\*v([0-9]+\.[0-9]+\.[0-9]+)')
_HIST = [
    re.compile(r'^\s*#{1,6}\s'),
    re.compile(r'\b[Aa]t the v[0-9]+\.[0-9]+\.[0-9]+ release\b'),
    re.compile(r'\brelease, surface was\b'),
    re.compile(r'\bv[0-9]+ added\b'),
    re.compile(r'\bwas [0-9]+ at v[0-9]'),
    re.compile(r'\bShip state at v[0-9]+\.[0-9]+'),
    re.compile(r'\bFrozen v[0-9]+\.[0-9]+[^ ]* baseline\b'),
]
_release = '''$CANONICAL_RELEASE_VERSION'''
def _is_historical(line):
    m = _PARA_LEAD.match(line)
    if m and m.group(1) != _release:
        return True
    return any(p.search(line) for p in _HIST)
for ln, line in enumerate(open('$f').read().splitlines(), 1):
    if _is_historical(line):
        continue
    for m in pat.finditer(line):
        # Alternation groups: take the FIRST non-None capture
        val = next((g for g in m.groups() if g is not None), '')
        if not val:
            continue
        ctx = line.strip()[:160]
        print(f'{ln}\t{val}\t{ctx}')
"
        )" || {
            printf 'FAIL: check-docs-vs-ssot: %s analysis engine errored on %s (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' "$rule_name" "$f" >&2
            exit 2
        }
        while IFS=$'\t' read -r ln val context; do
            [[ -z "$val" ]] && continue
            if [[ "$val" != "$canonical" ]]; then
                emit_fail "$rule_name" "$f" "$ln" "$val" "$canonical" "$context"
            fi
        done <<< "$narrative_rows"
    done
}

# pgvector certified-patch rule.
# The certified pgvector PATCH is pinned ONCE, in the docker-1461 lane's
# `DOCKER_1461_PGVECTOR_APT_VERSION` default (reduced x.y.z) — the SAME
# SSOT default tests/provisioning_pgvector_pin_parity.rs reads. Every
# current-cert doc citation must agree; this rule HARD-BLOCKS any doc that
# cites a pgvector version != the SSOT patch.
#
# THREE anchor forms (mirroring the #2492 noun-phrase discipline):
#   A. SSOT table cell:  `pgvector | **X.Y.Z**` / `pgvector (server extension) | **X.Y.Z**`
#   B. prose:            `pgvector X.Y.Z` / `pgvector **X.Y.Z**` / `pgvector \x60X.Y.Z\x60`
#   C. apt pin literal:  `PGVECTOR_APT_VERSION=X.Y.Z-`
# The two-part Rust binding-crate figure (`pgvector = "0.4"`, `pgvector
# (Rust binding crate) | **0.4**`) is NEVER matched: every anchor requires
# a full THREE-component x.y.z.
#
# ALTERNATE-STACK GUARD (load-bearing). Three of these current-cert docs
# legitimately name the DISJOINT alternate/campaign matrix — the
# `infra/lan-parity-test` PG 16 + AGE 1.6.0 + pgvector 0.8.2 combination
# and the 2-node DO campaign's PG 16 / AGE 1.6.0 / pgvector 0.8.4 — as
# EXPLICITLY-LABELLED non-certified evidence. A line asserting a pgvector
# figure alongside the alternate PG16/AGE1.6 stack, or self-labelled
# `alternate matrix` / `second tested combination`, is definitionally not
# the certified pin, so it is skipped. The certified pin is PG 18.4 / AGE
# 1.7.0, so these markers never appear on a genuine certified line — the
# guard's only failure mode is a rare false-NEGATIVE, never a false drift
# report. (The register's F9 findings-row form `pgvector0.8.5` — no space,
# slash-joined — matches no anchor at all and needs no guard.)
check_pgvector_version_rule() {
    local rule_name="PGVECTOR_APT_VERSION (certified pgvector patch)"
    local canonical="$CANONICAL_PGVECTOR_PATCH"
    for f in "${PGVECTOR_DOC_FILES[@]}"; do
        [[ -f "$f" ]] || continue
        # Empty canonical + a doc to validate = the SSOT file was
        # unreadable. FAIL CLOSED (#2713 discipline) rather than flag
        # every citation as drift OR silently pass.
        if [[ -z "$canonical" ]]; then
            printf 'FAIL: %s: could not resolve the pgvector SSOT patch from deploy/docker-1461/provision/lib.sh (DOCKER_1461_PGVECTOR_APT_VERSION) — refusing to validate %s (#2713 fail-closed)\n' \
                "$rule_name" "$f" >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        # Capture-then-check (never `done < <(python3 …)`): a
        # process-substitution's exit status is unobserved under
        # `set -euo pipefail`, so a crashing engine would silently pass.
        local pgv_rows
        pgv_rows="$(
            python3 -c "
import re
pats = [
    re.compile(r'pgvector[^|]*\|[ ]*\*\*([0-9]+\.[0-9]+\.[0-9]+)\*\*'),
    re.compile(r'pgvector[ ]+(?:\*\*|\x60)?([0-9]+\.[0-9]+\.[0-9]+)'),
    re.compile(r'PGVECTOR_APT_VERSION=([0-9]+\.[0-9]+\.[0-9]+)-'),
]
# Standard historical guard (paragraph-lead attributed to a non-current
# release; headings; unconditional past-tense) — mirrors is_historical in
# the generalised scanner. Single-quoted regexes only (this python is
# embedded in a double-quoted shell string).
_release = '''$CANONICAL_RELEASE_VERSION'''
_PARA_LEAD = re.compile(r'^\s*\*\*v([0-9]+\.[0-9]+\.[0-9]+)')
_HIST = [
    re.compile(r'^\s*#{1,6}\s'),
    re.compile(r'\b[Aa]t the v[0-9]+\.[0-9]+\.[0-9]+ release\b'),
    re.compile(r'\brelease, surface was\b'),
]
# ALTERNATE / campaign-stack markers (see the function header): a pgvector
# figure sharing a line with the disjoint PG16/AGE1.6 stack, or a
# self-labelled alternate/second matrix, is NOT the certified pin.
_ALT = [
    re.compile(r'AGE 1\.6\.0'),
    re.compile(r'PostgreSQL 16\b'),
    re.compile(r'\bPG 16\b'),
    re.compile(r'alternate matrix'),
    re.compile(r'second tested combination'),
]
def _skip(line):
    m = _PARA_LEAD.match(line)
    if m and m.group(1) != _release:
        return True
    if any(p.search(line) for p in _HIST):
        return True
    return any(p.search(line) for p in _ALT)
for ln, line in enumerate(open('$f', encoding='utf-8').read().splitlines(), 1):
    if _skip(line):
        continue
    for p in pats:
        for m in p.finditer(line):
            ctx = line.strip()[:160].replace('\t', ' ')
            print(f'{ln}\t{m.group(1)}\t{ctx}')
"
        )" || {
            printf 'FAIL: check-docs-vs-ssot: pgvector-patch analysis engine errored on %s (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' "$f" >&2
            exit 2
        }
        while IFS=$'\t' read -r ln val context; do
            [[ -z "$val" ]] && continue
            if [[ "$val" != "$canonical" ]]; then
                emit_fail "$rule_name" "$f" "$ln" "$val" "$canonical" "$context"
            fi
        done <<< "$pgv_rows"
    done
}

# Env-var census rule (#836 3B / 2026-06-09 GA drive). Every
# AI_MEMORY_* env var READ by production code must appear somewhere in
# CLAUDE.md (the env-var table is the operator-facing contract; 13
# missing rows were found by hand on 2026-06-09 — this makes the class
# mechanical). Intentionally one-directional — extra rows in CLAUDE.md
# for removed vars are caught by the symbol census, and vars only set
# (not read) by code are not operator knobs.
#
# WIDENED (#2830, 2026-08-09 lane-1 config sweep). The rule censused
# 102 of the 155 env vars production code actually reads, in three
# independent ways, and the seven knobs that were missing from the table
# had ALL slipped through one of them:
#
#   1. The const shape required the name to START with `ENV_`. The tree
#      uses TWO conventions — `ENV_FOO` and the `FOO_ENV` suffix — and
#      the suffix style is the majority style for the security /
#      federation knobs (`REQUIRE_WRITE_SIG_ENV`, `STORE_URL_ENV`,
#      `WITNESS_KEY_DIR_ENV`, …). 68 declarations were invisible.
#   2. Clap-bound flags (`#[arg(long, env = "AI_MEMORY_PROFILE")]`) were
#      not a recognised read shape at all.
#   3. The production boundary the comment CLAIMED ("skip *test* files
#      and lines below the first `mod tests {`") was never implemented —
#      the greps walked whole files. It is implemented for real below,
#      because widening 1+2 without it would newly red the gate on the
#      `#[cfg(test)]`-gated `AI_MEMORY_TEST_*` fixtures.
#
# The boundary skips a `#[cfg(test)]`-gated item by BRACE DEPTH (so a
# gated `fn` mid-file resumes production scanning after its body) rather
# than skipping to EOF, which would have dropped 40+ real production
# declarations. The filename filter matches `tests.rs` / `*_test.rs` /
# `*_tests.rs` / `test_*.rs` and deliberately NOT the looser `*test*.rs`
# the sibling gates use: that glob excludes `peer_attestation.rs` and
# `attest.rs` ("at-TEST-ation"), which declare live security knobs.
# Known residual: a const whose `= "AI_MEMORY_…"` wraps to a second line
# is still unseen (one var today, itself already documented).
check_env_var_census_rule() {
    local rule_name="ENV_VAR_CENSUS" var
    local code_vars
    # `|| true` guards against `set -e`/`pipefail`: when the scanned tree
    # has ZERO matches (e.g. the --self-test fixture's tiny src/ tree),
    # every grep stage in the pipe exits 1 (no-match), which under
    # pipefail propagates as the assignment's exit status and silently
    # aborts the whole gate before any later rule runs. Zero matches is a
    # legitimate (if rare) state, not a script error.
    _census_production_lines() {
        find "$REPO_ROOT/src" -name '*.rs' \
            ! -name 'tests.rs' ! -name '*_test.rs' ! -name '*_tests.rs' \
            ! -name 'test_*.rs' -print0 2>/dev/null \
        | xargs -0 -r awk '
            FNR==1 { skip=0; depth=0; armed=0 }
            !skip && /^[[:space:]]*#\[cfg\(test\)\]/ { skip=1; armed=0; depth=0; next }
            skip {
                n=gsub(/\{/,"{"); m=gsub(/\}/,"}")
                depth += n - m
                if (n > 0) armed=1
                if (armed && depth <= 0) { skip=0; next }
                if (!armed && /;[[:space:]]*$/) { skip=0 }
                next
            }
            { print }' 2>/dev/null
    }
    code_vars=$( { _census_production_lines | grep -oE 'env::var(_os)?\("AI_MEMORY_[A-Z0-9_]+"'; \
        _census_production_lines | grep -oE 'const [A-Z][A-Z0-9_]*: *&str *= *"AI_MEMORY_[A-Z0-9_]+"'; \
        _census_production_lines | grep -oE 'env *= *"AI_MEMORY_[A-Z0-9_]+"'; } \
        | grep -oE 'AI_MEMORY_[A-Z0-9_]+' | sort -u) || true
    for var in $code_vars; do
        # Word-boundaried: a bare `grep -q` lets a LONGER var's mention
        # satisfy a shorter one (`AI_MEMORY_STORE_URL` would be answered
        # by `AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS`).
        if ! grep -qE "${var}([^A-Z0-9_]|\$)" "$REPO_ROOT/CLAUDE.md"; then
            printf 'FAIL: %s: src reads %s but CLAUDE.md never mentions it (env-var table drift)\n' \
                "$rule_name" "$var" >&2
            fail_count=$((fail_count + 1))
        fi
    done
}

# --------------------------------------------------------------------
# #2492 — GENERALISED NUMERIC-CLAIM SCANNER + CURRENT-RELEASE ATTRIBUTION
# --------------------------------------------------------------------
#
# THE DEFECT THIS CLOSES. The 3x7 claims audit
# (docs/audit/3x7-claims-register-2026-08-01.md 3.3.1) found README.md
# carrying FIVE stale SSOT values — 94→92/93 routes, 88→78 schema,
# 30→28 Memory fields, 103→101 tools, 91/89→89/87 CLI subcommands —
# WITH THIS GATE GREEN. README is, and was, in DOC_FILES, so the gap
# was never the file walk: it was the PATTERN SET. Every rule above is
# a hand-written regex pinned to one exact phrasing
# (`\*\*N production \`\.route\(\.\.\.\)\` registrations\*\*`), and a
# document that says the same thing in the seventh way nobody enumerated
# is invisible. A gate that greens a page carrying five stale SSOT
# values is the #2444 "reports success while doing nothing" shape.
#
# THE METHOD, chosen so it does not rot the way the hand-written set
# did: for each SSOT const, match a small set of NOUN-PHRASE ANCHORS
# (`HTTP route registrations`, `unique URL paths`, `unique paths`,
# `MCP tools`, `-entry surface`, `CLI subcommands`, `-field \`Memory\``,
# `schema **v`) and extract ANY adjacent integer in bold / code / plain
# form. A new phrasing of an EXISTING claim is caught by the anchor;
# only a genuinely new NOUN gets past, and that is a much rarer event
# than a re-worded sentence.
#
# THE HISTORICAL GUARD IS LOAD-BEARING and must not be weakened. The
# register notes the drift direction is "consistently toward MORE
# CLAIMED ENFORCEMENT THAN EXISTS" — but README ALSO carries legitimate
# release-narrative paragraphs (`**v0.8.0 (…) — prior release.** … At
# the v0.8.0 release, surface was: schema **v70**, **100** MCP tools …,
# **91** HTTP route registrations …, a **27-field** `Memory`.`) whose
# numbers are TRUE STATEMENTS ABOUT A PAST RELEASE. Re-pointing them at
# the live canonical would FALSIFY the release history — the same
# reasoning that keeps CHANGELOG.md, the RFC files, and the three
# frozen v0.7 migration guides out of DOC_FILES entirely. So a line
# that OPENS a release-narrative paragraph (`^**v<semver>`) attributed
# to a NON-current release, or that says `At the v<x> release` /
# `release, surface was`, is skipped by the numeric rules.
#
# That guard would be a hole on its own — a stale paragraph could keep
# calling itself "current release" forever and buy silence for every
# number in it. RULE N1 closes it: a paragraph labelled `— current
# release` MUST attribute the Cargo.toml version. That is the mechanism
# that catches README's `**v0.9.0 — current release.** … schema **v78**,
# **101** MCP tools …, **92** HTTP route registrations …, **89** CLI
# subcommands … (**87** in the default build), a **28-field** `Memory`` —
# the exact paragraph carrying four of the register's five shapes. Once
# it is honestly relabelled `prior release` (or replaced by a v1.0.0
# paragraph) the numbers are either history (skipped) or current
# (checked). It is the same discipline as the #12 doc-drift
# release-version-attribution rule above, applied to the paragraph lead
# instead of the tool-count sentence.
check_generalised_numeric_claims() {
    local out
    if ! out="$(
        GATE_DOC_FILES="${DOC_FILES[*]}" \
        C_ROUTES="$CANONICAL_ROUTES_COUNT" \
        C_PATHS="$CANONICAL_UNIQUE_PATHS_COUNT" \
        C_SCHEMA="$CANONICAL_SCHEMA_VERSION" \
        C_FIELDS="$CANONICAL_MEMORY_FIELDS" \
        C_FULL_TOOLS="$CANONICAL_FULL_TOOL_COUNT" \
        C_CLI_SAL="$CANONICAL_CLI_SAL" \
        C_CLI_DEFAULT="$CANONICAL_CLI_DEFAULT" \
        C_RELEASE="$CANONICAL_RELEASE_VERSION" \
        python3 - <<'PY'
import os
import re

docs = os.environ["GATE_DOC_FILES"].split()
release = os.environ["C_RELEASE"]

# Self-test fault-injection (#2713): when this env var is set the analysis
# engine raises, so the gate's own --self-test can prove the gate FAILS
# CLOSED (exits non-zero, prints no PASS) on an engine error instead of
# swallowing it into an empty violation set. Never set in production / CI.
if os.environ.get("AI_MEMORY_DOCS_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-docs-vs-ssot self-test: injected analysis-engine fault (#2713)")

canon = {
    "EXPECTED_PRODUCTION_ROUTES_COUNT": os.environ["C_ROUTES"],
    "EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT": os.environ["C_PATHS"],
    "CURRENT_SCHEMA_VERSION": os.environ["C_SCHEMA"],
    "Memory::FIELD_COUNT": os.environ["C_FIELDS"],
    "Profile::full().expected_tool_count()": os.environ["C_FULL_TOOLS"],
    "EXPECTED_CLI_SUBCOMMANDS_SAL": os.environ["C_CLI_SAL"],
    "EXPECTED_CLI_SUBCOMMANDS_DEFAULT": os.environ["C_CLI_DEFAULT"],
}

# `**92**` / `92` / `` `92` `` -- bold, code-span, or bare.
NUM = r"(?:\*\*|`)?([0-9]+)(?:\*\*|`)?"

RULES = [
    ("EXPECTED_PRODUCTION_ROUTES_COUNT", [
        NUM + r"[ ]*(?:\*\*)?[ ]*(?:production[ ]+)?(?:HTTP|REST)[ ]+routes?[ ]+registrations",
        NUM + r"[ ]*(?:\*\*)?[ ]*(?:production[ ]+)?HTTP[ ]+routes\b",
        NUM + r"[ ]*production[ ]+`\.route\(\.\.\.\)`[ ]+registrations",
        NUM + r"[ ]*(?:\*\*)?[ ]*route[ ]+registrations",
    ]),
    ("EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT", [
        NUM + r"[ ]*(?:\*\*)?[ ]*unique[ ]+(?:URL[ ]+)?paths",
    ]),
    # BOLD-ONLY, deliberately. A bare `schema v52` is the ladder-history
    # phrasing the pre-existing CURRENT_SCHEMA_VERSION rule above already
    # refuses to touch ("v52 added X", RFC back-references, the three
    # frozen v0.7 migration guides); a bare-word anchor here would
    # red-line ~30 lines of legitimate history across ROADMAP, the
    # PORTABILITY spec, and the compliance inventory. `schema **vNN**`
    # is the SURFACE-SUMMARY phrasing — the register's own stale shape.
    ("CURRENT_SCHEMA_VERSION", [
        r"schema[ ]+\*\*v([0-9]+)\*\*",
    ]),
    ("Memory::FIELD_COUNT", [
        NUM + r"-field(?:\*\*)?[ ]*(?:`Memory`|struct)",
    ]),
    # `--profile full`-anchored, deliberately. A bare `N MCP tools`
    # matches the per-release capability ladder ("5 MCP tools", "4 MCP
    # tools") and per-family subset counts, none of which are claims
    # about the full-profile total.
    ("Profile::full().expected_tool_count()", [
        NUM + r"[ ]*(?:\*\*)?[ ]*MCP[ ]+tools[ ]+at[ ]+`--profile[ ]+full`",
        NUM + r"-entry(?:\*\*)?[ ]+surface",
        NUM + r"[ ]*(?:\*\*)?[ ]*advertised[ ]+entries[ ]+at[ ]+`--profile[ ]+full`",
    ]),
    ("EXPECTED_CLI_SUBCOMMANDS_SAL", [
        NUM + r"[ ]*(?:\*\*)?[ ]*(?:CLI[ ]+|top-level[ ]+)?subcommands[ ]+under[ ]+`--features[ ]+sal",
        r"yields[ ]+\*\*([0-9]+)\*\*[ ]+by[ ]+unlocking",
    ]),
    ("EXPECTED_CLI_SUBCOMMANDS_DEFAULT", [
        NUM + r"[ ]*(?:\*\*)?[ ]*(?:CLI[ ]+|top-level[ ]+)?subcommands[ ]+in[ ]+the[ ]+default[ ]+build",
        NUM + r"[ ]*(?:\*\*)?[ ]*in[ ]+the[ ]+default[ ]+build",
    ]),
]
RULES = [(k, [re.compile(p) for p in ps]) for k, ps in RULES]

# `— current release` paragraph lead. RULE N1.
CURRENT_RELEASE = re.compile(
    r"\*\*v([0-9]+\.[0-9]+\.[0-9]+)[^*\n]{0,120}?[-—]{1,2}[ ]*current release"
)
# Release-narrative paragraph lead: `**v0.8.0 (`x`) — prior release.**`
PARA_LEAD = re.compile(r"^\s*\*\*v([0-9]+\.[0-9]+\.[0-9]+)")
# Unconditionally past-tense phrasings.
PAST_TENSE = [
    re.compile(r"\bAt the v[0-9]+\.[0-9]+\.[0-9]+ release\b"),
    re.compile(r"\brelease, surface was\b"),
    re.compile(r"\bat the v[0-9]+\.[0-9]+\.[0-9]+ release\b"),
]
# Pre-existing historical-claim exclusions, preserved verbatim in intent
# from the CURRENT_SCHEMA_VERSION rule above: `v52 added X`,
# changelog-style headers, RFC back-references.
HISTORICAL = [
    re.compile(r"^\s*#{1,6}\s"),
    re.compile(r"\bv[0-9]+ added\b"),
    re.compile(r"\bwas [0-9]+ at v[0-9]"),
    re.compile(r"\bwas (?:four|five|six|seven|eight|nine|ten) at v[0-9]"),
    # ROADMAP 11.3.1 self-declares its frozen baselines and even
    # self-corrects inline ("the current substrate has advanced to
    # schema 88, 103 MCP tools"). Re-pointing those numbers at the
    # canonical would DESTROY the historical record they exist to keep.
    re.compile(r"\bShip state at v[0-9]+\.[0-9]+"),
    re.compile(r"\bFrozen v[0-9]+\.[0-9]+[^ ]* baseline\b"),
]


def is_historical(line):
    m = PARA_LEAD.match(line)
    if m and m.group(1) != release:
        return True
    if any(p.search(line) for p in PAST_TENSE):
        return True
    return any(p.search(line) for p in HISTORICAL)


for f in docs:
    try:
        text = open(f, encoding="utf-8").read()
    except OSError:
        continue
    for ln, line in enumerate(text.splitlines(), 1):
        ctx = line.strip()[:160].replace("\t", " ")
        m = CURRENT_RELEASE.search(line)
        if m and m.group(1) != release:
            print(
                "CURRENT_RELEASE_ATTRIBUTION\t"
                f"{f}\t{ln}\tv{m.group(1)}\tv{release}\t{ctx}"
            )
        if is_historical(line):
            continue
        for key, pats in RULES:
            for pat in pats:
                for hit in pat.finditer(line):
                    val = hit.group(1)
                    if val != canon[key]:
                        print(f"{key}\t{f}\t{ln}\t{val}\t{canon[key]}\t{ctx}")
PY
    )"; then
        # FAIL CLOSED (#2713): the numeric-claim analysis engine exited
        # non-zero (an uncaught exception — a UnicodeDecodeError on one
        # non-UTF-8 byte in a scanned doc, or the injected self-test
        # fault). The pre-fix `|| true` swallowed that into an empty
        # violation set and printed a FALSE "PASS" (the count in the pass
        # banner comes from a bash-side scan, attesting to work never run).
        printf 'FAIL: check-docs-vs-ssot: numeric-claim analysis engine errored (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' >&2
        exit 2
    fi

    # ---- PENDING-FIX ledger -------------------------------------------
    # Format, one per line: `<doc-file> <RULE_KEY> <claimed-value> #<issue>`
    # A MALFORMED entry HARD-FAILS (the ledger cannot rot into prose).
    # A STALE entry — one that suppresses nothing — is a loud NOTICE and
    # NOT a failure, exactly as `dual-trigger-cancel-allow.txt` handles
    # `token-budget.yml`: a stale entry can only suppress a failure that
    # no longer happens, and failing on it would red whichever PR lost
    # the race to the document-correction lane that removed the claim.
    # Five sibling lanes are correcting these documents concurrently; a
    # stale-fails ledger would guarantee exactly that collision.
    # The key is `<file> <rule> <value>` and NOT a line number precisely
    # so a lane's reflow does not silently re-open a suppression.
    local ledger="$REPO_ROOT/scripts/qc-allowlists/doc-numeric-claims-pending.txt"
    local ledger_keys="" ledger_used="" bad_entry=0
    if [[ -f "$ledger" ]]; then
        while IFS= read -r raw; do
            local entry="${raw%%#*}"
            entry="$(printf '%s' "$entry" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$entry" ]] && continue
            # shellcheck disable=SC2086
            set -- $entry
            if [[ $# -ne 3 ]] || ! [[ "$3" =~ ^v?[0-9][0-9.]*$ ]] || ! grep -qE '#[0-9]+' <<<"$raw"; then
                printf 'FAIL: doc-numeric-claims ledger: malformed entry "%s"\n' "$raw" >&2
                printf '       expected: <doc-file> <RULE_KEY> <claimed-value> #<issue>\n' >&2
                bad_entry=1
                continue
            fi
            ledger_keys="${ledger_keys}${1}|${2}|${3}"$'\n'
        done < "$ledger"
    fi
    if [[ "$bad_entry" -ne 0 ]]; then
        fail_count=$((fail_count + 1))
    fi

    if [[ -n "$out" ]]; then
        while IFS=$'\t' read -r rule f ln val expect ctx; do
            [[ -z "${rule:-}" ]] && continue
            local key="${f}|${rule}|${val}"
            if [[ -n "$ledger_keys" ]] && grep -Fxq "$key" <<<"$ledger_keys"; then
                ledger_used="${ledger_used}${key}"$'\n'
                continue
            fi
            emit_fail "$rule" "$f" "$ln" "$val" "$expect" "$ctx"
        done <<<"$out"
    fi

    if [[ -n "$ledger_keys" ]]; then
        local k
        while IFS= read -r k; do
            [[ -z "$k" ]] && continue
            if ! grep -Fxq "$k" <<<"$ledger_used"; then
                printf 'NOTICE: doc-numeric-claims ledger entry is STALE (suppresses nothing) — delete it: %s\n' \
                    "$(tr '|' ' ' <<<"$k")" >&2
            fi
        done < <(sort -u <<<"$ledger_keys")
    fi
}

run_all_rules() {
    fail_count=0
    check_schema_version_rule
    check_env_var_census_rule
    check_generalised_numeric_claims
    check_pgvector_version_rule
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
    # HookEvent count -- GENERALISED noun-phrase anchors (3x7 lane-3,
    # 2026-08-09), replacing the two hand-written phrasings this rule
    # shipped with. Per the #2492 diagnosis: a document that says the
    # same thing in the seventh way nobody enumerated is invisible.
    # Anchors are NOUNS + any adjacent integer, so a re-worded sentence
    # is still caught.
    #
    # The (?<![0-9])(?<!ships ) guard on the bare "lifecycle events"
    # anchor is load-bearing: ROADMAP opens its v0.8.0 planning row with
    # "v0.7.0 grand-slam ships 25 lifecycle events." -- a TRUE past-release
    # statement. The digit lookbehind is required too: without it the
    # engine simply re-anchors one character right and matches "5".
    # "variants total" is deliberately NOT an anchor for the same reason:
    # that same line legitimately carries "27 variants total AT v0.8.0".
    #
    # 3x7 lane-1 (#2780) UNION: the two `HookEvent`-SYMBOL phrasings below
    # are ADDITIVE to the lane-3 noun-phrase anchors — the generalised set
    # above does NOT cover the compliance-doc phrasing "**N** `HookEvent`
    # variants" (docs/compliance/nsa-csi-mcp-security-mapping.md:115, which
    # named the exact SSOT test it contradicted while shipping 27). They
    # stay BOLD-anchored + symbol-specific so the ROADMAP §11.3.1 frozen
    # v0.7.1 baseline's legitimate historical prose and the "27 variants
    # total AT v0.8.0" line are untouched.
    check_narrative_count_rule \
        "HookEvent variants" \
        "$CANONICAL_HOOK_EVENTS" \
        '([0-9]+)[- ]event hook pipeline|([0-9]+) named substrate events|([0-9]+) hook lifecycle events|(?<![0-9])(?<!ships )([0-9]+) lifecycle events|\*\*([0-9]+)\*\* `HookEvent` variants|`HookEvent` SSOT \(\*\*([0-9]+)\*\* variants' \
        "${HOOK_DOC_FILES[@]}"
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
    # CLI subcommand counts on operator-facing HTML surfaces (#2729 /
    # CB-32). The markdown rules above never see rendered .html pages;
    # these sibling rules police the same two anchors on the HTML
    # compliance docs (HTML_DOC_FILES). The default-build anchor is
    # "<N> CLI subcommands in the default build"; the sal anchor is the
    # "<N> under `sal`" figure that immediately follows it
    # ("... default build / <N> under <code>sal</code>"). Both survive
    # the code-span markup and match all three procurement-page uses
    # (the surface-table cell, the addresses-it paragraph, and the
    # operator-runbook `# Expected:` comment).
    check_narrative_count_rule \
        "EXPECTED_CLI_SUBCOMMANDS_DEFAULT (html)" \
        "$CANONICAL_CLI_DEFAULT" \
        '([0-9]+) CLI subcommands in the default build' \
        "${HTML_DOC_FILES[@]}"
    check_narrative_count_rule \
        "EXPECTED_CLI_SUBCOMMANDS_SAL (html)" \
        "$CANONICAL_CLI_SAL" \
        'default build / ([0-9]+) under' \
        "${HTML_DOC_FILES[@]}"

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
        printf '     pgvector patch = %s (deploy/docker-1461/provision/lib.sh DOCKER_1461_PGVECTOR_APT_VERSION)\n' "$CANONICAL_PGVECTOR_PATCH" >&2
        printf '     Current release version (Cargo.toml) = %s\n' "$CANONICAL_RELEASE_VERSION" >&2
        exit 1
    fi
    printf '✅ docs-vs-SSOT drift gate: PASS\n'
    printf '   Canonical values: schema=%s, full_tools=%s, core_tools=%s, routes=%s, paths=%s, cli_default=%s, cli_sal=%s, mem_fields=%s, link=%s, scope=%s, hooks=%s, pgvector=%s, release=%s\n' \
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
        "$CANONICAL_PGVECTOR_PATCH" \
        "$CANONICAL_RELEASE_VERSION"
}

# --------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------
# Inject a contrived stale claim into a temp file + run gate; verify
# it surfaces the violation; clean up. Mirrors the
# scripts/check-vendor-literals.sh self-test convention.

run_self_test() {
    # Scratch lives UNDER the repo, never system /tmp and never
    # `mktemp -d` (CLAUDE.md project hard rule; the #2494 /
    # migration-ladder gates set the precedent).
    local tmpdir="$REPO_ROOT/.local-runs/docs-ssot-selftest-$$"
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"
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

    # ================================================================
    # #2492 R-203 — the five README shapes that SLIPPED PAST THIS GATE
    # ================================================================
    #
    # This leg is the whole point. It plants the EXACT pre-fix README
    # phrasings the 3x7 claims audit found
    # (docs/audit/3x7-claims-register-2026-08-01.md 3.3.1) and asserts
    # BOTH directions:
    #
    #   * the FROZEN pre-fix gate (scripts/test/fixtures/
    #     docs-vs-ssot-prefix-2492.sh, verbatim at 03bbd556) ACCEPTS
    #     them — reproducing the defect, so the leg is not tautological
    #   * the LIVE gate REJECTS them
    #
    # Every number that the PRE-FIX pattern set CAN see is set to the
    # fixture canonical on purpose (e.g. `73 unique URL paths`), so the
    # old gate's pass is a real pass on the planted text and not an
    # accident of some unrelated rule staying quiet.
    local prefix_gate="$REPO_ROOT/scripts/test/fixtures/docs-vs-ssot-prefix-2492.sh"
    if [[ ! -x "$prefix_gate" ]]; then
        echo "FAIL: self-test — frozen pre-fix gate missing at $prefix_gate" >&2
        cd "$REPO_ROOT"
        exit 1
    fi

    # A CLAUDE.md that BOTH gates consider clean, so each leg below
    # isolates exactly the README text it plants.
    cat > CLAUDE.md <<'CLEANEOF'
Fixture CLAUDE.md — deliberately carries no narrative counts.
CLEANEOF

    # Fixture canonicals: routes 87 · paths 73 · schema 53 · fields 26
    #                     tools 12 · cli 78 default / 80 sal · release 9.9.9
    cat > README.md <<'STALEEOF'
Surface: **92** HTTP route registrations (73 unique URL paths).
2. **HTTP / mTLS daemon** -- 93 REST route registrations (73 unique URL paths) on `127.0.0.1:9077`.
- **92 HTTP routes (78 unique paths)** -- full REST API.
Surface: schema **v78**, **101** MCP tools at `--profile full`.
| **keyword** | FTS5 only | Baseline 101-entry surface | 0 MB |
| **smart** | Hybrid | full **101-entry** surface | ~1 GB |
The **CLI** (**89** CLI subcommands under `--features sal`/`sal-postgres` (**87** in the default build)).
a **28-field** `Memory`.
STALEEOF

    local prefix_out new_out
    if ! prefix_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$prefix_gate" 2>&1); then
        echo "FAIL: self-test R-203 — the FROZEN pre-fix gate REJECTED the planted shapes." >&2
        echo "       The whole finding was that it accepted them; this leg is broken, not the gate." >&2
        printf '%s\n' "$prefix_out" >&2
        cd "$REPO_ROOT"
        exit 1
    fi
    echo "PASS: self-test R-203 — frozen pre-fix gate ACCEPTS all five stale README shapes (the #2492 defect, reproduced)"

    if new_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — the WIDENED gate accepted the stale README shapes" >&2
        cd "$REPO_ROOT"
        exit 1
    fi
    local shape rules_missing=0
    for shape in \
        "EXPECTED_PRODUCTION_ROUTES_COUNT: README.md:1 claims \"92\"" \
        "EXPECTED_PRODUCTION_ROUTES_COUNT: README.md:2 claims \"93\"" \
        "EXPECTED_PRODUCTION_ROUTES_COUNT: README.md:3 claims \"92\"" \
        "EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT: README.md:3 claims \"78\"" \
        "CURRENT_SCHEMA_VERSION: README.md:4 claims \"78\"" \
        "Profile::full().expected_tool_count(): README.md:4 claims \"101\"" \
        "Profile::full().expected_tool_count(): README.md:5 claims \"101\"" \
        "Profile::full().expected_tool_count(): README.md:6 claims \"101\"" \
        "EXPECTED_CLI_SUBCOMMANDS_SAL: README.md:7 claims \"89\"" \
        "EXPECTED_CLI_SUBCOMMANDS_DEFAULT: README.md:7 claims \"87\"" \
        "Memory::FIELD_COUNT: README.md:8 claims \"28\"" \
    ; do
        if ! grep -qF "$shape" <<<"$new_out"; then
            echo "FAIL: self-test — widened gate did not flag: $shape" >&2
            rules_missing=1
        fi
    done
    if [[ "$rules_missing" -ne 0 ]]; then
        printf '%s\n' "$new_out" >&2
        cd "$REPO_ROOT"
        exit 1
    fi
    echo "PASS: self-test — widened gate REJECTS all 11 planted claims across the five register shapes"

    # ---- HISTORICAL CONTROL: a legitimate past-release mention PASSES.
    # The register's own guidance and this gate's original design both
    # depend on it: README carries `**v0.8.0 (…) — prior release.** …
    # surface was: schema **v70**, **100** MCP tools …` and ROADMAP
    # 11.3.1 carries a self-correcting frozen v0.7.1 baseline. Firing on
    # those would falsify the release history, so a regression HERE is a
    # data-integrity defect in its own right.
    cat > README.md <<'HISTEOF'
**v9.8.6 (`legacy`) — prior release.** At the v9.8.6 release, surface was: schema **v41**, **99** MCP tools at `--profile full`, **77** HTTP route registrations (70 unique paths), **60** CLI subcommands under `--features sal` (**58** in the default build), a **21-field** `Memory`.
**Ship state at v9.8.5 (frozen).** _(Frozen v9.8.5 baseline.)_ **55** HTTP route registrations / 44 unique paths, **90** MCP tools at `--profile full`.
schema v41 added the widget table; v40 added the gadget table.
### schema v39 — historical heading
HISTEOF
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — the widened gate fired on LEGITIMATE HISTORICAL mentions." >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"
        exit 1
    fi
    echo "PASS: self-test — historical release-narrative / frozen-baseline / ladder mentions still PASS"

    # ---- CURRENT-RELEASE ATTRIBUTION (rule N1): a paragraph that calls
    # itself the current release must name the Cargo.toml version. This
    # is what stops the historical guard above from becoming a hole a
    # stale "current release" paragraph could hide behind forever.
    cat > README.md <<'ATTREOF'
**v9.8.7 — current release.** A perfectly ordinary paragraph.
ATTREOF
    if new_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — gate accepted a stale '— current release' attribution" >&2
        cd "$REPO_ROOT"
        exit 1
    fi
    grep -q 'CURRENT_RELEASE_ATTRIBUTION' <<<"$new_out" || {
        echo "FAIL: self-test — stale current-release paragraph not flagged by its own rule" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test — a '— current release' paragraph naming a stale version is REJECTED"

    # ---- PENDING-FIX LEDGER, all three directions.
    mkdir -p "$tmpdir/scripts/qc-allowlists"
    local led="$tmpdir/scripts/qc-allowlists/doc-numeric-claims-pending.txt"
    cat > README.md <<'LEDEOF'
Surface: **92** HTTP route registrations (73 unique URL paths).
a **28-field** `Memory`.
LEDEOF
    printf 'README.md EXPECTED_PRODUCTION_ROUTES_COUNT 92 #1\n' > "$led"
    new_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1) && {
        echo "FAIL: self-test — ledger suppressed an UNLEDGERED claim (28-field Memory)" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -q 'FAIL: EXPECTED_PRODUCTION_ROUTES_COUNT:' <<<"$new_out" && {
        echo "FAIL: self-test — a LEDGERED claim was still reported as a failure" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -q 'FAIL: Memory::FIELD_COUNT:' <<<"$new_out" || {
        echo "FAIL: self-test — the unledgered claim was not reported" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test — ledger suppresses exactly its own key and nothing else"

    # STALE entry => loud NOTICE, exit 0 (the dual-trigger-cancel-allow
    # precedent: it can only suppress a failure that no longer happens,
    # and failing on it would red whichever PR lost the race to the
    # document-correction lane).
    cat > README.md <<'CLEANDOC'
Nothing to see here.
CLEANDOC
    printf 'README.md EXPECTED_PRODUCTION_ROUTES_COUNT 92 #1\n' > "$led"
    if ! new_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — a STALE ledger entry FAILED the gate (must be a NOTICE)" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -q 'NOTICE: doc-numeric-claims ledger entry is STALE' <<<"$new_out" || {
        echo "FAIL: self-test — a STALE ledger entry produced no NOTICE (the ledger can rot)" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test — a STALE ledger entry is a loud NOTICE, not a failure"

    # MALFORMED entry => HARD FAIL (the ledger cannot rot into prose).
    printf 'README.md EXPECTED_PRODUCTION_ROUTES_COUNT\n' > "$led"
    new_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1) && {
        echo "FAIL: self-test — a MALFORMED ledger entry did not fail the gate" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -q 'malformed entry' <<<"$new_out" || {
        echo "FAIL: self-test — malformed ledger entry not named in the failure" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test — a MALFORMED ledger entry HARD-FAILS"

    # ---- fail CLOSED on an analysis-engine error (CB-2 / #2713) -------
    # An internal engine error (a UnicodeDecodeError on one non-UTF-8 byte
    # in a scanned doc; a logic bug) must NEVER print PASS — the pre-fix
    # `|| true` on the numeric-claim heredoc did exactly that, and the
    # pass banner's count comes from a bash-side `find`, attesting to work
    # never run. R-203: first reproduce the pre-fix SHAPE, then prove the
    # FIXED gate fails closed under an injected engine fault.
    cat > README.md <<'CLEANDOC'
Nothing to see here.
CLEANDOC
    rm -f "$led"
    prefix_shape="$(v="$(python3 -c 'import sys; sys.exit(3)')" || true; [[ -z "$v" ]] && echo "WOULD-PRINT-PASS")"
    [[ "$prefix_shape" == "WOULD-PRINT-PASS" ]] || {
        echo "FAIL: self-test R-203 — the pre-fix \`|| true\` shape did not reproduce the false-PASS fail-open" >&2
        cd "$REPO_ROOT"; exit 1; }
    fault_rc=0
    fault_out="$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" AI_MEMORY_DOCS_GATE_SELFTEST_FAULT=1 "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1)" || fault_rc=$?
    [[ "$fault_rc" -ne 0 ]] || {
        echo "FAIL: self-test #2713 — the gate exited 0 on an injected analysis-engine fault (fail-OPEN)" >&2
        printf '%s\n' "$fault_out" | sed 's/^/       /' >&2; cd "$REPO_ROOT"; exit 1; }
    grep -q 'gate: PASS' <<<"$fault_out" && {
        echo "FAIL: self-test #2713 — the gate printed a PASS banner despite an engine fault" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -q 'analysis engine errored' <<<"$fault_out" || {
        echo "FAIL: self-test #2713 — engine fault did not produce the distinct fail-closed message" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test #2713 — an analysis-engine error FAILS CLOSED (exit $fault_rc, distinct message, no PASS banner)"
    # ---- HTML SURFACE COVERAGE (#2729 / CB-32, R-203). Before this
    # extension the gate had ZERO html coverage, so nsa-csi-mcp.html
    # shipped stale 89/91 CLI counts while its .md sibling was correct.
    # Plant a stale HTML count under the fixture and assert BOTH
    # html-aware CLI rules REJECT it. Clean the md docs + remove the
    # ledger first so this leg isolates exactly the planted HTML.
    rm -f "$led"
    cat > CLAUDE.md <<'HTMLCLEANCLAUDE'
Fixture CLAUDE.md — deliberately carries no narrative counts.
HTMLCLEANCLAUDE
    cat > README.md <<'HTMLCLEANREADME'
Fixture README — deliberately carries no narrative counts.
HTMLCLEANREADME
    mkdir -p "$tmpdir/docs/compliance"
    # Fixture canonicals: cli 78 default / 80 sal. Plant 89/91 — the exact
    # pre-fix nsa-csi-mcp.html shape — so the assertion reproduces CB-32.
    cat > "$tmpdir/docs/compliance/nsa-csi-mcp.html" <<'HTMLSTALEEOF'
<td>RequestValidator surface (94 production HTTP route registrations over 80 unique paths + 103 advertised MCP entries at <code>--profile full</code> + 89 CLI subcommands in the default build / 91 under <code>sal</code>)</td>
<span class="com"># Expected: 89 CLI subcommands in the default build / 91 under `sal`</span>
HTMLSTALEEOF
    if new_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — gate did NOT catch the stale HTML CLI counts (89/91 vs fixture 78/80)" >&2
        printf '%s\n' "$new_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -q 'EXPECTED_CLI_SUBCOMMANDS_DEFAULT (html): docs/compliance/nsa-csi-mcp.html' <<<"$new_out" || {
        echo "FAIL: self-test — stale HTML default-build CLI count not flagged by the html rule" >&2
        printf '%s\n' "$new_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -q 'EXPECTED_CLI_SUBCOMMANDS_SAL (html): docs/compliance/nsa-csi-mcp.html' <<<"$new_out" || {
        echo "FAIL: self-test — stale HTML sal CLI count not flagged by the html rule" >&2
        printf '%s\n' "$new_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test — html-aware gate REJECTS stale HTML CLI counts (#2729 / CB-32)"

    # ---- HTML CONTROL: correct HTML counts (matching the fixture
    # canonical 78/80) must PASS, proving the html rule is not a
    # blanket-fail on any html file it touches.
    cat > "$tmpdir/docs/compliance/nsa-csi-mcp.html" <<'HTMLGOODEOF'
<td>RequestValidator surface (78 CLI subcommands in the default build / 80 under <code>sal</code>)</td>
HTMLGOODEOF
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — html rule fired on CORRECT HTML CLI counts (78/80)" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test — correct HTML CLI counts (78/80) still PASS"

    # ---- HOOKEVENT WIDENING (3x7 lane-3, 2026-08-09). Before this
    # widening the HookEvent rule matched exactly TWO hand-written
    # phrasings and scanned only DOC_FILES/HTML_DOC_FILES, so at
    # f7399cfb it reported hooks=22 and PASSED while five live surfaces
    # published 25 or 27 -- including docs/audience/developer.html
    # naming pre_recall, an event #2758 REMOVED. Plant all five VERBATIM
    # pre-fix phrasings (fixture canonical is 25, so 27 is drift) and
    # assert the widened rule REJECTS every one, naming its file.
    rm -f "$led"
    mkdir -p "$tmpdir/docs/audience" "$tmpdir/docs/essays" "$tmpdir/docs/strategy"
    cat > README.md <<'HOOKSTALEREADME'
- **Hook pipeline (27 lifecycle events).** A programmable extension surface.
HOOKSTALEREADME
    cat > "$tmpdir/docs/production-deployment.md" <<'HOOKSTALEPD'
Hooks (`pre_store`, `post_store`, etc. — 27 lifecycle events, see hook-pipeline.md) are the supported extension surface.
HOOKSTALEPD
    cat > "$tmpdir/docs/strategy/coala-mapping.md" <<'HOOKSTALECOALA'
| Working memory | ... | `src/hooks/events.rs` (27 lifecycle events with typed payloads) |
HOOKSTALECOALA
    cat > "$tmpdir/docs/audience/developer.html" <<'HOOKSTALEDEV'
  <h2>27-event hook pipeline + HMAC subscriptions.</h2>
  <p>The hook pipeline fires on 27 named substrate events.</p>
HOOKSTALEDEV
    cat > "$tmpdir/docs/essays/brass-tacks-3-why.html" <<'HOOKSTALEBT'
  <p>The hook pipeline fires on 27 named substrate events.</p>
HOOKSTALEBT
    if hook_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — widened HookEvent rule did NOT catch the five planted 27-vs-25 claims" >&2
        printf '%s\n' "$hook_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    for hf in README.md docs/production-deployment.md docs/strategy/coala-mapping.md \
              docs/audience/developer.html docs/essays/brass-tacks-3-why.html; do
        grep -q "HookEvent variants: $hf" <<<"$hook_out" || {
            echo "FAIL: self-test — widened HookEvent rule missed the planted claim in $hf" >&2
            printf '%s\n' "$hook_out" >&2
            cd "$REPO_ROOT"; exit 1; }
    done
    echo "PASS: self-test — widened HookEvent rule REJECTS all five pre-fix phrasings across md + html"

    # ---- HOOKEVENT HISTORICAL CONTROL. The generalised anchors would be
    # unusable without the guard: ROADMAP legitimately opens a planning
    # row "v0.7.0 grand-slam ships 25 lifecycle events." and carries a
    # frozen v0.7.1 baseline, and README carries prior-release paragraph
    # leads. All must PASS even though their numbers differ from the
    # canonical. The bare digit lookbehind matters here too -- without
    # (?<![0-9]) the engine re-anchors one char right and matches "7".
    cat > README.md <<'HOOKHISTREADME'
**v9.8.6 (`legacy`) — prior release.** Shipped a programmable 27-event hook pipeline.
HOOKHISTREADME
    cat > "$tmpdir/docs/production-deployment.md" <<'HOOKHISTPD'
v0.7.0 grand-slam ships 27 lifecycle events.
**Ship state at v9.8.5 (frozen).** _(Frozen v9.8.5 baseline.)_ 27 hook lifecycle events at v9.8.5.
HOOKHISTPD
    rm -f "$tmpdir/docs/strategy/coala-mapping.md" \
          "$tmpdir/docs/audience/developer.html" \
          "$tmpdir/docs/essays/brass-tacks-3-why.html"
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — widened HookEvent rule fired on LEGITIMATE HISTORICAL hook mentions" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test — historical hook mentions (prior-release lead, 'ships N', frozen baseline) still PASS"

    # ---- PGVECTOR CERTIFIED-PATCH RULE. The certified pgvector patch is
    # pinned ONCE in deploy/docker-1461/provision/lib.sh's
    # DOCKER_1461_PGVECTOR_APT_VERSION default (the SAME default
    # tests/provisioning_pgvector_pin_parity.rs reads); ~15 current-cert
    # doc citations must agree. Plant the SSOT at 0.8.6, then plant a doc
    # citing a STALE 0.8.5 across all three anchor forms and assert the
    # gate REJECTS it; the correct 0.8.6 must PASS. Clean the leftover
    # HookEvent fixtures first so this leg isolates exactly the planted
    # pgvector doc.
    rm -f "$led" "$tmpdir/docs/production-deployment.md"
    mkdir -p "$tmpdir/deploy/docker-1461/provision"
    cat > "$tmpdir/deploy/docker-1461/provision/lib.sh" <<'PGVECSSOT'
PGVECTOR_APT_VERSION="${DOCKER_1461_PGVECTOR_APT_VERSION:-0.8.6-1.pgdg13+1}"
PGVECSSOT
    cat > CLAUDE.md <<'PGVECCLEANCLAUDE'
Fixture CLAUDE.md — deliberately carries no narrative counts.
PGVECCLEANCLAUDE
    cat > README.md <<'PGVECCLEANREADME'
Fixture README — deliberately carries no narrative counts.
PGVECCLEANREADME
    # Fixture SSOT patch = 0.8.6; plant a stale 0.8.5 across all three
    # anchors (table cell, prose, apt literal).
    cat > "$tmpdir/docs/CONFIG_SCHEMA.md" <<'PGVECSTALE'
| pgvector (server extension) | **0.8.5** | `PGVECTOR_APT_VERSION=0.8.5-1.pgdg13+1` |
| pgvector (Rust binding crate) | **0.4** | `pgvector = "0.4"` |
The image layers pgvector 0.8.5 onto the AGE base.
> Alternate tested matrix: PG 16 + AGE 1.6.0 + pgvector 0.8.2 is a second tested combination.
PGVECSTALE
    if pgv_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — gate did NOT catch the stale pgvector patch (0.8.5 vs SSOT 0.8.6)" >&2
        printf '%s\n' "$pgv_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -qF 'PGVECTOR_APT_VERSION (certified pgvector patch): docs/CONFIG_SCHEMA.md' <<<"$pgv_out" || {
        echo "FAIL: self-test — stale pgvector patch not flagged by the pgvector rule" >&2
        printf '%s\n' "$pgv_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    # The two-part Rust binding-crate figure (0.4) and the alternate-matrix
    # 0.8.2 must NOT be flagged — a match on either is a false positive.
    if grep -qF 'pgvector patch): docs/CONFIG_SCHEMA.md:2' <<<"$pgv_out"; then
        echo "FAIL: self-test — pgvector rule falsely flagged the two-part Rust crate figure (0.4)" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    if grep -qF 'pgvector patch): docs/CONFIG_SCHEMA.md:4' <<<"$pgv_out"; then
        echo "FAIL: self-test — pgvector rule falsely flagged the alternate PG16/AGE1.6 matrix (0.8.2)" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test — pgvector rule REJECTS a stale patch across all three anchors, spares the Rust-crate + alternate-matrix figures"

    # ---- PGVECTOR CONTROL: the correct patch (matching SSOT 0.8.6) PASSES.
    cat > "$tmpdir/docs/CONFIG_SCHEMA.md" <<'PGVECGOOD'
| pgvector (server extension) | **0.8.6** | `PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1` |
The image layers pgvector 0.8.6 onto the AGE base.
> Alternate tested matrix: PG 16 + AGE 1.6.0 + pgvector 0.8.2 is a second tested combination.
PGVECGOOD
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — pgvector rule fired on the CORRECT patch (0.8.6)" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test — the certified pgvector patch (0.8.6) still PASSES"

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
