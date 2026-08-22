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
#  - `src/security_profile.rs::KNOBS` entry count -> the asi-hard
#    pinned-knob narration in SECURITY.md / README.md / docs/deploy/*
#    / docs/enterprise-deployment.md ("is **N** knobs", "N-knob",
#    "N-entry pin-and-refuse", "PINS **N** security env knobs", "all
#    **N** `KNOBS` entries"). CHANGELOG + the cert doc's evidence notes
#    are EXCLUDED: their 17-knob text is a true pre-#3033 record.
#  - `enterprise_federation_posture::ENTERPRISE_FEDERATION_CHECK_COUNT`
#    -> the cert doc's normative exit contract ("returns **0 iff all N
#    checks pass, else 2**"). The same doc's 18/19-check EVIDENCE notes
#    are deliberately NOT anchored - they record a past capture.
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

# asi-hard pinned-knob count — the `KnobSpec` entries in
# `src/security_profile.rs::KNOBS`, which IS the no-disable contract:
# every knob in that table is pinned ON at boot and a value below its
# hard floor REFUSES boot. Five operator-facing surfaces narrate the
# count (SECURITY.md twice, README.md, docs/deploy/README.md,
# docs/deploy/enterprise-federation.env, docs/enterprise-deployment.md)
# and ALL FIVE shipped `17` after #3033 raised the table to 21 by adding
# the four outer federation-transport gates — a procurement-read
# understatement of the hardened posture that no gate saw. Counted from
# the table BODY (`^const KNOBS: &[KnobSpec] = &[` .. `^];`) so the
# `struct KnobSpec {` definition above it is never counted.
#
# `|| true` + the empty-normalisation below keep a genuinely-absent SSOT
# (the --self-test fixture tree) from aborting the gate under
# `set -euo pipefail`; an unresolved canonical then FAILS CLOSED inside
# the rule, but ONLY if a scan-set doc actually narrates a count (no
# claim to validate = nothing to fail).
# enterprise-federation posture check count — the SSOT the doctor
# posture asserts against (`evaluate()` must return exactly this many
# checks). The cert doc states it as the normative exit contract
# ("returns **0 iff all N checks pass, else 2**"), and that one sentence
# is what a procurement reader treats as the gate. It has moved four
# times (16 -> 18 -> 19 -> 20) and each move had to be caught by hand.
CANONICAL_EF_CHECK_COUNT="$(
    extract_const_value src/enterprise_federation_posture.rs \
        ENTERPRISE_FEDERATION_CHECK_COUNT 'usize' || true
)"
if [[ -z "$CANONICAL_EF_CHECK_COUNT" ]]; then
    CANONICAL_EF_CHECK_COUNT="<unresolved>"
fi

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
# asi-hard pinned-knob count (#3113). SSOT = the `KnobSpec` entries in the
# `KNOBS` table (mirrored by the derived const
# `security_profile::PINNED_KNOB_COUNT`). Counted from source for the same
# reason as the tool count above: the entries ARE the definition, so a knob
# cannot be added without moving this number.
CANONICAL_ASI_HARD_KNOBS=$(grep -cE '^[[:space:]]*KnobSpec \{' src/security_profile.rs 2>/dev/null || echo 0)

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

# Operator-facing HTML surfaces (rendered GitHub Pages). Markdown is the
# primary narrative form, but the published .html pages restate the same
# mechanically-pinned SSOT counts and drift INDEPENDENTLY of their .md
# siblings when an SSOT moves — #2729 / CB-32: nsa-csi-mcp.html shipped
# stale 89/91 CLI counts vs SSOT 90/92 while
# nsa-csi-mcp-security-mapping.md was already correct at 90/92. The gate
# had ZERO html references (same class as #2668 E-20 for benchmark.svg),
# so the rendered surface was invisible.
#
# #2977 — WIDENED from the one-file allowlist to the whole operator-facing
# `docs/**/*.html` surface. The one-file allowlist was itself the defect:
# ~70 hand-authored Jekyll pages were ungated, and the v1.0.0 doc-drift
# campaign (Waves 1-3) found stale schema versions, a sitewide v0.9.0
# chrome stamp, a false sub-10ms recall claim, a bench-as-merge-blocker
# claim and a kind-count 10-vs-16 across them WHILE THIS GATE STAYED
# GREEN. An enumerated allowlist cannot close that class: the rot is
# exactly that a NEW page lands ungated, so the scan set has to be
# ENROLL-BY-DEFAULT and the EXEMPTIONS have to be the enumerated thing.
#
# That inverts the #2839 `.md` argument, and deliberately so. The `.md`
# side stayed an additive list because a blanket `docs/**/*.md` glob drags
# in the historical ladder references, the frozen per-release summaries,
# and the analysis/adjudication artefacts under docs/reviews|design|audit
# — surfaces whose numbers are TRUE STATEMENTS ABOUT A PAST RELEASE. The
# .html tree has no such sprawl: its frozen surfaces are a small, named,
# structurally-obvious set (per-release trees, whats-new pages, release
# narratives, dated assessments), which is precisely the shape an
# exemption list can carry honestly. Every exemption below names WHY the
# page is frozen, so a reviewer can audit the boundary in one read.
#
# The exemption set is NOT declared here. It lives ONCE, in
# scripts/qc-allowlists/html-doc-frozen-exempt.txt, because
# scripts/check-ci-job-claims.sh walks the SAME html surface and two
# copies of a frozen-vs-live boundary would silently disagree the first
# time one is edited. That file's header carries the per-entry rationale
# and the test for admitting an entry.
#
# FAIL-CLOSED: a missing exemption file, or an EMPTY resolved set outside
# the --self-test fixture, is a hard failure — never a silent green
# (#2444 "reports success while doing nothing").
HTML_FROZEN_EXEMPT_FILE="$REPO_ROOT/scripts/qc-allowlists/html-doc-frozen-exempt.txt"
HTML_FROZEN_EXEMPT=()
if [[ -f "$HTML_FROZEN_EXEMPT_FILE" ]]; then
    while IFS= read -r _fx; do
        _fx="${_fx%%#*}"
        _fx="$(printf '%s' "$_fx" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -z "$_fx" ]] && continue
        HTML_FROZEN_EXEMPT+=("$_fx")
    done < "$HTML_FROZEN_EXEMPT_FILE"
else
    # Unconditional, fixture included: resolving the html scan set without
    # its frozen boundary would either red every frozen page or silently
    # drop the widening. Both are worse than refusing, and a check that is
    # waived under --self-test is a check the self-test cannot prove.
    printf 'FAIL: check-docs-vs-ssot: missing %s — refusing to resolve the html scan set without its frozen-page exemption SSOT (#2977 fail-closed)\n' \
        "$HTML_FROZEN_EXEMPT_FILE" >&2
    exit 1
fi

html_is_frozen() {
    local f="$1" pat
    for pat in "${HTML_FROZEN_EXEMPT[@]:-}"; do
        [[ -z "$pat" ]] && continue
        [[ "$f" == *"$pat"* ]] && return 0
    done
    return 1
}

HTML_DOC_FILES=()
while IFS= read -r _hf; do
    [[ -z "$_hf" ]] && continue
    _hf="${_hf#./}"
    html_is_frozen "$_hf" && continue
    HTML_DOC_FILES+=("$_hf")
done < <(find docs -name '*.html' -type f 2>/dev/null | sort)

if [[ ${#HTML_DOC_FILES[@]} -eq 0 && -z "${AI_MEMORY_DOCS_GATE_ROOT:-}" ]]; then
    printf 'FAIL: check-docs-vs-ssot: resolved ZERO operator-facing docs/**/*.html pages — the html rules would be a silent no-op (#2444)\n' >&2
    exit 1
fi

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
# De-duped (#2977): docs/audience/developer.html and
# docs/essays/brass-tacks-3-why.html were hand-added here when
# HTML_DOC_FILES held one file; the widened glob now already carries
# them, and a duplicate entry would report the same drift twice.
HOOK_DOC_FILES=()
for _hd in \
    "${DOC_FILES[@]}" \
    "${HTML_DOC_FILES[@]}" \
    docs/production-deployment.md \
    docs/strategy/coala-mapping.md \
    docs/audience/developer.html \
    docs/essays/brass-tacks-3-why.html
do
    _dup=0
    for _e in "${HOOK_DOC_FILES[@]:-}"; do [[ "$_e" == "$_hd" ]] && { _dup=1; break; }; done
    [[ "$_dup" == 0 ]] && HOOK_DOC_FILES+=("$_hd")
done

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

# Doc surfaces the asi-hard KNOBS-count rule walks. Its OWN scan set
# ("one rule, one scan set"): the surfaces that narrate the pinned-knob
# count as a PRESENT fact. Three of them (SECURITY.md, docs/deploy/*)
# are in no other scan set at all, which is exactly why the post-#3033
# 17-vs-21 drift was invisible.
#
# DELIBERATELY EXCLUDES:
#   * CHANGELOG.md — every entry is a landing-time snapshot; "the
#     existing 17-knob asi-hard hardened set" was TRUE when written.
#   * docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md — it
#     already says 21 in its current-state row AND carries a signed
#     `17`-knob EVIDENCE note recording what the captured `.out`
#     artifacts rendered PRE-#3033. Re-pointing an evidence note at the
#     canonical would falsify the record the cert rests on.
#   * infra/federation-lab/README.md — a campaign log, same class.
KNOB_DOC_FILES=(
    SECURITY.md
    README.md
    docs/deploy/README.md
    docs/deploy/asi-hard.env
    docs/deploy/enterprise-federation.env
    docs/enterprise-deployment.md
)

# Doc surface the enterprise-federation posture check-count rule walks.
CERT_CHECK_DOC_FILES=(
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
    # ONE python per RULE, not per FILE (#2977). The scan sets grew from a
    # handful of curated .md files to ~90 (the widened html surface), and a
    # per-file spawn made the gate's cost linear in interpreter startups
    # rather than in work. Batching is also why the fail-closed contract is
    # stated per-RULE below: a crash anywhere in the batch refuses the
    # whole rule, which is strictly safer than refusing one file.
    #
    # Capture-then-check, never `done < <(python3 …)`: a process
    # substitution's exit status is unobserved under `set -euo pipefail`,
    # so a crashing engine (a non-UTF-8 byte reaching an unguarded
    # `open()`) silently yields no rows and the rule PASSES — the #2713
    # fail-open shape.
    local narrative_rows
    narrative_rows="$(
        GATE_NC_FILES="${files[*]}" \
        GATE_NC_PATTERN="$pattern" \
        GATE_NC_RELEASE="$CANONICAL_RELEASE_VERSION" \
        python3 - <<'NCPY'
import html as htmlmod
import os
import re

pat = re.compile(os.environ["GATE_NC_PATTERN"])
release = os.environ["GATE_NC_RELEASE"]

if os.environ.get("AI_MEMORY_DOCS_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-docs-vs-ssot self-test: injected analysis-engine fault (#2713)")

# HISTORICAL GUARD -- 3x7 lane-3, 2026-08-09. Mirrors is_historical in
# the #2492 generalised scanner below. Principle: a TRUE statement about
# a PAST release must never be re-pointed at the canonical, or the gate
# destroys the record it exists to protect. This legacy per-rule function
# never had the guard -- harmless only while every rule regex was narrow
# enough to miss history by accident. Generalising the HookEvent anchors
# made that accident stop holding: the README prior-release paragraph and
# the ROADMAP frozen v0.7.1 baseline both legitimately say 25.
PARA_LEAD = re.compile(r"^\s*\*\*v([0-9]+\.[0-9]+\.[0-9]+)")
# MARKDOWN-ONLY (#3113). A leading `#` is a HEADING in .md/.html prose, but
# it is the COMMENT marker in .sh / .env / .toml / .yml. Held in the shared
# `HIST` ladder this anchor silently swallowed EVERY comment line of a
# non-markdown scan file, so a rule that listed such a file covered nothing
# in it and still reported PASS -- the fail-open shape this gate exists to
# refuse. Harmless until now only because every previous scan set was
# .md/.html; the asi-hard pinned-knob rule below is the first to walk a
# shell script and an env template. Rust is unaffected either way (`#[...]`
# / `#![...]` attributes are not `#` + space, and `//! # Heading` starts
# with `//!`), but it is scoped by the same test rather than by luck.
MD_HEADING = re.compile(r"^\s*#{1,6}\s")
HIST = [
    re.compile(r"\b[Aa]t the v[0-9]+\.[0-9]+\.[0-9]+ release\b"),
    re.compile(r"\brelease, surface was\b"),
    re.compile(r"\bv[0-9]+ added\b"),
    re.compile(r"\bwas [0-9]+ at v[0-9]"),
    re.compile(r"\bShip state at v[0-9]+\.[0-9]+"),
    re.compile(r"\bFrozen v[0-9]+\.[0-9]+[^ ]* baseline\b"),
]

# HTML HISTORICAL GUARD (#2977). Two things differ on the rendered .html
# surface and BOTH are load-bearing:
#   1. MARKUP SPLITS THE SENTENCE. `schema <strong>vNN</strong> added ...`
#      never matches the bare `vNN added` ladder guard, so a TRUE
#      historical ladder mention would be reported as drift. The guard is
#      therefore evaluated over a TAG-STRIPPED, entity-decoded,
#      WHITESPACE-COLLAPSED view (collapsing matters: a tag replaced by a
#      space leaves two spaces, which the single-space guard still misses
#      — a guard that looks present and does nothing).
#   2. THE RELEASE ATTRIBUTION LIVES IN A SIBLING ELEMENT. A markdown
#      release-narrative paragraph opens with its own
#      `**vX.Y.Z ... prior release.**` lead; an html release CARD puts
#      `PRIOR RELEASE` and `What's New in v0.7.0` in the two divs ABOVE
#      the card body carrying the numbers. So the two card markers are
#      evaluated over a SMALL PRECEDING WINDOW — the same shape
#      scripts/check-doc-symbol-anchors.sh uses for its hard-wrapped
#      absent-path disclaimers. Three lines: enough for eyebrow + title,
#      too short to reach into an unrelated block.
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")
HTML_WINDOW = 3
HTML_HIST_PRIOR = re.compile(r"PRIOR RELEASE", re.IGNORECASE)
HTML_HIST_WHATSNEW = re.compile(
    r"What.s New in v([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)


def plain(s):
    return WS.sub(" ", htmlmod.unescape(TAG.sub(" ", s))).strip()


def is_historical(line, markdownish=True):
    m = PARA_LEAD.match(line)
    if m and m.group(1) != release:
        return True
    if markdownish and MD_HEADING.search(line):
        return True
    return any(p.search(line) for p in HIST)


def html_window_historical(window):
    joined = " ".join(plain(w) for w in window)
    if HTML_HIST_PRIOR.search(joined):
        return True
    return any(m.group(1) != release
               for m in HTML_HIST_WHATSNEW.finditer(joined))


for f in os.environ["GATE_NC_FILES"].split():
    if not os.path.isfile(f):
        continue
    is_html = f.endswith(".html")
    markdownish = f.endswith((".md", ".html"))
    lines = open(f, encoding="utf-8").read().splitlines()
    for ln, line in enumerate(lines, 1):
        if is_html:
            if is_historical(plain(line), markdownish):
                continue
            if html_window_historical(lines[max(0, ln - 1 - HTML_WINDOW):ln]):
                continue
        elif is_historical(line, markdownish):
            continue
        for m in pat.finditer(line):
            # Alternation groups: take the FIRST non-None capture
            val = next((g for g in m.groups() if g is not None), "")
            if not val:
                continue
            ctx = line.strip()[:160].replace("\t", " ")
            print(f"{f}\t{ln}\t{val}\t{ctx}")
NCPY
    )" || {
        printf 'FAIL: check-docs-vs-ssot: %s analysis engine errored (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' "$rule_name" >&2
        exit 2
    }
    local f ln val context
    while IFS=$'\t' read -r f ln val context; do
        [[ -z "$val" ]] && continue
        if [[ "$val" != "$canonical" ]]; then
            emit_fail "$rule_name" "$f" "$ln" "$val" "$canonical" "$context"
        fi
    done <<< "$narrative_rows"
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

# Sitewide HTML CHROME version-stamp rule (#2977).
#
# THE DEFECT. The v1.0.0 doc-drift campaign found the published site's
# chrome carrying `v0.9.0` across 38 pages while every gate stayed green.
# Chrome is the highest-leverage claim on the whole site — it is the
# version an operator reads on EVERY page — and it was the one claim
# nothing checked.
#
# THE ANCHOR is CHROME, not prose. Two shapes, both of which are
# per-page furniture rather than narrative:
#   * the footer stamp, scoped to the text INSIDE a `<footer>` element:
#     `ai-memory v1.0.0 · Apache 2.0 · …`, `© 2026 AlphaOne LLC.
#     Licensed Apache-2.0. ai-memory v1.0.0 — …`
#   * the hero/nav release badge: `<span class="badge">v1.0.0 · …`
# Scoping to the chrome is what keeps the rule off legitimate prose. A
# page may say "v0.9.0 shipped the attestation default" in its body all
# day; that is history, and the rule never reads it.
#
# PUBLISHED-INSTALL REFERENCES ARE SKIPPED, deliberately and by name. The
# v1.0.0 TAG-CUT IS OPERATOR-GATED (CLAUDE.md §release gate), so the last
# PUBLISHED artefact is still v0.9.0 and an install/download line that
# says so is CORRECT — flagging it would push a doc author to publish an
# install command for a tag that does not exist, which is worse than the
# drift the rule is here to catch. Footer scoping already excludes almost
# all of these; the keyword skip below is the belt for the rare footer
# that carries a download link.
#
# Frozen pages never reach this rule: they are filtered out of
# HTML_DOC_FILES by HTML_FROZEN_EXEMPT at the top of this script, which is
# exactly why a `whats-new-v0.8.0` page may keep stamping v0.8.0.
check_html_version_stamp_rule() {
    local rule_name="HTML_CHROME_VERSION_STAMP"
    local canonical="$CANONICAL_RELEASE_VERSION"
    if [[ -z "$canonical" ]]; then
        printf 'FAIL: %s: could not resolve the release version from Cargo.toml — refusing to validate (#2713 fail-closed)\n' \
            "$rule_name" >&2
        fail_count=$((fail_count + 1))
        return
    fi
    # ONE python for the whole scan set (the check_narrative_count_rule
    # batching rationale): 53 interpreter startups to read 53 footers is
    # cost with no work in it.
    local rows
    rows="$(
        GATE_STAMP_FILES="${HTML_DOC_FILES[*]:-}" python3 - <<'PY'
import os
import re

if os.environ.get("AI_MEMORY_DOCS_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-docs-vs-ssot self-test: injected analysis-engine fault (#2713)")

FOOTER_OPEN = re.compile(r"<footer\b", re.IGNORECASE)
FOOTER_CLOSE = re.compile(r"</footer\s*>", re.IGNORECASE)
# `ai-memory v1.0.0` / `ai-memory&trade; v1.0.0` / `ai-memory™ v1.0.0`
FOOTER_STAMP = re.compile(
    r"ai-memory(?:&trade;|&#8482;|™)?\s+v([0-9]+\.[0-9]+\.[0-9]+)")
# The hero/nav release badge: `<span class="badge">v1.0.0 &middot; …`
BADGE_STAMP = re.compile(
    r'class="badge"[^>]*>\s*v([0-9]+\.[0-9]+\.[0-9]+)')
# Published-install / download references legitimately trail the last
# PUBLISHED tag while the tag-cut is operator-gated.
INSTALL_REF = re.compile(
    r"install|download|releases/download|/tag/|git\s+checkout|"
    r"cargo\s+add|crates\.io|homebrew|brew\s|docker\s+pull|"
    r"npm\s+i(?:nstall)?\b|pip\s+install|ghcr\.io|apt-get",
    re.IGNORECASE,
)

for path in os.environ.get("GATE_STAMP_FILES", "").split():
    if not os.path.isfile(path):
        continue
    lines = open(path, encoding="utf-8").read().splitlines()
    depth = 0
    for ln, line in enumerate(lines, 1):
        opens = len(FOOTER_OPEN.findall(line))
        closes = len(FOOTER_CLOSE.findall(line))
        in_footer = depth > 0 or opens > 0
        depth += opens - closes
        if depth < 0:
            depth = 0
        if INSTALL_REF.search(line):
            continue
        hits = []
        if in_footer:
            hits += [("footer", m) for m in FOOTER_STAMP.finditer(line)]
        hits += [("badge", m) for m in BADGE_STAMP.finditer(line)]
        for kind, m in hits:
            ctx = line.strip()[:160].replace("\t", " ")
            print(f"{path}\t{ln}\t{m.group(1)}\t{kind}\t{ctx}")
PY
    )" || {
        printf 'FAIL: check-docs-vs-ssot: html chrome version-stamp engine errored (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' >&2
        exit 2
    }
    local f ln val kind context
    while IFS=$'\t' read -r f ln val kind context; do
        [[ -z "$val" ]] && continue
        if [[ "$val" != "$canonical" ]]; then
            emit_fail "$rule_name ($kind)" "$f" "$ln" "v$val" "v$canonical" "$context"
        fi
    done <<< "$rows"
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
        GATE_HTML_FILES="${HTML_DOC_FILES[*]:-}" \
        C_ROUTES="$CANONICAL_ROUTES_COUNT" \
        C_PATHS="$CANONICAL_UNIQUE_PATHS_COUNT" \
        C_SCHEMA="$CANONICAL_SCHEMA_VERSION" \
        C_FIELDS="$CANONICAL_MEMORY_FIELDS" \
        C_FULL_TOOLS="$CANONICAL_FULL_TOOL_COUNT" \
        C_CLI_SAL="$CANONICAL_CLI_SAL" \
        C_CLI_DEFAULT="$CANONICAL_CLI_DEFAULT" \
        C_RELEASE="$CANONICAL_RELEASE_VERSION" \
        python3 - <<'PY'
import html as htmlmod
import os
import re

docs = os.environ["GATE_DOC_FILES"].split()
# #2977 — the operator-facing docs/**/*.html surface, resolved by the
# enroll-by-default glob + frozen-exemption list at the top of this
# script. Scanned by the SAME rule table as the .md set (see the markup
# dialect note below) but under an html-aware historical guard.
html_docs = os.environ.get("GATE_HTML_FILES", "").split()
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

# MARKUP DIALECT (#2977). ONE anchor grammar, two dialects. The rendered
# .html pages restate the same noun-phrase anchors as the .md sources, but
# with `<strong>`/`<code>` where markdown writes `**`/`` ` ``, and with
# `&nbsp;` where markdown writes a space. Writing a SECOND html rule table
# would give two definitions that can silently disagree (the standing
# CLAUDE.md objection: "two definitions that can disagree teach reviewers
# to ignore both"), so the delimiters below simply admit BOTH spellings and
# the SAME table serves both file types. A .md file never contains
# `<strong>` and a .html file never contains `**`, so neither dialect
# widens the other's match set.
#
# Each alternative inside MK is NON-EMPTY on purpose: a `*`-quantified
# alternative nested inside a `+`-quantified group is the classic
# catastrophic-backtracking shape.
MK = r"(?:</?(?:strong|b|code|em|i)>|\*\*|`)"
# SP1 keeps the "at least one separator" requirement the markdown `[ ]+`
# positions carried; SP0 replaces the `[ ]*(?:\*\*)?[ ]*` runs.
SP0 = r"(?:[ ]|&nbsp;|" + MK + r")*"
SP1 = r"(?:[ ]|&nbsp;|" + MK + r")+"
BOLD_OPEN = r"(?:\*\*|<strong>|<b>)"
BOLD_CLOSE = r"(?:\*\*|</strong>|</b>)"
CODE_OPEN = r"(?:`|<code>)"
CODE_CLOSE = r"(?:`|</code>)"
# `**92**` / `92` / `` `92` `` / `<strong>92</strong>` / `<code>92</code>`
NUM = (r"(?:" + BOLD_OPEN + r"|" + CODE_OPEN + r")?([0-9]+)"
       r"(?:" + BOLD_CLOSE + r"|" + CODE_CLOSE + r")?")

RULES = [
    ("EXPECTED_PRODUCTION_ROUTES_COUNT", [
        NUM + SP0 + r"(?:production" + SP1 + r")?(?:HTTP|REST)" + SP1 + r"routes?" + SP1 + r"registrations",
        NUM + SP0 + r"(?:production" + SP1 + r")?HTTP" + SP1 + r"routes\b",
        NUM + SP0 + r"production" + SP1 + CODE_OPEN + r"\.route\(\.\.\.\)" + CODE_CLOSE + SP1 + r"registrations",
        NUM + SP0 + r"route" + SP1 + r"registrations",
    ]),
    ("EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT", [
        NUM + SP0 + r"unique" + SP1 + r"(?:URL" + SP1 + r")?paths",
    ]),
    # BOLD-ONLY, deliberately. A bare `schema v52` is the ladder-history
    # phrasing the pre-existing CURRENT_SCHEMA_VERSION rule above already
    # refuses to touch ("v52 added X", RFC back-references, the three
    # frozen v0.7 migration guides); a bare-word anchor here would
    # red-line ~30 lines of legitimate history across ROADMAP, the
    # PORTABILITY spec, and the compliance inventory. `schema **vNN**`
    # is the SURFACE-SUMMARY phrasing — the register's own stale shape.
    # CODE-span is deliberately NOT admitted here either: the html twin of
    # a bare `schema v52` is `schema <code>v52</code>`, which is exactly
    # the pinned-artefact / ladder-history spelling the bold-only rule
    # exists to spare (docs/reference-architecture/index.html pins the
    # do-1461 golden fleet at `schema <code>v78</code>`).
    ("CURRENT_SCHEMA_VERSION", [
        r"schema" + SP1 + BOLD_OPEN + r"v([0-9]+)" + BOLD_CLOSE,
    ]),
    ("Memory::FIELD_COUNT", [
        NUM + r"-field" + SP0 + r"(?:" + CODE_OPEN + r"Memory" + CODE_CLOSE + r"|struct)",
    ]),
    # `--profile full`-anchored, deliberately. A bare `N MCP tools`
    # matches the per-release capability ladder ("5 MCP tools", "4 MCP
    # tools") and per-family subset counts, none of which are claims
    # about the full-profile total.
    ("Profile::full().expected_tool_count()", [
        NUM + SP0 + r"MCP" + SP1 + r"tools" + SP1 + r"at" + SP1 + CODE_OPEN + r"--profile" + SP1 + r"full" + CODE_CLOSE,
        NUM + r"-entry" + SP1 + r"surface",
        NUM + SP0 + r"advertised" + SP1 + r"entries" + SP1 + r"at" + SP1 + CODE_OPEN + r"--profile" + SP1 + r"full" + CODE_CLOSE,
    ]),
    ("EXPECTED_CLI_SUBCOMMANDS_SAL", [
        NUM + SP0 + r"(?:CLI" + SP1 + r"|top-level" + SP1 + r")?subcommands" + SP1 + r"under" + SP1 + CODE_OPEN + r"--features" + SP1 + r"sal",
        r"yields" + SP1 + BOLD_OPEN + r"([0-9]+)" + BOLD_CLOSE + SP1 + r"by" + SP1 + r"unlocking",
    ]),
    ("EXPECTED_CLI_SUBCOMMANDS_DEFAULT", [
        NUM + SP0 + r"(?:CLI" + SP1 + r"|top-level" + SP1 + r")?subcommands" + SP1 + r"in" + SP1 + r"the" + SP1 + r"default" + SP1 + r"build",
        NUM + SP0 + r"in" + SP1 + r"the" + SP1 + r"default" + SP1 + r"build",
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


# ---- HTML HISTORICAL GUARD (#2977) ----------------------------------
# The markdown guards above are line-scoped because a markdown
# release-narrative paragraph IS one line, opening with its own
# `**v0.8.0 … prior release.**` lead. The rendered .html surface breaks
# that assumption in two independent ways, and BOTH would turn TRUE
# history into reported drift:
#
#   1. MARKUP SPLITS THE SENTENCE. `schema <strong>v67</strong> added the
#      target_agent_id_idx column` never matches the bare `vNN added`
#      ladder guard, because the tags sit between the two words. The guard
#      is therefore evaluated over a TAG-STRIPPED, entity-decoded view of
#      the line. (This is not hypothetical: it is the single hit the
#      widened scan produced on the tree at 57b7fe35.)
#
#   2. THE RELEASE ATTRIBUTION LIVES IN A SIBLING ELEMENT. An HTML release
#      CARD puts `▸ PRIOR RELEASE` and `What's New in v0.7.0` in the two
#      divs ABOVE the card body that carries the numbers, so nothing on
#      the number-bearing line says which release it describes. The two
#      card markers are therefore evaluated over a SMALL PRECEDING WINDOW
#      — the same shape scripts/check-doc-symbol-anchors.sh uses for its
#      hard-wrapped absent-path disclaimers. THREE lines: enough for
#      eyebrow + title, too short to reach into an unrelated block.
#
# `What's New in vX.Y.Z` is historical only when X.Y.Z is NOT the current
# release, so a card describing the CURRENT release keeps being checked.
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")
HTML_WINDOW = 3
HTML_HIST_PRIOR = re.compile(r"PRIOR RELEASE", re.IGNORECASE)
HTML_HIST_WHATSNEW = re.compile(
    r"What.s New in v([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)


def plain(s):
    # Whitespace is COLLAPSED, not merely substituted: replacing a tag
    # with a space leaves `v67  added` (two spaces), which the ladder
    # guard's single-space `\bv[0-9]+ added\b` would still miss — the
    # guard would look present and do nothing.
    return WS.sub(" ", htmlmod.unescape(TAG.sub(" ", s))).strip()


def html_window_historical(window):
    joined = " ".join(plain(w) for w in window)
    if HTML_HIST_PRIOR.search(joined):
        return True
    return any(m.group(1) != release
               for m in HTML_HIST_WHATSNEW.finditer(joined))


def scan(f, is_html):
    try:
        text = open(f, encoding="utf-8").read()
    except OSError:
        return
    lines = text.splitlines()
    for ln, line in enumerate(lines, 1):
        ctx = line.strip()[:160].replace("\t", " ")
        if is_html:
            if is_historical(plain(line)):
                continue
            if html_window_historical(lines[max(0, ln - 1 - HTML_WINDOW):ln]):
                continue
        else:
            # RULE N1 is a MARKDOWN paragraph-lead rule; the html surface
            # has no `**vX — current release.**` shape. Its html analogue
            # is the footer/nav chrome stamp, policed by its own rule.
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


for f in docs:
    scan(f, False)
for f in html_docs:
    scan(f, True)
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
    # asi-hard pinned-knob count (#3113). The count is quoted in PROSE across
    # six files that cannot derive it; the module doc table sat two rows behind
    # `KNOBS` for a full release with nothing failing. Set equality of the
    # TABLE is pinned in-code by
    # `security_profile::tests::pinned_knobs_doc_table_matches_the_knobs_ssot_exactly`;
    # this rule pins the NARRATIVE count everywhere else.
    # Known limitation (stated, not hidden): a NEW phrasing that none of these
    # alternatives match would evade the rule. Add its shape here in the same
    # commit that introduces it.
    # CANONICAL RULE for this SSOT. PR #3169 proposes a second, overlapping
    # asi-hard knob-count rule with its own scan set; this one supersedes it
    # (it walks a strict superset of those surfaces) and the duplicate is to be
    # collapsed into this rule at #3169's rebase — one rule, one SSOT, one
    # scan set.
    # Coverage as verified at this commit (a rule whose regex matches nothing
    # in a listed file is a no-op that still reports PASS, so this is stated
    # rather than assumed, and re-verified whenever a file is enrolled):
    # 17 anchored citations across 11 of the 12 surfaces, all reading the
    # canonical — CLAUDE.md 3, README.md 1, SECURITY.md 2, PERFORMANCE.md 1,
    # docs/deploy/README.md 1, docs/deploy/enterprise-federation.env 1, the
    # certification doc 2, docs/enterprise-deployment.md 1,
    # src/security_profile.rs 2, src/enterprise_federation_posture.rs 2,
    # scripts/check-bootstrap-cert-gate.sh 1.
    # Two of the twelve surfaces are reachable ONLY because the markdown-heading
    # anchor is now scoped to .md/.html (see MD_HEADING above): the `#` shell
    # comment in scripts/check-bootstrap-cert-gate.sh and the `#` env-template
    # comment in docs/deploy/enterprise-federation.env — the latter being
    # precisely the line whose 17-vs-current drift went unseen.
    # docs/deploy/asi-hard.env quotes NO count today and is enrolled so that a
    # future one is policed on arrival; the knob NAMES in that template are
    # pinned instead by
    # tests/deploy_templates.rs::asi_hard_env_names_every_pinned_knob, and the
    # two documented pinned-knob TABLES (this module's and PERFORMANCE.md's)
    # by set equality in security_profile's own tests.
    check_narrative_count_rule \
        "ASI_HARD_PINNED_KNOB_COUNT" \
        "$CANONICAL_ASI_HARD_KNOBS" \
        '([0-9]+)-knob|(?:auto-)?[Pp]ins the ([0-9]+)(?: asi-hard)? knobs|holds \*\*([0-9]+)\*\* entries|names all ([0-9]+) correctly|SSOT for the ([0-9]+)|\*\*([0-9]+)\*\* post-#|shows `([0-9]+)/[0-9]+`|`PINNED_KNOB_COUNT` \(([0-9]+)\)|is \*\*([0-9]+) knobs\*\*|PINS \*\*([0-9]+)\*\* security env knobs|([0-9]+)-entry pin-and-refuse|all \*\*([0-9]+)\*\* `KNOBS` entries|All \*\*([0-9]+)\*\* of them' \
        CLAUDE.md \
        README.md \
        SECURITY.md \
        PERFORMANCE.md \
        docs/deploy/README.md \
        docs/deploy/asi-hard.env \
        docs/deploy/enterprise-federation.env \
        docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md \
        docs/enterprise-deployment.md \
        src/security_profile.rs \
        src/enterprise_federation_posture.rs \
        scripts/check-bootstrap-cert-gate.sh
    check_generalised_numeric_claims
    check_pgvector_version_rule
    check_html_version_stamp_rule
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
    # asi-hard pinned-knob count (src/security_profile.rs::KNOBS).
    # FIVE anchors, all BOLD- or hyphen-delimited so a bare integer next
    # to the word "knobs" can never match. The bold delimiter on the
    # `is **N** knobs` form is load-bearing: docs/deploy/README.md says
    # "the config-backed PE-1 knobs and", and a bare `([0-9]+) knobs`
    # anchor captures the `1` out of `PE-1` and reports phantom drift.
    check_narrative_count_rule \
        "asi-hard KNOBS count (src/security_profile.rs::KNOBS)" \
        "$CANONICAL_ASI_HARD_KNOBS" \
        'is \*\*([0-9]+) knobs\*\*|PINS \*\*([0-9]+)\*\* security env knobs|([0-9]+)-knob\b|([0-9]+)-entry pin-and-refuse|all \*\*([0-9]+)\*\* `KNOBS` entries' \
        "${KNOB_DOC_FILES[@]}"
    # enterprise-federation posture check count
    # (enterprise_federation_posture::ENTERPRISE_FEDERATION_CHECK_COUNT).
    # ONE anchor: the cert doc's NORMATIVE exit contract. Scoped that
    # tightly on purpose — the same document carries `18`/`19`-check
    # EVIDENCE NOTES describing what the committed `cert-54/*.out`
    # captures actually rendered at the tree they were taken on. Those
    # are TRUE statements about a past capture; a broader anchor would
    # "fix" them into a lie about the evidence bundle.
    check_narrative_count_rule \
        "ENTERPRISE_FEDERATION_CHECK_COUNT" \
        "$CANONICAL_EF_CHECK_COUNT" \
        'returns \*\*0 iff all ([0-9]+) checks pass' \
        "${CERT_CHECK_DOC_FILES[@]}"

    if [[ "$fail_count" -gt 0 ]]; then
        printf '\n❌ docs-vs-SSOT drift gate: %d violation(s)\n' "$fail_count" >&2
        printf '   Canonical values resolved from source:\n' >&2
        printf '     CURRENT_SCHEMA_VERSION = %s (src/storage/migrations.rs)\n' "$CANONICAL_SCHEMA_VERSION" >&2
        printf '     Profile::full() tool count = %s (registry RegisteredTool::of entries)\n' "$CANONICAL_FULL_TOOL_COUNT" >&2
        printf '     asi-hard pinned knobs = %s (security_profile KNOBS entries / PINNED_KNOB_COUNT)\n' "$CANONICAL_ASI_HARD_KNOBS" >&2
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
        printf '     asi-hard KNOBS entries = %s (src/security_profile.rs::KNOBS)\n' "$CANONICAL_ASI_HARD_KNOBS" >&2
        printf '     ENTERPRISE_FEDERATION_CHECK_COUNT = %s\n' "$CANONICAL_EF_CHECK_COUNT" >&2
        exit 1
    fi
    printf '✅ docs-vs-SSOT drift gate: PASS\n'
    printf '   Canonical values: schema=%s, full_tools=%s, core_tools=%s, routes=%s, paths=%s, cli_default=%s, cli_sal=%s, mem_fields=%s, link=%s, scope=%s, hooks=%s, pgvector=%s, release=%s, asi_hard_knobs=%s, ef_checks=%s\n' \
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
        "$CANONICAL_RELEASE_VERSION" \
        "$CANONICAL_ASI_HARD_KNOBS" \
        "$CANONICAL_EF_CHECK_COUNT"
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
    # #2977 — the frozen-page exemption SSOT the html scan set resolves
    # against. A REAL one (not an empty stub) so the html legs below can
    # prove BOTH directions of the boundary.
    mkdir -p scripts/qc-allowlists
    cat > scripts/qc-allowlists/html-doc-frozen-exempt.txt <<'FROZENEOF'
# fixture exemption SSOT
docs/whats-new-v
FROZENEOF
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

    # ---- ASI-HARD PINNED-KNOB COUNT + THE MARKDOWN-HEADING SCOPING (#3113).
    # Two directions in one leg, because the SECOND is what makes the first
    # real:
    #
    #   (a) A stale count in a SHELL COMMENT must be REJECTED. This rule is
    #       the first to walk a .sh / .env scan target, and until #3113 the
    #       historical-line guard treated a leading `#` as a markdown HEADING
    #       for EVERY file type — so in a shell script every comment line was
    #       skipped, the rule covered NOTHING in it, and the gate still
    #       printed PASS. That is the #2444 "reports success while doing
    #       nothing" shape, arrived at by accident rather than by decision.
    #
    #   (b) A stale count in a genuine MARKDOWN HEADING must still be SPARED.
    #       The scoping narrowed the anchor to .md/.html; it did not delete
    #       it. Without this direction the leg would pass just as well if the
    #       guard had been removed outright, which would re-point true
    #       historical headings at the canonical — the record-destroying
    #       failure the guard exists to prevent.
    #
    # Fixture SSOT = 3 `KnobSpec` entries; both planted claims say 9.
    rm -f "$tmpdir/docs/CONFIG_SCHEMA.md"
    cat > "$tmpdir/src/security_profile.rs" <<'KNOBSSOT'
const KNOBS: &[KnobSpec] = &[
    KnobSpec {
        env: "A",
    },
    KnobSpec {
        env: "B",
    },
    KnobSpec {
        env: "C",
    },
];
KNOBSSOT
    mkdir -p "$tmpdir/scripts"
    cat > "$tmpdir/scripts/check-bootstrap-cert-gate.sh" <<'KNOBSTALESH'
#!/bin/bash
# Shared certified env for a pg backend. asi-hard auto-pins the 9 knobs in
# the binary's pre-runtime phase.
KNOBSTALESH
    cat > CLAUDE.md <<'KNOBHEADINGMD'
## The 9-knob era — a heading, and a TRUE statement about the past

Fixture CLAUDE.md — deliberately carries no CURRENT narrative counts.
KNOBHEADINGMD
    if knob_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — gate did NOT catch the stale knob count in a SHELL COMMENT (9 vs SSOT 3)" >&2
        printf '%s\n' "$knob_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -qF 'ASI_HARD_PINNED_KNOB_COUNT: scripts/check-bootstrap-cert-gate.sh' <<<"$knob_out" || {
        echo "FAIL: self-test — a shell COMMENT line is still being skipped as a markdown heading (#3113 fail-open)" >&2
        printf '%s\n' "$knob_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    if grep -qF 'ASI_HARD_PINNED_KNOB_COUNT: CLAUDE.md' <<<"$knob_out"; then
        echo "FAIL: self-test — the markdown-heading historical guard was LOST, not scoped (a true past-tense heading was re-pointed)" >&2
        printf '%s\n' "$knob_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #3113 — a stale count in a SHELL COMMENT is REJECTED; the same count in a MARKDOWN HEADING is still spared"

    # ---- ASI-HARD CONTROL: the correct count (matching the fixture SSOT)
    # PASSES, so the leg above proves a real rejection rather than a rule
    # that fires on everything.
    cat > "$tmpdir/scripts/check-bootstrap-cert-gate.sh" <<'KNOBGOODSH'
#!/bin/bash
# Shared certified env for a pg backend. asi-hard auto-pins the 3 knobs in
# the binary's pre-runtime phase.
KNOBGOODSH
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — the asi-hard knob-count rule fired on the CORRECT count (3)" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #3113 — the correct asi-hard knob count still PASSES"
    rm -f "$tmpdir/scripts/check-bootstrap-cert-gate.sh" "$tmpdir/src/security_profile.rs"

    # ================================================================
    # asi-hard KNOBS count + ENTERPRISE_FEDERATION_CHECK_COUNT
    # ================================================================
    # Until this wave neither number had an SSOT rule, and both drifted:
    # five live surfaces said the asi-hard profile pins 17 knobs after
    # #3033 raised `KNOBS` to 21. Fixture SSOTs: 3 knobs / 5 checks, so a
    # planted 4 / 6 must be REJECTED and the true values ACCEPTED.
    mkdir -p "$tmpdir/docs/deploy" "$tmpdir/docs/compliance"
    cat > "$tmpdir/src/security_profile.rs" <<'KNOBSSSOT'
struct KnobSpec {
    env: &'static str,
}
const KNOBS: &[KnobSpec] = &[
    KnobSpec {
        env: "A",
    },
    KnobSpec {
        env: "B",
    },
    KnobSpec {
        env: "C",
    },
];
KNOBSSSOT
    cat > "$tmpdir/src/enterprise_federation_posture.rs" <<'EFSSOT'
pub const ENTERPRISE_FEDERATION_CHECK_COUNT: usize = 5;
EFSSOT
    cat > "$tmpdir/SECURITY.md" <<'KNOBSTALE'
- The pinned SSOT (`src/security_profile.rs::KNOBS`) is **4 knobs** — see the deploy template.
Last updated: 2026-08-21 (`asi-hard` 4-knob hardened profile cross-referenced).
KNOBSTALE
    cat > "$tmpdir/docs/deploy/README.md" <<'KNOBSTALEDEPLOY'
This template layers the config-backed PE-1 knobs and the egress posture on top.
(That list is all **4** `KNOBS` entries.)
KNOBSTALEDEPLOY
    cat > "$tmpdir/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md" <<'EFSTALE'
`run_posture` returns **0 iff all 6 checks pass, else 2**.
> Evidence note: the captures below PREDATE the last two checks and reflect the 4-check posture.
EFSTALE
    if knob_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — gate did NOT catch the stale asi-hard knob / EF check counts" >&2
        printf '%s\n' "$knob_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    for _want in \
        'asi-hard KNOBS count (src/security_profile.rs::KNOBS): SECURITY.md:1 claims "4"' \
        'asi-hard KNOBS count (src/security_profile.rs::KNOBS): SECURITY.md:2 claims "4"' \
        'asi-hard KNOBS count (src/security_profile.rs::KNOBS): docs/deploy/README.md:2 claims "4"' \
        'ENTERPRISE_FEDERATION_CHECK_COUNT: docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:1 claims "6"'
    do
        grep -qF "$_want" <<<"$knob_out" || {
            echo "FAIL: self-test — expected drift not flagged: $_want" >&2
            printf '%s\n' "$knob_out" >&2
            cd "$REPO_ROOT"; exit 1; }
    done
    # The `PE-1 knobs` prose must NOT match: a bare `([0-9]+) knobs`
    # anchor would capture the `1` out of `PE-1` and report phantom drift.
    if grep -qF 'KNOBS): docs/deploy/README.md:1' <<<"$knob_out"; then
        echo "FAIL: self-test — the knob rule falsely matched 'PE-1 knobs' prose" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    # The cert doc's EVIDENCE NOTE (a true record of a past capture) must
    # NOT be re-pointed at the canonical.
    if grep -qF 'ENTERPRISE_FEDERATION_CHECK_COUNT: docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:2' <<<"$knob_out"; then
        echo "FAIL: self-test — the EF check rule falsely flagged a historical evidence note" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test — asi-hard KNOBS + EF check-count rules REJECT stale counts, spare 'PE-1 knobs' and the evidence note"

    # ---- CONTROL: the canonical counts (3 knobs / 5 checks) PASS.
    cat > "$tmpdir/SECURITY.md" <<'KNOBGOOD'
- The pinned SSOT (`src/security_profile.rs::KNOBS`) is **3 knobs** — see the deploy template.
Last updated: 2026-08-21 (`asi-hard` 3-knob hardened profile cross-referenced).
KNOBGOOD
    cat > "$tmpdir/docs/deploy/README.md" <<'KNOBGOODDEPLOY'
This template layers the config-backed PE-1 knobs and the egress posture on top.
(That list is all **3** `KNOBS` entries.)
KNOBGOODDEPLOY
    cat > "$tmpdir/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md" <<'EFGOOD'
`run_posture` returns **0 iff all 5 checks pass, else 2**.
EFGOOD
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — the knob / EF check rules fired on the CANONICAL counts" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test — the canonical asi-hard knob (3) + EF check (5) counts PASS"

    # ---- FAIL-CLOSED-ONLY-WITH-A-CLAIM: remove both SSOTs. A doc that
    # narrates NO count has nothing to validate and must stay green;
    # a doc that DOES narrate one must fail rather than silently pass.
    rm -f "$tmpdir/src/security_profile.rs" "$tmpdir/src/enterprise_federation_posture.rs"
    rm -f "$tmpdir/SECURITY.md" "$tmpdir/docs/deploy/README.md"
    rm -f "$tmpdir/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test — an ABSENT knob/EF SSOT with no claim to validate did not stay green" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    cat > "$tmpdir/SECURITY.md" <<'KNOBORPHAN'
- The pinned SSOT (`src/security_profile.rs::KNOBS`) is **3 knobs** — see the deploy template.
KNOBORPHAN
    if orphan_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test — a knob claim with an UNRESOLVABLE SSOT passed silently (fail-open)" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -qF '<unresolved>' <<<"$orphan_out" || {
        echo "FAIL: self-test — the unresolved-SSOT failure did not name the unresolved canonical" >&2
        printf '%s\n' "$orphan_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    rm -f "$tmpdir/SECURITY.md"
    echo "PASS: self-test — an unresolvable knob SSOT FAILS CLOSED only when a doc actually narrates the count"

    # ================================================================
    # #2977 — THE GITHUB-PAGES (.html) SURFACE
    # ================================================================
    # Before #2977 the html scan set was ONE file, so ~70 hand-authored
    # Jekyll pages were ungated and drifted invisibly through the whole
    # v1.0.0 campaign. These legs pin the three properties the widening
    # rests on: the html dialect is really READ (RED), a corrected page
    # really PASSES (GREEN), and the two historical guards that make the
    # widening survivable are load-bearing rather than decorative.
    #
    # Fixture canonicals: schema 53 · routes 87 · paths 73 · tools 12 ·
    #                     cli 78 default / 80 sal · fields 26 · hooks 25 ·
    #                     release 9.9.9
    rm -f "$led" "$tmpdir/docs/CONFIG_SCHEMA.md" "$tmpdir/docs/compliance/nsa-csi-mcp.html"
    cat > CLAUDE.md <<'HTML2977CLAUDE'
Fixture CLAUDE.md — deliberately carries no narrative counts.
HTML2977CLAUDE
    cat > README.md <<'HTML2977README'
Fixture README — deliberately carries no narrative counts.
HTML2977README

    # ---- RED: the html markup dialect is really read. Every claim below
    # is the html twin of a shape the .md scanner already catches, and NOT
    # ONE of them matches a markdown-only anchor.
    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLSTALECLAIMS'
<p>Surface: schema <strong>v78</strong>, <strong>101</strong> MCP tools at <code>--profile full</code>.</p>
<p><strong>92</strong> HTTP route registrations over <strong>78</strong> unique URL paths.</p>
<p>The record is a <strong>28-field</strong> <code>Memory</code>.</p>
<p>The CLI ships <strong>89</strong> subcommands under <code>--features sal</code>.</p>
HTMLSTALECLAIMS
    if html_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test #2977 — the widened gate ACCEPTED html-dialect stale SSOT claims" >&2
        printf '%s\n' "$html_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    html_missing=0
    for shape in \
        "CURRENT_SCHEMA_VERSION: docs/at-a-glance.html:1 claims \"78\"" \
        "Profile::full().expected_tool_count(): docs/at-a-glance.html:1 claims \"101\"" \
        "EXPECTED_PRODUCTION_ROUTES_COUNT: docs/at-a-glance.html:2 claims \"92\"" \
        "EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT: docs/at-a-glance.html:2 claims \"78\"" \
        "Memory::FIELD_COUNT: docs/at-a-glance.html:3 claims \"28\"" \
        "EXPECTED_CLI_SUBCOMMANDS_SAL: docs/at-a-glance.html:4 claims \"89\"" \
    ; do
        if ! grep -qF "$shape" <<<"$html_out"; then
            echo "FAIL: self-test #2977 — widened gate did not flag: $shape" >&2
            html_missing=1
        fi
    done
    if [[ "$html_missing" -ne 0 ]]; then
        printf '%s\n' "$html_out" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 RED — six html-dialect SSOT claims (<strong>/<code> spans) are REJECTED on an enroll-by-default page"

    # ---- GREEN-on-fixed: the SAME page with the fixture canonicals.
    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLGOODCLAIMS'
<p>Surface: schema <strong>v53</strong>, <strong>12</strong> MCP tools at <code>--profile full</code>.</p>
<p><strong>87</strong> HTTP route registrations over <strong>73</strong> unique URL paths.</p>
<p>The record is a <strong>26-field</strong> <code>Memory</code>.</p>
<p>The CLI ships <strong>80</strong> subcommands under <code>--features sal</code>.</p>
HTMLGOODCLAIMS
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test #2977 GREEN — the CORRECTED html page was still rejected" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 GREEN — the same html page carrying the canonical values PASSES"

    # ---- HISTORICAL GUARD 1: TAG-STRIPPING. The verbatim
    # docs/agent-identity.html shape. `schema <strong>v67</strong> added`
    # is a TRUE ladder statement; without the tag-stripped view the guard
    # never sees the `vNN added` phrase and the gate reports history as
    # drift. This is the ONE hit the widened scan produced at 57b7fe35.
    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLLADDER'
<p>Backing this, schema <strong>v67</strong> added the <code>target_agent_id_idx</code> column.</p>
HTMLLADDER
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test #2977 — the html guard fired on a LEGITIMATE tag-split ladder mention" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 — a tag-split 'schema <strong>vNN</strong> added' ladder mention still PASSES"

    # ---- HISTORICAL GUARD 2: THE PRECEDING-LINE WINDOW. An html release
    # CARD puts its attribution in the two divs ABOVE the numbers, so
    # nothing on the number-bearing line says which release it describes.
    # BOTH directions are asserted, because a window guard that fired
    # unconditionally would be indistinguishable from not scanning at all.
    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLCARD'
<div class="card-eyebrow">&#9656; PRIOR RELEASE</div>
<div class="card-title">What's New in v0.7.0 — attested-cortex</div>
<p class="card-body"><strong>74</strong> MCP tools at <code>--profile full</code>, 27-event hook pipeline.</p>
HTMLCARD
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test #2977 — the window guard did NOT spare an html PRIOR-RELEASE card" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 — an html release CARD (eyebrow + title in the divs above) is spared"

    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLCARDLESS'
<p class="card-body"><strong>74</strong> MCP tools at <code>--profile full</code>, 27-event hook pipeline.</p>
HTMLCARDLESS
    if card_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test #2977 — the SAME numbers WITHOUT the release-card markers were accepted." >&2
        echo "       The window guard would then be a blanket exemption, not a guard." >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -qF 'Profile::full().expected_tool_count(): docs/at-a-glance.html:1 claims "74"' <<<"$card_out" || {
        echo "FAIL: self-test #2977 — card-less stale tool count not flagged" >&2
        printf '%s\n' "$card_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -qF 'HookEvent variants: docs/at-a-glance.html:1 claims "27"' <<<"$card_out" || {
        echo "FAIL: self-test #2977 — card-less stale hook count not flagged (the widened HookEvent scan set)" >&2
        printf '%s\n' "$card_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test #2977 — the SAME numbers with the card markers REMOVED are REJECTED (the window is a guard, not a blanket)"

    # ---- FROZEN EXEMPTION, both directions. A page named in
    # scripts/qc-allowlists/html-doc-frozen-exempt.txt carries the very
    # same stale claims and must PASS: "what's new in vN" is, by
    # construction, a statement about vN.
    rm -f "$tmpdir/docs/at-a-glance.html"
    cat > "$tmpdir/docs/whats-new-v09.html" <<'HTMLFROZEN'
<p>Surface: schema <strong>v78</strong>, <strong>101</strong> MCP tools at <code>--profile full</code>.</p>
HTMLFROZEN
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test #2977 — a FROZEN page (html-doc-frozen-exempt.txt) was scanned" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 — a page named in html-doc-frozen-exempt.txt is EXEMPT (the same claims pass there)"
    rm -f "$tmpdir/docs/whats-new-v09.html"

    # ---- THE EXEMPTION SSOT IS REQUIRED. A gate that silently resolves
    # its scan set without the frozen boundary either reds every frozen
    # page or drops the widening; refuse instead. Asserted here rather
    # than waived under --self-test, because a check the self-test cannot
    # reach is a check nobody has proven.
    mv "$tmpdir/scripts/qc-allowlists/html-doc-frozen-exempt.txt" "$tmpdir/exempt.bak"
    if ex_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test #2977 — a MISSING frozen-exemption SSOT did not fail the gate" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -q 'html-doc-frozen-exempt.txt' <<<"$ex_out" || {
        echo "FAIL: self-test #2977 — the missing-SSOT failure did not name the file" >&2
        cd "$REPO_ROOT"; exit 1; }
    mv "$tmpdir/exempt.bak" "$tmpdir/scripts/qc-allowlists/html-doc-frozen-exempt.txt"
    echo "PASS: self-test #2977 — a missing frozen-exemption SSOT FAILS CLOSED"

    # ---- SITEWIDE CHROME VERSION STAMP. The campaign found v0.9.0 chrome
    # on 38 pages while every gate stayed green. Fixture release: 9.9.9.
    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLSTAMPBAD'
<span class="badge">v0.9.0 &middot; Apache-2.0</span>
<p>ai-memory v0.7.0 shipped the attested cortex.</p>
<footer>
  <p>© 2026 AlphaOne LLC. Licensed Apache-2.0. ai-memory v0.9.0 — source on GitHub</p>
</footer>
HTMLSTAMPBAD
    if stamp_out=$(AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1); then
        echo "FAIL: self-test #2977 — a stale sitewide chrome version stamp was ACCEPTED" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    grep -qF 'HTML_CHROME_VERSION_STAMP (footer): docs/at-a-glance.html:4 claims "v0.9.0"' <<<"$stamp_out" || {
        echo "FAIL: self-test #2977 — the stale FOOTER chrome stamp was not flagged" >&2
        printf '%s\n' "$stamp_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    grep -qF 'HTML_CHROME_VERSION_STAMP (badge): docs/at-a-glance.html:1 claims "v0.9.0"' <<<"$stamp_out" || {
        echo "FAIL: self-test #2977 — the stale hero/nav BADGE chrome stamp was not flagged" >&2
        printf '%s\n' "$stamp_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    # ...and the PROSE mention OUTSIDE the footer must NOT be flagged: a
    # page saying what v0.7.0 shipped is history, not chrome.
    grep -qF 'docs/at-a-glance.html:2' <<<"$stamp_out" && {
        echo "FAIL: self-test #2977 — the chrome rule fired on PROSE outside the footer" >&2
        printf '%s\n' "$stamp_out" >&2
        cd "$REPO_ROOT"; exit 1; }
    echo "PASS: self-test #2977 — stale FOOTER + BADGE chrome stamps are REJECTED, body prose is spared"

    # ---- GREEN-on-fixed + the PUBLISHED-INSTALL carve-out. The v1.0.0
    # tag-cut is operator-gated, so an install/download line pinned at the
    # last PUBLISHED tag is CORRECT; flagging it would push a doc author
    # to publish an install command for a tag that does not exist.
    cat > "$tmpdir/docs/at-a-glance.html" <<'HTMLSTAMPGOOD'
<span class="badge">v9.9.9 &middot; Apache-2.0</span>
<footer>
  <p>© 2026 AlphaOne LLC. Licensed Apache-2.0. ai-memory v9.9.9 — source on GitHub</p>
  <p>Install the published build: <code>cargo install ai-memory v0.9.0</code></p>
</footer>
HTMLSTAMPGOOD
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test #2977 GREEN — a current chrome stamp + a published-install reference were rejected" >&2
        AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" 2>&1 >/dev/null | sed 's/^/       /' >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 GREEN — a current chrome stamp PASSES and a published-install reference is SKIPPED"

    # ---- and a FROZEN page keeps its own historical chrome stamp.
    rm -f "$tmpdir/docs/at-a-glance.html"
    cat > "$tmpdir/docs/whats-new-v09.html" <<'HTMLSTAMPFROZEN'
<footer><p>ai-memory v0.9.0 — what shipped in v0.9.0</p></footer>
HTMLSTAMPFROZEN
    if ! AI_MEMORY_DOCS_GATE_ROOT="$tmpdir" "$REPO_ROOT/scripts/check-docs-vs-ssot.sh" >/dev/null 2>&1; then
        echo "FAIL: self-test #2977 — the chrome rule fired on a FROZEN per-release page" >&2
        cd "$REPO_ROOT"; exit 1
    fi
    echo "PASS: self-test #2977 — a frozen per-release page keeps its own historical chrome stamp"

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
