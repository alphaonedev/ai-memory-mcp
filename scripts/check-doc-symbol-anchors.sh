#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-doc-symbol-anchors.sh
#
# v1.0.0 CERT GATE 2 — DOC SYMBOL/PATH ANCHOR RESOLUTION gate (#2629;
# 3x7 claims register, `docs/audit/3x7-claims-register-2026-08-01.md`).
#
# THE DEFECT THIS CLOSES. `scripts/check-docs-vs-ssot.sh` pins VALUES
# (counts, versions) and nothing pins SYMBOLS. Documents cite
# `file:line` anchors, `path.rs::symbol` qualifications, and
# `[`sym`](../src/path.rs)` links that rot silently the moment a
# function is renamed or a module is split. The audit sampled SIX
# anchors and found 6/6 MISS at HEAD, including `decorate_memory` —
# a symbol that has not existed since it became
# `decorate_memory_many` (`src/mcp/tools/recall.rs:610`). The register's
# verdict is unambiguous: "Anchors that miss 6/6 are worse than no
# anchors — they cost the reviewer trust they cannot get back."
#
# The class is worse than value drift because a wrong VALUE is
# falsifiable by a reader in one grep, while a wrong ANCHOR sends the
# reader to the wrong place and then makes them doubt the rest.
#
# SIX RULES, all conservative, all keyed on PATH-QUALIFIED grammar so
# a bare backticked identifier in prose is never guessed at:
#
#   PATH   — a cited `src/<path>.rs` must EXIST. This is what caught the
#            pre-modularisation `src/handlers.rs` / `src/mcp.rs` /
#            `src/db.rs` anchors still live in the operator guides.
#   LINE   — a cited `src/<path>.rs:<N>` must name a line the file
#            actually has: 1 <= N <= the file's line count (#4700; line
#            0 never lands on code). Cheap, dependency-free, and it catches the
#            whole truncated-anchor class without needing to know what
#            is ON that line.
#            The range separator may be `-`, `--`, an en dash, an em dash or
#            the minus sign U+2212, with optional spaces around it
#            (#5188, #5267, #5345). A `[label](src/x.rs#L<a>-L<b>)` fragment of a
#            RELATIVE link is range-checked the same way (#5189).
#   QUAL   — every identifier in `src/<path>.rs::<sym>` and
#            `src/<path>.rs::{a, B::c, d}` must be DEFINED IN THAT FILE.
#            Each `::`-separated component is checked, so
#            `VectorIndex::build_with_capacity` resolves only if both
#            the type and the method are in that file. The UNBACKTICKED
#            form is checked too (reported as BARE_QUAL, #5191), and a
#            qualified anchor never gets the absent-path exemption: it
#            asserts the file exists (#5201).
#   BARE_LN — (#4651) a BARE `src/<path>.rs:<N>` (no backtick: prose, a
#            link label, HTML text) is a finding unless it labels a
#            commit-pinned permalink (`/blob/<hex sha>/`, immutable).
#            Burn-down class: a finding FAILS, like a stale entry.
#   MDLINK — `[`sym`](../src/path.rs)` must resolve: the file must
#            exist AND `sym` must be defined in it (or BE it — a link
#            whose symbol equals the module's file stem is a module
#            citation, which is legitimate). A relative link to a
#            `src/` file with ANY label must point at an existing file
#            (#5190), as must a link with a title (double-quoted,
#            single-quoted or parenthesised), an angle-bracket
#            destination, a `?query`, a reference definition
#            (`[h]: src/x.rs`, also in a blockquote or list item or
#            with the destination on the next line) and an HTML
#            relative href (any case, spaces around `=`, quoted or
#            not) (#5269, #5343).
#   LADDER_TIP — a claimed end of the migration ladder
#            (`migrate_vNN`) must be the real tip.
#
# PATH FORMS. Before any rule runs, a `src/<path>.rs` token is
# normalised (#4699/#4701): any leading ./ and ../ segments are stripped
# and repeated slashes collapse, so `src/x.rs`, `./src/x.rs`,
# `.//src/x.rs`, `././src/x.rs`, `../src/x.rs` and `src//x.rs` are one
# anchor. A token preceded by a letter, digit, dot or slash has an
# unknown root and is not a `src/` anchor. Dot segments INSIDE the path
# (`src/./mcp/x.rs`, `src/mcp/../mcp/x.rs`) resolve before any rule runs
# (#4714). A token whose `..` segments climb out of `src/` (`src/../x.rs`)
# names no file under `src/`: it is reported as a PATH finding, and a
# qualified or link-target occurrence of it is reported whatever the wording
# nearby (#5346).
#
# THE ABSENT-PATH EXEMPTION. A plain path or `path:line` anchor is not
# reported when absence wording ("no longer exists", "formerly",
# "monolithic", "pre-split", "was split from", "removed in", ...) is on its
# line or the line above or below, because such a line says the file is
# gone. A qualified `path::symbol` anchor and a link target are never
# exempt (#5201, #5250). Wording that names a DESTINATION ("split into",
# "split out", "renamed to", an arrow before a `src/` path) exempts only an
# anchor BEFORE it on the same line (#5264, #5341, #5344).
#
# WHAT IS DELIBERATELY *NOT* A RULE. A bare backticked identifier
# sharing a line with a `src/` path is NOT checked. Measured against
# the tree that grammar produces 1,827 hits over 879 distinct tokens —
# MCP tool names, DB column names, wire strings, enum variants, env
# vars — almost none of which are Rust definitions. A rule with that
# false-positive rate would be turned off within a week, and a gate
# nobody can leave on is worse than no gate.
#
# NO NEW SSOT (operator direction). Where the migration-ladder tip is
# needed, this gate EXTRACTS and reuses `read_current_schema_version`
# from `scripts/check-migration-ladder.sh` rather than re-deriving the
# tip a third time. If that function is ever renamed, this gate fails
# loudly instead of silently computing its own answer.
#
# BURN-DOWN ALLOWLIST: `scripts/qc-allowlists/doc-symbol-anchors-allow.txt`.
# Unlike the three PENDING-FIX ledgers this campaign also ships, a STALE
# ENTRY HERE **FAILS** — the #2494 `required-contexts-joblevel-if-allow.txt`
# discipline — because these anchors are not the subject of a
# concurrent correction lane, so a rotted ledger here has no excuse.
#
# FROZEN DOC TREES ARE OUT OF SCOPE, by the same reasoning that keeps
# CHANGELOG.md out of the docs-vs-SSOT walk: `docs/v0.*/`,
# `docs/internal/`, `docs/audit/`, `docs/rfc/`, `docs/adr*`,
# `docs/BASELINE-*.md` and the frozen `perfect-endpoint-assessment`
# wave artefacts describe a tree AS IT WAS. Re-pointing their anchors
# at HEAD would falsify the record they exist to keep.
#
# CLI:
#   scripts/check-doc-symbol-anchors.sh              — run (exit 0/1)
#   scripts/check-doc-symbol-anchors.sh --self-test  — plant the
#       historical shapes (a `decorate_memory` rename, a
#       pre-modularisation path, an out-of-range line anchor, a stale
#       `migrate_vNN`, bare and unbackticked anchors, the path forms
#       and line ranges of #4699-#4716 and #5188-#5191) in a throwaway copy UNDER `.local-runs/` (never
#       system /tmp, never `mktemp -d`) and prove the gate rejects each,
#       alongside near-miss controls that must PASS.

set -euo pipefail

# --------------------------------------------------------------------
# Self-test (dispatched first so it can drive the real script)
# --------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    FIX="$ROOT/.local-runs/doc-symbol-anchors-selftest-$$"
    rm -rf "$FIX"
    mkdir -p "$FIX/src/mcp/tools" "$FIX/src/store" "$FIX/docs" "$FIX/scripts/qc-allowlists"
    trap 'rm -rf "$FIX"' EXIT

    # The REAL shape of the audit's `decorate_memory` finding: the old
    # name is gone, the new one is a few lines further down the same
    # file, and nothing in the tree notices.
    cat > "$FIX/src/mcp/tools/recall.rs" <<'RSEOF'
pub struct RecallTool;
pub fn decorate_memory_many(rows: &[u8]) -> usize {
    rows.len()
}
RSEOF
    cat > "$FIX/src/store/postgres.rs" <<'RSEOF'
pub const CURRENT_SCHEMA_VERSION: i64 = 88;
pub struct PostgresStore;
fn migrate_v87() {}
fn migrate_v88() {}
RSEOF
    printf 'placeholder\n' > "$FIX/scripts/qc-allowlists/doc-symbol-anchors-allow.txt"
    : > "$FIX/scripts/qc-allowlists/doc-symbol-anchors-allow.txt"

    run_fixture() { ( AI_MEMORY_SYMBOL_GATE_ROOT="$FIX" "$SELF" >/dev/null 2>&1; echo "$?" ); }
    run_fixture_out() { AI_MEMORY_SYMBOL_GATE_ROOT="$FIX" "$SELF" 2>&1 || true; }

    write_clean() {
        : > "$FIX/scripts/qc-allowlists/doc-symbol-anchors-allow.txt"
        # NEAR-MISS CONTROLS, every one must PASS:
        #  * the CORRECT symbol name, path-qualified
        #  * a brace list with a `Type::method` component
        #  * an IN-RANGE line anchor
        #  * a markdown link whose symbol is the MODULE (file stem)
        #  * a line that DELIBERATELY names a path as absent — the
        #    CLAUDE.md worktree pre-flight asserts `test ! -f
        #    src/handlers.rs`, and firing on that would be absurd
        cat > "$FIX/README.md" <<'MDEOF'
See `src/mcp/tools/recall.rs::decorate_memory_many` for the decorator.
Also `src/store/postgres.rs::{PostgresStore, migrate_v87, migrate_v88}`.
The struct is at `src/mcp/tools/recall.rs:1`.
Module doc: [`recall`](src/mcp/tools/recall.rs).
Stale-base pre-flight: `test ! -f src/handlers.rs` — the monolith no longer exists.
MDEOF
    }

    write_clean
    rc="$(run_fixture)"
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: self-test — the CLEAN near-miss control tree was REJECTED (exit $rc)." >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 1
    fi
    echo "PASS: self-test control — correct symbol, brace list with Type::method, in-range line anchor, module link, and a deliberate absent-path assertion all PASS"

    # ---- the audit's own finding: a RENAMED symbol -------------------
    write_clean
    printf '\n\nThe read-side decorator is `src/mcp/tools/recall.rs::decorate_memory`.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — a renamed symbol (decorate_memory -> decorate_memory_many) was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'decorate_memory' || {
        echo "FAIL: self-test — violation did not name the unresolved symbol" >&2; exit 1; }
    echo "PASS: self-test — the audit's own decorate_memory rename is REJECTED"

    # ---- a pre-modularisation PATH still cited as live ---------------
    write_clean
    printf '\n\nHandlers live in `src/handlers.rs` and the MCP loop in `src/mcp.rs`.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — a pre-modularisation path cited as live was ACCEPTED" >&2; exit 1; }
    echo "PASS: self-test — a cited src/ path that no longer exists is REJECTED"

    # ---- an out-of-range file:line anchor ----------------------------
    write_clean
    printf '\n\nSee `src/mcp/tools/recall.rs:9999` for the decorator.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — a file:line anchor past EOF was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'LINE' || {
        echo "FAIL: self-test — out-of-range anchor rejected for the wrong reason" >&2; exit 1; }
    echo "PASS: self-test — a file:line anchor past end-of-file is REJECTED"

    # ---- #4680: a backticked ./src/ anchor is checked like src/ ------
    write_clean
    printf '\n\nSee `./src/mcp/tools/recall.rs:9999` for the decorator.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #4680 — a ./src/ anchor with a stale line was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'LINE' || {
        echo "FAIL: self-test #4680 — a ./src/ stale-line anchor rejected for the wrong reason (no LINE)" >&2; exit 1; }
    echo "PASS: self-test #4680 — a backticked ./src/ anchor with a stale line is REJECTED"
    write_clean
    printf '\n\nHandlers live in `./src/handlers.rs`.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #4680 — a ./src/ anchor to a missing file was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'PATH' || {
        echo "FAIL: self-test #4680 — a ./src/ missing-file anchor rejected for the wrong reason (no PATH)" >&2; exit 1; }
    echo "PASS: self-test #4680 — a backticked ./src/ anchor to a missing file is REJECTED"


    # A well-formed 40-hex commit sha for the pinned-permalink plants.
    pin40="a1403c742f9d590a08b6fd170deec5f50ca8e940"
    # ---- #4699/#4700/#4701: anchor path normalisation + line range ----
    # anchor_red/anchor_green plant ONE line in the clean tree. A red case
    # must be rejected by the named rule; a green control must pass.
    anchor_red() {  # <issue> <rule> <description> <line planted in README.md>
        write_clean
        printf '\n\n%s\n' "$4" >> "$FIX/README.md"
        [[ "$(run_fixture)" != "0" ]] || {
            echo "FAIL: self-test #$1 — $3 was ACCEPTED" >&2; exit 1; }
        run_fixture_out | grep -q "\[$2\]" || {
            echo "FAIL: self-test #$1 — $3 rejected for the wrong reason (no $2)" >&2; exit 1; }
        echo "PASS: self-test #$1 — $3 is REJECTED"
    }
    anchor_green() {  # <issue> <description> <line planted in README.md>
        write_clean
        printf '\n\n%s\n' "$3" >> "$FIX/README.md"
        [[ "$(run_fixture)" = "0" ]] || {
            echo "FAIL: self-test #$1 — $2 was REJECTED" >&2
            run_fixture_out | sed 's/^/       /' >&2; exit 1; }
        echo "PASS: self-test #$1 — $2 is ACCEPTED"
    }

    # #4700: a line number is 1-based; recall.rs has 4 lines.
    anchor_red 4700 LINE "a :0 line anchor" 'See `src/mcp/tools/recall.rs:0`.'
    anchor_red 4700 LINE "a ./ :0 line anchor" 'See `./src/mcp/tools/recall.rs:0`.'
    anchor_red 4700 LINE "a :00 line anchor" 'See `src/mcp/tools/recall.rs:00`.'
    anchor_red 4700 LINE "a line one past the end (:5 of 4)" 'See `src/mcp/tools/recall.rs:5`.'
    anchor_green 4700 "the first line (:1)" 'See `src/mcp/tools/recall.rs:1`.'
    anchor_green 4700 "the last line (:4)" 'See `src/mcp/tools/recall.rs:4`.'

    # #4699: a ./ prefix on a symbol anchor is checked like no prefix.
    anchor_red 4699 QUAL "a ./src/ symbol anchor to a removed symbol" \
        'See `./src/mcp/tools/recall.rs::decorate_memory`.'
    anchor_red 4699 QUAL "a ./src/ brace list with a removed symbol" \
        'See `./src/mcp/tools/recall.rs::{RecallTool, no_such}`.'
    anchor_red 4699 QUAL "a ././src/ symbol anchor to a removed symbol" \
        'See `././src/mcp/tools/recall.rs::no_such`.'
    anchor_green 4699 "a ./src/ symbol anchor to a live symbol" \
        'See `./src/mcp/tools/recall.rs::decorate_memory_many`.'
    anchor_green 4699 "a ./src/ brace list of live symbols" \
        'See `./src/mcp/tools/recall.rs::{RecallTool, decorate_memory_many}`.'


    # #4701: repeated slashes and stacked ./ segments normalise to one form.
    anchor_red 4701 LINE "a .//src/ stale line anchor" 'See `.//src/mcp/tools/recall.rs:9999`.'
    anchor_red 4701 LINE "a ././src/ stale line anchor" 'See `././src/mcp/tools/recall.rs:9999`.'
    anchor_red 4701 LINE "a ./../src/ stale line anchor" 'See `./../src/mcp/tools/recall.rs:9999`.'
    anchor_red 4701 LINE "a src//mcp//tools stale line anchor" 'See `src//mcp//tools/recall.rs:9999`.'
    anchor_red 4701 LINE "a .//src//mcp stale :00 anchor" 'See `.//src//mcp/tools/recall.rs:00`.'
    anchor_red 4701 QUAL "a src//mcp symbol anchor to a removed symbol" 'See `src//mcp/tools/recall.rs::no_such`.'
    anchor_red 4701 PATH "a .//src/ anchor to a missing file" 'See `.//src/handlers.rs`.'
    anchor_red 4701 BARE_LN "a bare .//src/ line anchor" 'See .//src/mcp/tools/recall.rs:2 here.'
    anchor_green 4701 "a .//src/ in-range line anchor" 'See `.//src/mcp/tools/recall.rs:1`.'
    anchor_green 4701 "a src//mcp in-range line anchor" 'See `src//mcp/tools/recall.rs:2`.'
    anchor_green 4701 "an unknown-root foo./src/ anchor (not a src/ anchor)" 'See `foo./src/mcp/tools/recall.rs:9999`.'
    anchor_green 4701 "an unknown-root x/./src/ anchor (not a src/ anchor)" 'See `x/./src/mcp/tools/recall.rs:9999`.'

    # #4714: . and .. segments INSIDE the path resolve before any rule.
    anchor_red 4714 LINE "a src/./mcp stale line anchor" 'See `src/./mcp/tools/recall.rs:9999`.'
    anchor_red 4714 LINE "a src/mcp/../mcp stale line anchor" 'See `src/mcp/../mcp/tools/recall.rs:9999`.'
    anchor_red 4714 QUAL "a src/./mcp symbol anchor to a removed symbol" 'See `src/./mcp/tools/recall.rs::no_such`.'
    anchor_red 4714 PATH "a src/./ anchor to a missing file" 'See `src/./handlers.rs`.'
    anchor_red 4714 PATH "a src/../ anchor that leaves src/" 'See `src/../nope.rs:5`.'
    anchor_red 4714 BARE_LN "a bare src/./mcp line anchor" 'See src/./mcp/tools/recall.rs:2 here.'
    anchor_green 4714 "a src/mcp/../mcp in-range line anchor" 'See `src/mcp/../mcp/tools/recall.rs:4`.'
    anchor_green 4714 "a src/./mcp live symbol anchor" 'See `src/./mcp/tools/recall.rs::RecallTool`.'

    # #4716: both ends of a backticked :a-b range are range-checked.
    anchor_red 4716 LINE "a range whose end passes end-of-file (:2-9999)" 'See `src/mcp/tools/recall.rs:2-9999`.'
    anchor_red 4716 LINE "a reversed range (:3-2)" 'See `src/mcp/tools/recall.rs:3-2`.'
    anchor_red 4716 LINE "a range that starts at 0 (:0-2)" 'See `src/mcp/tools/recall.rs:0-2`.'
    anchor_green 4716 "a full-file range (:1-4)" 'See `src/mcp/tools/recall.rs:1-4`.'
    anchor_green 4716 "a one-line range (:4-4)" 'See `src/mcp/tools/recall.rs:4-4`.'

    # #5188: an en dash or em dash range separator is a range too.
    anchor_red 5188 LINE "an en-dash range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2–9999`.'
    anchor_red 5188 LINE "an em-dash range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2—9999`.'
    anchor_red 5188 LINE "a reversed en-dash range (:3-2)" 'See `src/mcp/tools/recall.rs:3–2`.'
    anchor_green 5188 "a valid en-dash range (:2-4)" 'See `src/mcp/tools/recall.rs:2–4`.'
    # #5267: whitespace around the dash does not hide a range.
    anchor_red 5267 LINE "a spaced hyphen range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2 - 9999`.'
    anchor_red 5267 LINE "a spaced en-dash range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2 – 9999`.'
    anchor_red 5267 LINE "a spaced em-dash range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2 — 9999`.'
    anchor_green 5267 "a valid spaced range (:2 - 4)" 'See `src/mcp/tools/recall.rs:2 - 4`.'
    # #5350: a run of spaces or a tab around the dash is still a range.
    anchor_red 5350 LINE "a range with two spaces around the dash" 'See `src/mcp/tools/recall.rs:2  -  9999`.'
    anchor_red 5350 LINE "a range with a tab around the dash" $'See `src/mcp/tools/recall.rs:2\t-\t9999`.'
    anchor_red 5350 LINE "a range with spaces only before the dash" 'See `src/mcp/tools/recall.rs:2 -9999`.'
    anchor_red 5350 LINE "a range with spaces only after the dash" 'See `src/mcp/tools/recall.rs:2- 9999`.'
    anchor_green 5267 "a closed code span followed by a spaced dash and a number" 'See `src/mcp/tools/recall.rs:2` - 9999 other things.'
    # #5345: a doubled hyphen and the minus sign (U+2212) are range separators.
    anchor_red 5345 LINE "a doubled-hyphen range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2--9999`.'
    anchor_red 5345 LINE "a spaced doubled-hyphen range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2 -- 9999`.'
    anchor_red 5345 LINE "a minus-sign range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2−9999`.'
    anchor_red 5345 LINE "a spaced minus-sign range whose end passes end-of-file" 'See `src/mcp/tools/recall.rs:2 − 9999`.'
    anchor_red 5345 LINE "a reversed doubled-hyphen range (:3--2)" 'See `src/mcp/tools/recall.rs:3--2`.'
    anchor_green 5345 "a valid doubled-hyphen range (:2--4)" 'See `src/mcp/tools/recall.rs:2--4`.'
    anchor_green 5345 "a valid minus-sign range (:2−4)" 'See `src/mcp/tools/recall.rs:2−4`.'

    # #5194: a src token preceded by a dot is left alone (its root is
    # unknown); the CANON lookbehind must keep the dot.
    anchor_green 5194 "an ellipsis-prefixed escape token (.../src/../x.rs)" \
        'See `.../src/../nope.rs:5`.'
    anchor_green 5194 "a dot-suffixed word before an escape token (x../src/../x.rs)" \
        'See `x../src/../nope.rs`.'

    # #5191: an UNBACKTICKED path::symbol anchor is a symbol claim too.
    anchor_red 5191 BARE_QUAL "an unbackticked anchor to a removed symbol" \
        'See (src/mcp/tools/recall.rs::no_such) here.'
    anchor_red 5191 BARE_QUAL "an unbackticked anchor in a code-block comment to a removed symbol" \
        '# store URL from the env (src/mcp/tools/recall.rs::no_such); do not'
    anchor_red 5191 PATH "an unbackticked anchor to a missing file" \
        'See (src/nope.rs::resolve_store_url, #4577) here.'
    anchor_red 5191 BARE_QUAL "an unbackticked brace list with a removed symbol" \
        'See src/mcp/tools/recall.rs::{RecallTool, no_such}.'
    anchor_green 5191 "an unbackticked anchor to a live symbol" \
        'See (src/mcp/tools/recall.rs::decorate_memory_many) here.'
    anchor_green 5191 "a dot-prefixed token has an unknown root (v1.src/x.rs::f)" \
        'See v1.src/nope.rs::no_such here.'
    anchor_green 5191 "a letter-prefixed token has an unknown root (xsrc/x.rs::f)" \
        'See xsrc/nope.rs::no_such here.'
    # #5255: generic arguments do not hide the method component.
    anchor_red 5255 QUAL "a backticked Type<T>::method anchor to a removed method" \
        'See `src/mcp/tools/recall.rs::RecallTool<T>::no_such`.'
    anchor_red 5255 BARE_QUAL "an unbackticked Type<T>::method anchor to a removed method" \
        'See src/mcp/tools/recall.rs::RecallTool<T>::no_such here.'
    anchor_red 5255 QUAL "a brace list with a Type<T>::method component to a removed method" \
        'See `src/mcp/tools/recall.rs::{RecallTool<T>::no_such, RecallTool}`.'
    anchor_green 5255 "a Type<T>::method anchor to live components" \
        'See src/mcp/tools/recall.rs::RecallTool<T>::decorate_memory_many here.'
    anchor_green 5255 "a bare anchor followed by a closing code tag" \
        'See <code>src/mcp/tools/recall.rs::RecallTool</code> here.'
    anchor_green 5191 "an unbackticked URL path segment is not an anchor" \
        'See https://example.com/x/src/mcp/tools/recall.rs::no_such for it.'
    # #5342: a generic group with commas, spaces, quotes or parentheses is
    # still ONE balanced group; the type and the method are both checked.
    R=src/mcp/tools/recall.rs
    anchor_red 5342 QUAL "a missing type with two generic arguments" \
        "See \`$R::NoSuch<T, U>\` here."
    anchor_red 5342 BARE_QUAL "an unbackticked missing type with two generic arguments" \
        "See $R::NoSuch<T, U> here."
    anchor_red 5342 QUAL "a missing type with two generic arguments, no space" \
        "See \`$R::NoSuch<T,U>\` here."
    anchor_red 5342 QUAL "a removed method after a lifetime and a type argument" \
        "See \`$R::RecallTool<'a, T>::no_such\`."
    anchor_red 5342 QUAL "a removed method after a lifetime argument" \
        "See \`$R::RecallTool<'a>::no_such\`."
    anchor_red 5342 QUAL "a removed method after a reference argument" \
        "See \`$R::RecallTool<&str>::no_such\`."
    anchor_red 5342 QUAL "a removed method after a dyn Fn argument" \
        "See \`$R::RecallTool<dyn Fn(u8)>::no_such\`."
    anchor_red 5342 BARE_QUAL "an unbackticked removed method after two generic arguments" \
        "See $R::RecallTool<T, U>::no_such here."
    anchor_red 5342 QUAL "a missing leading type of a <Type as Trait> path" \
        "See \`$R::<NoSuch as Trait>::decorate_memory_many\`."
    anchor_red 5342 QUAL "a removed method of a <Type as Trait> path" \
        "See \`$R::<RecallTool as Trait>::no_such\`."
    anchor_red 5342 QUAL "a removed method after HTML-entity generics" \
        "See \`$R::RecallTool&lt;T&gt;::no_such\`."
    anchor_red 5342 QUAL "a brace item with a two-argument generic and a removed method" \
        "See \`$R::{RecallTool<T, U>::no_such, RecallTool}\`."
    anchor_red 5342 QUAL "an unbalanced generic group on a missing type" \
        "See \`$R::NoSuch<T\`."
    anchor_green 5342 "a live method after a two-argument generic" \
        "See \`$R::RecallTool<T, U>::decorate_memory_many\`."
    anchor_green 5342 "a live method after a lifetime and a type argument" \
        "See \`$R::RecallTool<'a, T>::decorate_memory_many\`."
    anchor_green 5342 "a live method after a dyn Fn argument" \
        "See \`$R::RecallTool<dyn Fn(u8)>::decorate_memory_many\`."
    anchor_green 5342 "a live type with two generic arguments" \
        "See \`$R::RecallTool<T, U>\` for it."
    anchor_green 5342 "a live <Type as Trait> path" \
        "See \`$R::<RecallTool as Trait>::decorate_memory_many\`."
    anchor_green 5342 "a live method after HTML-entity generics" \
        "See \`$R::RecallTool&lt;T&gt;::decorate_memory_many\`."
    anchor_green 5342 "a brace list of live items, one with two generic arguments" \
        "See \`$R::{RecallTool<T, U>, decorate_memory_many}\`."
    anchor_green 5342 "a live symbol followed by a parenthesised aside" \
        "See $R::RecallTool (a unit struct) here."
    # #5347: the generic strip runs to a fixed point (a nested group needs
    # more than one pass) and a single-argument group on a MISSING type still
    # reports the type.
    anchor_red 5347 QUAL "a missing type with a one-argument generic before a live method" \
        "See \`$R::NoSuch<T>::decorate_memory_many\` here."
    anchor_red 5347 QUAL "a missing type with a nested generic before a live method" \
        "See \`$R::NoSuch<Vec<T>>::decorate_memory_many\` here."
    anchor_green 5347 "a live type with a nested generic before a live method" \
        "See \`$R::RecallTool<Vec<T>>::decorate_memory_many\` here."
    anchor_green 5347 "a live type with a doubly nested generic before a live method" \
        "See \`$R::RecallTool<Vec<Option<T>>>::decorate_memory_many\` here."

    # #5392: the generic group is a real balanced scan, so a group nested to
    # ANY depth still lets every later path component be checked. Each red
    # case has a missing component AFTER a nested group (a one-level capture
    # ends at the bare identifier and never sees it); the greens beside them
    # keep the live shapes from passing vacuously.
    anchor_red 5392 QUAL "a missing method after a three-deep generic" \
        "See \`$R::RecallTool<Vec<Option<T>>>::no_such\`."
    anchor_red 5392 BARE_QUAL "an unbackticked missing method after HashMap<String, Vec<u8>>" \
        "See $R::RecallTool<HashMap<String, Vec<u8>>>::no_such here."
    anchor_red 5392 QUAL "a missing method after a two-deep generic" \
        "See \`$R::RecallTool<Vec<T>>::no_such\`."
    anchor_red 5392 QUAL "a missing type behind a five-deep generic" \
        "See \`$R::NoSuch<A<B<C<D<E>>>>>::decorate_memory_many\`."
    anchor_red 5392 QUAL "a missing method after a five-deep generic" \
        "See \`$R::RecallTool<A<B<C<D<E>>>>>::no_such\`."
    anchor_red 5392 QUAL "a brace item with a three-deep generic and a missing method" \
        "See \`$R::{RecallTool<Vec<Option<T>>>::no_such, RecallTool}\`."
    anchor_red 5392 QUAL "a missing method after a generic holding a fn arrow" \
        "See \`$R::RecallTool<dyn Fn(u8) -> Vec<u8>>::no_such\`."
    anchor_red 5392 QUAL "a missing method after a turbofish group" \
        "See \`$R::RecallTool::<Vec<T>>::no_such\`."
    anchor_red 5392 QUAL "a missing method of a nested <Type<T> as Trait> path" \
        "See \`$R::<RecallTool<Vec<T>> as Trait>::no_such\`."
    anchor_red 5392 QUAL "a missing type of a nested <Type<T> as Trait> path" \
        "See \`$R::<NoSuch<Vec<T>> as Trait>::decorate_memory_many\`."
    anchor_green 5392 "a live method after a five-deep generic" \
        "See \`$R::RecallTool<A<B<C<D<E>>>>>::decorate_memory_many\`."
    anchor_green 5392 "a live method after a generic holding a fn arrow" \
        "See \`$R::RecallTool<dyn Fn(u8) -> Vec<u8>>::decorate_memory_many\`."
    anchor_green 5392 "a live method after a turbofish group" \
        "See \`$R::RecallTool::<Vec<T>>::decorate_memory_many\`."
    anchor_red 5392 QUAL "a missing type whose <Type<A as B>> argument holds an as" \
        "See \`$R::<NoSuch<A as B>>::decorate_memory_many\`."
    anchor_green 5392 "a live nested <Type<T> as Trait> path" \
        "See \`$R::<RecallTool<Vec<T>> as Trait>::decorate_memory_many\`."
    anchor_green 5392 "an unbackticked three-deep generic with live parts, then prose" \
        "See $R::RecallTool<Vec<Option<T>>>::decorate_memory_many, and more."

    # #5394: the HTML-entity spelling nests the same way, and mixes with real
    # angle brackets; a valid anchor is never a false red.
    anchor_green 5394 "a live method after doubly nested HTML-entity generics" \
        "See \`$R::RecallTool&lt;Vec&lt;T&gt;&gt;::decorate_memory_many\`."
    anchor_green 5394 "a live method after three-deep HTML-entity generics" \
        "See \`$R::RecallTool&lt;Vec&lt;Option&lt;T&gt;&gt;&gt;::decorate_memory_many\`."
    anchor_green 5394 "a live method after mixed entity and angle generics" \
        "See \`$R::RecallTool&lt;Vec<T>&gt;::decorate_memory_many\`."
    anchor_red 5394 QUAL "a missing method after doubly nested HTML-entity generics" \
        "See \`$R::RecallTool&lt;Vec&lt;T&gt;&gt;::no_such\`."
    anchor_red 5394 QUAL "a missing method after mixed entity and angle generics" \
        "See \`$R::RecallTool&lt;Vec<T>&gt;::no_such\`."
    anchor_green 5394 "a live method after HTML-entity generics with comma-space arguments" \
        "See \`$R::RecallTool&lt;T, U&gt;::decorate_memory_many\`."
    anchor_green 5394 "an unbackticked HTML-entity generic with live parts, then prose" \
        "See $R::RecallTool&lt;T, U&gt;::decorate_memory_many and more."

    # #5393: a generic group that never balances captures to the end of its
    # token and is REPORTED (it used to fall off the capture, skipping every
    # component behind it). Every component below is live, so only the
    # unbalanced-group rule can make these red.
    anchor_red 5393 QUAL "an unbalanced generic group before a live method" \
        "See \`$R::RecallTool<T::decorate_memory_many\`."
    anchor_red 5393 BARE_QUAL "an unbackticked unbalanced generic group before a live method" \
        "See $R::RecallTool<T::decorate_memory_many here."
    anchor_red 5393 QUAL "an unbalanced outer group around a balanced inner group" \
        "See \`$R::RecallTool<Vec<T>::decorate_memory_many\`."
    anchor_red 5393 QUAL "an unbalanced HTML-entity generic group" \
        "See \`$R::RecallTool&lt;T::decorate_memory_many\`."
    anchor_red 5393 QUAL "an unbalanced leading <Type as Trait> group" \
        "See \`$R::<RecallTool as Trait::decorate_memory_many\`."
    anchor_red 5393 QUAL "an unbalanced turbofish group" \
        "See \`$R::RecallTool::<T::decorate_memory_many\`."
    anchor_red 5393 QUAL "a lone trailing angle bracket after a live type" \
        "See \`$R::RecallTool<\`."
    anchor_red 5393 QUAL "a brace item with an unbalanced generic group" \
        "See \`$R::{RecallTool<T, decorate_memory_many}\`."
    anchor_red 5393 QUAL "an unbalanced group after a balanced one on a live method" \
        "See \`$R::RecallTool<T>::decorate_memory_many<U\`."
    anchor_green 5393 "a balanced group before a live method" \
        "See \`$R::RecallTool<T>::decorate_memory_many\`."
    anchor_green 5393 "a placeholder group with no path behind it is not a symbol claim" \
        "See \`$R::<name>\`."
    anchor_green 5393 "a live symbol followed by an unrelated less-than in prose" \
        "See \`$R::RecallTool\` when a < b holds."

    # #5396: CommonMark lets whitespace, a tab or one line ending sit between
    # `](` and the destination (and whitespace before `)`), and the destination
    # may be angle-bracketed. A link with any of these is still a link: a
    # missing file is reported, and an escape-token target (src/../x.rs) keeps
    # NO absence exemption.
    anchor_red 5396 PATH "a link with one space after the opening parenthesis" \
        'See [h]( src/gone.rs) held it.'
    anchor_red 5396 PATH "a link with spaces on both sides of the destination" \
        'See [h](  src/gone.rs  ) held it.'
    anchor_red 5396 PATH "a link with an angle destination and spaces around it" \
        'See [h]( <src/gone.rs> ) x'
    anchor_red 5396 PATH "an escape-token link target on a formerly line, space after the parenthesis" \
        'Formerly [h]( src/../gone.rs) held it.'
    anchor_red 5396 PATH "a link whose destination is on the next line" \
        $'See [the handler](\nsrc/gone.rs) for it.'
    anchor_red 5396 PATH "a link with a tab after the opening parenthesis" \
        $'See [h](\tsrc/gone.rs) x'
    anchor_red 5396 PATH "a link with an angle destination and a title, spaces around" \
        'See [h]( <src/gone.rs> "the file" ) x'
    anchor_red 5396 PATH "a backticked-label link with a space after the opening parenthesis" \
        'See [`gone`]( src/gone.rs) x'
    anchor_red 5396 PATH "an escape-token link target on the next line" \
        $'Formerly [h](\nsrc/../gone.rs) x'
    anchor_red 5396 PATH "an escape-token reference definition target on the next line" \
        $'Formerly it lived here.\n[h]:\nsrc/../gone.rs'
    anchor_red 5396 PATH "a missing file after a space, behind a live link on the same line" \
        'See [a](src/mcp/tools/recall.rs) and [b]( src/gone.rs) x'
    anchor_red 5396 LINE "a spaced link whose line fragment passes end-of-file" \
        'See [h]( src/mcp/tools/recall.rs#L9999 ) x'
    anchor_green 5396 "a spaced link to a live file" \
        'See [h]( src/mcp/tools/recall.rs ) x'
    anchor_green 5396 "a spaced angle link to a live file with a title" \
        'See [h]( <src/mcp/tools/recall.rs> "title" ) x'
    anchor_green 5396 "a next-line destination that is a live file" \
        $'See [h](\nsrc/mcp/tools/recall.rs) x'
    anchor_green 5396 "a spaced backticked-label link to the module (file stem)" \
        'See [`recall`]( src/mcp/tools/recall.rs) x'
    anchor_green 5396 "an open link whose next line is plain prose" \
        $'See [h](\nthe docs) x'

    # #5397: a brace payload splits at whitespace as well as at commas (outside
    # a generic group), so the SECOND name of a space-separated list is checked.
    anchor_red 5397 QUAL "a space-separated brace list whose second name is missing" \
        "See \`$R::{RecallTool no_such}\`."
    anchor_red 5397 QUAL "a space-separated brace list whose first name is missing" \
        "See \`$R::{no_such RecallTool}\`."
    anchor_red 5397 QUAL "a tab-separated brace list whose second name is missing" \
        $'See `src/mcp/tools/recall.rs::{RecallTool\tno_such}`.'
    anchor_red 5397 QUAL "a comma list with a space-separated pair whose second name is missing" \
        "See \`$R::{RecallTool, decorate_memory_many no_such}\`."
    anchor_green 5397 "a space-separated brace list of live names" \
        "See \`$R::{RecallTool decorate_memory_many}\`."
    anchor_green 5397 "a space-separated brace list of live names, one with a generic group holding a space" \
        "See \`$R::{RecallTool<dyn Fn(u8)> decorate_memory_many}\`."

    # Own probes of the #5392/#5393/#5396 classes (not from the review): a
    # group may not span a code span, a second anchor on a line is checked on
    # its own, and a next-line angle destination may be indented.
    anchor_red 5393 QUAL "an unbalanced group is not balanced by a later bracket in another code span" \
        "See \`$R::RecallTool<T\` and \`Vec>\`."
    anchor_red 5392 BARE_QUAL "a second anchor on a line with a nested generic and a missing method" \
        "See \`$R::RecallTool<Vec<T>>::decorate_memory_many\` and $R::RecallTool<Vec<T>>::no_such here."
    anchor_red 5396 PATH "a next-line angle destination with indentation" \
        $'See [h](\n   <src/gone.rs>) x'

    # Round-6 helper: a red case that also pins the exact text the violation
    # reports (a wrong token named is a wrong report).
    anchor_red_cites() {  # <issue> <rule> <description> <cites text> <line>
        write_clean
        printf '\n\n%s\n' "$5" >> "$FIX/README.md"
        [[ "$(run_fixture)" != "0" ]] || {
            echo "FAIL: self-test #$1 — $3 was ACCEPTED" >&2; exit 1; }
        run_fixture_out | grep -qF "[$2]: README.md" || {
            echo "FAIL: self-test #$1 — $3 rejected for the wrong reason (no $2)" >&2; exit 1; }
        run_fixture_out | grep -qF "cites \"$4\"" || {
            echo "FAIL: self-test #$1 — $3 did not name \"$4\"" >&2
            run_fixture_out | sed 's/^/       /' >&2; exit 1; }
        echo "PASS: self-test #$1 — $3 is REJECTED naming the right token"
    }

    # #5429: the entity spelling of an arrow (-&gt;) is not a group closer
    # either, in every mix with real angle brackets.
    anchor_green 5429 "a live method after a dyn Fn arrow written with entities throughout" \
        "See \`$R::RecallTool&lt;dyn Fn(u8) -&gt; u8&gt;::decorate_memory_many\`."
    anchor_green 5429 "an unbackticked entity arrow generic with a live method, then prose" \
        "See $R::RecallTool&lt;dyn Fn(u8) -&gt; u8&gt;::decorate_memory_many and more."
    anchor_green 5429 "an entity arrow inside real angle brackets with a live method" \
        "See \`$R::RecallTool<dyn Fn(u8) -&gt; u8>::decorate_memory_many\`."
    anchor_red_cites 5429 QUAL "a missing method after a mixed entity-arrow group" \
        "$R::no_such" \
        "See \`$R::RecallTool<dyn Fn(u8) -&gt; u8>::no_such\`."
    anchor_red_cites 5429 QUAL "a missing method after an all-entity arrow group" \
        "$R::no_such" \
        "See \`$R::RecallTool&lt;dyn Fn(u8) -&gt; u8&gt;::no_such\`."
    anchor_red_cites 5429 QUAL "a missing method in a brace item with an entity arrow" \
        "$R::no_such" \
        "See \`$R::{RecallTool&lt;F: Fn() -&gt; u8&gt;::no_such}\`."

    # #5430: a balanced group followed by a stray closer is unbalanced and is
    # REPORTED; it used to end the capture, hiding every component behind it.
    # Every component is live, so only the unbalanced rule can make these red.
    anchor_red 5430 QUAL "an over-closed generic group before a live method" \
        "See \`$R::RecallTool<T>>::decorate_memory_many\`."
    anchor_red 5430 BARE_QUAL "an unbackticked over-closed generic group before a live method" \
        "See $R::RecallTool<T>>::decorate_memory_many prose."
    anchor_red 5430 QUAL "an over-closed HTML-entity generic group" \
        "See \`$R::RecallTool&lt;T&gt;&gt;::decorate_memory_many\`."
    anchor_red 5430 QUAL "an over-closed mixed entity and angle group" \
        "See \`$R::RecallTool<T&gt;>::decorate_memory_many\`."
    anchor_red 5430 QUAL "an over-closed turbofish group" \
        "See \`$R::RecallTool::<T>>::decorate_memory_many\`."
    anchor_red 5430 QUAL "an over-closed leading <Type as Trait> group" \
        "See \`$R::<RecallTool as Tr>>::decorate_memory_many\`."
    anchor_red 5430 QUAL "an over-closed nested generic group with a missing method" \
        "See \`$R::RecallTool<Vec<T>>>::no_such\`."
    anchor_red 5430 QUAL "an over-closed group ending the anchor" \
        "See \`$R::RecallTool<T>>\`."
    anchor_green 5430 "a live symbol closed by a prose angle bracket, no group of its own" \
        "See Option<$R::RecallTool> here."

    # #5431: a backticked-label link whose destination is on the NEXT line has
    # its symbol checked like the one-line form.
    anchor_red 5431 MDLINK "a next-line destination with a missing symbol label" \
        $'See [`no_such`](\nsrc/mcp/tools/recall.rs) x'
    anchor_red 5431 MDLINK "a next-line angle destination with a missing symbol label" \
        $'See [`no_such`](\n   <src/mcp/tools/recall.rs>) x'
    anchor_red 5431 MDLINK "a spaced open link with a missing symbol label and the destination below" \
        $'See [`no_such`](  \nsrc/mcp/tools/recall.rs) x'
    anchor_red 5431 PATH "a next-line destination to a missing file under a symbol label" \
        $'See [`recall`](\nsrc/gone.rs) x'
    anchor_green 5431 "a next-line destination whose symbol is live" \
        $'See [`RecallTool`](\nsrc/mcp/tools/recall.rs) x'
    anchor_green 5431 "a next-line destination whose label is the module (file stem)" \
        $'See [`recall`](\nsrc/mcp/tools/recall.rs) x'

    # #5432: only a real reference-definition head (or an open `](`) makes the
    # next line a link target; prose that merely ends in `]:` does not.
    anchor_green 5432 "prose ending in a bracketed word and a colon, then an absent escape path" \
        $'Note [x]:\nsrc/../gone.rs no longer exists'
    anchor_green 5432 "a sentence ending in a bracketed word and a colon, then an absent escape path" \
        $'The legacy layout, see [old]:\nsrc/../gone.rs no longer exists'
    anchor_red 5432 PATH "a real reference definition head, then an escape path on the next line" \
        $'[x]:\nsrc/../gone.rs no longer exists'
    anchor_red 5432 PATH "a list-item reference definition head, then an escape path below" \
        $'- [x]:\nsrc/../gone.rs no longer exists'
    anchor_red 5432 PATH "a blockquote reference definition head, then an escape path below" \
        $'> [x]:\nsrc/../gone.rs no longer exists'
    anchor_red 5432 PATH "an open link head, then an escape path on the next line" \
        $'See [h](\nsrc/../gone.rs) no longer exists'

    # #5433: a leading group with no `as` (<Type<T>>::m, a real qualified path)
    # names its type as a symbol claim; a placeholder with no path behind it is
    # still not a claim.
    anchor_red 5433 QUAL "a leading generic type group with no as and a missing type" \
        "See \`$R::<NoSuch<T>>::decorate_memory_many\`."
    anchor_red 5433 QUAL "a leading plain type group with no as and a missing type" \
        "See \`$R::<NoSuch>::decorate_memory_many\`."
    anchor_red 5433 BARE_QUAL "an unbackticked leading type group with a missing type" \
        "See $R::<NoSuch<T>>::decorate_memory_many here."
    anchor_red 5433 QUAL "a leading entity type group with a missing type" \
        "See \`$R::&lt;NoSuch&lt;T&gt;&gt;::decorate_memory_many\`."
    anchor_red 5433 QUAL "a live type in a leading group but a missing method" \
        "See \`$R::<RecallTool<T>>::no_such\`."
    anchor_green 5433 "a leading generic type group with no as and live parts" \
        "See \`$R::<RecallTool<T>>::decorate_memory_many\`."
    anchor_green 5433 "a leading plain type group with no as and live parts" \
        "See \`$R::<RecallTool>::decorate_memory_many\`."
    anchor_green 5433 "a placeholder group with no path behind it, with a nested group" \
        "See \`$R::<name<T>>\` here."

    # #5435: where an unbalanced backticked token ends is pinned by the exact
    # text reported; the group may not run on into the next code span.
    anchor_red_cites 5435 QUAL "an unbalanced group followed by another code span" \
        "$R::RecallTool<T" \
        "See \`$R::RecallTool<T\` and \`Vec>\`."
    anchor_red_cites 5435 QUAL "an unbalanced group closed only by a later code span, no space between" \
        "$R::RecallTool<T" \
        "See \`$R::RecallTool<T\`\`Vec>\`."


    # #5436: a brace item that holds a second src path is judged once, against
    # the file it is qualified with; the head search resumes after the brace.
    write_clean
    printf '\n\n%s\n' "See $R::{src/store/postgres.rs::no_such} here." >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #5436 — a missing name in a brace item with a second path was ACCEPTED" >&2; exit 1; }
    [[ "$(run_fixture_out | grep -c 'cites "')" = "1" ]] || {
        echo "FAIL: self-test #5436 — a brace item with a second src path must be reported exactly once" >&2
        run_fixture_out | sed 's/^/       /' >&2; exit 1; }
    echo "PASS: self-test #5436 — a brace item with a second src path is reported exactly once"

    # Round-6 mutant pins: a missing file under a next-line symbol-label link is
    # reported exactly once (MDLINK owns it; the file-link scan must skip it),
    # and a placeholder group inside a brace item is not a symbol claim.
    write_clean
    printf '\n\n%s\n' $'See [`recall`](\nsrc/gone.rs) x' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #5431 — a next-line destination to a missing file was ACCEPTED" >&2; exit 1; }
    [[ "$(run_fixture_out | grep -c 'cites "')" = "1" ]] || {
        echo "FAIL: self-test #5431 — a next-line symbol-label link to a missing file must be reported exactly once" >&2
        run_fixture_out | sed 's/^/       /' >&2; exit 1; }
    echo "PASS: self-test #5431 — a next-line symbol-label link to a missing file is reported exactly once"
    anchor_green 5433 "a placeholder group with a nested group inside a brace item" \
        "See \`$R::{<name<T>>}\` here."

    # #5190: a relative link with a plain-text label to a src/ file.
    anchor_red 5190 PATH "a plain-label link to a missing file" \
        'See [the handler](src/nope.rs) for it.'
    anchor_red 5190 PATH "a plain-label ../ link to a missing file" \
        'See [the handler](../src/nope.rs#L3) for it.'
    anchor_red 5190 PATH "a plain-label link to a missing file on a 'formerly' line" \
        'Formerly [the handler](src/nope.rs) held it.'
    anchor_red 5190 PATH "a backticked-label link to a missing file on a 'pre-split' line" \
        'The pre-split [`handler`](src/nope.rs) held it.'
    anchor_red 5190 PATH "a plain-label link to a missing file under a 'renamed to' line" \
        $'It was renamed to something else.\nSee [the handler](src/nope.rs) for it.'
    anchor_green 5190 "a plain-label link to a live file" \
        'See [the handler](src/mcp/tools/recall.rs) for it.'

    # #5269: a link title, a reference definition and an HTML relative href
    # are relative links to a src/ file too.
    anchor_red 5269 PATH "a titled link to a missing file" \
        'See [the handler](src/nope.rs "the handler") for it.'
    anchor_red 5269 LINE "a titled link with #L past end-of-file" \
        "See [the handler](src/mcp/tools/recall.rs#L9999 'h') for it."
    anchor_red 5269 PATH "a reference definition to a missing file" \
        '[handler]: src/nope.rs'
    anchor_red 5269 LINE "a reference definition with #L past end-of-file" \
        '[handler]: src/mcp/tools/recall.rs#L9999 "title"'
    anchor_red 5269 PATH "an HTML relative href to a missing file" \
        'See <a href="../src/nope.rs">the handler</a> for it.'
    anchor_red 5269 LINE "an HTML relative href with #L past end-of-file" \
        'See <a href="src/mcp/tools/recall.rs#L9999">the handler</a> for it.'
    anchor_green 5269 "a titled link to a live file" \
        'See [the handler](src/mcp/tools/recall.rs "the handler") for it.'
    anchor_green 5269 "a reference definition to a live file" \
        '[handler]: src/mcp/tools/recall.rs#L2 "title"'
    anchor_green 5269 "an HTML relative href to a live file" \
        'See <a href="src/mcp/tools/recall.rs#L2">the handler</a> for it.'

    # #5343: the residual relative-link forms #5269 left open: a paren title,
    # an angle destination, a ?query, a reference definition in a blockquote
    # or list item or with the destination on the next line, and an HTML href
    # in any case, with spaces around "=", single-quoted or unquoted.
    anchor_red 5343 PATH "a link with a parenthesised title to a missing file" \
        'See [h](src/nope.rs (the handler)) here.'
    anchor_red 5343 PATH "an angle-bracket link destination to a missing file" \
        'See [h](<src/nope.rs>) here.'
    anchor_red 5343 PATH "an angle-bracket destination with a title to a missing file" \
        'See [h](<src/nope.rs> "t") here.'
    anchor_red 5343 LINE "a parenthesised-title link with #L past end-of-file" \
        'See [h](src/mcp/tools/recall.rs#L9999 (title)) here.'
    anchor_red 5343 LINE "an angle-bracket link with #L past end-of-file" \
        'See [h](<src/mcp/tools/recall.rs#L9999>) here.'
    anchor_red 5343 LINE "a ?plain=1 link with #L past end-of-file" \
        'See [h](src/mcp/tools/recall.rs?plain=1#L9999) here.'
    anchor_red 5343 PATH "a ?plain=1 link to a missing file" \
        'See [h](src/nope.rs?plain=1) here.'
    anchor_red 5343 PATH "a reference definition inside a blockquote to a missing file" \
        '> [h]: src/nope.rs'
    anchor_red 5343 PATH "a reference definition inside a list item to a missing file" \
        '- [h]: src/nope.rs'
    anchor_red 5343 PATH "a reference definition inside a numbered list item to a missing file" \
        '1. [h]: src/nope.rs'
    anchor_red 5343 LINE "a reference definition in a nested blockquote list with #L past end-of-file" \
        '> - [h]: src/mcp/tools/recall.rs#L9999'
    anchor_red 5343 PATH "a reference definition with its destination on the next line" \
        $'[h]:\nsrc/nope.rs'
    anchor_red 5343 PATH "a reference definition with an angle destination and a title on the next line" \
        $'[h]:\n  <src/nope.rs> "title"'
    anchor_red 5343 PATH "a reference definition with a parenthesised title" \
        '[h]: src/nope.rs (the handler)'
    anchor_red 5343 PATH "a reference definition with an angle destination" \
        '[h]: <src/nope.rs>'
    anchor_red 5343 PATH "an unquoted HTML href to a missing file" \
        '<a href=src/nope.rs>x</a>'
    anchor_red 5343 PATH "an HTML href with spaces around the equals sign" \
        '<a href = "src/nope.rs">x</a>'
    anchor_red 5343 PATH "an upper-case HTML HREF to a missing file" \
        '<a HREF="src/nope.rs">x</a>'
    anchor_red 5343 PATH "a single-quoted HTML href to a missing file" \
        "<a href='src/nope.rs'>x</a>"
    anchor_red 5343 LINE "an unquoted HTML href with #L past end-of-file" \
        '<a href=src/mcp/tools/recall.rs#L9999>x</a>'
    anchor_red 5343 LINE "an HTML href with ?plain=1 and #L past end-of-file" \
        '<a href="src/mcp/tools/recall.rs?plain=1#L9999">x</a>'
    anchor_green 5343 "an angle-bracket link to a live file" \
        'See [h](<src/mcp/tools/recall.rs>) here.'
    anchor_green 5343 "a parenthesised-title link to a live file" \
        'See [h](src/mcp/tools/recall.rs (the handler)) here.'
    anchor_green 5343 "a ?plain=1 link to a live file" \
        'See [h](src/mcp/tools/recall.rs?plain=1#L2) here.'
    anchor_green 5343 "a blockquote reference definition to a live file" \
        '> [h]: src/mcp/tools/recall.rs'
    anchor_green 5343 "a next-line reference definition to a live file" \
        $'[h]:\nsrc/mcp/tools/recall.rs#L2'
    anchor_green 5343 "an unquoted upper-case spaced single-quoted HTML href to a live file" \
        "<a HREF = 'src/mcp/tools/recall.rs'>x</a>"
    anchor_green 5343 "an unquoted HTML href to a live file" \
        '<a href=src/mcp/tools/recall.rs>x</a>'
    anchor_green 5343 "an indented code block that looks like a reference definition" \
        '    [h]: src/nope.rs'
    anchor_green 5343 "a reference-style line followed by prose is not a definition" \
        '[h]: src/nope.rs and more words'
    anchor_green 5343 "an attribute that merely ends in href" \
        '<a xhref="src/nope.rs">x</a>'
    # #5348: pins for the surviving #5269 mutants (REFDEF/HREF).
    anchor_red 5348 PATH "an unquoted HTML href at the very end of the line" \
        '<a href=src/nope.rs'
    anchor_red 5348 LINE "an unquoted HTML href at the end of the line with #L past end-of-file" \
        '<a href=src/mcp/tools/recall.rs#L9999'
    anchor_red 5348 PATH "a reference definition with a single-quoted title" \
        "[h]: src/nope.rs 't'"
    anchor_red 5348 PATH "a reference definition inside a list inside a blockquote" \
        '> 1. [h]: src/nope.rs "t"'
    anchor_green 5348 "an HTML href followed by more attributes" \
        "<a href=src/mcp/tools/recall.rs class=x>x</a>"

    # #5189: the #L fragment of a relative src link is range-checked.
    anchor_red 5189 LINE "a backticked-label link with #L past end-of-file" \
        'See [`RecallTool`](src/mcp/tools/recall.rs#L9999) for it.'
    anchor_red 5189 LINE "a link with an #L range whose end passes end-of-file" \
        'See [`RecallTool`](src/mcp/tools/recall.rs#L2-L9999) for it.'
    anchor_red 5189 LINE "a plain-label link with #L past end-of-file" \
        'See [recall](src/mcp/tools/recall.rs#L9999) for it.'
    anchor_red 5189 LINE "a link with a reversed #L range" \
        'See [recall](src/mcp/tools/recall.rs#L3-L2) for it.'
    anchor_red 5189 LINE "a link with #L0" \
        'See [recall](src/mcp/tools/recall.rs#L0) for it.'
    anchor_green 5189 "a link with an in-range #L fragment" \
        'See [recall](src/mcp/tools/recall.rs#L4) for it.'
    anchor_green 5189 "a link with a full-file #L range" \
        'See [`RecallTool`](src/mcp/tools/recall.rs#L1-L4) for it.'
    # #5268: a column part (#L<a>C<c>) does not hide the line.
    anchor_red 5268 LINE "a link with a #L<a>C<c> fragment past end-of-file" \
        'See [recall](src/mcp/tools/recall.rs#L9999C2) for it.'
    anchor_red 5268 LINE "a link with a #L<a>C<c>-L<b>C<d> range past end-of-file" \
        'See [recall](src/mcp/tools/recall.rs#L1C2-L9999C3) for it.'
    anchor_green 5268 "a link with an in-range #L<a>C<c> fragment" \
        'See [recall](src/mcp/tools/recall.rs#L2C3) for it.'
    # #5265: the second L of a range is optional (#L2-9999 is a range too).
    anchor_red 5265 LINE "a link with an #L<a>-<b> range (no second L) past end-of-file" \
        'See [recall](src/mcp/tools/recall.rs#L2-9999) for it.'
    anchor_green 5265 "a link with an in-range #L<a>-<b> range (no second L)" \
        'See [recall](src/mcp/tools/recall.rs#L2-4) for it.'
    anchor_green 5189 "a commit-pinned permalink link keeps its own #L (immutable)" \
        "See [recall](https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L9999) for it."
    write_clean
    printf '\n\nSee [`handler`](src/nope.rs) for it.\n' >> "$FIX/README.md"
    [[ "$(run_fixture_out | grep -c '^FAIL: doc-symbol-anchors \[')" = "1" ]] || {
        echo "FAIL: self-test #5190 — a backticked-label link to a missing file must be reported exactly once" >&2; exit 1; }
    echo "PASS: self-test #5190 — a backticked-label link to a missing file is reported exactly once"

    # #5191: a backticked qualified anchor is QUAL only, never also BARE_QUAL.
    write_clean
    printf '\n\nSee `src/mcp/tools/recall.rs::no_such` here.\n' >> "$FIX/README.md"
    [[ "$(run_fixture_out | grep -c '^FAIL: doc-symbol-anchors \[')" = "1" ]] || {
        echo "FAIL: self-test #5191 — a backticked qualified anchor must be reported exactly once" >&2; exit 1; }
    echo "PASS: self-test #5191 — a backticked qualified anchor is reported exactly once"

    # ---- #4651: a BARE src/x.rs:N line anchor (no backtick) ----------
    # Every form the #4651 census found must FAIL as BARE_LN; the only
    # exemption is the label of a commit-pinned permalink (immutable).
    bare_red() {  # <description> <line planted in README.md>
        write_clean
        printf '\n\n%s\n' "$2" >> "$FIX/README.md"
        [[ "$(run_fixture)" != "0" ]] || {
            echo "FAIL: self-test #4651 — $1 was ACCEPTED (bare line anchor invisible)" >&2; exit 1; }
        run_fixture_out | grep -q 'BARE_LN' || {
            echo "FAIL: self-test #4651 — $1 rejected for the wrong reason (no BARE_LN)" >&2; exit 1; }
        echo "PASS: self-test #4651 red probe — $1 is REJECTED"
    }
    bare_red "a bare anchor in plain prose" \
        'The decorator lives at src/mcp/tools/recall.rs:2 in the tree.'
    bare_red "a bare anchor in a markdown link label with a branch URL" \
        '[src/mcp/tools/recall.rs:2](https://github.com/o/r/blob/main/src/mcp/tools/recall.rs#L2)'
    bare_red "a bare anchor in HTML text" \
        '<td>src/mcp/tools/recall.rs:2</td>'
    bare_red "a bare anchor with a relative ../ prefix" \
        'See ../src/mcp/tools/recall.rs:2 for it.'
    bare_red "a bare anchor with a ./ prefix" \
        'See ./src/mcp/tools/recall.rs:2 here.'
    bare_red "a bare anchor wrapped in markdown underscore emphasis" \
        '_src/mcp/tools/recall.rs:2_'
    bare_red "a bare anchor whose permalink pins a branch, not a commit" \
        '<a href="https://github.com/o/r/blob/release/src/mcp/tools/recall.rs#L2">src/mcp/tools/recall.rs:2</a>'
    bare_red "a bare anchor whose permalink carries an abbreviated (9-hex) sha" \
        "<a href=\"https://github.com/o/r/blob/${pin40:0:9}/src/mcp/tools/recall.rs#L2\">src/mcp/tools/recall.rs:2</a>"
    bare_red "a bare anchor whose permalink names a hex-only branch" \
        '[src/mcp/tools/recall.rs:2](https://github.com/o/r/blob/cafe1234/src/mcp/tools/recall.rs#L2)'
    bare_red "a bare anchor whose URL has /blob/<hex>/ only in a query string" \
        "[src/mcp/tools/recall.rs:2](https://example.com/x?u=/blob/${pin40}/src/mcp/tools/recall.rs#L2)"
    bare_red "a 40-hex permalink on a host other than github.com" \
        "[src/mcp/tools/recall.rs:2](https://example.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L2)"
    bare_red "a pinned permalink with trailing text after the #L line" \
        "[src/mcp/tools/recall.rs:2](https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L2x)"
    bare_red "a pinned permalink whose label names a different line" \
        "[src/mcp/tools/recall.rs:2](https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L3)"
    bare_red "a pinned permalink whose label names a different file" \
        "<a href=\"https://github.com/o/r/blob/${pin40}/src/mcp/tools/other.rs#L2\">src/mcp/tools/recall.rs:2</a>"
    bare_red "a pinned permalink whose label range differs from the #L range" \
        "[src/mcp/tools/recall.rs:2-5](https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L2-L6)"
    bare_red "a pinned permalink whose label range START differs from the #L start (markdown)" \
        "[src/mcp/tools/recall.rs:2-4](https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L3-L4)"
    bare_red "a pinned permalink whose label range START differs from the #L start (HTML)" \
        "<a href=\"https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L1-L4\">src/mcp/tools/recall.rs:2-4</a>"
    bare_red "a bare anchor in plain text AFTER a closed commit-pinned link (#5215)" \
        "<a href=\"https://github.com/o/r/blob/${pin40}/src/mcp/tools/recall.rs#L2\">x</a> then src/mcp/tools/recall.rs:2 </a>"
    write_clean
    printf '\n\n[src/mcp/tools/recall.rs:2](https://github.com/o/r/blob/%s/src/mcp/tools/recall.rs#L2)\n' "$pin40" >> "$FIX/README.md"
    printf '<a href="https://github.com/o/r/blob/%s/src/mcp/tools/recall.rs#L3">src/mcp/tools/recall.rs:3</a>\n' "$pin40" >> "$FIX/README.md"
    printf '[src/mcp/tools/recall.rs:2-5](https://github.com/o/r/blob/%s/src/mcp/tools/recall.rs#L2-L5)\n' "$pin40" >> "$FIX/README.md"
    printf 'Raw URL path https://github.com/o/r/blob/%s/src/mcp/tools/recall.rs:2 is not a label.\n' "$pin40" >> "$FIX/README.md"
    # #5215: a second pinned HTML link on the same line keeps its own label.
    printf '<a href="https://github.com/o/r/blob/%s/src/mcp/tools/recall.rs#L1">src/mcp/tools/recall.rs:1</a> and <a href="https://github.com/o/r/blob/%s/src/mcp/tools/recall.rs#L2">src/mcp/tools/recall.rs:2</a>\n' "$pin40" "$pin40" >> "$FIX/README.md"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test #4651 — a commit-pinned permalink label was REJECTED" >&2
        run_fixture_out | sed 's/^/       /' >&2; exit 1; }
    echo "PASS: self-test #4651 green control — commit-pinned (40-hex) permalink labels are ACCEPTED"

    # ---- #5201: the absent-path exemption must not fail open --------
    # "split by #N" is not an absence assertion, and a QUAL anchor
    # (path::symbol) asserts the file exists whatever the wording says.
    anchor_red 5201 PATH "a plain path on a 'split by' line" \
        'Split by #1670: see `src/missing_5201.rs` for it.'
    anchor_red 5201 PATH "a qualified anchor on a 'split by' line" \
        'Split by #1670 from `src/missing_5201.rs::insert` today.'
    anchor_red 5201 PATH "a qualified anchor on a 'formerly' line" \
        'Formerly `src/missing_5201.rs::insert` held it.'
    anchor_red 5201 PATH "an unbackticked qualified anchor on a 'formerly' line" \
        'Formerly src/missing_5201.rs::insert held it.'
    anchor_red 5266 PATH "a qualified escape token on a 'formerly' line" \
        'Formerly `src/../missing_5266.rs::insert` held it.'
    anchor_red 5266 PATH "an unbackticked qualified escape token on a 'formerly' line" \
        'Formerly src/../missing_5266.rs::insert held it.'
    anchor_green 5266 "a plain escape token on a 'formerly' line" \
        'Formerly `src/../missing_5266.rs` held it.'
    # #5346: every occurrence of an escape token is judged, and a link target
    # is never an absence claim.
    anchor_red 5346 PATH "a markdown link to an escape token on a 'formerly' line" \
        'Formerly [h](src/../missing_5346.rs) held it.'
    anchor_red 5346 PATH "an HTML href to an escape token on a 'formerly' line" \
        'Formerly <a href="src/../missing_5346.rs">h</a> held it.'
    anchor_red 5346 PATH "an angle-bracket link to an escape token on a 'formerly' line" \
        'Formerly [h](<src/../missing_5346.rs>) held it.'
    anchor_red 5346 PATH "a reference definition to an escape token on a 'formerly' line" \
        $'Formerly:\n[h]: src/../missing_5346.rs'
    anchor_red 5346 PATH "a plain mention then a link to the same escape token on a 'formerly' line" \
        'Formerly `src/../missing_5346.rs` and see [h](src/../missing_5346.rs).'
    anchor_red 5346 PATH "a plain mention then a qualified use of the same escape token" \
        'Formerly `src/../missing_5346.rs` then `src/../missing_5346.rs::insert` too.'
    anchor_red 5346 PATH "an unbackticked plain mention then a qualified use of the same escape token" \
        'Formerly src/../missing_5346.rs then src/../missing_5346.rs::insert too.'
    anchor_green 5346 "a plain escape token repeated on a 'formerly' line" \
        'Formerly `src/../missing_5346.rs` and `src/../missing_5346.rs` held it.'
    anchor_green 5201 "a plain path with 'was split' wording" \
        'The old module `src/missing_5201.rs` was split by #1670.'
    anchor_green 5201 "a plain path with 'renamed to' wording" \
        'The loop `src/missing_5201.rs` was renamed to `src/mcp/tools/recall.rs`.'
    anchor_green 5201 "a plain path with 'pre-split' wording" \
        'It was `src/missing_5201.rs` pre-split.'
    # #5264: wording that names a DESTINATION never exempts the file after it.
    anchor_red 5264 PATH "a plain path after 'was split into'" \
        'The module was split into `src/missing_5264.rs` for it.'
    anchor_red 5264 PATH "a plain path after 'split out'" \
        'Split out `src/missing_5264.rs` from the monolith.'
    anchor_red 5264 PATH "a plain path after an arrow" \
        '-> `src/missing_5264.rs`'
    anchor_red 5264 PATH "a plain path after a unicode arrow" \
        'The loop moved → `src/missing_5264.rs` today.'
    anchor_green 5264 "a source path before 'was split into'" \
        '`src/missing_5264.rs` was split into `src/mcp/tools/recall.rs`.'
    anchor_green 5264 "a source path before an arrow" \
        '`src/missing_5264.rs` -> `src/mcp/tools/recall.rs`'
    anchor_green 5264 "a source path on the line above a wrapped arrow" \
        $'The module `src/missing_5264.rs`\n-> `src/mcp/tools/recall.rs` now.'
    # #5344: "split up into", "split across" and "renamed to" name a
    # destination as well.
    anchor_red 5344 PATH "a plain path after 'split up into'" \
        'It has been split up into `src/missing_5344.rs` now.'
    anchor_red 5344 PATH "a plain path after 'split across'" \
        'The module was split across `src/missing_5344.rs`.'
    anchor_red 5344 PATH "a plain path after 'renamed to'" \
        'It was renamed to `src/missing_5344.rs`.'
    anchor_red 5344 PATH "a second path after 'renamed to' on a line with a live source" \
        '`src/old_5344.rs` was renamed to `src/missing_5344.rs`.'
    anchor_green 5344 "a source path before 'split up into'" \
        '`src/missing_5344.rs` was split up into `src/mcp/tools/recall.rs`.'
    anchor_green 5344 "a source path before 'renamed to'" \
        '`src/missing_5344.rs` was renamed to `src/mcp/tools/recall.rs`.'
    anchor_green 5344 "a source path before 'split across'" \
        '`src/missing_5344.rs` was split across `src/mcp/tools/recall.rs`.'
    # #5349: pins for the destination words (cloud M14 and M15 survived).
    anchor_green 5349 "a source path before a unicode arrow" \
        '`src/missing_5349.rs` → `src/mcp/tools/recall.rs`'
    anchor_green 5349 "a source path before 'split out'" \
        '`src/missing_5349.rs` split out `src/mcp/tools/recall.rs`.'
    anchor_green 5349 "a source path on the line above a wrapped unicode arrow" \
        $'The module `src/missing_5349.rs`\n→ `src/mcp/tools/recall.rs` now.'
    anchor_red 5349 PATH "a plain path after a unicode arrow with no source before it" \
        'Moved → `src/missing_5349.rs` today.'
    # #5341: an arrow that is not followed by a src/ path names no
    # destination, so the missing file before it is still a stale anchor.
    anchor_red 5341 PATH "a missing file before a Rust signature arrow" \
        'The file `src/missing_5341.rs` exposes `fn f() -> u32`.'
    anchor_red 5341 PATH "a missing file before an HTML comment end" \
        'See `src/missing_5341.rs` <!-- note -->'
    anchor_red 5341 PATH "a missing file before a unicode arrow in prose" \
        'The file `src/missing_5341.rs` maps a → b.'
    anchor_red 5341 PATH "a missing file with a line anchor before a signature arrow" \
        'See `src/missing_5341.rs:3` for `fn g() -> bool`.'
    anchor_red 5341 PATH "a missing file above a next line that starts with a non-path arrow" \
        $'The file `src/missing_5341.rs`\n-> returns u32'
    anchor_green 5341 "a missing source before an arrow to a live path" \
        '`src/missing_5341.rs` -> `./src/mcp/tools/recall.rs`'

    # ---- a stale migrate_vNN (the #2629 issue title's own example) ---
    write_clean
    printf '\n\nThe postgres ladder ends at `src/store/postgres.rs::migrate_v86`.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — a stale migrate_vNN citation was ACCEPTED" >&2; exit 1; }
    echo "PASS: self-test — a stale \`migrate_vNN\` citation is REJECTED"

    # ---- a markdown link whose SYMBOL is gone ------------------------
    write_clean
    printf '\n\nSee [`decorate_memory`](src/mcp/tools/recall.rs).\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — a markdown symbol link to a renamed symbol was ACCEPTED" >&2; exit 1; }
    echo "PASS: self-test — a [\`sym\`](src/path.rs) link whose symbol is gone is REJECTED"

    # ---- #4593: every scanned tree has a red probe AND a green control
    # A stale symbol cite planted in each newly scanned doc must FAIL and
    # name that doc; the corrected cite in the same doc must PASS.
    for rel in SECURITY.md CONTRIBUTING.md docs/governance/x.md \
               docs/strategy/x.md sdk/ts/README.md infra/lab/README.md \
               docs/x.html; do
        write_clean
        mkdir -p "$FIX/$(dirname "$rel")"
        printf 'Renamed: `src/mcp/tools/recall.rs::decorate_memory`.\n' > "$FIX/$rel"
        [[ "$(run_fixture)" != "0" ]] || {
            echo "FAIL: self-test — a stale anchor in $rel was ACCEPTED (tree not scanned)" >&2; exit 1; }
        run_fixture_out | grep -q "$rel" || {
            echo "FAIL: self-test — the violation in $rel did not name that doc" >&2; exit 1; }
        echo "PASS: self-test red probe — a stale anchor in $rel is REJECTED"
        printf 'Live: `src/mcp/tools/recall.rs::decorate_memory_many`.\n' > "$FIX/$rel"
        [[ "$(run_fixture)" = "0" ]] || {
            echo "FAIL: self-test — the corrected anchor in $rel was REJECTED" >&2
            run_fixture_out | sed 's/^/       /' >&2; exit 1; }
        echo "PASS: self-test green control — the corrected anchor in $rel is ACCEPTED"
        rm -f "$FIX/$rel"
    done

    # ---- BURN-DOWN allowlist: BOTH directions, stale FAILS -----------
    allow="$FIX/scripts/qc-allowlists/doc-symbol-anchors-allow.txt"
    write_clean
    printf '\n\nThe decorator is `src/mcp/tools/recall.rs::decorate_memory`.\n' >> "$FIX/README.md"
    printf 'README.md src/mcp/tools/recall.rs::decorate_memory #1\n' > "$allow"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test allowlist — an ALLOWLISTED anchor still failed" >&2
        run_fixture_out | sed 's/^/       /' >&2; exit 1; }
    echo "PASS: self-test allowlist — an allowlisted anchor PASSES"

    write_clean
    printf 'README.md src/mcp/tools/recall.rs::decorate_memory #1\n' > "$allow"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test allowlist — a STALE entry PASSED. This ledger must not be able to rot." >&2; exit 1; }
    run_fixture_out | grep -q 'STALE' || {
        echo "FAIL: self-test allowlist — stale entry rejected without naming it stale" >&2; exit 1; }
    echo "PASS: self-test allowlist — a STALE entry FAILS (unlike the three pending-fix ledgers, by design)"

    write_clean
    printf 'README.md\n' > "$allow"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test allowlist — a MALFORMED entry did not fail" >&2; exit 1; }
    echo "PASS: self-test allowlist — a MALFORMED entry HARD-FAILS"

    # ---- fail CLOSED on an analysis-engine error (CB-2 / #2713) -------
    # An internal engine error must NEVER print PASS — the exact fail-open
    # this gate hits once its burn-down allowlist empties. R-203: first
    # reproduce the pre-fix SHAPE — `x="$(crashing-python)" || true` —
    # which swallows a crash into an empty value and would print a false
    # PASS; then prove the FIXED gate fails closed under an injected fault.
    write_clean
    prefix_shape="$(v="$(python3 -c 'import sys; sys.exit(3)')" || true; [[ -z "$v" ]] && echo "WOULD-PRINT-PASS")"
    [[ "$prefix_shape" == "WOULD-PRINT-PASS" ]] || {
        echo "FAIL: self-test R-203 — the pre-fix \`|| true\` shape did not reproduce the false-PASS fail-open" >&2; exit 1; }
    fault_rc=0
    fault_out="$(AI_MEMORY_SYMBOL_GATE_ROOT="$FIX" AI_MEMORY_SYMBOL_GATE_SELFTEST_FAULT=1 "$SELF" 2>&1)" || fault_rc=$?
    [[ "$fault_rc" -ne 0 ]] || {
        echo "FAIL: self-test #2713 — the gate exited 0 on an injected analysis-engine fault (fail-OPEN)" >&2
        printf '%s\n' "$fault_out" | sed 's/^/       /' >&2; exit 1; }
    grep -q 'gate: PASS' <<<"$fault_out" && {
        echo "FAIL: self-test #2713 — the gate printed a PASS banner despite an engine fault" >&2; exit 1; }
    grep -q 'analysis engine errored' <<<"$fault_out" || {
        echo "FAIL: self-test #2713 — engine fault did not produce the distinct fail-closed message" >&2; exit 1; }
    echo "PASS: self-test #2713 — an analysis-engine error FAILS CLOSED (exit $fault_rc, distinct message, no PASS banner)"

    # ---- never a silent no-op ----------------------------------------
    write_clean
    rm -rf "$FIX/src"
    mkdir -p "$FIX/src"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an EMPTY src tree passed; the gate can no-op to green (#2444 shape)" >&2; exit 1; }
    echo "PASS: self-test — an empty src/ symbol set fails CLOSED rather than reporting an unearned pass"
    exit 0
fi

if [[ -n "${AI_MEMORY_SYMBOL_GATE_ROOT:-}" ]]; then
    REPO_ROOT="$AI_MEMORY_SYMBOL_GATE_ROOT"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$REPO_ROOT"

ALLOWLIST="$REPO_ROOT/scripts/qc-allowlists/doc-symbol-anchors-allow.txt"

# --------------------------------------------------------------------
# REUSE the migration-ladder tip reader (operator direction: do NOT add
# a new SSOT). The function is EXTRACTED from the sibling gate rather
# than copied, so a rename there fails loudly here instead of leaving
# two divergent readers. Sourcing the whole script is not an option —
# it ends in `main "$@"` and would run the ladder gate.
# --------------------------------------------------------------------
LADDER_GATE="$REPO_ROOT/scripts/check-migration-ladder.sh"
LADDER_TIP=""
if [[ -f "$LADDER_GATE" ]]; then
    reader="$(awk '/^read_current_schema_version\(\) \{/,/^\}/' "$LADDER_GATE")"
    if [[ -z "$reader" ]]; then
        printf 'FAIL: doc-symbol-anchors: could not extract read_current_schema_version() from %s\n' \
            "${LADDER_GATE#"$REPO_ROOT"/}" >&2
        printf '       This gate REUSES that reader rather than deriving the ladder tip a third time.\n' >&2
        printf '       If it was renamed, update the extraction here in lockstep.\n' >&2
        exit 1
    fi
    eval "$reader"
    LADDER_TIP="$(read_current_schema_version "$REPO_ROOT/src/store/postgres.rs")"
fi

if ! violations="$(
    REPO_ROOT="$REPO_ROOT" LADDER_TIP="$LADDER_TIP" python3 - <<'PY'
import glob
import os
import posixpath
import re

root = os.environ["REPO_ROOT"].rstrip("/")
ladder_tip = os.environ.get("LADDER_TIP", "").strip()

# Self-test fault-injection (#2713): when this env var is set the analysis
# engine raises, so the gate's own --self-test can prove the gate FAILS
# CLOSED (exits non-zero, prints no PASS) on an engine error instead of
# swallowing it into an empty violation set. Never set in production / CI.
if os.environ.get("AI_MEMORY_SYMBOL_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-doc-symbol-anchors self-test: injected analysis-engine fault (#2713)")

# ---- symbol index over src/ ------------------------------------------
DEF = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(?:fn|struct|enum|trait|type|const|static|mod|union)\s+([A-Za-z_][A-Za-z0-9_]*)")
MACRO = re.compile(r"macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)")
# A 4-space-indented CamelCase item is an enum variant / struct field in
# house style; docs cite those the same way they cite functions.
VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*[,({=]", re.M)

per_file = {}
line_count = {}
for p in sorted(glob.glob(os.path.join(root, "src/**/*.rs"), recursive=True)):
    rel = p[len(root) + 1:]
    try:
        text = open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    # #4700: the number of lines, not newlines + 1 (a trailing newline
    # does not start a line, so `N+1` of an N-line file was accepted).
    line_count[rel] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    names = {m.group(1) for m in DEF.finditer(text)}
    names |= {m.group(1) for m in MACRO.finditer(text)}
    names |= {m.group(1) for m in VARIANT.finditer(text)}
    # The module's own name: `[`recall`](src/mcp/tools/recall.rs)` is a
    # MODULE citation, which is legitimate and extremely common.
    names.add(os.path.splitext(os.path.basename(rel))[0])
    per_file[rel] = names

if not per_file:
    print("SETUP\t-\t0\t-\tsrc/ yielded ZERO rust files; the gate would be a no-op")
    raise SystemExit(0)

# ---- scoped doc set ---------------------------------------------------
# Frozen trees are excluded for the CHANGELOG reason: they describe a
# tree AS IT WAS, and re-pointing their anchors at HEAD would falsify
# the record.
FROZEN = re.compile(
    r"^docs/(v0\.|internal/|audit/|rfc/|adr|BASELINE|"
    r"v1\.0\.0/perfect-endpoint-assessment/)")

docs = ["CLAUDE.md", "README.md", "ROADMAP.md", "PERFORMANCE.md",
        "SECURITY.md", "CONTRIBUTING.md"]
docs += sorted(glob.glob(os.path.join(root, "docs/*.md")))
docs += sorted(glob.glob(os.path.join(root, "docs/*.html")))
for sub in ("security", "compliance", "spec", "integrations", "deploy", "v1.0.0",
            "governance", "strategy"):
    docs += sorted(glob.glob(os.path.join(root, f"docs/{sub}/**/*.md"), recursive=True))
# #4593: the SDK and infra trees carry operator-facing READMEs that cite src/.
for top in ("sdk", "infra"):
    docs += sorted(glob.glob(os.path.join(root, f"{top}/**/*.md"), recursive=True))

seen_docs = []
for d in docs:
    rel = d[len(root) + 1:] if d.startswith(root + "/") else d
    if FROZEN.match(rel) or rel in seen_docs:
        continue
    if os.path.exists(os.path.join(root, rel)):
        seen_docs.append(rel)

# #4699/#4701: every rule below sees ONE canonical form. canon() strips
# any leading ./ and ../ segments (with any run of slashes after each)
# from a `src/<path>.rs` token and collapses repeated slashes inside it
# (`.//src/x.rs`, `././src/x.rs`, `src//a//x.rs` -> `src/a/x.rs`) before
# the rules run, so PATH, PATHLN, BARE_LN and QUAL need no prefix group
# of their own. A token preceded by a letter, digit, dot or slash is left
# alone: its root is unknown (`foo./src/x.rs`, `x/./src/x.rs`).
CANON = re.compile(
    r"(?<![A-Za-z0-9./])(?:\.{1,2}/+)*"
    r"(src/+(?:(?:[A-Za-z0-9_]+|\.{1,2})/+)*[A-Za-z0-9_]+\.rs)")


def canon(line):
    """Rewrite every `src/<path>.rs` token to its normal form: leading ./
    and ../ stripped, repeated slashes collapsed, and . and .. segments
    INSIDE the path resolved (`src/a/../a/x.rs` -> `src/a/x.rs`). Returns
    (line, escapes): a token whose .. segments leave src/ names no file the
    gate can check, so it is returned for a PATH finding, never dropped."""
    escapes = []

    def norm(m):
        p = posixpath.normpath(m.group(1))
        if not p.startswith("src/"):
            escapes.append(m.group(1))
            return m.group(0)
        return p

    return CANON.sub(norm, line), escapes


PATH = re.compile(r"`(src/[A-Za-z0-9_/]+\.rs)`")
# #5188: the range separator may also be an en dash (U+2013) or em dash
# (U+2014), which smart-quote editors and pasted prose produce.
# #5345: a doubled hyphen ("--") and the minus sign (U+2212) are range
# separators too; the whitespace around the separator may be any run.
PATHLN = re.compile(
    r"`(src/[A-Za-z0-9_/]+\.rs):(\d+)(?:\s*(?:-{1,2}|[\u2013\u2014\u2212])\s*(\d+))?")
# #4651: a BARE `src/x.rs:N` (no leading backtick: plain prose, a link
# label, HTML text). Not preceded by a backtick (PATHLN owns that form),
# a path separator, a dot or an alphanumeric, so URL path segments are
# skipped; canon() has already removed a ./ or ../ prefix and `_` (markdown
# emphasis) may precede the path (#4668).
BARE_LN = re.compile(r"(?<![`/A-Za-z0-9.])(src/[A-Za-z0-9_/]+\.rs):(\d+)")
# A bare anchor is exempt ONLY as the label of a link whose target is a
# commit-pinned permalink (/blob/<40 hex>/): immutable, cannot rot, and
# only when the label's path and line (or range) equal the URL's (#4670).
# PIN_TARGET below is the single owner of that pin rule (#5214).
LABEL_MD = re.compile(r"^[^\]\n]*\]\(([^)\s]*)")
LABEL_HTML = re.compile(r"^[^<\n]*</a>")
# #5342/#5392: the symbol after `::` is path components, each optionally
# followed by ONE balanced generic group, nested to ANY depth (commas, spaces,
# quotes, `&`, `->` and parentheses inside it are fine: `<T, U>`, `<'a>`,
# `<dyn Fn(u8) -> u8>`), with an optional leading `<Type as Trait>`. A group
# may be written with HTML entities (`&lt;T&gt;`), and the two spellings mix.
# A real depth-counting scan (scan_group / scan_sym below) replaces the old
# fixed-depth regex, which stopped at the first comma or space and then at one
# nesting level and so hid every component after a deeper group.
_ID = r"[A-Za-z_][A-Za-z0-9_]*"
ID_RE = re.compile(_ID)
QUAL_HEAD = re.compile(r"`(src/[A-Za-z0-9_/]+\.rs)::")
# #5191: an UNBACKTICKED `src/x.rs::symbol` anchor (prose, an HTML code
# element, a code-block comment) is a symbol claim too, and is the very form
# the BARE_LN failure text tells authors to use. Same lookbehind as BARE_LN,
# so a URL path segment is never matched.
BARE_QUAL_HEAD = re.compile(r"(?<![`/A-Za-z0-9.])(src/[A-Za-z0-9_/]+\.rs)::")
BRACE_BODY = re.compile(r"\{([^}]*)\}")


def _group_step(text, j):
    """Classify the text at `j`: ('open'|'close', width) for an angle bracket
    or its HTML entity, ('stop', 1) for a character a group may not contain,
    else ('other', 1). The `>` of an arrow (`->` or `-&gt;`) is not a closer."""
    if text.startswith("&lt;", j):
        return "open", 4
    if text.startswith("&gt;", j):
        # #5429: the entity spelling of an arrow (-&gt;) is not a closer.
        return ("other", 4) if j > 0 and text[j - 1] == "-" else ("close", 4)
    ch = text[j]
    if ch == "<":
        return "open", 1
    if ch == ">":
        return ("other", 1) if j > 0 and text[j - 1] == "-" else ("close", 1)
    if ch in "`\n":
        return "stop", 1
    return "other", 1


def scan_group(text, i):
    """End index (exclusive) of the balanced generic group opening at `i`
    (`<` or `&lt;`), any nesting depth; None when it never balances before a
    backtick or the end of the text."""
    depth, j = 0, i
    while j < len(text):
        kind, width = _group_step(text, j)
        if kind == "stop":
            return None
        if kind == "open":
            depth += 1
        elif kind == "close":
            depth -= 1
            if depth == 0:
                return j + width
        j += width
    return None


def _opens_group(text, i):
    return text.startswith("<", i) or text.startswith("&lt;", i)


def _token_end(text, i):
    """End of the whitespace- and backtick-delimited token containing `i`."""
    j = i
    while j < len(text) and not text[j].isspace() and text[j] != "`":
        j += 1
    return j


def _stray_close(text, i):
    """True when `text` has an extra group closer (`>` or `&gt;`) at `i`."""
    return i < len(text) and _group_step(text, i)[0] == "close"


def scan_sym(text, i):
    """Scan the symbol path starting at `i`; returns its end index, or None
    when no symbol starts there. Path components are identifiers, each with an
    optional balanced group, joined by `::` (a bare group after `::` is a
    turbofish), after an optional leading `<Type as Trait>::`. A group that
    never balances, or is followed by an extra closer (#5430), captures to the
    end of the token (#5393), so the caller reports it instead of skipping the
    components behind it."""
    pos = i
    if _opens_group(text, pos):
        end = scan_group(text, pos)
        if end is None:
            return _token_end(text, pos)
        if _stray_close(text, end):
            return _token_end(text, end)
        if not text.startswith("::", end):
            return None
        pos = end + 2
    m = ID_RE.match(text, pos)
    if not m:
        return None
    pos = m.end()
    while True:
        if _opens_group(text, pos):
            end = scan_group(text, pos)
            if end is None:
                return _token_end(text, pos)
            pos = end
            if _stray_close(text, pos):
                return _token_end(text, pos)
        if not text.startswith("::", pos):
            return pos
        m = ID_RE.match(text, pos + 2)
        if m:
            pos = m.end()
        elif _opens_group(text, pos + 2):
            end = scan_group(text, pos + 2)
            if end is None:
                return _token_end(text, pos + 2)
            pos = end
            if _stray_close(text, pos):
                return _token_end(text, pos)
        else:
            return pos


def iter_quals(line):
    """Yield (rule, file, payload) for every qualified anchor on `line`:
    backticked `src/x.rs::sym` (QUAL) and unbackticked (BARE_QUAL)."""
    for rule, head in (("QUAL", QUAL_HEAD), ("BARE_QUAL", BARE_QUAL_HEAD)):
        pos = 0
        while True:
            hm = head.search(line, pos)
            if not hm:
                break
            pos = hm.end()
            bm = BRACE_BODY.match(line, pos) if line.startswith("{", pos) else None
            if bm:
                yield rule, hm.group(1), bm.group(1)
                pos = bm.end()
                continue
            end = scan_sym(line, pos)
            if end is not None:
                yield rule, hm.group(1), line[pos:end]
                pos = end


def strip_generics(tok):
    """Remove every balanced generic group (any depth) from a token that has
    already had its HTML entities turned into angle brackets. A group that
    never balances stays, so the caller can report it."""
    out, j = [], 0
    while j < len(tok):
        if tok[j] == "<":
            end = scan_group(tok, j)
            if end is not None:
                j = end
                continue
        out.append(tok[j])
        j += 1
    return "".join(out)


MDLINK = re.compile(r"\[`([A-Za-z_][A-Za-z0-9_]*)`\]\(\s*<?([^)]*src/[A-Za-z0-9_/]+\.rs)[^)]*\)")
# #5190: ANY relative markdown link to a src/ file, whatever its label
# (MDLINK only sees a backticked-identifier label). canon() has already
# removed a ./ or ../ prefix, so the target starts with src/.
# #5343: the destination may be angle-bracketed (`<src/x.rs>`), carry a
# `?query` (GitHub's `?plain=1`) before the fragment, and be followed by a
# title in double quotes, single quotes or parentheses.
_TITLE = r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?"
_SRC = r"(src/[A-Za-z0-9_/]+\.rs)(?:\?[^)#\s>\"']*)?"
# #5396: CommonMark allows spaces, tabs and one line ending between `(` and the
# destination and again before `)`; a line ending after `(` is joined in the
# loop below (LINK_OPEN).
RELLINK = re.compile(r"\]\(\s*<?" + _SRC + r"(#[^)\s>]*)?>?" + _TITLE + r"\s*\)")
LINK_OPEN = re.compile(r"\]\(\s*$")
# #5269/#5343: two more relative-link forms to a src/ file: a markdown
# reference definition (`[h]: src/x.rs "title"`, also inside a blockquote or a
# list item; a destination on the NEXT line is joined in the loop below) and
# an HTML relative href (any case, spaces around `=`, quoted or not).
_REFDEF_HEAD = (r"^\s{0,3}(?:(?:>\s?|[-*+]\s+|\d{1,9}[.)]\s+)\s{0,3})*"
                r"\[[^\]\n]+\]:")
REFDEF = re.compile(
    _REFDEF_HEAD + r"\s*<?" + _SRC + r"(#[^\s>]*)?>?" + _TITLE + r"\s*$")
REFDEF_OPEN = re.compile(_REFDEF_HEAD + r"\s*$")
HREF = re.compile(
    r"\b(?i:href)\s*=\s*[\"']?" + _SRC + r"(#[^\"'\s>]*)?(?=[\"'\s>]|$)")
# #5189: the #L<a>[-L<b>] line fragment of such a link names lines too.
# Only a RELATIVE link is range-checked; a commit-pinned permalink (an
# https URL) is immutable and never reaches this rule.
LINEFRAG = re.compile(r"^#L(\d+)(?:C\d+)?(?:-L?(\d+)(?:C\d+)?)?$")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
AS_WORD = re.compile(r"\bas\b")


def unwrap_self_type(tok):
    """`<Type<T> as Trait>::m` -> `Type<T>::m` (the type is the claim); an
    `as` inside a nested argument (`<Vec<<T as Tr>::X>>::new`) counts too, and
    so does a group with no `as` that is followed by `::` (`<Type<T>>::m`)."""
    if not tok.startswith("<"):
        return tok
    end = scan_group(tok, 0)
    if end is None:
        return tok
    inner = tok[1:end - 1]
    m = ID_RE.match(inner.lstrip())
    # #5433: with no `as`, `<Type<T>>::m` is still a qualified path whose
    # type is the claim; a placeholder with nothing behind it is not.
    if m and (AS_WORD.search(inner) or tok.startswith("::", end)):
        return m.group(0) + tok[end:]
    return tok


def split_items(raw):
    """Split a qualified-anchor payload into symbol tokens at commas and
    whitespace that are NOT inside a generic group (`{A<T, U>::m, B}` is two
    items, not four)."""
    items, cur, depth = [], "", 0
    norm = raw.replace("&lt;", "<").replace("&gt;", ">")
    for idx, ch in enumerate(norm):
        if ch == "<":
            depth += 1
        elif ch == ">" and depth > 0 and not (idx and norm[idx - 1] == "-"):
            depth -= 1
        if depth == 0 and (ch == "," or ch.isspace()):
            if cur:
                items.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        items.append(cur)
    return items

# A line that DELIBERATELY names a path as absent is not a stale anchor.
# CLAUDE.md's worktree pre-flight literally asserts `test ! -f
# src/handlers.rs`; the whole point of those lines is that the file is
# gone. Same for prose narrating a split or a rename.
# Evaluated over a THREE-LINE WINDOW, because this repo hard-wraps
# prose at ~72 columns and the disclaimer routinely lands on the line
# ABOVE the path it disclaims ("... a pre-\n> modularisation snapshot of
# `src/handlers.rs` ..."). A line-local test would fire on exactly the
# sentences that say the file is gone.
ABSENT_ASSERTION = re.compile(
    r"test ! -f|no longer exists?|pre-?modularisation|pre-?modularization|"
    r"modularisation|modularization|monolithic|formerly|\bsplit (?:from|off)\b|\b(?:was|been|got) split\b(?!\s+(?:(?:up\s+)?into|out|across)\b)|pre-?split|"
    r"removed in|deleted in|STALE BASE|does not exist",
    re.IGNORECASE,
)
# #5264: wording that names a DESTINATION ("split into X", "split out X",
# "-> X") says the file AFTER it is live, so it must never exempt a missing
# file. It exempts only an anchor BEFORE it on the same line (the source,
# which the sentence says has gone: "`src/old.rs` was split into ...").
# #5344: "split up into", "split across" and "renamed to" are destination
# wording too: they say the path AFTER them is live, so they are positional
# (ABSENT_DEST) and no longer window-wide absence wording.
# #5341: an arrow is destination wording ONLY when a src/ path follows it
# (`-> `src/new.rs``); any other arrow (a Rust signature `-> u32`, an HTML
# comment end `-->`, a table cell `a -> b`) names no destination and must
# not exempt the missing file before it.
ABSENT_DEST = re.compile(
    r"\bsplit (?:(?:up )?into|out|across)\b|\brenamed to\b|(?:->|" + chr(0x2192) + r")(?=\s*`?(?:\.{0,2}/)*src/)",
    re.IGNORECASE)
# #5346: text that ends right before a link destination: `](`, `](<`,
# `href=`, `href="` or a reference definition `]:`.
ESCAPE_LINK_HEAD = re.compile(
    r"(?:\]\(\s*<?|\b(?i:href)\s*=\s*[\"']?|\]:\s*<?)$")


PIN_TARGET = re.compile(
    r"^https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/(src/[^#?\s]+)#L(\d+)(?:-L(\d+))?$")
LABEL_RANGE = re.compile(r"^-(\d+)(?=[\]<\s]|$)")


def pinned_label(line, m):
    """True when the BARE_LN match `m` is the label of a commit-pinned
    permalink whose path and line (or range) equal the label's:
    `[label](URL)` markdown or `<a href="URL">label</a>` HTML (#4651,
    #4670). A mismatched label is a finding."""
    start, end = m.start(), m.end()
    rest = line[end:]
    first = int(m.group(2))
    last = first
    rng = LABEL_RANGE.match(rest)
    if rng:
        last = int(rng.group(1))
        rest = rest[rng.end():]
    target = None
    md = LABEL_MD.match(rest)
    if md and line[:start].rfind("[") > line[:start].rfind("]"):
        target = md.group(1)
    elif LABEL_HTML.match(rest) and line[:start].rfind("<a ") >= 0:
        # #5215: borrow the href only when no closing tag lies between the
        # last opening <a and the anchor; otherwise the anchor is plain
        # text after an already-closed link, not that link's label.
        seg = line[line[:start].rfind("<a "):start]
        href = re.findall(r'href="([^"]*)"', seg) if "</a>" not in seg else []
        target = href[-1] if href else None
    if target is None:
        return False
    pt = PIN_TARGET.match(target)
    if pt is None:
        return False
    want_last = int(pt.group(3)) if pt.group(3) else int(pt.group(2))
    return pt.group(1) == m.group(1) and int(pt.group(2)) == first and want_last == last


def emit(rule, doc, ln, token, ctx):
    print(f"{rule}\t{doc}\t{ln}\t{token}\t{ctx[:150]}")


for doc in seen_docs:
    try:
        text = open(os.path.join(root, doc), encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    doc_lines = text.splitlines()
    for ln, line in enumerate(doc_lines, 1):
        ctx = line.strip()
        line, escapes = canon(line)
        window = "\n".join(doc_lines[max(0, ln - 2):ln + 1])
        absent_win = bool(ABSENT_ASSERTION.search(window))
        dest_at = [d.start() for d in ABSENT_DEST.finditer(line)]
        # A hard-wrapped sentence may put the arrow at the start of the NEXT
        # line ("`src/old.rs`\n-> `src/new/`"): the anchor above is a source.
        dest_next = ln < len(doc_lines) and bool(ABSENT_DEST.match(doc_lines[ln].lstrip()))

        def absent_ok_at(pos):
            """The absence exemption for an anchor starting at `pos`."""
            return absent_win or dest_next or any(pos < d for d in dest_at)

        for tok in dict.fromkeys(escapes):
            # #5346: judge EVERY occurrence of the token, not the first. A
            # qualified occurrence (`src/../x.rs::sym`) asserts the file
            # exists, like every qualified anchor (#5266), and a link target
            # (`](tok)`, `href=tok`, `[h]: tok`) is never an absence claim,
            # whatever wording is nearby: either one reports the token.
            for tm in re.finditer(re.escape(tok), line):
                at = tm.start()
                # #5396: a destination on the line after an open `](` or
                # `]:` is a link target too.
                # #5432: `]:` counts only at the start of a reference
                # definition, never at the end of prose.
                prev_line = doc_lines[ln - 2] if ln > 1 else ""
                next_line_dest = (ln > 1 and not line[:at].strip(" \t<")
                                  and bool(LINK_OPEN.search(prev_line)
                                           or REFDEF_OPEN.match(prev_line)))
                if (not absent_ok_at(at)
                        or line.startswith(tok + "::", at)
                        or ESCAPE_LINK_HEAD.search(line[:at])
                        or next_line_dest):
                    emit("PATH", doc, ln, tok, ctx)
                    break

        for m in PATH.finditer(line):
            f = m.group(1)
            if f not in per_file and not absent_ok_at(m.start(1)):
                emit("PATH", doc, ln, f, ctx)

        for m in PATHLN.finditer(line):
            f, n = m.group(1), int(m.group(2))
            last = int(m.group(3)) if m.group(3) else n
            if f not in per_file:
                if not absent_ok_at(m.start(1)):
                    emit("PATH", doc, ln, f, ctx)
            elif n < 1 or last < n or last > line_count[f]:
                tok = f"{f}:{n}" if m.group(3) is None else f"{f}:{n}-{last}"
                emit("LINE", doc, ln, tok, ctx)

        for m in BARE_LN.finditer(line):
            if pinned_label(line, m):
                continue
            emit("BARE_LN", doc, ln, f"{m.group(1)}:{m.group(2)}", ctx)

        for rule, f, raw in iter_quals(line):
            if f not in per_file:
                # #5201: a qualified anchor asserts the file exists, so the
                # absence-wording exemption never applies to it.
                emit("PATH", doc, ln, f, ctx)
                continue
            for tok in split_items(raw):
                # #5255/#5342: `Type<T, U>::method` checks BOTH components;
                # generic arguments are not symbol claims. `<Type as
                # Trait>::m` checks `Type` and `m`.
                tok = tok.replace("&lt;", "<").replace("&gt;", ">")
                tok = unwrap_self_type(tok)
                tok = strip_generics(tok).strip().rstrip("(){}[].,;")
                if "<" in tok or ">" in tok:
                    # An unbalanced group cannot be resolved: report it
                    # rather than skip a component that may be missing.
                    emit(rule, doc, ln, f"{f}::{tok}".replace(" ", ""), ctx)
                    continue
                if not tok:
                    continue
                for part in tok.split("::"):
                    part = part.split("(")[0].strip()
                    # `…`, `*`, `_`, generics and other prose fillers are
                    # not symbol claims.
                    if not part or not IDENT.match(part):
                        continue
                    if part in per_file[f]:
                        continue
                    # A trailing `_` is a PREFIX citation of a test/fn
                    # family (`issue_965_audit_*`); it resolves if any
                    # symbol in that file starts with it.
                    if part.endswith("_") and any(
                            n.startswith(part) for n in per_file[f]):
                        continue
                    emit(rule, doc, ln, f"{f}::{part}", ctx)

        # #5431: the joined line feeds MDLINK too, so a symbol label whose
        # destination is on the next line is checked like the one-line form.
        # #5396: a line that ends in an open `](` takes its destination from
        # the next line, as CommonMark does.
        link_line = line
        if LINK_OPEN.search(line) and ln < len(doc_lines):
            link_line = line.rstrip() + " " + canon(doc_lines[ln])[0].lstrip()
        for m in MDLINK.finditer(link_line):
            sym = m.group(1)
            tgt = m.group(2).split("#")[0]
            if tgt not in per_file:
                # A link to a missing file is a dead link whatever the
                # surrounding wording says: no absence exemption.
                emit("PATH", doc, ln, tgt, ctx)
            elif sym not in per_file[tgt]:
                emit("MDLINK", doc, ln, f"{tgt}::{sym}", ctx)

        # #5190: a relative link with a plain-text label must still point at
        # a file that exists. MDLINK already reported a backticked-label link.
        md_spans = [(m.start(2), m.end(2)) for m in MDLINK.finditer(link_line)]
        rel_hits = [(m.group(1), m.group(2), m.start(1), True)
                    for m in RELLINK.finditer(link_line)]
        # #5343: a reference definition may carry its destination on the
        # NEXT line (`[h]:` then `src/x.rs`); join the two before matching.
        refdef_line = line
        if REFDEF_OPEN.match(line) and ln < len(doc_lines):
            refdef_line = line.rstrip() + " " + canon(doc_lines[ln])[0].strip()
        rel_hits += [(m.group(1), m.group(2), m.start(1), False)
                     for m in REFDEF.finditer(refdef_line)]
        rel_hits += [(m.group(1), m.group(2), m.start(1), False)
                     for m in HREF.finditer(line)]
        for tgt, frag, start, is_md in rel_hits:
            if tgt in per_file and frag:
                fm = LINEFRAG.match(frag)
                if fm:
                    n = int(fm.group(1))
                    last = int(fm.group(2)) if fm.group(2) else n
                    if n < 1 or last < n or last > line_count[tgt]:
                        emit("LINE", doc, ln, f"{tgt}{frag}", ctx)
            if is_md and any(a <= start < b for a, b in md_spans):
                continue
            if tgt not in per_file:
                emit("PATH", doc, ln, tgt, ctx)

        # `migrate_vNN` claimed as the LADDER TIP must equal the tip the
        # migration-ladder gate computes. No new SSOT: the value comes
        # from that gate's own reader.
        if ladder_tip:
            for m in re.finditer(
                    r"(?:ladder (?:ends|end) at|ladder tip(?: is)?|tip is)\s*`?"
                    r"(?:[A-Za-z0-9_/.]*::)?migrate_v(\d+)", line, re.IGNORECASE):
                if m.group(1) != ladder_tip:
                    # Token is whitespace-free so the allowlist stays
                    # parseable; the tip lives in the failure detail.
                    emit("LADDER_TIP", doc, ln,
                         f"migrate_v{m.group(1)}!=migrate_v{ladder_tip}", ctx)
PY
)"; then
    # FAIL CLOSED (#2713): the analysis engine exited non-zero (an uncaught
    # exception — e.g. the injected self-test fault, or a logic error). The
    # pre-fix `|| true` swallowed that into an empty violation set and
    # printed a FALSE "PASS" the moment the burn-down allowlist emptied.
    printf 'FAIL: check-doc-symbol-anchors: analysis engine errored (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' >&2
    exit 2
fi

# ---- BURN-DOWN allowlist (STALE ENTRY FAILS) -------------------------
allow_keys=""
allow_used=""
fail_count=0

if [[ -f "$ALLOWLIST" ]]; then
    while IFS= read -r raw; do
        entry="${raw%%#*}"
        entry="$(printf '%s' "$entry" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -z "$entry" ]] && continue
        # shellcheck disable=SC2086
        set -- $entry
        if [[ $# -ne 2 ]] || ! grep -qE '#[0-9]+' <<<"$raw"; then
            printf 'FAIL: doc-symbol-anchors allowlist: malformed entry "%s"\n' "$raw" >&2
            printf '       expected: <doc-file> <anchor-token> #<issue>\n' >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        allow_keys="${allow_keys}${1}|${2}"$'\n'
    done < "$ALLOWLIST"
fi

if [[ -n "$violations" ]]; then
    while IFS=$'\t' read -r rule doc ln token ctx; do
        [[ -z "${rule:-}" ]] && continue
        if [[ "$rule" == "SETUP" ]]; then
            printf 'FAIL: doc-symbol-anchors: %s\n' "$ctx" >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        key="${doc}|${token}"
        if [[ -n "$allow_keys" ]] && grep -Fxq "$key" <<<"$allow_keys"; then
            allow_used="${allow_used}${key}"$'\n'
            continue
        fi
        case "$rule" in
            PATH)  detail="cited src/ path does not exist" ;;
            LINE)  detail="file:line anchor is out of range (line numbers are 1-based and must not pass end-of-file)" ;;
            QUAL)  detail="symbol is not defined in the file it is qualified against" ;;
            MDLINK) detail="markdown symbol link does not resolve in its target file" ;;
            BARE_QUAL) detail="symbol is not defined in the file it is qualified against (unbackticked anchor)" ;;
            BARE_LN) detail="bare file:line anchor in a live doc (rots silently); cite \`path::symbol\`, or pin a commit permalink" ;;
            LADDER_TIP) detail="claimed ladder tip disagrees with the tip scripts/check-migration-ladder.sh computes (left=cited, right=actual)" ;;
            *)     detail="unresolved anchor" ;;
        esac
        printf 'FAIL: doc-symbol-anchors [%s]: %s:%s cites "%s" — %s\n' \
            "$rule" "$doc" "$ln" "$token" "$detail" >&2
        printf '       context: %s\n' "$ctx" >&2
        fail_count=$((fail_count + 1))
    done <<<"$violations"
fi

# A STALE entry FAILS here. This ledger is a BURN-DOWN, not a
# pending-fix hold: nothing else in flight is correcting these anchors,
# so an entry that suppresses nothing is pure rot, and the #2494
# `required-contexts-joblevel-if-allow.txt` discipline applies —
# "a STALE entry also fails so the ledger cannot rot".
if [[ -n "$allow_keys" ]]; then
    while IFS= read -r k; do
        [[ -z "$k" ]] && continue
        if ! grep -Fxq "$k" <<<"$allow_used"; then
            printf 'FAIL: doc-symbol-anchors allowlist: STALE entry (suppresses nothing) — delete it: %s\n' \
                "$(tr '|' ' ' <<<"$k")" >&2
            fail_count=$((fail_count + 1))
        fi
    done < <(LC_ALL=C sort -u <<<"$allow_keys")
fi

if [[ "$fail_count" -gt 0 ]]; then
    printf '\n❌ doc symbol/path anchor gate: %d violation(s)\n' "$fail_count" >&2
    printf '   Repoint the anchor at HEAD, or cite the symbol without a line number.\n' >&2
    printf '   An anchor that misses is worse than no anchor (register 3.2, C-44/C-45/C-42/C-55/C-56).\n' >&2
    exit 1
fi
printf '✅ doc symbol/path anchor gate: PASS\n'
