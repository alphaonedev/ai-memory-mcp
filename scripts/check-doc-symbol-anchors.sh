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
# RULE TABLE. Every rule below is a row of the engine's RULES table, which
# also holds the detail text the gate prints for it; a rule that is not a
# row makes the engine error, and the --self-test census matches the table
# with this header both ways, counts included (#5680, #5783).
#
# SIX CHECKING RULES, all conservative, all keyed on PATH-QUALIFIED
# grammar so a bare backticked identifier in prose is never guessed at,
# and four REFUSALS (below) for what the gate cannot decide (#5680):
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
#            asserts the file exists (#5201). A raw identifier (`r#match`)
#            is looked up by its name and cited as written (#5778).
#            Self types and closers (#5457, #5493, #5498, #5530-#5537,
#            #5608-#5612): the type and every bound of `<dyn A + B>::m`,
#            `<A + B>::m`, `<&mut T>::m` or a lone `<*const T>` are checked
#            (a lifetime bound, `?Sized`, a `use<..>` bound and the empty
#            bound after a trailing `+` name no type and are skipped, #5767;
#            any other bound that is not a plain path is reported) and a self
#            type naming no type is refused; a closer after the anchor's own
#            group (attached, spaced, or an entity) is reported; whitespace
#            before or after any `::` is followed (#5609). A prose `<` opens
#            a group only when a type provably follows it; a closed code
#            span before the anchor is atomic text (#5608). The turbofish spellings
#            `Vec::<src/x.rs::T>::new`, `Arc<src/x.rs::T>::clone` and
#            `HashMap<u8, src/x.rs::T>::NoSuch` are all reported (fail
#            closed: the name after the closer may belong to Vec or Arc).
#   BARE_QUAL — the QUAL check on an UNBACKTICKED anchor (#5191),
#            reported under its own name; it is part of QUAL, not a seventh rule.
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
# REFUSALS. Where the gate cannot positively read an anchor it refuses
# it rather than pass it (fail closed, #5680):
#   UNDECIDABLE_REF — a line's character references decode differently
#            in CommonMark and HTML and any rule judges the two readings
#            differently (#5607, #5782); its qualified anchors are cited,
#            or with none, the tokens the readings disagree on.
#   UNDECIDABLE_LT — a prose `<` before it may or may not open a group,
#            and the anchor is judged differently either way (#5608).
#   UNMODELLED — a self type the gate cannot read, any Rust keyword
#            in a checked path (#5610, #5611), a raw identifier Rust
#            rejects (`r#crate`, `r#self`, `r#super`, `r#Self`, `r#_`,
#            #5778), a brace-list item or path component that is not an
#            identifier (punctuation, a digit, a glob, an empty item; an
#            ellipsis item is an elision and is skipped) or a path after a
#            brace list (#5779), a `::` followed by nothing the gate can
#            read, after the file head (#5698) or after a component
#            (#5780), an empty brace list (#5698), or a nested brace list
#            (`T::{a, b}`, each item checked as `T::a`, #5780) that is
#            empty, holds braces or is followed by `::`; a `src/` token
#            still holding a non-ASCII letter, mark, digit, private-use
#            or unassigned character (a variation selector, a combining
#            accent) after the text form (#5781).
#   SETUP  — the gate cannot do its job: a doc or source file in the
#            checked set cannot be read (#5616), or src/ has no Rust file.
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
# TEXT FORM. Before any rule runs, every Unicode format character
# (category Cf: a zero-width space, a word joiner, a soft hyphen, a bidi
# control) is dropped from the doc, the same as from a decoded character
# reference, and a line ends only at CR, LF or CRLF (#5781). Every rule
# then runs on the text a reader sees: a line holding a character
# reference is read as CommonMark and as HTML (an .html doc as HTML only),
# and a finding both readings make is reported (#5607, #5782).
#
# THE ABSENT-PATH EXEMPTION. A plain path or `path:line` anchor is not
# reported when absence wording ("no longer exists", "formerly",
# "monolithic", "pre-split", "was split from", "removed in", ...) is on its
# line or the line above or below, because such a line says the file is
# gone. A qualified `path::symbol` anchor, a link or a fragment is never
# exempt (#5201, #5250). Wording that names a DESTINATION ("split
# into", "split up into", "split across", "split out", "renamed to", an arrow
# before a `src/` path) exempts only an anchor BEFORE it on the same line
# (#5264, #5341, #5344).
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
    printf 'pub fn r#%s() {}\n' match > "$FIX/src/store/raw.rs"
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
    # (Kept red conservatively: CommonMark lets a definition interrupt no paragraph, so
    # this head after a prose line is not strictly a definition; #5459.)
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

    # #5456: prose that opens a generic BEFORE the anchor owns the closers
    # that follow the anchor's own groups; one closer more than the open
    # prose groups, or a `::` behind a closer, is still an over-closed group.
    anchor_green 5456 "a live generic anchor inside a prose generic" \
        "See Vec<$R::RecallTool<T>> here."
    anchor_green 5456 "a live generic anchor inside a prose generic, HTML entities" \
        "See Vec&lt;$R::RecallTool&lt;T&gt;&gt; here."
    anchor_green 5456 "a live generic anchor inside a prose generic opened in the same code span" \
        "See \`Arc<$R::RecallTool<T>>\`."
    anchor_green 5456 "a live generic anchor inside two prose generics" \
        "See Option<Vec<$R::RecallTool<T>>> here."
    # #5612: an unbalanced anchor is cited as written, generics kept.
    anchor_red_cites 5456 BARE_QUAL "a generic anchor over-closed beyond the prose generic" \
        "$R::RecallTool<T>>>" \
        "See Vec<$R::RecallTool<T>>> here."
    anchor_red_cites 5456 BARE_QUAL "a missing symbol is still named inside a prose generic" \
        "$R::NoSuch" \
        "See Vec<$R::NoSuch<T>> here."
    anchor_red 5456 BARE_QUAL "a path that continues past a closer inside a prose generic" \
        "See Vec<$R::RecallTool<T>>::decorate_memory_many> here."

    anchor_green 5456 "a live generic anchor after a stray closer in the prose" \
        "If a > b then see $R::RecallTool<T> here."

    # #5457: a self type that opens with dyn, impl or a reference names the
    # type behind that word, not the keyword.
    anchor_green 5457 "a dyn trait-object self type with live parts" \
        "See \`$R::<dyn RecallTool>::decorate_memory_many\`."
    anchor_green 5457 "a dyn self type with an as clause and live parts" \
        "See \`$R::<dyn RecallTool as Tr>::decorate_memory_many\`."
    anchor_green 5457 "an impl self type with live parts" \
        "See \`$R::<impl RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5457 QUAL "an impl self type whose trait is missing" \
        "$R::NoSuch" \
        "See \`$R::<impl NoSuch>::decorate_memory_many\`."
    anchor_green 5457 "a mutable reference self type with live parts" \
        "See \`$R::<&mut RecallTool>::decorate_memory_many\`."
    anchor_green 5457 "a lifetime reference self type with live parts" \
        "See \`$R::<&'a RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5457 QUAL "a dyn self type whose trait is missing" \
        "$R::NoSuch" \
        "See \`$R::<dyn NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5457 QUAL "a lifetime mutable reference self type whose type is missing" \
        "$R::NoSuch" \
        "See \`$R::<&'a mut NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5457 QUAL "a dyn self type with a live trait but a missing method" \
        "$R::no_such" \
        "See \`$R::<dyn RecallTool>::no_such\`."

    # #5494: one killing case per round-7 mutant of the closer depth (#5456)
    # and the self-type prefix (#5457).
    anchor_green 5494 "a prose generic after a stray closer keeps the depth at zero, not below" \
        "If a > b then see Vec<$R::RecallTool<T>> here."
    anchor_red 5494 BARE_QUAL "a closed prose generic no longer owns the closer after the anchor" \
        "See Vec<x> and $R::RecallTool<T>> here."
    anchor_green 5494 "a bare mut self type with live parts" \
        "See \`$R::<mut RecallTool>::decorate_memory_many\`."
    anchor_green 5494 "a stacked reference and dyn self type with live parts" \
        "See \`$R::<&dyn RecallTool>::decorate_memory_many\`."
    anchor_green 5494 "a stacked mutable reference and dyn self type with live parts" \
        "See \`$R::<&mut dyn RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5494 QUAL "a stacked reference and dyn self type whose trait is missing" \
        "$R::NoSuch" \
        "See \`$R::<&dyn NoSuch>::decorate_memory_many\`."

    # #5493: a lifetime or a ?Trait bound cannot stand in for the type of a
    # dyn self type; the type behind the bounds is checked, and a bound list
    # with no type at all is refused.
    anchor_red_cites 5493 QUAL "a dyn self type with a lifetime bound first and a missing trait" \
        "$R::NoSuch" \
        "See \`$R::<dyn 'a + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5493 QUAL "a dyn self type with a ?Sized bound first and a missing trait" \
        "$R::NoSuch" \
        "See \`$R::<dyn ?Sized + NoSuch>::decorate_memory_many\`."
    anchor_green 5493 "a dyn self type with a lifetime bound first and a live trait" \
        "See \`$R::<dyn 'a + RecallTool>::decorate_memory_many\`."
    anchor_green 5493 "a dyn self type with a live trait and a lifetime bound last" \
        "See \`$R::<dyn RecallTool + 'a>::decorate_memory_many\`."
    anchor_red 5493 QUAL "a dyn self type that is only a lifetime bound is refused" \
        "See \`$R::<dyn 'a>::decorate_memory_many\`."

    # #5533: the plus of a bound list needs no space around it.
    anchor_green 5533 "a dyn self type with an unspaced plus after a lifetime and a live trait" \
        "See \`$R::<dyn 'a+RecallTool>::decorate_memory_many\`."
    anchor_green 5533 "a dyn self type with a plus spaced on the left only" \
        "See \`$R::<dyn 'a +RecallTool>::decorate_memory_many\`."
    anchor_green 5533 "a dyn self type with a plus spaced on the right only" \
        "See \`$R::<dyn 'a+ RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5533 QUAL "a dyn self type with an unspaced plus and a missing trait" \
        "$R::NoSuch" \
        "See \`$R::<dyn 'a+NoSuch>::decorate_memory_many\`."

    # #5495: a pointer self type names the type behind `*const`/`*mut`; a
    # tuple, slice or other head with no leading type names none the gate can
    # check, so the anchor is refused rather than accepted.
    anchor_red_cites 5495 QUAL "a const pointer self type whose type is missing" \
        "$R::NoSuch" \
        "See \`$R::<*const NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5495 QUAL "a mutable pointer self type whose type is missing" \
        "$R::NoSuch" \
        "See \`$R::<*mut NoSuch>::decorate_memory_many\`."
    anchor_green 5495 "a const pointer self type with live parts" \
        "See \`$R::<*const RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5495 QUAL "a parenthesised self type is refused and reported with its whole token" \
        "$R::<(NoSuch)>::decorate_memory_many" \
        "See \`$R::<(NoSuch)>::decorate_memory_many\`."
    anchor_red 5495 QUAL "a slice self type is refused" \
        "See \`$R::<[NoSuch]>::decorate_memory_many\`."
    anchor_red 5495 QUAL "a tuple self type with an as clause is refused" \
        "See \`$R::<(NoSuch, u8) as Tr>::decorate_memory_many\`."
    anchor_red 5495 QUAL "a self type that opens with a nested group is refused" \
        "See \`$R::<<NoSuch as Tr>::X>::decorate_memory_many\`."

    # #5534: a refused self type is cited without the author's spaces, so one
    # anchor is reported one way whatever its spacing.
    anchor_red_cites 5534 QUAL "a spaced parenthesised self type is cited without spaces" \
        "$R::<(NoSuch)>::decorate_memory_many" \
        "See \`$R::<( NoSuch )>::decorate_memory_many\`."
    anchor_red_cites 5534 QUAL "a spaced tuple self type is cited without spaces" \
        "$R::<(NoSuch,u8)>::decorate_memory_many" \
        "See \`$R::<( NoSuch, u8 )>::decorate_memory_many\`."
    anchor_red_cites 5534 QUAL "a spaced slice self type is cited without spaces" \
        "$R::<[NoSuch]>::decorate_memory_many" \
        "See \`$R::<[ NoSuch ]>::decorate_memory_many\`."

    # #5496: a `::` right after a closer continues the path past the closer
    # whether or not the anchor has a generic of its own; the component behind
    # it is a claim, so the token is reported, not skipped.
    anchor_red 5496 BARE_QUAL "a path with no generic of its own, a closer inside a prose generic, then :: and a missing name" \
        "See Vec<$R::RecallTool>::NoSuch here."
    anchor_red 5496 BARE_QUAL "a path with no generic of its own, a lone closer, then :: and a missing name" \
        "See $R::RecallTool>::NoSuch here."
    anchor_red 5496 BARE_QUAL "a nested path component with no generic of its own, a closer, then :: and a missing name" \
        "See Vec<$R::RecallTool::decorate_memory_many>::NoSuch here."
    anchor_red 5496 BARE_QUAL "a path with no generic of its own, an entity closer, then :: and a missing name" \
        "See Vec&lt;$R::RecallTool&gt;::NoSuch here."
    anchor_green 5496 "a path with no generic of its own inside a prose generic and no :: after the closer" \
        "See Vec<$R::RecallTool> here."
    anchor_green 5496 "a path with no generic of its own followed by a closer and prose" \
        "See $R::RecallTool> and then more."

    # #5529: every closer in a run of closers counts before `::`, so a mutant
    # that stops after the first closer is killed by the nested prefix and by
    # the lone double closer.
    anchor_red 5529 BARE_QUAL "two closers inside a nested prose generic, then :: and a missing name" \
        "See Vec<Vec<$R::RecallTool>>::NoSuch here."
    anchor_red 5529 BARE_QUAL "a lone double closer, then :: and a missing name" \
        "See $R::RecallTool>>::NoSuch here."
    anchor_red 5529 BARE_QUAL "a lone triple closer, then :: and a missing name" \
        "See $R::RecallTool>>>::NoSuch here."

    # #5498: a prose comparison (`a < b`, `a <= b`) opens no generic group, so
    # it cannot absorb a real over-closing closer after the anchor.
    anchor_red 5498 BARE_QUAL "an over-closed anchor after a spaced less-than comparison" \
        "See a < b and $R::RecallTool<T>> here."
    anchor_red 5498 BARE_QUAL "an over-closed anchor after a less-or-equal comparison" \
        "See a <= b and $R::RecallTool<T>> here."
    anchor_red 5498 BARE_QUAL "an over-closed anchor after a tab-spaced comparison" \
        $'See a <\tb and '"$R"'::RecallTool<T>> here.'
    anchor_green 5498 "a live generic anchor inside a prose generic after a comparison" \
        "If a < b then see Vec<$R::RecallTool<T>> here."
    # The unspaced a<b cannot be told from a prose generic: it is counted as
    # an opener, so the extra closer after the anchor belongs to it.
    anchor_green 5498 "an unspaced comparison counted as a prose generic before an extra closer" \
        "If a<b then see $R::RecallTool<T>> here."

    # #5530: a `<` is a comparison only with whitespace on both sides, so a
    # `<` attached to a word with whitespace after it is never read as a
    # comparison. #5608: nor is it provably an opener (`x< y` is a valid
    # comparison too), so an anchor whose verdict depends on it is refused.
    anchor_red 5530 UNDECIDABLE_LT "a word-attached < with a space before the anchor" \
        "See Vec< $R::RecallTool<T>> here."
    anchor_red 5530 UNDECIDABLE_LT "a word-attached < with a tab before the anchor" \
        $'See Vec<\t'"$R"'::RecallTool<T>> here.'
    anchor_red 5530 UNDECIDABLE_LT "a word-attached < with two spaces before the anchor" \
        "See Vec<  $R::RecallTool<T>> here."
    anchor_red 5530 BARE_QUAL "an over-closed anchor right after a spaced comparison" \
        "See a < $R::RecallTool<T>> here."

    # #5531: a whitespace-delimited operator token made of the characters
    # `< > = - !` (`<<`, `<<=`, `<-`, an entity or non-breaking-space spacing)
    # is a comparison-like spelling that opens no generic group; a `<` attached
    # to a word, or whitespace written as an entity before an anchor, is still a
    # generic opener.
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a shift operator" \
        "See a << b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a shift-assign operator" \
        "See a <<= b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a left-arrow operator" \
        "See a <- b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a comparison spaced with a named entity" \
        "See a <&nbsp;b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a comparison spaced with a numeric entity" \
        "See a <&#32;b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a comparison spaced with a non-breaking space" \
        $'See a <\xc2\xa0b and '"$R"'::RecallTool<T>> here.'
    anchor_red 5531 BARE_QUAL "an over-closed anchor after an entity-spelled shift operator" \
        "See a &lt;&lt; b and $R::RecallTool<T>> here."
    # #5608: a word-attached `<` followed by whitespace is not provably an
    # opener, so the anchor whose verdict depends on it is refused.
    anchor_red 5531 UNDECIDABLE_LT "a word-attached < with a non-breaking-space entity before the anchor" \
        "See Vec<&nbsp;$R::RecallTool<T>> here."
    anchor_green 5531 "a generic opener attached to the anchor after a spaced word" \
        "See a <$R::RecallTool<T>> here."
    anchor_green 5531 "a word-attached less-than is a generic opener, not an operator token" \
        "See a <b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after an HTML comment opener" \
        "See <!-- a and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a comparison spaced with a thin-space entity" \
        "See a <&thinsp;b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a comparison spaced with an en-space entity" \
        "See a <&ensp;b and $R::RecallTool<T>> here."
    anchor_red 5531 BARE_QUAL "an over-closed anchor after a comparison spaced with an em-space entity" \
        "See a <&emsp;b and $R::RecallTool<T>> here."
    anchor_green 5531 "a decimal-entity angle bracket is not whitespace and opens a prose generic" \
        "See Vec&#60;$R::RecallTool<T>> here."

    # #5532: the only `?` bound is `?Sized`, and every bound AFTER the type of
    # a trait-object or impl bound list is checked like the type: a missing
    # name is reported, an unverifiable bound is refused.
    anchor_red_cites 5532 QUAL "a dyn self type with a missing trait after the live one" \
        "$R::NoSuch" \
        "See \`$R::<dyn RecallTool + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5532 QUAL "a dyn self type with an unspaced plus and a missing trait" \
        "$R::NoSuch" \
        "See \`$R::<dyn RecallTool+NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5532 QUAL "an impl self type with a missing trait after the live one" \
        "$R::NoSuch" \
        "See \`$R::<impl RecallTool + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5532 QUAL "a dyn self type with a missing trait behind a path of modules" \
        "$R::NoSuch" \
        "See \`$R::<dyn RecallTool + a::NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5532 QUAL "a dyn self type with a missing trait behind a higher-ranked binder" \
        "$R::NoSuch" \
        "See \`$R::<dyn RecallTool + for<'a> NoSuch>::decorate_memory_many\`."
    anchor_red 5532 QUAL "a dyn self type whose leading ? bound is not Sized is refused" \
        "See \`$R::<dyn ?NoSuch + RecallTool>::decorate_memory_many\`."
    anchor_red 5532 QUAL "a dyn self type whose trailing ? bound is not Sized is refused" \
        "See \`$R::<dyn RecallTool + ?NoSuch>::decorate_memory_many\`."
    anchor_red 5532 QUAL "a dyn self type with a sugared bound is refused" \
        "See \`$R::<dyn RecallTool + Fn(u8)>::decorate_memory_many\`."
    anchor_green 5532 "a dyn self type with a lifetime, a ?Sized bound and a trailing plus" \
        "See \`$R::<dyn RecallTool + 'a + ?Sized + >::decorate_memory_many\`."
    anchor_green 5532 "a dyn self type with two live traits" \
        "See \`$R::<dyn RecallTool + RecallTool>::decorate_memory_many\`."
    anchor_red 5532 QUAL "a dyn self type with an empty bound between two pluses is refused" \
        "See \`$R::<dyn RecallTool + + 'a>::decorate_memory_many\`."
    anchor_red 5532 QUAL "a dyn self type with a lifetime followed by a name is refused" \
        "See \`$R::<dyn RecallTool + 'a NoSuch>::decorate_memory_many\`."
    anchor_green 5532 "a dyn self type with two live traits and an as clause" \
        "See \`$R::<dyn RecallTool + RecallTool as RecallTool>::decorate_memory_many\`."

    # #5535: a self type group with nothing after it (no method) is still a
    # self type: its type is checked, and one that names no type is refused.
    anchor_red_cites 5535 QUAL "a lone pointer self type whose type is missing" \
        "$R::NoSuch" \
        "See \`$R::<*const NoSuch>\`."
    anchor_red_cites 5535 QUAL "a lone as-cast self type with a missing type" \
        "$R::NoSuch" \
        "See \`$R::<NoSuch as RecallTool>\`."
    anchor_red_cites 5535 QUAL "a lone dyn self type with a missing bound after the live trait" \
        "$R::NoSuch" \
        "See \`$R::<dyn RecallTool + NoSuch>\`."
    anchor_red 5535 QUAL "a lone tuple self type is refused" \
        "See \`$R::<(A, B)>\`."
    anchor_red 5535 QUAL "a lone slice self type is refused" \
        "See \`$R::<[u8]>\`."
    anchor_red 5535 QUAL "a lone lifetime self type is refused" \
        "See \`$R::<'a>\`."
    anchor_green 5535 "a lone self type that is a live type" \
        "See \`$R::<RecallTool>\`."
    anchor_green 5535 "a lone pointer self type with a live type" \
        "See \`$R::<*const RecallTool>\`."
    anchor_green 5535 "a lone dyn self type with a live trait" \
        "See \`$R::<dyn RecallTool>\`."
    anchor_red_cites 5535 BARE_QUAL "a lone dyn self type followed by a period names its missing trait" \
        "$R::NoSuch" \
        "See $R::<dyn NoSuch>. Next."
    anchor_red_cites 5535 BARE_QUAL "a lone pointer self type followed by a comma names its missing type" \
        "$R::NoSuch" \
        "See $R::<*const NoSuch>, next."

    # #5536: a group closer is a closer however it is written or spaced: a
    # numeric or upper-case entity is an angle bracket, and whitespace (space,
    # tab, non-breaking space, a whitespace entity) between the closers or
    # before `::` does not hide the path that continues past them.
    anchor_red 5536 BARE_QUAL "a missing name after a space-separated closer" \
        "See $R::RecallTool >::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after a closer then a space then ::" \
        "See $R::RecallTool> ::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after a closer spaced from the group" \
        "See $R::RecallTool<T> >::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after a tab-separated closer" \
        $'See '"$R"$'::RecallTool\t>::NoSuch here.'
    anchor_red 5536 BARE_QUAL "a missing name after a non-breaking-space-separated closer" \
        $'See '"$R"$'::RecallTool\xc2\xa0>::NoSuch here.'
    anchor_red 5536 BARE_QUAL "a missing name after an entity-spaced closer" \
        "See $R::RecallTool&nbsp;>::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after a decimal entity closer" \
        "See $R::RecallTool&#62;::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after a hexadecimal entity closer" \
        "See $R::RecallTool&#x3e;::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after an upper-case entity closer" \
        "See $R::RecallTool&GT;::NoSuch here."
    anchor_red 5536 BARE_QUAL "a missing name after a closer of a decimal-entity prose generic" \
        "See Vec&#60;$R::RecallTool&#62;::NoSuch here."
    anchor_red 5536 BARE_QUAL "an over-closed anchor whose group is written with decimal entities" \
        "See $R::RecallTool&#60;T&#62;>::decorate_memory_many here."
    anchor_green 5536 "a closer followed by prose that merely mentions a later path separator" \
        "See $R::RecallTool> and :: later here."
    anchor_green 5536 "a live anchor whose group is written with decimal entities" \
        "See $R::RecallTool&#60;T&#62;::decorate_memory_many here."
    anchor_green 5536 "a live anchor in a prose generic written with upper-case entities" \
        "See Vec&LT;$R::RecallTool&GT; here."
    anchor_green 5536 "a group followed by a spaced greater-than comparison" \
        "See $R::RecallTool<T> > 3 here."
    anchor_green 5536 "a prose generic opened with a hexadecimal entity" \
        "See Vec&#x3c;$R::RecallTool<T>> here."
    anchor_green 5536 "a prose generic opened with a zero-padded decimal entity" \
        "See Vec&#060;$R::RecallTool<T>> here."
    anchor_green 5536 "a decimal-entity group with a comma and a space inside" \
        "See $R::RecallTool&#60;T, U&#62;::decorate_memory_many here."
    anchor_green 5536 "a decimal-entity as clause self type with live names" \
        "See $R::&#60;RecallTool as RecallTool&#62;::decorate_memory_many here."
    anchor_red_cites 5536 BARE_QUAL "a decimal-entity as clause self type with a missing type names it" \
        "$R::NoSuch" \
        "See $R::&#60;NoSuch as RecallTool&#62;::decorate_memory_many here."
    anchor_red_cites 5536 BARE_QUAL "a missing type before a decimal-entity group names the type" \
        "$R::NoSuch" \
        "See $R::NoSuch&#60;T&#62;::decorate_memory_many here."

    # #5537: a higher-ranked binder (`for<'a>`) before a bound is skipped, so
    # the trait behind it is the name that is checked, not the word `for`.
    anchor_red_cites 5537 QUAL "a dyn self type behind a binder with a missing trait" \
        "$R::NoSuch" \
        "See \`$R::<dyn for<'a> NoSuch>::decorate_memory_many\`."
    anchor_green 5537 "a dyn self type behind a binder with a live trait" \
        "See \`$R::<dyn for<'a> RecallTool>::decorate_memory_many\`."
    anchor_green 5537 "a dyn self type behind a spaced binder with two lifetimes" \
        "See \`$R::<dyn for <'a, 'b> RecallTool>::decorate_memory_many\`."
    anchor_green 5537 "an impl self type behind a binder with a live trait" \
        "See \`$R::<impl for<'a> RecallTool>::decorate_memory_many\`."
    anchor_green 5537 "a reference to a dyn self type behind a binder" \
        "See \`$R::<&dyn for<'a> RecallTool>::decorate_memory_many\`."
    # #5537: a turbofish or an own-generic spelling around the anchor is
    # reported, consistently: the name after the closer may belong to Vec or
    # Arc, so the gate cannot tell it from a claim about the cited file.
    anchor_red 5537 BARE_QUAL "a turbofish around the anchor is reported" \
        "See Vec::<$R::RecallTool>::new here."
    anchor_red 5537 BARE_QUAL "an own-generic spelling around the anchor is reported" \
        "See Arc<$R::RecallTool>::clone here."
    anchor_red 5537 BARE_QUAL "a generic with a leading argument around the anchor is reported" \
        "See HashMap<u8, $R::RecallTool>::NoSuch here."

    # #5497: the header, ABSENT_DEST and the CLAUDE.md gate paragraph state the
    # same destination wording and the same never-exempt cases.
    for wording in "split into" "split up into" "split across" "split out" "renamed to" "a link or a fragment"; do
        python3 - "$SELF" "$ROOT/CLAUDE.md" "$wording" <<'PYEOF' || { echo "FAIL: self-test #5497 — \"$wording\" is missing from the header, ABSENT_DEST or CLAUDE.md" >&2; exit 1; }
import re, sys
self_path, claude_path, wording = sys.argv[1:4]
src = open(self_path, encoding="utf-8").read()
header = re.sub(r"\s+", " ", re.sub(r"(?m)^#", "", src.split("\nset -", 1)[0]))
dest = re.search(r"^ABSENT_DEST = re\.compile\(\n(.*?)re\.IGNORECASE\)", src, re.S | re.M)
claude = re.sub(r"\s+", " ", open(claude_path, encoding="utf-8").read())
ok = wording in header and wording in claude
if wording != "a link or a fragment":
    ok = ok and bool(dest) and all(w in dest.group(1) for w in wording.split())
sys.exit(0 if ok else 1)
PYEOF
        echo "PASS: self-test #5497 — the header and CLAUDE.md name \"$wording\""
    done

    # #5680/#5783: the census. The rules come from the engine's RULES table
    # (the one table emit() and the reporter use), read as Python, plus every
    # rule literal the engine emits or builds a finding with. The table and
    # the header rule lines must name the same rules both ways, the refusal
    # rows must be the header REFUSALS block, every literal must be a row,
    # and the header's counts of checking rules and refusals must equal the
    # table's.
    census_5680() {  # <script>
        python3 - "$1" <<'PYEOF'
import ast, re, sys
src = open(sys.argv[1], encoding="utf-8").read()
head, body = src.split("\nset -", 1)
engine = body.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
table = None
for node in ast.parse(engine).body:
    if (isinstance(node, ast.Assign) and len(node.targets) == 1
            and getattr(node.targets[0], "id", None) == "RULES"):
        table = ast.literal_eval(node.value)
if not table:
    print("no RULES table in the engine", file=sys.stderr)
    sys.exit(1)
used = set(re.findall(r'emit\("([A-Z][A-Z_]+)"', engine))
used |= set(re.findall(r'(?<![A-Za-z_])\("([A-Z][A-Z_]{2,})",\s', engine))
named = set(re.findall(r"(?m)^#   ([A-Z][A-Z_]+) +—", head))
refusal_block = head.split("# REFUSALS.", 1)[1].split("# PATH FORMS.", 1)[0]
refusals = set(re.findall(r"(?m)^#   ([A-Z][A-Z_]+) +—", refusal_block))
words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
         "seven": 7, "eight": 8, "nine": 9, "ten": 10}
checks_word = re.search(r"(?m)^# ([A-Z]+) CHECKING RULES", head)
refusals_word = re.search(r"and ([a-z]+) REFUSALS", head)
kinds = {k: v[0] for k, v in table.items()}
bad = []
if set(table) != named:
    bad.append(("table not in header", sorted(set(table) - named)))
    bad.append(("header not in table", sorted(named - set(table))))
if {k for k, v in kinds.items() if v == "refusal"} != refusals:
    bad.append(("refusal rows vs REFUSALS block", sorted(refusals)))
if not used <= set(table):
    bad.append(("emitted but not in table", sorted(used - set(table))))
if set(kinds.values()) - {"check", "part", "refusal"}:
    bad.append(("unknown kind", sorted(set(kinds.values()))))
if not checks_word or words.get(checks_word.group(1).lower()) != list(kinds.values()).count("check"):
    bad.append(("checking-rule count", checks_word and checks_word.group(1)))
if not refusals_word or words.get(refusals_word.group(1)) != list(kinds.values()).count("refusal"):
    bad.append(("refusal count", refusals_word and refusals_word.group(1)))
if len(table) < 11 or len(used) < 11:
    bad.append(("too few rules read", len(table), len(used)))
if bad:
    print("census:", bad, file=sys.stderr)
    sys.exit(1)
PYEOF
    }
    census_5680 "$SELF" || { echo "FAIL: self-test #5680 — the RULES table and the header disagree" >&2; exit 1; }
    echo "PASS: self-test #5680 — the RULES table and the header name the same rules and counts"

    # #5783: the census and emit() fail on each planted disagreement.
    plant_5783() {  # <old text> <new text> <out file>
        # The text is replaced where it occurs in the header (before the
        # self-test) or else in the engine (after the self-test), never in
        # the self-test's own arguments.
        python3 - "$SELF" "$1" "$2" "$3" <<'PYEOF'
import sys
s = open(sys.argv[1], encoding="utf-8").read()
head, rest = s.split("\nset -", 1)
pre, engine = rest.split("<<'PY'\n", 1)
if sys.argv[2] in head:
    head = head.replace(sys.argv[2], sys.argv[3], 1)
elif sys.argv[2] in engine:
    engine = engine.replace(sys.argv[2], sys.argv[3], 1)
else:
    sys.exit("plant_5783: text not found: " + sys.argv[2])
open(sys.argv[4], "w", encoding="utf-8").write(head + "\nset -" + pre + "<<'PY'\n" + engine)
PYEOF
    }
    census_red_5783() {  # <description> <old text> <new text>
        plant_5783 "$2" "$3" "$FIX/planted-5783.sh" || exit 1
        if census_5680 "$FIX/planted-5783.sh" 2>/dev/null; then
            echo "FAIL: self-test #5783 — the census passed $1" >&2; exit 1
        fi
        echo "PASS: self-test #5783 — the census fails $1"
    }
    census_red_5783 "a table row with no header line" \
        '    "SETUP": ("refusal",' '    "ZZ_EXTRA": ("part", "planted"),
    "SETUP": ("refusal",'
    census_red_5783 "a header line with no table row" \
        '#   SETUP  — the gate' '#   ZZ_EXTRA — planted.
#   SETUP  — the gate'
    census_red_5783 "a refusal row listed as a check" \
        '"SETUP": ("refusal",' '"SETUP": ("check",'
    census_red_5783 "a wrong count of checking rules" \
        '# SIX CHECKING RULES' '# FIVE CHECKING RULES'
    census_red_5783 "a wrong count of refusals" \
        'and four REFUSALS' 'and five REFUSALS'
    census_red_5783 "a finding built with a rule that is not a row" \
        'out.append(("BARE_LN",' 'out.append(("ZZ_UNLISTED",'
    plant_5783 'out.append(("BARE_LN",' 'out.append(("ZZ_UNLISTED",' "$FIX/planted-5783.sh" || exit 1
    chmod +x "$FIX/planted-5783.sh"
    write_clean
    printf '\n\nSee %s:1 here.\n' "$R" >> "$FIX/README.md"
    unl_rc=0
    unl_out="$(AI_MEMORY_SYMBOL_GATE_ROOT="$FIX" "$FIX/planted-5783.sh" 2>&1)" || unl_rc=$?
    [[ "$unl_rc" -eq 2 ]] && grep -q 'analysis engine errored' <<<"$unl_out" \
        && ! grep -q 'gate: PASS' <<<"$unl_out" || {
        echo "FAIL: self-test #5783 — a rule outside the RULES table did not fail closed (exit $unl_rc)" >&2
        printf '%s\n' "$unl_out" | sed 's/^/       /' >&2; exit 1; }
    rm -f "$FIX/planted-5783.sh"
    echo "PASS: self-test #5783 — a rule outside the RULES table FAILS CLOSED (exit 2, no PASS banner)"

    # #5765: every issue a refusal line of the header cites has a self-test
    # case of that rule filed under that issue, so a refusal cannot cite an
    # issue that never pinned it.
    python3 - "$SELF" <<'PYEOF' || { echo "FAIL: self-test #5765 — a refusal line cites an issue with no case of that rule" >&2; exit 1; }
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
head, body = src.split("\nset -", 1)
block = head.split("# REFUSALS.", 1)[1].split("# PATH FORMS.", 1)[0]
cited = {}
rule = None
for line in block.splitlines():
    m = re.match(r"#   ([A-Z][A-Z_]+) +—", line)
    if m:
        rule = m.group(1)
    if rule:
        cited.setdefault(rule, set()).update(re.findall(r"#(\d{4,})", line))
pairs = set(re.findall(r"anchor_red\w*\s+(\d+)\s+([A-Z][A-Z_]+)", body))
unread = re.search(r"unreadable_red\(\) \{.*?\n    \}", body, re.S)
if unread:
    pairs |= {(n, "SETUP") for n in re.findall(r"self-test #(\d+) — \$1 is REJECTED", unread.group(0))}
bad = sorted((r, n) for r, ns in cited.items() for n in ns if (n, r) not in pairs)
if len(cited) < 4 or bad:
    print("refusal citations with no case:", bad, "rules:", sorted(cited), file=sys.stderr)
    sys.exit(1)
PYEOF
    echo "PASS: self-test #5765 — every issue a refusal line cites has a case of that rule"

    # #5767: every bound _bound_tokens skips is named in the header. The
    # skips are read from the function (each regex a bound is matched
    # against before `continue`, and the trailing-plus skip), so a new skip
    # with no header wording fails here.
    python3 - "$SELF" <<'PYEOF' || { echo "FAIL: self-test #5767 — a bound the gate skips is not named in the header" >&2; exit 1; }
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
head, body = src.split("\nset -", 1)
header = re.sub(r"\s+", " ", re.sub(r"(?m)^#", "", head))
fn = re.search(r"\ndef _bound_tokens\(body\):\n(.*?)\n\n\n", body, re.S)
wording = {"_LIFETIME_BOUND": "a lifetime bound", "_SIZED_BOUND": "`?Sized`",
           "_USE_BOUND": "a `use<..>` bound", "trailing": "the empty bound after a trailing `+`"}
if not fn:
    sys.exit(1)
skips = set(re.findall(r"(_[A-Z_]+)\.match\(piece\)", fn.group(1)))
if "idx == len(pieces) - 1" in fn.group(1):
    skips.add("trailing")
bad = sorted(k for k in skips if k not in wording or wording[k] not in header)
if len(skips) < 4 or bad:
    print("skipped bounds the header does not name:", bad, "skips:", sorted(skips), file=sys.stderr)
    sys.exit(1)
PYEOF
    echo "PASS: self-test #5767 — the header names every bound the gate skips"

    # #5615: a changelog entry for this gate states what is decoded, refused
    # and unmodelled, not a closure the code does not have. The entry is read
    # from changelog.d, or from CHANGELOG.md once the fragments are compiled.
    changelog_wording() {  # <issue> <required text> <forbidden text>
        python3 - "$ROOT" "$1" "$2" "$3" <<'PYEOF' || { echo "FAIL: self-test #$1 — the changelog entry lacks \"$2\" or still says \"$3\"" >&2; exit 1; }
import os, re, sys
root, issue, need, ban = sys.argv[1:5]
frag = os.path.join(root, "changelog.d", issue + ".fixed.md")
src = frag if os.path.exists(frag) else os.path.join(root, "CHANGELOG.md")
try:
    text = open(src, encoding="utf-8").read()
except OSError:
    sys.exit(1)
entries = [e for e in re.split(r"\n\s*\n", text) if "(#" + issue + ")" in e]
ok = bool(entries) and all(need in e and ban not in e for e in entries)
sys.exit(0 if ok else 1)
PYEOF
        echo "PASS: self-test #$1 — the changelog entry names \"$2\" and not \"$3\""
    }
    # #5766: the 5530 entry names no mutant the script cannot have.
    changelog_wording 5530 "gains 4 cases (#5530)." "width-guard"
    changelog_wording 5531 "refused as \`UNDECIDABLE_LT\` (#5608)" "whitespace entities are read as whitespace"
    # #5617: the #5532 entry no longer overstates the fix.
    changelog_wording 5532 "checked from #5610" "every bound of a trait-object or impl self type"
    # #5618: the #5536 entry no longer overstates the fix.
    changelog_wording 5536 "followed from #5609" "recognised in every entity spelling"
    # #5619: the #5537 entry no longer overstates the fix.
    changelog_wording 5537 "until #5611" "now reported under the right name"

    # #5538: the word check above proves the wording is NAMED; these cases
    # prove ABSENT_DEST does not match wording it does not name, so a pattern
    # that keeps the words and changes the match is killed.
    anchor_red 5538 PATH "a missing path before \"split up out\" is not exempt" \
        'See `src/handlers.rs` split up out here.'
    anchor_red 5538 PATH "a missing path before \"split up across\" is not exempt" \
        'See `src/handlers.rs` split up across here.'
    anchor_red 5538 PATH "a missing path before \"renamed it later to\" is not exempt" \
        'See `src/handlers.rs` renamed it later to x here.'

    # #5616: a path in the doc or source set that cannot be read was never
    # checked, so the gate refuses it by name instead of passing it.
    unreadable_red() {  # <description> <relative path> <dir|mode0> <message>
        write_clean
        if [[ "$3" == dir ]]; then
            mkdir -p "$FIX/$2"
        else
            [[ -e "$FIX/$2" ]] || printf 'x\n' > "$FIX/$2"
            chmod 000 "$FIX/$2"
        fi
        local out rc
        out="$(run_fixture_out)"; rc="$(run_fixture)"
        if [[ "$3" == dir ]]; then rmdir "$FIX/$2"; else chmod 644 "$FIX/$2"; fi
        [[ "$rc" != "0" ]] || {
            echo "FAIL: self-test #5616 — $1 was ACCEPTED" >&2; exit 1; }
        grep -Fq "$4" <<<"$out" || {
            echo "FAIL: self-test #5616 — $1 rejected without naming it ($4)" >&2; exit 1; }
        echo "PASS: self-test #5616 — $1 is REJECTED"
    }
    # #5698: a qualified head followed by nothing the scanner reads is a
    # claim the gate has not understood; it is refused, not dropped.
    anchor_red_cites 5698 UNMODELLED "a qualified head at the end of a code span" \
        "$R::" "See \`$R::\` here."
    anchor_red_cites 5698 UNMODELLED "a glob after a qualified head" \
        "$R::*" "See \`$R::*\` here."
    anchor_red_cites 5698 UNMODELLED "an ampersand before a name after a qualified head" \
        "$R::&NoSuch" "See \`$R::&NoSuch\` here."
    anchor_red_cites 5698 UNMODELLED "a parenthesised name after a qualified head" \
        "$R::(NoSuch)" "See \`$R::(NoSuch)\` here."
    anchor_red_cites 5698 UNMODELLED "a name starting with a digit after a qualified head" \
        "$R::0NoSuch" "See \`$R::0NoSuch\` here."
    anchor_red_cites 5698 UNMODELLED "an empty brace list after a qualified head" \
        "$R::{}" "See \`$R::{}\` here."
    anchor_red_cites 5698 UNMODELLED "an unbackticked qualified head before a minus" \
        "$R::-NoSuch" "See $R::-NoSuch here."
    anchor_green 5698 "a live name after a qualified head" "See \`$R::RecallTool\` here."
    anchor_green 5698 "a live name in a one-item brace list" "See \`$R::{RecallTool}\` here."

    unreadable_red "a directory in place of a top-level doc" ROADMAP.md dir \
        "cannot read ROADMAP.md"
    unreadable_red "a directory matched by the docs glob" docs/x.md dir \
        "cannot read docs/x.md"
    unreadable_red "a directory matched by a recursive docs glob" docs/integrations/y.md dir \
        "cannot read docs/integrations/y.md"
    unreadable_red "a directory matched by the sdk glob" sdk/a/README.md dir \
        "cannot read sdk/a/README.md"
    unreadable_red "a directory matched by the source glob" src/z.rs dir \
        "cannot read src/z.rs"
    if [[ "$(id -u)" != "0" ]]; then
        unreadable_red "a doc with no read permission" SECURITY.md mode0 \
            "cannot read SECURITY.md"
        unreadable_red "a source file with no read permission" src/store/postgres.rs mode0 \
            "cannot read src/store/postgres.rs"
        rm -f "$FIX/SECURITY.md"
    fi

    # #5460: the type of an as group inside a brace item is a claim.
    anchor_red_cites 5460 QUAL "an as group with a missing type inside a brace item" \
        "$R::NoSuch" \
        "See \`$R::{<NoSuch as Tr>}\` x"
    anchor_green 5460 "an as group with a live type inside a brace item" \
        "See \`$R::{<RecallTool as Tr>}\` x"

    # #5459: a reference-definition head indented 4 or more spaces is an
    # indented code block, like the same-line form pinned by #5343, so the
    # line below it is not a link target (green). A tab-indented head is
    # still read as a head: the gate counts one tab as one column, stricter
    # than CommonMark's tab stop of 4, so the line below it is checked (red;
    # #5614 corrects this comment, which used to call both a code block).
    anchor_green 5459 "a 4-space indented definition head, then an absent escape path" \
        $'    [x]:\nsrc/../gone.rs no longer exists'
    anchor_red 5459 PATH "a tab-indented definition head (conservative: one tab counts as one space), then an escape path" \
        $'\t[x]:\nsrc/../gone.rs no longer exists'

    # #5606: a numeric reference for an angle bracket may carry leading zeros
    # (`&#062;`, `&#x003e;`); a padded closer or opener is read as the sign.
    anchor_red 5606 BARE_QUAL "a zero-padded decimal closer before a path separator" \
        "See $R::RecallTool<T>&#062;::NoSuch here."
    anchor_red 5606 BARE_QUAL "a zero-padded hex closer before a path separator" \
        "See $R::RecallTool&#x003e;::NoSuch here."
    anchor_red 5606 BARE_QUAL "a seven-digit zero-padded decimal closer" \
        "See $R::RecallTool<T>&#0000062;::NoSuch here."
    anchor_red 5606 BARE_QUAL "an upper-case X zero-padded hex closer" \
        "See $R::RecallTool<T>&#X03E;::NoSuch here."
    anchor_red_cites 5606 BARE_QUAL "a zero-padded decimal as group with a missing type" \
        "$R::NoSuch" \
        "See $R::&#060;NoSuch as RecallTool&#062;::decorate_memory_many here."
    anchor_red_cites 5606 BARE_QUAL "a zero-padded hex as group with a missing type" \
        "$R::NoSuch" \
        "See $R::&#x003C;NoSuch as RecallTool&#x0003E;::decorate_memory_many here."


    # #5607: every character reference is decoded with the full HTML5 table
    # before the anchor is read, so a whitespace reference outside the old
    # hand list (`&Tab;`, `&hairsp;` ...) no longer turns a spaced comparison
    # into a phantom group that absorbs a real over-closer.
    anchor_red 5607 BARE_QUAL "a comparison spaced with &Tab; before an over-closed anchor" \
        "See a <&Tab;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &hairsp; before an over-closed anchor" \
        "See a <&hairsp;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &NonBreakingSpace; before an over-closed anchor" \
        "See a <&NonBreakingSpace;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &ThinSpace; before an over-closed anchor" \
        "See a <&ThinSpace;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &numsp; before an over-closed anchor" \
        "See a <&numsp;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &emsp13; before an over-closed anchor" \
        "See a <&emsp13;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &NewLine; before an over-closed anchor" \
        "See a <&NewLine;b and $R::RecallTool<T>> here."
    anchor_red 5607 BARE_QUAL "a comparison spaced with &MediumSpace; before an over-closed anchor" \
        "See a <&MediumSpace;b and $R::RecallTool<T>> here."
    anchor_red_cites 5607 BARE_QUAL "a zero-width space reference renders as nothing" \
        "$R::NoSuch" \
        "See $R::RecallTool&ZeroWidthSpace;::NoSuch here."
    # #5607: a reference HTML decodes and CommonMark keeps literal (no `;`,
    # more than 7 decimal or 6 hex digits) is undecidable in a Markdown doc
    # when the two readings judge the anchor differently: it is refused.
    anchor_red 5607 UNDECIDABLE_REF "a non-breaking space with no semicolon before an over-closed anchor" \
        "See a <&nbsp b and $R::RecallTool<T>> here."
    anchor_red_cites 5607 UNDECIDABLE_REF "a decimal closer with no semicolon is cited as written" \
        "$R::RecallTool&#62::NoSuch" \
        "See $R::RecallTool&#62::NoSuch here."
    anchor_red 5607 UNDECIDABLE_REF "an eight-digit decimal closer" \
        "See $R::RecallTool<T>&#00000062;::NoSuch here."
    anchor_red 5607 UNDECIDABLE_REF "a seven-digit hex closer" \
        "See $R::RecallTool<T>&#x000003e;::NoSuch here."
    anchor_green 5607 "a legacy reference with no semicolon beside a live anchor" \
        "Copyright &copy 2026 and $R::RecallTool<T> here."
    anchor_green 5607 "an ampersand reference after a live anchor" \
        "See $R::RecallTool&amp; here."
    anchor_green 5607 "an escaped angle reference is decoded once, never twice" \
        "See $R::RecallTool&amp;lt;T&amp;gt; here."
    # #5607: CommonMark keeps a backslash-escaped reference literal while HTML
    # decodes it, so the two readings differ and the anchor is refused.
    anchor_red 5607 UNDECIDABLE_REF "a backslash-escaped opener reference before an over-closed anchor" \
        "See \&lt;$R::RecallTool<T>> here."
    anchor_red_cites 5607 UNDECIDABLE_REF "a refused anchor with a space after its separator" \
        "$R::\&lt;NoSuch" "See $R:: \&lt;NoSuch here."
    # A decoded backtick is text, never a code-span delimiter, and a decoded
    # line feed inside a group is whitespace, never the end of the anchor.
    anchor_red 5607 BARE_QUAL "a backtick reference around an anchor" \
        "See &#96;$R::NoSuch&#96; here."
    anchor_red_cites 5607 BARE_QUAL "a line-feed reference inside a generic group" \
        "$R::NoSuch" "See $R::RecallTool<T&#10;>::NoSuch here."
    # An .html doc has the HTML reading only: a legacy closer with no
    # semicolon is decoded and reported, never refused as undecidable.
    write_clean
    mkdir -p "$FIX/docs"
    printf 'See %s::RecallTool<T>&gt::NoSuch here.\n' "$R" > "$FIX/docs/x.html"
    html_out="$(run_fixture_out)"; html_rc="$(run_fixture)"
    rm -f "$FIX/docs/x.html"
    [[ "$html_rc" != "0" ]] || {
        echo "FAIL: self-test #5607 — a legacy closer in an .html doc was ACCEPTED" >&2; exit 1; }
    grep -Fq "[BARE_QUAL]: docs/x.html" <<<"$html_out" && ! grep -Fq "[UNDECIDABLE_REF]" <<<"$html_out" || {
        echo "FAIL: self-test #5607 — a legacy closer in an .html doc was not read the HTML way" >&2; exit 1; }
    echo "PASS: self-test #5607 — a legacy closer in an .html doc is REJECTED as BARE_QUAL"


    # #5608: a `<` written in a closed code span is atomic code, never a
    # prose opener; a `<` is an opener only when a type provably follows it,
    # and an anchor whose verdict depends on any other `<` is refused.
    anchor_red 5608 BARE_QUAL "a less-than in a code span before an over-closed anchor" \
        "Use the \`<\` operator; see $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a quoted less-than before an over-closed anchor" \
        "Use the \"<\" sign; see $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a parenthesised less-than before an over-closed anchor" \
        "Use (<) and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a less-than before a negative number" \
        "See x <-1 and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a single-quoted less-than" \
        "See '<' and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a bracketed less-than" \
        "See [<] and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a less-or-equal before a digit" \
        "See x <=1 and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a word-attached less-than before a comma" \
        "See x<, and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a word-attached less-than before a minus" \
        "See x<-y and $R::RecallTool<T>> here."
    anchor_red 5608 UNDECIDABLE_LT "a spaced less-than before a digit" \
        "See x <1 and $R::RecallTool<T>> here."
    anchor_red 5608 QUAL "an over-closed backticked anchor after a prose opener" \
        "See a <b and \`$R::RecallTool<T>>\` here."
    anchor_green 5608 "a code-span less-than before a balanced anchor" \
        "Use the \`<\` operator; see $R::RecallTool<T> here."
    anchor_green 5608 "a less-than before a negative number and a live path" \
        "See x <-1 and $R::RecallTool<T>::decorate_memory_many here."
    anchor_green 5608 "a prose generic inside the same code span as the anchor" \
        "See \`Vec<$R::RecallTool<T>>\` here."
    anchor_green 5608 "a prose generic with a lifetime argument before the anchor" \
        "See Vec<'a, $R::RecallTool<T>> here."
    anchor_green 5608 "a prose generic whose argument is a reference type" \
        "See x<&y and $R::RecallTool<T>> here."
    anchor_green 5769 "a prose generic opened by a question-mark bound before the anchor" \
        "See Box<?Sized $R::RecallTool<u8>> here."

    # #5609: whitespace before or after `::` continues a path, as Rust
    # reads it; it never ends the anchor before a missing component.
    anchor_red_cites 5609 BARE_QUAL "a space between a group closer and the path separator" \
        "$R::NoSuch" "See $R::RecallTool<T> ::NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a tab between a group closer and the path separator" \
        "$R::NoSuch" "See $R::RecallTool<T>	::NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a no-break space entity before the path separator" \
        "$R::NoSuch" "See $R::RecallTool<T>&nbsp;::NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a decimal space reference before the path separator" \
        "$R::NoSuch" "See $R::RecallTool<T>&#32;::NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a hex space reference before the path separator" \
        "$R::NoSuch" "See $R::RecallTool<T>&#x20;::NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a tab entity before the path separator" \
        "$R::NoSuch" "See $R::RecallTool<T>&Tab;::NoSuch here."
    anchor_red_cites 5609 QUAL "a backticked anchor with a space before the separator" \
        "$R::NoSuch" "See \`$R::RecallTool<T> ::NoSuch\`."
    anchor_red_cites 5609 QUAL "a self type followed by two spaces and the separator" \
        "$R::NoSuch" "See \`$R::<dyn RecallTool>  ::NoSuch\`."
    anchor_red_cites 5609 BARE_QUAL "a plain component with a space before the separator" \
        "$R::NoSuch" "See $R::RecallTool ::NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "spaces on both sides of the separator" \
        "$R::NoSuch" "See $R::decorate_memory_many :: NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a space after the separator" \
        "$R::NoSuch" "See $R::RecallTool<T>:: NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a space after the file separator" \
        "$R::NoSuch" "See $R:: NoSuch here."
    anchor_red_cites 5609 BARE_QUAL "a space between the file and its separator" \
        "$R::NoSuch" "See $R ::NoSuch here."
    anchor_red_cites 5609 QUAL "a placeholder-shaped self type with a spaced separator" \
        "$R::NoSuchType" "See \`$R::<NoSuchType> ::decorate_memory_many\`."
    anchor_green 5609 "a live path with a space before the separator" \
        "See $R::RecallTool<T> ::decorate_memory_many here."
    anchor_green 5609 "a path followed by a spaced separator in prose" \
        "See $R::RecallTool and :: in C++."
    anchor_red_cites 5609 QUAL "a space between the file and its separator" \
        "$R::NoSuch" "See \`$R ::NoSuch\` here."
    anchor_red_cites 5609 QUAL "a space between the separator and a brace list" \
        "$R::NoSuch" "See \`$R:: {NoSuch}\` here."

    # #5610: every bound of a self type is checked whatever its prefix, the
    # type is a whole path, and a form the reader does not model is refused.
    anchor_red_cites 5610 QUAL "a bare trait-object self type with a missing second bound" \
        "$R::NoSuch" "See \`$R::<RecallTool + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5610 QUAL "a bare bound list with a lifetime before the missing bound" \
        "$R::NoSuch" "See \`$R::<RecallTool + 'a + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5610 QUAL "a lone bare bound list" \
        "$R::NoSuch" "See \`$R::<RecallTool + NoSuch>\`."
    anchor_red_cites 5610 QUAL "an unspaced bare bound list" \
        "$R::NoSuch" "See \`$R::<RecallTool+NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5610 QUAL "a generic first bound before a missing bound" \
        "$R::NoSuch" "See \`$R::<RecallTool<T> + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5610 QUAL "a rooted first bound before a missing bound" \
        "$R::NoSuch" "See \`$R::<::RecallTool + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5610 QUAL "a missing component inside the self type path" \
        "$R::NoSuch" "See \`$R::<RecallTool::NoSuch>::decorate_memory_many\`."
    anchor_red 5610 UNMODELLED "two words in a self type" \
        "See \`$R::<RecallTool NoSuch>::decorate_memory_many\`."
    anchor_red 5610 UNMODELLED "a sugared Fn self type" \
        "See \`$R::<dyn Fn(NoSuch)>::decorate_memory_many\`."
    anchor_green 5610 "a spaced lone self type naming a live type" \
        "See \`$R::< RecallTool >\`."
    anchor_green 5610 "a bare bound list of live types" \
        "See \`$R::<RecallTool + RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5610 QUAL "a placeholder with a trailing space is a self type" \
        "$R::NoSuch" "See \`$R::<NoSuch >\` here."

    # #5611: a keyword is never a symbol: an anchor with one in its path is
    # refused as UNMODELLED, and a precise-capturing use bound is skipped.
    anchor_green 5611 "a precise-capturing bound after an impl self type" \
        "See \`$R::<impl RecallTool + use<'a>>::decorate_memory_many\`."
    anchor_green 5611 "an empty precise-capturing bound" \
        "See \`$R::<impl RecallTool + use<>>::decorate_memory_many\`."
    anchor_red_cites 5611 QUAL "a missing bound after a precise-capturing bound" \
        "$R::NoSuch" "See \`$R::<impl RecallTool + use<'a, T> + NoSuch>::decorate_memory_many\`."
    anchor_red_cites 5611 UNMODELLED "a function-pointer self type" \
        "$R::<fn(u8)>::decorate_memory_many" "See \`$R::<fn(u8)>::decorate_memory_many\`."
    anchor_red 5611 UNMODELLED "a lone function-pointer self type" \
        "See \`$R::<fn(NoSuch)>\`."
    anchor_red 5611 UNMODELLED "a lone unsafe function-pointer self type" \
        "See \`$R::<unsafe fn(NoSuch)>\`."
    anchor_red 5611 UNMODELLED "a lone extern function-pointer self type" \
        "See \`$R::<extern \"C\" fn(NoSuch)>\`."
    anchor_red_cites 5611 UNMODELLED "a lone keyword is not a placeholder" \
        "$R::<fn>" "See \`$R::<fn>\`."
    anchor_red_cites 5611 UNMODELLED "a crate-rooted path" \
        "$R::crate::RecallTool" "See \`$R::crate::RecallTool\`."
    anchor_red_cites 5611 UNMODELLED "a crate-rooted self type" \
        "$R::<crate::RecallTool>::decorate_memory_many" "See \`$R::<crate::RecallTool>::decorate_memory_many\`."
    anchor_red 5611 UNMODELLED "a crate-rooted bound" \
        "See \`$R::<dyn RecallTool + crate::RecallTool>::decorate_memory_many\`."
    anchor_red_cites 5611 UNMODELLED "a keyword as the last component" \
        "$R::RecallTool::fn" "See \`$R::RecallTool::fn\`."
    anchor_red_cites 5768 UNMODELLED "a lone 2024 gen keyword is not a placeholder" \
        "$R::<gen>" "See \`$R::<gen>\`."
    anchor_red_cites 5768 UNMODELLED "the 2024 gen keyword as the last component" \
        "$R::RecallTool::gen" "See \`$R::RecallTool::gen\`."
    anchor_red_cites 5611 UNMODELLED "a self-rooted bare path" \
        "$R::self::RecallTool" "See $R::self::RecallTool here."
    anchor_red_cites 5611 UNMODELLED "a Self self type" \
        "$R::<Self>::decorate_memory_many" "See \`$R::<Self>::decorate_memory_many\`."
    anchor_red_cites 5611 UNMODELLED "a keyword brace item" \
        "$R::fn" "See \`$R::{RecallTool, fn}\`."
    anchor_red_cites 5611 UNMODELLED "a lone use keyword is not a placeholder" \
        "$R::<use>" "See \`$R::<use>\` here."

    # #5612 (and review item N-3): a cited token is the anchor as written,
    # whitespace removed, generics kept, never cut at a tab or a separator.
    anchor_red_cites 5612 BARE_QUAL "a spaced over-closer is cited with its type" \
        "$R::RecallTool>::NoSuch" "See $R::RecallTool >::NoSuch here."
    anchor_red_cites 5612 BARE_QUAL "a no-break space entity before an over-closer" \
        "$R::RecallTool>::NoSuch" "See $R::RecallTool&nbsp;>::NoSuch here."
    anchor_red_cites 5612 BARE_QUAL "an entity over-closer keeps the generic in the citation" \
        "$R::RecallTool<T>>::NoSuch" "See $R::RecallTool<T>&#62;::NoSuch here."
    anchor_red_cites 5612 BARE_QUAL "a space after the separator behind an over-closer" \
        "$R::RecallTool<T>>::NoSuch" "See $R::RecallTool<T> >:: NoSuch here."
    anchor_red_cites 5612 BARE_QUAL "a closer then a spaced separator names the component" \
        "$R::RecallTool>::NoSuch" "See $R::RecallTool> ::NoSuch here."
    anchor_red_cites 5612 BARE_QUAL "a tab before an over-closer" \
        "$R::RecallTool<T>>::NoSuch" "See $R::RecallTool<T>	>::NoSuch here."
    anchor_red_cites 5612 QUAL "tabs inside a refused self type" \
        "$R::<(NoSuch)>::decorate_memory_many" "See \`$R::<(	NoSuch	)>::decorate_memory_many\`."
    anchor_red_cites 5612 QUAL "tabs inside a lone refused self type" \
        "$R::<(NoSuch)>" "See \`$R::<(	NoSuch	)>\`."
    anchor_red_cites 5612 BARE_QUAL "a numeric plus entity between bounds" \
        "$R::NoSuch" "See <code>$R::&lt;dyn RecallTool &#43; NoSuch&gt;::decorate_memory_many</code> here."
    anchor_red_cites 5612 BARE_QUAL "a named plus entity between bounds" \
        "$R::NoSuch" "See <code>$R::&lt;dyn RecallTool &plus; NoSuch&gt;::decorate_memory_many</code> here."
    anchor_red_cites 5612 QUAL "an unclosed self type keeps the component behind a spaced separator" \
        "$R::<RecallTool::NoSuch" "See \`$R::<RecallTool:: NoSuch\` here."

    # #5778: a raw identifier is one component, looked up by its name and
    # cited as written; one Rust rejects is refused; a raw link label is read.
    anchor_green 5778 "a raw identifier defined raw" "See \`src/store/raw.rs::r#match\` here."
    anchor_green 5778 "a raw spelling of a plain name" "See \`$R::RecallTool::r#decorate_memory_many\`."
    anchor_red_cites 5778 QUAL "a missing raw identifier is cited with its prefix" \
        "$R::r#no_such" "See \`$R::RecallTool::r#no_such\`."
    anchor_red_cites 5778 UNMODELLED "a raw identifier Rust rejects" \
        "$R::r#crate::RecallTool" "See \`$R::r#crate::RecallTool\`."
    anchor_red_cites 5778 MDLINK "a raw link label that does not resolve" \
        "$R::r#no_such" "See [\`r#no_such\`]($R)."
    anchor_green 5778 "a raw link label that resolves" "See [\`r#match\`](src/store/raw.rs)."

    # #5779: every brace-list item and component is read or refused.
    anchor_red_cites 5779 UNMODELLED "an ampersand brace item" \
        "$R::&NoSuch" "See \`$R::{RecallTool, &NoSuch}\`."
    anchor_red_cites 5779 UNMODELLED "a parenthesised brace item" \
        "$R::(NoSuch)" "See \`$R::{RecallTool, (NoSuch)}\`."
    anchor_red_cites 5779 UNMODELLED "a brace item starting with a digit" \
        "$R::9NoSuch" "See \`$R::{RecallTool, 9NoSuch}\`."
    anchor_red_cites 5779 UNMODELLED "a brace item starting with a minus" \
        "$R::-NoSuch" "See \`$R::{RecallTool, -NoSuch}\`."
    anchor_red_cites 5779 UNMODELLED "a glob inside a brace item" \
        "$R::RecallTool::*" "See \`$R::{decorate_memory_many, RecallTool::*}\`."
    anchor_red_cites 5779 UNMODELLED "an empty brace item" \
        "$R::{RecallTool,,NoSuch}" "See \`$R::{RecallTool, , NoSuch}\`."
    anchor_red_cites 5779 UNMODELLED "a path after a brace list" \
        "$R::{RecallTool,decorate_memory_many}::NoSuch" "See \`$R::{RecallTool, decorate_memory_many}::NoSuch\`."
    anchor_green 5779 "an elision brace item" "See \`$R::{RecallTool, …}\`."
    anchor_green 5779 "a turbofish before the last component" \
        "See \`$R::RecallTool::<u8>::decorate_memory_many\`."

    # #5780: a later `::` is read or refused; a nested brace list is read.
    anchor_red_cites 5780 UNMODELLED "an ampersand after a later separator" \
        "$R::RecallTool::&NoSuch" "See \`$R::RecallTool::&NoSuch\`."
    anchor_red_cites 5780 UNMODELLED "a parenthesis after a later separator" \
        "$R::RecallTool::(NoSuch)" "See \`$R::RecallTool::(NoSuch)\`."
    anchor_red_cites 5780 UNMODELLED "a digit after a later separator" \
        "$R::RecallTool::9NoSuch" "See \`$R::RecallTool::9NoSuch\`."
    anchor_red_cites 5780 UNMODELLED "a glob after a later separator" \
        "$R::RecallTool::*" "See \`$R::RecallTool::*\`."
    anchor_red_cites 5780 UNMODELLED "a later separator at the end of a code span" \
        "$R::RecallTool::" "See \`$R::RecallTool::\`."
    anchor_red_cites 5780 QUAL "a missing item in a nested brace list" \
        "$R::NoSuch" "See \`$R::RecallTool::{decorate_memory_many, NoSuch}\`."
    anchor_green 5780 "a nested brace list of live items" \
        "See \`$R::RecallTool::{decorate_memory_many, RecallTool}\`."
    anchor_red_cites 5780 UNMODELLED "a path after a nested brace list" \
        "$R::RecallTool::{decorate_memory_many,RecallTool}::NoSuch" \
        "See \`$R::RecallTool::{decorate_memory_many, RecallTool}::NoSuch\`."
    anchor_red_cites 5780 UNMODELLED "an empty nested brace list" \
        "$R::RecallTool::{}" "See \`$R::RecallTool::{}\`."

    # #5781: literal text reaches the same normal form as decoded text. The
    # characters are written as UTF-8 bytes so the case holds in any locale.
    ZW=$'\xe2\x80\x8b' SHY=$'\xc2\xad' WJ=$'\xe2\x81\xa0' \
        RLO=$'\xe2\x80\xae' VS=$'\xef\xb8\x8f' LS=$'\xe2\x80\xa8'
    anchor_red_cites 5781 QUAL "a zero-width space before a later separator" \
        "$R::NoSuch" "See \`$R::RecallTool${ZW}::NoSuch\`."
    anchor_red_cites 5781 QUAL "a zero-width space after the file" \
        "$R::NoSuch" "See \`$R${ZW}::NoSuch\`."
    anchor_red_cites 5781 QUAL "a zero-width space inside the symbol" \
        "$R::NoSuch" "See \`$R::No${ZW}Such\`."
    anchor_red_cites 5781 BARE_QUAL "a soft hyphen in a bare anchor" \
        "$R::NoSuch" "See $R::No${SHY}Such here."
    anchor_red_cites 5781 QUAL "a word joiner before a later separator" \
        "$R::NoSuch" "See \`$R::Recall${WJ}Tool::NoSuch\`."
    anchor_red_cites 5781 QUAL "a bidi control before the symbol" \
        "$R::NoSuch" "See \`$R::${RLO}NoSuch\`."
    anchor_red_cites 5781 PATH "a zero-width space inside a missing path" \
        "src/nosuch.rs" "See \`src/no${ZW}such.rs\`."
    anchor_red_cites 5781 UNMODELLED "a variation selector glued to the file" \
        "$R${VS}::NoSuch" "See \`$R${VS}::NoSuch\`."
    CA=$'\xcc\x81' PU=$'\xee\x80\x80'
    anchor_red_cites 5781 UNMODELLED "a combining accent glued to a symbol" \
        "$R::RecallTool${CA}" "See \`$R::RecallTool${CA}\`."
    anchor_red_cites 5781 UNMODELLED "a private-use character glued to a symbol" \
        "$R::NoSuch${PU}" "See \`$R::NoSuch${PU}\`."
    anchor_red_cites 5781 QUAL "a line separator before a later separator" \
        "$R::NoSuch" "See \`$R::RecallTool${LS}::NoSuch\`."
    anchor_green 5781 "a zero-width space inside a live anchor" \
        "See \`$R::Recall${ZW}Tool\`."

    # #5782: every per-line rule runs on each reading of the line, so a
    # path written with character references is checked like its literal.
    anchor_red_cites 5782 PATH "an entity-spelled dot-dot segment before a qualified anchor" \
        "src/../x.rs" "See \`src/&#46;&#46;/x.rs::NoSuch\`."
    anchor_red_cites 5782 PATH "an entity-spelled underscore in a missing path" \
        "src/no_such.rs" "See \`src/no&#95;such.rs\`."
    anchor_red_cites 5782 LINE "an entity-spelled dot before a line number" \
        "$R:9999" "See \`src/mcp/tools/recall&#46;rs:9999\`."
    anchor_red_cites 5782 BARE_LN "an entity-spelled colon before a line number" \
        "$R:1" "See $R&#58;1 here."
    anchor_red_cites 5782 MDLINK "an entity-spelled dot in a symbol link target" \
        "$R::NoSuch" "See [\`NoSuch\`](src/mcp/tools/recall&#46;rs) here."
    anchor_red_cites 5782 UNDECIDABLE_REF "a path the two readings decode differently" \
        "src/no_such.rs" "See \`src/no&#95such.rs\`."
    anchor_green 5782 "an entity-spelled dot in a live path" \
        "See \`src/mcp/tools/recall&#46;rs\`."

    # #5613 (review item N-2): pin the #5536 repro and its self-type sibling
    # so that every spaced closer is counted and a spaced extra closer after a
    # self type still continues the path.
    anchor_red 5613 BARE_QUAL "the #5536 repro: a spaced extra closer and a spaced separator" \
        "See $R::RecallTool<T> > ::NoSuch here."
    anchor_red 5613 BARE_QUAL "a plain component, a spaced closer and a spaced separator" \
        "See $R::RecallTool > ::NoSuch here."
    anchor_red 5613 BARE_QUAL "two spaced extra closers" \
        "See $R::RecallTool<T> > > ::NoSuch here."
    anchor_red 5613 QUAL "a spaced extra closer after a self type" \
        "See \`$R::<dyn RecallTool> >::NoSuch\`."
    anchor_red 5613 QUAL "a tab before an extra closer after a self type" \
        "See \`$R::<dyn RecallTool>	>::NoSuch\`."

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
    # #5251: every wording alternative of ABSENT_ASSERTION has its own killing
    # cell: a plain path next to it is exempt.
    anchor_green 5251 "a plain path with 'test ! -f' wording" \
        'The pre-flight runs test ! -f `src/missing_5251.rs` first.'
    anchor_green 5251 "a plain path with 'modularisation' wording" \
        'After the modularisation `src/missing_5251.rs` is gone.'
    anchor_green 5251 "a plain path with 'modularization' wording" \
        'After the modularization `src/missing_5251.rs` is gone.'
    anchor_green 5251 "a plain path with 'monolithic' wording" \
        'The monolithic `src/missing_5251.rs` is gone.'
    anchor_green 5251 "a plain path with 'split from' wording" \
        'It is `src/missing_5251.rs` split from the rest.'
    anchor_green 5251 "a plain path with 'split off' wording" \
        'It is `src/missing_5251.rs` split off the rest.'
    anchor_green 5251 "a plain path with 'removed in' wording" \
        'The file `src/missing_5251.rs` was removed in 1.0.'
    anchor_green 5251 "a plain path with 'deleted in' wording" \
        'The file `src/missing_5251.rs` was deleted in 1.0.'
    anchor_green 5251 "a plain path with 'STALE BASE' wording" \
        'STALE BASE: `src/missing_5251.rs` is absent.'
    anchor_green 5251 "a plain path with 'does not exist' wording" \
        'The file `src/missing_5251.rs` does not exist here.'
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
import html
import os
import posixpath
import re
import unicodedata
from html.entities import html5 as HTML5

root = os.environ["REPO_ROOT"].rstrip("/")
ladder_tip = os.environ.get("LADDER_TIP", "").strip()

# Self-test fault-injection (#2713): when this env var is set the analysis
# engine raises, so the gate's own --self-test can prove the gate FAILS
# CLOSED (exits non-zero, prints no PASS) on an engine error instead of
# swallowing it into an empty violation set. Never set in production / CI.
if os.environ.get("AI_MEMORY_SYMBOL_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-doc-symbol-anchors self-test: injected analysis-engine fault (#2713)")

# #5783: the ONE rule table. Every record the engine prints names a rule in
# it and carries that rule's detail text, so the reporter prints what the
# table says and has no table of its own; emit() refuses any other rule (the
# engine errors and the gate fails closed), and the --self-test census reads
# this table and matches it with the header both ways. The kind says where
# the header lists the rule: "check" (a checking rule), "part" (reported
# under its own name, part of the check named in its header line) or
# "refusal".
RULES = {
    "PATH": ("check", "cited src/ path does not exist"),
    "LINE": ("check", "file:line anchor is out of range (line numbers are 1-based and must not pass end-of-file)"),
    "QUAL": ("check", "symbol is not defined in the file it is qualified against"),
    "BARE_QUAL": ("part", "symbol is not defined in the file it is qualified against (unbackticked anchor)"),
    "BARE_LN": ("check", "bare file:line anchor in a live doc (rots silently); cite `path::symbol`, or pin a commit permalink"),
    "MDLINK": ("check", "markdown symbol link does not resolve in its target file"),
    "LADDER_TIP": ("check", "claimed ladder tip disagrees with the tip scripts/check-migration-ladder.sh computes (left=cited, right=actual)"),
    "UNDECIDABLE_REF": ("refusal", "anchor is refused: its character references decode differently in CommonMark and HTML, so the anchor cannot be resolved; write the characters plainly"),
    "UNDECIDABLE_LT": ("refusal", "anchor is refused: a `<` before it may or may not open a group, and the anchor is judged differently either way; write a comparison spaced (a < b) or in code"),
    "UNMODELLED": ("refusal", "anchor is refused: it is written in a form this gate does not model (a self type it cannot read, a Rust keyword in its path, or a component that is not an identifier), so it cannot be checked; name the type and method plainly (src/x.rs::Type::method)"),
    "SETUP": ("refusal", "the gate cannot do its job"),
}
# A decoded backtick never opens a code span; it is this private-use
# character until emit() shows it as written (#5607).
CODE_TICK = "\ue060"


def emit(rule, doc, ln, token, ctx):
    """Print one record: rule, doc, line, token, detail, context (#5783)."""
    if rule not in RULES:
        raise RuntimeError(f"rule {rule!r} is not in the RULES table (#5783)")
    # #5612: a cited token never holds whitespace (a tab would split the
    # record, a space the allowlist key) and shows a decoded backtick as
    # written.
    token = re.sub(r"\s+", "", token).replace(CODE_TICK, "`")
    print(f"{rule}\t{doc}\t{ln}\t{token}\t{RULES[rule][1]}\t{ctx[:150]}")


# ---- symbol index over src/ ------------------------------------------
DEF = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(?:fn|struct|enum|trait|type|const|static|mod|union)\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
# #5778: a raw identifier (`fn r#match`) is indexed under its name.
MACRO = re.compile(r"macro_rules!\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
# A 4-space-indented CamelCase item is an enum variant / struct field in
# house style; docs cite those the same way they cite functions.
VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*[,({=]", re.M)

per_file = {}
line_count = {}
for p in sorted(glob.glob(os.path.join(root, "src/**/*.rs"), recursive=True)):
    rel = p[len(root) + 1:]
    try:
        text = open(p, encoding="utf-8", errors="replace").read()
    except OSError as e:
        # #5616: an unreadable source file is not an empty one; refuse it
        # rather than report its anchors under a misleading rule.
        emit("SETUP", "-", 0, "-", f"cannot read {rel}: {e.strerror or e}")
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
    emit("SETUP", "-", 0, "-", "src/ yielded ZERO rust files; the gate would be a no-op")
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
# #5778: a raw identifier (`r#match`) is one component, cited as written.
_ID = r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*"
ID_RE = re.compile(_ID)
# #5609: whitespace between the file and `::` does not end the anchor.
QUAL_HEAD = re.compile(r"`(src/[A-Za-z0-9_/]+\.rs)\s*::")
# #5191: an UNBACKTICKED `src/x.rs::symbol` anchor (prose, an HTML code
# element, a code-block comment) is a symbol claim too, and is the very form
# the BARE_LN failure text tells authors to use. Same lookbehind as BARE_LN,
# so a URL path segment is never matched.
BARE_QUAL_HEAD = re.compile(r"(?<![`/A-Za-z0-9.])(src/[A-Za-z0-9_/]+\.rs)\s*::")
BRACE_BODY = re.compile(r"\{([^}]*)\}")


# #5607: a character reference is decoded ONCE, before any anchor analysis,
# with the complete HTML5 table (html.entities.html5), never a hand list, so
# every whitespace, angle-bracket or plus spelling is read as its character
# and the scanners below see characters only (`&amp;lt;` stays the text
# `&lt;`, it is not decoded twice). Two readings exist: HTML (html.unescape:
# a legacy name or a number with no `;`, any zero padding) and CommonMark (a
# `;` is required, at most 7 decimal or 6 hex digits, no backslash before
# the `&`). A Markdown line whose anchor findings differ between the two
# readings is refused as UNDECIDABLE_REF, citing the anchor as written. A
# decoded backtick never opens a code span (it becomes CODE_TICK), a decoded
# line ending is a space, and a decoded format character (Unicode Cf, such
# as a zero-width space) is dropped: it renders as nothing.
_REF_HTML = re.compile(r"&(?:#[xX][0-9A-Fa-f]+;?|#[0-9]+;?|[A-Za-z][A-Za-z0-9]*;?)")
_REF_CM = re.compile(r"(?<!\\)&(?:#[xX][0-9A-Fa-f]{1,6};|#[0-9]{1,7};|[A-Za-z][A-Za-z0-9]*;)")


def _invisible(ch):
    """A format character (Unicode Cf: a zero-width space, a word joiner, a
    soft hyphen, a bidi control) renders as nothing (#5607, #5781)."""
    return unicodedata.category(ch) == "Cf"


_NON_ASCII = re.compile(r"[^\x00-\x7f]")


def normal_form(text):
    """`text` with every format character dropped: the one normal form that
    literal and decoded text both reach before any rule runs (#5781)."""
    if text.isascii():
        return text
    return _NON_ASCII.sub(lambda m: "" if _invisible(m.group(0)) else m.group(0), text)


# #5781: a src/ token holding a non-ASCII letter, mark or digit (or an
# unassigned or private-use character) ends every scanner early, so the
# rest of the anchor would go unchecked; the token is refused instead.
LINE_END = re.compile(r"\r\n|\r|\n")
SRC_RUN = re.compile(r"(?<![A-Za-z0-9./])src/[^\s`]*")


def _glued(run):
    """True when `run` holds a character the scanners cannot read past."""
    for ch in run:
        if ord(ch) > 127:
            cat = unicodedata.category(ch)
            if cat[0] in "LMN" or cat in ("Co", "Cn", "Cs"):
                return True
    return False


def _decoded_chars(text):
    """Decoded reference text as the scanners must see it (#5607)."""
    out = []
    for ch in text:
        if ch == "`":
            out.append(CODE_TICK)
        elif ch in "\r\n":
            out.append(" ")
        elif not _invisible(ch):
            out.append(ch)
    return "".join(out)


def _ref_html(m):
    raw = m.group(0)
    dec = html.unescape(raw)
    return raw if dec == raw else _decoded_chars(dec)


def _ref_cm(m):
    raw = m.group(0)
    if raw[1] == "#":
        return _decoded_chars(html.unescape(raw))
    return _decoded_chars(HTML5[raw[1:]]) if raw[1:] in HTML5 else raw


def decode_html(line):
    """`line` with every character reference decoded as HTML does."""
    return _REF_HTML.sub(_ref_html, line) if "&" in line else line


def decode_cm(line):
    """`line` with every character reference decoded as CommonMark does."""
    return _REF_CM.sub(_ref_cm, line) if "&" in line else line


def _group_step(text, j):
    """Classify the text at `j`: ('open'|'close', width) for an angle bracket
    or its HTML entity, ('stop', 1) for a character a group may not contain,
    else ('other', 1). The `>` of an arrow (`->` or `-&gt;`) is not a closer."""
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
    return text.startswith("<", i)


def _token_end(text, i):
    """End of the whitespace- and backtick-delimited token containing `i`."""
    j = i
    while j < len(text) and not text[j].isspace() and text[j] != "`":
        j += 1
    return j


_OP_CHARS = frozenset("<>=-!")


def _operator_token_end(prefix, j):
    """End of the comparison-like operator token that starts the open at `j`,
    or None when that open is a generic opener (#5531). The token is the
    whitespace-delimited run around `j`; it is an operator (`<`, `<=`, `<<`,
    `<-`, `<>` ...) only when it is terminated by whitespace inside `prefix`,
    holds nothing but the characters `< > = - !` (an entity `&lt;`/`&gt;`
    counts as its sign) and begins at `j`: anything attached to a word is a
    generic opener, spaced oddly."""
    if j > 0 and not prefix[j - 1].isspace():
        return None
    e = j
    while e < len(prefix) and not prefix[e].isspace():
        e += 1
    if e >= len(prefix):
        return None
    tok = prefix[j:e]
    return e if tok and set(tok) <= _OP_CHARS else None


# #5608: a `<` is a generic opener only when it is PROVABLY one: the next
# character begins a type (a letter, `_`, `&`, `(`, `[`, `*`, `<`, `/`, `:`,
# `?`, or `'` followed by a letter: a lifetime). A whitespace-delimited
# operator token (#5531) is a comparison. Any other `<` (before a quote, a
# digit, `-`, `=`, `,`, `)`, whitespace ...) is undecidable: it may or may
# not open a group.
_TYPE_START = re.compile(r"[A-Za-z_&(\[*</:?]|'[A-Za-z_]")


def _outer_range(prefix, nxt=""):
    """(lo, hi): the fewest and the most angle groups that can still be open
    at the end of `prefix` (#5456), counting each undecidable `<` as no
    opener (lo) and as an opener (hi) (#5608). `nxt` is the character after
    the prefix (the anchor head), which decides a `<` at its very end. Prose
    such as `Vec<src/x.rs::T<U>>` opens a group of its own before the anchor,
    and the last closer belongs to it."""
    text = prefix + nxt
    lo = hi = j = 0
    while j < len(prefix):
        kind, width = _group_step(prefix, j)
        if kind == "open":
            end = _operator_token_end(prefix, j)
            if end is not None:
                # #5498/#5530/#5531: `a < b`, `a <= b`, `a << b`, `a <- b`
                # is a comparison, not a generic open.
                j = end
                continue
            hi += 1
            if _TYPE_START.match(text, j + 1):
                lo += 1
        elif kind == "close":
            lo, hi = max(0, lo - 1), max(0, hi - 1)
        j += width
    return lo, hi


def _code_spans(line):
    """(open start, content start, content end, close end) of every CommonMark
    code span on `line`: a backtick run closed by the next run of the same
    length; a run with no such closer is literal text (#5608)."""
    runs = [(m.start(), m.end()) for m in re.finditer(r"`+", line)]
    spans, i = [], 0
    while i < len(runs):
        width = runs[i][1] - runs[i][0]
        k = next((k for k in range(i + 1, len(runs))
                  if runs[k][1] - runs[k][0] == width), None)
        if k is None:
            i += 1
            continue
        spans.append((runs[i][0], runs[i][1], runs[k][0], runs[k][1]))
        i = k + 1
    return spans


def _anchor_prefix(line, spans, p):
    """The text whose open groups can belong around the anchor at `p`
    (#5608). Inside a code span it is the span's own text before `p`; outside,
    it is the line before `p` with every closed code span made atomic (one
    neutral character), so a `<` written in code is never a prose opener."""
    for _o, cs, ce, _c in spans:
        if cs <= p < ce:
            return line[cs:p]
    out, j = [], 0
    for o, _cs, _ce, c in spans:
        if c > p:
            break
        out.append(line[j:o])
        out.append("\ue061")
        j = c
    out.append(line[j:p])
    return "".join(out)


def _skip_space(text, j):
    """Index after any whitespace at `j` (references are already decoded)."""
    while j < len(text) and text[j].isspace():
        j += 1
    return j


def _spaced_path(text, i):
    """Index of the `::` that follows whitespace at `i`, or None (#5609): a
    path continues across whitespace before `::`, as Rust reads it."""
    k = _skip_space(text, i)
    return k if k > i and text.startswith("::", k) else None


def _path_end(text, i):
    """End of an unresolvable anchor's text from `i`: the token, continued
    across whitespace after a trailing `::` or before a `::` (#5612), so the
    citation holds the component behind the separator."""
    j = _token_end(text, i)
    while j < len(text) and text[j] != "`":
        if text.endswith("::", 0, j):
            k = _skip_space(text, j)
            if k < len(text) and text[k] != "`":
                j = _token_end(text, k)
                continue
        sp = _spaced_path(text, j)
        if sp is None:
            break
        j = _token_end(text, sp)
    return j


def _closer_run(text, i):
    """Closers at `i`: (attached count, index after them, count of closers
    when whitespace between them is skipped, index after those and the
    whitespace that follows them) (#5536)."""
    n, j = 0, i
    while j < len(text):
        kind, width = _group_step(text, j)
        if kind != "close":
            break
        n, j = n + 1, j + width
    total, k = n, j
    while True:
        k = _skip_space(text, k)
        kind, width = _group_step(text, k) if k < len(text) else ("other", 1)
        if kind != "close":
            break
        total, k = total + 1, k + width
    return n, j, total, k


def _closer_then_path(text, i):
    """The index to take the token end from when one or more group closers at
    `i` (attached, or separated by whitespace, #5536) are followed by `::`
    (#5496); None otherwise."""
    n, j, total, k = _closer_run(text, i)
    if n > 0 and text.startswith("::", j):
        return j
    if total > 0 and text.startswith("::", k):
        return k
    return None


def _stray_close(text, i, outer=0):
    """The index to take the token end from when `text` has more extra group
    closers (`>` or `&gt;`) at `i` than the `outer` groups opened before the
    anchor can take (#5456), or a closer is followed by `::` (the path then
    continues past a closer, the #5430 shape, also across whitespace, #5536);
    None otherwise."""
    n, j, total, k = _closer_run(text, i)
    if n > outer or (n > 0 and text.startswith("::", j)):
        return j
    if total > 0 and text.startswith("::", k):
        return k
    return None


def scan_sym(text, i, outer=0):
    """Scan the symbol path starting at `i`; returns its end index, or None
    when no symbol starts there. Path components are identifiers, each with an
    optional balanced group, joined by `::` (a bare group after `::` is a
    turbofish), after an optional leading `<Type as Trait>::`. A group that
    never balances, or is followed by an extra closer (#5430), captures to the
    end of the token (#5393), so the caller reports it instead of skipping the
    components behind it. `outer` is the count of prose groups still open
    before the anchor (#5456): that many closers after the path close those
    groups and end the capture instead of over-closing the anchor's own."""
    pos = _skip_space(text, i)
    if _opens_group(text, pos):
        end = scan_group(text, pos)
        if end is None:
            return _path_end(text, pos)
        stray = _stray_close(text, end, outer)
        if stray is not None:
            return _path_end(text, stray)
        if not text.startswith("::", end):
            # #5609: whitespace before `::` continues the path.
            sp = _spaced_path(text, end)
            if sp is None:
                # #5535: a lone balanced group is a self type with no method:
                # the caller checks (or refuses) it, never silently drops it.
                return end
            end = sp
        pos = _skip_space(text, end + 2)
    m = ID_RE.match(text, pos)
    if not m:
        return None
    pos = m.end()
    while True:
        if _opens_group(text, pos):
            end = scan_group(text, pos)
            if end is None:
                return _path_end(text, pos)
            pos = end
            stray = _stray_close(text, pos, outer)
            if stray is not None:
                return _path_end(text, stray)
        if not text.startswith("::", pos):
            # #5496: a closer followed by `::` continues the path past the
            # closer even when the anchor has no group of its own.
            past = _closer_then_path(text, pos)
            if past is not None:
                return _path_end(text, past)
            sp = _spaced_path(text, pos)
            if sp is None:
                return pos
            pos = sp
        # #5609: whitespace after `::` does not end the path either.
        nxt = _skip_space(text, pos + 2)
        m = ID_RE.match(text, nxt)
        if m:
            pos = m.end()
        elif _opens_group(text, nxt):
            end = scan_group(text, nxt)
            if end is None:
                return _path_end(text, nxt)
            pos = end
            stray = _stray_close(text, pos, outer)
            if stray is not None:
                return _path_end(text, stray)
        elif text.startswith("{", nxt):
            # #5780: a nested brace list (`T::{a, b}`) ends the path; its
            # items are checked one by one. A `::` after it is not read, so
            # the capture runs on and the item check refuses it.
            close = text.find("}", nxt)
            if close < 0:
                return _path_end(text, pos)
            after = _skip_space(text, close + 1)
            if text.startswith("::", after):
                return _path_end(text, after)
            return close + 1
        else:
            # #5780: a `::` followed by nothing the scanner reads (a glob,
            # punctuation, a digit, the end of the anchor) is captured to
            # the token end, so the item check refuses it, never drops it.
            return _path_end(text, pos)


def iter_quals(line):
    """Yield (rule, file, payload) for every qualified anchor on `line`:
    backticked `src/x.rs::sym` (QUAL) and unbackticked (BARE_QUAL). A brace
    payload is a string; any other payload is a list of the candidate scans
    (one per possible outer depth, #5608)."""
    spans = _code_spans(line)
    for rule, head in (("QUAL", QUAL_HEAD), ("BARE_QUAL", BARE_QUAL_HEAD)):
        pos = 0
        while True:
            hm = head.search(line, pos)
            if not hm:
                break
            pos = _skip_space(line, hm.end())
            bm = BRACE_BODY.match(line, pos) if line.startswith("{", pos) else None
            if bm:
                after = _skip_space(line, bm.end())
                if line.startswith("::", after):
                    # #5779: a path after a brace list is not read; refuse it.
                    yield rule, hm.group(1), (UNMODELLED, line[pos:_path_end(line, after)])
                elif split_items(bm.group(1)):
                    yield rule, hm.group(1), bm.group(1)
                else:
                    # #5698: an empty brace list names nothing to check.
                    yield rule, hm.group(1), (UNMODELLED, line[pos:bm.end()])
                pos = bm.end()
                continue
            p0 = hm.start(1)
            lo, hi = _outer_range(_anchor_prefix(line, spans, p0), line[p0:p0 + 1])
            ends = [scan_sym(line, pos, d) for d in range(lo, hi + 1)]
            if ends[0] is not None:
                # #5608: one payload per possible outer depth; the caller
                # refuses the anchor when they are judged differently.
                yield rule, hm.group(1), [line[pos:e] for e in dict.fromkeys(ends)]
                pos = min(ends)
            else:
                # #5698: a head whose separator is followed by nothing the
                # scanner reads (end of text, a glob, punctuation, a digit) is
                # a claim the gate has not understood, so it is refused, cited
                # as written up to the next whitespace or backtick.
                tail = re.match(r"[^\s`]*", line[pos:]).group(0)
                yield rule, hm.group(1), (UNMODELLED, tail)


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


MDLINK = re.compile(r"\[`((?:r#)?[A-Za-z_][A-Za-z0-9_]*)`\]\(\s*<?([^)]*src/[A-Za-z0-9_/]+\.rs)[^)]*\)")
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
IDENT = re.compile(r"^(?:r#)?[A-Za-z_][A-Za-z0-9_]*$")
# #5778: Rust rejects these as raw identifiers, so they name nothing.
# #5779: the one filler a brace list may hold: an elision.
ELISIONS = frozenset(["\u2026", "..."])
EMPTY_ITEM = re.compile(r"^\s*,|,\s*,")
RAW_FORBIDDEN = frozenset("crate self super Self _".split())


def raw_name(part):
    """The name a component looks up: a raw identifier without its `r#`."""
    return part[2:] if part.startswith("r#") else part
AS_WORD = re.compile(r"\bas\b")
# #5457: a self type may open with a reference or a trait-object keyword
# (`<dyn Trait>::m`, `<&mut T>::m`); those are not the type's name.
# #5493: a leading lifetime or ?Trait bound of a bound list (`dyn 'a + T`,
# `dyn ?Sized + T`) is skipped too; it is not the type either. #5532: the only
# `?` bound Rust has is `?Sized`, so any other name after `?` is not skipped
# (the self type is then refused) and the bounds after the type are checked.
# #5537: a higher-ranked binder (`dyn for<'a> Tr`) is skipped too, so the
# trait behind it is the checked name and `for` is never cited as a symbol.
SELF_PREFIX = re.compile(
    r"(?:&\s*(?:'[A-Za-z_]\w*\s+)?(?:mut\s+)?|\*\s*(?:const|mut)\s+|\b(?:dyn|impl|mut)\s+"
    r"|\bfor\s*<[^<>]*>\s*"
    r"|(?:'[A-Za-z_]\w*|\?\s*Sized\b)\s*\+\s*)+")
# #5393/#5433 pin a lone `<name>` and `<name<T>>` (an identifier head, no
# prefix, no `as`) as a placeholder, not a symbol claim; every other lone
# group (a prefixed type, a tuple, a slice, a lifetime) is a self type (#5535).
_LIFETIME_BOUND = re.compile(r"^'[A-Za-z_]\w*$")
_SIZED_BOUND = re.compile(r"^\?\s*Sized$")
_HRTB = re.compile(r"^for\s*<[^<>]*>\s*")
_BOUND_PATH = re.compile(r"^(?:::)?" + _ID + r"(?:::" + _ID + r")*$")


def _split_bounds(body):
    """Split a bound list at its top-level `+` (a `+` inside a generic group
    or parentheses is not a separator) and cut it at a top-level `as`."""
    pieces, cur, depth = [], "", 0
    j = 0
    while j < len(body):
        ch = body[j]
        if ch in "<(":
            depth += 1
        elif ch in ">)" and not (ch == ">" and j and body[j - 1] == "-"):
            depth = max(0, depth - 1)
        if depth == 0 and ch == "+":
            pieces.append(cur)
            cur = ""
        elif depth == 0 and AS_WORD.match(body, j):
            break
        else:
            cur += ch
        j += 1
    pieces.append(cur)
    return pieces


def _bound_tokens(body):
    """The extra bounds after the first type of a trait-object or impl bound
    list as symbol tokens (#5532); None when a bound cannot be checked (a
    `?` bound other than `?Sized`, a parenthesised or sugared bound), which
    the caller refuses. Lifetimes, `?Sized` and a trailing `+` name no type."""
    pieces = _split_bounds(body)
    toks = []
    for idx, piece in enumerate(pieces[1:], start=1):
        piece = piece.strip()
        if not piece:
            if idx == len(pieces) - 1:
                continue
            return None
        if _LIFETIME_BOUND.match(piece) or _SIZED_BOUND.match(piece):
            continue
        if _USE_BOUND.match(piece):
            continue
        piece = _HRTB.sub("", piece)
        path = strip_generics(piece).strip()
        if "<" in path or ">" in path or not _BOUND_PATH.match(path):
            return None
        toks.append(path.lstrip(":"))
    return toks


# #5610: the type of a self type is a whole path, every component of which
# is checked; a lone placeholder is exactly `<Name>` or `<Name<...>>`.
_TYPE_PATH = re.compile(r"(?:::)?" + _ID + r"(?:\s*::\s*" + _ID + r")*")
_PLACEHOLDER_HEAD = re.compile(_ID)
# A form the self-type reader does not model (sugared `Fn(..)` bounds, a
# function pointer, text after the type it cannot place): refused as
# UNMODELLED, never read as a placeholder or a checked type (#5610).
UNMODELLED = object()
# #5611: Rust's strict and reserved keywords (2024 edition). A keyword is
# never a symbol name, so one in a checked path is refused as UNMODELLED,
# never cited as a missing symbol and never read as a placeholder.
KEYWORDS = frozenset(
    "as break const continue crate else enum extern false fn for if impl in "
    "let loop match mod move mut pub ref return self Self static struct super "
    "trait true type unsafe use where while async await dyn "
    "abstract become box do final macro override priv typeof unsized virtual "
    "yield try gen".split())
# #5611: a precise-capturing bound (`use<'a, T>`) names no type to check.
_USE_BOUND = re.compile(r"^use\s*<[^<>]*>$")


def _is_placeholder(inner):
    """True for the inner text of a lone `<Name>` or `<Name<...>>` (#5393,
    #5433): an identifier with at most one balanced generic group and
    nothing else, not even whitespace (#5610)."""
    m = _PLACEHOLDER_HEAD.match(inner)
    if not m or m.group(0) in KEYWORDS:
        return False
    if m.end() == len(inner):
        return True
    return inner[m.end()] == "<" and scan_group(inner, m.end()) == len(inner)


def unwrap_self_type(tok):
    """`<Type<T> as Trait>::m` -> `Type<T>::m` (the type is the claim); an
    `as` inside a nested argument (`<Vec<<T as Tr>::X>>::new`) counts too, and
    so does a group with no `as` that is followed by `::` (`<Type<T>>::m`).
    Returns a list of the tokens to check (the type path, then each further
    bound of a bound list, #5532, whatever the prefix, #5610), None when the
    group is a self type that names no type to check (#5493), or UNMODELLED
    when the group holds a form this reader does not model (#5610)."""
    if not tok.startswith("<"):
        return [tok]
    end = scan_group(tok, 0)
    if end is None:
        return [tok]
    inner = tok[1:end - 1]
    lone = end == len(tok)
    if lone and _is_placeholder(inner):
        # #5393/#5433: a lone `<name>` is a placeholder, not a symbol claim.
        return [tok]
    if not (AS_WORD.search(inner) or tok.startswith("::", end) or lone):
        return [tok]
    head = inner.strip()
    pm = SELF_PREFIX.match(head)
    pos = pm.end() if pm else 0
    tm = _TYPE_PATH.match(head, pos)
    if not tm:
        # #5493/#5495: a self type with no identifier after its prefix (a
        # bare bound, a pointer-free tuple, slice or nested group) names no
        # type to check, so it is refused, never accepted.
        return None
    q = tm.end()
    if head.startswith("<", q):
        q = scan_group(head, q)
        if q is None:
            return UNMODELLED
    q = _skip_space(head, q)
    if q < len(head) and not (head.startswith("+", q) or AS_WORD.match(head, q)):
        # #5610: the first bound is not fully read (a `Fn(..)` sugar, a
        # function pointer, two words): refuse it, never check a prefix.
        return UNMODELLED
    toks = [re.sub(r"\s+", "", tm.group(0)).lstrip(":") + tok[end:]]
    extra = _bound_tokens(head[pos:])
    if extra is None:
        return None
    return toks + extra


def _scan_items(raw):
    """The symbol items of a scanned (non-brace) payload: whitespace outside
    a generic group is dropped first, so `T<U> ::m` is the one path
    `T<U>::m` (#5609), never two unrelated items."""
    out, depth = [], 0
    for idx, ch in enumerate(raw):
        if ch == "<":
            depth += 1
        elif ch == ">" and depth > 0 and not (idx and raw[idx - 1] == "-"):
            depth -= 1
        if depth == 0 and ch.isspace():
            continue
        out.append(ch)
    return [x for item in split_items("".join(out)) for x in _expand(item)]


NESTED_BRACE = re.compile(r"^([^{}]*)::\{([^{}]*)\}$")


def _expand(item):
    """`P::{a, b}` -> [`P::a`, `P::b`] (#5780). An item with any other
    brace shape (nested braces, a path after the list, an empty or
    comma-empty list) is returned whole, so the item check refuses it."""
    if "{" not in item and "}" not in item:
        return [item]
    m = NESTED_BRACE.match(item)
    if not m or EMPTY_ITEM.search(m.group(2)):
        return [item]
    parts = split_items(m.group(2))
    return [m.group(1) + "::" + x for x in parts] if parts else [item]


def split_items(raw):
    """Split a qualified-anchor payload into symbol tokens at commas and
    whitespace that are NOT inside a generic group (`{A<T, U>::m, B}` is two
    items, not four)."""
    items, cur, depth, braces = [], "", 0, 0
    norm = raw
    for idx, ch in enumerate(norm):
        if ch == "<":
            depth += 1
        elif ch == ">" and depth > 0 and not (idx and norm[idx - 1] == "-"):
            depth -= 1
        # #5780: a nested brace list is one item until it is expanded.
        elif ch == "{":
            braces += 1
        elif ch == "}" and braces > 0:
            braces -= 1
        if depth == 0 and braces == 0 and (ch == "," or ch.isspace()):
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


def _item_findings(rule, f, tok):
    """(rule, token) findings for one symbol item `tok` of a file `f` anchor."""
    out = []
    # #5255/#5342: `Type<T, U>::method` checks BOTH components;
    # generic arguments are not symbol claims. `<Type as
    # Trait>::m` checks `Type` and `m`.
    whole = tok
    toks = unwrap_self_type(tok)
    if toks is UNMODELLED:
        out.append(("UNMODELLED", f"{f}::{whole}".replace(" ", "")))
        return out
    if toks is None:
        # #5493: a self type that names no type cannot be
        # resolved: report it rather than accept it.
        out.append((rule, f"{f}::{whole}".replace(" ", "")))
        return out
    refuse = ("UNMODELLED", f"{f}::{whole}".replace(" ", ""))
    for tok in toks:
        if tok.strip() in ELISIONS:
            # #5779: an ellipsis item (`{a, …}`) elides; it names nothing.
            continue
        # #5779: a turbofish separator (`T::<U>::m`) is a generic group.
        lone = tok.startswith("<")
        tok = strip_generics(tok.replace("::<", "<")).strip().rstrip("(){}[].,;")
        if any(part.split("(")[0].strip() in KEYWORDS for part in tok.split("::")):
            # #5611: a keyword is not a symbol: refuse the whole anchor.
            out.append(("UNMODELLED", f"{f}::{whole}".replace(" ", "")))
            return out
        if "<" in tok or ">" in tok:
            # An unbalanced group cannot be resolved: report it
            # rather than skip a component that may be missing; cite the
            # anchor as written, generics kept (#5612).
            out.append((rule, f"{f}::{whole}"))
            continue
        if not tok:
            if lone:
                # A lone `<Name>` placeholder (#5393) names nothing.
                continue
            out.append(refuse)
            return out
        for part in tok.split("::"):
            part = part.split("(")[0].strip()
            # #5779: closed world: every component is an identifier. An
            # empty one, punctuation, a digit or a glob is not read, so
            # the anchor is refused, never passed with the part skipped.
            if not part or not IDENT.match(part):
                out.append(refuse)
                return out
            name = raw_name(part)
            if name != part and name in RAW_FORBIDDEN:
                # #5778: `r#crate` and friends are not identifiers.
                out.append(("UNMODELLED", f"{f}::{whole}".replace(" ", "")))
                return out
            if name in per_file[f]:
                continue
            # A trailing `_` is a PREFIX citation of a test/fn
            # family (`issue_965_audit_*`); it resolves if any
            # symbol in that file starts with it.
            if name.endswith("_") and any(
                    n.startswith(name) for n in per_file[f]):
                continue
            out.append((rule, f"{f}::{part}"))
    return out


def qual_findings(line):
    """(rule, token) for every qualified anchor on `line` (decoded, canon)."""
    out = []
    for rule, f, raw in iter_quals(line):
        if f not in per_file:
            # #5201: a qualified anchor asserts the file exists, so the
            # absence-wording exemption never applies to it.
            out.append(("PATH", f))
            continue
        if isinstance(raw, tuple):
            out.append(("UNMODELLED", f"{f}::{raw[1]}"))
            continue
        if isinstance(raw, str):
            if EMPTY_ITEM.search(raw):
                # #5779: an empty item (`{, a}`, `{a, , b}`) is not read.
                out.append(("UNMODELLED", f"{f}::{{{raw}}}"))
                continue
            for tok in split_items(raw):
                out += _item_findings(rule, f, tok)
            continue
        # #5608: an undecidable `<` before the anchor leaves more than one
        # scan; when they are judged differently the anchor is refused.
        judged = [[x for tok in _scan_items(r) for x in _item_findings(rule, f, tok)]
                  for r in raw]
        if all(j == judged[0] for j in judged):
            out += judged[0]
        else:
            out.append(("UNDECIDABLE_LT", f"{f}::{max(raw, key=len)}"))
    return out


def undecidable_extents(line, readings, differing):
    """UNDECIDABLE_REF findings for the qualified anchors of `line`, each
    cited as written: the head and the whitespace-free text after it (#5607).
    An anchor that exists only once decoded is cited from the first reading
    that holds it. With no qualified anchor in any reading, the tokens the
    readings disagree on are cited (#5782): never a bare dash."""
    out = []
    for text in [line] + readings:
        for head in (QUAL_HEAD, BARE_QUAL_HEAD):
            for hm in head.finditer(text):
                start = _skip_space(text, hm.end())
                out.append(("UNDECIDABLE_REF",
                            hm.group(1) + "::" + text[start:_path_end(text, start)]))
        if out:
            break
    return out or [("UNDECIDABLE_REF", tok) for tok in differing]


def line_findings(doc, doc_lines, ln, dec):
    """Every finding the per-line rules make on ONE reading of line `ln`
    (#5782): the raw line when `dec` is None, else the line decoded by `dec`
    (CommonMark or HTML). Each finding is (rule, token, qualified), where
    `qualified` marks a finding of the qualified-anchor rules. A neighbour
    line (a link destination or a hard-wrapped arrow) is read the same way."""
    out = []

    def read(text):
        """`text` canonicalised, then decoded by this reading, then
        canonicalised again: (line, escapes)."""
        text, esc = canon(text)
        if dec is None:
            return text, esc
        text, more = canon(dec(text))
        return text, esc + more

    line, escapes = read(doc_lines[ln - 1])
    window = "\n".join(doc_lines[max(0, ln - 2):ln + 1])
    absent_win = bool(ABSENT_ASSERTION.search(window))
    dest_at = [d.start() for d in ABSENT_DEST.finditer(line)]
    # A hard-wrapped sentence may put the arrow at the start of the NEXT
    # line ("`src/old.rs`\n-> `src/new/`"): the anchor above is a source.
    next_line = read(doc_lines[ln])[0] if ln < len(doc_lines) else ""
    prev_line = read(doc_lines[ln - 2])[0] if ln > 1 else ""
    dest_next = ln < len(doc_lines) and bool(ABSENT_DEST.match(next_line.lstrip()))

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
            next_line_dest = (ln > 1 and not line[:at].strip(" \t<")
                              and bool(LINK_OPEN.search(prev_line)
                                       or REFDEF_OPEN.match(prev_line)))
            if (not absent_ok_at(at)
                    or line.startswith(tok + "::", at)
                    or ESCAPE_LINK_HEAD.search(line[:at])
                    or next_line_dest):
                out.append(("PATH", tok, False))
                break

    if not line.isascii():
        for m in SRC_RUN.finditer(line):
            if _glued(m.group(0)):
                out.append(("UNMODELLED", m.group(0), False))

    for m in PATH.finditer(line):
        f = m.group(1)
        if f not in per_file and not absent_ok_at(m.start(1)):
            out.append(("PATH", f, False))

    for m in PATHLN.finditer(line):
        f, n = m.group(1), int(m.group(2))
        last = int(m.group(3)) if m.group(3) else n
        if f not in per_file:
            if not absent_ok_at(m.start(1)):
                out.append(("PATH", f, False))
        elif n < 1 or last < n or last > line_count[f]:
            tok = f"{f}:{n}" if m.group(3) is None else f"{f}:{n}-{last}"
            out.append(("LINE", tok, False))

    for m in BARE_LN.finditer(line):
        if pinned_label(line, m):
            continue
        out.append(("BARE_LN", f"{m.group(1)}:{m.group(2)}", False))

    out += [(rule, tok, True) for rule, tok in qual_findings(line)]

    # #5431: the joined line feeds MDLINK too, so a symbol label whose
    # destination is on the next line is checked like the one-line form.
    # #5396: a line that ends in an open `](` takes its destination from
    # the next line, as CommonMark does.
    link_line = line
    if LINK_OPEN.search(line) and ln < len(doc_lines):
        link_line = line.rstrip() + " " + next_line.lstrip()
    for m in MDLINK.finditer(link_line):
        sym = m.group(1)
        tgt = m.group(2).split("#")[0]
        if tgt not in per_file:
            # A link to a missing file is a dead link whatever the
            # surrounding wording says: no absence exemption.
            out.append(("PATH", tgt, False))
        elif raw_name(sym) not in per_file[tgt]:
            out.append(("MDLINK", f"{tgt}::{sym}", False))

    # #5190: a relative link with a plain-text label must still point at
    # a file that exists. MDLINK already reported a backticked-label link.
    md_spans = [(m.start(2), m.end(2)) for m in MDLINK.finditer(link_line)]
    rel_hits = [(m.group(1), m.group(2), m.start(1), True)
                for m in RELLINK.finditer(link_line)]
    # #5343: a reference definition may carry its destination on the
    # NEXT line (`[h]:` then `src/x.rs`); join the two before matching.
    refdef_line = line
    if REFDEF_OPEN.match(line) and ln < len(doc_lines):
        refdef_line = line.rstrip() + " " + next_line.strip()
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
                    out.append(("LINE", f"{tgt}{frag}", False))
        if is_md and any(a <= start < b for a, b in md_spans):
            continue
        if tgt not in per_file:
            out.append(("PATH", tgt, False))

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
                out.append(("LADDER_TIP",
                            f"migrate_v{m.group(1)}!=migrate_v{ladder_tip}", False))
    return out


for doc in seen_docs:
    try:
        text = open(os.path.join(root, doc), encoding="utf-8", errors="replace").read()
    except OSError as e:
        # #5616: a doc in the set that cannot be read was never checked, so
        # the gate must not pass it (a directory named like a doc, or a file
        # with no read permission, was skipped silently).
        emit("SETUP", doc, 0, "-", f"cannot read {doc}: {e.strerror or e}")
        continue
    # #5781: literal text reaches the same normal form as decoded text, and
    # a line ends only at a line ending (CR, LF or CRLF), as in Markdown:
    # splitlines() also broke at U+2028, form feed and the like, cutting an
    # anchor in two so neither half was checked.
    doc_lines = LINE_END.split(normal_form(text))
    if doc_lines and doc_lines[-1] == "":
        doc_lines.pop()
    for ln, raw in enumerate(doc_lines, 1):
        ctx = raw.strip()
        # #5607/#5782: EVERY per-line rule runs on every reading of the
        # line: the raw line when it holds no character reference, else the
        # CommonMark and HTML readings (an .html doc has the HTML reading
        # only). A finding every reading makes is reported; when the
        # readings disagree the line is undecidable and its anchors (or, with
        # no qualified anchor, the tokens the readings disagree on) are
        # refused as UNDECIDABLE_REF.
        line = canon(raw)[0]
        if "&" in line:
            decs = [decode_html] if doc.endswith(".html") else [decode_cm, decode_html]
        else:
            decs = [None]
        found = [line_findings(doc, doc_lines, ln, d) for d in decs]
        keys = [{(rule, tok) for rule, tok, _ in f} for f in found]
        for rule, tok, _ in found[0]:
            if all((rule, tok) in other for other in keys[1:]):
                emit(rule, doc, ln, tok, ctx)
        if any(other != keys[0] for other in keys[1:]):
            common = set.intersection(*keys)
            differing = [(tok, q) for f in found for rule, tok, q in f
                         if (rule, tok) not in common]
            plain = list(dict.fromkeys(tok for tok, q in differing if not q))
            cited = []
            if any(q for _, q in differing):
                cited = undecidable_extents(
                    line, [canon(d(line))[0] for d in decs],
                    list(dict.fromkeys(tok for tok, q in differing if q)))
            for rule, tok in cited + [("UNDECIDABLE_REF", tok) for tok in plain]:
                emit(rule, doc, ln, tok, ctx)
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
    while IFS=$'\t' read -r rule doc ln token detail ctx; do
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
