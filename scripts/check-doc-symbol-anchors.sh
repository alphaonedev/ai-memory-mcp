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
# FOUR RULES, all conservative, all keyed on PATH-QUALIFIED grammar so
# a bare backticked identifier in prose is never guessed at:
#
#   PATH   — a cited `src/<path>.rs` must EXIST. This is what caught the
#            pre-modularisation `src/handlers.rs` / `src/mcp.rs` /
#            `src/db.rs` anchors still live in the operator guides.
#   LINE   — a cited `src/<path>.rs:<N>` must name a line the file
#            actually has. Cheap, dependency-free, and it catches the
#            whole truncated-anchor class without needing to know what
#            is ON that line.
#   QUAL   — every identifier in `src/<path>.rs::<sym>` and
#            `src/<path>.rs::{a, B::c, d}` must be DEFINED IN THAT FILE.
#            Each `::`-separated component is checked, so
#            `VectorIndex::build_with_capacity` resolves only if both
#            the type and the method are in that file.
#   MDLINK — `[`sym`](../src/path.rs)` must resolve: the file must
#            exist AND `sym` must be defined in it (or BE it — a link
#            whose symbol equals the module's file stem is a module
#            citation, which is legitimate).
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
# Unlike the two PENDING-FIX ledgers this campaign also ships, a STALE
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
#       `migrate_vNN`) in a throwaway copy UNDER `.local-runs/` (never
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
    echo "PASS: self-test allowlist — a STALE entry FAILS (unlike the two pending-fix ledgers, by design)"

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
    line_count[rel] = text.count("\n") + 1
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

docs = ["CLAUDE.md", "README.md", "ROADMAP.md", "PERFORMANCE.md"]
docs += sorted(glob.glob(os.path.join(root, "docs/*.md")))
for sub in ("security", "compliance", "spec", "integrations", "deploy", "v1.0.0"):
    docs += sorted(glob.glob(os.path.join(root, f"docs/{sub}/**/*.md"), recursive=True))

seen_docs = []
for d in docs:
    rel = d[len(root) + 1:] if d.startswith(root + "/") else d
    if FROZEN.match(rel) or rel in seen_docs:
        continue
    if os.path.exists(os.path.join(root, rel)):
        seen_docs.append(rel)

PATH = re.compile(r"`(?:\.\./)*(src/[A-Za-z0-9_/]+\.rs)`")
PATHLN = re.compile(r"`(?:\.\./)*(src/[A-Za-z0-9_/]+\.rs):(\d+)")
QUAL = re.compile(
    r"`(?:\.\./)*(src/[A-Za-z0-9_/]+\.rs)::(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_:]*))")
MDLINK = re.compile(r"\[`([A-Za-z_][A-Za-z0-9_]*)`\]\(([^)]*src/[A-Za-z0-9_/]+\.rs)[^)]*\)")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

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
    r"modularisation|modularization|monolithic|formerly|\bsplit\b|renamed to|"
    r"removed in|deleted in|STALE BASE|does not exist|(?:->|\u2192)\s*`?src/",
    re.IGNORECASE,
)


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
        window = "\n".join(doc_lines[max(0, ln - 2):ln + 1])
        absent_ok = bool(ABSENT_ASSERTION.search(window))

        for m in PATH.finditer(line):
            f = m.group(1)
            if f not in per_file and not absent_ok:
                emit("PATH", doc, ln, f, ctx)

        for m in PATHLN.finditer(line):
            f, n = m.group(1), int(m.group(2))
            if f not in per_file:
                if not absent_ok:
                    emit("PATH", doc, ln, f, ctx)
            elif n > line_count[f]:
                emit("LINE", doc, ln, f"{f}:{n}", ctx)

        for m in QUAL.finditer(line):
            f = m.group(1)
            raw = m.group(2) if m.group(2) is not None else (m.group(3) or "")
            if f not in per_file:
                if not absent_ok:
                    emit("PATH", doc, ln, f, ctx)
                continue
            for tok in raw.replace(",", " ").split():
                tok = tok.strip().rstrip("(){}[]<>.,;")
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
                    emit("QUAL", doc, ln, f"{f}::{part}", ctx)

        for m in MDLINK.finditer(line):
            sym = m.group(1)
            tgt = re.sub(r"^(\.\./)+", "", m.group(2)).split("#")[0]
            if tgt not in per_file:
                if not absent_ok:
                    emit("PATH", doc, ln, tgt, ctx)
            elif sym not in per_file[tgt]:
                emit("MDLINK", doc, ln, f"{tgt}::{sym}", ctx)

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
            LINE)  detail="file:line anchor points past end-of-file" ;;
            QUAL)  detail="symbol is not defined in the file it is qualified against" ;;
            MDLINK) detail="markdown symbol link does not resolve in its target file" ;;
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
    done < <(sort -u <<<"$allow_keys")
fi

if [[ "$fail_count" -gt 0 ]]; then
    printf '\n❌ doc symbol/path anchor gate: %d violation(s)\n' "$fail_count" >&2
    printf '   Repoint the anchor at HEAD, or cite the symbol without a line number.\n' >&2
    printf '   An anchor that misses is worse than no anchor (register 3.2, C-44/C-45/C-42/C-55/C-56).\n' >&2
    exit 1
fi
printf '✅ doc symbol/path anchor gate: PASS\n'
