#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-doc-surface-completeness.sh
#
# v1.0.0 CERT GATE — REFERENCE-DOC COMPLETENESS gate (#2839; 3x7 lane-2
# register `.local-runs/3x7-2026-08-09/lane2-api-netnew-register.md` §E).
#
# THE DEFECT THIS CLOSES. `scripts/check-docs-vs-ssot.sh` (gate 4) and
# `scripts/check-doc-symbol-anchors.sh` (gate 9) both answer "is this
# CITED value / symbol RIGHT?" — an ACCURACY axis. NEITHER answers "is
# anything MISSING?" — a COMPLETENESS axis. #2831 found, by three trivial
# diffs, that a reference doc can be a full release behind while every
# accuracy gate is GREEN:
#   - `Command` variants absent from `docs/CLI_REFERENCE.md`, which
#     asserts at line 16 that it "is kept in sync with the source";
#   - `routes.rs` path consts absent from `docs/API_REFERENCE.md`, which
#     asserts a total "unique URL paths" surface;
#   - `memory_skill_*` tools absent from `docs/agent-skills.md` — and the
#     two undocumented tools were the DESTRUCTIVE pair from #2024,
#     including an irreversible hard purge.
# In all three the doc CLAIMS the completeness it lacks, so this is the
# same #2492 overclaim bias ("the drift direction is consistently toward
# MORE CLAIMED ENFORCEMENT THAN EXISTS"), one axis over. This is the
# gate that would have caught the phantom endpoint + the undocumented
# `memory_skill_delete`.
#
# THREE RULES, each a SET-DIFFERENCE against a const the repo already
# exports (no new SSOT):
#   CLI   — every `pub enum Command` variant (`src/daemon_runtime.rs`),
#           kebab-cased the way clap renames it, appears SOMEWHERE in
#           `docs/CLI_REFERENCE.md` (heading, prose, OR code fence — a
#           subcommand documented only inside a fenced example still
#           counts). A `#[command(hide…)]` variant is EXEMPT (not a
#           user-facing surface).
#   ROUTE — every `pub const …: &str = "/…"` production path in
#           `src/handlers/routes.rs`, PARAM-NORMALISED (`{id}` / `:id` /
#           `<id>` / `${…}` / `{memory_id}` → `{}`), appears in
#           `docs/API_REFERENCE.md` param-normalised. The normalisation
#           is what makes it catch a collection-vs-item mismatch (the
#           #2629 gate-10 precedent): a raw-string test would pass a
#           `/subscriptions/{id}` doc claim against a collection-only
#           registration.
#   TOOL  — every `registry::tool_names` const (`src/mcp/registry.rs`)
#           appears in at least ONE non-CHANGELOG, non-FROZEN LIVE doc. A
#           tool named ONLY in a frozen `docs/v0.*/` snapshot does NOT
#           count — a past release documenting a tool is not the current
#           reference documenting it.
#
# BURN-DOWN ALLOWLIST: `scripts/qc-allowlists/doc-surface-completeness-allow.txt`.
# A STALE ENTRY **FAILS** — the `doc-symbol-anchors-allow.txt` /
# `required-contexts-joblevel-if-allow.txt` discipline (gate 7 rule (b2)):
# nothing is concurrently correcting these omissions, so an entry that
# suppresses nothing is pure rot. A MALFORMED entry HARD-FAILS. This is
# NOT a pending-fix ledger — the passing state is EMPTY.
#
# FAIL CLOSED. An EMPTY scan set (zero variants / zero routes / zero
# tools parsed) FAILS — a gate that can no-op to green is worse than no
# gate (the #2444 shape). An analysis-engine error FAILS CLOSED (exit 2,
# distinct message, no PASS banner) rather than swallowing into an empty
# violation set (the #2713 fail-open the pre-fix `|| true` shape hides).
#
# CLI:
#   scripts/check-doc-surface-completeness.sh              — run (exit 0/1)
#   scripts/check-doc-surface-completeness.sh --self-test  — plant one
#       real omission per rule (an undocumented subcommand, an
#       undocumented route, an undocumented tool) in a throwaway copy
#       UNDER `.local-runs/` (never system `/tmp`, never `mktemp -d`) and
#       prove the gate rejects each, alongside near-miss controls that
#       must PASS (a subcommand documented only in a code fence; a route
#       documented with `:id` not `{id}`) and the frozen-exclusion
#       control (a tool named ONLY in a frozen `docs/v0.*/` file, which
#       must NOT count as coverage).

set -euo pipefail

# --------------------------------------------------------------------
# Self-test (dispatched first so it can drive the real script)
# --------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    FIX="$ROOT/.local-runs/doc-surface-completeness-selftest-$$"
    rm -rf "$FIX"
    mkdir -p "$FIX/src/daemon_runtime_dir" "$FIX/src/handlers" "$FIX/src/mcp" \
             "$FIX/docs" "$FIX/docs/v0.9.0" "$FIX/scripts/qc-allowlists"
    trap 'rm -rf "$FIX"' EXIT

    # A minimal Command enum in the real house shape.
    cat > "$FIX/src/daemon_runtime.rs" <<'RSEOF'
#[derive(Subcommand)]
pub enum Command {
    /// Start the daemon.
    Serve(ServeArgs),
    /// Verify the reflection chain.
    VerifyReflectionChain(VerifyChainArgs),
    /// A hidden internal command — never user-facing.
    #[command(hide = true)]
    SecretInternal(SecretArgs),
    /// The record-stop actuator.
    Stop(StopArgs),
}
RSEOF
    cat > "$FIX/src/handlers/routes.rs" <<'RSEOF'
pub const MEMORIES: &str = "/api/v1/memories";
pub const MEMORIES_ID: &str = "/api/v1/memories/{id}";
pub const SUBSCRIPTIONS: &str = "/api/v1/subscriptions";
pub const METRICS_BARE: &str = "/metrics";
RSEOF
    cat > "$FIX/src/mcp/registry.rs" <<'RSEOF'
pub mod tool_names {
    pub const MEMORY_STORE: &str = "memory_store";
    pub const MEMORY_RECALL: &str = "memory_recall";
    pub const MEMORY_SKILL_DELETE: &str = "memory_skill_delete";
    pub const ALL: &[&str] = &[MEMORY_STORE, MEMORY_RECALL, MEMORY_SKILL_DELETE];
}
RSEOF
    : > "$FIX/scripts/qc-allowlists/doc-surface-completeness-allow.txt"

    run_fixture() { ( AI_MEMORY_SURFACE_GATE_ROOT="$FIX" "$SELF" >/dev/null 2>&1; echo "$?" ); }
    run_fixture_out() { AI_MEMORY_SURFACE_GATE_ROOT="$FIX" "$SELF" 2>&1 || true; }

    write_clean() {
        : > "$FIX/scripts/qc-allowlists/doc-surface-completeness-allow.txt"
        # Every surface documented. NEAR-MISS CONTROLS that must PASS:
        #  * `verify-reflection-chain` appears ONLY inside a ```code fence```
        #  * the item route is documented with `:id`, not `{id}`
        #  * a frozen v0.9.0 doc ALSO names memory_store — but the LIVE
        #    reference is what counts (frozen is neither required nor
        #    sufficient); memory_store is also named live, so it passes.
        cat > "$FIX/docs/CLI_REFERENCE.md" <<'MDEOF'
# CLI Reference

## serve
The `serve` subcommand starts the daemon.

## stop
The `stop` subcommand freezes the record plane.

Examples:
```
ai-memory verify-reflection-chain <id>
```
MDEOF
        cat > "$FIX/docs/API_REFERENCE.md" <<'MDEOF'
# API Reference

- `GET /api/v1/memories` — list.
- `GET /api/v1/memories/:id` — fetch one (documented with :id, not {id}).
- `POST /api/v1/subscriptions` — subscribe.
- `GET /metrics` — Prometheus.
MDEOF
        cat > "$FIX/docs/agent-skills.md" <<'MDEOF'
# Skills
Tools: `memory_store`, `memory_recall`, `memory_skill_delete`.
MDEOF
        # A frozen snapshot names memory_store too — must not be the ONLY
        # thing keeping any tool covered (control below removes it live).
        cat > "$FIX/docs/v0.9.0/release-notes.md" <<'MDEOF'
At v0.9.0 the surface included `memory_store` and `memory_skill_delete`.
MDEOF
    }

    write_clean
    rc="$(run_fixture)"
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: self-test — the CLEAN near-miss control tree was REJECTED (exit $rc)." >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 1
    fi
    echo "PASS: self-test control — a fenced-only subcommand, a :id-documented route, and a live+frozen tool all PASS"

    # ---- an UNDOCUMENTED subcommand (the #2831 CLI class) ------------
    write_clean
    # Drop `stop` from the doc entirely.
    cat > "$FIX/docs/CLI_REFERENCE.md" <<'MDEOF'
# CLI Reference
## serve
```
ai-memory verify-reflection-chain <id>
```
MDEOF
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an undocumented Command variant (stop) was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'CLI' && run_fixture_out | grep -q 'stop' || {
        echo "FAIL: self-test — CLI omission not named in the violation" >&2; exit 1; }
    echo "PASS: self-test — an undocumented \`stop\` subcommand is REJECTED"

    # ---- a hidden command is EXEMPT ---------------------------------
    write_clean
    # SecretInternal is #[command(hide)] and appears in NO doc — must still PASS.
    run_fixture_out | grep -q 'secret-internal' && {
        echo "FAIL: self-test — a #[command(hide)] variant was required in the docs" >&2; exit 1; }
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test — the clean tree with a hidden command was REJECTED" >&2
        run_fixture_out | sed 's/^/       /' >&2; exit 1; }
    echo "PASS: self-test — a #[command(hide)] variant is EXEMPT from the completeness requirement"

    # ---- an UNDOCUMENTED route (the #2831 route class) --------------
    write_clean
    cat > "$FIX/docs/API_REFERENCE.md" <<'MDEOF'
# API Reference
- `GET /api/v1/memories` — list.
- `GET /api/v1/memories/:id` — fetch one.
- `GET /metrics` — Prometheus.
MDEOF
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an undocumented route (/api/v1/subscriptions) was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'ROUTE' || {
        echo "FAIL: self-test — route omission not reported under the ROUTE rule" >&2; exit 1; }
    echo "PASS: self-test — an undocumented route is REJECTED"

    # ---- an UNDOCUMENTED tool (the #2831 destructive-tool class) ----
    write_clean
    cat > "$FIX/docs/agent-skills.md" <<'MDEOF'
# Skills
Tools: `memory_store`, `memory_recall`.
MDEOF
    # memory_skill_delete now lives ONLY in the frozen v0.9.0 snapshot.
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — a tool documented ONLY in a frozen docs/v0.*/ file was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'TOOL' && run_fixture_out | grep -q 'memory_skill_delete' || {
        echo "FAIL: self-test — frozen-only tool coverage not rejected under the TOOL rule" >&2; exit 1; }
    echo "PASS: self-test — a tool named ONLY in a frozen docs/v0.*/ file does NOT count as coverage"

    # ---- BURN-DOWN allowlist: BOTH directions, stale FAILS ----------
    allow="$FIX/scripts/qc-allowlists/doc-surface-completeness-allow.txt"
    write_clean
    cat > "$FIX/docs/CLI_REFERENCE.md" <<'MDEOF'
# CLI Reference
## serve
```
ai-memory verify-reflection-chain <id>
```
MDEOF
    printf 'CLI stop #2831\n' > "$allow"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test allowlist — an ALLOWLISTED omission still failed" >&2
        run_fixture_out | sed 's/^/       /' >&2; exit 1; }
    echo "PASS: self-test allowlist — an allowlisted omission PASSES"

    write_clean
    printf 'CLI stop #2831\n' > "$allow"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test allowlist — a STALE entry PASSED. This ledger must not be able to rot." >&2; exit 1; }
    run_fixture_out | grep -q 'STALE' || {
        echo "FAIL: self-test allowlist — stale entry rejected without naming it stale" >&2; exit 1; }
    echo "PASS: self-test allowlist — a STALE entry FAILS (burn-down discipline)"

    write_clean
    printf 'CLI\n' > "$allow"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test allowlist — a MALFORMED entry did not fail" >&2; exit 1; }
    echo "PASS: self-test allowlist — a MALFORMED entry HARD-FAILS"

    # ---- fail CLOSED on an analysis-engine error (#2713 shape) -------
    write_clean
    prefix_shape="$(v="$(python3 -c 'import sys; sys.exit(3)')" || true; [[ -z "$v" ]] && echo "WOULD-PRINT-PASS")"
    [[ "$prefix_shape" == "WOULD-PRINT-PASS" ]] || {
        echo "FAIL: self-test R-203 — the pre-fix \`|| true\` shape did not reproduce the false-PASS fail-open" >&2; exit 1; }
    fault_rc=0
    fault_out="$(AI_MEMORY_SURFACE_GATE_ROOT="$FIX" AI_MEMORY_SURFACE_GATE_SELFTEST_FAULT=1 "$SELF" 2>&1)" || fault_rc=$?
    [[ "$fault_rc" -ne 0 ]] || {
        echo "FAIL: self-test — the gate exited 0 on an injected analysis-engine fault (fail-OPEN)" >&2
        printf '%s\n' "$fault_out" | sed 's/^/       /' >&2; exit 1; }
    grep -q 'gate: PASS' <<<"$fault_out" && {
        echo "FAIL: self-test — the gate printed a PASS banner despite an engine fault" >&2; exit 1; }
    grep -q 'analysis engine errored' <<<"$fault_out" || {
        echo "FAIL: self-test — engine fault did not produce the distinct fail-closed message" >&2; exit 1; }
    echo "PASS: self-test — an analysis-engine error FAILS CLOSED (exit $fault_rc, distinct message, no PASS banner)"

    # ---- never a silent no-op (empty scan set) ----------------------
    write_clean
    : > "$FIX/src/daemon_runtime.rs"
    : > "$FIX/src/handlers/routes.rs"
    : > "$FIX/src/mcp/registry.rs"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an EMPTY scan set passed; the gate can no-op to green (#2444 shape)" >&2; exit 1; }
    echo "PASS: self-test — an empty scan set fails CLOSED rather than reporting an unearned pass"
    exit 0
fi

if [[ -n "${AI_MEMORY_SURFACE_GATE_ROOT:-}" ]]; then
    REPO_ROOT="$AI_MEMORY_SURFACE_GATE_ROOT"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$REPO_ROOT"

ALLOWLIST="$REPO_ROOT/scripts/qc-allowlists/doc-surface-completeness-allow.txt"

if ! violations="$(
    REPO_ROOT="$REPO_ROOT" python3 - <<'PY'
import glob
import os
import re

root = os.environ["REPO_ROOT"].rstrip("/")

# Self-test fault-injection (#2713): prove the gate FAILS CLOSED on an
# engine error instead of swallowing it into an empty violation set.
if os.environ.get("AI_MEMORY_SURFACE_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-doc-surface-completeness self-test: injected analysis-engine fault (#2713)")


def read(rel):
    p = os.path.join(root, rel)
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


def emit(rule, token, ctx):
    print(f"{rule}\t{token}\t{ctx[:160]}")


scan_total = 0

# ---- RULE CLI ---------------------------------------------------------
dr = read("src/daemon_runtime.rs")
cli_doc = read("docs/CLI_REFERENCE.md") or ""
if dr:
    m = re.search(r"pub enum Command\s*\{(.*?)\n\}", dr, re.S)
    if m:
        body = m.group(1)
        lines = body.splitlines()
        variants = []  # (name, hidden)
        pending_hidden = False
        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s.startswith("#["):
                # a command attribute — mark hidden if it hides the variant
                if re.search(r"\bhide\b", s):
                    pending_hidden = True
                continue
            if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
                continue
            vm = re.match(r"([A-Z][A-Za-z0-9]*)\s*[({,]", s)
            if vm:
                variants.append((vm.group(1), pending_hidden))
                pending_hidden = False
            else:
                # any other code line clears a pending attribute
                pending_hidden = False
        for name, hidden in variants:
            if hidden:
                continue
            scan_total += 1
            kebab = re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()
            # bounded word match: the kebab token not embedded in a longer
            # ident (so `--features` never satisfies the `features` subcommand)
            if not re.search(r"(?<![A-Za-z0-9_-])" + re.escape(kebab) + r"(?![A-Za-z0-9_-])", cli_doc):
                emit("CLI", kebab,
                     f"`Command::{name}` has no entry in docs/CLI_REFERENCE.md")

# ---- RULE ROUTE -------------------------------------------------------
def norm_path(p):
    p = re.sub(r"\{[^}]+\}", "{}", p)
    p = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "{}", p)
    p = re.sub(r"<[^>]+>", "{}", p)
    p = re.sub(r"\$\{[^}]+\}", "{}", p)
    return p


routes_rs = read("src/handlers/routes.rs")
api_doc = read("docs/API_REFERENCE.md") or ""
if routes_rs:
    consts = re.findall(r'pub const [A-Z0-9_]+: &str = "(/[^"]*)"', routes_rs)
    doc_paths = set(
        norm_path(x)
        for x in re.findall(r'/[A-Za-z0-9_/{}:<>$.\-]*', api_doc)
        if x.startswith("/api/") or x == "/metrics" or x.startswith("/health")
    )
    for p in consts:
        scan_total += 1
        if norm_path(p) not in doc_paths:
            emit("ROUTE", norm_path(p),
                 f"route const `{p}` has no entry in docs/API_REFERENCE.md")

# ---- RULE TOOL --------------------------------------------------------
FROZEN = re.compile(
    r"^docs/(v0\.|internal/|audit/|rfc/|adr|BASELINE|"
    r"v1\.0\.0/perfect-endpoint-assessment/)")

reg = read("src/mcp/registry.rs")
if reg:
    tnb = re.search(r"pub mod tool_names\s*\{(.*?)\n\}", reg, re.S)
    tools = []
    if tnb:
        tools = re.findall(r'pub const [A-Z0-9_]+: &str = "([a-z_][a-z0-9_]*)"', tnb.group(1))
    # LIVE doc corpus: top-level + docs/**/*.md minus frozen + CHANGELOG.
    docs = ["README.md", "ROADMAP.md", "CLAUDE.md", "PERFORMANCE.md"]
    docs += [d[len(root) + 1:] for d in glob.glob(os.path.join(root, "docs/**/*.md"), recursive=True)]
    live = []
    for d in docs:
        rel = d
        if FROZEN.match(rel) or "CHANGELOG" in rel:
            continue
        if os.path.exists(os.path.join(root, rel)):
            live.append(rel)
    corpus = "\n".join((read(d) or "") for d in live)
    for t in tools:
        scan_total += 1
        if not re.search(r"(?<![A-Za-z0-9_])" + re.escape(t) + r"(?![A-Za-z0-9_])", corpus):
            emit("TOOL", t,
                 f"tool `{t}` (registry::tool_names) is named in no live doc")

# ---- FAIL CLOSED on an empty scan set ---------------------------------
if scan_total == 0:
    print("SETUP\t-\tno CLI variants / routes / tools parsed; the gate would be a no-op")
PY
)"; then
    printf 'FAIL: check-doc-surface-completeness: analysis engine errored (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' >&2
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
            printf 'FAIL: doc-surface-completeness allowlist: malformed entry "%s"\n' "$raw" >&2
            printf '       expected: <RULE> <token> #<issue>   (RULE = CLI|ROUTE|TOOL)\n' >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        allow_keys="${allow_keys}${1}|${2}"$'\n'
    done < "$ALLOWLIST"
fi

if [[ -n "$violations" ]]; then
    while IFS=$'\t' read -r rule token ctx; do
        [[ -z "${rule:-}" ]] && continue
        if [[ "$rule" == "SETUP" ]]; then
            printf 'FAIL: doc-surface-completeness: %s\n' "$ctx" >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        key="${rule}|${token}"
        if [[ -n "$allow_keys" ]] && grep -Fxq "$key" <<<"$allow_keys"; then
            allow_used="${allow_used}${key}"$'\n'
            continue
        fi
        case "$rule" in
            CLI)   detail="Command variant is not documented in docs/CLI_REFERENCE.md" ;;
            ROUTE) detail="routes.rs path is not documented in docs/API_REFERENCE.md" ;;
            TOOL)  detail="registry tool is documented in no live (non-frozen, non-CHANGELOG) doc" ;;
            *)     detail="undocumented surface" ;;
        esac
        printf 'FAIL: doc-surface-completeness [%s]: "%s" — %s\n' "$rule" "$token" "$detail" >&2
        printf '       %s\n' "$ctx" >&2
        fail_count=$((fail_count + 1))
    done <<<"$violations"
fi

# A STALE entry FAILS (burn-down, not pending-fix): nothing else is
# concurrently correcting these omissions, so an entry that suppresses
# nothing is pure rot.
if [[ -n "$allow_keys" ]]; then
    while IFS= read -r k; do
        [[ -z "$k" ]] && continue
        if ! grep -Fxq "$k" <<<"$allow_used"; then
            printf 'FAIL: doc-surface-completeness allowlist: STALE entry (suppresses nothing) — delete it: %s\n' \
                "$(tr '|' ' ' <<<"$k")" >&2
            fail_count=$((fail_count + 1))
        fi
    done < <(sort -u <<<"$allow_keys")
fi

if [[ "$fail_count" -gt 0 ]]; then
    printf '\n❌ doc surface completeness gate: %d violation(s)\n' "$fail_count" >&2
    printf '   Document the surface in its canonical reference doc, or (last resort)\n' >&2
    printf '   add a `<RULE> <token> #<issue>` burn-down entry with a tracking issue.\n' >&2
    printf '   A reference doc that CLAIMS completeness it lacks is the #2492 overclaim class.\n' >&2
    exit 1
fi
printf '✅ doc surface completeness gate: PASS\n'
