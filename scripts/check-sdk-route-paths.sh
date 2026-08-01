#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-sdk-route-paths.sh
#
# v1.0.0 CERT GATE 2 — SDK-PATH-vs-`routes.rs` MEMBERSHIP gate
# (3x7 claims register 3.3.2, `docs/audit/3x7-claims-register-2026-08-01.md`).
#
# THE DEFECT THIS CLOSES. Nothing pinned the SDK READMEs or the SDK
# client sources against `src/handlers/routes.rs`, so a published SDK
# method could name a route the server has never registered and every
# gate in the repo stayed green. Two shipped instances:
#
#   C-19 — `grant()` / `revoke()` / `cluster()` shipped in BOTH SDKs,
#          calling `/api/v1/memories/{id}/grant`,
#          `/api/v1/memories/{id}/revoke` and `/api/v1/cluster`. Those
#          three paths have ZERO hits in `routes.rs`. Three shipped,
#          documented, typed SDK methods that 404 at runtime. The TS
#          source even says so in a comment ("Some may not be merged
#          server-side yet") — the knowledge was in the tree and no
#          control acted on it.
#   C-20 — TS `unsubscribe(id)` targets `DELETE
#          /api/v1/subscriptions/:id`, but `src/lib.rs` registers
#          `delete` on `"/api/v1/subscriptions"` ONLY and the id rides
#          the QUERY STRING (`src/handlers/subscriptions.rs`). This is
#          the subtler half: the RESOURCE exists, only the SHAPE is
#          wrong, so an "is this string anywhere in routes.rs" grep
#          would have passed it.
#
# The register calls the check "mechanically trivial", and it is — the
# value is that it catches both AT AUTHORING TIME rather than at a
# customer's first call.
#
# HOW IT WORKS (dependency-free: grep/python3 only, because CI has no
# codegraph).
#
#   1. Build the REGISTERED path set from the `routes.rs` SSOT — one
#      `pub const … : &str = "/api/v1/…"` per production route path
#      (#1558 batch 4; `src/lib.rs` registers these and the postgres
#      surface gate / federation receiver / CLI doctor match on them,
#      so the const set IS the surface).
#   2. Extract every `/api/v1/…` path literal from the SDK sources and
#      SDK READMEs.
#   3. NORMALISE path PARAMETERS on both sides — `{id}`, `:id`,
#      `${encodeURIComponent(id)}`, `{memory_id}`, `<id>` all collapse
#      to the single placeholder `{}`. This is the load-bearing step
#      and the reason the rule catches C-20: a correctly-templated path
#      (`/api/v1/memories/:id` -> `/api/v1/memories/{}`) is a MEMBER,
#      while a wrong-SHAPE path (`/api/v1/subscriptions/:id` ->
#      `/api/v1/subscriptions/{}`) is NOT, because only the collection
#      path is registered. Comparing raw strings would miss it; ignoring
#      parameters entirely would miss it in the other direction.
#   4. Assert membership. A non-member is a violation.
#
# PENDING-FIX ledger: `scripts/qc-allowlists/sdk-route-paths-pending.txt`
# (see that file's header for the stale-entry-is-a-NOTICE rationale).
#
# CLI:
#   scripts/check-sdk-route-paths.sh              — run the gate (exit 0/1)
#   scripts/check-sdk-route-paths.sh --self-test  — plant C-19 + C-20 in a
#       throwaway copy UNDER `.local-runs/` (never system /tmp, never
#       `mktemp -d`) and prove the gate rejects each, alongside NEAR-MISS
#       controls that must each PASS so the rule is shown to fire on the
#       defect and not on its neighbourhood.
#
# Path inputs (env-overridable so --self-test can point at fixtures):
#   SDK_ROUTES_RS   (default <root>/src/handlers/routes.rs)
#   SDK_SCAN_ROOT   (default <root>)

set -euo pipefail

# --------------------------------------------------------------------
# Self-test — dispatched BEFORE the gate body so it can drive the real,
# unmodified script against a planted fixture tree.
# --------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    FIX="$ROOT/.local-runs/sdk-route-paths-selftest-$$"
    rm -rf "$FIX"
    mkdir -p "$FIX/src/handlers" "$FIX/sdk/typescript/src" "$FIX/sdk/python/ai_memory" \
             "$FIX/sdk/typescript" "$FIX/sdk/python" "$FIX/scripts/qc-allowlists"
    trap 'rm -rf "$FIX"' EXIT

    # A minimal routes.rs SSOT in the real house shape: the collection
    # path is registered, the {id} member path is NOT — which is exactly
    # the asymmetry C-20 tripped over.
    cat > "$FIX/src/handlers/routes.rs" <<'ROUTESEOF'
pub const MEMORIES: &str = "/api/v1/memories";
pub const MEMORIES_ID: &str = "/api/v1/memories/{id}";
pub const MEMORIES_ID_PROMOTE: &str = "/api/v1/memories/{id}/promote";
pub const SUBSCRIPTIONS: &str = "/api/v1/subscriptions";
pub const HEALTH: &str = "/api/v1/health";
ROUTESEOF

    run_fixture() { ( AI_MEMORY_SDK_GATE_ROOT="$FIX" "$SELF" >/dev/null 2>&1; echo "$?" ); }
    run_fixture_out() { AI_MEMORY_SDK_GATE_ROOT="$FIX" "$SELF" 2>&1 || true; }

    write_clean() {
        rm -f "$FIX"/sdk/typescript/src/client.ts "$FIX"/sdk/python/ai_memory/client.py \
              "$FIX"/sdk/typescript/README.md "$FIX"/sdk/python/README.md \
              "$FIX"/scripts/qc-allowlists/sdk-route-paths-pending.txt
        # NEAR-MISS CONTROLS. Every one of these must PASS, so the rule
        # is shown to fire on the DEFECT and not on its neighbourhood:
        #  * a correctly-templated member path in each SDK's own dialect
        #    (`:id` TS, `{memory_id}` py f-string, `${...}` TS template)
        #  * the collection path with a QUERY STRING (the shape C-20's
        #    fix must adopt) — the `?` must not make it a new path
        #  * the bare `/api/v1/` base-URL prefix, which is prose, not a
        #    route claim
        cat > "$FIX/sdk/typescript/src/client.ts" <<'TSEOF'
// Base path is `/api/v1/` for every call.
/** `DELETE /api/v1/memories/:id` — delete one. */
const a = `/api/v1/memories/${encodeURIComponent(id)}`;
const b = `/api/v1/memories/${encodeURIComponent(id)}/promote`;
const c = "/api/v1/subscriptions?id=abc";
const d = "/api/v1/health";
TSEOF
        cat > "$FIX/sdk/python/ai_memory/client.py" <<'PYEOF'
# ``GET /api/v1/memories/{id}``
X = f"/api/v1/memories/{memory_id}"
Y = "/api/v1/subscriptions"
PYEOF
        cat > "$FIX/sdk/typescript/README.md" <<'MDEOF'
| `get(id)` | `GET /api/v1/memories/:id` | Fetch one. |
MDEOF
        cat > "$FIX/sdk/python/README.md" <<'MDEOF'
| `health()` | `/api/v1/health` | Liveness. |
MDEOF
    }

    write_clean
    rc="$(run_fixture)"
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: self-test — the CLEAN near-miss control tree was REJECTED (exit $rc)." >&2
        echo "       A rule that fires on a correctly-templated path is useless." >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 1
    fi
    echo "PASS: self-test control — templated member paths, a query-string collection call, and the bare /api/v1/ prefix all PASS"

    # ---- C-19: three shipped methods with ZERO hits in routes.rs -----
    for c19 in "/api/v1/memories/\${encodeURIComponent(id)}/grant" \
               "/api/v1/memories/\${encodeURIComponent(id)}/revoke" \
               "/api/v1/cluster"; do
        write_clean
        printf 'const dead = `%s`;\n' "$c19" >> "$FIX/sdk/typescript/src/client.ts"
        rc="$(run_fixture)"
        if [[ "$rc" = "0" ]]; then
            echo "FAIL: self-test C-19 — gate ACCEPTED an unregistered SDK path: $c19" >&2
            exit 1
        fi
    done
    echo "PASS: self-test C-19 — grant / revoke / cluster (zero hits in routes.rs) are each REJECTED"

    # C-19 in the python client + both READMEs too, since the register's
    # disposition is "delete from both SDKs and both READMEs".
    write_clean
    printf 'Z = f"/api/v1/memories/{memory_id}/grant"\n' >> "$FIX/sdk/python/ai_memory/client.py"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-19 — python client grant() accepted" >&2; exit 1; }
    write_clean
    printf '| `cluster(req)` | `POST /api/v1/cluster` | Peer management. |\n' >> "$FIX/sdk/python/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-19 — python README cluster row accepted" >&2; exit 1; }
    write_clean
    printf '| `grant(id)` | `POST /api/v1/memories/:id/grant` | ACL. |\n' >> "$FIX/sdk/typescript/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-19 — TS README grant row accepted" >&2; exit 1; }
    echo "PASS: self-test C-19 — the same dead paths are REJECTED in the python client and in BOTH READMEs"

    # ---- C-20: the WRONG-SHAPE path. The resource exists; only the
    # parameterisation is wrong. This is the leg that proves the
    # normalisation is load-bearing: a raw-string membership test would
    # have accepted it (`/api/v1/subscriptions` IS in routes.rs) and a
    # parameter-blind test would have accepted it too.
    write_clean
    printf 'const u = `/api/v1/subscriptions/${encodeURIComponent(id)}`;\n' >> "$FIX/sdk/typescript/src/client.ts"
    rc="$(run_fixture)"
    if [[ "$rc" = "0" ]]; then
        echo "FAIL: self-test C-20 — gate ACCEPTED DELETE /api/v1/subscriptions/:id" >&2
        echo "       The collection path is registered; the MEMBER path is not. That distinction IS the rule." >&2
        exit 1
    fi
    run_fixture_out | grep -q '/api/v1/subscriptions/{}' || {
        echo "FAIL: self-test C-20 — violation reported without the normalised form" >&2; exit 1; }
    echo "PASS: self-test C-20 — the wrong-SHAPE subscriptions member path is REJECTED (normalised to /api/v1/subscriptions/{})"

    write_clean
    printf '| `unsubscribe(id)` | `DELETE /api/v1/subscriptions/:id` | Remove. |\n' >> "$FIX/sdk/typescript/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-20 — TS README unsubscribe row accepted" >&2; exit 1; }
    echo "PASS: self-test C-20 — the README row documenting the same wrong shape is REJECTED"

    # ---- LEDGER, all three directions --------------------------------
    led="$FIX/scripts/qc-allowlists/sdk-route-paths-pending.txt"
    write_clean
    printf 'const dead = "/api/v1/cluster";\n' >> "$FIX/sdk/typescript/src/client.ts"
    printf 'Z = f"/api/v1/memories/{memory_id}/grant"\n' >> "$FIX/sdk/python/ai_memory/client.py"
    printf 'sdk/typescript/src/client.ts /api/v1/cluster #1\n' > "$led"
    out="$(run_fixture_out)"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test ledger — an UNLEDGERED violation was suppressed" >&2; exit 1; }
    grep -q 'targets "/api/v1/cluster"' <<<"$out" && {
        echo "FAIL: self-test ledger — a LEDGERED violation was still reported" >&2; exit 1; }
    grep -q '/api/v1/memories/{}/grant' <<<"$out" || {
        echo "FAIL: self-test ledger — the unledgered violation was not reported" >&2; exit 1; }
    echo "PASS: self-test ledger — suppresses exactly its own key and nothing else"

    write_clean
    printf 'sdk/typescript/src/client.ts /api/v1/cluster #1\n' > "$led"
    [[ "$(run_fixture)" = "0" ]] || { echo "FAIL: self-test ledger — a STALE entry FAILED the gate" >&2; exit 1; }
    run_fixture_out | grep -q 'ledger entry is STALE' || {
        echo "FAIL: self-test ledger — a STALE entry produced no NOTICE (the ledger can rot)" >&2; exit 1; }
    echo "PASS: self-test ledger — a STALE entry is a loud NOTICE, not a failure"

    write_clean
    printf 'sdk/typescript/src/client.ts\n' > "$led"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test ledger — a MALFORMED entry did not fail" >&2; exit 1; }
    run_fixture_out | grep -q 'malformed entry' || {
        echo "FAIL: self-test ledger — malformed entry not named" >&2; exit 1; }
    echo "PASS: self-test ledger — a MALFORMED entry HARD-FAILS"

    # ---- The gate must never be a silent no-op ------------------------
    rm -rf "$FIX/sdk"
    mkdir -p "$FIX/sdk"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an EMPTY sdk tree passed; the gate can no-op to green (#2444 shape)" >&2; exit 1; }
    echo "PASS: self-test — an empty sdk scan set fails CLOSED rather than reporting an unearned pass"
    exit 0
fi

if [[ -n "${AI_MEMORY_SDK_GATE_ROOT:-}" ]]; then
    REPO_ROOT="$AI_MEMORY_SDK_GATE_ROOT"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$REPO_ROOT"

ROUTES_RS="${SDK_ROUTES_RS:-$REPO_ROOT/src/handlers/routes.rs}"
LEDGER="$REPO_ROOT/scripts/qc-allowlists/sdk-route-paths-pending.txt"

# SDK surfaces scanned. Client SOURCES and READMEs both, because the
# register names both and because a README that documents a dead method
# is the same lie as the method itself.
SDK_FILES=()
while IFS= read -r f; do
    SDK_FILES+=("$f")
done < <(
    {
        find "$REPO_ROOT/sdk" -type f \
            \( -name '*.ts' -o -name '*.py' -o -name '*.js' -o -name 'README.md' \) \
            -not -path '*/node_modules/*' -not -path '*/__tests__/*' -not -path '*/tests/*' \
            2>/dev/null || true
    } | sort
)

if [[ ! -f "$ROUTES_RS" ]]; then
    printf 'FAIL: sdk-route-paths: routes SSOT not found at %s\n' "$ROUTES_RS" >&2
    exit 1
fi
if [[ "${#SDK_FILES[@]}" -eq 0 ]]; then
    # Fail CLOSED. An empty scan set would make this gate a control that
    # reports success while doing nothing — the #2444 shape the register
    # names as worse than a missing control.
    printf 'FAIL: sdk-route-paths: scanned ZERO sdk files under %s/sdk (gate would be a no-op)\n' "$REPO_ROOT" >&2
    exit 1
fi

violations="$(
    ROUTES_RS="$ROUTES_RS" \
    SDK_FILE_LIST="$(printf '%s\n' "${SDK_FILES[@]}")" \
    REPO_ROOT="$REPO_ROOT" \
    python3 - <<'PY'
import os
import re

root = os.environ["REPO_ROOT"].rstrip("/")
routes_rs = os.environ["ROUTES_RS"]
sdk_files = [f for f in os.environ["SDK_FILE_LIST"].splitlines() if f.strip()]

PARAM = re.compile(r"^(?:\{[^}]*\}|:[A-Za-z_][A-Za-z0-9_]*|\$\{.*\}|<[^>]*>)$")


def normalise(path):
    """Collapse every path-PARAMETER segment to the single `{}` token.

    `{id}` / `{memory_id}` / `:id` / `${encodeURIComponent(id)}` / `<id>`
    all mean "one caller-supplied segment here", so they must compare
    equal; anything else is a literal segment and must match verbatim.
    """
    path = path.split("?", 1)[0].split("#", 1)[0]
    path = path.rstrip("/.,;:)*`\"'")
    segs = path.split("/")
    out = []
    for s in segs:
        out.append("{}" if PARAM.match(s) else s)
    return "/".join(out)


# ---- 1. registered set, from the routes.rs SSOT ----------------------
registered = set()
for line in open(routes_rs, encoding="utf-8"):
    m = re.search(r'pub const [A-Z0-9_]+: *&str *= *"(/[^"]*)"', line)
    if m:
        registered.add(normalise(m.group(1)))

if not registered:
    print("SSOT\t-\t0\t-\troutes.rs yielded ZERO path consts")
    raise SystemExit(0)

# ---- 2/3. SDK literals, normalised the same way ----------------------
# A template literal's `${...}` may itself contain `/`, `)` and quotes
# (`${encodeURIComponent(id)}`), so `${...}` is consumed as one unit
# BEFORE the ordinary terminator class applies.
LITERAL = re.compile(r"/api/v1/(?:\$\{[^}]*\}|[^\s\"'`)\]|,;<>]|<[^>]*>)*")

for f in sdk_files:
    try:
        text = open(f, encoding="utf-8").read()
    except OSError:
        continue
    rel = f[len(root) + 1:] if f.startswith(root + "/") else f
    for ln, line in enumerate(text.splitlines(), 1):
        for hit in LITERAL.finditer(line):
            raw = hit.group(0)
            norm = normalise(raw)
            # A bare `/api/v1` / `/api/v1/` is the base-URL prefix, not a
            # route claim (it appears in SDK prose and in the client's
            # own base-path constant).
            if norm in ("/api/v1", "/api/v1/"):
                continue
            if norm in registered:
                continue
            print(f"{rel}\t{ln}\t{raw}\t{norm}\t{line.strip()[:140]}")
PY
)" || true

# ---- PENDING-FIX ledger ---------------------------------------------
# Format: `<sdk-file> <normalised-path> #<issue> <note>`. Same three
# dispositions as the docs-vs-SSOT ledger: MALFORMED hard-fails, a used
# entry suppresses silently, a STALE entry is a loud NOTICE (never a
# failure) because it can only suppress a violation that no longer
# happens and failing on it would red whichever PR lost the race to the
# SDK-correction lane.
ledger_keys=""
ledger_used=""
fail_count=0

if [[ -f "$LEDGER" ]]; then
    while IFS= read -r raw; do
        entry="${raw%%#*}"
        entry="$(printf '%s' "$entry" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -z "$entry" ]] && continue
        # shellcheck disable=SC2086
        set -- $entry
        if [[ $# -ne 2 ]] || [[ "$2" != /api/v1/* ]] || ! grep -qE '#[0-9]+' <<<"$raw"; then
            printf 'FAIL: sdk-route-paths ledger: malformed entry "%s"\n' "$raw" >&2
            printf '       expected: <sdk-file> <normalised-path> #<issue>\n' >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        ledger_keys="${ledger_keys}${1}|${2}"$'\n'
    done < "$LEDGER"
fi

if [[ -n "$violations" ]]; then
    while IFS=$'\t' read -r f ln raw norm ctx; do
        [[ -z "${f:-}" ]] && continue
        if [[ "$f" == "SSOT" ]]; then
            printf 'FAIL: sdk-route-paths: %s\n' "$ctx" >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        key="${f}|${norm}"
        if [[ -n "$ledger_keys" ]] && grep -Fxq "$key" <<<"$ledger_keys"; then
            ledger_used="${ledger_used}${key}"$'\n'
            continue
        fi
        printf 'FAIL: sdk-route-paths: %s:%s targets "%s" (normalised "%s") which is NOT a registered route path\n' \
            "$f" "$ln" "$raw" "$norm" >&2
        printf '       context: %s\n' "$ctx" >&2
        fail_count=$((fail_count + 1))
    done <<<"$violations"
fi

if [[ -n "$ledger_keys" ]]; then
    while IFS= read -r k; do
        [[ -z "$k" ]] && continue
        if ! grep -Fxq "$k" <<<"$ledger_used"; then
            printf 'NOTICE: sdk-route-paths ledger entry is STALE (suppresses nothing) — delete it: %s\n' \
                "$(tr '|' ' ' <<<"$k")" >&2
        fi
    done < <(sort -u <<<"$ledger_keys")
fi

if [[ "$fail_count" -gt 0 ]]; then
    printf '\n❌ SDK-path-vs-routes.rs gate: %d violation(s)\n' "$fail_count" >&2
    printf '   Registered production route paths come from %s.\n' "${ROUTES_RS#"$REPO_ROOT"/}" >&2
    printf '   Either register the route, or delete/repoint the SDK method + its README row.\n' >&2
    exit 1
fi
printf '✅ SDK-path-vs-routes.sh gate: PASS (%d sdk files scanned)\n' "${#SDK_FILES[@]}"
