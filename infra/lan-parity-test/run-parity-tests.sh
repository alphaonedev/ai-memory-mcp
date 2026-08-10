#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Runs the SAL-postgres cross-adapter parity tests against the scoped
# LAN-parity PG+AGE container exposed on 127.0.0.1:15432. Captures the
# full log under .local-runs/ for ship-gate audit trail.
#
# WHY `-- --test-threads=1` IS MANDATORY (do not remove):
#   The sal-postgres suite shares ONE `ai_memory_test` database with NO
#   per-test schema isolation (see CLAUDE.md §"Local coverage"). Running
#   it WITHOUT serialising threads lets two postgres-backed tests grab the
#   same advisory-lock key (`SELECT pg_advisory_lock($1)`) and DEADLOCK on
#   shared Postgres locks. This actually happened during the v1.0.0 cert
#   campaign: a parallel run wedged after 7007 passing tests, with a stack
#   of sessions blocked on `pg_advisory_lock` (the oldest stuck 6h27m),
#   until the run had to be killed. Serialising with `--test-threads=1`
#   is the same posture CI's coverage.yml already uses.
#
# The suite runs in TWO serialized passes: the default pass, then a second
# pass with `--include-ignored` so the `#[ignore]`-gated live-pg tests are
# exercised too. The script exits non-zero if EITHER pass fails.
#
# WHY PASS 2 GIVES EACH BINARY ITS OWN DATABASE (#2848 — durable class fix):
#   Pass 1 (the default suite) shares ONE `ai_memory_test` database, which
#   is safe because `--test-threads=1` serialises access. Pass 2 exercises
#   the `#[ignore]`-gated LIVE-PG tests, several of which SEED long-lived
#   rows in mutable, cross-test-contaminating tables (e.g. the #1831 G17
#   recovery tests seed `agent_lineage` `ai:rec-*` rows). Serialisation
#   prevents a DEADLOCK but NOT contamination: residue one binary leaves
#   behind can perturb a LATER binary's preconditions, so a live-pg test
#   can silently pass or fail on the order it happened to run in. #2843
#   (PR #2847) made one such test order-independent; this is the durable
#   CLASS fix — Pass 2 enumerates the compiled test binaries and gives each
#   binary that carries `#[ignore]`-gated tests its OWN freshly-created
#   database (age + vector extensions, empty schema bootstrapped on first
#   connect), runs just that binary `--include-ignored --test-threads=1`
#   against it, then DROPs it. No binary can ever observe another binary's
#   residue. This is the CLAUDE.md #79/#898 shared-DB-no-isolation lesson
#   applied structurally. A binary with NO `#[ignore]` tests is SKIPPED in
#   Pass 2 (its `--include-ignored` run would be byte-identical to its
#   Pass 1 run — no new coverage, no DB needed), which also keeps the
#   per-binary DB churn proportional to the live-pg surface.
#
# Pre-flight:
#   docker compose -f infra/lan-parity-test/docker-compose.yml up -d pg-age
#   (wait for pg-age healthcheck → healthy)
#
# Usage:
#   ./infra/lan-parity-test/run-parity-tests.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
LOG="$REPO_ROOT/.local-runs/lan-parity-${TIMESTAMP}.log"
mkdir -p "$(dirname "$LOG")"

# Connection components (shared by Pass 1's PG_URL and Pass 2's per-binary
# databases). PG_URL resolves to the identical string Pass 1 has always
# used, so Pass 1 behaviour is unchanged.
PG_HOST="127.0.0.1"
PG_PORT="15432"
PG_USER="ai_memory"
PG_PASS="ai_memory_test"
PG_MAINT_DB="ai_memory_test"
# Prefix for the throwaway per-binary Pass-2 probe databases. Kept distinct
# from PG_MAINT_DB so leftover probes are trivially identifiable + reapable.
PG_PROBE_PREFIX="ai_memory_test_p2_"
PG_URL="postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${PG_MAINT_DB}"

echo "[lan-parity] PG URL: ${PG_URL/${PG_PASS}@/<redacted>@}"
echo "[lan-parity] Log:    $LOG"
echo "[lan-parity] Pre-flight PG reach check..."
PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_MAINT_DB" \
    -c "SELECT 'pg+age reachable' AS status;" >/dev/null
echo "[lan-parity] PG+AGE reachable. Running cargo SAL-postgres tests..."
echo ""

# Pass 1 — default suite, serialized (--test-threads=1 mandatory; see header).
echo "[lan-parity] Pass 1/2: default suite (serialized)..."
AI_MEMORY_TEST_POSTGRES_URL="$PG_URL" \
AI_MEMORY_NO_CONFIG=1 \
cargo test --features sal,sal-postgres --release -- --test-threads=1 2>&1 | tee "$LOG"
EXIT_DEFAULT=${PIPESTATUS[0]}
echo ""
echo "[lan-parity] Pass 1/2 cargo exit code: $EXIT_DEFAULT"

# ---------------------------------------------------------------------------
# Pass 2 — #[ignore]-gated live-pg tests, serialized, PER-BINARY-ISOLATED.
# Appended to the same log. See the header block for why each binary gets its
# own fresh database.
# ---------------------------------------------------------------------------

# psql against the maintenance DB (used only for CREATE/DROP DATABASE, which
# cannot run inside a transaction block — hence one `-c` per statement).
export PGPASSWORD="$PG_PASS"
pg_maint() {
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_MAINT_DB" \
        -v ON_ERROR_STOP=1 -q "$@"
}

# Track the probe DBs this run created so the EXIT trap can reap them even on
# an early failure / interrupt. Idempotent: DROP ... IF EXISTS WITH (FORCE).
declare -a CREATED_PROBE_DBS=()
cleanup_probe_dbs() {
    local db
    for db in "${CREATED_PROBE_DBS[@]:-}"; do
        [ -n "$db" ] || continue
        pg_maint -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE);" >/dev/null 2>&1 || true
    done
}
trap cleanup_probe_dbs EXIT

# Reap any probe DBs left behind by a previously-crashed run (idempotent /
# safe-to-re-run).
reap_stale_probe_dbs() {
    local stale db
    stale="$(pg_maint -tA -c \
        "SELECT datname FROM pg_database WHERE datname LIKE '${PG_PROBE_PREFIX}%';" \
        2>/dev/null || true)"
    for db in $stale; do
        [ -n "$db" ] || continue
        echo "[lan-parity]   reaping stale probe DB: $db"
        pg_maint -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE);" >/dev/null 2>&1 || true
    done
}

echo ""
echo "[lan-parity] Pass 2/2: #[ignore]-gated live-pg tests (per-binary DB isolation)..."
{
    echo ""
    echo "[lan-parity] Pass 2/2: #[ignore]-gated live-pg tests (per-binary DB isolation)..."
} >> "$LOG"

reap_stale_probe_dbs

# Enumerate the compiled test binaries. `--no-run` builds them (a near-no-op
# after Pass 1) and the JSON stream carries each runnable test binary's path.
echo "[lan-parity]   enumerating test binaries (cargo test --no-run)..."
BINARIES_RAW="$(
    AI_MEMORY_NO_CONFIG=1 \
    cargo test --features sal,sal-postgres --release --no-run \
        --message-format=json 2>>"$LOG" \
    | python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line or not line.startswith("{"):
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") != "compiler-artifact":
        continue
    exe = msg.get("executable")
    prof = msg.get("profile") or {}
    if exe and prof.get("test"):
        print(exe)
'
)"

if [ -z "${BINARIES_RAW//[[:space:]]/}" ]; then
    echo "[lan-parity] ERROR: no test binaries enumerated for Pass 2." | tee -a "$LOG"
    EXIT_IGNORED=1
else
    EXIT_IGNORED=0
    PROBE_IDX=0
    # Iterate binaries. For each that carries >=1 ignored test, give it a fresh
    # DB, run it --include-ignored, then drop the DB. Do NOT let a single test
    # failure or a psql hiccup abort the whole loop (we aggregate the exit code
    # and must run every binary), so disable -e for the loop body and restore
    # it afterwards.
    set +e
    while IFS= read -r BIN; do
        [ -n "$BIN" ] || continue
        [ -x "$BIN" ] || continue

        # Count this binary's ignored tests. `--list --ignored` lists ONLY the
        # ignored tests without running them; each test prints one `<name>: test`
        # line. Zero => nothing new for Pass 2 to run (its non-ignored tests
        # already ran identically in Pass 1), so skip it.
        IGNORED_COUNT="$("$BIN" --list --ignored --format terse 2>/dev/null \
            | grep -c ': test$' || true)"
        IGNORED_COUNT="${IGNORED_COUNT:-0}"
        if [ "$IGNORED_COUNT" -eq 0 ]; then
            continue
        fi

        SLUG="$(basename "$BIN" | sed -E 's/-[0-9a-f]{8,}$//')"
        PROBE_DB="${PG_PROBE_PREFIX}${PROBE_IDX}"
        PROBE_IDX=$((PROBE_IDX + 1))

        echo "[lan-parity]   binary '${SLUG}' → DB '${PROBE_DB}' (${IGNORED_COUNT} ignored tests)" \
            | tee -a "$LOG"

        # Fresh database + extensions. Separate `-c` per CREATE/DROP DATABASE
        # (cannot share a transaction); CREATE EXTENSION is fine batched.
        pg_maint -c "DROP DATABASE IF EXISTS \"$PROBE_DB\" WITH (FORCE);" >>"$LOG" 2>&1
        if ! pg_maint -c "CREATE DATABASE \"$PROBE_DB\";" >>"$LOG" 2>&1; then
            echo "[lan-parity] ERROR: could not CREATE probe DB '$PROBE_DB'." | tee -a "$LOG"
            EXIT_IGNORED=1
            continue
        fi
        CREATED_PROBE_DBS+=("$PROBE_DB")
        if ! psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PROBE_DB" \
            -v ON_ERROR_STOP=1 -q \
            -c "CREATE EXTENSION IF NOT EXISTS age; CREATE EXTENSION IF NOT EXISTS vector;" \
            >>"$LOG" 2>&1; then
            echo "[lan-parity] ERROR: could not create age/vector in '$PROBE_DB'." | tee -a "$LOG"
            EXIT_IGNORED=1
            pg_maint -c "DROP DATABASE IF EXISTS \"$PROBE_DB\" WITH (FORCE);" >>"$LOG" 2>&1
            continue
        fi

        PROBE_URL="postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${PROBE_DB}"
        AI_MEMORY_TEST_POSTGRES_URL="$PROBE_URL" \
        AI_MEMORY_NO_CONFIG=1 \
        "$BIN" --include-ignored --test-threads=1 2>&1 | tee -a "$LOG"
        RC=${PIPESTATUS[0]}
        if [ "$RC" -ne 0 ]; then
            echo "[lan-parity]   binary '${SLUG}' FAILED (exit $RC)" | tee -a "$LOG"
            EXIT_IGNORED="$RC"
        fi

        # Drop the probe DB immediately (do not wait for the EXIT trap) so the
        # per-binary footprint stays a single database at a time.
        pg_maint -c "DROP DATABASE IF EXISTS \"$PROBE_DB\" WITH (FORCE);" >>"$LOG" 2>&1
        # It is now dropped; remove it from the trap's reap list.
        for i in "${!CREATED_PROBE_DBS[@]}"; do
            if [ "${CREATED_PROBE_DBS[$i]}" = "$PROBE_DB" ]; then
                unset 'CREATED_PROBE_DBS[i]'
            fi
        done
    done <<< "$BINARIES_RAW"
    set -e
fi

# Final safety-net cleanup (in case any probe DB survived the per-binary drop),
# then a fresh scan to prove none remain.
cleanup_probe_dbs
reap_stale_probe_dbs

echo ""
echo "[lan-parity] Pass 2/2 aggregate exit code: $EXIT_IGNORED"

# Propagate failure from EITHER pass (non-zero if either did not pass).
EXIT=0
if [ "$EXIT_DEFAULT" -ne 0 ]; then
    EXIT="$EXIT_DEFAULT"
elif [ "$EXIT_IGNORED" -ne 0 ]; then
    EXIT="$EXIT_IGNORED"
fi

echo ""
echo "[lan-parity] Overall exit code: $EXIT (default=$EXIT_DEFAULT, ignored=$EXIT_IGNORED)"
echo "[lan-parity] Log preserved at: $LOG"
exit "$EXIT"
