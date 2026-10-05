#!/usr/bin/env bash
# postgres-droplet-reinit.sh — reset the v0.7.0 postgres droplet's
# `aimemory` schema state and stand up clean disposable databases for
# integration / live A2A scenarios.
#
# WHEN TO RUN
# -----------
#   * The droplet's primary `aimemory` database was bootstrapped against
#     an older `postgres_schema.sql` and is missing columns / indices
#     that the current build's `INIT_SCHEMA` expects (the symptom
#     surfaced in v0.7.0 Wave-3 Continuation 2: `agent_id_idx` generated
#     column was added after the droplet was first provisioned, so
#     `CREATE INDEX idx_memories_agent_id ON memories (agent_id_idx)`
#     failed before any migration could run).
#   * You need a clean roster of per-scenario disposable databases for
#     a Wave-4-style live A2A re-validation pass and want them all
#     bootstrapped to the same schema version.
#   * A previous run left half-applied schema state and you want to
#     blow it away from a known-good baseline.
#
# WHEN *NOT* TO RUN
# -----------------
#   * On a postgres host that is actively serving production traffic
#     for any tenant. This script destroys data. The pg_dump backup is
#     defense in depth, not a license to skip a maintenance window.
#   * Without first verifying you have a current `ai-memory schema-init`
#     binary on the orchestrator host. Bootstrapping with a stale
#     binary just reproduces the original drift.
#
# WHAT THIS DOES (defense-in-depth ordering)
# ------------------------------------------
#   1. Take a pg_dump custom-format backup of the existing `aimemory`
#      database into /var/backups/. Backups are timestamped and never
#      overwritten.
#   2. DROP / CREATE the primary `aimemory` database and reinstall the
#      `age` + `vector` extensions (extension installs into the new
#      database; they are per-database in PostgreSQL).
#   3. Run `ai-memory schema-init --json` against the fresh database to
#      bootstrap the bundled `postgres_schema.sql`, run pending
#      migrations, and create the `memory_graph` AGE projection. The
#      JSON report is captured for audit + verification.
#   4. CREATE a roster of disposable per-scenario databases
#      (`aimemory_w4_<subset>`) and schema-init each one. These exist
#      so parallel scenario subsets do not pollute each other's state.
#   5. Print a verification summary (table counts, schema_version,
#      extensions, AGE projection state) to stdout for the operator's
#      runbook.
#
# WHAT THIS DOES NOT DO
# ---------------------
#   * Touch `template1`, `postgres`, or any pre-existing operator
#     database (`aimemory_perf*`, `aimemory_kg*`, `aimemory_smoke`, …).
#     Those are left alone so prior testing artifacts survive.
#   * Run the daemon. After this script completes, redeploy / restart
#     `ai-memory.service` on each daemon host so the new schema is
#     picked up by the running process.
#   * Push or commit anything. This is purely an operator runbook
#     helper.
#
# REQUIREMENTS
# ------------
#   * Run on the postgres droplet (or a host with `psql` + `pg_dump`
#     and network access to the postgres host).
#   * `AI_MEMORY_BIN` must point to a v0.7.0 build that supports the
#     `schema-init` subcommand (Wave-1 Fix 3, commit 90b4144 onwards).
#     If the binary is on a different host, set `AI_MEMORY_SSH_HOST`
#     and the script will run schema-init via SSH.
#   * `PG_PASSWORD_FILE` must contain the postgres role password (mode
#     0600). Default: /root/aimemory-pg-password.txt.
#   * `PG_SSLROOTCERT` must name the CA certificate file that signed the
#     postgres server certificate (on the host that runs schema-init, so on
#     the AI_MEMORY_SSH_HOST host when that is set). schema-init connects
#     with sslmode=verify-full&sslrootcert=<PG_SSLROOTCERT> (#5143, #3705).
#     No default: an unset, unreadable or oddly spelled path is refused before
#     the backup and the first DROP. With AI_MEMORY_SSH_HOST set, one
#     verify-full psql connection from that host (psql must be installed
#     there) must also succeed before the backup, or the run exits 7 (#5600).
#   * `PG_DUMP_SSLROOTCERT` (#5402): the CA file for the pg_dump backup, on THIS
#     host (pg_dump connects to PG_HOST over TCP with sslmode=verify-full).
#     Defaults to PG_SSLROOTCERT when AI_MEMORY_SSH_HOST is unset; required when
#     it is set. Refused (exit 7) before the backup and the first DROP.
#
# USAGE
# -----
#   sudo ./postgres-droplet-reinit.sh                 # default: full reinit
#   sudo ./postgres-droplet-reinit.sh --dry-run       # show plan, take no action
#   sudo ./postgres-droplet-reinit.sh --skip-disposable
#                                                     # only re-init `aimemory`
#   sudo ./postgres-droplet-reinit.sh --yes           # skip the interactive
#                                                     # type-the-db-name confirm
#                                                     # (vetted automation only)
#
# The live (non --dry-run) path prompts you to TYPE the primary db name
# (#1785) before any DROP DATABASE runs; pass --yes/-y to bypass it for
# vetted automation. A non-interactive stdin without --yes is refused.
#
# POST-RUN VERIFICATION
# ---------------------
#   * /tmp/aimemory-schema-init.json should show
#       tables   > 0
#       schema_version == 28   (v0.7.0 expected)
#       extensions includes "age" and "vector"
#       age_projection_created == true
#   * `psql -c "\\dt" aimemory` lists the v0.7.0 table set (memories,
#     memory_links, archived_memories, pending_actions, sync_state,
#     subscriptions, namespace_meta, entity_aliases, schema_version,
#     plus any v0.7.0 additions: agent_registry, audit_log, transcripts,
#     transcript_links, signed_events, agent_quotas, …).
#   * Each disposable database should have an identical schema_version
#     (compare via `SELECT version FROM schema_version` across the
#     roster).
#
# Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via env)
# ---------------------------------------------------------------------------

PG_HOST="${PG_HOST:-10.20.0.4}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-aimemory}"
PG_PRIMARY_DB="${PG_PRIMARY_DB:-aimemory}"
PG_PASSWORD_FILE="${PG_PASSWORD_FILE:-/root/aimemory-pg-password.txt}"
# #5143: every 1.0.0 binary refuses a PostgreSQL store DSN that does not pin
# sslmode=verify-full (#3705, loopback included), so schema-init needs the CA
# bundle that signed the server certificate. No default: unset is refused.
PG_SSLROOTCERT="${PG_SSLROOTCERT:-}"
# #5402: pg_dump runs on THIS host and connects to PG_HOST over TCP, so it needs
# a CA file on this host: PG_DUMP_SSLROOTCERT, defaulting to PG_SSLROOTCERT when
# no AI_MEMORY_SSH_HOST is set (one host runs both). With an ssh host the
# PG_SSLROOTCERT path is remote, so PG_DUMP_SSLROOTCERT must be set explicitly.
PG_DUMP_SSLROOTCERT="${PG_DUMP_SSLROOTCERT:-}"

BACKUP_DIR="${BACKUP_DIR:-/var/backups}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/aimemory-pre-reinit-${TIMESTAMP}.dump"
SCHEMA_INIT_JSON="${SCHEMA_INIT_JSON:-/tmp/aimemory-schema-init-${TIMESTAMP}.json}"

AI_MEMORY_BIN="${AI_MEMORY_BIN:-/opt/ai-memory-src/target/release/ai-memory}"
AI_MEMORY_SSH_HOST="${AI_MEMORY_SSH_HOST:-}"   # empty => run binary locally

DISPOSABLE_DBS=(
    aimemory_w4_core
    aimemory_w4_federation
    aimemory_w4_kg
    aimemory_w4_audit
    aimemory_w4_governance
    aimemory_w4_recall
    aimemory_w4_subscriptions
    aimemory_w4_smoke
)

DRY_RUN=0
SKIP_DISPOSABLE=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --skip-disposable) SKIP_DISPOSABLE=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --help|-h)
            sed -n '1,/^set -euo pipefail$/p' "$0" | sed -e 's/^# \?//' -e '$d'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "DRY-RUN: $*"
    else
        log "RUN: $*"
        "$@"
    fi
}

require_password() {
    if [[ ! -r "$PG_PASSWORD_FILE" ]]; then
        echo "FATAL: cannot read postgres password file: $PG_PASSWORD_FILE" >&2
        exit 3
    fi
    PG_PWD="$(cat "$PG_PASSWORD_FILE")"
    export PGPASSWORD="$PG_PWD"
}

# libpq conninfo value: backslash and single quote escaped, the value single-quoted.
conninfo_quote() {
    local v="$1"
    v="${v//\\/\\\\}"
    v="${v//\'/\\\'}"
    printf "'%s'" "$v"
}

# #5600: with AI_MEMORY_SSH_HOST, schema-init connects from the remote host with
# the remote CA path, which pg_dump (on this host) does not prove. Before the
# backup and any DROP, make one sslmode=verify-full psql connection from the
# remote host to the same host, port, user and database as the store URL, with
# the same CA path, and refuse (exit 7) when it fails. The password and the
# connection string go over ssh stdin, never argv (#4603). psql must be
# installed on the remote host; without it the probe fails and the run stops.
require_remote_verify_full() {
    local conninfo
    conninfo="host=$(conninfo_quote "$PG_HOST") port=${PG_PORT} user=$(conninfo_quote "$PG_USER") dbname=${PG_PRIMARY_DB} sslmode=verify-full sslrootcert=${PG_SSLROOTCERT}"
    if ! printf '%s\n%s\n' "$PG_PWD" "$conninfo" | ssh "$AI_MEMORY_SSH_HOST" \
        "unset PGSERVICE PGSERVICEFILE; IFS= read -r PGPASSWORD; IFS= read -r c; export PGPASSWORD PGSSLMODE=verify-full PGSSLROOTCERT='$PG_SSLROOTCERT'; exec psql \"\$c\" -X -q -t -A -c 'select 1'" >/dev/null; then
        echo "FATAL: a sslmode=verify-full connection from $AI_MEMORY_SSH_HOST to ${PG_HOST}:${PG_PORT} with sslrootcert=$PG_SSLROOTCERT failed; refusing before the backup and any DROP (#5600)" >&2
        exit 7
    fi
}

# #5143: refuse BEFORE the backup and any DROP unless the CA path is usable.
# Plain path characters only: the path is spliced into the store URL query.
require_sslrootcert() {
    if [[ -z "$PG_SSLROOTCERT" ]]; then
        echo "FATAL: PG_SSLROOTCERT is unset: schema-init needs the CA file for sslmode=verify-full (#3705, #5143)" >&2
        exit 7
    fi
    if [[ ! "$PG_SSLROOTCERT" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
        echo "FATAL: PG_SSLROOTCERT must be an absolute path of [A-Za-z0-9._/-] characters" >&2
        exit 7
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
        return 0
    fi
    if [[ -n "$AI_MEMORY_SSH_HOST" ]]; then
        if ! ssh "$AI_MEMORY_SSH_HOST" "test -r '$PG_SSLROOTCERT'"; then
            echo "FATAL: PG_SSLROOTCERT $PG_SSLROOTCERT is not readable on $AI_MEMORY_SSH_HOST" >&2
            exit 7
        fi
        require_remote_verify_full
    elif [[ ! -r "$PG_SSLROOTCERT" ]]; then
        echo "FATAL: PG_SSLROOTCERT $PG_SSLROOTCERT is not readable" >&2
        exit 7
    fi
}

# #5449: PG_PRIMARY_DB is spliced into the pg_dump connection string and into
# DROP/CREATE DATABASE, so only a plain identifier is accepted; a conninfo such
# as "dbname=x sslmode=disable" would otherwise outrank the PGSSLMODE pin.
# #5484: lower case only. DROP/CREATE DATABASE below are unquoted, so PostgreSQL folds
# the name to lower case, while the pg_dump dbname is case-sensitive: an upper case name
# would back up one database and drop another.
require_primary_db_identifier() {
    if [[ ! "$PG_PRIMARY_DB" =~ ^[a-z_][a-z0-9_]*$ ]]; then
        echo "FATAL: PG_PRIMARY_DB must be a plain identifier in lower case ([a-z_][a-z0-9_]*) (#5449, #5484)" >&2
        exit 7
    fi
}

# #5454: PG_PORT is spliced into the pg_dump connection string and passed to the local
# psql, so it must be a port number (no leading zero, 1..65535); the backup, the DROP and
# the store URL then name the same server.
require_pg_port() {
    if [[ ! "$PG_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || (( PG_PORT > 65535 )); then
        echo "FATAL: PG_PORT must be a port number from 1 to 65535 (#5454)" >&2
        exit 7
    fi
}

# #5402: the pg_dump backup is a TCP connection to PG_HOST; refuse BEFORE the
# backup and any DROP unless it can run with sslmode=verify-full and a local CA.
require_dump_sslrootcert() {
    if [[ -z "$PG_DUMP_SSLROOTCERT" && -z "$AI_MEMORY_SSH_HOST" ]]; then
        PG_DUMP_SSLROOTCERT="$PG_SSLROOTCERT"
    fi
    if [[ -z "$PG_DUMP_SSLROOTCERT" ]]; then
        echo "FATAL: PG_DUMP_SSLROOTCERT is unset: pg_dump runs on this host and needs a local CA file for sslmode=verify-full (AI_MEMORY_SSH_HOST is set, so PG_SSLROOTCERT is a remote path) (#5402)" >&2
        exit 7
    fi
    if [[ ! "$PG_DUMP_SSLROOTCERT" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
        echo "FATAL: PG_DUMP_SSLROOTCERT must be an absolute path of [A-Za-z0-9._/-] characters (#5402)" >&2
        exit 7
    fi
    if [[ "$DRY_RUN" -ne 1 && ! -r "$PG_DUMP_SSLROOTCERT" ]]; then
        echo "FATAL: PG_DUMP_SSLROOTCERT $PG_DUMP_SSLROOTCERT is not readable on this host (#5402)" >&2
        exit 7
    fi
}

# #1785 — interactive confirmation gate on the LIVE (non-dry-run)
# destructive path. The operator must TYPE the primary db name to confirm
# before any `DROP DATABASE` runs (step 2 primary + step 4 disposables).
# No-op under --dry-run (psql_postgres only logs there). Bypassable with
# --yes/-y for vetted automation; refuses to silently proceed on a
# non-interactive stdin without --yes so a fat-fingered piped invocation
# cannot drop the prod db unattended.
confirm_destruction() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        return 0
    fi
    if [[ "$ASSUME_YES" -eq 1 ]]; then
        log "confirmation bypassed via --yes; proceeding with destructive reinit"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        echo "FATAL: refusing to DROP DATABASE on a non-interactive stdin without --yes." >&2
        echo "       Re-run attached to a terminal, or pass --yes if this is vetted automation." >&2
        exit 6
    fi
    echo "" >&2
    echo "WARNING: this will DROP DATABASE ${PG_PRIMARY_DB} (and the disposable scenario" >&2
    echo "         databases unless --skip-disposable) on host ${PG_HOST}. This DESTROYS data." >&2
    echo "         A pg_dump backup was taken at ${BACKUP_FILE}, but recovery is manual." >&2
    local typed=""
    read -r -p "Type the database name (${PG_PRIMARY_DB}) to confirm, anything else to abort: " typed
    if [[ "$typed" != "$PG_PRIMARY_DB" ]]; then
        echo "FATAL: confirmation text did not match '${PG_PRIMARY_DB}' — aborting before destructive step." >&2
        exit 6
    fi
    log "confirmation accepted; proceeding with destructive reinit"
}

psql_postgres() {
    # Run psql as the OS `postgres` superuser via local socket — no
    # password required. Use this for DROP / CREATE DATABASE and
    # CREATE EXTENSION since `aimemory` role is not a superuser.
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "DRY-RUN: sudo -u postgres psql -p ${PG_PORT} $*"
    else
        sudo -u postgres psql -p "$PG_PORT" "$@"
    fi
}

run_schema_init() {
    local db="$1"
    # #5143: pin sslmode=verify-full (the #3705 floor refuses any other DSN).
    local url="postgres://${PG_USER}:${PG_PWD}@${PG_HOST}:${PG_PORT}/${db}?sslmode=verify-full&sslrootcert=${PG_SSLROOTCERT}"
    local out="${SCHEMA_INIT_JSON%.json}-${db}.json"
    # #4603: the store URL carries the db password, so it never goes on argv
    # (local /proc/<pid>/cmdline, nor the ssh remote command string, which is
    # argv on the remote host). It reaches schema-init through the
    # AI_MEMORY_STORE_URL env channel (src/store_url.rs resolve_store_url): set
    # in the local process env, or piped over ssh stdin and exported remotely.
    # #4796: AI_MEMORY_STORE_URL_FILE outranks the env channel, so an exported
    # FILE from the caller would initialise the wrong database. Both forms
    # unset it (the local form in a subshell, so the caller's export stays).
    log "schema-init -> ${db} (output: ${out})"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "DRY-RUN: schema-init --json for ${db} via ${AI_MEMORY_SSH_HOST:-local} (store URL postgres://${PG_USER}:***@${PG_HOST}:${PG_PORT}/${db}?sslmode=verify-full&sslrootcert=${PG_SSLROOTCERT}) | tee ${out}"
        return 0
    fi
    if [[ -n "$AI_MEMORY_SSH_HOST" ]]; then
        printf '%s\n' "$url" | ssh "$AI_MEMORY_SSH_HOST" \
            "unset AI_MEMORY_STORE_URL_FILE; IFS= read -r AI_MEMORY_STORE_URL; export AI_MEMORY_STORE_URL; exec '$AI_MEMORY_BIN' schema-init --json" | tee "$out"
    else
        ( unset AI_MEMORY_STORE_URL_FILE; AI_MEMORY_STORE_URL="$url" "$AI_MEMORY_BIN" schema-init --json ) | tee "$out"
    fi
    echo
    # Quick sanity check
    if command -v jq >/dev/null 2>&1; then
        local tables version age_ok
        tables="$(jq -r '.tables | length' "$out" 2>/dev/null || echo 0)"
        version="$(jq -r '.schema_version' "$out" 2>/dev/null || echo unknown)"
        age_ok="$(jq -r '.age_projection_created' "$out" 2>/dev/null || echo unknown)"
        log "  -> tables=${tables} schema_version=${version} age_projection_created=${age_ok}"
    fi
}

# ---------------------------------------------------------------------------
# Step 0 — preflight
# ---------------------------------------------------------------------------

log "postgres-droplet-reinit.sh starting (dry_run=${DRY_RUN}, skip_disposable=${SKIP_DISPOSABLE})"
require_primary_db_identifier
require_pg_port
require_password
require_sslrootcert
require_dump_sslrootcert

if [[ -z "$AI_MEMORY_SSH_HOST" && ! -x "$AI_MEMORY_BIN" ]]; then
    echo "FATAL: ai-memory binary not found at $AI_MEMORY_BIN — set AI_MEMORY_BIN or AI_MEMORY_SSH_HOST" >&2
    exit 4
fi

# ---------------------------------------------------------------------------
# Step 1 — backup
# ---------------------------------------------------------------------------

run mkdir -p "$BACKUP_DIR"
log "step 1: pg_dump ${PG_PRIMARY_DB} -> ${BACKUP_FILE}"
if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: pg_dump -h ${PG_HOST} -U ${PG_USER} -d 'dbname=${PG_PRIMARY_DB} port=${PG_PORT} sslmode=verify-full sslrootcert=${PG_DUMP_SSLROOTCERT}' -F c -f ${BACKUP_FILE}"
else
    # #5402 / #5449: libpq ranks a connection string above PGSSLMODE/PGSSLROOTCERT and
    # above a PGSERVICE file, so the pin is IN the connection string (measured: a
    # conninfo sslmode=disable and a service-file sslmode=disable both beat the env
    # pin; the conninfo pin beats a service file) and the service sources are
    # unset. PGPASSWORD stays in the environment, never on the argv.
    unset PGSERVICE PGSERVICEFILE
    PGSSLMODE=verify-full PGSSLROOTCERT="$PG_DUMP_SSLROOTCERT" \
        pg_dump -h "$PG_HOST" -U "$PG_USER" \
        -d "dbname=${PG_PRIMARY_DB} port=${PG_PORT} sslmode=verify-full sslrootcert=${PG_DUMP_SSLROOTCERT}" \
        -F c -f "$BACKUP_FILE"
    if [[ ! -s "$BACKUP_FILE" ]]; then
        echo "FATAL: backup file is empty — aborting before destructive step" >&2
        exit 5
    fi
    log "  -> $(ls -lh "$BACKUP_FILE" | awk '{print $5, $9}')"
fi

# ---------------------------------------------------------------------------
# Step 2 — drop + recreate primary
# ---------------------------------------------------------------------------

# #1785 — interactive confirm AFTER the backup (so the pg_dump-first guard
# is preserved) and BEFORE the first DROP. No-op under --dry-run.
confirm_destruction

log "step 2: drop + recreate ${PG_PRIMARY_DB}"
psql_postgres -c "DROP DATABASE IF EXISTS ${PG_PRIMARY_DB};"
psql_postgres -c "CREATE DATABASE ${PG_PRIMARY_DB} OWNER ${PG_USER};"
psql_postgres -d "$PG_PRIMARY_DB" -c "CREATE EXTENSION IF NOT EXISTS age;"
psql_postgres -d "$PG_PRIMARY_DB" -c "CREATE EXTENSION IF NOT EXISTS vector;"

# ---------------------------------------------------------------------------
# Step 3 — schema-init primary
# ---------------------------------------------------------------------------

log "step 3: schema-init ${PG_PRIMARY_DB}"
run_schema_init "$PG_PRIMARY_DB"

# ---------------------------------------------------------------------------
# Step 4 — disposable scenario databases
# ---------------------------------------------------------------------------

if [[ "$SKIP_DISPOSABLE" -eq 1 ]]; then
    log "step 4: SKIPPED (--skip-disposable)"
else
    log "step 4: disposable scenario databases"
    for db in "${DISPOSABLE_DBS[@]}"; do
        log "  - ${db}: drop + create + extensions"
        psql_postgres -c "DROP DATABASE IF EXISTS ${db};"
        psql_postgres -c "CREATE DATABASE ${db} OWNER ${PG_USER};"
        psql_postgres -d "$db" -c "CREATE EXTENSION IF NOT EXISTS age;"
        psql_postgres -d "$db" -c "CREATE EXTENSION IF NOT EXISTS vector;"
        run_schema_init "$db"
    done
fi

# ---------------------------------------------------------------------------
# Step 5 — verification
# ---------------------------------------------------------------------------

log "step 5: verification"
if [[ "$DRY_RUN" -eq 0 ]]; then
    log "  primary db (${PG_PRIMARY_DB}) tables:"
    psql_postgres -d "$PG_PRIMARY_DB" -c "\dt" || true
    log "  primary db schema_version row:"
    psql_postgres -d "$PG_PRIMARY_DB" -c "SELECT version FROM schema_version;" || true
    log "  primary db extensions:"
    psql_postgres -d "$PG_PRIMARY_DB" -c "SELECT extname, extversion FROM pg_extension ORDER BY extname;" || true
fi

log "DONE — backup at ${BACKUP_FILE}"
log "DONE — schema-init reports under ${SCHEMA_INIT_JSON%.json}-*.json"
