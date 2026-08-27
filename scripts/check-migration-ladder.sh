#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 guardrail-D (2x5-vote decision memory b682c76a) — FAIL-CLOSED
# MIGRATION-LADDER-UNIQUENESS gate.
#
# THE DEFECT THIS CLOSES (the silent migration-ladder-collision class).
# Migration SQL is loaded by `include_str!` at explicit paths in
# `src/storage/migrations.rs` (sqlite) + `src/store/postgres.rs` (postgres)
# with NO uniqueness enforcement anywhere. A PR built on an OLD base can add
# `migrations/postgres/0041_v82_archived_valid_time.sql` (#2036) while release
# already carries `migrations/postgres/0041_v84_embedding_space.sql` — SAME
# numeric prefix, DIFFERENT filename => ZERO git conflict. git silently keeps
# BOTH, the build succeeds, and a CORRUPTED / ambiguous ladder ships fleet-wide.
# Probe-guarded ALTERs make a double-apply a silent no-op (non-fail-closed).
# #2192 renumbered the collider to `0042_v85_*`; THIS gate structurally
# prevents the whole class from ever re-landing silently.
#
# DATA-INTEGRITY posture (North Star): a mixed / ambiguous schema ladder is a
# corruption vector; this gate DEGRADES a colliding PR to a loud non-zero exit
# rather than letting it corrupt the ladder. Fail-closed, not fail-silent.
#
# DETECTION RULES (any one => non-zero exit):
#   (a) two files in migrations/<backend>/ sharing the same 4-digit numeric
#       prefix (e.g. two `0041_*`) — the EXACT #2036-vs-#2192 collision shape.
#   (b) two ladder ARMS declaring the same schema VERSION (a duplicate
#       `if version < N {` in migrations.rs, or a duplicate `migrate_vN` /
#       `if current_version < N {` in postgres.rs). Arm-lane hardening (#2198,
#       Fable audit of #2197): the CURRENT house convention phrases the TAIL
#       arms against the const — `if version < CURRENT_SCHEMA_VERSION {` — which
#       is INVISIBLE to a literal-`N` scan (three demonstrated escapes: a 2nd
#       const-phrased arm; a literal `if version < 85` that duplicates the
#       const-phrased v85 tip; a postgres `fn migrate_v85_extra` name-variant).
#       So rule (b) now ALSO: (b1) NORMALIZES symbolic arms — a literal /
#       resolved-arithmetic (`CURRENT_SCHEMA_VERSION - K`) arm AT OR ABOVE the
#       const tip collides with the const-phrased cohort; (b2) PINS the exact
#       count of bare const-phrased arms per adapter (a silent add moves the
#       count and fails — bump the pin in lockstep, module-size-ceiling style);
#       (b3) flags a DUPLICATE migrate_vN VERSION even under a name-variant
#       (`migrate_vNN_suffix`) the exact-name dup regex misses.
#   (c) a GAP (outside the documented historical allow-list) OR a
#       non-monotonic jump in the ladder numbering: file prefixes must be
#       gap-free per backend, and the literal `if version < N` arm sequence
#       must be strictly increasing.
#   (d) cross-adapter DISAGREEMENT: the sqlite `CURRENT_SCHEMA_VERSION` must
#       equal the postgres `CURRENT_SCHEMA_VERSION`, the highest-prefix
#       migration file in each backend must carry that same `vNN` tag, and the
#       postgres ladder tip (`migrate_vN`) must equal it too.
#   (e) an ORPHAN migration file (present on disk but referenced NOWHERE under
#       src/, and not on the documented exempt list), or an `include_str!`
#       arm referencing a file that is missing on disk.
#   (f) a BOOTSTRAP↔LADDER FORWARD REFERENCE (#2424, the GA-blocker class): a
#       `CREATE [UNIQUE] INDEX` in a backend's BOOTSTRAP schema that references
#       a column the LADDER adds via `ALTER TABLE <t> ADD COLUMN <c>`. Both
#       adapters replay the bootstrap on EVERY open — `db::open` (sqlite) and
#       `PostgresStore::connect` (postgres) apply it BEFORE `migrate` — so on a
#       LEGACY database the pre-existing table makes `CREATE TABLE IF NOT
#       EXISTS` a no-op, the ALTER-added column is absent, and the inline index
#       CRASHES the open. `CREATE INDEX IF NOT EXISTS` does NOT save you: the
#       `IF NOT EXISTS` is keyed on the INDEX NAME, so a legacy DB that never
#       reached the arm which creates it takes the CREATE path and errors on
#       the missing column. This is exactly #1861 (sqlite, `idx_memories_cid`)
#       and #2424 (postgres: v67 `idx_memories_target_agent_id`, v74
#       `idx_memories_cid`, v84 `idx_memories_embedding_space` — two live
#       deployments bricked). An index on a ladder-added column belongs
#       EXCLUSIVELY in its `migrate_vN` arm / migration .sql file, which runs
#       AFTER the ALTER on legacy DBs and still runs on fresh installs (they
#       enter the ladder at version 0 and execute every arm) — so
#       `bootstrap(fresh)` and `ladder(v0→tip)` converge on the same schema.
#       That equivalence is the invariant; this rule is its static enforcement.
#   (g) a MISSING or SYMBOLICALLY-KEYED per-migration METADATA row (#3158, the
#       claims-truth class). `src/storage/migration_meta.rs::MIGRATION_LADDER`
#       is the operator-facing answer to "is this migration reversible? does it
#       lose data? is it idempotent?" — the input to every rollback plan. It
#       drifted silently to the point where the tail row was keyed to
#       `current_schema_version()` (so it re-labelled itself on every bump,
#       `meta_for(54)` returned None, `meta_for(89)` returned v54's semantics,
#       and there were NO rows at all for v54–v88 — 35 arms including three
#       full-table rebuilds), while its own lockstep test asserted
#       `last().version == current_schema_version()`, TRUE BY CONSTRUCTION.
#       This rule enforces, from the shell lane: (g1) exactly ONE meta row per
#       sqlite ladder arm — literal arms AND const-phrased arms, the latter
#       resolved from the mandatory `// vNN` comment that opens the arm body;
#       (g2) NO row keyed to `current_schema_version()` (every row is a
#       LITERAL, the same literalize-on-settle convention the postgres
#       `record_schema_version(&mut tx, 88)` stamps follow); (g3) the matrix is
#       gap-free from v2 to CURRENT_SCHEMA_VERSION, since every number in that
#       range is a real ladder step on at least one adapter. Mirrored by the
#       `arch_8_*` unit tests in migration_meta.rs, which additionally check
#       each row's NAME is grounded in the arm it describes.
#
# Mirrors the structure + `--self-test` convention of the sibling gates
# (`scripts/check-vendor-literals.sh`, `scripts/check-l3-boundary.sh`).
#
# CLI:
#   scripts/check-migration-ladder.sh              — run the gate (exit 0/1)
#   scripts/check-migration-ladder.sh --self-test  — plant the #2036/#2192
#       same-prefix-different-name shape AND a same-version-two-arms case AND
#       the #2424 v84 bootstrap-inline-index shape (both backends) in a
#       throwaway copy UNDER the repo (never system /tmp) AND the #3158
#       metadata-matrix escapes (a ladder arm with no meta row; a tail row
#       re-keyed to `current_schema_version()`) and confirm the gate rejects
#       EACH, plus a clean-tree control — proving it is load-bearing.
#
# Path inputs (env-overridable so --self-test can point at planted fixtures):
#   LADDER_MIGRATIONS_DIR  (default <root>/migrations)
#   LADDER_MIGRATIONS_RS   (default <root>/src/storage/migrations.rs)
#   LADDER_POSTGRES_RS     (default <root>/src/store/postgres.rs)
#   LADDER_PG_SCHEMA_SQL   (default <root>/src/store/postgres_schema.sql)
#   LADDER_SRC_DIR         (default <root>/src)  — orphan reference scan root
#   LADDER_MIGRATION_META_RS (default <root>/src/storage/migration_meta.rs)
#
# Requires bash >= 4 (Grok W2-bash3): this gate uses associative arrays
# (`declare -A`) and negative array indexing (`${arr[-1]}`), both absent
# from bash 3.2 (stock on macOS — Apple has shipped no post-3.2 bash since
# the GPLv3 switch). Running under 3.2 previously died with an opaque
# "bad array subscript" / syntax error deep in the script; the guard below
# fails fast with an actionable message instead.

if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "check-migration-ladder.sh: requires bash >= 4 (found ${BASH_VERSION:-unknown}) — this gate uses associative arrays + negative array indexing that stock macOS bash 3.2 cannot run. Install a modern bash (e.g. 'brew install bash') and re-run explicitly, e.g. '/opt/homebrew/bin/bash $0 --self-test'." >&2
    exit 1
fi

set -euo pipefail

# Membership test that is safe under `set -o pipefail`.
# `printf | grep -q` is a SIGPIPE footgun: grep -q closes the pipe on the
# first match, printf gets EPIPE, and pipefail makes a HIT look like a miss
# (CI on 02ee71f8: "NO row for v32" while MIGRATION_LADDER carries v32).
array_contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BACKENDS=(sqlite postgres)

# --- Documented historical exceptions (real tree, dated) -------------------
#
# KNOWN_PREFIX_GAPS: prefixes that are legitimately ABSENT from a backend's
# sequence. `sqlite:48` — the `0048_v58_recall_observations_identity.sql`
# file was removed after the v58 sqlite migration was folded into an inline
# probe-guarded arm; only a comment reference survives (src/store/postgres.rs).
# A NEW gap anywhere else still fails rule (c).
KNOWN_PREFIX_GAPS=("sqlite:48")
#
# LADDER_EXEMPT_FILES: migration files that legitimately live on disk without
# an `include_str!` / inline-arm reference under src/ (superseded / never-wired
# greenfield-era postgres files that predate the current ladder). A NEW
# unreferenced file still fails rule (e) until it is either wired or added
# here with a justification.
LADDER_EXEMPT_FILES=(
    "postgres/0011_v0631_data_integrity.sql"
    "postgres/0012_v0700_metadata_object_check.sql"
)
#
# EXPECTED_CONST_ARMS_<backend>: the exact count of bare const-phrased ladder
# arms — `if version < CURRENT_SCHEMA_VERSION {` (sqlite) /
# `if current_version < CURRENT_SCHEMA_VERSION {` (postgres) — that a
# convention-following tree carries (#2198). These arms are the idempotent,
# probe-guarded TAIL steps that run on any legacy upgrade; they gate on the
# symbolic const rather than a literal, so the literal-`N` duplicate/monotonic
# scan cannot see them. Pinning the count makes a silent ADD move the number
# and FAIL — the author must either renumber the previous tip arm to a literal
# (which then enters the monotonic lane) or bump this pin in lockstep with a
# dated comment. Same discipline as the qual_10 module-size ceilings. Mirrored
# in tests/migration_ladder_integrity.rs (EXPECTED_CONST_ARMS_*), bump both.
# 2026-07-18 (#2198): sqlite=8 (the v74/v75/v76/v77/v78/v79/v80/v85-era arms),
#                     postgres=1 (the single `if current_version < CSV` tail arm).
# 2026-07-19 (#1834 pre-ship 3x7 / PR #2265): sqlite stays 8 — the v86
#                     VALID-time rendering-normalization arm joins the
#                     const-phrased cohort AND the settled v85 arm is
#                     LITERALIZED to `if version < 85` (the #2218 convention:
#                     settled arms enter the monotonic literal lane, only the
#                     current tip stays symbolic), so the count is unchanged.
#                     postgres stays 1 (v85 renumbered to a literal arm,
#                     migrate_v86 takes the const tail slot).
# 2026-07-23 (#2333 FBL-03): counts UNCHANGED — the settled v86 arm is
#                     LITERALIZED on both backends (`if version < 86` /
#                     `if current_version < 86`) and the new v87 tip arm
#                     (archived_memories.kind_provenance + the #2332
#                     expiry-rendering heal) takes the const slot.
# 2026-07-31 (#2578): sqlite 8 -> 7 — v88 lands composite list indexes on
#                     POSTGRES only (sqlite has had them since v56), so there
#                     is NO sqlite v88 arm; the settled v87 arm is LITERALIZED
#                     to `if version < 87` and nothing takes the const slot.
#                     postgres stays 1 (v87 literalized, migrate_v88 takes the
#                     const tail slot).
# 2026-08-22 (#2385): sqlite 7 -> 8 — the v90 archive cid-parity arm takes the
# const-phrased tip slot sqlite left empty at v88/v89. Bumped in lockstep with
# tests/migration_ladder_integrity.rs::EXPECTED_CONST_ARMS_SQLITE.
EXPECTED_CONST_ARMS_SQLITE=8
EXPECTED_CONST_ARMS_POSTGRES=1

# --- Helpers ----------------------------------------------------------------

# extract_prefix <filename> -> 4-digit numeric prefix as a base-10 int, or empty.
extract_prefix() {
    local base="$1"
    if [[ "$base" =~ ^([0-9]{4})_ ]]; then
        # Strip leading zeros via base-10 arithmetic (10#) so `0048` -> 48.
        echo $((10#${BASH_REMATCH[1]}))
    fi
}

# extract_vtag <filename> -> the schema version from the FIRST `_vNN_` tag
# (leading zeros stripped), or empty when the file carries no numeric v-tag.
extract_vtag() {
    local base="$1"
    if [[ "$base" =~ _v0*([0-9]+)_ ]]; then
        echo $((10#${BASH_REMATCH[1]}))
    fi
}

# is_known_prefix_gap <backend> <int-prefix>
is_known_prefix_gap() {
    local key="$1:$2"
    local g
    for g in "${KNOWN_PREFIX_GAPS[@]}"; do
        [[ "$g" == "$key" ]] && return 0
    done
    return 1
}

# is_exempt_file <backend/filename>
is_exempt_file() {
    local rel="$1"
    local e
    for e in "${LADDER_EXEMPT_FILES[@]}"; do
        [[ "$e" == "$rel" ]] && return 0
    done
    return 1
}

# read_current_schema_version <rust-file> — parses `CURRENT_SCHEMA_VERSION: iNN = M`.
read_current_schema_version() {
    local f="$1"
    grep -oE 'CURRENT_SCHEMA_VERSION: i(32|64) = [0-9]+' "$f" 2>/dev/null \
        | head -1 | grep -oE '[0-9]+$' || true
}

# collect_arm_versions <rust-file> — echoes the schema version of each REAL
# ladder arm, in file order. Anchored to a code line that OPENS the arm block
# (`^<ws>if version < N {`) so a `///` doc-comment that merely mentions an arm
# (e.g. "the `if version < 34` arm only on a downgrade-replay path") is NOT
# mistaken for an out-of-order arm.
collect_arm_versions() {
    local f="$1"
    grep -E '^[[:space:]]*if version < [0-9]+ \{' "$f" 2>/dev/null \
        | grep -oE 'version < [0-9]+' | grep -oE '[0-9]+' || true
}

# collect_literal_arm_versions <rust-file> <arm-var> — the generic form of
# `collect_arm_versions` for either adapter's arm variable (`version` for
# sqlite migrations.rs, `current_version` for postgres.rs). Literal-`N` arms
# only, in file order.
collect_literal_arm_versions() {
    local f="$1" var="$2"
    grep -E "^[[:space:]]*if ${var} < [0-9]+ \{" "$f" 2>/dev/null \
        | grep -oE "${var} < [0-9]+" | grep -oE '[0-9]+' || true
}

# count_bare_const_arms <rust-file> <arm-var> — how many arms gate on the BARE
# symbolic const `if <var> < CURRENT_SCHEMA_VERSION {` (the count-pinned tail
# cohort). Arithmetic forms (`… - K`) are deliberately EXCLUDED here — those are
# resolved to a concrete numeric and treated as literal-equivalent arms.
count_bare_const_arms() {
    local f="$1" var="$2" n
    n="$(grep -cE "^[[:space:]]*if ${var} < CURRENT_SCHEMA_VERSION \{" "$f" 2>/dev/null || true)"
    echo "${n:-0}"
}

# collect_resolved_arithmetic_arms <rust-file> <arm-var> <csv> — NORMALIZATION:
# resolve `if <var> < CURRENT_SCHEMA_VERSION - K {` / `+ K` to its concrete
# numeric (csv-K / csv+K) so a symbolic-arithmetic arm cannot smuggle a
# duplicate of a literal arm past the scan. Emits one concrete version per such
# arm, in file order. (None exist in the tree today — this is the fail-closed
# generalization the #2198 normalization mandate asks for.)
collect_resolved_arithmetic_arms() {
    local f="$1" var="$2" csv="$3" line op num
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        op="$(printf '%s' "$line" | grep -oE '[-+] *[0-9]+' | grep -oE '[-+]' | head -1)"
        num="$(printf '%s' "$line" | grep -oE '[-+] *[0-9]+' | grep -oE '[0-9]+' | head -1)"
        [[ -z "$op" || -z "$num" ]] && continue
        if [[ "$op" == "-" ]]; then echo $((csv - num)); else echo $((csv + num)); fi
    done < <(grep -oE "^[[:space:]]*if ${var} < CURRENT_SCHEMA_VERSION *[-+] *[0-9]+ \{" "$f" 2>/dev/null || true)
}

# --- Rule (g) helpers: per-migration metadata coverage (#3158) ---------------

# collect_const_arm_versions <rust-file> — the schema version of every
# CONST-PHRASED sqlite arm (`if version < CURRENT_SCHEMA_VERSION {`), resolved
# from the MANDATORY `// vNN` comment that opens the arm body (the house
# convention for the tip cohort). Emits `?` for an arm that carries no such
# comment so rule (g) can FAIL LOUDLY rather than silently skipping an arm —
# a skipped arm is a missing meta row nobody would ever notice.
collect_const_arm_versions() {
    local f="$1"
    awk '
        /^[[:space:]]*if version < CURRENT_SCHEMA_VERSION \{/ { inarm = 1; found = 0; next }
        inarm && !found && /^[[:space:]]*\/\/ v[0-9]+/ {
            line = $0
            sub(/^[[:space:]]*\/\/ v/, "", line)
            n = ""
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1)
                if (c ~ /[0-9]/) { n = n c } else { break }
            }
            print n
            found = 1
            inarm = 0
            next
        }
        # An arm that opens another arm before yielding a `// vNN` comment.
        inarm && /^[[:space:]]*if version < / { print "?"; inarm = 0 }
    ' "$f" 2>/dev/null || true
}

# collect_meta_versions <migration_meta.rs> — the schema version of every
# MIGRATION_LADDER row (`meta(<N>, "NAME", …)` table entries).
collect_meta_versions() {
    local f="$1"
    grep -oE '^[[:space:]]*meta\([0-9]+,' "$f" 2>/dev/null \
        | grep -oE '[0-9]+' || true
}

# --- Rule (f) helpers: bootstrap↔ladder forward-reference (#2424) ------------
#
# strip_comments — drop `//`-style Rust comment lines and `--`-to-EOL SQL
# comments so DDL quoted in PROSE (a doc-comment describing an arm, a `--`
# rationale header in a .sql file) can never be mistaken for real DDL. Also
# neutralises Rust string-literal punctuation (`"` and the `\` line
# continuation) so a multi-line `sqlx::query("ALTER TABLE … \` statement scans
# the same as plain SQL.
strip_comments() {
    sed -e 's|^[[:space:]]*//.*$||' -e 's|//.*$||' -e 's|--.*$||' \
        -e 's|["\\]| |g' "$@" 2>/dev/null || true
}

# collect_ladder_added_columns <backend> <mig-dir> <ladder-rust-file>
#   Emits one `<table>.<column>` per ALTER-ADD-COLUMN found anywhere in the
#   backend's ladder (its migrations/<backend>/*.sql files AND the inline
#   `ALTER TABLE … ADD COLUMN` statements in the adapter's migrate arms).
#   Handles the multi-clause form
#       ALTER TABLE memory_links
#           ADD COLUMN IF NOT EXISTS valid_from  TIMESTAMPTZ,
#           ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ;
#   by carrying the most-recent `ALTER TABLE <t>` forward as the current
#   target. Table-QUALIFIED on purpose: `namespace` is ladder-added on
#   `agent_quotas` but original on `memories`, so an unqualified column-name
#   match would false-positive on `memories_namespace_idx`.
collect_ladder_added_columns() {
    local backend="$1" mig_dir="$2" ladder_rs="$3"
    local -a inputs=()
    [[ -d "$mig_dir/$backend" ]] && while IFS= read -r f; do
        inputs+=("$f")
    done < <(find "$mig_dir/$backend" -maxdepth 1 -type f -name '*.sql' | sort)
    [[ -f "$ladder_rs" ]] && inputs+=("$ladder_rs")
    (( ${#inputs[@]} == 0 )) && return 0

    strip_comments "${inputs[@]}" | awk '
        {
            line = $0
            if (match(line, /ALTER[ \t]+TABLE[ \t]+(IF[ \t]+EXISTS[ \t]+)?[A-Za-z_][A-Za-z0-9_]*/)) {
                s = substr(line, RSTART, RLENGTH)
                n = split(s, a, /[ \t]+/)
                cur = a[n]
            }
            rest = line
            while (cur != "" && match(rest, /ADD[ \t]+COLUMN[ \t]+(IF[ \t]+NOT[ \t]+EXISTS[ \t]+)?[A-Za-z_][A-Za-z0-9_]*/)) {
                s = substr(rest, RSTART, RLENGTH)
                n = split(s, a, /[ \t]+/)
                print cur "." a[n]
                rest = substr(rest, RSTART + RLENGTH)
            }
        }
    ' | sort -u
}

# extract_bootstrap <backend> <pg-schema-sql> <sqlite-migrations-rs>
#   Emits the backend's BOOTSTRAP schema text on stdout. Postgres keeps it in a
#   standalone .sql file; sqlite embeds it as the `const SCHEMA: &str = r"…";`
#   raw-string block at the top of migrations.rs (the rest of that file is
#   ladder arms, which must NOT be scanned as bootstrap).
extract_bootstrap() {
    local backend="$1" pg_sql="$2" sqlite_rs="$3"
    if [[ "$backend" == "postgres" ]]; then
        [[ -f "$pg_sql" ]] && cat "$pg_sql"
    else
        [[ -f "$sqlite_rs" ]] || return 0
        awk '/const SCHEMA: *&str *= *r"/ { inblock = 1; next }
             inblock && /^";$/          { inblock = 0; next }
             inblock                    { print }' "$sqlite_rs"
    fi
}

# collect_bootstrap_indexes  (stdin = bootstrap schema text)
#   Emits one `<index-name>|<table>|<rest-of-statement>` per CREATE INDEX,
#   re-joining statements that wrap across lines (every in-tree bootstrap
#   wraps the `ON <table> (<cols>)` clause onto its own line).
collect_bootstrap_indexes() {
    sed -e 's|--.*$||' | awk '
        BEGIN { acc = "" }
        {
            if (acc != "")                                    { acc = acc " " $0 }
            else if ($0 ~ /CREATE[ \t]+(UNIQUE[ \t]+)?INDEX/)  { acc = $0 }
            if (acc != "" && acc ~ /;/)                        { print acc; acc = "" }
        }
        END { if (acc != "") print acc }
    ' | awk '
        {
            if (!match($0, /CREATE[ \t]+(UNIQUE[ \t]+)?INDEX[ \t]+(IF[ \t]+NOT[ \t]+EXISTS[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]+ON[ \t]+[A-Za-z_][A-Za-z0-9_]*/)) next
            head = substr($0, RSTART, RLENGTH)
            rest = substr($0, RSTART + RLENGTH)
            n = split(head, a, /[ \t]+/)
            # …INDEX [IF NOT EXISTS] <name> ON <table> => a[n-2]=name, a[n]=table
            print a[n-2] "|" a[n] "|" rest
        }
    '
}

# --- The gate ---------------------------------------------------------------

run_gate() {
    local mig_dir="${LADDER_MIGRATIONS_DIR:-$ROOT/migrations}"
    local mig_rs="${LADDER_MIGRATIONS_RS:-$ROOT/src/storage/migrations.rs}"
    local pg_rs="${LADDER_POSTGRES_RS:-$ROOT/src/store/postgres.rs}"
    local pg_schema_sql="${LADDER_PG_SCHEMA_SQL:-$ROOT/src/store/postgres_schema.sql}"
    local src_dir="${LADDER_SRC_DIR:-$ROOT/src}"

    local violations=0
    local backend dir

    # CURRENT_SCHEMA_VERSION per adapter — read once up front so the arm-lane
    # normalization (rule b1) can resolve the const-phrased tip; rule (d)
    # cross-adapter agreement re-uses the same values.
    local cv_sqlite cv_pg
    cv_sqlite="$(read_current_schema_version "$mig_rs")"
    cv_pg="$(read_current_schema_version "$pg_rs")"

    # ---- Rule (a) + (c-gap): per-backend prefix uniqueness + gap-free -------
    for backend in "${BACKENDS[@]}"; do
        dir="$mig_dir/$backend"
        [[ -d "$dir" ]] || continue

        local -a prefixes=()
        local f base pfx
        local seen_dup=0
        # Map prefix -> first filename, to name a collision precisely.
        declare -A first_for=()
        while IFS= read -r f; do
            base="$(basename "$f")"
            pfx="$(extract_prefix "$base")"
            if [[ -z "$pfx" ]]; then
                echo "❌ migration-ladder [$backend]: file does not match NNNN_* convention: $base" >&2
                violations=$((violations + 1))
                continue
            fi
            if [[ -n "${first_for[$pfx]:-}" ]]; then
                echo "❌ migration-ladder [$backend]: RULE (a) DUPLICATE PREFIX $(printf '%04d' "$pfx") — the #2036/#2192 collision shape:" >&2
                echo "     ${first_for[$pfx]}" >&2
                echo "     ${base}" >&2
                echo "     Two files share one numeric prefix => an ambiguous ladder that ships silently. Renumber one." >&2
                violations=$((violations + 1))
                seen_dup=1
            else
                first_for[$pfx]="$base"
                prefixes+=("$pfx")
            fi
        done < <(find "$dir" -maxdepth 1 -type f -name '*.sql' | sort)
        unset first_for

        # Gap check over the sorted unique prefix set.
        if (( seen_dup == 0 )) && (( ${#prefixes[@]} > 0 )); then
            local sorted min max i
            IFS=$'\n' sorted=($(printf '%s\n' "${prefixes[@]}" | sort -n)); unset IFS
            min="${sorted[0]}"; max="${sorted[-1]}"
            for (( i = min; i <= max; i++ )); do
                if ! array_contains "$i" "${sorted[@]}"; then
                    if is_known_prefix_gap "$backend" "$i"; then
                        continue
                    fi
                    echo "❌ migration-ladder [$backend]: RULE (c) GAP in prefix sequence at $(printf '%04d' "$i") (present: ${min}..${max})." >&2
                    echo "     A skipped number hides a lost/renamed migration; renumber contiguously or document the gap in KNOWN_PREFIX_GAPS." >&2
                    violations=$((violations + 1))
                fi
            done
        fi
    done

    # ---- Rule (b) + (c-monotonic): sqlite arm versions ----------------------
    if [[ -f "$mig_rs" ]]; then
        local -a arms=()
        local v prev=""
        while IFS= read -r v; do
            [[ -z "$v" ]] && continue
            arms+=("$v")
            if [[ -n "$prev" ]] && (( v <= prev )); then
                echo "❌ migration-ladder [sqlite]: RULE (b)/(c) arm \`if version < $v\` is not strictly greater than the preceding \`if version < $prev\` (duplicate or out-of-order arm)." >&2
                violations=$((violations + 1))
            fi
            prev="$v"
        done < <(collect_arm_versions "$mig_rs")

        # (b1) NORMALIZATION + tip-cohort ceiling (#2198): a literal or
        #      resolved-arithmetic arm AT OR ABOVE CURRENT_SCHEMA_VERSION
        #      duplicates the const-phrased `if version < CURRENT_SCHEMA_VERSION`
        #      tip cohort. Catches the D1b escape (a literal `if version < 85`
        #      alongside the const-phrased v85 tip — invisible to the monotonic
        #      scan because 85 > 84 reads as "increasing").
        if [[ -n "$cv_sqlite" ]]; then
            local eff
            while IFS= read -r eff; do
                [[ -z "$eff" ]] && continue
                if (( eff >= cv_sqlite )); then
                    echo "❌ migration-ladder [sqlite]: RULE (b) arm \`if version < $eff\` is at/above CURRENT_SCHEMA_VERSION=$cv_sqlite — it duplicates the const-phrased \`if version < CURRENT_SCHEMA_VERSION\` tip cohort. Renumber below the tip, or bump the const AND the tip migration file in lockstep." >&2
                    violations=$((violations + 1))
                fi
            done < <( { collect_literal_arm_versions "$mig_rs" version; \
                        collect_resolved_arithmetic_arms "$mig_rs" version "$cv_sqlite"; } )

            # (b2) const-phrased tip-cohort COUNT pin: catches the D1a escape
            #      (a silently-added 2nd `if version < CURRENT_SCHEMA_VERSION`
            #      arm the literal scan never sees).
            local nconst
            nconst="$(count_bare_const_arms "$mig_rs" version)"
            if (( nconst != EXPECTED_CONST_ARMS_SQLITE )); then
                echo "❌ migration-ladder [sqlite]: RULE (b) const-phrased arm count is $nconst but the pin is $EXPECTED_CONST_ARMS_SQLITE — a bare \`if version < CURRENT_SCHEMA_VERSION\` arm was added or removed (invisible to the literal-arm scan). Renumber the previous tip arm to a literal, or bump EXPECTED_CONST_ARMS_SQLITE in lockstep with a dated comment." >&2
                violations=$((violations + 1))
            fi
        fi
    else
        echo "❌ migration-ladder: sqlite ladder source not found: $mig_rs" >&2
        violations=$((violations + 1))
    fi

    # ---- Rule (b): postgres duplicate migrate_vN / arm ----------------------
    if [[ -f "$pg_rs" ]]; then
        local dupfn
        # Match fn DEFINITIONS (`fn migrate_vN(`), not doc-comment mentions.
        dupfn="$(grep -oE 'fn migrate_v[0-9]+\(' "$pg_rs" 2>/dev/null | sort | uniq -d || true)"
        if [[ -n "$dupfn" ]]; then
            echo "❌ migration-ladder [postgres]: RULE (b) DUPLICATE migrate fn(s):" >&2
            printf '%s\n' "$dupfn" | sed -E 's/^/     /' >&2
            violations=$((violations + 1))
        fi
        local duparm
        # Anchor to arm-opening code lines so a comment mention is not a false dup.
        duparm="$(grep -E '^[[:space:]]*if current_version < [0-9]+ \{' "$pg_rs" 2>/dev/null | grep -oE 'current_version < [0-9]+' | sort | uniq -d || true)"
        if [[ -n "$duparm" ]]; then
            echo "❌ migration-ladder [postgres]: RULE (b) DUPLICATE arm(s):" >&2
            printf '%s\n' "$duparm" | sed -E 's/^/     /' >&2
            violations=$((violations + 1))
        fi

        # (b3) DUPLICATE migrate fn VERSION under a name-variant (#2198): the
        #      exact-name dup regex above (`fn migrate_vN(`) misses a variant
        #      like `fn migrate_v85_extra(` (precedent in-tree: migrate_v29_stamp).
        #      Scan the NUMERIC after `fn migrate_v` across ALL variants and flag
        #      a repeated version. Catches the D2 escape.
        local dupfnnum
        dupfnnum="$(grep -oE 'fn migrate_v[0-9]+' "$pg_rs" 2>/dev/null | grep -oE '[0-9]+' | sort -n | uniq -d || true)"
        if [[ -n "$dupfnnum" ]]; then
            echo "❌ migration-ladder [postgres]: RULE (b) DUPLICATE migrate fn VERSION(s) (a name-variant like migrate_vNN_suffix escapes the exact-name dup check):" >&2
            printf '%s\n' "$dupfnnum" | sed -E 's/^/     v/' >&2
            violations=$((violations + 1))
        fi

        # (b1)+(b2) NORMALIZATION ceiling + const-phrased cohort COUNT pin,
        #      mirroring the sqlite arm lane.
        if [[ -n "$cv_pg" ]]; then
            local peff
            while IFS= read -r peff; do
                [[ -z "$peff" ]] && continue
                if (( peff >= cv_pg )); then
                    echo "❌ migration-ladder [postgres]: RULE (b) arm \`if current_version < $peff\` is at/above CURRENT_SCHEMA_VERSION=$cv_pg — it duplicates the const-phrased tip cohort. Renumber below the tip, or bump the const AND the tip migration in lockstep." >&2
                    violations=$((violations + 1))
                fi
            done < <( { collect_literal_arm_versions "$pg_rs" current_version; \
                        collect_resolved_arithmetic_arms "$pg_rs" current_version "$cv_pg"; } )

            local npgconst
            npgconst="$(count_bare_const_arms "$pg_rs" current_version)"
            if (( npgconst != EXPECTED_CONST_ARMS_POSTGRES )); then
                echo "❌ migration-ladder [postgres]: RULE (b) const-phrased arm count is $npgconst but the pin is $EXPECTED_CONST_ARMS_POSTGRES — a bare \`if current_version < CURRENT_SCHEMA_VERSION\` arm was added or removed (invisible to the literal-arm scan). Renumber the previous tip arm to a literal, or bump EXPECTED_CONST_ARMS_POSTGRES in lockstep with a dated comment." >&2
                violations=$((violations + 1))
            fi
        fi
    else
        echo "❌ migration-ladder: postgres ladder source not found: $pg_rs" >&2
        violations=$((violations + 1))
    fi

    # ---- Rule (d): cross-adapter tip agreement ------------------------------
    # (cv_sqlite / cv_pg were read once at the top of run_gate for the arm-lane
    # normalization; rule (d) re-uses them.)
    if [[ -z "$cv_sqlite" ]]; then
        echo "❌ migration-ladder: could not read CURRENT_SCHEMA_VERSION from $mig_rs" >&2
        violations=$((violations + 1))
    fi
    if [[ -z "$cv_pg" ]]; then
        echo "❌ migration-ladder: could not read CURRENT_SCHEMA_VERSION from $pg_rs" >&2
        violations=$((violations + 1))
    fi
    if [[ -n "$cv_sqlite" && -n "$cv_pg" && "$cv_sqlite" != "$cv_pg" ]]; then
        echo "❌ migration-ladder: RULE (d) cross-adapter CURRENT_SCHEMA_VERSION mismatch — sqlite=$cv_sqlite postgres=$cv_pg." >&2
        violations=$((violations + 1))
    fi

    # Highest-prefix file per backend must carry the CURRENT_SCHEMA_VERSION vtag.
    if [[ -n "$cv_sqlite" ]]; then
        for backend in "${BACKENDS[@]}"; do
            dir="$mig_dir/$backend"
            [[ -d "$dir" ]] || continue
            local tip tip_base tip_v
            tip="$(find "$dir" -maxdepth 1 -type f -name '*.sql' | sort | tail -1)"
            [[ -z "$tip" ]] && continue
            tip_base="$(basename "$tip")"
            tip_v="$(extract_vtag "$tip_base")"
            if [[ -z "$tip_v" ]]; then
                echo "❌ migration-ladder [$backend]: RULE (d) tip file carries no vNN tag: $tip_base" >&2
                violations=$((violations + 1))
            elif [[ "$tip_v" != "$cv_sqlite" ]]; then
                echo "❌ migration-ladder [$backend]: RULE (d) tip file $tip_base is v$tip_v but CURRENT_SCHEMA_VERSION=$cv_sqlite — bump the const AND the file in lockstep." >&2
                violations=$((violations + 1))
            fi
        done
    fi

    # Postgres ladder tip (`migrate_vN`) must equal CURRENT_SCHEMA_VERSION.
    if [[ -n "$cv_pg" && -f "$pg_rs" ]]; then
        local pg_tip
        pg_tip="$(grep -oE 'fn migrate_v[0-9]+\(' "$pg_rs" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1 || true)"
        if [[ -n "$pg_tip" && "$pg_tip" != "$cv_pg" ]]; then
            echo "❌ migration-ladder [postgres]: RULE (d) ladder tip migrate_v$pg_tip != CURRENT_SCHEMA_VERSION=$cv_pg." >&2
            violations=$((violations + 1))
        fi
    fi

    # ---- Rule (e): orphan / missing -----------------------------------------
    # All migration path strings referenced ANYWHERE under src/ (include_str!
    # or an inline-arm "canonical DDL" comment). One grep pass.
    local referenced=""
    if [[ -d "$src_dir" ]]; then
        referenced="$(grep -rhoE 'migrations/(sqlite|postgres)/[0-9]{4}_[A-Za-z0-9_]+\.sql' "$src_dir" 2>/dev/null | sort -u || true)"
    fi
    for backend in "${BACKENDS[@]}"; do
        dir="$mig_dir/$backend"
        [[ -d "$dir" ]] || continue
        local f base rel
        while IFS= read -r f; do
            base="$(basename "$f")"
            rel="$backend/$base"
            is_exempt_file "$rel" && continue
            if ! printf '%s\n' "$referenced" | grep -qx "migrations/$rel"; then
                echo "❌ migration-ladder [$backend]: RULE (e) ORPHAN file (referenced nowhere under src/): $base" >&2
                echo "     Wire it into the ladder (include_str! or an inline arm), or add it to LADDER_EXEMPT_FILES with a reason." >&2
                violations=$((violations + 1))
            fi
        done < <(find "$dir" -maxdepth 1 -type f -name '*.sql' | sort)
    done
    # include_str! arms referencing a missing file (compiler-enforced; belt).
    local ref_path
    while IFS= read -r ref_path; do
        [[ -z "$ref_path" ]] && continue
        if [[ ! -f "$mig_dir/${ref_path#migrations/}" ]]; then
            echo "❌ migration-ladder: RULE (e) include_str! references a missing file: $ref_path" >&2
            violations=$((violations + 1))
        fi
    done < <(grep -rhoE 'include_str!\("[^"]*migrations/(sqlite|postgres)/[0-9]{4}_[A-Za-z0-9_]+\.sql"\)' "$mig_rs" "$pg_rs" 2>/dev/null \
                | grep -oE 'migrations/(sqlite|postgres)/[0-9]{4}_[A-Za-z0-9_]+\.sql' | sort -u || true)

    # ---- Rule (f): BOOTSTRAP↔LADDER forward reference (#2424) ---------------
    # The bootstrap replays over LEGACY databases BEFORE the ladder runs, so an
    # inline index on a ladder-ALTER-added column crashes every legacy open.
    # Enforced on BOTH adapters: the invariant is `bootstrap(fresh)` ≡
    # `ladder(v0→tip)`, and a bootstrap-only index on a ladder column is exactly
    # the shape that breaks it.
    local fb_backend fb_ladder_rs
    for fb_backend in "${BACKENDS[@]}"; do
        if [[ "$fb_backend" == "postgres" ]]; then fb_ladder_rs="$pg_rs"; else fb_ladder_rs="$mig_rs"; fi

        local fb_bootstrap fb_cols
        fb_bootstrap="$(extract_bootstrap "$fb_backend" "$pg_schema_sql" "$mig_rs")"
        [[ -z "$fb_bootstrap" ]] && continue
        fb_cols="$(collect_ladder_added_columns "$fb_backend" "$mig_dir" "$fb_ladder_rs")"
        [[ -z "$fb_cols" ]] && continue

        local fb_stmt fb_idx fb_tbl fb_rest fb_pair fb_ptbl fb_pcol
        while IFS= read -r fb_stmt; do
            [[ -z "$fb_stmt" ]] && continue
            fb_idx="${fb_stmt%%|*}"
            fb_rest="${fb_stmt#*|}"
            fb_tbl="${fb_rest%%|*}"
            fb_rest="${fb_rest#*|}"
            while IFS= read -r fb_pair; do
                [[ -z "$fb_pair" ]] && continue
                fb_ptbl="${fb_pair%%.*}"
                fb_pcol="${fb_pair#*.}"
                [[ "$fb_ptbl" == "$fb_tbl" ]] || continue
                if printf '%s' "$fb_rest" | grep -qE "(^|[^A-Za-z0-9_])${fb_pcol}([^A-Za-z0-9_]|$)"; then
                    echo "❌ migration-ladder [$fb_backend]: RULE (f) BOOTSTRAP↔LADDER FORWARD REFERENCE — bootstrap index \`$fb_idx\` ON $fb_tbl references \`$fb_pcol\`, a column the LADDER adds via ALTER TABLE (#2424 / #1861 class)." >&2
                    echo "     The bootstrap schema replays over LEGACY databases BEFORE the ladder runs; the pre-existing \`$fb_tbl\` makes CREATE TABLE IF NOT EXISTS a no-op, \`$fb_pcol\` is absent, and this CREATE INDEX crashes the open. (CREATE INDEX IF NOT EXISTS does not help — it keys on the INDEX NAME, which a legacy DB below the owning arm does not have.)" >&2
                    echo "     FIX: delete it from the bootstrap and create it ONLY in the migrate arm / migration .sql that adds \`$fb_pcol\`. Fresh installs still get it — they enter the ladder at version 0 and execute every arm, so bootstrap(fresh) stays equivalent to ladder(v0→tip)." >&2
                    violations=$((violations + 1))
                fi
            done <<< "$fb_cols"
        done < <(printf '%s\n' "$fb_bootstrap" | collect_bootstrap_indexes)
    done

    # ---- Rule (g): per-migration METADATA coverage (#3158) ------------------
    local meta_rs="${LADDER_MIGRATION_META_RS:-$ROOT/src/storage/migration_meta.rs}"
    if [[ ! -f "$meta_rs" ]]; then
        echo "❌ migration-ladder: RULE (g) migration-metadata matrix not found: $meta_rs" >&2
        violations=$((violations + 1))
    elif [[ -f "$mig_rs" && -n "$cv_sqlite" ]]; then
        # (g2) NO symbolic key. A row keyed to `current_schema_version()`
        #      re-labels itself on every bump and makes the matrix's own
        #      lockstep test a tautology.
        local meta_table
        meta_table="$(awk '/^pub const MIGRATION_LADDER:/ { intable = 1 } intable { print } intable && /^\];/ { exit }' "$meta_rs")"
        if printf '%s' "$meta_table" | grep -q 'current_schema_version()'; then
            echo "❌ migration-ladder: RULE (g) MIGRATION_LADDER carries a row keyed to \`current_schema_version()\` — a SYMBOLIC tail key silently re-labels the new tip with the OLD arm's semantics and makes the lockstep assertion true by construction (#3158). Key every row to a LITERAL version." >&2
            violations=$((violations + 1))
        fi

        # (g1) exactly one meta row per sqlite arm (literal + const-phrased).
        local -a g_arms=() g_metas=()
        local gv
        while IFS= read -r gv; do
            [[ -z "$gv" ]] && continue
            g_arms+=("$gv")
        done < <( { collect_arm_versions "$mig_rs"; collect_const_arm_versions "$mig_rs"; } )
        while IFS= read -r gv; do
            [[ -z "$gv" ]] && continue
            g_metas+=("$gv")
        done < <(collect_meta_versions "$meta_rs")

        if (( ${#g_metas[@]} == 0 )); then
            echo "❌ migration-ladder: RULE (g) parsed ZERO MIGRATION_LADDER rows out of $meta_rs — the matrix parser lost its anchor (\`meta(<N>, \"NAME\", …)\`); fix the parser before trusting this gate." >&2
            violations=$((violations + 1))
        else
            local ga
            for ga in "${g_arms[@]}"; do
                if [[ "$ga" == "?" ]]; then
                    echo "❌ migration-ladder [sqlite]: RULE (g) a const-phrased arm (\`if version < CURRENT_SCHEMA_VERSION\`) does not open with the mandatory \`// vNN …\` comment, so its schema version cannot be resolved and its meta row cannot be checked. Add the comment, or LITERALIZE the guard now that the arm has settled." >&2
                    violations=$((violations + 1))
                    continue
                fi
                if ! array_contains "$ga" "${g_metas[@]}"; then
                    echo "❌ migration-ladder: RULE (g) sqlite ladder arm v$ga has NO row in MIGRATION_LADDER (src/storage/migration_meta.rs). Its reversibility / data-loss / idempotency contract is operator-facing truth and is the input to every rollback plan — add the row, DERIVED from the arm's SQL, never guessed." >&2
                    violations=$((violations + 1))
                fi
            done
            # Duplicate rows.
            local gdup
            gdup="$(printf '%s\n' "${g_metas[@]}" | sort -n | uniq -d || true)"
            if [[ -n "$gdup" ]]; then
                echo "❌ migration-ladder: RULE (g) DUPLICATE MIGRATION_LADDER row(s) for version(s):" >&2
                printf '%s\n' "$gdup" | sed -E 's/^/     v/' >&2
                violations=$((violations + 1))
            fi
            # (g3) gap-free v2..CURRENT_SCHEMA_VERSION.
            local gi
            for (( gi = 2; gi <= cv_sqlite; gi++ )); do
                if ! array_contains "$gi" "${g_metas[@]}"; then
                    echo "❌ migration-ladder: RULE (g) MIGRATION_LADDER has NO row for v$gi — every number from 2 to CURRENT_SCHEMA_VERSION=$cv_sqlite is a real ladder step on at least one adapter (a postgres-only step still needs a row flagged \`LadderArm::PostgresOnly\`)." >&2
                    violations=$((violations + 1))
                fi
            done
        fi
    fi

    return "$violations"
}

# --- Self-test --------------------------------------------------------------

run_self_test() {
    echo "migration-ladder gate: self-test (clean control -> PASS; #2036/#2192 same-prefix collision -> FAIL; same-version-two-arms -> FAIL; #2198 arm-lane const-phrase escapes D1a/D1b/D2 -> FAIL; #2424 bootstrap-inline index on a ladder-added column, postgres v84 + sqlite cid -> FAIL; #3158 metadata-matrix missing row + symbolic tail key -> FAIL)"
    local scratch
    # Project hard rule: scratch UNDER the repo, never system /tmp.
    scratch="$(mktemp -d "$ROOT/.migration-ladder-selftest.XXXXXX")"
    trap 'rm -rf "$scratch"' RETURN

    local fail=0
    # CURRENT_SCHEMA_VERSION of the real tree — the #2198 escapes are phrased
    # against it, so resolve it dynamically (never hard-code the tip version).
    local csv
    csv="$(read_current_schema_version "$ROOT/src/storage/migrations.rs")"

    # (0) Clean control — the real tree must PASS.
    if run_gate >/dev/null 2>&1; then
        echo "  [0] clean control (real tree): PASS"
    else
        echo "  [0] clean control (real tree): UNEXPECTED FAIL — the shipped ladder is dirty" >&2
        run_gate >&2 || true
        fail=1
    fi

    # (a) Same-prefix-different-name collision (the EXACT #2036/#2192 shape):
    #     plant a second file at sqlite prefix 0041 with a DIFFERENT name.
    local dupdir="$scratch/mig-dup"
    cp -R "$ROOT/migrations" "$dupdir"
    # Real sqlite 0041 is 0041_v07_federation_push_dlq.sql; add a colliding sibling.
    printf -- '-- self-test collider (same 0041 prefix, different name)\n' \
        > "$dupdir/sqlite/0041_v99_selftest_collision.sql"
    local out_a
    if out_a="$(LADDER_MIGRATIONS_DIR="$dupdir" run_gate 2>&1)"; then
        echo "  [a] same-prefix collision: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_a" | grep -q 'RULE (a) DUPLICATE PREFIX 0041'; then
        echo "  [a] same-prefix collision (#2036/#2192 shape): CAUGHT"
    else
        echo "  [a] same-prefix collision: gate failed but without the rule-(a) message — FAIL" >&2
        printf '%s\n' "$out_a" >&2
        fail=1
    fi

    # (b) Same-version-two-arms: copy migrations.rs, inject a DUPLICATE
    #     `if version < 84 {` arm so two arms declare version 84.
    local duprs="$scratch/migrations_dup.rs"
    cp "$ROOT/src/storage/migrations.rs" "$duprs"
    printf '\n// self-test injected duplicate arm\n        if version < 84 {\n            // duplicate v84 arm\n        }\n' >> "$duprs"
    local out_b
    if out_b="$(LADDER_MIGRATIONS_RS="$duprs" run_gate 2>&1)"; then
        echo "  [b] same-version-two-arms: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_b" | grep -q 'RULE (b)/(c) arm .if version < 84'; then
        echo "  [b] same-version-two-arms: CAUGHT"
    else
        echo "  [b] same-version-two-arms: gate failed but without the rule-(b) message — FAIL" >&2
        printf '%s\n' "$out_b" >&2
        fail=1
    fi

    # ---- #2198 arm-lane const-phrase escapes (Fable audit of #2197) ----------
    #
    # These three shapes ALL exited 0 on the pre-#2198 gate because rule (b)
    # only saw LITERAL-number arms and the CURRENT house convention phrases the
    # tail arms against `CURRENT_SCHEMA_VERSION`.

    # (c) D1a — append a SECOND bare `if version < CURRENT_SCHEMA_VERSION {` arm
    #     to migrations.rs. Invisible to the literal scan; caught by the
    #     const-cohort COUNT pin (b2).
    local duprs_c="$scratch/migrations_d1a.rs"
    cp "$ROOT/src/storage/migrations.rs" "$duprs_c"
    printf '\n// self-test injected 2nd const-phrased arm (D1a)\n        if version < CURRENT_SCHEMA_VERSION {\n            // duplicate const-phrased tip arm\n        }\n' >> "$duprs_c"
    local out_c
    if out_c="$(LADDER_MIGRATIONS_RS="$duprs_c" run_gate 2>&1)"; then
        echo "  [c] D1a extra const-phrased arm: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    # The expected counts are DERIVED from the live pin, never hard-coded:
    # injecting one extra arm must report (pin + 1) against the pin. The
    # literal form ("9 but the pin is 8") went stale the first time the pin
    # moved (#2578: 8 -> 7), which made the self-test report FAIL while the
    # gate underneath was working perfectly — a self-test that cries wolf on
    # a correct gate is worse than none.
    elif printf '%s' "$out_c" \
        | grep -q "const-phrased arm count is $((EXPECTED_CONST_ARMS_SQLITE + 1)) but the pin is $EXPECTED_CONST_ARMS_SQLITE"; then
        echo "  [c] D1a extra const-phrased arm (invisible to literal scan): CAUGHT"
    else
        echo "  [c] D1a extra const-phrased arm: gate failed but without the count-pin message — FAIL" >&2
        printf '%s\n' "$out_c" >&2
        fail=1
    fi

    # (d) D1b — append a LITERAL `if version < <csv> {` arm that duplicates the
    #     const-phrased tip. Monotonic scan reads it as "increasing" (csv > 84);
    #     caught by the normalization tip-cohort ceiling (b1).
    local duprs_d="$scratch/migrations_d1b.rs"
    cp "$ROOT/src/storage/migrations.rs" "$duprs_d"
    printf '\n// self-test injected literal-at-ceiling arm (D1b)\n        if version < %s {\n            // literal duplicate of the const-phrased tip\n        }\n' "$csv" >> "$duprs_d"
    local out_d
    if out_d="$(LADDER_MIGRATIONS_RS="$duprs_d" run_gate 2>&1)"; then
        echo "  [d] D1b literal-at-ceiling arm: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_d" | grep -q "RULE (b) arm .if version < ${csv}. is at/above CURRENT_SCHEMA_VERSION"; then
        echo "  [d] D1b literal duplicate of const-phrased tip: CAUGHT"
    else
        echo "  [d] D1b literal-at-ceiling arm: gate failed but without the ceiling message — FAIL" >&2
        printf '%s\n' "$out_d" >&2
        fail=1
    fi

    # (e) D2 — postgres `fn migrate_v<csv>_extra(` name-variant (precedent:
    #     migrate_v29_stamp) escapes the exact-name `fn migrate_vN(` dup regex.
    #     Caught by the numeric-version dup scan (b3).
    local dupg_e="$scratch/postgres_d2.rs"
    cp "$ROOT/src/store/postgres.rs" "$dupg_e"
    printf '\nfn migrate_v%s_extra(conn: &SelfTestConn) -> SelfTestResult {\n    // name-variant duplicate of migrate_v%s (D2)\n    Ok(())\n}\n' "$csv" "$csv" >> "$dupg_e"
    local out_e
    if out_e="$(LADDER_POSTGRES_RS="$dupg_e" run_gate 2>&1)"; then
        echo "  [e] D2 postgres fn name-variant: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_e" | grep -q 'DUPLICATE migrate fn VERSION'; then
        echo "  [e] D2 postgres migrate_vNN_suffix name-variant: CAUGHT"
    else
        echo "  [e] D2 postgres fn name-variant: gate failed but without the fn-version-dup message — FAIL" >&2
        printf '%s\n' "$out_e" >&2
        fail=1
    fi

    # ---- #2424 bootstrap↔ladder forward reference (rule f) ------------------
    #
    # The GA-blocker class. Both cases plant the EXACT shape that shipped:
    # an inline `CREATE INDEX` in the bootstrap over a column the ladder
    # ALTER-adds. Pre-rule-(f) the gate exited 0 on both.

    # (f1) POSTGRES — re-plant the v84 `idx_memories_embedding_space` shape
    #      (`embedding_space` is ALTER-added by migrations/postgres/0041_v84_*).
    #      This is verbatim what bricked the v74–v83 deployments.
    local pgsql_f1="$scratch/postgres_schema_v84_shape.sql"
    cp "$ROOT/src/store/postgres_schema.sql" "$pgsql_f1"
    printf '\nCREATE INDEX IF NOT EXISTS idx_memories_embedding_space\n    ON memories (embedding_space) WHERE embedding_space IS NOT NULL;\n' >> "$pgsql_f1"
    local out_f1
    if out_f1="$(LADDER_PG_SCHEMA_SQL="$pgsql_f1" run_gate 2>&1)"; then
        echo "  [f1] #2424 postgres v84 bootstrap-inline index: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_f1" | grep -q 'RULE (f) BOOTSTRAP.*idx_memories_embedding_space.*embedding_space'; then
        echo "  [f1] #2424 postgres v84 bootstrap-inline index (the confirmed brick): CAUGHT"
    else
        echo "  [f1] #2424 postgres v84 shape: gate failed but without the rule-(f) message — FAIL" >&2
        printf '%s\n' "$out_f1" >&2
        fail=1
    fi

    # (f2) SQLITE — the same class on the other adapter (#1861's original
    #      shape): re-plant `idx_memories_cid` inside the bootstrap `SCHEMA`
    #      const. Proves rule (f) is not postgres-only.
    local mig_rs_f2="$scratch/migrations_cid_shape.rs"
    awk '{ print }
         /^CREATE INDEX IF NOT EXISTS idx_memories_tier ON memories\(tier\);$/ {
             print "CREATE INDEX IF NOT EXISTS idx_memories_cid ON memories(cid);"
         }' "$ROOT/src/storage/migrations.rs" > "$mig_rs_f2"
    local out_f2
    if out_f2="$(LADDER_MIGRATIONS_RS="$mig_rs_f2" run_gate 2>&1)"; then
        echo "  [f2] #1861/#2424 sqlite bootstrap-inline index: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_f2" | grep -q 'migration-ladder \[sqlite\]: RULE (f) BOOTSTRAP.*idx_memories_cid'; then
        echo "  [f2] #1861/#2424 sqlite bootstrap-inline index (cross-adapter): CAUGHT"
    else
        echo "  [f2] #1861/#2424 sqlite shape: gate failed but without the rule-(f) message — FAIL" >&2
        printf '%s\n' "$out_f2" >&2
        fail=1
    fi

    # ---- #3158 per-migration metadata coverage (rule g) ---------------------
    #
    # Both cases re-plant the EXACT shapes that shipped: a ladder arm with no
    # metadata row, and a tail row keyed to the moving const.

    # (g1) MISSING META ROW — delete the v43 row (the issue's headline row:
    #      the arm that irreversibly rewrites `memory_links.attest_level`).
    local meta_g1="$scratch/migration_meta_missing_row.rs"
    grep -v '^[[:space:]]*meta(43,' "$ROOT/src/storage/migration_meta.rs" > "$meta_g1"
    local out_g1
    if out_g1="$(LADDER_MIGRATION_META_RS="$meta_g1" run_gate 2>&1)"; then
        echo "  [g1] #3158 missing meta row: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_g1" | grep -q 'RULE (g) sqlite ladder arm v43 has NO row in MIGRATION_LADDER'; then
        echo "  [g1] #3158 ladder arm with no metadata row: CAUGHT"
    else
        echo "  [g1] #3158 missing meta row: gate failed but without the rule-(g) coverage message — FAIL" >&2
        printf '%s\n' "$out_g1" >&2
        fail=1
    fi

    # (g2) SYMBOLIC TAIL KEY — re-key the tail row to the moving const, the
    #      exact pre-#3158 shape that made `meta_for(54)` None, `meta_for(89)`
    #      return v54's semantics, and the lockstep test unfailable.
    local meta_g2="$scratch/migration_meta_symbolic_tail.rs"
    sed -E "s/^([[:space:]]*)meta\\(${csv},/\\1meta(crate::storage::migrations::current_schema_version(),/" \
        "$ROOT/src/storage/migration_meta.rs" > "$meta_g2"
    local out_g2
    if out_g2="$(LADDER_MIGRATION_META_RS="$meta_g2" run_gate 2>&1)"; then
        echo "  [g2] #3158 symbolic tail key: NOT CAUGHT (gate passed) — FAIL" >&2
        fail=1
    elif printf '%s' "$out_g2" | grep -q 'RULE (g) MIGRATION_LADDER carries a row keyed to'; then
        echo "  [g2] #3158 tail row keyed to current_schema_version(): CAUGHT"
    else
        echo "  [g2] #3158 symbolic tail key: gate failed but without the rule-(g) symbolic-key message — FAIL" >&2
        printf '%s\n' "$out_g2" >&2
        fail=1
    fi

    if (( fail == 0 )); then
        echo "migration-ladder gate self-test: PASS (load-bearing — catches the prefix collision, the dup-arm shapes, the #2198 const-phrase arm-lane escapes D1a/D1b/D2, the #2424 bootstrap↔ladder forward reference on BOTH adapters, AND the #3158 metadata-matrix escapes (missing row / symbolic tail key); spares a clean tree)"
        return 0
    fi
    echo "migration-ladder gate self-test: FAIL" >&2
    return 1
}

# --- Entry ------------------------------------------------------------------

main() {
    if [[ "${1:-}" == "--self-test" ]]; then
        run_self_test
        exit $?
    fi
    if run_gate; then
        echo "✅ migration-ladder-uniqueness gate: PASS (prefixes unique + gap-free, arms strictly monotonic incl. normalized const-phrased tip cohort, cross-adapter tip agrees, no orphans, no bootstrap↔ladder forward references on either adapter, every ladder arm carries a literally-keyed migration_meta row)"
        exit 0
    else
        echo "" >&2
        echo "migration-ladder-uniqueness gate: FAIL — see the rule violations above (guardrail-D, 2x5 vote b682c76a)." >&2
        exit 1
    fi
}

main "$@"
