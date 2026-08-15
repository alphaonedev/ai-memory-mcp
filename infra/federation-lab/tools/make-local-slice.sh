#!/usr/bin/env bash
# =============================================================================
# tools/make-local-slice.sh — build your own LOCAL corpus slice (never committed).
# =============================================================================
# Turns a real SQLite corpus you already have into an import-shaped JSON file
# the lab can seed from, so `run.sh --corpus-db <path>` exercises the lab
# against YOUR data instead of the committed synthetic fixture.
#
# THE OUTPUT OF THIS SCRIPT MUST NOT BE COMMITTED. It is a verbatim slice of
# whatever corpus you point it at, and this repository is PUBLIC: committing
# one would redistribute that corpus's text (size and stripped vectors are
# irrelevant to the rights question), attribution-free, under this project's
# name — and would carry along whatever identifiers the source rows happen to
# hold, such as an internal `metadata.agent_id` or a `version_vector` keyed by
# the machine that generated them. The committed fixture is SYNTHETIC and is
# built by the sibling `tools/make-synthetic-corpus.sh`; that is the house
# standard for committed data in this repo (see PR #2926, which re-minted the
# golden/conformance vectors from synthetic identities).
#
# Accordingly the default output path is `sample/local/`, which the lab's
# .gitignore excludes, and `run.sh --corpus-db` writes its slice under `run/`,
# which is also ignored and is deleted on exit.
#
# EMBEDDER-AGNOSTIC BY CONSTRUCTION (caveat F-L8a). This script NULLs the
# embedding columns before exporting. Vectors are only meaningful against the
# embedder that produced them; feeding another embedder's vectors into a lab
# whose nodes run at `tier = "keyword"` (no embedder, no network) would be
# feeding in numbers nobody can interpret. The lab's recall lane is therefore
# LEXICAL, and its assertions are about federation + attestation, not about
# semantic ranking quality. To exercise the semantic lane, configure the node's
# embedder to MATCH the one that produced your corpus's vectors.
#
# Determinism: rows are taken `ORDER BY id LIMIT N` (id is a UUID string, so
# this is a stable arbitrary slice, not a "first N inserted" slice), and the
# volatile `exported_at` stamp is normalised out, so re-running this against
# the same corpus reproduces the same file byte-for-byte.
#
# USAGE
#   tools/make-local-slice.sh --corpus-db /path/to/your.db --namespace ns
#   tools/make-local-slice.sh --corpus-db /path/to/your.db --rows 2000 --out /tmp/slice.json
#
# Requires: sqlite3, jq, and an `ai-memory` binary (--bin, or PATH, or the
# repo's target/release build).
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$LAB/../.." && pwd)"

CORPUS_DB="${CORPUS_DB:-}"
ROWS="${ROWS:-2000}"
NAMESPACE="${NAMESPACE:-}"
# Default lands in the gitignored sample/local/ — never in a committable path.
OUT="${OUT:-$LAB/sample/local/slice.json}"
BIN="${BIN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --corpus-db) CORPUS_DB="$2"; shift 2 ;;
    --rows)      ROWS="$2";      shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --out)       OUT="$2";       shift 2 ;;
    --bin)       BIN="$2";       shift 2 ;;
    -h|--help)   sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BIN" ] || BIN="$ROOT/target/release/ai-memory"
[ -x "$BIN" ] || BIN="$(command -v ai-memory || true)"
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "no ai-memory binary (pass --bin)" >&2; exit 1; }
[ -f "$CORPUS_DB" ] || { echo "no corpus database at $CORPUS_DB" >&2; exit 1; }
command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 1; }
command -v jq      >/dev/null || { echo "jq is required" >&2; exit 1; }

# Both values are interpolated into SQL below, and --namespace comes from argv,
# so they are validated rather than trusted. The namespace charset mirrors the
# substrate's own `validate_agent_id`-style shape (alphanumerics plus the
# separators hierarchical namespaces legitimately use) and deliberately admits
# no quote, backslash, semicolon or whitespace.
case "$NAMESPACE" in
  *[!A-Za-z0-9_/:.@-]* | "") echo "refusing unsafe --namespace: $NAMESPACE" >&2; exit 2 ;;
esac
case "$ROWS" in
  *[!0-9]* | "") echo "refusing non-numeric --rows: $ROWS" >&2; exit 2 ;;
esac

WORK="$LAB/run/sample-build"
rm -rf "$WORK"; mkdir -p "$WORK"
SRC="$WORK/slice.db"

echo "== slicing $ROWS rows of namespace '$NAMESPACE' from $CORPUS_DB"
cp "$CORPUS_DB" "$SRC"
# Drop the WAL/SHM siblings a copied live DB may carry so the slice reads the
# committed state only.
rm -f "$SRC-wal" "$SRC-shm"

# The SQL is built with a QUOTED heredoc and two placeholders, then the
# placeholders are substituted — NOT written as an unquoted heredoc with the
# values inlined. An unquoted heredoc runs command substitution over its whole
# body, so a single backtick anywhere in a SQL comment executes a shell
# command: an earlier revision of this script carried the phrase
# "expires_at > now" in backticks inside an unquoted heredoc, which silently
# ran a command and left a stray file named `now` in the lab directory. The
# rationale prose below is worth keeping, so the heredoc is quoted and the
# prose can say whatever it needs to.
cat > "$WORK/slice.sql" <<'SQL'
PRAGMA journal_mode=DELETE;
DELETE FROM memories WHERE namespace <> '@@NS@@';
DELETE FROM memories WHERE id NOT IN (
  SELECT id FROM memories WHERE namespace = '@@NS@@' ORDER BY id LIMIT @@ROWS@@
);
-- Embedder-agnostic: strip vectors (see the F-L8a note in the header).
UPDATE memories SET embedding = NULL, embedding_dim = NULL, embedding_space = NULL;
-- Make the sample a PERMANENT fixture: long tier, no TTL.
--
-- Two distinct expiry defects are closed here, both observed:
--
--   1. EXPORT side. The source corpus was built by a perf run whose mid-tier
--      rows carry an expires_at, and 7,674 of its 7,855 rows are already past
--      it. `db::export_all` drops expired rows, so a slice taken without
--      clearing expires_at exports almost nothing (measured: 7 rows of a
--      300-row slice).
--
--   2. IMPORT side, and this one is the subtle half. Clearing expires_at is
--      NOT enough, because tier carries its own TTL: a mid-tier row is stamped
--      created_at + 7d on write, and these rows' created_at is ~14 days old,
--      so all 300 land ALREADY EXPIRED. They are present in `memories` (a
--      COUNT(*) says 300 -- which is exactly why this was not obvious) but
--      recall filters on `expires_at IS NULL OR expires_at > now`, so recall
--      returns nothing, and the next gc tick archives them out from under the
--      run. A committed fixture must not depend on how long ago it was
--      generated, so the tier -- not the timestamp -- is what gets fixed:
--      long tier is permanent and carries no TTL, whatever created_at says.
--
-- The original tier is preserved in metadata.sample_source_tier so nothing
-- about the source corpus is silently erased.
UPDATE memories
   SET metadata = json_set(COALESCE(NULLIF(metadata, ''), '{}'),
                           '$.sample_source_tier', tier),
       tier = 'long',
       expires_at = NULL;
VACUUM;
SQL

# Substitution is safe because both values passed the charset guards above:
# neither can contain the `|` delimiter, a newline, or a backslash.
sed -i "s|@@NS@@|$NAMESPACE|g; s|@@ROWS@@|$ROWS|g" "$WORK/slice.sql"
sqlite3 "$SRC" < "$WORK/slice.sql"

echo "== exporting"
AI_MEMORY_NO_CONFIG=1 "$BIN" export --db "$SRC" > "$WORK/raw.json" 2>"$WORK/export.err" || {
  echo "export failed:"; cat "$WORK/export.err" >&2; exit 1
}

# Normalise the volatile stamp so the committed artifact is reproducible, and
# re-emit with stable key order + 2-space indent so a diff is reviewable.
jq -S --indent 2 '.exported_at = "1970-01-01T00:00:00+00:00"' "$WORK/raw.json" > "$OUT"

echo "== wrote $OUT"
jq -r '"   memories: \(.count)   links: \(.links|length)   scope: \(.export_scope)"' "$OUT"
echo "   sha256: $(sha256sum "$OUT" | awk '{print $1}')"
rm -rf "$WORK"
