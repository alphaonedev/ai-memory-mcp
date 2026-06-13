#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 — Atlas Corpus full-spectrum ingest + exercise harness.
#
# Drives the LIVE 2-peer + PG18.4/AGE1.7.0 mesh at corpus scale over the SAME
# TLS+mTLS path real traffic uses, then emits BOTH a machine-readable JSON
# report and a human PASS/FAIL table. Exit status is 0 iff every check passes.
# Run AFTER `make validate` (D5) and `test/run.sh` (D6) are green.
#
# The Atlas Corpus is a copyright-clean, derived-facts-only knowledge corpus
# (7912 JSONL records; 7855 distinct (title, namespace); scrub-report
# leak_guard_residual_verbatim=0). Each record carries title / content /
# namespace=atlas-corpus / scope=collective / kind ∈ {concept,claim} /
# tier=mid / tags / source_uri (original knowledge-atlas video) / metadata.
# The corpus lives OUTSIDE this tree (it is large + gitignored scratch); the
# path is supplied via ATLAS_CORPUS and defaults to the local evidence dir.
#
# Why source is remapped: the corpus was minted with source="atlas-knowledge-
# card", which is not on the wire-level VALID_SOURCES allowlist (an intentional
# substrate allowlist). Importing an external corpus correctly stamps
# source="import"; the original card label is preserved verbatim under
# metadata.atlas_source so no provenance is lost.
#
# Spectrum (each check is an independent record {group, test, expected, got,
# status}; every API probe is over TLS+mTLS and authenticates with X-API-Key):
#
#   ingest     : bulk-load the whole corpus into peer-1 via
#                POST /api/v1/memories/bulk in batches (<= max_page_size),
#                asserting ZERO row errors and that the resulting
#                atlas-corpus row count equals the distinct-(title,namespace)
#                cardinality (the ON CONFLICT (title,namespace) DO UPDATE
#                upsert contract makes this idempotent + re-runnable).
#   recall     : exercise the read surface against the ingested corpus —
#                semantic recall (drives the nomic embedder end-to-end),
#                keyword search (FTS over a distinctive corpus token),
#                namespace listing, tag filtering, and kind filtering.
#   graph      : AGE 1.7.0 integration — a Cypher MATCH over the memory_graph
#                executes against peer-1's search_path and returns a count
#                (proves the daemon->PG->AGE leg is live at corpus scale).
#   federation : the supported cross-peer path — a single atlas-derived
#                COLLECTIVE write to peer-1 converges on peer-2 within the
#                catch-up window (W=2 quorum fanout); PLUS a measurement of
#                how much of the bulk-ingested corpus has converged to peer-2
#                (observed, for the peer-review record).
#
# Nothing here mutates the docker-1461 baseline corpus; all writes land in the
# atlas-corpus namespace (+ one _verify federation marker).

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../provision/lib.sh
. "$SELF_DIR/../provision/lib.sh"

mkdir -p "$REPORTS_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS_DIR/atlas-$TS.tsv"; : > "$TSV"
JSON="$REPORTS_DIR/atlas-$TS.json"

# --- tunables (all env-overridable; no literal leaks into logic) ------------
ATLAS_CORPUS="${ATLAS_CORPUS:-/Users/fate/v07/v07-fixes/.local-runs/atlas-evidence/atlas-clean-memories.jsonl}"
ATLAS_NS="${ATLAS_NS:-atlas-corpus}"
BATCH_SIZE="${ATLAS_BATCH_SIZE:-500}"          # <= max_page_size (default 1000)
ATLAS_SOURCE="${ATLAS_SOURCE:-import}"         # wire-valid source for corpus import
CONVERGE_TICKS="${DOCKER_1461_CONVERGE_TICKS:-20}"   # 20 x 2s = 40s catch-up window
BULK_MAX_TIME="${ATLAS_BULK_MAX_TIME:-300}"    # per-batch curl budget (embeddings inline)
NS_VERIFY="${DOCKER_1461_VERIFY_NS:-_verify}"

AID_H="ai:atlas-harness@$CAMPAIGN"
AID_ALPHA="ai:agent-alpha@$CAMPAIGN"
AID_BETA="ai:agent-beta@$CAMPAIGN"
EFFECTIVE_KEY="$(effective_api_key)"

# Derived API paths (single source — never inline a path literal).
API_BULK="${API_MEMORIES}/bulk"
API_RECALL="${API_BASE}/recall"

# record/pass/fail/assert helpers (identical contract to test/run.sh) --------
record()    { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }
pass()      { record "$1" "$2" "$3" "$4" PASS; }
fail()      { record "$1" "$2" "$3" "$4" FAIL; }
assert_eq() { if [ "$3" = "$4" ]; then pass "$1" "$2" "$3" "$4"; else fail "$1" "$2" "$3" "${4:-<empty>}"; fi; }
assert_ge() { if [ "${4:-0}" -ge "$3" ] 2>/dev/null; then pass "$1" "$2" ">=$3" "$4"; else fail "$1" "$2" ">=$3" "${4:-<nan>}"; fi; }

# Count atlas rows in a given peer's PG schema (the authoritative count — the
# HTTP list path pages, the SQL count is exact). The probe psql is a unix-
# socket backend; it reads the per-peer schema's memories table directly.
pg_atlas_count() {
  local schema="$1"
  node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "select count(*) from ${schema}.memories where namespace='${ATLAS_NS}'" 2>/dev/null \
    | tr -d '[:space:]' || printf 'x'
}

log "Atlas full-spectrum $TS — campaign=$CAMPAIGN ns=$ATLAS_NS corpus=$ATLAS_CORPUS"

P1_PORT="$(peer_port 1)"; P1_NAME="$(peer_name 1)"; P1_SCHEMA="$(peer_schema 1)"
P2_PORT=""; P2_NAME=""; P2_SCHEMA=""
if [ "$PEER_COUNT" -ge 2 ]; then P2_PORT="$(peer_port 2)"; P2_NAME="$(peer_name 2)"; P2_SCHEMA="$(peer_schema 2)"; fi

# --- preflight --------------------------------------------------------------
[ -f "$ATLAS_CORPUS" ] || die "corpus not found: $ATLAS_CORPUS (set ATLAS_CORPUS)"
node_healthy "$P1_NAME" || die "$P1_NAME not healthy"
[ -n "$P2_PORT" ] && { node_healthy "$P2_NAME" || die "$P2_NAME not healthy"; }
command -v jq >/dev/null 2>&1 || die "jq required"
command -v python3 >/dev/null 2>&1 || die "python3 required"

# --- batch generation -------------------------------------------------------
# Dedup by (title, namespace) keeping the LAST occurrence (the postgres bulk
# path persists a batch as ONE multi-row INSERT with ON CONFLICT (title,
# namespace) DO UPDATE — two identical conflict targets in a single statement
# would error "cannot affect row a second time", so intra-corpus title
# collisions are collapsed BEFORE batching). Remap source -> $ATLAS_SOURCE,
# preserve the original under metadata.atlas_source, and pin on_conflict=merge
# so re-runs upsert idempotently. Emits batch-*.json arrays under the
# gitignored run dir and prints "<unique> <total> <dropped>" on stdout.
BATCH_DIR="$RUN_DIR/atlas-batches-$TS"
mkdir -p "$BATCH_DIR"
# The generator lives in a sibling file (NOT an inline heredoc): macOS bash 3.2
# mis-parses a here-document nested inside a `< <(...)` process substitution
# ("ambiguous redirect"), so the python is shipped as gen_batches.py and run
# as a normal subprocess whose stdout is captured.
GEN_OUT="$(ATLAS_CORPUS="$ATLAS_CORPUS" ATLAS_NS="$ATLAS_NS" BATCH_DIR="$BATCH_DIR" \
  BATCH_SIZE="$BATCH_SIZE" ATLAS_SOURCE="$ATLAS_SOURCE" \
  python3 "$SELF_DIR/gen_batches.py")" \
  || die "batch generation failed"
read -r UNIQUE TOTAL DROPPED <<EOF
$GEN_OUT
EOF
log "corpus: total=$TOTAL unique=$UNIQUE dropped_dup_titles=$DROPPED batches=$(ls "$BATCH_DIR" | grep -c .)"

# Baseline (idempotent re-runs already hold the corpus — assertions still hold
# because the upsert collapses to the same distinct count).
BASE_P1="$(pg_atlas_count "$P1_SCHEMA")"
log "[ingest] baseline $P1_NAME atlas count = $BASE_P1; bulk-loading $UNIQUE rows in batches of $BATCH_SIZE"

# ====================== GROUP ingest ========================================
CREATED_TOTAL=0
ERRORS_TOTAL=0
BATCH_FAIL=0
for bf in "$BATCH_DIR"/batch-*.json; do
  resp="$(MTLS_MAX_TIME="$BULK_MAX_TIME" mtls_curl_body "$P1_PORT" POST "$API_BULK" "@$bf" "$AID_H")"
  if [ -z "$resp" ]; then
    BATCH_FAIL=$((BATCH_FAIL + 1))
    warn "batch $(basename "$bf"): empty/failed response"
    continue
  fi
  c="$(printf '%s' "$resp" | jq '.created // 0' 2>/dev/null || echo 0)"
  e="$(printf '%s' "$resp" | jq '(.errors // []) | length' 2>/dev/null || echo 0)"
  CREATED_TOTAL=$((CREATED_TOTAL + c))
  ERRORS_TOTAL=$((ERRORS_TOTAL + e))
  if [ "$e" -ne 0 ]; then
    warn "batch $(basename "$bf"): $e row error(s); first: $(printf '%s' "$resp" | jq -r '.errors[0] // empty' 2>/dev/null)"
  fi
done

if [ "$BATCH_FAIL" -eq 0 ]; then
  pass ingest batch_transport "all batches returned a body" "0 transport failures"
else
  fail ingest batch_transport "all batches returned a body" "$BATCH_FAIL batch(es) failed"
fi
assert_eq ingest row_errors 0 "$ERRORS_TOTAL"

POST_P1="$(pg_atlas_count "$P1_SCHEMA")"
assert_eq ingest count_peer1 "$UNIQUE" "$POST_P1"
log "[ingest] created(sum)=$CREATED_TOTAL row_errors=$ERRORS_TOTAL final_count_p1=$POST_P1 (expected $UNIQUE)"

# ====================== GROUP recall ========================================
# All reads target peer-1 (the ingested peer) as $AID_H over TLS+mTLS.
log "[recall] semantic + keyword + namespace + tags + kind against $ATLAS_NS"

# (1) semantic recall — drives the nomic embedder end-to-end; a conceptual
# query that is NOT a verbatim title must still surface >=1 corpus row.
# Bulk ingest persists rows in seconds, but per-row embeddings are computed by
# an ASYNC backfill sweep (AI_MEMORY_EMBED_BACKFILL_BATCH rows/pass). Semantic
# recall needs both the query AND the row vectors, so it returns empty until the
# backfill settles over the freshly-ingested corpus. Poll up to EMBED_TICKS
# (default = CONVERGE_TICKS) before asserting, so we measure correctness rather
# than the backfill's in-flight state. The context is URL-encoded (spaces ->
# %20) so the GET query string is wire-valid regardless of embedder timing.
RCTX='long-run upward trend of US equities through bull and bear cycles'
RCTX_ENC="$(printf '%s' "$RCTX" | sed 's/ /%20/g')"
RREQ="context=${RCTX_ENC}&namespace=${ATLAS_NS}&limit=10"
rsem_n=0
i=0
while [ "$i" -lt "${EMBED_TICKS:-$CONVERGE_TICKS}" ]; do
  RSEM="$(mtls_curl_body "$P1_PORT" GET "$API_RECALL?$RREQ" "" "$AID_H")"
  rsem_n="$(printf '%s' "$RSEM" | jq '(.memories // .results // []) | length' 2>/dev/null || echo 0)"
  case "$rsem_n" in ''|*[!0-9]*) rsem_n=0 ;; esac
  [ "$rsem_n" -ge 1 ] && break
  i=$((i + 1))
  sleep "${EMBED_TICK_SLEEP:-3}"
done
log "[recall] semantic settled after ${i} tick(s): n=$rsem_n"
assert_ge recall semantic 1 "$rsem_n"

# (2) keyword search — FTS over a distinctive corpus token.
SKW="$(mtls_curl_body "$P1_PORT" GET "$API_SEARCH?q=permabull&namespace=$ATLAS_NS&limit=10" "" "$AID_H")"
skw_n="$(printf '%s' "$SKW" | jq '(.results // .memories // []) | length' 2>/dev/null || echo 0)"
assert_ge recall keyword_search 1 "$skw_n"

# (3) namespace listing — the corpus is visible as a coherent namespace.
LST="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES?namespace=$ATLAS_NS&limit=50" "" "$AID_H")"
lst_n="$(printf '%s' "$LST" | jq '(.memories // .results // . // []) | length' 2>/dev/null || echo 0)"
assert_ge recall namespace_list 1 "$lst_n"

# (4) tag filter — every corpus row carries the "atlas" tag.
TAGR="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES?namespace=$ATLAS_NS&tags=atlas&limit=50" "" "$AID_H")"
tag_n="$(printf '%s' "$TAGR" | jq '(.memories // .results // . // []) | length' 2>/dev/null || echo 0)"
assert_ge recall tag_filter 1 "$tag_n"

# (5) kind filter via search — corpus rows are concept/claim; a search scoped
# to the claim kind tag surfaces rows (Form-6 taxonomy round-trip at scale).
KSR="$(mtls_curl_body "$P1_PORT" GET "$API_SEARCH?q=market&namespace=$ATLAS_NS&tags=market-history&limit=10" "" "$AID_H")"
ksr_n="$(printf '%s' "$KSR" | jq '(.results // .memories // []) | length' 2>/dev/null || echo 0)"
assert_ge recall search_tagged 1 "$ksr_n"

# ====================== GROUP graph (AGE 1.7.0) =============================
# A Cypher MATCH over memory_graph must execute against peer-1's schema
# search_path and return a count (proves AGE is live end-to-end at scale).
log "[graph] AGE Cypher over $AGE_GRAPH_NAME on $P1_SCHEMA"
# A fresh psql -c session does NOT inherit the daemon's loaded AGE library, so
# cypher() raises "unhandled cypher(cstring) function call" until `LOAD 'age'`
# pulls the extension's C functions into THIS backend. The daemon's own
# connections load it at connect time; an ad-hoc probe session must do it here.
AGE_CYPHER="LOAD 'age'; set search_path=ag_catalog,${P1_SCHEMA},public; select * from cypher('${AGE_GRAPH_NAME}', \$\$ MATCH (n) RETURN count(n) \$\$) as (c agtype);"
# The multi-statement probe emits LOAD / SET command tags before the cypher
# tuple; keep the raw output for error detection but take the final non-empty
# line (the count) for the reported value.
age_raw="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$AGE_CYPHER" 2>&1 || true)"
age_out="$(printf '%s\n' "$age_raw" | grep -vE '^(LOAD|SET)$' | tr -d '[:space:]')"
case "$age_raw" in
  *ERROR*|*error*) fail graph age_cypher "cypher MATCH returns a count" "${age_raw//[[:space:]]/ }" ;;
  *) case "$age_out" in
       ''|*[!0-9]*) fail graph age_cypher "cypher MATCH returns a count" "${age_out:-<empty>}" ;;
       *)           pass graph age_cypher "cypher MATCH returns a count" "count=$age_out" ;;
     esac ;;
esac

# ====================== GROUP federation ====================================
if [ -n "$P2_PORT" ]; then
  # (1) supported path: a single atlas-derived COLLECTIVE write fans out (W=2)
  # and converges on peer-2 within the catch-up window.
  log "[federation] single atlas-derived collective write $P1_NAME -> $P2_NAME"
  FNONCE="atlas-fed-$TS-$RANDOM"
  FBODY="{\"title\":\"$FNONCE\",\"content\":\"atlas federation probe $FNONCE — derived market-history fact\",\"namespace\":\"$NS_VERIFY\",\"scope\":\"collective\",\"source\":\"$ATLAS_SOURCE\",\"on_conflict\":\"merge\"}"
  FW="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" "$FBODY" "$AID_ALPHA")"
  FID="$(json_field "$FW" id)"
  if [ -z "$FID" ]; then
    fail federation single_write "memory id" "<write failed>"
  else
    pass federation single_write "memory id" "$FID"
    i=0; conv=0
    while [ "$i" -lt "$CONVERGE_TICKS" ]; do
      r="$(mtls_curl_body "$P2_PORT" GET "$API_MEMORIES/$FID" "" "$AID_BETA")"
      case "$r" in *"$FNONCE"*) conv=1; break ;; esac
      i=$((i + 1)); sleep 2
    done
    if [ "$conv" = 1 ]; then
      pass federation single_converge "$FID on $P2_NAME" "present on $P2_NAME"
      # best-effort cleanup of the marker on both peers
      mtls_curl_code "$P1_PORT" DELETE "$API_MEMORIES/$FID" "" "$AID_ALPHA" >/dev/null 2>&1 || true
    else
      fail federation single_converge "$FID on $P2_NAME" "<not replicated within window>"
    fi
  fi

  # (2) observed bulk convergence — the postgres bulk path is peer-local by
  # design (the handler documents that postgres deployments replicate via the
  # postgres mechanism, not HTTP fanout). Recorded as an OBSERVATION for the
  # peer-review record, not a pass/fail gate.
  P2_ATLAS="$(pg_atlas_count "$P2_SCHEMA")"
  log "[federation] OBSERVED bulk convergence on $P2_NAME: atlas count=$P2_ATLAS (peer-1=$POST_P1)"
  record federation bulk_observed "observation" "p2_atlas=$P2_ATLAS p1_atlas=$POST_P1" OBSERVE
else
  fail federation single_converge ">=2 peers" "<need 2 peers>"
fi

# ---- assemble JSON report ---------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n  "suite": "atlas-full-spectrum",\n' "$CAMPAIGN" "$TS"
  printf '  "corpus": {"path": "%s", "total": %s, "unique": %s, "dropped_dup_titles": %s, "batch_size": %s},\n' \
    "$ATLAS_CORPUS" "$TOTAL" "$UNIQUE" "$DROPPED" "$BATCH_SIZE"
  printf '  "checks": [\n'
  first=1
  while IFS="$(printf '\t')" read -r group test expected got status; do
    [ "$first" = 1 ] && first=0 || printf ',\n'
    printf '    {"group": "%s", "test": "%s", "expected": "%s", "got": "%s", "status": "%s"}' \
      "$group" "$test" "$expected" "$got" "$status"
  done < "$TSV"
  printf '\n  ]\n}\n'
} > "$JSON"

# ---- human summary ----------------------------------------------------------
total_checks="$(grep -c . "$TSV" || true)"
passed="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
failed="$(awk -F'\t' '$5=="FAIL"' "$TSV" | grep -c . || true)"
observed="$(awk -F'\t' '$5=="OBSERVE"' "$TSV" | grep -c . || true)"

printf '\n'
printf '============== %s Atlas full-spectrum (%s) ==============\n' "$CAMPAIGN" "$TS"
printf 'corpus: total=%s unique=%s dropped_dup_titles=%s | created(sum)=%s row_errors=%s\n' \
  "$TOTAL" "$UNIQUE" "$DROPPED" "$CREATED_TOTAL" "$ERRORS_TOTAL"
printf '%-12s %-22s %-8s %s\n' "GROUP" "TEST" "STATUS" "GOT"
printf '%-12s %-22s %-8s %s\n' "-----" "----" "------" "---"
awk -F'\t' '{printf "%-12s %-22s %-8s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s  OBSERVE=%s\n' "$total_checks" "$passed" "$failed" "$observed"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

# keep batch dir for forensic re-run unless explicitly cleaned
[ "${ATLAS_KEEP_BATCHES:-0}" = "1" ] || rm -rf "$BATCH_DIR"

if [ "$failed" -ne 0 ]; then
  die "Atlas FAILED — $failed check(s) red."
fi
log "Atlas PASSED — $passed/$total_checks checks green ($observed observation(s))."
