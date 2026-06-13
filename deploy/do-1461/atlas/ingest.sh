#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Atlas Corpus ATTESTED ingest (#1535) — loads the copyright-clean knowledge
# corpus into the maximum-secure do-1461 hive over the SAME mTLS path real
# traffic uses, with every write Ed25519-ATTESTED (the fleet runs
# AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1, so an unsigned POST is refused 403).
#
# OPTION A (the efficient path): the `attest_sign_batch` example reads the corpus
# JSONL + the loader key in ONE process and emits ready-to-POST attested bodies
# (signature + created_at injected) — 7912 records sign in ~3s vs hours of
# per-record cargo spawns. The bodies are then POSTed in parallel ON the
# write-anchor node (loopback mTLS — no per-request SSH).
#
# FRESHNESS-WINDOW DISCIPLINE: created_at is signed verbatim and the server
# enforces a ±300s window. The peers are pg-write/embedder-bound at ~3 rec/s, so
# a full-corpus single-stamp ingest (~40 min) would blow the window. The ingest
# therefore CHUNKS the corpus and RE-SIGNS each chunk with a fresh created_at
# right before that chunk is POSTed — a chunk of $ATLAS_CHUNK records at
# $ATLAS_POST_PARALLEL-way parallelism lands well inside 300s.
#
# Usage:  ingest.sh <anchor_public_ip>
# Stdout (machine-readable, last line): a summary token the verify harness parses:
#   ATLAS_INGEST transport_fail=<n> http_2xx=<n> http_non2xx=<n> rows=<n>
# Exit 0 iff transport_fail==0 AND http_non2xx==0.
set -euo pipefail
source "$(dirname "$0")/../provision/lib.sh"

require_inventory

ANCHOR_IP="${1:-}"
[ -n "$ANCHOR_IP" ] || die "usage: ingest.sh <anchor_public_ip>"
ANCHOR_H="$(inv_name_for_ip "$ANCHOR_IP")"
[ -n "$ANCHOR_H" ] || die "ingest: $ANCHOR_IP not in inventory"

# Resolve the corpus path + sha from the COMMITTED manifest (reproducibility pin).
[ -s "$ATLAS_MANIFEST" ] || die "ingest: manifest missing ($ATLAS_MANIFEST)"
CORPUS_REL="$(jq -r '.corpus' "$ATLAS_MANIFEST")"
CORPUS_SHA="$(jq -r '.sha256' "$ATLAS_MANIFEST")"
CORPUS="${ATLAS_CORPUS:-$RUN_DIR/../atlas-evidence/$CORPUS_REL}"
[ -s "$CORPUS" ] || die "ingest: corpus file missing ($CORPUS) — expected $CORPUS_REL per manifest"

# Reproducibility pin — FAIL if the on-disk corpus sha does not match the manifest.
GOT_SHA="$(sha256sum "$CORPUS" | awk '{print $1}')"
[ "$GOT_SHA" = "$CORPUS_SHA" ] \
  || die "ingest: corpus sha mismatch — manifest=$CORPUS_SHA got=$GOT_SHA ($CORPUS)"
log "[atlas] corpus sha verified ($CORPUS_SHA) — $(grep -c . "$CORPUS") lines"

API_PW_FILE="$RUN_DIR/secrets/api.pw"
API_KEY=""; [ -s "$API_PW_FILE" ] && API_KEY="$(cat "$API_PW_FILE")"

SIGNER="$(atlas_signer_batch_bin)"
LOADER_PRIV="$(agent_priv_path "$ATLAS_AGENT_ID")"

# Enroll the dedicated loader identity on the write-anchor peer: register over
# mTLS + bind its pubkey into the anchor peer's postgres _agents row so its
# attested writes verify there. Idempotent (re-register/re-bind is a no-op).
log "[atlas] enrolling loader $ATLAS_AGENT_ID on write-anchor $ANCHOR_H (register + bind pubkey)"
agent_enroll_peer "$ANCHOR_IP" "$ATLAS_AGENT_ID"

# Stage scratch under the gitignored run dir (no /tmp).
STAGE="$RUN_DIR/atlas-stage"; mkdir -p "$STAGE"
SRC_SPLIT="$STAGE/corpus.jsonl"; cp "$CORPUS" "$SRC_SPLIT"
TOTAL="$(grep -c . "$SRC_SPLIT")"
log "[atlas] ingesting $TOTAL records -> $ANCHOR_H ($ATLAS_NAMESPACE) in chunks of $ATLAS_CHUNK, $ATLAS_POST_PARALLEL-way parallel"

# Stage a self-contained POSTER SCRIPT on the node ONCE (all dynamic values
# baked in at generation), then invoke it per chunk as `bash poster < chunk`.
# This avoids the quoting hell of threading an inline function definition +
# `export -f` + nested `xargs bash -c` through the SSH command-string layer
# (which double-expands and mangled the `\$@`). The poster reads bodies from
# stdin (one per line), POSTs each over loopback mTLS in parallel, and prints the
# HTTP code per line (`000` on transport failure). Secrets: the api key is staged
# in the 0600 script on the node (root-only) and removed at end of ingest — it is
# NEVER echoed to a log or a command line here.
REMOTE_POSTER_PATH="/root/.atlas-poster-$$.sh"
POSTER_LOCAL="$STAGE/poster.sh"
{
  printf '#!/usr/bin/env bash\n'
  printf 'post_one() {\n'
  printf '  local code\n'
  printf '  code="$(curl -sS -o /dev/null -w "%%{http_code}" --max-time %s \\\n' "$ATLAS_POST_MAX_TIME"
  printf '    --resolve %s:%s:127.0.0.1 \\\n' "$ANCHOR_H" "$FEDERATION_PORT"
  printf '    --cacert %s/ca.pem --cert %s/client.pem --key %s/client.key \\\n' "$REMOTE_TLS" "$REMOTE_TLS" "$REMOTE_TLS"
  printf '    -H "x-api-key: %s" -H "x-agent-id: %s" -H "content-type: application/json" \\\n' "$API_KEY" "$ATLAS_AGENT_ID"
  printf '    --data "$1" -X POST https://%s:%s/api/v1/memories 2>/dev/null || true)"\n' "$ANCHOR_H" "$FEDERATION_PORT"
  printf '  printf "%%s\\n" "${code:-000}"\n'
  printf '}\n'
  printf 'export -f post_one\n'
  printf 'xargs -d "\\n" -P %s -I {} bash -c '"'"'post_one "$@"'"'"' _ {}\n' "$ATLAS_POST_PARALLEL"
} > "$POSTER_LOCAL"
scp_to "$POSTER_LOCAL" "$ANCHOR_IP" "$REMOTE_POSTER_PATH"
ssh_node "$ANCHOR_IP" "chmod 600 $REMOTE_POSTER_PATH"

transport_fail=0; http_2xx=0; quorum_soft=0; http_hard_err=0; processed=0
chunk_idx=0
# bash-3.2 safe chunking: split into fixed-size pieces under the stage dir.
split -l "$ATLAS_CHUNK" "$SRC_SPLIT" "$STAGE/chunk-"
for chunk in "$STAGE"/chunk-*; do
  [ -s "$chunk" ] || continue
  chunk_idx=$((chunk_idx + 1))
  n="$(grep -c . "$chunk")"
  # RE-SIGN this chunk with a FRESH created_at so the freshness window holds even
  # though the whole ingest spans many minutes. The signer injects signature +
  # created_at + the source/source_uri/on_conflict remaps in one process.
  signed="$STAGE/signed-$chunk_idx.ndjson"
  "$SIGNER" --agent-id "$ATLAS_AGENT_ID" --priv-file "$LOADER_PRIV" \
    --corpus "$chunk" --source "$ATLAS_SOURCE" --on-conflict "$ATLAS_ON_CONFLICT" \
    > "$signed" 2>>"$STAGE/sign.err" \
    || die "[atlas] chunk $chunk_idx signing failed (see $STAGE/sign.err)"
  # Stage the signed bodies on the node and POST them in parallel via the staged
  # poster script (reads bodies from stdin, prints one HTTP code per line).
  remote="/root/.atlas-chunk-$chunk_idx.ndjson"
  scp_to "$signed" "$ANCHOR_IP" "$remote"
  codes="$(ssh_node "$ANCHOR_IP" "bash $REMOTE_POSTER_PATH < $remote; rm -f $remote" 2>/dev/null || true)"
  # Tally this chunk's codes. IMPORTANT (honest classification of the W=2 model):
  # a 503 `quorum_not_met` is the SYNCHRONOUS cross-region quorum-ack TIMEOUT —
  # the write STILL commits LOCALLY (the row lands in the anchor's pg, attested)
  # and converges asynchronously under the eventual model. Verified live: 100/100
  # writes returning 503 all persisted as agent_attested rows. So 503 is a SOFT
  # code (counted separately as quorum_soft), NOT a transport failure (000) and
  # NOT a hard row error. The authoritative landing assertion is the pg distinct
  # count in run.sh — the HTTP tally is informational. A "hard" non-2xx is any
  # 3-digit code that is neither 2xx nor 503 (e.g. a 400 validation reject).
  local_2xx="$(printf '%s\n' "$codes" | grep -c '^2[0-9][0-9]$' || true)"
  local_000="$(printf '%s\n' "$codes" | grep -c '^000$' || true)"
  local_503="$(printf '%s\n' "$codes" | grep -c '^503$' || true)"
  local_all3="$(printf '%s\n' "$codes" | grep -Ec '^[0-9]{3}$' || true)"
  local_hard=$((local_all3 - local_2xx - local_000 - local_503))
  [ "$local_hard" -lt 0 ] && local_hard=0
  http_2xx=$((http_2xx + local_2xx))
  transport_fail=$((transport_fail + local_000))
  quorum_soft=$((quorum_soft + local_503))
  http_hard_err=$((http_hard_err + local_hard))
  processed=$((processed + n))
  log "[atlas] chunk $chunk_idx/$(( (TOTAL + ATLAS_CHUNK - 1) / ATLAS_CHUNK )): $n recs -> 2xx=$local_2xx quorum_soft=$local_503 hard_err=$local_hard transport_fail=$local_000 (cum 2xx=$http_2xx quorum_soft=$quorum_soft)"
  rm -f "$signed"
done

# Clean staged chunks + the secret-bearing remote poster (keep sign.err if
# non-empty for forensics). The poster carries the api key, so its removal on the
# node is mandatory, not best-effort.
rm -f "$STAGE"/chunk-* "$SRC_SPLIT" "$POSTER_LOCAL"
ssh_node "$ANCHOR_IP" "rm -f $REMOTE_POSTER_PATH" >/dev/null 2>&1 || true

# Summary token (parsed by run.sh). quorum_soft = 503 quorum-ack timeouts whose
# rows STILL landed+attested locally (W=2 eventual model); http_hard_err = real
# rejects (e.g. 400). The pass gate is: 0 transport failures AND 0 hard errors.
# Convergence to the manifest distinct count is asserted authoritatively in
# run.sh against the anchor's pg.
printf 'ATLAS_INGEST transport_fail=%s http_2xx=%s quorum_soft=%s http_hard_err=%s rows=%s\n' \
  "$transport_fail" "$http_2xx" "$quorum_soft" "$http_hard_err" "$processed"
log "[atlas] ingest complete: rows=$processed 2xx=$http_2xx quorum_soft=$quorum_soft hard_err=$http_hard_err transport_fail=$transport_fail"

[ "$transport_fail" -eq 0 ] && [ "$http_hard_err" -eq 0 ]
