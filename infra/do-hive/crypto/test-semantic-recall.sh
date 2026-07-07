#!/usr/bin/env bash
# =============================================================================
# test-semantic-recall.sh — CAVEAT 2: semantic recall end-to-end via the daemon
# with the in-process MiniLM-L6-v2 (384-dim candle) embedder — NO Ollama/nomic,
# NO external embedding service.
# =============================================================================
# The earlier DO round HUNG because the daemon resolved a 768-dim nomic embedder
# with no Ollama backend present. Root cause: tier=autonomous/smart resolves the
# Ollama nomic-embed model. FIX: pin tier=semantic (compiled default) so the
# in-process candle MiniLM-384 embedder generates vectors offline.
#
# AI_MEMORY_NO_CONFIG=1 skips the operator config.toml entirely, so:
#   - tier falls back to the compiled default `semantic` -> EmbeddingModel::MiniLmL6V2
#   - no `db`/`embeddings` overrides from the host config leak in.
#
# Proof: store three topically-distinct memories, then recall with a PARAPHRASE
# that shares NO salient keywords with the target; assert the semantic hit ranks
# first and the response mode is "hybrid" (embedder produced a real vector
# component — pure keyword recall reports a non-hybrid mode).
#
# $STORE_URL (optional) points at a postgres pgvector store to prove the real
# `<=>` operator path (the DO substrate). Unset = sqlite (fast, same embedder).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/../../.."
BIN="${BIN:-$ROOT/target/release/ai-memory}"
PORT="${PORT:-19080}"
WORK="$(mktemp -d)"; LOG="$WORK/d.log"
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }
cleanup(){ [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

STORE_ARGS=(--db "$WORK/rec.db")
[ -n "${STORE_URL:-}" ] && STORE_ARGS=(--store-url "$STORE_URL")

# attestation OFF here — this test isolates the EMBEDDER, not the attest gate.
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 \
  "$BIN" serve --host 127.0.0.1 --port "$PORT" "${STORE_ARGS[@]}" >"$LOG" 2>&1 &
DPID=$!
for i in $(seq 1 60); do curl -s "http://127.0.0.1:$PORT/api/v1/health" -o /dev/null && break; sleep 0.5; done
BASE="http://127.0.0.1:$PORT/api/v1"

store(){ curl -s -H "x-agent-id: ai:seed" -H "content-type: application/json" \
  -X POST "$BASE/memories" -d "$(jq -nc --arg t "$1" --arg c "$2" \
  '{title:$t,content:$c,namespace:"semtest",tier:"mid"}')" -o /dev/null -w '%{http_code}'; }

c1=$(store "k8s-ops" "Rolling out containerized microservices across a managed cluster with automated pod scheduling, self-healing, and horizontal autoscaling.")
c2=$(store "sourdough" "Maintaining a wild-yeast starter, bulk fermentation times, and oven spring when baking artisan bread at home.")
c3=$(store "tax-law" "Depreciation schedules and capital-gains treatment for long-held real-estate assets under the current tax code.")
echo "INFO: store codes k8s=$c1 sourdough=$c2 tax=$c3"

# first store loads MiniLM weights; give the embedder a beat + let vectors land
sleep 2

# Paraphrase of the k8s memory sharing NO distinctive keyword ("container",
# "cluster", "pod" all avoided) — only a KEYWORD recall would miss this; a
# semantic vector recall ranks the k8s memory first.
Q="orchestration platform that automatically restarts failed workloads and scales replicas"
resp=$(curl -s -H "x-agent-id: ai:seed" "$BASE/recall?query=$(jq -rn --arg q "$Q" '$q|@uri')&limit=3")
mode=$(echo "$resp" | jq -r '.mode // .recall_mode // empty')
top=$(echo "$resp"  | jq -r '(.memories // .results // .hits)[0].title // empty')

if echo "${mode:-}" | grep -qi hybrid; then
  ok "semantic: recall mode='$mode' (embedder produced a real vector component)"
else
  no "semantic: recall mode='${mode:-<none>}' is not hybrid — embedder did NOT vectorise (resp: $(echo "$resp" | head -c 300))"
fi
if [ "$top" = "k8s-ops" ]; then
  ok "semantic: paraphrase (no shared keywords) ranked the k8s memory #1 -> real MiniLM-384 <=> similarity"
else
  no "semantic: expected top hit 'k8s-ops', got '${top:-<none>}' (resp: $(echo "$resp" | head -c 300))"
fi

# corroborate the embedder identity + dim from the daemon log
if grep -qiE "MiniLM|all-MiniLM-L6-v2|384" "$LOG"; then
  ok "semantic: daemon log confirms MiniLM/384-dim embedder ($(grep -oiE 'MiniLM[^ ]*|384[- ]?dim' "$LOG" | head -1))"
else
  echo "INFO: embedder id not surfaced in log at default verbosity (ranking proof stands)"
fi

echo "----"; echo "semantic-recall summary: $pass PASS / $fail FAIL"
echo "== log tail =="; grep -iE "embed|minilm|tier|nomic|ollama|384|768" "$LOG" | tail -6
[ "$fail" -eq 0 ]
