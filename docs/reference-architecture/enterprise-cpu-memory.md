# Enterprise Reference Architecture: CPU + Memory Federated Nodes

**API embeddings on commodity CPU nodes — no GPU, no Ollama, full
semantic/autonomous tier.** This is the #1598 reference shape for
enterprise federated deployments where the fleet is CPU + memory only
(cloud VMs, droplets, containers, on-prem servers without
accelerators). The embedder is wired to an embedding **API** — either
a cloud vendor (the operator-selected reference is OpenRouter +
`google/gemini-embedding-2`) or a self-hosted OpenAI-compatible
serving stack for airgapped sites — so no node runs Ollama anywhere.

The GPU sibling of this page is
[Enterprise Reference Architecture: CPU + Memory + GPU Federated Nodes](enterprise-cpu-memory-gpu.md)
(local Ollama embeddings on GPU-equipped nodes). A
when-to-choose-which table lives on that page. The visual catalog of
all deployment topologies is
[`docs/reference-architectures.md`](../reference-architectures.md);
capacity / cost / SLA planning is
[`docs/enterprise-deployment.md`](../enterprise-deployment.md).

## Topology

```
                      federated mesh (N nodes, W-of-N quorum)
   ┌────────────────────────────────────────────────────────────────────┐
   │                                                                    │
   │   node-a (CPU+RAM)          node-b (CPU+RAM)      node-c (CPU+RAM) │
   │   ┌────────────────┐  mTLS  ┌────────────────┐    ┌──────────────┐ │
   │   │ ai-memory serve│◀──────▶│ ai-memory serve│◀──▶│ ai-memory    │ │
   │   │  sqlite/pg+AGE │ signed │  sqlite/pg+AGE │    │ serve        │ │
   │   └───────┬────────┘  sync  └───────┬────────┘    └──────┬───────┘ │
   │           │ HTTPS (Bearer)          │                    │         │
   └───────────┼────────────────────────┼────────────────────┼─────────┘
               ▼                        ▼                    ▼
        ┌──────────────────────────────────────────────────────────┐
        │  Embedding API — ONE of:                                  │
        │   • cloud: openrouter → google/gemini-embedding-2 (3072d) │
        │   • airgapped: self-hosted TEI / vLLM / llama.cpp server  │
        │     exposing OpenAI-compatible /v1/embeddings             │
        └──────────────────────────────────────────────────────────┘

   embeddings hop p50: ~80–300 ms (API)    federation: W=2 quorum, mTLS,
                                           X-Memory-Sig + X-Memory-Nonce
```

**When to choose this.** Your fleet is commodity CPU nodes (cloud
VMs, containers, droplets) and you want full semantic recall +
autonomous-tier features without provisioning GPUs. You accept an
80–300 ms embedding hop (per store / per recall query embed) in
exchange for zero accelerator cost and a fleet image with no model
weights. Operator policy: **Ollama runs only on GPU-equipped nodes**
— on a CPU-only fleet the `ai-memory doctor` "Embeddings Reachability
(#1598)" section fires a GPU-policy WARN if `backend = ollama` is
resolved, which this architecture never triggers.

## Shape A — cloud embeddings (OpenRouter reference)

Operator-selected reference cloud model: **`google/gemini-embedding-2`
via OpenRouter** — 3072-dim, 8192-token context, ~$0.20/M tokens,
Google AI Studio provider, USA. Policy constraints baked into this
reference: **USA models only**, **paid-tier only** (no `:free` routes
— paid routing avoids free-tier providers with data-retention/training
terms).

`/etc/ai-memory/config.toml` (per node, identical across the fleet):

```toml
schema_version = 2
tier = "autonomous"

[llm]
backend     = "openrouter"            # chat LLM — any #1067 alias works
model       = "x-ai/grok-4.3"         # USA-vendor policy example
api_key_env = "OPENROUTER_API_KEY"

[embeddings]
backend     = "openrouter"            # #1598 — API embeddings
# base_url omitted — the openrouter alias pre-fills
# https://openrouter.ai/api/v1
model       = "google/gemini-embedding-2"   # native 3072-dim
dim         = 768                     # #1598 fleet follow-up: explicit dim is
                                      # sent as the wire `dimensions` param —
                                      # gemini-embedding-2 truncates server-side
                                      # (Matryoshka). REQUIRED posture for
                                      # pgvector-backed federated fleets: ANN
                                      # indexes cap at 2000 dims and the fleet
                                      # schemas template vector(768). sqlite-only
                                      # single nodes may omit dim (native 3072).
api_key_file = "/etc/ai-memory/keys/embed.key"   # mode 0400 enforced;
                                                 # or api_key_env
backfill_batch = 100

[reranker]
enabled = true                        # cross-encoder runs on-CPU
model   = "ms-marco-MiniLM-L-6-v2"

[storage]
default_namespace = "fleet"
archive_on_gc     = true
```

## Shape B — self-hosted / airgapped embeddings

For airgapped sites, serve an **Apache-2.0 USA model** behind an
OpenAI-compatible `/v1/embeddings` endpoint on a shared CPU inference
node (or per-rack):

| Model | Dims | License | Note |
|---|---|---|---|
| `nomic-embed-text-v1.5` | 768 | Apache 2.0 | **Zero re-embed** for existing corpora — it is the compiled default model, so vectors are unchanged. |
| Snowflake `arctic-embed` l / m / s | 1024 / 768 / 384 | Apache 2.0 | Pick by recall-quality vs. CPU budget. |
| IBM `granite-embedding` | 768 / 384 | Apache 2.0 | In `KNOWN_EMBEDDING_DIMS` (#1598). |

Serving stacks exposing OpenAI-compatible `/v1/embeddings`:
**HuggingFace text-embeddings-inference** (Apache 2.0), **vLLM**
(Apache 2.0), **llama.cpp server** (MIT).

```toml
[embeddings]
backend  = "openai-compatible"        # generic escape hatch — base_url
base_url = "http://tei.internal:8080/v1"   # REQUIRED for this backend
model    = "nomic-embed-text-v1.5"    # 768d — zero re-embed migration
# keyless internal endpoint: omit api_key_env / api_key_file entirely
```

Env-var equivalents (highest precedence; useful for container
fleets): `AI_MEMORY_EMBED_BACKEND`, `AI_MEMORY_EMBED_BASE_URL`,
`AI_MEMORY_EMBED_MODEL`, `AI_MEMORY_EMBED_API_KEY` (secret).

## Federation skeleton

Identical to the standard hardened mesh — this architecture changes
only the embedder leg. Per
[`docs/federation.md`](../federation.md):

- **Transport** — TLS + mTLS fingerprint allowlist
  (`ai-memory serve --tls-cert … --tls-key …
  --mtls-allowlist /etc/ai-memory/peer-fingerprints.allow`).
- **Application** — `--api-key` (X-API-Key on every endpoint except
  `/api/v1/health`).
- **Identity / wire integrity** — per-message Ed25519 signed sync
  (`X-Memory-Sig` + `X-Memory-Nonce`; `AI_MEMORY_FED_REQUIRE_SIG=1` +
  `AI_MEMORY_FED_REQUIRE_NONCE=1` are the v0.7.0 secure defaults),
  peer enrollment (`AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1`).
- **Quorum** — W-of-N writes (W = 2 for 2–3 peers; `ceil((N+1)/2)`
  above that), vector-clock CRDT-lite merge, periodic catch-up pull.

**Embedding-dim consistency is fleet-critical.** Every federated peer
MUST resolve the same embedding model/dim (this architecture pins
`model = "google/gemini-embedding-2"` + `dim = 768` fleet-wide so
pgvector `vector(768)` schemas and their HNSW indexes — capped at
2000 dims by pgvector — keep serving ANN recall) — vectors from different
models do not compare. Roll out a model change fleet-wide:
(1) update `[embeddings]` on every node, (2) run
`ai-memory reembed --dry-run` then `ai-memory reembed` per node,
(3) verify with `ai-memory doctor` (the "Embeddings Reachability
(#1598)" section reports the resolved backend/model/provenance).

## Sizing notes

- **Embedding latency** — 80–300 ms p50 per API embed call (cloud
  vendor and network dependent; self-hosted TEI on a modern CPU node
  typically lands at the low end for short inputs). This hop is on
  the store path (one embed per memory) and on the semantic-recall
  path (one embed per query). Budget it on top of the local recall
  numbers in [`docs/performance.html`](../performance.html).
- **Backfill / reembed throughput** — bounded by the API rate limit,
  not local CPU; tune `backfill_batch` (1–10000, default 100) and
  `ai-memory reembed --batch` accordingly.
- **Reranker CPU cost** — the autonomous-tier cross-encoder
  (`ms-marco-MiniLM-L-6-v2`) runs in-process on CPU; budget one CPU
  core burst per reranked recall on top of the embed hop. Disable
  (`[reranker] enabled = false`) on the smallest nodes if recall p99
  matters more than ranking quality.
- **No GPU, no model weights on fleet nodes** — node images stay
  small; the only embedding state on a node is its vector column.

## Security posture

- **Key files 0400** — `[embeddings].api_key_file` (like
  `[llm].api_key_file`) is refused unless mode 0400 or stricter;
  inline `api_key = "<literal>"` in config.toml is rejected at parse
  time.
- **Paid-tier, no-training routing** — the cloud reference uses paid
  OpenRouter routes only (no `:free`), pinning providers whose terms
  exclude training on inputs.
- **USA-vendor compliance hook** — the reference model set is
  USA-only (Google AI Studio via OpenRouter; Nomic / Snowflake / IBM
  for self-host). Substitute per your compliance regime; the
  `KNOWN_EMBEDDING_DIMS` table + `[embeddings].dim` override accept
  any model.
- **Fail-closed degradation (#1593)** — if the embedding API is
  unreachable at boot or at request time, semantic recall degrades
  loudly to keyword mode (stderr ERROR + `embedder_loaded = false` +
  `recall_mode_active = "degraded"` in `memory_capabilities`, #1594).
  The chat LLM client is never reused for embeddings.

## See also

- [CPU + Memory + GPU sibling architecture](enterprise-cpu-memory-gpu.md)
  — including the when-to-choose-which table.
- [`docs/v0.7.0/release-notes.md` §"Substrate-native API embeddings"](../v0.7.0/release-notes.md)
  — the #1598 change inventory.
- [`docs/CONFIG_SCHEMA.md`](../CONFIG_SCHEMA.md) — full `[embeddings]`
  field reference + resolver precedence.
- [`docs/federation.md`](../federation.md) — mTLS / X-API-Key / peer
  attestation hardening; quorum tuning tables.
- [`docs/enterprise-deployment.md`](../enterprise-deployment.md) —
  tier-by-tier capacity / cost / SLA planning.
