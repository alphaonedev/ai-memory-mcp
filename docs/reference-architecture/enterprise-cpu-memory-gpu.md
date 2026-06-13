# Enterprise Reference Architecture: CPU + Memory + GPU Federated Nodes

**Local Ollama embeddings on GPU-equipped nodes — zero per-token
cost, no embedding egress.** This is the #1598 reference shape for
enterprise federated deployments where every memory-bearing node has
a compatible GPU. Operator GPU policy: **Ollama runs only on
GPU-equipped nodes** — `ai-memory doctor`'s "Embeddings Reachability
(#1598)" section fires a GPU-policy WARN when `backend = ollama`
resolves on a host with no detectable NVIDIA GPU. On this
architecture every node satisfies the policy by construction.

The CPU-only sibling of this page is
[Enterprise Reference Architecture: CPU + Memory Federated Nodes](enterprise-cpu-memory.md)
(API embeddings, no Ollama anywhere). The visual catalog of all
deployment topologies is
[`docs/reference-architectures.md`](../reference-architectures.md);
capacity / cost / SLA planning is
[`docs/enterprise-deployment.md`](../enterprise-deployment.md).

## Topology

```
                      federated mesh (N nodes, W-of-N quorum)
   ┌────────────────────────────────────────────────────────────────────┐
   │                                                                    │
   │   node-a (CPU+RAM+GPU)            node-b (CPU+RAM+GPU)             │
   │   ┌─────────────────────┐  mTLS   ┌─────────────────────┐          │
   │   │ ai-memory serve     │◀───────▶│ ai-memory serve     │  ◀─▶ …   │
   │   │  sqlite/pg+AGE      │ signed  │  sqlite/pg+AGE      │          │
   │   │        │ localhost  │  sync   │        │ localhost  │          │
   │   │        ▼ /api/embed │         │        ▼ /api/embed │          │
   │   │ ┌─────────────────┐ │         │ ┌─────────────────┐ │          │
   │   │ │ Ollama (GPU)    │ │         │ │ Ollama (GPU)    │ │          │
   │   │ │ nomic-embed-text│ │         │ │ nomic-embed-text│ │          │
   │   │ └─────────────────┘ │         │ └─────────────────┘ │          │
   │   └─────────────────────┘         └─────────────────────┘          │
   │                                                                    │
   └────────────────────────────────────────────────────────────────────┘

   embeddings hop p50: ~5–30 ms (localhost, GPU)   federation: W=2 quorum,
                                                   mTLS, X-Memory-Sig +
                                                   X-Memory-Nonce
```

**When to choose this.** Your fleet nodes have GPUs (or you are
sizing new nodes and embedding volume justifies them). You want the
lowest embedding latency, zero per-token embedding cost, and no
embedding traffic leaving the node — at the price of GPU hardware,
Ollama as a per-node dependency, and model weights in every node
image.

## Per-node configuration

```toml
schema_version = 2
tier = "autonomous"

[llm]
# Chat LLM is independent of the embedder (#1067): point it at a
# cloud vendor, or at the same local Ollama for full airgap.
backend     = "openrouter"
model       = "x-ai/grok-4.3"
api_key_env = "OPENROUTER_API_KEY"

[embeddings]
backend = "ollama"                    # local GPU Ollama — the compiled
                                      # default backend
url     = "http://localhost:11434"    # synonym of base_url; this is the
                                      # ollama default, shown explicit
model   = "nomic-embed-text"          # 768d, Apache 2.0, USA (Nomic);
                                      # in KNOWN_EMBEDDING_DIMS
backfill_batch = 100
# No api_key_* — Ollama's native /api/embed wire shape is unauthenticated
# and loopback-only in this shape.

[reranker]
enabled = true
model   = "ms-marco-MiniLM-L-6-v2"

[storage]
default_namespace = "fleet"
archive_on_gc     = true
```

Backfill requests to Ollama send `truncate: true` (#1595) so
over-length inputs are truncated server-side instead of failing the
batch; per-row fallback + skip-with-WARN applies on this backend the
same as on API backends.

## Federation skeleton

Identical to the CPU-only sibling — the embedder leg is the only
difference. Per [`docs/federation.md`](../federation.md): TLS + mTLS
fingerprint allowlist at the transport layer, `--api-key` at the
application layer, per-message Ed25519 signed sync (`X-Memory-Sig` +
`X-Memory-Nonce`, secure-by-default at v0.7.0) with peer enrollment
at the identity layer, W-of-N quorum writes + vector-clock merge +
periodic catch-up pull.

**Embedding-dim consistency is fleet-critical** here too: every peer
must run the same embedding model/dim. Mixed fleets (some GPU nodes
on local `nomic-embed-text`, some CPU nodes on a 3072-dim API model)
are NOT a supported shape — pick one architecture per federation, or
align the API nodes on the same 768-dim model the GPU nodes serve.
Migrate with `ai-memory reembed --dry-run` → `ai-memory reembed` per
node after any model change.

## When to choose which architecture

| Dimension | [CPU + Memory (API embeddings)](enterprise-cpu-memory.md) | CPU + Memory + GPU (local Ollama) |
|---|---|---|
| Node hardware | Commodity VMs / containers; no accelerator | GPU on every memory-bearing node |
| Embedding backend | Any #1067 alias (`openrouter` reference) or self-hosted TEI / vLLM / llama.cpp server (`openai-compatible`) | Local Ollama, native `/api/embed` |
| Ollama on nodes | **None anywhere** | Required, GPU-backed (operator GPU policy) |
| Embed latency p50 | ~80–300 ms (API hop) | ~5–30 ms (localhost GPU) |
| Marginal embed cost | Per-token API spend (e.g. ~$0.20/M on the gemini-embedding-2 reference) | $0 after hardware |
| Embedding egress | Cloud shape: yes (paid no-training routes); airgapped shape: LAN-only | None (loopback) |
| Reference model | `google/gemini-embedding-2` (3072d) cloud; `nomic-embed-text-v1.5` (768d) airgapped | `nomic-embed-text` (768d) |
| Re-embed on adoption | Cloud shape: yes (768d → 3072d, `ai-memory reembed`); airgapped nomic shape: none | None (same default model/dim) |
| Node image size | Small (no weights) | + Ollama + model weights |
| Failure mode | API outage → loud keyword-mode degradation (#1593), truthful capabilities (#1594) | Local Ollama down → same fail-closed degradation, but failure domain is per-node |
| Doctor GPU-policy WARN | Never fires (`backend != ollama`) | Never fires (GPU present); fires on a mis-scheduled CPU-only node |
| Choose when | Fleet is CPU-only; elastic / containerized; embedding volume modest or bursty | GPUs already present; highest embed volume; hard data-locality requirements with no self-host serving tier |

Hybrid note: a self-hosted TEI/vLLM serving node with a GPU, fronting
CPU-only ai-memory nodes via `backend = "openai-compatible"`, is the
CPU + Memory architecture (Shape B) with GPU-accelerated serving — it
keeps the fleet nodes Ollama-free and complies with the GPU policy at
the serving tier.

## See also

- [CPU + Memory sibling architecture](enterprise-cpu-memory.md) —
  cloud + airgapped API-embedding shapes, sizing and security posture.
- [`docs/v0.7.0/release-notes.md` §"Substrate-native API embeddings"](../v0.7.0/release-notes.md)
  — the #1598 change inventory.
- [`docs/RUNBOOK-ollama-kv-tuning.md`](../RUNBOOK-ollama-kv-tuning.md)
  — Ollama serving tunables on GPU nodes.
- [`docs/federation.md`](../federation.md) — hardening + quorum
  tuning.
