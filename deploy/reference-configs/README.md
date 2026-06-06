# Enterprise Compute Reference Configurations (EC-1)

Three benchmark-ready `config.toml` reference files, one per compute archetype,
plus the selection decision tree. These are the concrete substrate the
downstream EC benchmark harness measures against. Every value is annotated with
the exact code path that consumes it; the resolvers are pure (no network I/O),
so the resolution semantics are fully determined by the file content and proven
by [`tests/ec1_reference_configs_resolve.rs`](../../tests/ec1_reference_configs_resolve.rs).

| File | Archetype | Embedder | Ollama? | GPU? |
|------|-----------|----------|---------|------|
| [`ec-cpu.toml`](./ec-cpu.toml) | **EC-CPU** | candle, in-process (`EmbeddingModel::MiniLmL6V2`) | no | no |
| [`ec-gpu.toml`](./ec-gpu.toml) | **EC-GPU** | Ollama HTTP (`EmbeddingModel::NomicEmbedV15`) | dedicated | yes |
| [`ec-gpu-shared.toml`](./ec-gpu-shared.toml) | **EC-GPU-SHARED** | Ollama HTTP (`EmbeddingModel::NomicEmbedV15`) | shared / co-tenant | yes |

> Model identifiers in these files are **operator-facing aliases only** —
> irreducible configuration data the resolver canonicalises. No vector-dimension
> literal appears in any TOML; the dim is derived at runtime from the
> `EmbeddingModel` SSOT enum (`.dim()`) via `canonical_embedding_dim()`. The
> validation test asserts against those SSOT symbols, never against bare
> model-id or dimension literals.

---

## Selection decision tree — "Ollama or no Ollama?"

The first and load-bearing question is whether a GPU-backed Ollama endpoint is
available to the daemon. That single decision picks the embedder family, which
in turn picks the entire archetype.

```
                       ┌────────────────────────────────────────┐
                       │ Is a GPU-backed Ollama endpoint         │
                       │ available to the daemon for embeddings? │
                       └───────────────┬────────────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │ NO                                           │ YES
                ▼                                              ▼
        ┌───────────────┐                       ┌──────────────────────────────┐
        │   EC-CPU      │                       │ Is the GPU DEDICATED to       │
        │               │                       │ ai-memory, or SHARED with     │
        │ candle MiniLM │                       │ other co-tenant workloads?    │
        │ 384-dim,      │                       └───────────────┬───────────────┘
        │ in-process,   │                                       │
        │ NO Ollama.    │              ┌────────────────────────┴───────────┐
        │ LLM = cloud   │              │ DEDICATED                          │ SHARED
        │ provider.     │              ▼                                    ▼
        └───────────────┘      ┌───────────────┐               ┌────────────────────────┐
                               │   EC-GPU      │               │    EC-GPU-SHARED       │
                               │               │               │                        │
                               │ nomic 768-dim │               │ nomic 768-dim over a   │
                               │ over local    │               │ SHARED Ollama host;    │
                               │ Ollama GPU.   │               │ smaller batch + pool,  │
                               │ Full local    │               │ longer acquire timeout │
                               │ AI surface.   │               │ (good-neighbour).      │
                               └───────────────┘               └────────────────────────┘
```

### EC-CPU — no GPU, no Ollama
Choose when the fleet has **no GPU budget**. The embedder is the candle
in-process `all-MiniLM-L6-v2` (384-dim) running on CPU; the daemon never opens
an Ollama connection for embeddings. LLM autonomy runs against a **cloud**
provider (OpenRouter/etc.) so the host needs no local accelerator at all. This
is the posture of the free do-1461 CPU swarm.

### EC-GPU — dedicated GPU, Ollama
Choose when ai-memory **owns** a GPU. Both the embedder (768-dim nomic) and the
LLM run on the local Ollama, so the full AI surface is local with no co-tenant
contention. Larger pool and batch sizes exploit the dedicated silicon.

### EC-GPU-SHARED — shared GPU, Ollama
Choose when a **central Ollama host** serves several daemons/workloads. Model
resolution is byte-identical to EC-GPU; only the resource envelope changes:
smaller `backfill_batch` (gentler bursts on the shared endpoint), a tighter
connection pool (don't hoard substrate connections), and a longer acquire
timeout (ride out contention instead of failing fast).

---

## Code-precedence map

Every resolved field follows one uniform precedence ladder (highest wins):

```
CLI flag  >  AI_MEMORY_* env var  >  config.toml section
          >  legacy flat field (one-shot deprecation WARN)  >  compiled default
```

| Concern | Resolver | What it does for these configs |
|---------|----------|--------------------------------|
| Embedder URL + model + dim | `AppConfig::resolve_embeddings()` (`src/config.rs`) | `[embeddings].model` wins, is canonicalised via `canonicalise_embedding_model()`, and its dim is looked up in `KNOWN_EMBEDDING_DIMS` via `canonical_embedding_dim()`. `[embeddings].url` wins the URL sub-ladder over the legacy `embed_url` / `ollama_url` flat fields. |
| Daemon embedder model | `resolve_embedder_model()` (`src/daemon_runtime.rs`) | Parses the resolved alias via `EmbeddingModel::from_canonical_id()`. EC-CPU → `MiniLmL6V2`; EC-GPU / EC-GPU-SHARED → `NomicEmbedV15`. |
| Embedder backend wiring | `Embedder::for_model()` (`src/embeddings.rs`) | `MiniLmL6V2` → `Embedder::new_local()` (candle, **Ollama client ignored** → the no-Ollama path). `NomicEmbedV15` → `Embedder::new_ollama()` (**requires** the Ollama client → the GPU path). |
| Reranker | `AppConfig::resolve_reranker()` | `[reranker].enabled` / `model`; folds the legacy `cross_encoder` flag. |
| Storage | `AppConfig::resolve_storage()` | `[storage]` namespace + archive policy. |
| Limits | `AppConfig::resolve_limits()` | `[limits]` quotas + page-size cap; `AI_MEMORY_MAX_*` env overrides. |
| Postgres pool | `AppConfig::resolve_pg_pool()` | top-level `postgres_pool_*` / `postgres_acquire_timeout_secs`; `AI_MEMORY_PG_*` env overrides. |
| Permissions | `AppConfig::effective_permissions_mode()` | `[permissions].mode`; v0.7.0 secure default is `enforce`. |

---

## Secrets posture

No secret is ever inlined in these files:

- **LLM API key** — supplied at runtime via the env var named by
  `[llm].api_key_env` (or `[llm].api_key_file`). Inline `[llm].api_key` is
  **rejected at parse time** with a security-rationale message.
- **HTTP API key** — supplied via the `AI_MEMORY_API_KEY` env override, never
  written to the file.
- **Database password** — supplied out-of-band via the `AI_MEMORY_DB` env
  override or the `PG*` environment; the `db` URL here carries no password.

---

## Validation

`tests/ec1_reference_configs_resolve.rs` parses each file in this directory and
asserts that the resolvers yield the intended `(EmbeddingModel variant, dim)`
tuple per archetype — using only the `EmbeddingModel` SSOT symbols
(`from_canonical_id`, `.dim()`, `.hf_model_id()`) and `canonical_embedding_dim`,
with zero bare model-id / dimension literals.

```sh
AI_MEMORY_NO_CONFIG=1 cargo test --test ec1_reference_configs_resolve
```
