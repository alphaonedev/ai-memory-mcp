# 07 — Memory Cognition Lifecycle (v0.7.0)

> Domain: `src/confidence/`, `src/atomisation/`, `src/synthesis/`,
> `src/multistep_ingest/`, `src/observations/`, `src/persona/`, `src/kg/`,
> `src/inference/`, `src/offload/`, `src/recover/`, `src/transcripts/`,
> `src/mine.rs`, `src/reranker.rs`, `src/hnsw.rs`, `src/embeddings.rs`.
>
> Every claim below carries `file:line` provenance verified against the
> on-disk `release/v0.7.0` source. Where a behaviour is gated behind an
> env var, the env var name is verbatim. Models/constants are quoted from
> source, not from memory.

---

## 1. Recall Pipeline (FTS5 + Semantic Hybrid + Cross-Encoder Rerank)

The recall hot-path blends two retrievers (SQLite FTS5 keyword + HNSW
semantic), then optionally re-ranks the merged candidate set with a
cross-encoder, then touches recalled rows (sliding-TTL + decay).

### 1.1 Retrievers and blending

| Capability | Provenance | Notes |
|---|---|---|
| FTS5 keyword retriever | `src/observations/mod.rs:48` (retriever names `"fts5"` / `"hnsw"` / `"hybrid"` documented on `Candidate`) | Keyword arm of the hybrid recall. |
| HNSW semantic retriever | `src/hnsw.rs` `VectorIndex` (struct ~line 294), `search` (~line 718) | In-memory `instant-distance` HNSW index. |
| Adaptive semantic/keyword blend | recall dispatcher (CLAUDE.md-documented `semantic_weight` 0.50→0.15 by content length) | Adaptive weight shrinks semantic share for longer queries. |
| Recall-consumption ledger (#886 Gap 3) | `src/observations/mod.rs:65` `record_recall`, `:108` `mark_consumed`, `:162` `list_observations` | One ledger row per returned candidate (`recall_id`+`memory_id`+`retriever`+`rank`+`score`); composite PK `(recall_id, memory_id)` keeps it idempotent (`:30`). |
| Citation feedback loop | `src/observations/mod.rs:229` `parse_cite_batch`, `:259` `try_mark_consumed_from_params` | `memory_store`/`memory_link` citing a `recall_id`+`cited_memory_ids` flips `consumed=TRUE` + captures `consumed_by_memory_id`. Best-effort; never blocks the write (`:269` warn-and-continue). |
| Observation ledger TTL prune | `src/observations/gc.rs` (`DEFAULT_TTL_DAYS=7`, env `AI_MEMORY_OBSERVATIONS_TTL_DAYS`) | Read-side TTL sweep. |

`record_recall` is best-effort: a SQL error logs at warn and continues —
"the substrate MUST NOT block a successful recall response on a failed
audit write" (`src/observations/mod.rs:54-58`).

### 1.2 Cross-encoder reranker

| Capability | Provenance | Notes |
|---|---|---|
| `CrossEncoder` enum | `src/reranker.rs:349` | Two arms: `Lexical { degraded: bool }` (fallback) and `Neural` (cross-encoder). |
| Neural model | `src/reranker.rs` `Neural` arm — **ms-marco-MiniLM-L-6-v2** | Cross-encoder; held as `Arc<BertModel>` (no per-call mutex, post-#1084). |
| Reflection-boost blend | `src/reranker.rs:641` `rerank_with_reflection_boost`, score blend `:651` | Reflection-kind candidates receive a score boost in the blend. |
| Batched coalescer (#G9) | `src/reranker.rs:1005` `RerankJob`, `:1403` `process_batch` | `BatchedReranker` coalesces concurrent rerank requests. |
| Drift closed (G8) | `src/reranker.rs` self-doc | Prior impl only emitted `tracing::warn!`; now surfaces `meta.reranker_used` in the response. |

### 1.3 Embeddings

| Capability | Provenance | Notes |
|---|---|---|
| `Embed` trait | `src/embeddings.rs` (`Embed::embed`) | Single-vector embedding seam; used by `inference::CpuBackend` (`src/inference/mod.rs:148`). |
| `Embedder` enum / `for_model` | `src/embeddings.rs:154` (enum), `:241` `for_model` | Dispatch by configured model. |
| `EmbeddingModel` enum | `src/config.rs:16-58` | `MiniLmL6V2` (384-dim, candle local) and `NomicEmbedV15` (768-dim, Ollama `nomic-embed-text-v1.5`). |

### 1.4 HNSW vector index internals (`src/hnsw.rs`)

| Constant / fn | Provenance | Value / role |
|---|---|---|
| `REBUILD_THRESHOLD` | `src/hnsw.rs:30` | `200` — dirty-insert count that triggers an async rebuild. |
| `MAX_ENTRIES` | `src/hnsw.rs:50` | `100_000` — eviction ceiling. |
| `EVICTION_RATE_CEILING_PER_HOUR` | `src/hnsw.rs:116` | `10` — eviction-rate guard. |
| `cosine_distance` | `src/hnsw.rs:200` | L2-normalised cosine distance metric. |
| `EmbeddingPoint` | `src/hnsw.rs:192` | Point wrapper for `instant-distance`. |
| `VectorIndex` | `src/hnsw.rs:294` | The index struct. |
| `build` / `insert` / `search` | `src/hnsw.rs:394` / `:485` / `:718` | Core ops. |
| `rebuild_async` / `try_swap_warming` | `src/hnsw.rs:883` / `:954` | #968 active/warming double-buffer rebuild with atomic swap. |

> **§10.4 G2/G3/G4 gaps (v0.9 targets):** the HNSW index is in-memory
> only and rebuilt from the `memories` embedding column; persistence /
> incremental-merge / sharding are deferred to v0.9 per the index's
> documented gap list. v0.7.0 ships the double-buffer rebuild
> (`rebuild_async` #968), the eviction ceiling (#1074 generation
> counter), and the `Arc<str> valid_ids` cache (#1087).

### 1.5 Touch-on-recall (sliding TTL + confidence decay)

| Capability | Provenance | Notes |
|---|---|---|
| Touch-after-recall | `src/store/sqlite.rs::touch_after_recall` (called from recall dispatch) | Bumps `access_count`, refreshes `last_accessed_at`; mid→long promotion at 5 accesses (CLAUDE.md recall-pipeline contract). |
| Recall-time decay hook | `src/confidence/decay.rs:77` `apply_decay_touch` | Fired from `touch_after_recall` only when `AI_MEMORY_CONFIDENCE_DECAY=1` (`:28` `ENV_DECAY`, `:32` `decay_enabled`). |

---

## 2. Confidence (Batman Form 5)

Pure derive engine + freshness decay + shadow-mode calibration. All math
is side-effect-free; the only substrate writer is `apply_decay_touch`.

| Capability | Provenance | Notes |
|---|---|---|
| `derive()` pure engine | `src/confidence/mod.rs:159` | Computes confidence from atom/corroboration/age signals. Formula: `base = 0.5 + 0.1*atom + 0.05*log10(1+corrob) − 0.02*age*decay_rate`, blended with the caller baseline via a freshness factor. |
| `DeriveContext` | `src/confidence/mod.rs:76` | Input bundle for `derive()`. |
| `DEFAULT_HALF_LIFE_DAYS` | `src/confidence/mod.rs:119` | `30` days. |
| Auto-confidence opt-in | `src/confidence/mod.rs:57` `ENV_AUTO_CONFIDENCE` (`AI_MEMORY_AUTO_CONFIDENCE`) | Env-gated; default off. |
| Submodules | `src/confidence/mod.rs:50-52` | `calibrate`, `decay`, `shadow`. |
| Freshness decay math | `src/confidence/decay.rs:52` `decayed` | `base * 2^(-age/half_life)` = `base * exp(-age*ln2/half_life)`; clamps `[0,1]`; negative age→0; `half_life<=0`→`EPSILON` (degenerate collapse-to-0). |
| Decay touch (substrate writer) | `src/confidence/decay.rs:77` `apply_decay_touch` | Anchors age on `confidence_decayed_at` (fallback `created_at`), writes new `confidence` + `confidence_source='decayed'` + fresh `confidence_decayed_at`. Idempotent / converging. |
| **Non-version-bumping write (#1036)** | `src/confidence/decay.rs:107-129` | Decay UPDATE intentionally does NOT bump `memories.version` — a system sweep, not a user edit — so it can't trigger spurious `VersionConflict` on the next `update_with_expected_version`. Pinned by `tests/non_version_bumping_sites_1036.rs`. |
| `ConfidenceSource` markers | `src/models/*` (`CallerProvided`, `Decayed`, …) | Confidence provenance on each row. |

`AI_MEMORY_CONFIDENCE_DECAY` is the recall-touch opt-in
(`src/confidence/decay.rs:28`); confidence writeback to
`memories.confidence` happens only under that flag or a namespace
`confidence_decay_half_life_days` policy (`:5-11`).

---

## 3. Atomisation (WT-1-B) — `src/atomisation/mod.rs`

| Capability | Provenance | Notes |
|---|---|---|
| `AtomiserConfig` defaults | `src/atomisation/mod.rs` (defaults `200/2/10/3/1`) | Decompose thresholds. |
| `AtomiseError` | `src/atomisation/mod.rs:136` | Domain error enum. |
| `MAX_ATOMISATION_DEPTH` | `src/atomisation/mod.rs:261` | `3` — thread-local recursion guard. |
| `Atomiser` | `src/atomisation/mod.rs:333` | The decomposition engine. |
| `atomise_sync_with_retries` | `src/atomisation/mod.rs:488` | Retrying sync entry point. |
| `write_atom` → `derives_from` link | `src/atomisation/mod.rs:709` | Each atom links back to its parent via `derives_from`. |
| `compute_atom_span` | `src/atomisation/mod.rs:990` | Source-span provenance per atom. |
| Curator decompose path | `src/atomisation/curator.rs` (44 symbols) | Curator-driven atomisation; signed `atomisation_complete` events. |

> Recursive-primitive depth cap = **3** (matches synthesis + reflection).

---

## 4. Synthesis (Batman Form 1) — `src/synthesis/mod.rs`

Online dedup at store-time: decide add / update / delete / no-op against
existing candidates.

| Capability | Provenance | Notes |
|---|---|---|
| `SynthesisVerb` | `src/synthesis/mod.rs:152` | `add` / `update` / `delete` / `no_op`. |
| `build_prompt_with_cap` (USER_CONTENT envelope) | `src/synthesis/mod.rs:239` | SEC-1 trust envelope wrapping caller content. |
| `parse_response` validation | `src/synthesis/mod.rs:373` | Verdict/response parse + validation. |
| `DEFAULT_MAX_CANDIDATE_CHARS` | `src/synthesis/mod.rs:97` | `1500` — per-candidate prompt cap. |
| `MAX_SYNTHESIS_DEPTH` | `src/synthesis/mod.rs:559` | `3` — recursion cap. |
| K9 delete re-check | `src/synthesis/mod.rs` (delete branch) | Delete verdict re-checks before acting. |

---

## 5. Multistep Ingest — `src/multistep_ingest/`

Two-phase (helpers → LLM) ingestion pipeline with prompt-cache-friendly
shared prefix and explicit trust slots.

| Capability | Provenance | Notes |
|---|---|---|
| `PipelineVariant` | `src/multistep_ingest/pipeline.rs:21` | `TwoPhase` (Understand-Anything) / `FourStep` (OpenKB). `as_str`/`from_str` at `:32`/`:42`. |
| `Pipeline` struct | `src/multistep_ingest/pipeline.rs:105` | `variant` + ordered `stages` + shared `system_prompt`. |
| `two_phase_default` | `src/multistep_ingest/pipeline.rs:135` | Phase 1: `FtsClassifier` + `JaccardOverlap` helpers; Phase 2: `synthesise` LLM stage with trust slots citing helper output. |
| `four_step_default` | `src/multistep_ingest/pipeline.rs:186+` | OpenKB four-step exemplar. |
| Executor `run` | `src/multistep_ingest/executor.rs:291` | Phase-1 helpers run on a **borrowed** content slice (PERF-11 #782 — no per-stage clone, pinned by `multistep_phase_1_helpers_receive_content_borrow_not_clone`); Phase-2 assembles shared prefix + resolves trust slots. |
| Shared-prefix cache | `src/multistep_ingest/executor.rs:364-365` `build_shared_prefix` + `CacheKey::from_prefix` | Prompt-cache key derived from variant tag + system prompt. |
| `DEFAULT_MULTISTEP_MAX_CONTENT_CHARS` cap | `src/multistep_ingest/executor.rs:366-368` | LLM content cap. |
| MCP tool | `src/mcp/tools/ingest_multistep.rs` + CLI `src/cli/commands/ingest_multistep.rs` | `resolve_variant` picks `two_phase_default`/`four_step_default`. |

---

## 6. Knowledge Graph — `src/kg/`, KG MCP tools

Bitemporal `reflects_on` / typed-relation graph with cycle safety,
temporal validity, and supersession.

| Capability | Provenance | Notes |
|---|---|---|
| Anti-self-reflection cycle check | `src/kg/cycle_check.rs:71` `would_create_reflection_cycle` | Bounded forward BFS over `reflects_on`; returns `CycleCheckResult{would_cycle, cycle_path}`. |
| `DEFAULT_MAX_DEPTH` | `src/kg/cycle_check.rs:26` | `16` — sentinel cap when caller passes `max_depth=0`. |
| **Fail-CLOSED on SQL error (#1090)** | `src/kg/cycle_check.rs:110-114` | A transient `BUSY/LOCKED` during the walk now propagates as `Err` (was: `warn!` + `would_cycle=false`). Pinned by `sql_error_fails_closed_1090` (`:393`). |
| `memory_kg_query` | `src/mcp/tools/kg_query.rs:78` `handle_kg_query` | Outbound BFS/CTE traversal ≤5 hops; rows carry `valid_from`/`valid_until`/`observed_by`+title+namespace; filters chain across hops. |
| Reciprocal source-uri subgraph (#889) | `src/mcp/tools/kg_query.rs:86-124` | `by_source_uri` returns the forest rooted at a document, bypassing `source_id`. |
| Current-view default (NHI-P3-T7) | `src/mcp/tools/kg_query.rs:160-163` | Excludes edges with past `valid_until` unless `include_invalidated=true`. |
| `memory_kg_invalidate` | `src/mcp/tools/kg_invalidate.rs:60` `handle_kg_invalidate` | Sets `valid_until` on `(source,target,relation)`; idempotent; returns `previous_valid_until`; `found:false` on no-match. K9 namespace-scoped permission gate (`:82-90`) — symmetrical with `handle_link`, prevents cross-tenant signature NULL. |
| `memory_kg_timeline` | `src/mcp/tools/kg_timeline.rs` | Temporal walk. |
| `memory_find_paths` | `src/mcp/tools/find_paths.rs` | Path search between memories. |
| `memory_dependents_of_invalidated` | `src/mcp/tools/dependents_of_invalidated.rs` | Surfaces rows derived from an invalidated edge. |
| `memory_detect_contradiction` | `src/mcp/tools/detect_contradiction.rs:18` `handle_detect_contradiction` | LLM-bound (smart/autonomous tier only `:23`); two-memory lookup → `llm.detect_contradiction`; quality validated via LongMemEval. |
| `memory_consolidate` | `src/mcp/tools/consolidate.rs` + `src/autonomy.rs` `find_consolidation_clusters` | Cosine-primary clustering: orthogonal embeddings defeat a Jaccard-1.0 pair (`src/autonomy.rs:907`); no-embedding corpora fall back to Jaccard (`:976`). 0.75 cosine threshold. |

---

## 7. Reflection / Recursive Learning (#655) + Persona

### 7.1 Reflection

| Capability | Provenance | Notes |
|---|---|---|
| `reflect` / `reflect_with_hooks` | `src/storage/reflect.rs:261` / `:273` | Reflection boundary entry points. |
| `ReflectError` | `src/storage/reflect.rs:32` | `DepthExceeded` / `HookVeto` arms. |
| `ReflectionOrigin` federation bookkeeping | `src/federation/reflection_bookkeeping.rs:70` (struct), `:151` (`reflection_origin`), `:200` (`enforce_local_cap_on_derived`) | Tracks derivation origin across namespaces; enforces local cap on derived reflections. |
| Reflection replay union (I4 / #669) | `src/transcripts/replay.rs:95` `replay_transcript_union` | For a Reflection memory, BFS over `reflects_on` (depth-capped) gathers the union of every reachable transcript; non-reflection memories short-circuit to single-memory read (acceptance-pinned unchanged). Dedups by `transcript_id`, first-seen wins, chronological sort. |
| `memory_reflect` / `memory_export_reflection` MCP | `src/mcp/tools/reflect.rs`, `src/mcp/tools/export_reflection.rs` | In-session reflection + Markdown export. |
| `reflection_origin` CLI/MCP | `src/cli/commands/reflection_origin.rs:40`, `src/mcp/tools/reflection_origin.rs` | Origin lookup surface. |
| Export-reflections CLI | `src/cli/commands/export_reflections.rs:100` `run`, `:146` `parse_format` | Note: `summary.skipped` field is computed but unused (minor drift). |
| Episodic→semantic→procedural (#655 Tasks 1-8) | reflection + curator passes (`src/curator/reflection_pass.rs`, 100 symbols) | Recursive-learning layering; depth-capped. |

> Recursive-primitive depth cap = **3** for reflection (matches synthesis
> + atomisation); cycle-check ceiling is a separate `16`-hop safety bound.

### 7.2 Persona (QW-2) — `src/persona/mod.rs`

| Capability | Provenance | Notes |
|---|---|---|
| `PersonaGenerator` | `src/persona/mod.rs:200` | Reflections → Markdown persona document. |
| `PersonaError::NoReflections` | `src/persona/mod.rs:153` | Refuses generation with zero source reflections. |
| `generate` / `generate_cross_namespace` | `src/persona/mod.rs:257` / `:284` | Same-ns + cross-ns generation. |
| `get_latest_persona` / `next_version` | `src/persona/mod.rs:561` / `:641` | Monotonic version bookkeeping. |
| `DEFAULT_MAX_REFLECTION_SOURCES` | `src/persona/mod.rs:72` | `20`. |
| Ed25519 signing | `src/persona/mod.rs` `SignablePersona` (via `AgentKeypair`) | Persona document is signed. |
| MCP/CLI surface | `src/mcp/tools/persona.rs`, `src/cli/commands/persona.rs`, `src/hooks/post_reflect/auto_persona.rs` | Auto-persona post-reflect hook. |

---

## 8. #1389 Layered Capture / Recovery (L1–L4)

Fail-safe defence against losing decisions when an agent session dies
ungracefully between turns.

### 8.1 L2 — recover-previous-session (`src/recover/`)

| Capability | Provenance | Notes |
|---|---|---|
| Canonical handler | `src/recover/mod.rs:261` `recover_from_transcript` | Dual surface: CLI `recover-previous-session` + MCP `memory_recover_previous_session`. Never panics; errors surface via `RecoverReport.errors` so a SessionStart hook can't wedge boot (`:246-249`). |
| `RecoverReport` wire shape | `src/recover/mod.rs:43-93` | Per-phase elapsed-ms, lines total/atomised/skipped-dedup/skipped-limit, memories_created, `fast_path_hit`, `schema_version_at_run`. |
| `DEFAULT_RECOVER_LIMIT` | `src/recover/mod.rs:169` | `100` lines/run (bounds SessionStart latency). |
| `QUIET_MEMORY_ID_PREVIEW_CAP` | `src/recover/mod.rs:176` | `10` — caps echoed IDs in `--quiet`. |
| Fast-path short-circuit | `src/recover/mod.rs:307-341` | If transcript mtime ≤ agent's `MAX(created_at)` watermark, skip parse+write. **#1419:** routed through indexed `agent_id_idx` VIRTUAL column (v14 migration) to avoid full-table scan that blew the <100ms budget. |
| Transcript-line dedup | `src/recover/mod.rs:390-401` | `transcript_line_dedup` table keyed by line `sha256`; already-recovered lines skipped (sole idempotency mechanism, `:343-351`). |
| Atomic per-turn write | `src/recover/mod.rs:449-570` `write_recovered_turn` | One observation memory + one dedup row under `BEGIN IMMEDIATE`; rollback on failure (mirrors L4 `capture_turn`). User-role turns get priority 6 + `operator-directive` tag (`:491-503`). |
| JSONL parser | `src/recover/parsers/claude_code_jsonl.rs:28` `ClaudeCodeJsonlParser` | Swallows per-line errors; `since_iso` filter; sha256 over verbatim line (`:133`) so line-shape drift doesn't re-atomise. Skips sentinel lines (`last-prompt`, `permission-mode`) (`:129`). |
| Path resolver | `src/recover/transcript_paths.rs` `resolve_transcript`, `HostKind` | Per-host candidate-set walk, picks most-recent. |
| `RecoverError` | `src/recover/mod.rs:578` | Only hard failure is `DbOpen`; `InvalidOpts` otherwise. |

### 8.2 L1 / L3 / L4 touch-points

| Layer | Provenance | Role |
|---|---|---|
| L1 — store-first rule + nag watcher | `src/recover/nag.rs:96` `CaptureNagWatcher`, `:122` `new_from_env` | Per-(agent,session) counter of non-store tool calls. `NagAction::{None,Warn,WarnAndEscalate}` (`:79`). `ToolKind::MemoryWrite` resets streak, `Other` increments (`:105`). |
| L1 thresholds | `src/recover/nag.rs:123-124` | `AI_MEMORY_CAPTURE_NAG_THRESHOLD` default `5`; `AI_MEMORY_CAPTURE_NAG_ESCALATE_THRESHOLD` default `20`. Saturating add (`:424` test). |
| L4 — capture_turn | `src/mcp/tools/capture_turn.rs` (schema v52 dedup) | In-session turn capture + `transcript_line_dedup`; host pubkey allowlist (#47, env `AI_MEMORY_CAPTURE_TURN_HOST_PUBKEYS`). |

---

## 9. Offload / Deref (QW-3) — `src/offload/mod.rs`

Substrate primitive for the offload+deref pattern (full Mermaid/auto-cadence pattern is v0.8).

| Capability | Provenance | Notes |
|---|---|---|
| `ContextOffloader` | `src/offload/mod.rs:164` | `offload` (`:194`) + `deref` (`:309`). |
| `ref_id` format | `src/offload/mod.rs:84` `REF_ID_PREFIX="ofl_"`, `ref_id_from_sha` `:458` | `ofl_<base32 of sha256 first 8 bytes>` (13-char body). |
| Integrity commitment | `src/offload/mod.rs:208-217` | SHA-256 over original bytes taken BEFORE zstd compression (`ZSTD_LEVEL=3` `:60`). |
| `MAX_DECOMPRESSED_BYTES` / `DEFAULT_MAX_OFFLOAD_BLOB_BYTES` | `src/offload/mod.rs:66` / `:72` | `16 MiB` zstd-bomb ceiling / `1 MiB` per-blob default. |
| Ed25519 signing over canonical CBOR | `src/offload/mod.rs:482` `canonical_payload` | RFC 8949 deterministic CBOR over `{ref_id, content_sha256, stored_at, namespace}`. |
| H5 audit binding | `src/offload/mod.rs:549` `append_audit_row` | `context_offloaded`/`context_dereferenced` signed_events rows. **#1438 fix:** uses canonical `AttestLevel::SelfSigned`/`Unsigned` (was orphan `"signed"`). |
| Tamper + IDOR guards | `src/offload/mod.rs:386-394` (integrity), `:346-357` (SEC-4 #767 ownership) | Deref recomputes SHA; cross-agent caller → `NotFound` (leak-resistant); `None` caller bypasses for internal sweepers. |
| TTL sweep | `src/offload/mod.rs:606` `sweep_expired` | Bounded `max_per_run`; **#1264** per-row DELETE re-evaluates TTL predicate to avoid dropping a concurrently-refreshed blob. |
| `OffloadError` | `src/offload/mod.rs:111` | `SizeLimitExceeded`/`IntegrityFailed`/`SignatureFailed`/`NotFound`. |
| MCP/CLI | `src/mcp/tools/offload.rs`, `src/cli/offload.rs` | `memory_offload` / `memory_deref`. |

---

## 10. Inference Backend Abstraction (#651/#654) — `src/inference/mod.rs`

Forward-compatible seam for the v0.8 GPU/MTP backend; **v0.7.0 recall
hot-path still uses the legacy types directly** (no callsite churn).

| Capability | Provenance | Notes |
|---|---|---|
| `InferenceBackend` trait | `src/inference/mod.rs:80` | `embed` / `chat` / `attested_weights`. |
| `CpuBackend` (shipped) | `src/inference/mod.rs:111` | Wraps `embeddings::Embed` + optional `OllamaClient`. The only backend used on the v0.7.0 hot-path. |
| `GpuBackend` (stub) | `src/inference/mod.rs:170` | Returns `not implemented` (`:188-201`); v0.8 placeholder. |
| Attested weights (#654 MVP) | `src/inference/mod.rs:63` `AttestedWeights`, `:209` `compute_attested_weights`, `:235` `verify_attested_weights` | SHA-256 of on-disk weight file + optional Ed25519 sig; verify refuses to serve a tampered file (`:237-245`). |

> **Drift note:** the inference abstraction is a *seam*, not yet wired
> into recall. Hot-path embedding/chat go through `embeddings::Embedder`
> / `llm::OllamaClient` directly (`src/inference/mod.rs:76-79`).

---

## 11. Transcripts + Retroactive Mining

| Capability | Provenance | Notes |
|---|---|---|
| Transcript storage (zstd) | `src/transcripts/storage.rs`, `src/transcripts/mod.rs` | Sidechain compressed transcript blobs; `TranscriptLink` span offsets. |
| Reflection replay union | `src/transcripts/replay.rs:95` | (see §7.1) |
| `memory_replay` MCP / `replay` CLI | `src/mcp/tools/replay.rs`, `src/cli/commands/replay.rs` | Replays a memory's transcripts. |
| Retroactive import (`mine.rs`) | `src/mine.rs:45` `Format` (`Claude`/`ChatGpt`/`Slack`), `:76` `parse_claude` | Imports conversation exports → `MinedMemory` (`:33`). `MAX_CONTENT_SIZE` cap applied. |

---

## 12. DRIFT / DEFECTS (self-documented in source)

| Item | Provenance | Status |
|---|---|---|
| Reranker G8 | `src/reranker.rs` self-doc | **Closed** — prior `warn!`-only path now surfaces `meta.reranker_used`. |
| HNSW persistence/merge/sharding (§10.4 G2/G3/G4) | `src/hnsw.rs` gap list | **Deferred to v0.9** — in-memory only, rebuilt from embedding column. |
| Inference backend not on hot-path | `src/inference/mod.rs:76-79` | **By design (v0.7.0)** — seam present, GPU backend stubbed (#651 v0.8). |
| `export_reflections` `summary.skipped` unused | `src/cli/commands/export_reflections.rs:132` | **Minor** — computed-but-unused field. |
| `#1438` offload `AttestLevel` orphan | `src/offload/mod.rs:570-578` | **Fixed** — orphan `"signed"` variant replaced with canonical `SelfSigned`/`Unsigned`. |
| `#1264` offload TTL TOCTOU | `src/offload/mod.rs:631-642` | **Fixed** — per-row DELETE re-checks TTL predicate. |
| `#1090` cycle-check fail-open | `src/kg/cycle_check.rs:110-114` | **Fixed** — now fail-CLOSED (propagates SQL error). |
| `#1419` recover fast-path full-scan | `src/recover/mod.rs:312-329` | **Fixed** — indexed `agent_id_idx` VIRTUAL column. |
| `#1036` decay version-bump | `src/confidence/decay.rs:107-129` | **Fixed** — decay write is intentionally non-version-bumping. |

---

## 13. Recursive-Primitive Depth-Cap Discipline (summary)

| Primitive | Cap | Provenance |
|---|---|---|
| Atomisation | `3` | `src/atomisation/mod.rs:261` `MAX_ATOMISATION_DEPTH` |
| Synthesis | `3` | `src/synthesis/mod.rs:559` `MAX_SYNTHESIS_DEPTH` |
| Reflection | `3` | `src/storage/reflect.rs` (`ReflectError::DepthExceeded`) |
| Cycle-check safety bound | `16` | `src/kg/cycle_check.rs:26` `DEFAULT_MAX_DEPTH` (sentinel, not a primitive depth) |
| Recover lines/run | `100` | `src/recover/mod.rs:169` `DEFAULT_RECOVER_LIMIT` |

All three recursive cognition primitives (atomise / synthesise / reflect)
share the depth cap of **3**, enforced via thread-local guards / explicit
depth threading; the `16`-hop cycle-check ceiling and `100`-line recover
limit are independent operational bounds.
