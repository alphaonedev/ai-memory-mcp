# 08 — Core Infra / LLM / Config / Runtime (v0.7.0)

Scope: `src/config.rs`, `src/llm.rs`, `src/encryption/`, `src/tls.rs`,
`src/validate.rs`, `src/replication.rs`, `src/metrics.rs`,
`src/runtime_context.rs`, `src/toon.rs`, `src/sizes.rs`,
`src/daemon_runtime.rs` (config/build-ladder parts only), `src/lib.rs`
(top-level wiring). All file:line refs verified against the
`release/v0.7.0` working tree. `signed_events.rs` / `profile.rs` are
other agents' domains and excluded.

---

## 1. LLM backends

The substrate is **provider-agnostic** post-#1066/#1067. There are exactly
**two wire shapes**, selected by `LlmProvider` (`src/llm.rs:248-261`):

| Wire shape | Endpoints | Auth | Provenance |
|---|---|---|---|
| `LlmProvider::Ollama` | `POST /api/chat`, `POST /api/embed` | none | `src/llm.rs:250-253` |
| `LlmProvider::OpenAiCompatible { api_key }` | `POST /v1/chat/completions`, `POST /v1/embeddings` | `Authorization: Bearer <key>` | `src/llm.rs:254-260` |

There is **no `LlmBackend` enum** (codegraph + grep both confirm absent);
the backend is carried as a lowercase `String` on `ResolvedLlm.backend`,
compared against the single typed constant `BACKEND_OLLAMA = "ollama"`
(`src/llm.rs:190`). The struct is still named `OllamaClient`
(`src/llm.rs:382`); rename to `LlmClient` is documented as non-breaking
and deferred.

### 1.1 Backend aliases (15 OpenAI-compatible + ollama + generic escape-hatch)

Two parallel alias tables drive defaults (intentionally duplicated to
avoid a circular dep — see §DRIFT for the sync risk):

| Alias | Default model (`config.rs:4705`) | Default base URL (`config.rs:4731` / `llm.rs:195`) | API-key env fallback (`config.rs:4757` / `llm.rs:219`) |
|---|---|---|---|
| `ollama` (default) | `gemma3:4b` | `http://localhost:11434` | — (no key) |
| `openai` | `gpt-5` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| `xai` | `grok-4.3` | `https://api.x.ai/v1` | `XAI_API_KEY` |
| `anthropic` | `claude-opus-4.7` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` |
| `gemini` | `gemini-2.0-flash` | `…/v1beta/openai` | `GEMINI_API_KEY`,`GOOGLE_API_KEY` |
| `deepseek` | `deepseek-chat` | `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY` |
| `kimi`/`moonshot` | `moonshot-v1-8k` | `https://api.moonshot.cn/v1` | `MOONSHOT_API_KEY`,`KIMI_API_KEY` |
| `qwen`/`dashscope` | `qwen-max` | `…/compatible-mode/v1` | `DASHSCOPE_API_KEY`,`QWEN_API_KEY` |
| `mistral` | `mistral-large-latest` | `https://api.mistral.ai/v1` | `MISTRAL_API_KEY` |
| `groq` | `llama-3.3-70b-versatile` | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` |
| `together` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | `https://api.together.xyz/v1` | `TOGETHER_API_KEY` |
| `cerebras` | `llama-3.3-70b` | `https://api.cerebras.ai/v1` | `CEREBRAS_API_KEY` |
| `openrouter` | `openai/gpt-5` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` |
| `fireworks` | `accounts/fireworks/models/llama-v3p3-70b-instruct` | `https://api.fireworks.ai/inference/v1` | `FIREWORKS_API_KEY` |
| `lmstudio` | `local-model` | `http://localhost:1234/v1` | — (no key) |
| `openai-compatible` (generic) | `gemma3:4b` (fallthrough) | `http://localhost:11434` (fallthrough — see DRIFT) | — |

**Ollama (native) + OpenAI-compatible (15 aliases + generic) are the
backends supported.** xAI is present as the `xai` alias. OpenRouter is
present (`openrouter`). vLLM and llama.cpp-server are NOT distinct
backends — they are reachable via the generic `openai-compatible` alias.

### 1.2 vLLM — confirmed NOT a shipped backend in v0.7.0

`grep -rn 'vllm\|vLLM\|VLLM' src/` returns **only doc-comment mentions**
inside "…LMStudio, vLLM, llama.cpp server, and any other vendor that
follows the OpenAI chat-completions spec" prose lists
(`src/llm.rs:14,258,387,744`; `src/config.rs:737`) plus three boot-banner
comment references (`src/daemon_runtime.rs:339,1296`, `src/cli/boot.rs:9`).
There is **no `"vllm"` alias** in `default_base_url_for_alias`,
`backend_default_model`, `backend_default_base_url`, or
`alias_api_key_env_vars*`. This matches ROADMAP §11.4.C positioning vLLM
as v0.8. Verdict: **vLLM is correctly absent as a first-class backend.**

### 1.3 Resolution ladder — `build_llm_client` → `resolve_llm`

`build_llm_client(feature_tier, app_config)` (`src/daemon_runtime.rs:2083`)
is the single canonical daemon entry. It calls
`app_config.resolve_llm(None, None, None)` then
`OllamaClient::build_from_resolved_async(&resolved)` (`src/llm.rs:694`).

**No-preset short-circuit** (`daemon_runtime.rs:2106-2118`): when the tier
has no compiled `llm_model` preset (Keyword + Semantic) AND
`resolved.source == ConfigSource::CompiledDefault`, returns `None` (no
client) — matches pre-#1146 v0.6 behaviour and avoids a blocking probe to
absent Ollama under tokio tests.

`resolve_llm` precedence (`src/config.rs:5568-5653`):

| Field | Ladder (highest → lowest) | Source tag |
|---|---|---|
| backend | CLI flag → `AI_MEMORY_LLM_BACKEND` → `[llm].backend` → legacy (`llm_model`/`ollama_url` ⇒ `ollama`) → compiled `ollama` | `config.rs:5586-5598` |
| model | CLI → `AI_MEMORY_LLM_MODEL` → `[llm].model` → legacy `llm_model` → `backend_default_model()` | `config.rs:5601-5616` |
| base_url | CLI → `AI_MEMORY_LLM_BASE_URL` → `[llm].base_url` → legacy `ollama_url` (only if backend==ollama) → `backend_default_base_url()` | `config.rs:5619-5640` |
| api_key | `resolve_api_key()` (separate ladder, §1.4) | `config.rs:5643` |

`ConfigSource` arms: `Cli`, `Env`, `Config`, `Legacy`, `CompiledDefault`.
`ResolvedLlm` carries `backend, model, base_url, api_key, api_key_source,
source`; its `Debug` redacts `api_key` to `<redacted>` and the
`LlmProvider` zeroizes the key on `Drop` (`src/llm.rs:287-303` #1258/#1262).

### 1.4 API-key resolution ladder (`resolve_api_key`, `src/config.rs:4891`)

1. `AI_MEMORY_LLM_API_KEY` → `KeySource::ProcessEnv`
2. Per-vendor alias env (`XAI_API_KEY`, etc.) → `KeySource::AliasFallback`
3. `[llm].api_key_env` → `KeySource::ConfigEnvVar`
4. `[llm].api_key_file` (mode-0400 enforced, `config.rs:4976`) → `KeySource::ConfigFile`
5. none → `KeySource::None` (correct for ollama; error-surfaced for others).

Non-ollama backend with no key ⇒ `build_from_resolved*` returns `Err`
(`src/llm.rs:655-666,712-723`). `[llm].api_key` inline literal is
**rejected at parse time** (`config.rs:3060` field comment + parse guard).

### 1.5 LLM-powered operations (`src/llm.rs`)

| Op | Sync / async fn | Prompt const |
|---|---|---|
| Query expansion (5-8 terms) | `expand_query`/`_async` (`llm.rs:1120,1131`) | `QUERY_EXPANSION_PROMPT` (`llm.rs:321`) |
| Summarize memories | `summarize_memories`/`_async` (`llm.rs:1145,1155`) | `SUMMARIZE_PROMPT` (`llm.rs:325`) |
| Auto-tag (3-5 tags) | `auto_tag`/`_async` (`llm.rs:1180,1195`) | `AUTO_TAG_PROMPT` (`llm.rs:329`) |
| Detect contradiction (yes/no) | `detect_contradiction`/`_async` (`llm.rs:1633,1644`) | `CONTRADICTION_PROMPT` (`llm.rs:334`) |
| Generate (raw) | `generate`/`_async` (`llm.rs:1001,1018`) | — |
| Embed text | `embed_text`/`_async` (`llm.rs:1459,1475`) | — |

`auto_tag` uses the fast `[llm.auto_tag]` sibling resolver
(`resolve_llm_auto_tag`, `config.rs:5664`) defaulting to `gemma3:4b`
(L15 fast-structured-output, ~0.7s p50 vs ~15s thinking-mode).

**Circuit breaker** (`llm.rs:305-379`, F6): `CONNECT_TIMEOUT`=5s,
`HEALTH_TIMEOUT`=5s, `GENERATE_TIMEOUT`=30s, `PULL_TIMEOUT`=120s,
`CIRCUIT_BREAKER_THRESHOLD`=3 failures, `CIRCUIT_BREAKER_COOLDOWN`=30s.
Open breaker fast-fails without issuing the HTTP request.

---

## 2. Embeddings + reranker + tier presets

### 2.1 FeatureTier (`src/config.rs:115-195`)

| Tier | Embedding model | LLM preset | Cross-encoder | max_mem_mb |
|---|---|---|---|---|
| `Keyword` | none (FTS5 only) | none | false | 0 |
| `Semantic` | `MiniLmL6V2` | none | false | 256 |
| `Smart` | `NomicEmbedV15` | `Gemma4E2B` | false | 1024 |
| `Autonomous` | `NomicEmbedV15` | `Gemma4E4B` | **true** | 4096 |

`effective_tier(cli_tier)` (`config.rs:5365`): `cli_tier` → `[tier]` →
default `"semantic"`; unknown strings fall back to `Semantic`
(`config.rs:6616`). `from_memory_budget` auto-selects by MB
(`config.rs:184`). **NB (#1067): tier no longer dictates LLM vendor** —
any tier can speak to any provider via `AI_MEMORY_LLM_BACKEND`; tier still
gates embedder + reranker.

### 2.2 Embeddings resolver (`resolve_embeddings`, `config.rs:5734`)

backend → `[embeddings].backend` else `"ollama"` (**ollama is the only
embedding backend at v0.7.0** — `EmbeddingsSection` doc `config.rs:3119`);
url → `[embeddings].url` → legacy `embed_url`/`ollama_url` → `localhost:11434`;
model → `[embeddings].model` → legacy `embedding_model` →
`canonicalise_embedding_model()` → default `nomic-embed-text-v1.5`;
`backfill_batch` 1..=10000 else 100 (env `AI_MEMORY_EMBED_BACKFILL_BATCH`);
`embedding_dim` from `KNOWN_EMBEDDING_DIMS` (`config.rs:4811`, #1169, 30
entries: nomic 768, MiniLM 384, BGE 384/768/1024, mxbai 1024, OpenAI
1536/3072, Google 768, Snowflake Arctic 384/768/1024).

### 2.3 Reranker resolver (`resolve_reranker`, `config.rs:5805`)

`enabled` ← `[reranker].enabled` → legacy `cross_encoder` → `false`
(boot wires the tier default off `TierConfig.cross_encoder`); `model` ←
`[reranker].model` → default `ms-marco-MiniLM-L-6-v2`
(`RerankerSection` reserves the field for future bake-offs, `config.rs:3158`).
`ResolvedModels` (`config.rs:3429`) bundles llm+embeddings+reranker for
the capabilities surface (`resolve_models`, `config.rs:5850`).

---

## 3. Encryption (at-rest, field-level)

`src/encryption/mod.rs` (#228) — **E2E field-level encryption of memory
`content`**, NOT whole-DB:

| Aspect | Value | Ref |
|---|---|---|
| Scheme | X25519 ECDH + ChaCha20-Poly1305 AEAD | `mod.rs:50-56` |
| Envelope | `0x01` version ‖ 32B ephemeral pub ‖ 12B nonce ‖ ciphertext+16B tag | `mod.rs:18-23,110` |
| Column | `memories.encrypted_envelope` BLOB (schema v44) | `mod.rs:15-16` |
| Keypair cache | per-agent `Keypair`, in-memory only on `RuntimeContext::keypair_cache` (no on-disk persistence yet) | `mod.rs:171-202` |
| Activation gate | `encryption_enabled(config_flag)` — config flag OR `AI_MEMORY_ENCRYPT_AT_REST=1`/`true`/`yes`/`on` | `mod.rs:286` |
| Constants | `PUBKEY_LEN`=32, `NONCE_LEN`=12, `TAG_LEN`=16 | `mod.rs:64-71` |

**Whole-DB at-rest** is separate: the `sqlcipher` cargo feature +
`AI_MEMORY_ENCRYPT_AT_REST` + `encrypt_at_rest: Option<bool>` flat config
field (`config.rs:4638`) gate SQLCipher DB opens
(`src/storage/connection.rs` is the sole `cfg(feature = "sqlcipher")`
consumer). Switching the flag on against a plain DB does NOT encrypt it
(export→encrypted-init→import required).

---

## 4. TLS / mTLS (`src/tls.rs`)

Three layers (`tls.rs:6-42`):

1. **Server TLS** — `load_rustls_config` (PEM cert + PKCS#8/RSA/SEC1 key).
2. **mTLS** — `load_mtls_rustls_config`: demands a client cert, accepts
   only SHA-256 fingerprints on the operator allowlist (HPKP-style pinning,
   no CA dependency). Allowlist parser tolerates blanks/comments/inline
   comments/`:`-separated hex/`sha256:` prefix; rejects embedded whitespace
   (#338/#358).
3. **Client mTLS** — `build_rustls_client_config` (presents client cert,
   accepts any server cert; peer auth runs the other direction).

Protocol floor pinned TLS 1.3 preferred, 1.2 floor; 1.0/1.1 omitted
(`SUPPORTED_PROTOCOL_VERSIONS`, `tls.rs:54`). Loose key-perm warning
(`mode & 0o077`) is WARN-only, never blocks (`tls.rs:69`).

CLI wiring (`src/daemon_runtime.rs`): `--tls-cert`+`--tls-key` (mutual
`requires`, `:671,674`), `--mtls-allowlist` (requires tls-cert, `:685`),
`--quorum-client-cert` (`:713`). mTLS engages when all three present
(`daemon_runtime.rs:3735,3843`).

---

## 5. Config / AppConfig

`AppConfig` struct (`src/config.rs:2530`). Sectioned v2 schema (#1146):
`LlmSection` (`:3018`), `LlmAutoTagSection` (`:3083`), `EmbeddingsSection`
(`:3108`), `RerankerSection` (`:3149`), `StorageSection` (`:3178`).
Capabilities envelope `schema_version` = `"3"` (`config.rs:1733`);
config-file `schema_version` = `"2"` (`config.rs:267`). Legacy flat
fields (`llm_model`, `ollama_url`, `embed_url`, `embedding_model`,
`cross_encoder`, `default_namespace`, `archive_on_gc`, `archive_max_days`,
`max_memory_mb`, `auto_tag_model`) feed the resolvers' `Legacy` arm with a
`Once`-gated deprecation WARN; removal scheduled v0.8.0.

Universal precedence: `CLI flag > AI_MEMORY_* env > config.toml section >
legacy flat > compiled default` (resolvers are pure; file reads in
`resolve_api_key` only). `AI_MEMORY_NO_CONFIG=1` skips loading
`~/.config/ai-memory/config.toml` (env-var table row #4). `effective_*`
accessors: `effective_tier` (`:5365`), `effective_ollama_url` (`:5395`),
`effective_permissions_mode` (`:5323`), `effective_transcripts` (`:5508`).
`config migrate` rewrites legacy→v2 (idempotent, `.bak.<ts>` backup);
`ai-memory doctor` emits an "LLM Reachability (#1146)" probe section
(`src/cli/doctor.rs:866`).

---

## 6. Validation (`src/validate.rs`)

Post-#966 routes DTO validation through `RequestValidator`. Hard limits:

| Limit | Value | Ref |
|---|---|---|
| `MAX_CONTENT_SIZE` | 65 536 bytes | `src/models/mod.rs:29` (`validate.rs:155`) |
| `MAX_TITLE_LEN` | 512 | `validate.rs:11` |
| `MAX_NAMESPACE_LEN` | 512 | `validate.rs:15` |
| `MAX_SOURCE_LEN` | 64 | `validate.rs:16` |
| `MAX_TAG_LEN` / `MAX_TAGS_COUNT` | 128 / 50 | `validate.rs:17-18` |
| `MAX_RELATION_LEN` | 64 | `validate.rs:19` |
| `MAX_ID_LEN` / `MAX_AGENT_ID_LEN` | 128 / 128 | `validate.rs:20-21` |
| `MAX_METADATA_SIZE` / `MAX_METADATA_DEPTH` | 65 536 / 32 | `validate.rs:22-23` |
| `MAX_AGENT_TYPE_LEN` | 64 | `validate.rs:463` |
| `MAX_CITATIONS_PER_MEMORY` / `MAX_SOURCE_URI_LEN` | 64 / 4 096 | `validate.rs:680,684` |

Typed `ValidationError { field, reason }` carries field attribution while
preserving byte-equal legacy wire messages.

---

## 7. Metrics (Prometheus, `src/metrics.rs`)

Lazy process-global `registry()` (`metrics.rs:211`); `render()` emits the
text exposition (`metrics.rs:564`) served at bare `/metrics`. The
`Metrics` struct (`metrics.rs:111-208`) registers: `store_total`,
`recall_total`, `recall_latency_seconds`, `autonomy_hook_total`,
`contradiction_detected_total`, `webhook_dispatched_total`,
`webhook_failed_total`, `memories_gauge`, `hnsw_size_gauge`,
`subscriptions_active_gauge`, `curator_cycles_total`,
`curator_operations_total`, `curator_cycle_duration_seconds`,
`federation_fanout_dropped_total`, `federation_fanout_retry_total`,
`federation_partial_quorum_total`, `corrupt_provenance_rows_total`,
`auto_export_spawn_failed_total`, **`federation_push_dlq_depth`**
(`IntGauge` `ai_memory_federation_push_dlq_depth`, `metrics.rs:166,419`,
Track D #933 — `federation_push_dlq` rows WHERE `replayed_at IS NULL`),
`federation_push_dlq_quarantined` (#1032), `hnsw_evictions_total`,
`hnsw_last_eviction_at_nanos`, `subscription_dlq_overflow_total` (#1253).
`replication.rs` declares `replication_quorum_ack_total{result}`,
`replication_quorum_failures_total{reason}`,
`replication_clock_skew_seconds` (`replication.rs` header).

---

## 8. Replication (`src/replication.rs`)

W-of-N quorum-write scaffold (v0.7 track C, ADR-0001). Ships
`QuorumPolicy` (N/W/timeouts), `QuorumWriter::commit` (local + W-1 remote
acks within deadline else `QuorumError::QuorumNotMet`), `AckTracker`.
**Explicitly NOT wired into the `memory_store` path** — header states wiring
is a follow-up PR; deployments without `--quorum-writes` keep v0.6 one-way
push byte-for-byte. (See §DRIFT — advertised-but-unwired.)

---

## 9. Runtime context (`src/runtime_context.rs`)

`RuntimeContext` (`:62`) replaces a swarm of per-static `OnceLock`s with
one `OnceLock<Arc<RuntimeContext>>` (`GLOBAL`, `:185`) reachable via
`global()` / `global_arc()` (`:217,233`). Holds: `hooks_hmac_secret`
(`RwLock`), `max_decompressed_bytes`, `audit: Arc<AuditState>`,
`recall_tracker`, and `keypair_cache: Arc<Mutex<HashMap<String,
Keypair>>>` (the encryption keypair cache, §3). `AuditState` carries
`sink: RwLock<Option<Arc<AuditSink>>>` + `sequence: AtomicU64`.

---

## 10. TOON serialization (`src/toon.rs`)

TOON (Token-Oriented Object Notation) — token-efficient JSON alternative
claiming 40-60% smaller for arrays of objects (field names declared once
as header, pipe-delimited rows) (`toon.rs:4-10`).

`src/sizes.rs` — tool-payload token accounting: `tool_sizes()`,
`trimmed_tool_sizes()`, `tool_sizes_under_ci_gate()`,
`full_profile_total_tokens()`, `trimmed_full_profile_total_tokens()`,
`tool_size(name)` (`sizes.rs:72-123`) backing the C5 token-budget gate.

---

## 11. Cargo features (`Cargo.toml [features]`)

| Feature | Gates | Default? |
|---|---|---|
| `default` | `["sqlite-bundled"]` | yes |
| `sqlite-bundled` | `rusqlite/bundled` | yes |
| `sqlcipher` | `rusqlite/bundled-sqlcipher-vendored-openssl` (whole-DB at-rest encryption; sole consumer `src/storage/connection.rs`) | no |
| `sal` | `dep:async-trait`,`dep:bitflags`,`dep:thiserror` — SAL trait + `SqliteStore`; unlocks CLI `Migrate`+`SchemaInit` (`daemon_runtime.rs:315,326`) | no |
| `sal-postgres` | `["sal", "dep:sqlx", "dep:pgvector"]` — Postgres/pgvector backend (implies `sal`) | no |
| `test-with-models` | tests pulling large model weights (BERT/MiniLM) | no |
| `e2e` | gated live-agent smoke tests (#487) | no |

CLI subcommand SSOT: `EXPECTED_CLI_SUBCOMMANDS_DEFAULT = 79`,
`EXPECTED_CLI_SUBCOMMANDS_SAL = 81` (`src/lib.rs:257,264`). Dead-flag
invariant enforced by `tests/feature_flag_audit_arch_11.rs` (every flag
must have a `cfg(feature=…)` consumer). `lib.rs` time consts:
`SECS_PER_MINUTE/HOUR/DAY/WEEK` (`:29-32`); `DEFAULT_NAMESPACE = "global"`
(`:335`).

---

## DRIFT / DEFECTS SPOTTED

1. **Encryption config-field name drift (docstring vs reality).**
   `src/encryption/mod.rs:42` documents activation via the
   `[encryption].at_rest = true` config field, but **no `EncryptionSection`
   / `[encryption]` TOML table exists**. The real config field is the FLAT
   top-level `encrypt_at_rest: Option<bool>` (`src/config.rs:4638`). The
   `encryption_enabled(config_flag)` gate (`mod.rs:286`) takes an
   `Option<bool>` so it works, but the docstring names a non-existent
   sectioned key. Operator-facing prose drift — fix the docstring to
   `encrypt_at_rest`.

2. **Generic `openai-compatible` alias has no meaningful default base URL.**
   `backend_default_base_url("openai-compatible")` falls through to the
   `_ =>` arm returning `http://localhost:11434` (the Ollama URL)
   (`config.rs:4747-4748`), and `backend_default_model` falls through to
   `gemma3:4b` (`config.rs:4721-4722`). The doc/comment at `config.rs:4728`
   claims `openai-compatible` "returns the empty string" for base URL —
   it does NOT; it returns the localhost-Ollama URL. The env-var table row
   #32 correctly states a base URL is REQUIRED for this alias, but a
   misconfigured operator gets a silently-wrong localhost default rather
   than an empty-string-triggered error. Comment drift + a mild footgun;
   the `ai-memory doctor` reachability probe is the catch.

3. **Duplicated alias tables (sync hazard).** `alias_api_key_env_vars`
   (`llm.rs:219`) and `alias_api_key_env_vars_for_resolver`
   (`config.rs:4757`) are byte-identical and intentionally duplicated to
   avoid a circular dep (`config.rs:4752-4756`). The resolver table also
   omits the `lmstudio` no-key case that `default_base_url_for_alias`
   handles. Pinned-by-test per the comment, but the two lists drifting is
   a latent risk; not a live defect.

4. **`replication.rs` quorum layer advertised but NOT wired.** The module
   header explicitly states quorum-write commit is NOT wired into the
   `memory_store` path at v0.7.0 ("follow-up PR once the sync-daemon gains
   a synchronous ack channel"). `QuorumWriter::commit` is reachable as a
   library primitive but no production write path drives it. This is
   honestly documented (not a hidden defect) but means the
   `replication_quorum_*` metrics will read zero in production.

5. **`Metrics` struct carries `#[allow(dead_code)]`** (`metrics.rs:110`):
   several gauges/counters are registered + appear in `/metrics` output but
   are not yet `.inc()`/`.set()` from any caller (acknowledged in the
   comment — "instrumented as sibling features land"). Wire-honest (they
   render) but several are inert at v0.7.0.

6. **No backend enum (naming legacy).** The provider abstraction is a
   bare lowercase `String` compared to `BACKEND_OLLAMA` rather than a typed
   `enum`; the only typed split is `LlmProvider {Ollama, OpenAiCompatible}`.
   The struct is still `OllamaClient` despite being provider-agnostic.
   Documented as a deliberate non-breaking-rename deferral, not a defect.

7. **vLLM — NO drift.** vLLM is referenced only in "any OpenAI-spec vendor"
   prose lists and is correctly NOT a shipped alias/backend. No accidental
   "shipped" claim found.
