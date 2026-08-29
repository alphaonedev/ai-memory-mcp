# `ai-memory` configuration schema reference

This is the canonical reference for the v0.7.x schema-versioned
sectioned configuration format introduced in
[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146).
Every deployment of `ai-memory` (MCP server, HTTP daemon, CLI) reads
configuration from a single file at `~/.config/ai-memory/config.toml`.

> **No GPU required.** Nothing in this schema is hard-wired to a GPU,
> to Ollama, or to Gemma — those are the local-first default, not a
> requirement. Post-[#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067)
> + #1146 the autonomous tier drives every feature through **any
> OpenAI-compatible endpoint**: a remote cloud API (e.g. OpenRouter as
> a low-cost example) *where you have API access*, or an internal
> air-gapped HA inference VIP *where you have systems with no GPUs* and
> want to run ai-memory in autonomous mode with `--profile full`. Set
> `[llm].backend` to a cloud/`openai-compatible` value and the daemon
> host carries no model weight at all (only the ~90 MB CPU
> cross-encoder if `[reranker].enabled = true`). The model names below
> are examples — substitute whatever your provider or endpoint serves.

## Quick reference

```toml
schema_version = 2

# Top-level operational settings.
tier = "autonomous"
db   = "/Users/fate/.claude/ai-memory.db"

# ---------------------------------------------------------------------
# [llm] — chat-completion LLM configuration.
# ---------------------------------------------------------------------
[llm]
backend     = "xai"           # ollama | openai | xai | anthropic | gemini |
                              # deepseek | kimi | qwen | mistral | groq |
                              # together | cerebras | openrouter |
                              # fireworks | lmstudio | vllm | openai-compatible
model       = "grok-4.3"      # vendor-specific identifier
base_url    = "https://api.x.ai/v1"   # optional; vendor-default if unset

# Exactly one of api_key_env / api_key_file (or neither — falls back to
# the per-vendor env-var chain). Inline `api_key = "<literal>"` is
# REJECTED at parse time.
api_key_env = "XAI_API_KEY"
# api_key_file = "/etc/ai-memory/keys/xai.key"   # mode 0400 enforced

# Fast structured-output sibling (auto_tag, query expansion,
# contradiction detection). Field-by-field fallback to parent [llm];
# commonly only `model` is overridden.
[llm.auto_tag]
backend = "ollama"
model   = "gemma3:4b"

# ---------------------------------------------------------------------
# [embeddings] — embedding-model configuration.
#
# #1598 — fully API-capable: `backend` accepts the same vendor-alias
# vocabulary as [llm].backend — `ollama` (the default; native
# /api/embed wire shape), any #1067 alias (`openrouter`, `openai`,
# `gemini`, `xai`, `mistral`, …), or the generic `openai-compatible`
# escape hatch for self-hosted OpenAI-compatible /v1/embeddings
# endpoints (HuggingFace text-embeddings-inference, vLLM, llama.cpp
# server). Per-field precedence:
#   AI_MEMORY_EMBED_* env > [embeddings] section > legacy flat fields
#   (embed_url / embedding_model / ollama_url) > compiled default.
# ---------------------------------------------------------------------
[embeddings]
backend        = "ollama"
url            = "http://localhost:11434"  # synonym of base_url; base_url
                                           # wins when both are set
# base_url     = "https://openrouter.ai/api/v1"  # API backends; vendor
                                           # default when omitted for a
                                           # named alias
model          = "nomic-embed-text-v1.5"   # e.g. "google/gemini-embedding-2"
                                           # (3072-dim) on openrouter

# Exactly one of api_key_env / api_key_file for API backends (or
# neither — falls back to the per-vendor env-var chain, highest
# precedence AI_MEMORY_EMBED_API_KEY). Inline `api_key = "<literal>"`
# is REJECTED at parse time, same as [llm].api_key.
# api_key_env  = "OPENROUTER_API_KEY"
# api_key_file = "/etc/ai-memory/keys/embed.key"  # mode 0400 enforced

# dim          = 768             # env override: AI_MEMORY_EMBED_DIM (#2626 —
#                                 # env BEATS this field; a non-positive /
#                                 # unparseable env value FAILS CLOSED to an
#                                 # UNKNOWN dim rather than falling through to
#                                 # the compiled table, which would resolve the
#                                 # exact width the operator was overriding).
#                                 # Explicit vector-dim override for models
#                                 # not in KNOWN_EMBEDDING_DIMS. #1598 fleet
#                                 # follow-up: for OpenAI-compatible backends an
#                                 # EXPLICIT dim is also sent as the wire
#                                 # `dimensions` request param — Matryoshka-capable
#                                 # models (gemini-embedding-2, text-embedding-3-*)
#                                 # truncate server-side. Use dim = 768 on
#                                 # pgvector-backed federated fleets: pgvector ANN
#                                 # indexes cap at 2000 dims and the fleet schemas
#                                 # template vector(768).
backfill_batch = 100             # env override: AI_MEMORY_EMBED_BACKFILL_BATCH

# ---------------------------------------------------------------------
# [reranker] — cross-encoder rerank configuration.
# ---------------------------------------------------------------------
[reranker]
enabled = true
model   = "ms-marco-MiniLM-L-6-v2"
max_seq_tokens = 256             # rerank input-sequence cap (#1604).
                                 # Compiled default 256; admissible
                                 # range 1..=512 (the model ceiling) —
                                 # zero / out-of-range values fall
                                 # through. Env override:
                                 # AI_MEMORY_RERANK_MAX_SEQ (env > this
                                 # field > compiled default).

# ---------------------------------------------------------------------
# [storage] — storage configuration.
# ---------------------------------------------------------------------
[storage]
default_namespace = "alphaone"
archive_on_gc     = true
archive_max_days  = 90
max_memory_mb     = 4096
db_mmap_size_bytes = 268435456  # sqlite PRAGMA mmap_size (#1579 B7).
                                # 256 MiB compiled default; 0 disables
                                # memory-mapped I/O. Env override:
                                # AI_MEMORY_DB_MMAP_SIZE (env > this
                                # field > compiled default).

# ---------------------------------------------------------------------
# [limits] — operator-tunable resource caps (#1156 follow-up; #1733
# added max_inflight_requests at v0.8.0, #2032 M3 made it default-ON).
# Precedence per field:
#   AI_MEMORY_MAX_* env > [limits] section > compiled default.
# Absent / non-positive / unparseable values fall through to the compiled
# default — EXCEPT max_inflight_requests, whose tri-state resolver has no
# `> 0` filter and honours an explicit 0 as DISABLED.
# ---------------------------------------------------------------------
[limits]
max_memories_per_day = 1000        # per-agent daily memory-write quota
max_storage_bytes    = 104857600   # per-agent storage cap (bytes; 100 MiB)
max_links_per_day    = 5000        # per-agent daily link-write quota
max_page_size        = 1000        # list/bulk/sync page-size cap (OOM guard)
# max_inflight_requests            # #1733 HTTP admission cap, TRI-STATE since
                                   # #2032 M3 — LEAVE UNSET for the secure
                                   # default. UNSET = ON, CPU-scaled to
                                   # clamp(cores*64, 256, 4096). Positive n =
                                   # that exact cap (sheds >n concurrent
                                   # in-flight requests with a typed 503).
                                   # An EXPLICIT 0 = DISABLED. Do not paste
                                   # `= 0` here: it turns the DoS admission
                                   # guard OFF, it is not "the default".
                                   # Env: AI_MEMORY_MAX_INFLIGHT_REQUESTS.
vector_index_capacity = 100000     # #1005 G2 in-memory vector-index residency
                                   # cap (entries); default = compiled 100k.
                                   # Env: AI_MEMORY_VECTOR_INDEX_CAPACITY.
vector_index_hard_fail_at_cap = false  # #1005 G2 opt-in: reject inserts AT cap
                                   # (ERROR log) instead of evicting oldest.
                                   # Env: AI_MEMORY_VECTOR_INDEX_HARD_FAIL.

# ---------------------------------------------------------------------
# Existing sections at v0.7.x — see env-var table in CLAUDE.md.
# ---------------------------------------------------------------------
[mcp]
profile = "full"

[permissions]
mode = "enforce"
```

## Substrate component versions (Enterprise Federated)

The postgres-backed Enterprise Federated substrate pins an exact,
tested component matrix. These versions are the **single source of
truth** in
[`deploy/docker-1461/provision/lib.sh`](../deploy/docker-1461/provision/lib.sh)
and are asserted at bring-up by the validate harness (the daemon refuses
to certify a stack whose probed versions drift from the pins below).

| Component | Canonical version | SSOT pin (`deploy/docker-1461/provision/lib.sh`) |
|---|---|---|
| PostgreSQL | **18.6** | `PG_APT_VERSION=18.6-1.pgdg13+2`, `EXPECTED_PG_VERSION=18.6` |
| Apache AGE | **1.8.0** | `AGE_APT_VERSION=1.8.0~rc0-2.pgdg13+1` (overlaid via pgdg apt on base `AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0`; `CREATE EXTENSION age` reports extversion 1.8.0), `EXPECTED_AGE_VERSION=1.8.0` |
| pgvector (server extension) | **0.8.6** | `PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1` |
| pgvector (Rust binding crate) | **0.4** | `Cargo.toml` → `pgvector = "0.4"` |
| ai-memory postgres schema | **v91** | postgres ladder pinned in lockstep with SQLite `CURRENT_SCHEMA_VERSION = 91` (`src/storage/migrations.rs`). NOTE: the `deploy/docker-1461` / `deploy/do-1461` provisioning configs are reproducibility anchors **pinned to the v0.7.0 release** (`EXPECTED_VERSION=0.7.0`, `EXPECTED_SCHEMA=57`, golden SHA), so their `57` is correct *for that pinned release* — it is not a stale copy of the current tip (`CURRENT_SCHEMA_VERSION = 91`). A deployment-validation anchor at the current schema would be a separate config. |

The bundled stacked image at
[`deploy/docker-1461/Dockerfile.pg-age-vector`](../deploy/docker-1461/Dockerfile.pg-age-vector)
(`ARG AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0`, `ARG PG_MAJOR=18`)
layers pgvector 0.8.6 onto the AGE base so K8s / ECS / Cloud Run
operators do not build AGE from source. See
[`postgres-age-guide.md`](postgres-age-guide.md) for the from-source
install recipe and the Docker layering rationale (#1065).

> **Alternate tested matrix.** `infra/lan-parity-test/` and the
> lan-parity compose harness legitimately run **PG 16 + AGE 1.6.0 +
> pgvector 0.8.2** as a second tested combination. Those references are
> factual (not drift); the *recommended* Enterprise Federated install
> targets the PG 18.6 / AGE 1.8.0 matrix above.

## Enterprise & operational sections

Beyond the four #1146 sectioned blocks (`[llm]` / `[embeddings]` /
`[reranker]` / `[storage]`) and `[limits]` shown in the Quick reference,
`AppConfig` (`src/config.rs`) parses the following operator-facing
sections. Each is **default-safe** — absent blocks select the compiled
default and preserve the pre-existing behaviour. Field names are given as
the SSOT struct declares them.

> **Coverage caveat (v1.0.0 lane-1 config sweep).** This page is not yet
> an exhaustive enumeration, and until v1.0.0 it claimed to be ("Fields
> are listed exactly as the SSOT struct declares them"). Sections that
> `AppConfig` resolves but this page does not define below — while the
> shipped `docs/deploy/config.asi-hard.toml` template sets several of
> them — include at least: `[security].secret_screen_mode` (compiled
> default `refuse`), `[capabilities].enabled` (compiled default **`true`**
> since R9 #1960) + `[capabilities.issuers]`, `[hooks].enforce_mode` +
> `[hooks].required_events` (#1734 PE-1; the `[hooks]` section below
> documents only `hooks.subscription.hmac_secret`), the `[curator]`
> fields (`transcript_classify_enabled`, `[curator.compaction]`
> `enabled` / `cosine_threshold`), `[logging]` (incl. `sink`,
> `syslog_address`, `syslog_transport`, `syslog_tls_ca_file`),
> `[reranker].score_floor`, and the `[storage]` data-integrity switches
> `append_only` / `lineage_dag` / `consolidate_tombstone_sources` /
> `age_projection_mode`. Every one of them IS documented per-knob in the
> CLAUDE.md environment-variable table (each names its `[section].field`
> twin); treat that table as the exhaustive index until these sections
> land here.

### Top-level operational fields

```toml
schema_version = 2          # None/1 = legacy flat parse; >=2 = sectioned parse

# Postgres connection-pool + query bounds (resolved by AppConfig::resolve_pg_pool).
postgres_pool_max_connections   = 16    # env: AI_MEMORY_PG_POOL_MAX
postgres_pool_min_connections   = 2     # env: AI_MEMORY_PG_POOL_MIN
postgres_acquire_timeout_secs   = 30    # env: AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS
postgres_statement_timeout_secs = 30    # after_connect SET statement_timeout; 0 = disable

# Per-request / per-LLM-call wall-clock timeouts (DoS bounds).
request_timeout_secs  = 60    # axum middleware ceiling (slowloris guard)
llm_call_timeout_secs = 30    # wraps every spawn_blocking LLM call in tokio timeout

# MCP-stdio → HTTP daemon write forwarder (federation fanout).
mcp_federation_forward_url = "http://localhost:9077"
```

| Field | Type | Default | Purpose |
|---|---|---|---|
| `schema_version` | `u32?` | `1` (legacy) | `>= 2` selects the sectioned parse path; warns if legacy flat fields coexist. |
| `postgres_pool_max_connections` | `u32?` | `DEFAULT_MAX_CONNECTIONS` | sqlx `max_connections`; non-positive falls through to default. |
| `postgres_pool_min_connections` | `u32?` | `DEFAULT_MIN_CONNECTIONS` | sqlx `min_connections` (warm floor). |
| `postgres_acquire_timeout_secs` | `u64?` | derived from `DEFAULT_ACQUIRE_TIMEOUT` | sqlx `acquire_timeout`, whole seconds. |
| `postgres_statement_timeout_secs` | `u64?` | `30` | per-connection `statement_timeout`; `0` disables. |
| `request_timeout_secs` | `u64?` | `60` | per-HTTP-request wall-clock cap (H7). |
| `llm_call_timeout_secs` | `u64?` | `30` | per-LLM-call timeout; on timeout falls back to the LLM-absent path (H8). |
| `mcp_federation_forward_url` | `String?` | unset (direct SQLite) | when set, MCP-stdio write tools POST to this daemon so federation fanout runs (#318). |

### `[identity]` — identity-resolution fallback (#198)

```toml
[identity]
anonymize_default = false   # true → anonymous:pid-<pid>-<uuid8> instead of host:<hostname>:...
```

`anonymize_default = true` swaps the hostname-revealing default
`agent_id` fallback for `anonymous:pid-<pid>-<uuid8>` (the persistent
equivalent of `AI_MEMORY_ANONYMIZE=1`).

### `[audit]` — tamper-evident audit trail (#487)

Default-OFF. When enabled, emits a hash-chained, append-only JSON audit
log suitable for SIEM ingestion and SOC2 / HIPAA / GDPR / FedRAMP
evidence. See [`security/audit-trail.md`](security/audit-trail.md).

```toml
[audit]
enabled                     = true
path                        = "~/.local/state/ai-memory/audit/"   # dir or file
schema_version              = 1       # reserved; must equal the binary's emitted version
redact_content              = true    # v1 only supports true (no content field on the wire)
hash_chain                  = true    # per-line hash chain (load-bearing tamper evidence)
attestation_cadence_minutes = 60      # periodic CHECKPOINT.sig marker; 0 disables
append_only                 = true    # best-effort platform append-only file flag
retention_days              = 90      # purge/verify horizon; compliance presets override

  [audit.compliance]
  # Industry presets layered on top of the base config. The strictest
  # (longest retention / most-frequent attestation) applied preset wins.
  [audit.compliance.soc2]
  applied                     = true
  retention_days              = 365
  [audit.compliance.hipaa]
  applied                     = false
  retention_days              = 2190    # 6 years
  # encrypt_at_rest is an ENFORCEMENT-GATED CLAIM, not a switch (see below).
  # encrypt_at_rest           = true
  [audit.compliance.gdpr]
  applied                     = false
  # pseudonymize_actors is RESERVED / NOT IMPLEMENTED at v1.0.0 (see below).
  # pseudonymize_actors       = true
  [audit.compliance.fedramp]
  applied                     = false
  attestation_cadence_minutes = 15
```

Each `[audit.compliance.<preset>]` table is a `CompliancePreset`:
`applied` / `retention_days` / `redact_content` /
`attestation_cadence_minutes` / `encrypt_at_rest` /
`pseudonymize_actors`. `AuditConfig::effective_retention_days()` and
`effective_attestation_cadence_minutes()` resolve the strictest active
policy.

**`encrypt_at_rest` and `pseudonymize_actors` are enforcement-gated
claims — the preset does NOT turn them on (#2401).** Setting either
`true` on an `applied` preset does not, by itself, make the daemon
perform the control:

- `encrypt_at_rest = true` records the *intent* to encrypt memory
  content at rest, but at-rest content encryption is only ACTIVE when
  the binary is built with `--features sqlcipher` **and**
  `AI_MEMORY_ENCRYPT_AT_REST=1` is set (env #37). Absent that gate,
  memory content is persisted in PLAINTEXT.
- `pseudonymize_actors = true` is **RESERVED and has no consumer at
  v1.0.0** — audit actor ids are recorded verbatim regardless of this
  flag. It is **retired from the shipped presets**; do not set it, and
  do not rely on it for compliance until a future release implements it.

To keep the substrate from advertising a control it does not perform,
an `applied` preset that sets `encrypt_at_rest = true` while the real
gate is inactive, or that sets `pseudonymize_actors = true` at all
(unsatisfiable at v1.0.0), **REFUSES to boot** — a hard boot ERROR
(non-zero exit; `tracing` target `compliance.unenforced`) naming the
preset, the unenforced field, what the daemon does NOT do, and the
remediation. It does not boot while silently failing to perform a
claimed compliance control. This is the operator cutline ruling
(2026-08-01, §1-condition-2: a compliance defaults-lie is a hard boot
ERROR); a compliance surface must fail closed, not serve while lying.
Only `retention_days` and `attestation_cadence_minutes` are actually
consumed by the preset resolver today.

### `[transcripts]` — transcript lifecycle sweeper (I3)

```toml
[transcripts]
default_ttl_secs       = 2592000     # 30d archive-eligibility; None → DEFAULT_TRANSCRIPT_TTL_SECS
archive_grace_secs     = 604800      # 7d linger before prune; None → DEFAULT_..._ARCHIVE_GRACE_SECS
max_decompressed_bytes = 16777216    # 16 MiB decompression-bomb cap (per fetch call)

  # Per-namespace overrides. Literal match first; trailing "/*" = subtree; "*" = catch-all (last).
  [transcripts.namespaces."projects/atlas"]
  default_ttl_secs   = 7776000       # 90d for this namespace
  archive_grace_secs = 1209600       # 14d
  auto_extract       = true          # opt into the R5 pre_store transcript-extractor hook
```

### `[hooks]` — outgoing-webhook signing (K7)

```toml
[hooks]
  [hooks.subscription]
  hmac_secret = "..."   # server-wide HMAC override; signs every webhook payload
```

`hmac_secret` is a secret: it is `skip_serializing`, redacted to
`<redacted>` in `Debug`, and zeroized on drop. Keep the config file
`chmod 600`. When unset, only per-subscription secrets apply.

### `[subscriptions]` — webhook SSRF guard (H11, #628)

```toml
[subscriptions]
allow_loopback_webhooks = false   # default false closes an authenticated SSRF gadget
```

Default-OFF rejects webhook URLs resolving to `127.0.0.0/8` /
`localhost` / `::1` (which are reachable from the daemon and would
expose locally-bound services such as Postgres on 5432). Set `true`
only for CI / dev.

### `[verify]` — link-verification replay protection (H5)

```toml
[verify]
require_nonce = false   # true → every POST /api/v1/links/verify must carry verification_nonce
```

When `true`, missing nonces → 400; replayed `(link_id, signature,
nonce)` tuples → 409 Conflict. Default-OFF preserves v0.6.x
verify-anytime semantics.

### `[agents]` — session-default recall scope (#518)

```toml
[agents]
  [agents.defaults]
    [agents.defaults.recall_scope]
    namespaces = ["projects/atlas"]   # default namespace filter (first applied today)
    since      = "24h"                # duration → since = now() - 24h
    tier       = "long"              # "short" / "mid" / "long"
    limit      = 50                  # default cap (still clamped to per-tool max 50)
```

Splices defaults into recall requests that pass `session_default=true`
and omit a field. Resolution: **explicit request args > recall_scope
defaults > compiled defaults** — the splice never overrides an explicit
filter.

### `[governance]` — fail-closed rule enforcement (SEC-2, #767)

```toml
[governance]
require_operator_pubkey = false   # true → refuse boot if enabled rules exist but no operator pubkey
```

When `true`, daemon `serve` refuses to start if `governance_rules`
contains any `enabled = 1` row AND no operator pubkey is resolved (env
`AI_MEMORY_OPERATOR_PUBKEY` or `~/.config/ai-memory/operator.key.pub`),
closing the fail-OPEN gap where a SQL-write gadget could install
unsigned enabled rules.

### `[confidence]` — shadow-observation retention (Cluster G, #767)

```toml
[confidence]
shadow_retention_days = 30   # GC purge window; None → 30; 0/negative → sweep is a no-op
```

### `[admin]` — admin-class caller allowlist (SHIP cluster, #946/#957/#960/#961)

```toml
[admin]
agent_ids = ["ops:admin", "ai:claude@workstation"]
```

**Default-closed.** When absent, every admin-class endpoint
(`GET /api/v1/export`, `GET /api/v1/agents`, `GET /api/v1/stats`, the
`POST /api/v1/quota/status` list path) returns `403 Forbidden`. Entries
must match a caller's resolved `agent_id` verbatim (no glob); entries
failing `validate_agent_id` are logged at `warn` and dropped so a typo
cannot lock the operator out. The role gate runs **after**
`api_key_auth` — set `api_key` too for sensitive corpora.

## Canonical resolver

Every LLM / embedder / reranker / storage decision in the binary
consumes the corresponding `Resolved*` struct produced by these
methods:

- `AppConfig::resolve_llm(cli_backend, cli_model, cli_base_url)`
- `AppConfig::resolve_llm_auto_tag()`
- `AppConfig::resolve_embeddings()` — #1598: full per-field ladder
  (`AI_MEMORY_EMBED_*` env > `[embeddings]` section > legacy flat
  `embed_url`/`embedding_model`/`ollama_url` > compiled default), embed
  API key via `AI_MEMORY_EMBED_API_KEY` > per-vendor alias env >
  `api_key_env` > `api_key_file` (0400), vector dim via
  `[embeddings].dim` override > `KNOWN_EMBEDDING_DIMS` table. Consumed
  by the MCP stdio init, daemon `build_embedder`, `ai-memory doctor`
  ("Embeddings Reachability (#1598)" section), and `ai-memory reembed`.
- `AppConfig::resolve_reranker()`
- `AppConfig::resolve_storage()`
- `AppConfig::resolve_limits()` — resource caps; produces `ResolvedLimits`
  (`max_memories_per_day` / `max_storage_bytes` / `max_links_per_day`
  as `i64`, `max_page_size` and the #1733 `max_inflight_requests` as
  `usize`). The three quota fields seed the
  process-wide `crate::quotas::QuotaDefaults` OnceLock once at boot (the
  `agent_quotas`-row SQL binds have no `AppConfig` in scope);
  `max_page_size` lands on `AppState.max_page_size`, read by every Axum
  handler via `State(app)`. Precedence ladder for this section is
  `AI_MEMORY_MAX_* env > [limits] > compiled default` (no CLI flag, no
  legacy flat field). Non-positive / unparseable values are filtered so
  a stray `0` `max_page_size` cannot clamp every list response to empty —
  **except `max_inflight_requests`**, which is resolved by
  `env_tristate_usize` (no `> 0` filter) precisely so an explicit `0` can
  mean "operator disabled admission control", distinct from unset. Do not
  read the filtering sentence as covering that knob.

**Uniform precedence ladder** (CLI > env > config > legacy > compiled):

```
CLI flag  >  AI_MEMORY_LLM_* env  >  [llm] section  >  legacy flat fields  >  compiled default
```

**The ONE documented inversion — the store-URL channel (#1927 / CWE-214).**
`AppConfig::resolve_store_url` (`src/store_url.rs`) deliberately
INVERTS the ladder above: `AI_MEMORY_STORE_URL_FILE` (env #158) >
`AI_MEMORY_STORE_URL` (env #157) > the `--store-url` CLI flag. Here
**env beats flag** — the reverse of every other knob. This is
intentional: argv is world-readable via `/proc/<pid>/cmdline` and
`ps auxww`, so the leakier channel (`--store-url`, which can carry a
Postgres DSN password) must NOT be able to override the safer ones
(the owner-only env block, or a `0600` file). `--store-url` carries no
`#[arg(env = …)]`, so clap does not merge the flag and the env into one
slot; passing a password-bearing `--store-url` while an env channel is
set logs a WARN naming both. Source:
`src/store_url.rs::{STORE_URL_FILE_ENV, STORE_URL_ENV, resolve_store_url}`.

Resolvers are pure (no network I/O). File reads for `api_key_file`
happen at resolve time; permission-bit enforcement is non-fatal and
surfaces via `KeySource::Error(reason)` so the daemon can boot and
report the problem through `ai-memory doctor` rather than failing
at load time.

The `Resolved*` structs carry provenance tags:

- `ConfigSource` — which layer of the precedence ladder won
  (`Cli` / `Env` / `Config` / `Legacy` / `CompiledDefault`).
- `KeySource` — where the resolved API key came from
  (`ProcessEnv` / `AliasFallback(name)` / `ConfigEnvVar(name)` /
  `ConfigFile(path)` / `None` / `Error(reason)`).

The `ResolvedLlm::Debug` impl redacts the resolved `api_key` to
`<redacted>` so accidental `{:?}` prints never leak credentials.

## Secret handling discipline

`[llm].api_key = "<literal>"` is **REJECTED at parse time** with a
clear stderr error. **[#3166]** The daemon no longer falls back to
`AppConfig::default()` on rejection — that fail-OPEN behaviour meant a
rejected (or merely typo'd) config silently repointed `db` at the relative
`ai-memory.db` in the working directory. Boot now REFUSES with exit `78`
(`EX_CONFIG`) and nothing is started; the operator sees:

```
ai-memory: config rejected (~/.config/ai-memory/config.toml): inline
`api_key = "<literal>"` in [llm] is forbidden — use
`api_key_env = "<ENV_VAR_NAME>"` to reference a process env var, or
`api_key_file = "/path/to/key"` to reference a file (mode 0400
enforced). Inline secrets in config.toml (typically world-readable)
are a credential leak.
```

`[llm].api_key_env` and `[llm].api_key_file` are mutually exclusive
— the daemon refuses to load a config that sets both. Same mutex
applies to `[llm.auto_tag]`.

`[llm].api_key_file` requires `mode 0400` (or stricter). The check
is skipped on non-Unix platforms. To opt out (operator-advisory,
NOT recommended for production):

```bash
export AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=1
```

This is the same escape hatch [#1055](https://github.com/alphaonedev/ai-memory-mcp/issues/1055)
introduced for `AI_MEMORY_DB_PASSPHRASE_FILE`.

## Migration from v0.6.x (legacy flat fields)

The v0.6.x flat-field shape (`llm_model`, `ollama_url`, `embed_url`,
`embedding_model`, `cross_encoder`, `default_namespace`,
`archive_on_gc`, `archive_max_days`, `max_memory_mb`,
`auto_tag_model`) still parse at v1.0.0 and feed the
resolver's `Legacy` arm. Loading a legacy config emits a one-shot
stderr WARN pointing operators at the migration tool. **These fields
remain parseable at v1.0.0.** They were slated for removal in v0.8.0
(the `#[deprecated(note = "… slated for removal in v0.8.0")]`
attribute in `src/config.rs` still says so), but that hard removal
has not yet shipped — migrate off them with `ai-memory config
migrate` rather than relying on the stale target.

To migrate in place:

```bash
ai-memory config migrate              # write <file>.bak.<ts> + rewrite
ai-memory config migrate --dry-run    # print diff, write nothing
ai-memory config migrate \
    --also-clean-claude-json          # additionally remove
                                      # mcpServers.<*>.env from
                                      # ~/.claude.json
```

The migrator is **idempotent** — running against an already-v2 file
is a no-op INFO log.

## Reachability probe

`ai-memory doctor` emits a section `LLM Reachability (#1146)` that
resolves the canonical LLM config and probes the endpoint with the
resolved Bearer key:

- `ollama` → `GET <base_url>/api/tags` (no auth)
- any OpenAI-compatible → `GET <base_url>/models` (Bearer auth)

Severity partition:

| Severity | HTTP outcomes                                    |
|----------|--------------------------------------------------|
| INFO     | 200 (vendor reachable + auth OK)                 |
| WARN     | 401 / 403 (auth issue; URL reachable)            |
| WARN     | 429 (rate-limited; reachable)                    |
| WARN     | 5xx (vendor outage; reachable)                   |
| CRIT     | 4xx other (likely wrong base_url / endpoint)     |
| CRIT     | network / DNS / connect-refused / TLS error      |

Surfaces the resolved provenance facts (`backend`, `model`,
`base_url`, `config_source`, `key_source`) so the operator can see
WHICH precedence layer won.

## API-key resolution chain

For non-Ollama backends, the resolver consults these layers in
order:

1. `AI_MEMORY_LLM_API_KEY` (process env) — universal escape hatch.
2. Per-vendor process env-var fallback:
   - `xai` → `XAI_API_KEY`
   - `openai` → `OPENAI_API_KEY`
   - `anthropic` → `ANTHROPIC_API_KEY`
   - `gemini` → `GEMINI_API_KEY` (or `GOOGLE_API_KEY`)
   - `deepseek` → `DEEPSEEK_API_KEY`
   - `kimi` / `moonshot` → `MOONSHOT_API_KEY` (or `KIMI_API_KEY`)
   - `qwen` / `dashscope` → `DASHSCOPE_API_KEY` (or `QWEN_API_KEY`)
   - `mistral` → `MISTRAL_API_KEY`
   - `groq` → `GROQ_API_KEY`
   - `together` → `TOGETHER_API_KEY`
   - `cerebras` → `CEREBRAS_API_KEY`
   - `openrouter` → `OPENROUTER_API_KEY`
   - `fireworks` → `FIREWORKS_API_KEY`
3. `[llm].api_key_env = "<NAME>"` — config-pointed env var.
4. `[llm].api_key_file = "/path"` — file (mode 0400 enforced).

If all four return empty, the resolver returns `KeySource::None`
(correct for `backend = "ollama"`; a misconfiguration for any
OpenAI-compatible backend — `ai-memory doctor` surfaces this).

## Backend defaults

For each backend, the resolver applies these defaults when the
operator does not override:

| Backend          | Default base URL                                  | Default model                                   |
|------------------|---------------------------------------------------|-------------------------------------------------|
| `ollama`         | `http://localhost:11434`                          | `gemma3:4b`                                     |
| `openai`         | `https://api.openai.com/v1`                       | `gpt-5`                                         |
| `xai`            | `https://api.x.ai/v1`                             | `grok-4.3`                                      |
| `anthropic`      | `https://api.anthropic.com/v1`                    | `claude-opus-4.7`                               |
| `gemini`         | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-2.0-flash`                      |
| `deepseek`       | `https://api.deepseek.com/v1`                     | `deepseek-chat`                                 |
| `kimi`/`moonshot`| `https://api.moonshot.cn/v1`                      | `moonshot-v1-8k`                                |
| `qwen`/`dashscope`| `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-max`                                |
| `mistral`        | `https://api.mistral.ai/v1`                       | `mistral-large-latest`                          |
| `groq`           | `https://api.groq.com/openai/v1`                  | `llama-3.3-70b-versatile`                       |
| `together`       | `https://api.together.xyz/v1`                     | `meta-llama/Llama-3.3-70B-Instruct-Turbo`       |
| `cerebras`       | `https://api.cerebras.ai/v1`                      | `llama-3.3-70b`                                 |
| `openrouter`     | `https://openrouter.ai/api/v1`                    | `openai/gpt-5`                                  |
| `fireworks`      | `https://api.fireworks.ai/inference/v1`           | `accounts/fireworks/models/llama-v3p3-70b-instruct` |
| `lmstudio`       | `http://localhost:1234/v1`                        | `local-model`                                   |
| `vllm`           | `http://localhost:8000/v1`                        | `local-model`                                   |
| `openai-compatible` | _(no meaningful default — operator must set `base_url`; the env-var path errors without it)_ | `gemma3:4b` (legacy fallthrough)                |

The model defaults are intentionally aggressive — operators MUST
verify the chosen model exists on their account before relying on it.

## Optional vector-index backend — `vectorlite` (off-by-default)

By default ai-memory serves approximate-nearest-neighbour recall from a
**built-in pure-Rust HNSW index** (`src/hnsw.rs`) — no native dependency,
no extra build step, works everywhere the binary works. For deployments
that want a SQLite-native ANN backend, an **off-by-default cargo feature**
`vectorlite` ([#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860)
/ [#2219](https://github.com/alphaonedev/ai-memory-mcp/issues/2219)) wires
the [vectorlite](https://github.com/1yefuwang1/vectorlite) SQLite loadable
extension in as an alternate index.

It is opt-in in **three** independent steps — none of which a stock build
performs — because the extension is a **native shared library** that ships
outside the Rust dependency graph:

1. **Compile the feature in.** `vectorlite = ["rusqlite/load_extension"]`
   in `Cargo.toml` is OFF by default:

   ```bash
   cargo build --release --features vectorlite
   ```

   A stock (`--features`-less) build never reads the env var below and
   never loads any extension. There is **no Rust `vectorlite` crate** — the
   crates.io name of that spelling is unrelated to this project — so the
   native library is acquired out-of-band, not via `cargo`.

2. **Acquire the native library out-of-band.** The `.so` / `.dylib` /
   `.dll` is fetched by the repo's helper script rather than a package
   manager:

   ```bash
   scripts/fetch-vectorlite.sh /opt/ai-memory   # -> /opt/ai-memory/vectorlite.{so|dylib|dll}
   ```

   The helper downloads the correct per-platform artefact (from the
   Apache-2.0 [vectorlite](https://github.com/1yefuwang1/vectorlite)
   project — there is no Rust crate) and prints the
   `export AI_MEMORY_VECTORLITE_EXTENSION=<path>` line to use. The filename
   **MUST keep the `vectorlite` stem** — SQLite derives the
   `sqlite3_vectorlite_init` entry-point name from the file stem, so a
   renamed library will not load.

3. **Point the runtime at it.** Set the path at daemon / MCP startup:

   ```bash
   export AI_MEMORY_VECTORLITE_EXTENSION=/opt/ai-memory/vectorlite.so
   ```

   (env-var row #145 in the CLAUDE.md environment-variable table.)

**Fail-closed-to-pure-Rust-HNSW behaviour.** This is the data-integrity
guarantee: when the feature is compiled AND the path is set, the
vector-index funnel loads the extension as the ANN backend; but if the var
is **unset / empty**, if the library **fails to load or fails its
construction-time smoke test**, or if it **hard-fails mid-life**, the
substrate silently **degrades to the built-in pure-Rust HNSW index**. The
durable memory **text** is never at risk — an ANN index is derived,
regenerable data (the North-Star "degrade, never corrupt; worst case is
fewer results, never wrong results"). A misconfigured extension therefore
never takes the substrate down; it only forgoes the acceleration.

Sibling off-by-default cargo feature: `fs-notify`
([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978) /
[#2220](https://github.com/alphaonedev/ai-memory-mcp/issues/2220)) — the
event-driven (`inotify` / FSEvents / ReadDirectoryChangesW) watch path for
the L3 `ai-memory watch` capture daemon, which likewise degrades to the
dependency-free std-only poll loop when absent or on init failure.

Source: `src/vectorlite.rs::{VECTORLITE_EXTENSION_ENV,from_env}` +
`src/hnsw.rs`.

## Boot contract — what happens to a config the daemon cannot honour

**[#3166]** Boot FAILS CLOSED. The rule is one sentence: *a boot must never
silently open a different database than the one configured.*

| Config state | Behaviour |
|---|---|
| File ABSENT | Compiled defaults. Documented, unchanged. |
| `AI_MEMORY_NO_CONFIG` truthy (`1`/`true`/`yes`/`on`) | File skipped, compiled defaults. Unchanged. |
| File parses and validates | Loaded. `ai-memory: loaded config from <path>` on stderr. |
| TOML syntax error | **Boot REFUSED.** Error printed, exit `78` (`EX_CONFIG`). No database opened. |
| Secret-handling rejection (inline `api_key`, `api_key_env`+`api_key_file` both set, lax key-file mode) | **Boot REFUSED.** Exit `78`. |
| File unreadable (`EACCES`, `EIO`, a directory in its place) | **Boot REFUSED.** The io error is surfaced with its `ErrorKind`, never flattened into the "missing file" arm. Exit `78`. |

### Where `config.toml` is looked for

**[#3002]** The path resolves through the platform config dir — the SAME
resolver the identity key dir (`<config-dir>/ai-memory/keys`) and the hooks
file (`<config-dir>/ai-memory/hooks.toml`) use:

| `XDG_CONFIG_HOME` | Resolved path |
|---|---|
| unset | `~/.config/ai-memory/config.toml` (unchanged) |
| set, and it carries `ai-memory/config.toml` | `$XDG_CONFIG_HOME/ai-memory/config.toml` |
| set, empty, but `~/.config/ai-memory/config.toml` exists | **the legacy `~/.config` file, plus a one-shot stderr WARN** |
| set, and neither file exists | `$XDG_CONFIG_HOME/ai-memory/config.toml` (where a default is written) |

The third row is a deliberate migration guard, not sloppiness. Before #3002
the path was hardcoded to `$HOME/.config`; making it XDG-aware without a
fallback would mean that on any host setting `XDG_CONFIG_HOME` the operator's
existing config simply stops being found. An ABSENT config is the documented
"compiled defaults" case, so the #3166 boot refusal does NOT fire — `db` would
silently revert to the relative `ai-memory.db` in the working directory, which
is exactly the corpus split-brain #3166 exists to prevent. Honouring the legacy
file (loudly) keeps the upgrade lossless; move it to the XDG root to
consolidate with the keys and hooks.

Why refusing is the safe answer: on a fall-back to compiled defaults, `db`
becomes the RELATIVE `ai-memory.db` resolved against the process working
directory, so the daemon opens/creates a fresh empty database, serves
`count=0`, and accepts writes into that orphan — corpus split-brain against
the real corpus at the configured path. `[storage].append_only`,
`[governance].require_operator_pubkey` and `[[permissions.rules]]` revert in
the same stroke.

Four subcommands deliberately keep running on compiled defaults, because
refusing them would remove the operator's ability to diagnose or repair the
fault:

- `ai-memory doctor` — reports the breakage in its `Configuration` section
  (severity `Critical`, with the parse/io error verbatim) and states that every
  other section reflects compiled defaults.
- `ai-memory config` — the repair verb; it reads and rewrites the file directly
  and has its own parse-error exit codes.
- `ai-memory completions` / `ai-memory man` — pure argv-to-stdout generators.

`--version` and `--help` are unaffected: argv is parsed before the config is
resolved.

Everything else — including `ai-memory boot` — fails closed. Serving an agent
its first-turn context out of the wrong database is a WRONG ANSWER, which the
data-integrity directive ranks with corruption, not with degraded function.

## Related

- [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) —
  umbrella issue for this schema (QC-amended 2026-05-22).
- [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) —
  the underlying provider-agnostic LLM substrate this schema configures.
- [#1143](https://github.com/alphaonedev/ai-memory-mcp/issues/1143) —
  the sibling-site cleanup this schema subsumed (embed-client wire-shape
  disambiguation; its boot-site behaviour is superseded by #1598's
  API-capable `[embeddings]` resolver).
- [#1598](https://github.com/alphaonedev/ai-memory-mcp/issues/1598) —
  API-wired embeddings: `[embeddings]` backend/base_url/api_key/dim
  fields, `AI_MEMORY_EMBED_*` env vars, fail-closed embedder boot
  (#1593), truthful capabilities (#1594), resilient backfill (#1595),
  `ai-memory reembed`, doctor "Embeddings Reachability" section.
- [#1055](https://github.com/alphaonedev/ai-memory-mcp/issues/1055) —
  the `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS` escape hatch
  reused by `api_key_file`.
- CLAUDE.md `### Environment Variables` — full env-var table with
  precedence ladder and classification (`secret` / `config` /
  `test-only`).
