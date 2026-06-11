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
                              # fireworks | lmstudio | openai-compatible
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

# dim          = 3072            # explicit vector-dim override for models
                                 # not in config.rs::KNOWN_EMBEDDING_DIMS
backfill_batch = 100             # env override: AI_MEMORY_EMBED_BACKFILL_BATCH

# ---------------------------------------------------------------------
# [reranker] — cross-encoder rerank configuration.
# ---------------------------------------------------------------------
[reranker]
enabled = true
model   = "ms-marco-MiniLM-L-6-v2"

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
# [limits] — operator-tunable resource caps (#1156 follow-up).
# All four fall back to the compiled default when absent, non-positive,
# or unparseable. Precedence per field:
#   AI_MEMORY_MAX_* env > [limits] section > compiled default.
# ---------------------------------------------------------------------
[limits]
max_memories_per_day = 1000        # per-agent daily memory-write quota
max_storage_bytes    = 104857600   # per-agent storage cap (bytes; 100 MiB)
max_links_per_day    = 5000        # per-agent daily link-write quota
max_page_size        = 1000        # list/bulk/sync page-size cap (OOM guard)

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
| PostgreSQL | **18.4** | `PG_APT_VERSION=18.4-1.pgdg13+1`, `EXPECTED_PG_VERSION=18.4` |
| Apache AGE | **1.7.0** | `AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0`, `EXPECTED_AGE_VERSION=1.7.0` |
| pgvector (server extension) | **0.8.2** | `PGVECTOR_APT_VERSION=0.8.2-1.pgdg13+1` |
| pgvector (Rust binding crate) | **0.4** | `Cargo.toml` → `pgvector = "0.4"` |
| ai-memory postgres schema | **v56** | `EXPECTED_SCHEMA=56`; postgres ladder pinned in lockstep with SQLite `CURRENT_SCHEMA_VERSION = 56` (`src/storage/migrations.rs`) |

The bundled stacked image at
[`deploy/docker-1461/Dockerfile.pg-age-vector`](../deploy/docker-1461/Dockerfile.pg-age-vector)
(`ARG AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0`, `ARG PG_MAJOR=18`)
layers pgvector 0.8.2 onto the AGE base so K8s / ECS / Cloud Run
operators do not build AGE from source. See
[`postgres-age-guide.md`](postgres-age-guide.md) for the from-source
install recipe and the Docker layering rationale (#1065).

> **Alternate tested matrix.** `infra/lan-parity-test/` and the
> lan-parity compose harness legitimately run **PG 16 + AGE 1.6.0 +
> pgvector 0.8.2** as a second tested combination. Those references are
> factual (not drift); the *recommended* Enterprise Federated install
> targets the PG 18.4 / AGE 1.7.0 matrix above.

## Enterprise & operational sections

Beyond the four #1146 sectioned blocks (`[llm]` / `[embeddings]` /
`[reranker]` / `[storage]`) and `[limits]` shown in the Quick reference,
`AppConfig` (`src/config.rs`) parses the following operator-facing
sections. Each is **default-safe** — absent blocks select the compiled
default and preserve the pre-existing behaviour. Fields are listed
exactly as the SSOT struct declares them.

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
  encrypt_at_rest             = true    # pair with --features sqlcipher
  [audit.compliance.gdpr]
  applied                     = false
  pseudonymize_actors         = true
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
  as `i64`, `max_page_size` as `usize`). The three quota fields seed the
  process-wide `crate::quotas::QuotaDefaults` OnceLock once at boot (the
  `agent_quotas`-row SQL binds have no `AppConfig` in scope);
  `max_page_size` lands on `AppState.max_page_size`, read by every Axum
  handler via `State(app)`. Precedence ladder for this section is
  `AI_MEMORY_MAX_* env > [limits] > compiled default` (no CLI flag, no
  legacy flat field). Non-positive / unparseable values are filtered so
  a stray `0` `max_page_size` cannot clamp every list response to empty.

**Uniform precedence ladder** (CLI > env > config > legacy > compiled):

```
CLI flag  >  AI_MEMORY_LLM_* env  >  [llm] section  >  legacy flat fields  >  compiled default
```

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
clear stderr error. The daemon falls back to `AppConfig::default()`
on rejection so it still boots, and the operator sees:

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
`auto_tag_model`) continues to parse in v0.7.x and feeds the
resolver's `Legacy` arm. Loading a legacy config emits a one-shot
stderr WARN pointing operators at the migration tool. **Legacy
fields will be removed in v0.8.0.**

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
| `openai-compatible` | _(no meaningful default — operator must set `base_url`; the env-var path errors without it)_ | `gemma3:4b` (legacy fallthrough)                |

The model defaults are intentionally aggressive — operators MUST
verify the chosen model exists on their account before relying on it.

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
