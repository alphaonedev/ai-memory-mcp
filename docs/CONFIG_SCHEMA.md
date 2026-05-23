# `ai-memory` configuration schema reference

This is the canonical reference for the v0.7.x schema-versioned
sectioned configuration format introduced in
[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146).
Every deployment of `ai-memory` (MCP server, HTTP daemon, CLI) reads
configuration from a single file at `~/.config/ai-memory/config.toml`.

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
# ---------------------------------------------------------------------
[embeddings]
backend        = "ollama"
url            = "http://localhost:11434"
model          = "nomic-embed-text-v1.5"
backfill_batch = 100            # env override: AI_MEMORY_EMBED_BACKFILL_BATCH

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

# ---------------------------------------------------------------------
# Existing sections at v0.7.x — see env-var table in CLAUDE.md.
# ---------------------------------------------------------------------
[mcp]
profile = "full"

[permissions]
mode = "enforce"
```

## Canonical resolver

Every LLM / embedder / reranker / storage decision in the binary
consumes the corresponding `Resolved*` struct produced by these
methods:

- `AppConfig::resolve_llm(cli_backend, cli_model, cli_base_url)`
- `AppConfig::resolve_llm_auto_tag()`
- `AppConfig::resolve_embeddings()`
- `AppConfig::resolve_reranker()`
- `AppConfig::resolve_storage()`

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
| `openai-compatible` | _(no default — operator must set `base_url`)_ | `gpt-5`                                         |

The model defaults are intentionally aggressive — operators MUST
verify the chosen model exists on their account before relying on it.

## Related

- [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) —
  umbrella issue for this schema (QC-amended 2026-05-22).
- [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) —
  the underlying provider-agnostic LLM substrate this schema configures.
- [#1143](https://github.com/alphaonedev/ai-memory-mcp/issues/1143) —
  the sibling-site cleanup this schema subsumed.
- [#1055](https://github.com/alphaonedev/ai-memory-mcp/issues/1055) —
  the `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS` escape hatch
  reused by `api_key_file`.
- CLAUDE.md `### Environment Variables` — full env-var table with
  precedence ladder and classification (`secret` / `config` /
  `test-only`).
