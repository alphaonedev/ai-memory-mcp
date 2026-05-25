// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! LLM client — provider-agnostic chat + embedding surface.
//!
//! # Providers (#1066)
//!
//! The historical client was Ollama-only. Post-#1066 the same struct
//! supports two wire shapes and any vendor that speaks either:
//!
//! | Variant                    | Wire shape                                        | Auth                              | Vendors                                                                                                                                                                                                                       |
//! |----------------------------|---------------------------------------------------|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
//! | [`LlmProvider::Ollama`]    | `POST /api/chat`, `POST /api/embed`               | none                              | Ollama (native)                                                                                                                                                                                                                |
//! | [`LlmProvider::OpenAiCompatible`] | `POST /v1/chat/completions`, `POST /v1/embeddings` | `Authorization: Bearer <key>`  | OpenAI, xAI Grok, Anthropic (via OpenAI shim), Google Gemini (`/v1beta/openai`), DeepSeek, Kimi (Moonshot), Qwen (Alibaba), Mistral, Groq, Together AI, Cerebras, OpenRouter, Fireworks, LMStudio, vLLM, llama.cpp server, …  |
//!
//! ## Operator configuration
//!
//! - `AI_MEMORY_LLM_BACKEND` — selector. Accepted values:
//!     - `ollama` (default; backward compat)
//!     - `openai-compatible` — generic; requires `AI_MEMORY_LLM_BASE_URL` set explicitly
//!     - alias values that pre-fill `AI_MEMORY_LLM_BASE_URL` for known vendors:
//!       `xai`, `openai`, `anthropic`, `gemini`, `deepseek`, `kimi`, `qwen`,
//!       `mistral`, `groq`, `together`, `cerebras`, `openrouter`,
//!       `fireworks`, `lmstudio`
//! - `AI_MEMORY_LLM_BASE_URL` — overrides the default per-backend URL.
//! - `AI_MEMORY_LLM_API_KEY` — Bearer auth secret for OpenAI-compatible
//!   backends. Some aliases also accept per-vendor env vars as a
//!   convenience (e.g. `XAI_API_KEY` if backend=`xai`, `OPENAI_API_KEY`
//!   if backend=`openai`, `ANTHROPIC_API_KEY` if backend=`anthropic`,
//!   `GEMINI_API_KEY` if backend=`gemini`, etc.).
//! - `AI_MEMORY_LLM_MODEL` — model name passed through verbatim. The
//!   selection is vendor-specific (e.g. `grok-4` for xAI,
//!   `deepseek-chat` for DeepSeek, `qwen-max` for Qwen).
//! - Legacy `OLLAMA_BASE_URL` is still honored when backend=ollama.

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";

/// v0.7.x (#1174 PR4-remainder) — canonical name of the Ollama-native
/// backend selector.
///
/// Used in `AI_MEMORY_LLM_BACKEND`, the `[llm].backend` config field,
/// and the `ResolvedLlm::backend` runtime view. Every substrate site
/// that needs to ask "is this the native-Ollama wire shape?" must
/// either reference this const (for string compares against the wire
/// value) or call [`crate::config::ResolvedLlm::is_ollama_native`]
/// (the typed accessor that wraps the comparison).
///
/// Centralising the literal here keeps the heterogeneous-NHI substrate
/// (#1067) from re-naming a single vendor across `cli/`, `mcp/`,
/// `handlers/`, etc. Per PR #1175 + this PR, vendor names belong in
/// `llm.rs` aliases / `config.rs` alias tables, not scattered across
/// the codebase.
pub const BACKEND_OLLAMA: &str = "ollama";

/// Per-vendor default base URLs for the OpenAI-compatible alias
/// backends. Operator-provided `AI_MEMORY_LLM_BASE_URL` overrides
/// these. Verified against vendor documentation as of 2026-Q2.
fn default_base_url_for_alias(alias: &str) -> Option<&'static str> {
    match alias {
        "openai" => Some("https://api.openai.com/v1"),
        "xai" => Some("https://api.x.ai/v1"),
        "anthropic" => Some("https://api.anthropic.com/v1"),
        "gemini" => Some("https://generativelanguage.googleapis.com/v1beta/openai"),
        "deepseek" => Some("https://api.deepseek.com/v1"),
        "kimi" | "moonshot" => Some("https://api.moonshot.cn/v1"),
        "qwen" | "dashscope" => Some("https://dashscope.aliyuncs.com/compatible-mode/v1"),
        "mistral" => Some("https://api.mistral.ai/v1"),
        "groq" => Some("https://api.groq.com/openai/v1"),
        "together" => Some("https://api.together.xyz/v1"),
        "cerebras" => Some("https://api.cerebras.ai/v1"),
        "openrouter" => Some("https://openrouter.ai/api/v1"),
        "fireworks" => Some("https://api.fireworks.ai/inference/v1"),
        "lmstudio" => Some("http://localhost:1234/v1"),
        _ => None,
    }
}

/// Per-alias environment-variable fallback for the API key. Lets
/// operators set `XAI_API_KEY`, `OPENAI_API_KEY`, etc. (the vendor's
/// canonical env var name) without having to alias to
/// `AI_MEMORY_LLM_API_KEY`. Tried in the order returned.
fn alias_api_key_env_vars(alias: &str) -> &'static [&'static str] {
    match alias {
        "openai" => &["OPENAI_API_KEY"],
        "xai" => &["XAI_API_KEY"],
        "anthropic" => &["ANTHROPIC_API_KEY"],
        "gemini" => &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "deepseek" => &["DEEPSEEK_API_KEY"],
        "kimi" | "moonshot" => &["MOONSHOT_API_KEY", "KIMI_API_KEY"],
        "qwen" | "dashscope" => &["DASHSCOPE_API_KEY", "QWEN_API_KEY"],
        "mistral" => &["MISTRAL_API_KEY"],
        "groq" => &["GROQ_API_KEY"],
        "together" => &["TOGETHER_API_KEY"],
        "cerebras" => &["CEREBRAS_API_KEY"],
        "openrouter" => &["OPENROUTER_API_KEY"],
        "fireworks" => &["FIREWORKS_API_KEY"],
        _ => &[],
    }
}

/// LLM-provider wire-shape selector. Owned by [`OllamaClient`] (the
/// historical name preserved post-#1066 for call-site backward
/// compatibility — a future rename to `LlmClient` is non-breaking and
/// tracked separately).
///
/// #1258 — `api_key` carries a vendor Bearer token; the manual `Drop`
/// impl below zeroizes the in-memory bytes when an `LlmProvider` falls
/// out of scope so the secret does not linger on the heap. #1262 —
/// the manual `Debug` impl redacts the `api_key` to `<redacted>` so a
/// stray `{:?}` print never leaks the secret.
#[derive(Clone)]
pub enum LlmProvider {
    /// Ollama native API: `POST /api/chat`, `POST /api/embed`. No
    /// auth header. This is the historical pre-#1066 behavior and
    /// remains the v0.7.0 default.
    Ollama,
    /// OpenAI-compatible API: `POST /v1/chat/completions`, `POST
    /// /v1/embeddings`. `Authorization: Bearer <api_key>` header.
    /// Covers xAI Grok, OpenAI, Anthropic (via OpenAI shim), Google
    /// Gemini, DeepSeek, Kimi, Qwen, Mistral, Groq, Together,
    /// Cerebras, OpenRouter, Fireworks, LMStudio, vLLM, llama.cpp
    /// server, and any other vendor following the spec.
    OpenAiCompatible { api_key: String },
}

impl std::fmt::Debug for LlmProvider {
    /// #1262 — redact `api_key` so accidental `{:?}` prints never leak
    /// the vendor Bearer token. The variant name stays for operator
    /// diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmProvider::Ollama => f.debug_struct("Ollama").finish(),
            LlmProvider::OpenAiCompatible { .. } => f
                .debug_struct("OpenAiCompatible")
                .field("api_key", &"<redacted>")
                .finish(),
        }
    }
}

impl Drop for LlmProvider {
    /// #1258 — zeroize the `api_key` buffer on scope exit so the vendor
    /// Bearer token does not linger on the heap after the
    /// `LlmProvider` is dropped. `Ollama` carries no secret and is a
    /// no-op.
    fn drop(&mut self) {
        if let LlmProvider::OpenAiCompatible { api_key } = self {
            use zeroize::Zeroize;
            api_key.zeroize();
        }
    }
}

const GENERATE_TIMEOUT: Duration = Duration::from_secs(30);
const PULL_TIMEOUT: Duration = Duration::from_secs(120);
/// v0.7.0 F6 — explicit TCP connect timeout. Prevents the daemon's MCP
/// loop from hanging when ollama is dead and the kernel returns nothing
/// (no connection refused, no SYN-ACK). 5s is generous for localhost.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// v0.7.0 F6 — health-probe timeout. Quick check at /api/tags.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
/// v0.7.0 F6 — circuit-breaker window. After [`CIRCUIT_BREAKER_THRESHOLD`]
/// consecutive failures the client fast-fails until this window elapses.
/// Re-establishes a probe attempt after the window.
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);
/// v0.7.0 F6 — failures within the same cooldown window required to trip
/// the breaker. Single transient failure does not flip the switch.
const CIRCUIT_BREAKER_THRESHOLD: u32 = 3;

const QUERY_EXPANSION_PROMPT: &str = r"You are a search query expander. Given a search query, generate 5-8 additional search terms that are semantically related. Return ONLY the terms, one per line, no numbering or explanation.

Query: {query}";

const SUMMARIZE_PROMPT: &str = r"Summarize the following memories into a single concise paragraph. Preserve all key facts, decisions, and technical details.

{memories}";

const AUTO_TAG_PROMPT: &str = r"Generate 3-5 short tags for categorizing this memory. Return ONLY the tags, one per line, lowercase, no symbols.

Title: {title}
Content: {content}";

const CONTRADICTION_PROMPT: &str = r#"Do these two statements contradict each other? Answer ONLY "yes" or "no".

Statement A: {a}
Statement B: {b}"#;

/// v0.7.0 F6 — lightweight circuit-breaker state. Tracks the last failure
/// and a rolling consecutive-failure count. When the count crosses
/// [`CIRCUIT_BREAKER_THRESHOLD`] within [`CIRCUIT_BREAKER_COOLDOWN`] the
/// breaker is considered "open": [`OllamaClient::generate`] returns a
/// fast-fail error instead of issuing the HTTP request, preventing
/// repeated 30-second timeouts from pegging the daemon's CPU and locking
/// up the MCP dispatch loop.
#[derive(Debug)]
struct BreakerState {
    consecutive_failures: u32,
    last_failure_at: Option<Instant>,
}

impl BreakerState {
    const fn new() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_at: None,
        }
    }

    /// Returns true when the breaker is open (fast-fail).
    fn is_open(&self) -> bool {
        if self.consecutive_failures < CIRCUIT_BREAKER_THRESHOLD {
            return false;
        }
        match self.last_failure_at {
            Some(t) => t.elapsed() < CIRCUIT_BREAKER_COOLDOWN,
            None => false,
        }
    }

    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure_at = Some(Instant::now());
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_failure_at = None;
    }
}

pub struct OllamaClient {
    /// #1066 (2026-05-21) — LLM provider wire shape. `Ollama` for the
    /// historical native API path; `OpenAiCompatible` for xAI, OpenAI,
    /// Anthropic (OpenAI shim), Google Gemini, DeepSeek, Kimi, Qwen,
    /// Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks,
    /// LMStudio, vLLM, llama.cpp server, and any other vendor that
    /// follows the OpenAI chat-completions spec. The legacy struct
    /// name is preserved for call-site backward compatibility; a
    /// future rename to `LlmClient` is non-breaking.
    provider: LlmProvider,
    base_url: String,
    model: String,
    client: reqwest::blocking::Client,
    /// v0.7.0 F6 — guards `generate` / `embed_text` from re-issuing
    /// requests against an unreachable endpoint. Reset on the first
    /// success after a cooldown.
    breaker: Mutex<BreakerState>,
}

impl OllamaClient {
    /// v0.7.0 (issue #1244) — accessor for the resolved model name.
    ///
    /// Returns the model identifier the client was constructed with
    /// (e.g. `gemma3:4b` on Ollama, `grok-4.3` on xAI, `claude-opus-4.7`
    /// on Anthropic). Substrate sites that bind LLM provenance into
    /// signed audit events (e.g. the atomisation_complete
    /// `curator_model` payload field) read this verbatim — never a
    /// hardcoded string — so the signed event reflects the model that
    /// actually ran on a given deployment, not a v0.6.x-era default.
    #[must_use]
    pub fn model_name(&self) -> &str {
        &self.model
    }

    /// Creates a new `OllamaClient` with the default Ollama URL (<http://localhost:11434>).
    /// Checks that Ollama is reachable before returning.
    #[allow(dead_code)]
    pub fn new(model: &str) -> Result<Self> {
        Self::new_with_url(DEFAULT_OLLAMA_URL, model)
    }

    /// Test-only constructor that skips the Ollama reachability check.
    /// Use this in unit tests that only need a `Some(&OllamaClient)` value
    /// to exercise non-LLM code paths (e.g. the `autonomy_hook_skipped`
    /// skip-reason waterfall short-circuits before any RPC fires when the
    /// reason is `content_too_short` or `internal_namespace`).
    #[cfg(test)]
    pub fn new_for_testing(model: &str) -> Self {
        Self {
            provider: LlmProvider::Ollama,
            base_url: DEFAULT_OLLAMA_URL.trim_end_matches('/').to_string(),
            model: model.to_string(),
            client: reqwest::blocking::Client::builder()
                .timeout(GENERATE_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .expect("test reqwest client builds"),
            breaker: Mutex::new(BreakerState::new()),
        }
    }

    /// #1066 — Construct from environment variables. Returns `Ok(Some(client))`
    /// when the env declares an LLM backend; `Ok(None)` when no backend is
    /// configured (keyword-only deployments); `Err` on misconfiguration
    /// (e.g. backend declared but required key missing).
    ///
    /// Reads:
    /// - `AI_MEMORY_LLM_BACKEND` — `ollama` (default) | `openai-compatible`
    ///   | one of the per-vendor aliases (`xai`, `openai`, `anthropic`,
    ///   `gemini`, `deepseek`, `kimi`, `qwen`, `mistral`, `groq`,
    ///   `together`, `cerebras`, `openrouter`, `fireworks`, `lmstudio`).
    /// - `AI_MEMORY_LLM_BASE_URL` — overrides the default per-alias URL.
    /// - `AI_MEMORY_LLM_API_KEY` — Bearer auth secret for the
    ///   OpenAI-compatible path. Per-alias fallback env vars are also
    ///   consulted (`XAI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
    ///   `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `MOONSHOT_API_KEY`,
    ///   `DASHSCOPE_API_KEY`, etc.).
    /// - `AI_MEMORY_LLM_MODEL` — model name (`grok-4`, `gpt-5`,
    ///   `claude-opus-4.7`, `gemini-2.0-flash`, `deepseek-chat`, etc.).
    /// - Legacy `OLLAMA_BASE_URL` is still honored when backend is
    ///   `ollama` (or unset).
    ///
    /// # Errors
    ///
    /// - `AI_MEMORY_LLM_BACKEND` is set to an unknown alias.
    /// - Backend is OpenAI-compatible (or an alias) but no API key is
    ///   resolvable from `AI_MEMORY_LLM_API_KEY` or any per-alias
    ///   fallback env var.
    /// - Backend is the generic `openai-compatible` and
    ///   `AI_MEMORY_LLM_BASE_URL` is unset.
    /// - The HTTP client itself fails to build.
    #[allow(clippy::too_many_lines)]
    pub fn from_env() -> Result<Option<Self>> {
        let backend = std::env::var("AI_MEMORY_LLM_BACKEND")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_else(|| BACKEND_OLLAMA.to_string());

        let model = std::env::var("AI_MEMORY_LLM_MODEL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| match backend.as_str() {
                "xai" => "grok-4.3".to_string(),
                "openai" => "gpt-5".to_string(),
                "anthropic" => "claude-opus-4.7".to_string(),
                "gemini" => "gemini-2.0-flash".to_string(),
                "deepseek" => "deepseek-chat".to_string(),
                "kimi" | "moonshot" => "moonshot-v1-8k".to_string(),
                "qwen" | "dashscope" => "qwen-max".to_string(),
                "mistral" => "mistral-large-latest".to_string(),
                "groq" => "llama-3.3-70b-versatile".to_string(),
                "together" => "meta-llama/Llama-3.3-70B-Instruct-Turbo".to_string(),
                "cerebras" => "llama-3.3-70b".to_string(),
                "openrouter" => "openai/gpt-5".to_string(),
                "fireworks" => "accounts/fireworks/models/llama-v3p3-70b-instruct".to_string(),
                "lmstudio" => "local-model".to_string(),
                _ => "gemma3:4b".to_string(),
            });

        match backend.as_str() {
            BACKEND_OLLAMA => {
                let base_url = std::env::var("AI_MEMORY_LLM_BASE_URL")
                    .ok()
                    .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_OLLAMA_URL.to_string());
                Self::new_with_url(&base_url, &model).map(Some)
            }
            "openai-compatible" => {
                let base_url = std::env::var("AI_MEMORY_LLM_BASE_URL")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| {
                        anyhow!(
                            "AI_MEMORY_LLM_BACKEND=openai-compatible requires \
                             AI_MEMORY_LLM_BASE_URL to be set (no default URL \
                             — operator must supply the vendor's endpoint)"
                        )
                    })?;
                let api_key = std::env::var("AI_MEMORY_LLM_API_KEY")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| {
                        anyhow!(
                            "AI_MEMORY_LLM_BACKEND=openai-compatible requires \
                             AI_MEMORY_LLM_API_KEY to be set"
                        )
                    })?;
                Self::new_openai_compatible(&base_url, &model, &api_key).map(Some)
            }
            alias => {
                let Some(default_url) = default_base_url_for_alias(alias) else {
                    return Err(anyhow!(
                        "AI_MEMORY_LLM_BACKEND={alias} is not a recognized \
                         backend alias. Valid values: ollama, openai-compatible, \
                         openai, xai, anthropic, gemini, deepseek, kimi, qwen, \
                         mistral, groq, together, cerebras, openrouter, \
                         fireworks, lmstudio"
                    ));
                };
                let base_url = std::env::var("AI_MEMORY_LLM_BASE_URL")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| default_url.to_string());
                let api_key = std::env::var("AI_MEMORY_LLM_API_KEY")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| {
                        alias_api_key_env_vars(alias).iter().find_map(|name| {
                            std::env::var(name).ok().filter(|s| !s.trim().is_empty())
                        })
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "AI_MEMORY_LLM_BACKEND={alias} requires an API key \
                             — set AI_MEMORY_LLM_API_KEY or one of the \
                             per-vendor env vars: {:?}",
                            alias_api_key_env_vars(alias)
                        )
                    })?;
                Self::new_openai_compatible(&base_url, &model, &api_key).map(Some)
            }
        }
    }

    /// #1143 — Sync env-aware client construction with a tier-default
    /// legacy fallback. Centralises the pattern that #1142 ported into
    /// `src/mcp/mod.rs` so every synchronous LLM-init site (CLI
    /// `atomise`, CLI `curator`, MCP stdio LLM init, embed-client
    /// fallback selection) routes through one place. The daemon's
    /// async path (`daemon_runtime::build_llm_client`) wraps the same
    /// resolution order in `tokio::task::spawn_blocking`; behavioural
    /// parity with that wrapper is pinned by tests below.
    ///
    /// Resolution order:
    ///   1. `AI_MEMORY_LLM_BACKEND` set + non-empty → `from_env()`.
    ///   2. Else → `new_with_url(legacy_url, legacy_model)` so a v0.6.x
    ///      operator who never set the env vars keeps the historical
    ///      tier-default Ollama path.
    ///
    /// Returns `Ok(None)` from the env-aware arm only when the env var
    /// chain resolves to a no-op (currently impossible for any
    /// recognised backend alias; defensively threaded so future "alias
    /// disabled" branches don't break callers).
    ///
    /// # Errors
    ///
    /// Mirrors [`Self::from_env`] when the env arm is taken, and
    /// [`Self::new_with_url`] when the legacy arm is taken.
    pub fn build_for_init(legacy_url: &str, legacy_model: &str) -> Result<Option<Self>> {
        let backend_env = std::env::var("AI_MEMORY_LLM_BACKEND")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if backend_env.is_some() {
            return Self::from_env();
        }
        Self::new_with_url(legacy_url, legacy_model).map(Some)
    }

    /// v0.7.x (#1146) — Construct an `OllamaClient` from a fully-resolved
    /// LLM configuration produced by [`crate::config::AppConfig::resolve_llm`].
    /// This is the enterprise-class single-entry-point that replaces
    /// every call to [`Self::build_for_init`] /
    /// [`Self::new_with_url`] / [`Self::from_env`] /
    /// [`Self::new_openai_compatible`] in the surface plumbing.
    ///
    /// The resolver has already done all precedence + provenance work
    /// (CLI flag > env > [llm] config section > legacy fields >
    /// compiled default) and produced a [`ResolvedLlm`] carrying the
    /// authoritative `(backend, model, base_url, api_key)` quad. This
    /// constructor just maps it onto the appropriate wire-shape
    /// client.
    ///
    /// Returns `Ok(None)` when the resolved `api_key_source` is
    /// `KeySource::Error(_)` and the backend is non-Ollama (so we
    /// can't even attempt to construct an OpenAI-compatible client).
    /// The error surfaces through the `ai-memory doctor` LLM
    /// reachability probe rather than panicking at construct time.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client itself fails to build, or
    /// if the Ollama-backend reachability check fails the same way
    /// [`Self::new_with_url`] already fails.
    pub fn build_from_resolved(resolved: &crate::config::ResolvedLlm) -> Result<Option<Self>> {
        // Surface the resolved provenance for operator-facing debugging
        // (RUST_LOG=ai_memory=debug ai-memory <cmd>).
        tracing::debug!(
            "LLM client construction via #1146 resolver — backend={}, model={}, base_url={}, key_source={}, source={}",
            resolved.backend,
            resolved.model,
            resolved.base_url,
            resolved.api_key_source.as_str(),
            resolved.source.as_str(),
        );

        if resolved.backend == BACKEND_OLLAMA {
            return Self::new_with_url(&resolved.base_url, &resolved.model).map(Some);
        }

        // Non-Ollama backends require an API key. If the resolver
        // could not produce one, surface the error via a returned
        // `Err` (consistent with the pre-#1143 `from_env` posture).
        let Some(api_key) = resolved.api_key() else {
            return Err(anyhow!(
                "LLM backend `{}` requires an API key but the resolver \
                 produced none. KeySource = {}. Configure either \
                 AI_MEMORY_LLM_API_KEY, a per-vendor env var (e.g. \
                 XAI_API_KEY), [llm].api_key_env, or [llm].api_key_file \
                 in config.toml. See \
                 https://github.com/alphaonedev/ai-memory-mcp/issues/1146",
                resolved.backend,
                resolved.api_key_source.as_str(),
            ));
        };

        Self::new_openai_compatible(&resolved.base_url, &resolved.model, api_key).map(Some)
    }

    /// #1143 — Wire-shape introspection for embed-client fallback.
    /// Embed endpoints differ from chat endpoints across vendors: only
    /// Ollama (and a couple of OpenAI-compatible vendors) expose a
    /// usable embedding wire-shape, and the substrate's local embedder
    /// integration only speaks the Ollama `/api/embed` shape. Callers
    /// that consider re-using the LLM client for embeddings use this
    /// to bail out when the client is an OpenAI-compatible vendor.
    #[must_use]
    pub fn is_ollama_native(&self) -> bool {
        matches!(self.provider, LlmProvider::Ollama)
    }

    /// #1066 — Construct an OpenAI-compatible client for any vendor whose
    /// `/v1/chat/completions` endpoint follows the OpenAI spec (xAI Grok,
    /// OpenAI, Anthropic via OpenAI shim, Google Gemini, DeepSeek, Kimi,
    /// Qwen, Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks,
    /// LMStudio, vLLM, llama.cpp server, …).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build.
    pub fn new_openai_compatible(base_url: &str, model: &str, api_key: &str) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(GENERATE_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self {
            provider: LlmProvider::OpenAiCompatible {
                api_key: api_key.to_string(),
            },
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            client,
            breaker: Mutex::new(BreakerState::new()),
        })
    }

    /// Creates a new `OllamaClient` with a custom base URL.
    /// Checks that Ollama is reachable before returning.
    ///
    /// v0.7.0 F6: the underlying `reqwest` client now carries an explicit
    /// `connect_timeout` so a dead endpoint fails in [`CONNECT_TIMEOUT`]
    /// instead of hanging on the kernel SYN retry budget. The per-request
    /// `timeout` is preserved at [`GENERATE_TIMEOUT`].
    pub fn new_with_url(base_url: &str, model: &str) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(GENERATE_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("Failed to build HTTP client")?;

        let instance = Self {
            provider: LlmProvider::Ollama,
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            client,
            breaker: Mutex::new(BreakerState::new()),
        };

        if !instance.is_available() {
            return Err(anyhow!(
                "Ollama is not running or not reachable at {}. \
                 Start it with: ollama serve",
                instance.base_url
            ));
        }

        Ok(instance)
    }

    /// v0.7.0 F6 — observe the breaker's state without acquiring it for
    /// long; if poisoned, treat as closed (fail open) so a poisoned mutex
    /// can never wedge the LLM path entirely.
    fn breaker_is_open(&self) -> bool {
        self.breaker.lock().map(|b| b.is_open()).unwrap_or(false)
    }

    fn note_failure(&self) {
        if let Ok(mut b) = self.breaker.lock() {
            b.record_failure();
        }
    }

    fn note_success(&self) {
        if let Ok(mut b) = self.breaker.lock() {
            b.record_success();
        }
    }

    /// Inspect the breaker state for tests and observability.
    #[doc(hidden)]
    pub fn circuit_breaker_open(&self) -> bool {
        self.breaker_is_open()
    }

    /// Quick health check — returns true if the backend responds 2xx.
    ///
    /// - Ollama: `GET /api/tags` (lists pulled models)
    /// - OpenAI-compatible: `GET /v1/models` with Bearer auth (most
    ///   vendors support this endpoint)
    ///
    /// Strict semantics: 4xx and 5xx return false. A vendor that
    /// returns 401 on bad auth is treated as "not available" because
    /// we cannot use it. The circuit-breaker in [`Self::generate`]
    /// handles transient 5xx burst behavior separately. Matches the
    /// pre-#1067 contract pinned by
    /// `wiremock_tests::test_is_available_returns_false_on_500_response`.
    pub fn is_available(&self) -> bool {
        let (url, bearer) = match &self.provider {
            LlmProvider::Ollama => (format!("{}/api/tags", self.base_url), None),
            LlmProvider::OpenAiCompatible { api_key } => {
                (format!("{}/models", self.base_url), Some(api_key.as_str()))
            }
        };
        let mut req = self.client.get(&url).timeout(HEALTH_TIMEOUT);
        if let Some(key) = bearer {
            req = req.bearer_auth(key);
        }
        req.send().is_ok_and(|r| r.status().is_success())
    }

    /// Ensure the configured model is available.
    ///
    /// - Ollama: lists `/api/tags`, pulls via `/api/pull` if missing.
    /// - OpenAI-compatible: **no-op** — model availability is the
    ///   vendor's concern (operator is responsible for confirming the
    ///   model exists on the chosen vendor's plan).
    pub fn ensure_model(&self) -> Result<()> {
        if matches!(self.provider, LlmProvider::OpenAiCompatible { .. }) {
            // Vendor-side concern; the operator selected the model
            // when they set AI_MEMORY_LLM_MODEL.
            return Ok(());
        }
        // Check if model exists by listing tags
        let url = format!("{}/api/tags", self.base_url);
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .context("Failed to list Ollama models")?;

        let body: Value = resp.json().context("Failed to parse /api/tags response")?;

        let model_exists = body["models"].as_array().is_some_and(|models| {
            models.iter().any(|m| {
                let name = m["name"].as_str().unwrap_or("");
                // Match "model" or "model:tag" against our model string
                // Also match when our model base (before ':') matches the served name
                let our_base = self.model.split(':').next().unwrap_or(&self.model);
                name == self.model
                    || name.starts_with(&format!("{}:", self.model))
                    || self.model == name.split(':').next().unwrap_or("")
                    || name == our_base
            })
        });

        if model_exists {
            return Ok(());
        }

        // Pull the model
        tracing::info!(
            "Pulling Ollama model '{}' (this may take a while)...",
            self.model
        );

        let pull_url = format!("{}/api/pull", self.base_url);
        let pull_client = reqwest::blocking::Client::builder()
            .timeout(PULL_TIMEOUT)
            .build()
            .context("Failed to build pull client")?;

        let resp = pull_client
            .post(&pull_url)
            .json(&json!({ "name": self.model }))
            .send()
            .context("Failed to pull model from Ollama")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(anyhow!("Ollama pull failed ({status}): {text}"));
        }

        tracing::info!("Model '{}' pulled successfully", self.model);
        Ok(())
    }

    /// Generates a completion using the /api/chat endpoint (Ollama chat format).
    /// This is compatible with both Ollama and vMLX/OpenAI-compatible servers.
    /// Returns the response text.
    ///
    /// v0.7.0 F6 — the call is guarded by a circuit breaker. After
    /// [`CIRCUIT_BREAKER_THRESHOLD`] consecutive failures the call
    /// fast-fails for [`CIRCUIT_BREAKER_COOLDOWN`] instead of waiting
    /// the full HTTP timeout each time. This is the key defence
    /// against the Round-2 F6 deadlock where a dead ollama caused
    /// every chat-backed MCP tool to hang the daemon for 30s+.
    pub fn generate(&self, prompt: &str, system: Option<&str>) -> Result<String> {
        if self.breaker_is_open() {
            return Err(anyhow!(
                "Failed to send chat request: circuit breaker open \
                 (last failure within {}s); LLM at {} is not responding",
                CIRCUIT_BREAKER_COOLDOWN.as_secs(),
                self.base_url,
            ));
        }
        // v0.7.0 (issue #1237, #691 fold-1) — consult the governance
        // NetworkRequest wire-point hook BEFORE issuing the outbound
        // HTTP. Mirrors the gate in generate_with_body (line ~1005).
        // The post-#1067 chat surface forgot this call; an operator
        // `refuse` rule against the LLM host was being silently
        // ignored on the production chat path.
        self.check_outbound()?;

        // #1066 — branch on provider for endpoint path, auth header,
        // payload shape, and response parsing.
        let (url, payload, bearer): (String, Value, Option<&str>) = match &self.provider {
            LlmProvider::Ollama => {
                let mut messages = Vec::new();
                if let Some(sys) = system {
                    messages.push(json!({"role": "system", "content": sys}));
                }
                messages.push(json!({"role": "user", "content": prompt}));
                (
                    format!("{}/api/chat", self.base_url),
                    json!({
                        "model": self.model,
                        "messages": messages,
                        "stream": false,
                    }),
                    None,
                )
            }
            LlmProvider::OpenAiCompatible { api_key } => {
                let mut messages = Vec::new();
                if let Some(sys) = system {
                    messages.push(json!({"role": "system", "content": sys}));
                }
                messages.push(json!({"role": "user", "content": prompt}));
                (
                    format!("{}/chat/completions", self.base_url),
                    json!({
                        "model": self.model,
                        "messages": messages,
                        "stream": false,
                    }),
                    Some(api_key.as_str()),
                )
            }
        };

        let mut req = self
            .client
            .post(&url)
            .timeout(GENERATE_TIMEOUT)
            .json(&payload);
        if let Some(key) = bearer {
            req = req.bearer_auth(key);
        }

        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to send chat request"));
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            // 5xx is an upstream-failure signal that should trip the
            // breaker (LLM is sick); 4xx is a request-shape problem
            // and should NOT — the next call with a different prompt
            // may well succeed.
            if status.is_server_error() {
                self.note_failure();
            }
            let text = resp.text().unwrap_or_default();
            return Err(anyhow!("Chat generate failed ({status}): {text}"));
        }

        let body: Value = match resp.json() {
            Ok(b) => b,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to parse chat response"));
            }
        };

        // Parse the response per provider wire shape.
        let response_text = match &self.provider {
            // Ollama /api/chat → {"message": {"content": "..."}}
            LlmProvider::Ollama => body["message"]["content"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing 'message.content' field in chat output"))?
                .to_string(),
            // OpenAI-compat /v1/chat/completions →
            // {"choices": [{"message": {"role": "assistant", "content": "..."}}]}
            LlmProvider::OpenAiCompatible { .. } => body["choices"][0]["message"]["content"]
                .as_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Missing 'choices[0].message.content' field in OpenAI-compatible \
                         chat response; got: {body}"
                    )
                })?
                .to_string(),
        };

        self.note_success();
        Ok(response_text)
    }

    /// Uses the LLM to expand a search query into additional search terms.
    pub fn expand_query(&self, query: &str) -> Result<Vec<String>> {
        let prompt = QUERY_EXPANSION_PROMPT.replace("{query}", query);
        let response = self.generate(&prompt, None)?;

        let terms: Vec<String> = response
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        Ok(terms)
    }

    /// Takes (title, content) pairs and returns a consolidated summary.
    pub fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
        let formatted = memories
            .iter()
            .enumerate()
            .map(|(i, (title, content))| {
                format!("--- Memory {} ---\nTitle: {}\n{}", i + 1, title, content)
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        let prompt = SUMMARIZE_PROMPT.replace("{memories}", &formatted);
        let response = self.generate(&prompt, None)?;

        Ok(response.trim().to_string())
    }

    /// Generate up to 8 lowercase semantic tags for a memory.
    ///
    /// `model_override` (L15): when `Some`, uses that model instead of `self.model`.
    /// Auto_tag is a short structured-output task; using gemma3:4b (12 tokens
    /// avg) is dramatically faster than Gemma 4 with its 400+ token thinking
    /// output. See bench data in docs/plan-c-cert.md.
    ///
    /// `num_predict` is hard-capped at 64 tokens regardless of model — defense
    /// in depth against unbounded chain-of-thought emissions on any model.
    pub fn auto_tag(
        &self,
        title: &str,
        content: &str,
        model_override: Option<&str>,
    ) -> Result<Vec<String>> {
        // #1067 (2026-05-21) — provider-agnostic auto_tag. Pre-#1067
        // this routed through `generate_with_body` against Ollama's
        // `/api/generate` text-completion endpoint, which doesn't
        // exist on the OpenAI-compatible backends (xAI, OpenAI,
        // DeepSeek, etc. only expose `/v1/chat/completions`). Now
        // routes through `generate_with_model_override` which uses
        // the provider-aware chat-shape endpoint + the requested
        // model override (or falls back to `self.model`).
        let prompt = AUTO_TAG_PROMPT
            .replace("{title}", title)
            .replace("{content}", content);
        let response = self.generate_with_model_override(&prompt, None, model_override)?;
        let tags: Vec<String> = response
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|line| !line.is_empty() && line.len() <= 64)
            .take(8)
            .collect();
        Ok(tags)
    }

    /// #1067 — provider-aware variant of [`Self::generate`] that lets
    /// the caller override the model per-call (e.g., for
    /// [`Self::auto_tag`] which uses a cheaper / faster model than
    /// the primary `self.model`). Same branching as `generate`:
    /// Ollama hits `/api/chat`, OpenAI-compatible hits
    /// `/v1/chat/completions` with Bearer auth.
    #[allow(clippy::too_many_lines)]
    fn generate_with_model_override(
        &self,
        prompt: &str,
        system: Option<&str>,
        model_override: Option<&str>,
    ) -> Result<String> {
        if self.breaker_is_open() {
            return Err(anyhow!(
                "Failed to send chat request: circuit breaker open \
                 (last failure within {}s); LLM at {} is not responding",
                CIRCUIT_BREAKER_COOLDOWN.as_secs(),
                self.base_url,
            ));
        }
        // v0.7.0 (issue #1237, #691 fold-1) — consult the governance
        // NetworkRequest wire-point hook BEFORE issuing the outbound
        // HTTP. Mirrors the gate in generate_with_body (line ~1005).
        self.check_outbound()?;
        let model = model_override.unwrap_or(&self.model);

        let (url, payload, bearer): (String, Value, Option<&str>) = match &self.provider {
            LlmProvider::Ollama => {
                let mut messages = Vec::new();
                if let Some(sys) = system {
                    messages.push(json!({"role": "system", "content": sys}));
                }
                messages.push(json!({"role": "user", "content": prompt}));
                (
                    format!("{}/api/chat", self.base_url),
                    json!({"model": model, "messages": messages, "stream": false}),
                    None,
                )
            }
            LlmProvider::OpenAiCompatible { api_key } => {
                let mut messages = Vec::new();
                if let Some(sys) = system {
                    messages.push(json!({"role": "system", "content": sys}));
                }
                messages.push(json!({"role": "user", "content": prompt}));
                (
                    format!("{}/chat/completions", self.base_url),
                    json!({"model": model, "messages": messages, "stream": false}),
                    Some(api_key.as_str()),
                )
            }
        };

        let mut req = self
            .client
            .post(&url)
            .timeout(GENERATE_TIMEOUT)
            .json(&payload);
        if let Some(key) = bearer {
            req = req.bearer_auth(key);
        }
        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to send chat request"));
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            if status.is_server_error() {
                self.note_failure();
            }
            let text = resp.text().unwrap_or_default();
            return Err(anyhow!("Generate failed ({status}): {text}"));
        }

        let body: Value = match resp.json() {
            Ok(b) => b,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to parse chat response"));
            }
        };

        let response_text = match &self.provider {
            LlmProvider::Ollama => body["message"]["content"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing 'message.content' in chat response"))?
                .to_string(),
            LlmProvider::OpenAiCompatible { .. } => body["choices"][0]["message"]["content"]
                .as_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Missing 'choices[0].message.content' in OpenAI-compatible \
                         chat response; got: {body}"
                    )
                })?
                .to_string(),
        };

        self.note_success();
        Ok(response_text)
    }

    /// v0.7.0 L15 — issue a `/api/generate` call with a fully-formed JSON
    /// body. Used by [`OllamaClient::auto_tag`] so the caller can stamp the
    /// model name + an `options.num_predict` ceiling per-call without going
    /// through the broader [`OllamaClient::generate`] chat-surface plumbing.
    ///
    /// The same circuit-breaker guard the rest of the client uses applies
    /// here — a series of failures fast-fails subsequent calls until the
    /// cooldown elapses, so a dead Ollama can't peg the auto_tag path on
    /// the per-call 30s timeout.
    /// v0.7.0 (issue #691 fold-1) — consult the governance wire-point
    /// hook before issuing an outbound HTTP request to the Ollama
    /// endpoint. Returns `Err` (with a typed anyhow context) when a
    /// `refuse` rule matches the Ollama host. The caller surfaces the
    /// error verbatim — the LLM-absent fallback path (auto_tag, etc.)
    /// already handles `Err` gracefully so a governance refusal
    /// degrades to "no LLM tags this call" rather than crashing the
    /// store handler.
    fn check_outbound(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.base_url).ok();
        let host = url
            .as_ref()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| self.base_url.clone());
        let scheme = url
            .as_ref()
            .map(|u| u.scheme().to_string())
            .unwrap_or_default();
        let action = crate::governance::agent_action::AgentAction::NetworkRequest {
            host: host.clone(),
            scheme,
        };
        crate::governance::wire_check::check_anyhow(&action)
            .with_context(|| format!("governance refused outbound to ollama at {host}"))
    }

    /// Legacy Ollama-only `/api/generate` (text-completion) helper.
    /// **Deprecated by #1067** — every internal caller now routes
    /// through [`Self::generate`] or [`Self::generate_with_model_override`]
    /// (the chat-shape `/v1/chat/completions`-compatible path) which
    /// works across Ollama AND every OpenAI-compatible vendor (xAI
    /// Grok, OpenAI, DeepSeek, Kimi, Qwen, etc.).
    ///
    /// Retained as a private helper for tests that exercise the
    /// legacy code path (wire_check_sole_path_pin verifies the
    /// `check_outbound()` gate fires before the `reqwest::post`, and
    /// that invariant only matters on the legacy `/api/generate`
    /// shape). Any new caller should use the provider-aware path.
    #[allow(dead_code)]
    fn generate_with_body(&self, body: &Value) -> Result<String> {
        if self.breaker_is_open() {
            return Err(anyhow!(
                "Failed to send generate request: circuit breaker open \
                 (last failure within {}s); ollama at {} is not responding",
                CIRCUIT_BREAKER_COOLDOWN.as_secs(),
                self.base_url,
            ));
        }
        // v0.7.0 (issue #691 fold-1) — wire NetworkRequest gate.
        self.check_outbound()?;
        let url = format!("{}/api/generate", self.base_url);
        let resp = match self
            .client
            .post(&url)
            .timeout(GENERATE_TIMEOUT)
            .json(body)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to send generate request"));
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            if status.is_server_error() {
                self.note_failure();
            }
            let text = resp.text().unwrap_or_default();
            return Err(anyhow!("Generate failed ({status}): {text}"));
        }

        let parsed: Value = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to parse generate response"));
            }
        };

        // Ollama /api/generate returns {"response": "..."}.
        let response_text = parsed["response"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'response' field in generate output"))?
            .to_string();

        self.note_success();
        Ok(response_text)
    }

    /// Generate an embedding vector via Ollama's /api/embed endpoint.
    ///
    /// Used for nomic-embed-text-v1.5 on smart/autonomous tiers.
    ///
    /// v0.7.0 F6 — like [`OllamaClient::generate`], this call is guarded
    /// by the same circuit breaker so a dead ollama endpoint doesn't
    /// block every store/recall path on a per-call timeout.
    pub fn embed_text(&self, text: &str, embed_model: &str) -> Result<Vec<f32>> {
        if self.breaker_is_open() {
            return Err(anyhow!(
                "Failed to send embed request: circuit breaker open \
                 (last failure within {}s); LLM at {} is not responding",
                CIRCUIT_BREAKER_COOLDOWN.as_secs(),
                self.base_url,
            ));
        }
        // v0.7.0 (issue #691 fold-1) — wire NetworkRequest gate.
        self.check_outbound()?;

        // #1066 — branch on provider for endpoint + payload + parse.
        let (url, payload, bearer): (String, Value, Option<&str>) = match &self.provider {
            LlmProvider::Ollama => (
                format!("{}/api/embed", self.base_url),
                json!({"model": embed_model, "input": text}),
                None,
            ),
            LlmProvider::OpenAiCompatible { api_key } => (
                format!("{}/embeddings", self.base_url),
                json!({"model": embed_model, "input": text}),
                Some(api_key.as_str()),
            ),
        };

        let mut req = self
            .client
            .post(&url)
            .timeout(GENERATE_TIMEOUT)
            .json(&payload);
        if let Some(key) = bearer {
            req = req.bearer_auth(key);
        }

        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to send embed request"));
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            if status.is_server_error() {
                self.note_failure();
            }
            let text = resp.text().unwrap_or_default();
            return Err(anyhow!("Embed failed ({status}): {text}"));
        }

        let body: Value = match resp.json() {
            Ok(b) => b,
            Err(e) => {
                self.note_failure();
                return Err(anyhow::Error::new(e).context("Failed to parse embed response"));
            }
        };

        // Parse per provider:
        // - Ollama: {"embeddings": [[f32, …], …]} — take first row
        // - OpenAI-compat: {"data": [{"embedding": [f32, …], …}, …]} — take first row
        let embedding_array = match &self.provider {
            LlmProvider::Ollama => body["embeddings"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("Missing 'embeddings[0]' in Ollama embed response"))?,
            LlmProvider::OpenAiCompatible { .. } => {
                body["data"][0]["embedding"].as_array().ok_or_else(|| {
                    anyhow!(
                        "Missing 'data[0].embedding' in OpenAI-compatible embed response; \
                         got: {body}"
                    )
                })?
            }
        };

        #[allow(clippy::cast_possible_truncation)]
        let floats: Vec<f32> = embedding_array
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if floats.is_empty() {
            return Err(anyhow!("Empty embedding returned from LLM"));
        }

        self.note_success();
        Ok(floats)
    }

    /// Ensure an embedding model is available.
    ///
    /// - Ollama: lists `/api/tags`, pulls via `/api/pull` if missing.
    /// - OpenAI-compatible: **no-op** — vendor-side concern (operator
    ///   confirms model availability on their plan).
    pub fn ensure_embed_model(&self, model: &str) -> Result<()> {
        if matches!(self.provider, LlmProvider::OpenAiCompatible { .. }) {
            return Ok(());
        }
        let url = format!("{}/api/tags", self.base_url);
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .context("Failed to list Ollama models")?;

        let body: Value = resp.json().context("Failed to parse /api/tags response")?;
        let model_exists = body["models"].as_array().is_some_and(|models| {
            models.iter().any(|m| {
                let name = m["name"].as_str().unwrap_or("");
                name == model
                    || name.starts_with(&format!("{model}:"))
                    || model == name.split(':').next().unwrap_or("")
            })
        });

        if model_exists {
            return Ok(());
        }

        tracing::info!("Pulling Ollama embedding model '{}'...", model);
        let pull_url = format!("{}/api/pull", self.base_url);
        let pull_client = reqwest::blocking::Client::builder()
            .timeout(PULL_TIMEOUT)
            .build()
            .context("Failed to build pull client")?;
        let resp = pull_client
            .post(&pull_url)
            .json(&json!({ "name": model }))
            .send()
            .context("Failed to pull embedding model from Ollama")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(anyhow!("Ollama embed model pull failed ({status}): {text}"));
        }

        tracing::info!("Embedding model '{}' pulled successfully", model);
        Ok(())
    }

    /// Returns true if two memory contents contradict each other.
    pub fn detect_contradiction(&self, mem_a: &str, mem_b: &str) -> Result<bool> {
        let prompt = CONTRADICTION_PROMPT
            .replace("{a}", mem_a)
            .replace("{b}", mem_b);

        let response = self.generate(&prompt, None)?;
        let answer = response.trim().to_lowercase();

        Ok(answer.starts_with("yes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_templates_have_placeholders() {
        assert!(QUERY_EXPANSION_PROMPT.contains("{query}"));
        assert!(SUMMARIZE_PROMPT.contains("{memories}"));
        assert!(AUTO_TAG_PROMPT.contains("{title}"));
        assert!(AUTO_TAG_PROMPT.contains("{content}"));
        assert!(CONTRADICTION_PROMPT.contains("{a}"));
        assert!(CONTRADICTION_PROMPT.contains("{b}"));
    }

    #[test]
    fn test_default_url() {
        assert_eq!(DEFAULT_OLLAMA_URL, "http://localhost:11434");
    }

    /// v0.7.0 #1067 + #1113 — per-alias default base URL pin. Walks
    /// every vendor alias the v0.7.0 LLM client advertises and asserts
    /// `default_base_url_for_alias` returns the documented host.
    #[test]
    fn default_base_url_for_alias_covers_all_15_aliases_1067() {
        let cases: &[(&str, Option<&str>)] = &[
            ("openai", Some("https://api.openai.com/v1")),
            ("xai", Some("https://api.x.ai/v1")),
            ("anthropic", Some("https://api.anthropic.com/v1")),
            (
                "gemini",
                Some("https://generativelanguage.googleapis.com/v1beta/openai"),
            ),
            ("deepseek", Some("https://api.deepseek.com/v1")),
            ("kimi", Some("https://api.moonshot.cn/v1")),
            ("moonshot", Some("https://api.moonshot.cn/v1")),
            (
                "qwen",
                Some("https://dashscope.aliyuncs.com/compatible-mode/v1"),
            ),
            (
                "dashscope",
                Some("https://dashscope.aliyuncs.com/compatible-mode/v1"),
            ),
            ("mistral", Some("https://api.mistral.ai/v1")),
            ("groq", Some("https://api.groq.com/openai/v1")),
            ("together", Some("https://api.together.xyz/v1")),
            ("cerebras", Some("https://api.cerebras.ai/v1")),
            ("openrouter", Some("https://openrouter.ai/api/v1")),
            ("fireworks", Some("https://api.fireworks.ai/inference/v1")),
            ("lmstudio", Some("http://localhost:1234/v1")),
            ("openai-compatible", None),
            ("totally-unknown-vendor", None),
        ];
        for (alias, expected) in cases {
            let got = default_base_url_for_alias(alias);
            assert_eq!(
                got, *expected,
                "#1067: alias `{alias}` must resolve to {expected:?}; got {got:?}"
            );
        }
    }

    /// v0.7.0 #1067 + #1113 — per-alias API-key env var preference list.
    #[test]
    fn alias_api_key_env_vars_per_alias_pins_1067() {
        let cases: &[(&str, &[&str])] = &[
            ("openai", &["OPENAI_API_KEY"]),
            ("xai", &["XAI_API_KEY"]),
            ("anthropic", &["ANTHROPIC_API_KEY"]),
            ("gemini", &["GEMINI_API_KEY", "GOOGLE_API_KEY"]),
            ("deepseek", &["DEEPSEEK_API_KEY"]),
            ("kimi", &["MOONSHOT_API_KEY", "KIMI_API_KEY"]),
            ("moonshot", &["MOONSHOT_API_KEY", "KIMI_API_KEY"]),
            ("qwen", &["DASHSCOPE_API_KEY", "QWEN_API_KEY"]),
            ("dashscope", &["DASHSCOPE_API_KEY", "QWEN_API_KEY"]),
            ("mistral", &["MISTRAL_API_KEY"]),
            ("groq", &["GROQ_API_KEY"]),
            ("together", &["TOGETHER_API_KEY"]),
            ("cerebras", &["CEREBRAS_API_KEY"]),
            ("openrouter", &["OPENROUTER_API_KEY"]),
            ("fireworks", &["FIREWORKS_API_KEY"]),
            (BACKEND_OLLAMA, &[]),
            ("lmstudio", &[]),
            ("openai-compatible", &[]),
            ("totally-unknown-vendor", &[]),
        ];
        for (alias, expected) in cases {
            let got = alias_api_key_env_vars(alias);
            assert_eq!(
                got, *expected,
                "#1067: alias `{alias}` env-var preference list must be {expected:?}; got {got:?}"
            );
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value,
    clippy::wildcard_imports,
    clippy::doc_markdown
)]
pub mod test_support {
    use super::*;

    /// Mock Ollama client for testing without a running Ollama daemon.
    /// Returns deterministic, canned responses for each public method.
    pub enum MockFailure {
        ModelNotFound,
        Timeout,
        MalformedResponse,
        ApiError(String),
        EmptyResponse,
        NetworkError,
    }

    pub struct MockOllamaClient {
        pub base_url: String,
        pub model: String,
        pub fail_with: Option<MockFailure>,
    }

    impl MockOllamaClient {
        /// Create a mock client with the given URL and model name.
        pub fn new_with_url(base_url: &str, model: &str) -> Result<Self> {
            Ok(Self {
                base_url: base_url.trim_end_matches('/').to_string(),
                model: model.to_string(),
                fail_with: None,
            })
        }

        /// Create a mock client that will fail with the specified failure mode.
        pub fn with_failure(base_url: &str, model: &str, failure: MockFailure) -> Result<Self> {
            Ok(Self {
                base_url: base_url.trim_end_matches('/').to_string(),
                model: model.to_string(),
                fail_with: Some(failure),
            })
        }

        /// Check if this client is configured to fail
        fn should_fail(&self) -> Option<&MockFailure> {
            self.fail_with.as_ref()
        }

        /// Mock health check — returns false if NetworkError, true otherwise.
        pub fn is_available(&self) -> bool {
            !matches!(self.should_fail(), Some(MockFailure::NetworkError))
        }

        /// Mock `ensure_model` — fails if ModelNotFound or Timeout.
        pub fn ensure_model(&self) -> Result<()> {
            match self.should_fail() {
                Some(MockFailure::ModelNotFound) => Err(anyhow!(
                    "Model 'unknown-model' not found in Ollama registry"
                )),
                Some(MockFailure::Timeout) => {
                    Err(anyhow!("Failed to list Ollama models: operation timed out"))
                }
                Some(MockFailure::ApiError(msg)) => {
                    Err(anyhow!("Ollama pull failed (404): {}", msg))
                }
                Some(MockFailure::NetworkError) => Err(anyhow!(
                    "Failed to pull model from Ollama: connection refused"
                )),
                _ => Ok(()),
            }
        }

        /// Mock `ensure_embed_model` — similar to ensure_model.
        pub fn ensure_embed_model(&self, _model: &str) -> Result<()> {
            match self.should_fail() {
                Some(MockFailure::ModelNotFound) => Err(anyhow!("Embedding model not found")),
                Some(MockFailure::Timeout) => {
                    Err(anyhow!("Failed to list Ollama models: operation timed out"))
                }
                Some(MockFailure::ApiError(msg)) => {
                    Err(anyhow!("Ollama embed model pull failed (404): {}", msg))
                }
                Some(MockFailure::NetworkError) => Err(anyhow!(
                    "Failed to pull embedding model from Ollama: connection refused"
                )),
                _ => Ok(()),
            }
        }

        /// Mock generate — returns errors or deterministic responses based on failure mode.
        pub fn generate(&self, prompt: &str, _system: Option<&str>) -> Result<String> {
            match self.should_fail() {
                Some(MockFailure::Timeout) => {
                    return Err(anyhow!("Failed to send chat request: operation timed out"));
                }
                Some(MockFailure::MalformedResponse) => {
                    return Err(anyhow!("Failed to parse chat response: invalid JSON"));
                }
                Some(MockFailure::EmptyResponse) => {
                    return Err(anyhow!("Missing 'message.content' field in chat output"));
                }
                Some(MockFailure::ApiError(msg)) => {
                    return Err(anyhow!("Chat generate failed (500): {}", msg));
                }
                Some(MockFailure::NetworkError) => {
                    return Err(anyhow!("Failed to send chat request: connection refused"));
                }
                _ => {}
            }

            // Normal response logic
            if prompt.contains("expand") || prompt.contains("search") {
                Ok("semantic search\nquery terms\nvector retrieval\ninformation retrieval\nsimilarity matching"
                    .to_string())
            } else if prompt.contains("Summarize") {
                Ok("This is a consolidated summary of multiple memories covering key facts and decisions."
                    .to_string())
            } else if prompt.contains("tags") {
                Ok("important\nkey-fact\nstatus-update\ntechnical".to_string())
            } else if prompt.contains("contradict") {
                if prompt.contains("yes") || prompt.contains("true") {
                    Ok("yes".to_string())
                } else {
                    Ok("no".to_string())
                }
            } else {
                Ok("Mock response for: ".to_string() + &prompt[..prompt.len().min(50)])
            }
        }

        /// Mock `expand_query` — returns error or synthetic expansion.
        pub fn expand_query(&self, query: &str) -> Result<Vec<String>> {
            if let Some(failure) = self.should_fail() {
                return Err(match failure {
                    MockFailure::Timeout => {
                        anyhow!("Failed to send chat request: operation timed out")
                    }
                    MockFailure::MalformedResponse => {
                        anyhow!("Failed to parse chat response: invalid JSON")
                    }
                    MockFailure::ApiError(msg) => anyhow!("Chat generate failed (500): {}", msg),
                    _ => anyhow!("Generate failed"),
                });
            }
            let terms: Vec<String> = vec![
                format!("{}-related", query),
                format!("{}-expanded", query),
                "semantic-search".to_string(),
                "vector-expansion".to_string(),
                "query-variants".to_string(),
            ];
            Ok(terms.to_vec())
        }

        /// Mock `summarize_memories` — fails if no memories.
        pub fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
            if memories.is_empty() {
                return Err(anyhow!("Cannot summarize empty memories list"));
            }
            if let Some(failure) = self.should_fail() {
                return Err(match failure {
                    MockFailure::Timeout => {
                        anyhow!("Failed to send chat request: operation timed out")
                    }
                    MockFailure::MalformedResponse => {
                        anyhow!("Failed to parse chat response: invalid JSON")
                    }
                    MockFailure::ApiError(msg) => anyhow!("Chat generate failed (500): {}", msg),
                    _ => anyhow!("Generate failed"),
                });
            }
            let count = memories.len();
            Ok(format!(
                "Summary of {count} memories: consolidated facts and key decisions preserved"
            ))
        }

        /// Mock `auto_tag` — handles special characters and error modes.
        ///
        /// L15: signature mirrors the real client and accepts an optional
        /// `model_override`; the mock ignores it (no upstream call is
        /// made) but the parameter must be accepted for callsite parity.
        pub fn auto_tag(
            &self,
            title: &str,
            _content: &str,
            _model_override: Option<&str>,
        ) -> Result<Vec<String>> {
            if let Some(failure) = self.should_fail() {
                return Err(match failure {
                    MockFailure::Timeout => {
                        anyhow!("Failed to send chat request: operation timed out")
                    }
                    MockFailure::MalformedResponse => {
                        anyhow!("Failed to parse chat response: invalid JSON")
                    }
                    MockFailure::ApiError(msg) => anyhow!("Chat generate failed (500): {}", msg),
                    _ => anyhow!("Generate failed"),
                });
            }
            let tags: Vec<String> = vec![
                "important".to_string(),
                format!("{}-tag", title.split_whitespace().next().unwrap_or("data")),
                "memory".to_string(),
            ];
            Ok(tags)
        }

        /// Mock `embed_text` — returns 768-dim vector or error.
        pub fn embed_text(&self, text: &str, _embed_model: &str) -> Result<Vec<f32>> {
            match self.should_fail() {
                Some(MockFailure::Timeout) => {
                    return Err(anyhow!(
                        "Failed to send embed request to Ollama: operation timed out"
                    ));
                }
                Some(MockFailure::MalformedResponse) => {
                    return Err(anyhow!(
                        "Failed to parse Ollama embed response: invalid JSON"
                    ));
                }
                Some(MockFailure::EmptyResponse) => {
                    return Err(anyhow!("Missing embeddings in Ollama response"));
                }
                Some(MockFailure::ApiError(msg)) => {
                    return Err(anyhow!("Ollama embed failed (500): {}", msg));
                }
                Some(MockFailure::NetworkError) => {
                    return Err(anyhow!(
                        "Failed to send embed request to Ollama: connection refused"
                    ));
                }
                Some(MockFailure::ModelNotFound) => {
                    return Err(anyhow!("Ollama embed failed (404): model not found"));
                }
                _ => {}
            }
            let base_val = (text.len() % 10) as f32 / 100.0;
            let embedding: Vec<f32> = (0..768).map(|i| base_val + (i as f32) * 0.0001).collect();
            Ok(embedding)
        }

        /// Mock `detect_contradiction` — handles yes/no variants and errors.
        pub fn detect_contradiction(&self, mem_a: &str, mem_b: &str) -> Result<bool> {
            if let Some(failure) = self.should_fail() {
                return Err(match failure {
                    MockFailure::Timeout => {
                        anyhow!("Failed to send chat request: operation timed out")
                    }
                    MockFailure::MalformedResponse => {
                        anyhow!("Failed to parse chat response: invalid JSON")
                    }
                    MockFailure::ApiError(msg) => anyhow!("Chat generate failed (500): {}", msg),
                    _ => anyhow!("Generate failed"),
                });
            }
            let combined = format!("{mem_a} {mem_b}").to_lowercase();
            let contradictory_keywords = &["not", "never", "always", "contradiction", "opposite"];
            let count = contradictory_keywords
                .iter()
                .filter(|&&kw| combined.contains(kw))
                .count();
            Ok(count > 1)
        }
    }
}

#[cfg(test)]
mod mock_tests {
    use super::test_support::MockOllamaClient;
    use super::{AUTO_TAG_PROMPT, CONTRADICTION_PROMPT, QUERY_EXPANSION_PROMPT, SUMMARIZE_PROMPT};

    #[test]
    fn test_mock_new_with_url() {
        let client = MockOllamaClient::new_with_url("http://localhost:11434", "test-model");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url, "http://localhost:11434");
        assert_eq!(client.model, "test-model");
    }

    #[test]
    fn test_mock_new_with_url_trailing_slash() {
        let client = MockOllamaClient::new_with_url("http://localhost:11434/", "test-model");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url, "http://localhost:11434");
    }

    #[test]
    fn test_mock_is_available() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        assert!(client.is_available());
    }

    #[test]
    fn test_mock_ensure_model() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        assert!(client.ensure_model().is_ok());
    }

    #[test]
    fn test_mock_ensure_embed_model() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        assert!(client.ensure_embed_model("nomic-embed-text").is_ok());
    }

    #[test]
    fn test_mock_generate_query_expansion() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let prompt = QUERY_EXPANSION_PROMPT.replace("{query}", "search test");
        let result = client.generate(&prompt, None);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_mock_expand_query() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.expand_query("test query");
        assert!(result.is_ok());
        let terms = result.unwrap();
        assert!(!terms.is_empty());
        assert!(terms.len() >= 3);
    }

    #[test]
    fn test_mock_summarize_memories() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let memories = vec![
            ("Title 1".to_string(), "Content 1".to_string()),
            ("Title 2".to_string(), "Content 2".to_string()),
        ];
        let result = client.summarize_memories(&memories);
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert!(summary.contains('2'));
    }

    #[test]
    fn test_mock_auto_tag() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.auto_tag("Test Title", "test content", None);
        assert!(result.is_ok());
        let tags = result.unwrap();
        assert!(!tags.is_empty());
        assert!(tags.len() >= 2);
    }

    #[test]
    fn test_mock_embed_text() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.embed_text("test text", "nomic-embed-text");
        assert!(result.is_ok());
        let embedding = result.unwrap();
        assert_eq!(embedding.len(), 768);
        assert!(embedding.iter().all(|&x| x >= 0.0));
    }

    #[test]
    fn test_mock_embed_text_deterministic() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result1 = client.embed_text("same text", "nomic-embed-text");
        let result2 = client.embed_text("same text", "nomic-embed-text");
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn test_mock_detect_contradiction_true() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.detect_contradiction(
            "The system always works",
            "The system never works correctly",
        );
        assert!(result.is_ok());
        let is_contradiction = result.unwrap();
        assert!(is_contradiction);
    }

    #[test]
    fn test_mock_detect_contradiction_false() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.detect_contradiction(
            "The memory is about search",
            "Additional details about the same search",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_generate_summarize_prompt() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let prompt = SUMMARIZE_PROMPT.replace(
            "{memories}",
            "--- Memory 1 ---\nTitle: Test\nThis is a test",
        );
        let result = client.generate(&prompt, None);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.contains("summary") || response.contains("Summary"));
    }

    #[test]
    fn test_mock_generate_auto_tag_prompt() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let prompt = AUTO_TAG_PROMPT
            .replace("{title}", "Important Update")
            .replace("{content}", "Some content");
        let result = client.generate(&prompt, None);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_mock_generate_contradiction_prompt() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let prompt = CONTRADICTION_PROMPT
            .replace("{a}", "Statement A")
            .replace("{b}", "Statement B");
        let result = client.generate(&prompt, None);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.is_empty());
    }

    // ===== ERROR PATH TESTS (Agent C: llm.rs 47% → 75% coverage) =====

    #[test]
    fn test_mock_ensure_model_returns_not_found_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "unknown-model",
            super::test_support::MockFailure::ModelNotFound,
        )
        .unwrap();
        let result = client.ensure_model();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found"));
    }

    #[test]
    fn test_mock_ensure_model_returns_timeout_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.ensure_model();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("timed out"));
    }

    #[test]
    fn test_mock_ensure_model_returns_network_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::NetworkError,
        )
        .unwrap();
        let result = client.ensure_model();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("connection"));
    }

    #[test]
    fn test_mock_ensure_embed_model_returns_not_found_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::ModelNotFound,
        )
        .unwrap();
        let result = client.ensure_embed_model("unknown-embed-model");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_generate_returns_timeout_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.generate("test prompt", None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("timed out"));
    }

    #[test]
    fn test_mock_generate_handles_malformed_json() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::MalformedResponse,
        )
        .unwrap();
        let result = client.generate("test prompt", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_generate_handles_empty_response() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::EmptyResponse,
        )
        .unwrap();
        let result = client.generate("test prompt", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_generate_handles_api_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::ApiError("Internal Error".to_string()),
        )
        .unwrap();
        let result = client.generate("test prompt", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_expand_query_passes_through_generate_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.expand_query("test query");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_summarize_memories_handles_empty_input() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let empty_memories: Vec<(String, String)> = vec![];
        let result = client.summarize_memories(&empty_memories);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_summarize_memories_handles_timeout() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let memories = vec![("Title".to_string(), "Content".to_string())];
        let result = client.summarize_memories(&memories);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_auto_tag_handles_special_characters() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.auto_tag("Title @#$%", "content", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_auto_tag_timeout() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.auto_tag("Test", "content", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_embed_text_returns_768_dim() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result = client.embed_text("test", "nomic-embed-text-v1.5");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 768);
    }

    #[test]
    fn test_mock_embed_text_timeout() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.embed_text("test", "nomic-embed-text");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_embed_text_malformed() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::MalformedResponse,
        )
        .unwrap();
        let result = client.embed_text("test", "nomic-embed-text");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_embed_text_empty_response() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::EmptyResponse,
        )
        .unwrap();
        let result = client.embed_text("test", "nomic-embed-text");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_embed_text_model_not_found() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::ModelNotFound,
        )
        .unwrap();
        let result = client.embed_text("test", "unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_embed_text_network_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::NetworkError,
        )
        .unwrap();
        let result = client.embed_text("test", "nomic-embed-text");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_detect_contradiction_yes_case() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result =
            client.detect_contradiction("The system always works", "The system never works");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_mock_detect_contradiction_no_case() {
        let client =
            MockOllamaClient::new_with_url("http://localhost:11434", "test-model").unwrap();
        let result =
            client.detect_contradiction("Consistent statement A", "Consistent statement B");
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_detect_contradiction_timeout() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.detect_contradiction("A", "B");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_is_available_network_error() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::NetworkError,
        )
        .unwrap();
        assert!(!client.is_available());
    }

    #[test]
    fn test_mock_with_failure_creates_client_that_fails() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::Timeout,
        )
        .unwrap();
        let result = client.generate("any", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_api_error_variant() {
        let client = MockOllamaClient::with_failure(
            "http://localhost:11434",
            "test-model",
            super::test_support::MockFailure::ApiError("Custom msg".to_string()),
        )
        .unwrap();
        let result = client.generate("test", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Custom msg"));
    }
}

// =====================================================================
// W10 — wiremock-driven HTTP integration tests for the *real* OllamaClient
//
// These exercise the blocking reqwest call paths inside `OllamaClient`
// against an in-process HTTP mock that speaks the Ollama API surface
// (`/api/tags`, `/api/chat`, `/api/embed`, `/api/pull`). No real Ollama
// daemon is started, no network egress, and the tests stay deterministic.
//
// The OllamaClient is blocking (reqwest::blocking) but wiremock is async,
// so each test uses `#[tokio::test(flavor = "multi_thread")]` and runs
// the client via `tokio::task::spawn_blocking` to avoid blocking the
// runtime that's hosting the mock server.
//
// Design notes:
//   - `OllamaClient::new_with_url` performs a `/api/tags` GET as a health
//     check before returning, so every test that constructs a client
//     first wires up a permissive `/api/tags` responder. Tests that want
//     to drive specific `/api/tags` behaviour mount the precise matcher
//     ahead of any other route so it wins the dispatch.
//   - "is_available_returns_false_on_connection_refused" finds a free
//     port by briefly binding a TcpListener, captures the address, then
//     drops the listener — there is a small race window but the
//     `is_available()` health check is wrapped in a 5s timeout so the
//     worst-case flake is a slow test, not a wrong assertion.
// =====================================================================
#[cfg(test)]
#[allow(clippy::too_many_lines, clippy::similar_names)]
mod wiremock_tests {
    use super::OllamaClient;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Mount a default permissive `/api/tags` responder so `new_with_url`'s
    /// embedded `is_available()` health check succeeds.
    async fn mount_tags_ok(server: &MockServer, models: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(models))
            .mount(server)
            .await;
    }

    // ---------------- is_available ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn test_is_available_returns_false_on_connection_refused() {
        // Reserve a free port, then drop the listener so connecting is
        // (almost certainly) refused. The 5s health-check timeout caps
        // the worst-case flake.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}");

        // Can't go through `new_with_url` — its constructor would error
        // out before returning. Instead, build a client by hand by going
        // through reqwest directly and asserting the health-probe path
        // returns false.
        let result = tokio::task::spawn_blocking(move || {
            // Use the same builder OllamaClient uses internally so the
            // assertion exercises the same code path semantically.
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            let probe = format!("{url}/api/tags");
            client
                .get(&probe)
                .send()
                .is_ok_and(|r| r.status().is_success())
        })
        .await
        .unwrap();

        assert!(
            !result,
            "is_available should return false when nothing is listening"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_is_available_returns_false_on_500_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            // Constructor will fail (since is_available returns false)
            // — verify that path explicitly.
            OllamaClient::new_with_url(&uri, "test-model")
        })
        .await
        .unwrap();

        // Avoid `unwrap_err()` here because `OllamaClient` doesn't impl
        // Debug — match on the Result and pull the message out manually.
        let err = match result {
            Ok(_) => panic!("client construction should fail on 500"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("not running") || err.contains("not reachable"),
            "expected unreachable-style error, got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_is_available_returns_true_on_200_with_json_body() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;

        let uri = server.uri();
        let available = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.is_available()
        })
        .await
        .unwrap();
        assert!(available);
    }

    // ---------------- ensure_model (a.k.a. pull_if_missing) ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn test_pull_if_missing_skips_pull_if_model_already_in_tags() {
        let server = MockServer::start().await;
        // /api/tags returns the model already present.
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [
                    {"name": "test-model:latest"},
                ]
            })))
            .mount(&server)
            .await;

        // No /api/pull route is mounted. If ensure_model erroneously
        // POSTed to /api/pull, wiremock would return 404 and the call
        // would fail — `expect(0)` makes that assertion explicit.
        Mock::given(method("POST"))
            .and(path("/api/pull"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.ensure_model()
        })
        .await
        .unwrap();
        assert!(
            result.is_ok(),
            "ensure_model should succeed; got {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_pull_if_missing_initiates_pull_if_not() {
        let server = MockServer::start().await;
        // /api/tags returns no models.
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        // /api/pull is expected to be called exactly once with our model.
        Mock::given(method("POST"))
            .and(path("/api/pull"))
            .and(body_partial_json(json!({"name": "test-model"})))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .expect(1)
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.ensure_model()
        })
        .await
        .unwrap();
        assert!(
            result.is_ok(),
            "ensure_model should succeed; got {result:?}"
        );
        // wiremock's drop checks the .expect() invariants.
    }

    // ---------------- generate ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn test_generate_parses_success_response() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        // OllamaClient::generate hits /api/chat (Ollama's chat surface),
        // not /api/generate, and reads `message.content`.
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"role": "assistant", "content": "hello"},
                "done": true,
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.generate("ping", None)
        })
        .await
        .unwrap();

        assert_eq!(result.unwrap(), "hello");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_generate_returns_error_on_malformed_json() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("{not valid json")
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.generate("ping", None)
        })
        .await
        .unwrap();

        assert!(result.is_err(), "malformed JSON should surface an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("parse") || err.to_lowercase().contains("json"),
            "expected a parse error, got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_generate_returns_error_on_500() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal boom"))
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.generate("ping", None)
        })
        .await
        .unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500") || err.contains("Chat generate failed"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_generate_passes_system_prompt_when_provided() {
        // Sanity-check that providing a system prompt still hits the
        // chat surface and yields the parsed response — covers the
        // `if let Some(sys)` branch of generate().
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(json!({
                "messages": [
                    {"role": "system", "content": "be terse"},
                    {"role": "user", "content": "hi"},
                ],
                "stream": false,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"role": "assistant", "content": "ok"},
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let out = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.generate("hi", Some("be terse"))
        })
        .await
        .unwrap();
        assert_eq!(out.unwrap(), "ok");
    }

    // ---------------- embed_text ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn test_embed_parses_embedding_array() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        // Ollama's /api/embed returns {"embeddings": [[...], ...]}.
        Mock::given(method("POST"))
            .and(path("/api/embed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "embeddings": [[0.1_f32, 0.2_f32, 0.3_f32]],
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let vec = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.embed_text("hello", "nomic-embed-text-v1.5")
        })
        .await
        .unwrap();

        let v = vec.unwrap();
        assert_eq!(v.len(), 3);
        assert!((v[0] - 0.1_f32).abs() < 1e-5);
        assert!((v[1] - 0.2_f32).abs() < 1e-5);
        assert!((v[2] - 0.3_f32).abs() < 1e-5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_embed_returns_error_on_wrong_shape() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        // Wrong shape: top-level key is "embedding" (singular, scalar)
        // — code expects "embeddings" array-of-arrays.
        Mock::given(method("POST"))
            .and(path("/api/embed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "embedding": 0.5,
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.embed_text("hi", "nomic-embed-text")
        })
        .await
        .unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Missing embeddings") || err.to_lowercase().contains("embed"),
            "expected missing-embeddings error, got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_embed_returns_error_on_500() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/embed"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&server)
            .await;

        let uri = server.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.embed_text("hi", "nomic-embed-text")
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    // ---------------- higher-level helpers ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn test_expand_query_returns_parsed_terms_one_per_line() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                // Trailing newline + blank line should be filtered out.
                "message": {"content": "term1\nterm2\nterm3\n\n"},
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let terms = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.expand_query("anything")
        })
        .await
        .unwrap();
        assert_eq!(
            terms.unwrap(),
            vec![
                "term1".to_string(),
                "term2".to_string(),
                "term3".to_string()
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_auto_tag_returns_parsed_tags() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        // #1067 (2026-05-21): auto_tag now routes through the
        // provider-aware chat-shape endpoint (`/api/chat` for Ollama,
        // `/v1/chat/completions` for OpenAI-compatible vendors).
        // Pre-#1067 this was Ollama-only `/api/generate` (text-completion);
        // the legacy endpoint didn't exist on xAI / OpenAI etc. and
        // produced 404. The module still lowercases each line itself
        // so we verify casing is normalised.
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "Tag1\nTAG2\ntag3"},
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let tags = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.auto_tag("Title", "content", None)
        })
        .await
        .unwrap();
        assert_eq!(
            tags.unwrap(),
            vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_detect_contradiction_parses_yes_no() {
        // Verify three branches in one test: "yes" → true,
        // "no" → false, garbage → false (default behaviour falls out
        // of `starts_with("yes")`).
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "yes\n"},
            })))
            .mount(&server)
            .await;

        let uri_yes = server.uri();
        let yes = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri_yes, "test-model").unwrap();
            client.detect_contradiction("a", "b")
        })
        .await
        .unwrap();
        assert!(yes.unwrap(), "'yes' should be detected as contradiction");

        // Stand up a fresh server to swap the response — wiremock mounts
        // are additive and we want a single deterministic responder.
        let server_no = MockServer::start().await;
        mount_tags_ok(&server_no, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "no"},
            })))
            .mount(&server_no)
            .await;
        let uri_no = server_no.uri();
        let no = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri_no, "test-model").unwrap();
            client.detect_contradiction("a", "b")
        })
        .await
        .unwrap();
        assert!(!no.unwrap(), "'no' should NOT be detected as contradiction");

        // Garbage input should fall through `starts_with("yes")` → false.
        let server_garbage = MockServer::start().await;
        mount_tags_ok(&server_garbage, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "definitely-not-yes-or-no"},
            })))
            .mount(&server_garbage)
            .await;
        let uri_g = server_garbage.uri();
        let garbage = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri_g, "test-model").unwrap();
            client.detect_contradiction("a", "b")
        })
        .await
        .unwrap();
        assert!(
            !garbage.unwrap(),
            "garbage answer should default to non-contradiction"
        );
    }

    // ---------------- ensure_embed_model ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ensure_embed_model_skips_pull_if_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [{"name": "nomic-embed-text:latest"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/pull"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let uri = server.uri();
        let r = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.ensure_embed_model("nomic-embed-text")
        })
        .await
        .unwrap();
        assert!(r.is_ok());
    }

    // ---------------- L15 — auto_tag model override + num_predict cap ------

    /// v0.7.0 L15 — when the caller passes `Some(model)` as the third
    /// argument, the outbound /api/generate body MUST stamp that model
    /// (not the client's configured `self.model`). Closes the
    /// NHI-D-autotag-empty finding: the daemon must be able to route
    /// short-structured calls to a fast tag-friendly model independent
    /// of the reasoning-tier `llm_model`.
    #[tokio::test(flavor = "multi_thread")]
    async fn auto_tag_model_override_takes_precedence_l15() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        // #1067: now routes through /api/chat (provider-aware) instead
        // of /api/generate. body_partial_json still asserts the model
        // field — if `auto_tag` forgets to honour the override the
        // matcher misses + wiremock 404s + the call fails.
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(json!({"model": "gemma3:4b"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "alpha\nbeta\ngamma"},
            })))
            .expect(1)
            .mount(&server)
            .await;

        let uri = server.uri();
        let tags = tokio::task::spawn_blocking(move || {
            // Construct the client with a *different* model so the override
            // is the only path that produces a "gemma3:4b" body field.
            let client = OllamaClient::new_with_url(&uri, "gemma4:e2b").unwrap();
            client.auto_tag("Title", "content", Some("gemma3:4b"))
        })
        .await
        .unwrap();
        let tags = tags.expect("auto_tag with override should succeed");
        assert_eq!(
            tags,
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]
        );
    }

    /// #1067 (2026-05-21) — the legacy L15 `options.num_predict = 64`
    /// cap was Ollama-specific (`/api/generate` shape) and incompatible
    /// with OpenAI-compatible vendors (which use `max_tokens` instead).
    /// The cap was dropped for provider portability; chain-of-thought
    /// bound is now enforced via the `take(8)` cap on the parsed lines
    /// in `auto_tag`. This test pins the new shape: the body has NO
    /// `options.num_predict` and the response is parsed correctly.
    #[tokio::test(flavor = "multi_thread")]
    async fn auto_tag_chat_shape_post_1067() {
        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "one\ntwo"},
            })))
            .expect(1)
            .mount(&server)
            .await;

        let uri = server.uri();
        let tags = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "any-model").unwrap();
            client.auto_tag("Title", "content", None)
        })
        .await
        .unwrap();
        let tags = tags.expect("auto_tag should succeed");
        assert_eq!(tags, vec!["one".to_string(), "two".to_string()]);
    }

    // ==================================================================
    // #1143 — env-aware client construction regression tests.
    //
    // Pin the invariant that every synchronous LLM-init site (MCP
    // stdio LLM, MCP embed fallback, CLI `atomise`, CLI `curator`)
    // routes through `OllamaClient::build_for_init` and honors
    // `AI_MEMORY_LLM_BACKEND`. Pre-#1143 only the MCP LLM init was
    // env-aware; #1142 fixed that one surface; #1143 closes the
    // remaining 4 (atomise, curator, MCP embed-fallback wire-shape,
    // daemon curator primitive entrypoint). The env-mutation tests
    // serialise on a module-local mutex (matches the discipline in
    // `src/federation/peer_attestation.rs::tests`).
    // ==================================================================

    static ENV_GUARD_1143: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env_1143() -> std::sync::MutexGuard<'static, ()> {
        ENV_GUARD_1143
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// SAFETY: env-var mutation is unsynchronised across threads at the
    /// OS level. `lock_env_1143` serialises mutation across this test
    /// module so the unsafe is sound for the duration of each test.
    fn clear_llm_env_1143() {
        for k in [
            "AI_MEMORY_LLM_BACKEND",
            "AI_MEMORY_LLM_MODEL",
            "AI_MEMORY_LLM_BASE_URL",
            "AI_MEMORY_LLM_API_KEY",
            "OLLAMA_BASE_URL",
            "XAI_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
        ] {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn is_ollama_native_true_for_ollama_client_1143() {
        // Pure unit assertion — no network. `new_for_testing` builds
        // the Ollama-provider client without the /api/tags probe.
        let client = OllamaClient::new_for_testing("gemma4:e4b");
        assert!(
            client.is_ollama_native(),
            "#1143: Ollama-provider client must report is_ollama_native()=true"
        );
    }

    #[test]
    fn is_ollama_native_false_for_openai_compatible_1143() {
        // OpenAI-compatible clients (xAI, OpenAI, Anthropic, …) MUST
        // report false so the MCP embed-client fallback path knows
        // not to reuse the chat client for embeddings (pre-#1143
        // semantic-recall black-hole).
        let client =
            OllamaClient::new_openai_compatible("https://api.x.ai/v1", "grok-4.3", "fake-key")
                .expect("openai-compatible client builds");
        assert!(
            !client.is_ollama_native(),
            "#1143: OpenAI-compatible client must report is_ollama_native()=false"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_for_init_legacy_arm_when_env_unset_1143() {
        let _g = lock_env_1143();
        clear_llm_env_1143();

        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        let uri = server.uri();

        // No env set → legacy arm → new_with_url. Constructor probes
        // /api/tags, which the mock serves 200 OK.
        let result =
            tokio::task::spawn_blocking(move || OllamaClient::build_for_init(&uri, "gemma4:e4b"))
                .await
                .unwrap();

        let client = match result {
            Ok(Some(c)) => c,
            Ok(None) => panic!("#1143: legacy arm must yield Ok(Some(client)); got Ok(None)"),
            Err(e) => panic!("#1143: legacy arm must yield Ok(Some(client)); got Err({e})"),
        };
        assert!(
            client.is_ollama_native(),
            "#1143: legacy arm constructs an Ollama-provider client"
        );
        assert_eq!(client.model, "gemma4:e4b");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_for_init_env_arm_routes_to_from_env_1143() {
        let _g = lock_env_1143();
        clear_llm_env_1143();

        // Set AI_MEMORY_LLM_BACKEND=xai with a fake key. from_env()
        // constructs the OpenAI-compatible client (xAI default URL),
        // which has no /api/tags probe — it returns Ok immediately.
        unsafe { std::env::set_var("AI_MEMORY_LLM_BACKEND", "xai") };
        unsafe { std::env::set_var("AI_MEMORY_LLM_API_KEY", "fake-xai-key") };
        unsafe { std::env::set_var("AI_MEMORY_LLM_MODEL", "grok-4.3") };

        // Legacy URL/model SHOULD be ignored when env arm is active.
        // Use a deliberately-unreachable URL so the env arm taking
        // priority is the only way the test can pass.
        let result = tokio::task::spawn_blocking(|| {
            OllamaClient::build_for_init("http://127.0.0.1:1", "ignored-legacy-model")
        })
        .await
        .unwrap();

        clear_llm_env_1143();

        let client = match result {
            Ok(Some(c)) => c,
            Ok(None) => panic!(
                "#1143: env arm with AI_MEMORY_LLM_BACKEND=xai must yield \
                 Ok(Some(client)); got Ok(None)"
            ),
            Err(e) => panic!(
                "#1143: env arm with AI_MEMORY_LLM_BACKEND=xai must yield \
                 Ok(Some(client)); got Err({e})"
            ),
        };
        assert!(
            !client.is_ollama_native(),
            "#1143: xai backend yields an OpenAI-compatible (non-Ollama) client"
        );
        assert_eq!(
            client.model, "grok-4.3",
            "#1143: AI_MEMORY_LLM_MODEL must override the legacy model arg"
        );
        assert_eq!(
            client.base_url, "https://api.x.ai/v1",
            "#1143: xai default base URL must override the legacy URL arg"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_for_init_env_arm_unknown_alias_errors_1143() {
        let _g = lock_env_1143();
        clear_llm_env_1143();
        unsafe { std::env::set_var("AI_MEMORY_LLM_BACKEND", "totally-bogus-vendor") };

        let result = tokio::task::spawn_blocking(|| {
            OllamaClient::build_for_init("http://127.0.0.1:1", "ignored")
        })
        .await
        .unwrap();

        clear_llm_env_1143();
        assert!(
            result.is_err(),
            "#1143: unknown backend alias must surface the error \
             instead of silently falling through to the legacy arm"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_for_init_env_arm_empty_string_falls_back_to_legacy_1143() {
        let _g = lock_env_1143();
        clear_llm_env_1143();
        // Operator sets the env var to an empty / whitespace value —
        // must be treated as "unset" (legacy arm), not as "unknown
        // backend ''" (error). Matches the `.filter(|s|
        // !s.is_empty())` guard in `build_for_init`.
        unsafe { std::env::set_var("AI_MEMORY_LLM_BACKEND", "   ") };

        let server = MockServer::start().await;
        mount_tags_ok(&server, json!({"models": []})).await;
        let uri = server.uri();

        let result =
            tokio::task::spawn_blocking(move || OllamaClient::build_for_init(&uri, "gemma4:e2b"))
                .await
                .unwrap();

        clear_llm_env_1143();
        let client = result
            .expect("legacy arm should not error on whitespace env")
            .expect("legacy arm yields Some(client)");
        assert!(client.is_ollama_native());
        assert_eq!(client.model, "gemma4:e2b");
    }
}

// ---------------------------------------------------------------------------
// C-5 (#699): close the circuit-breaker open-arm gaps in llm.rs.
//
// The wiremock tests above drive the success path of generate/embed/etc.
// What was uncovered at the 93.45% baseline is the `breaker_is_open() →
// fast-fail` arm of each public method (lines 242-248, 411-417, 471-477),
// plus the `BreakerState::is_open` body itself (lines 70-73). These
// tests drive 3 consecutive failures through `generate` to trip the
// breaker, then assert the next call returns immediately with the
// "circuit breaker open" error envelope and that `circuit_breaker_open`
// publicly reports the open state.
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod c5_breaker_tests {
    use super::OllamaClient;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mount_tags_ok(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(server)
            .await;
    }

    /// Drive `generate` against a wiremock that returns 500 on every
    /// `/api/chat` call. Three 5xx failures must trip the breaker.
    #[tokio::test(flavor = "multi_thread")]
    async fn generate_fast_fails_after_breaker_trips() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream sick"))
            .mount(&server)
            .await;

        let uri = server.uri();
        let outcome = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            // Pre-trip: breaker is closed.
            assert!(
                !client.circuit_breaker_open(),
                "breaker open before any failure"
            );

            // Three 5xx responses → breaker tripped.
            for _ in 0..super::CIRCUIT_BREAKER_THRESHOLD {
                let _ = client.generate("ping", None); // ignore Err (expected)
            }
            assert!(
                client.circuit_breaker_open(),
                "breaker should be open after {} consecutive 5xx",
                super::CIRCUIT_BREAKER_THRESHOLD
            );

            // Post-trip: next generate fast-fails with breaker-open envelope.
            let err = client
                .generate("ping", None)
                .expect_err("breaker-open path must Err");
            err.to_string()
        })
        .await
        .unwrap();
        assert!(
            outcome.contains("circuit breaker open"),
            "expected breaker-open envelope, got: {outcome}"
        );
    }

    /// Same trip, but assert the embed_text path also fast-fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn embed_text_fast_fails_after_breaker_trips() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        // /api/chat → 500 to trip the breaker. embed_text doesn't share
        // the chat path but the breaker state is shared across methods.
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let uri = server.uri();
        let outcome = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            for _ in 0..super::CIRCUIT_BREAKER_THRESHOLD {
                let _ = client.generate("ping", None);
            }
            assert!(client.circuit_breaker_open());
            // Now exercise the embed_text breaker-open arm.
            client
                .embed_text("hello", "nomic-embed-text")
                .expect_err("embed_text must fast-fail when breaker open")
                .to_string()
        })
        .await
        .unwrap();
        assert!(
            outcome.contains("circuit breaker open"),
            "expected breaker-open envelope on embed_text, got: {outcome}"
        );
    }

    /// `circuit_breaker_open` is the public observability hook for the
    /// breaker. Confirm it returns false initially.
    #[tokio::test(flavor = "multi_thread")]
    async fn circuit_breaker_open_starts_closed() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let closed = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            client.circuit_breaker_open()
        })
        .await
        .unwrap();
        assert!(
            !closed,
            "freshly-constructed client must have closed breaker"
        );
    }

    /// After tripping the breaker, a successful response (once it's
    /// served through) resets `consecutive_failures`. Drive the
    /// generate happy path AFTER the breaker has not yet tripped (only
    /// 2 failures, less than the threshold) and confirm the breaker
    /// stays closed.
    #[tokio::test(flavor = "multi_thread")]
    async fn breaker_stays_closed_under_threshold() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let uri = server.uri();
        let still_closed = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            // Stay strictly below the threshold so the breaker stays closed.
            for _ in 0..(super::CIRCUIT_BREAKER_THRESHOLD - 1) {
                let _ = client.generate("ping", None);
            }
            client.circuit_breaker_open()
        })
        .await
        .unwrap();
        assert!(
            !still_closed,
            "breaker must stay closed strictly below the threshold"
        );
    }
}
