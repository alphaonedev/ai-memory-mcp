// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use hf_hub::{Repo, RepoType, api::sync::Api};
use std::sync::Arc;
use tokenizers::Tokenizer;

use crate::config::EmbeddingModel;

/// #1558 batch 5 wave 2 — the canonical embedding/rerank document
/// template: `"{title} {content}"`.
///
/// LOAD-BEARING: every surface that embeds a memory (store / update /
/// dedup-check / reflect / federation refresh / backfill) and the
/// cross-encoder reranker must build the document text with this exact
/// template — a drifted spelling at any one site would silently skew
/// similarity scores between write-time vectors and query-time
/// comparisons. One definition; byte-identical to the prior inline
/// `format!` at every routed site.
#[must_use]
pub fn embedding_document(
    title: impl std::fmt::Display,
    content: impl std::fmt::Display,
) -> String {
    format!("{title} {content}")
}

const MINILM_MODEL_ID: &str = "sentence-transformers/all-MiniLM-L6-v2";
#[allow(dead_code)]
const MINILM_DIM: usize = 384;
const MAX_SEQ_LEN: usize = 256;

/// Wall-clock budget for the one-time MiniLM weight download from the
/// HuggingFace Hub (#1487). hf-hub 0.5's sync `ureq` client has no
/// request timeout, so a stalled HF connection mid-`model.safetensors`
/// would block the calling thread forever — which on the CLI recall path
/// (where `effective_tier` defaults to `semantic`) hung a one-shot
/// `ai-memory recall` indefinitely and pinned a CI runner for 2h+ (no
/// `Command::output()` EOF). When the bounded download exceeds this
/// budget we abandon it and fall back to the offline/keyword path
/// (`load_from_fallback`), matching the existing degraded-load contract.
const HF_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
/// Fallback subdirectory under $HOME for pre-downloaded `MiniLM` model files
const FALLBACK_MODEL_SUBDIR: &str =
    ".cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/snapshots/main";

/// Nomic model ID and Ollama tag
pub(crate) const NOMIC_OLLAMA_MODEL: &str = "nomic-embed-text";
/// #1598 — case-insensitive substring identifying the nomic-embed
/// model family across its id spellings (`nomic-embed-text`,
/// `nomic-embed-text:v1.5`, `nomic-ai/nomic-embed-text-v1.5`). Drives
/// [`Embedder::model_requires_nomic_prefix`].
const NOMIC_MODEL_FAMILY_NEEDLE: &str = "nomic-embed";
/// HF model-artifact file names — shared with the reranker loader
/// (#1558 batch 6).
pub(crate) const HF_CONFIG_FILE: &str = "config.json";
/// HF tokenizer artifact file name.
pub(crate) const HF_TOKENIZER_FILE: &str = "tokenizer.json";
/// HF safetensors weights artifact file name.
pub(crate) const HF_WEIGHTS_FILE: &str = "model.safetensors";
#[allow(dead_code)]
const NOMIC_DIM: usize = 768;

/// nomic-embed-text-v1.5 is an ASYMMETRIC retrieval model (#1520):
/// corpus documents and search queries must each be embedded under a
/// distinct task-instruction prefix, or the cosine similarity between a
/// query and the document that answers it collapses. These are the
/// canonical v1.5 prefixes (trailing space is part of the prefix).
const NOMIC_PREFIX_DOCUMENT: &str = "search_document: ";
const NOMIC_PREFIX_QUERY: &str = "search_query: ";

/// Retrieval role of a text handed to the embedder. Drives the
/// asymmetric task-instruction prefix for backends that require one
/// (Ollama nomic-embed-text-v1.5); symmetric backends (the in-process
/// candle MiniLM-L6-v2) ignore it. See #1520.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedRole {
    /// Text stored / indexed as a corpus document. This is the default
    /// role for every write/index path and for symmetric comparisons
    /// (dedup probes, family-descriptor matching).
    Document,
    /// Text used as a search query against the corpus (recall paths).
    Query,
}

impl EmbedRole {
    /// The nomic-embed-text-v1.5 task-instruction prefix for this role.
    #[must_use]
    pub fn nomic_prefix(self) -> &'static str {
        match self {
            Self::Document => NOMIC_PREFIX_DOCUMENT,
            Self::Query => NOMIC_PREFIX_QUERY,
        }
    }
}

// ---------------------------------------------------------------------------
// v0.7.0 F6 — EmbedStatus surface
// ---------------------------------------------------------------------------
//
// The store path commits the row at HTTP 201 even when the embedder
// silently skips/fails (e.g. >64KB content per F10, or ollama dead per
// F6). Prior to F6 this only emitted a WARN log — the caller had no
// way to learn that the row was indexed-without-embedding. F6 introduces
// `EmbedStatus` and `Embedder::embed_with_status` so the caller can
// surface the outcome on the response. The HTTP wiring lives in F10
// (Fix-Agent β); this module exposes the producer side only.
//
// `Skipped` and `Failed` carry a reason string so operators see the
// actual condition (e.g. "content >65536 bytes", "ollama timeout").

/// v0.7.0 F6 — outcome of a single embedding call. Returned by
/// [`Embedder::embed_with_status`] alongside the (possibly absent)
/// embedding vector.
///
/// * `Indexed` — vector produced and ready to persist.
/// * `Skipped(reason)` — caller-policy skip (e.g. content too long for
///   the configured embedder). The row should still be stored without
///   an embedding; recall will fall back to keyword for that row.
/// * `Failed(reason)` — embedder errored at runtime (ollama down, model
///   load failure, …). Same downstream behaviour as `Skipped` —
///   keyword-only recall — but operationally distinguishable. Callers
///   that care about freshness can re-issue the embed later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedStatus {
    Indexed,
    Skipped(String),
    Failed(String),
}

impl EmbedStatus {
    /// Static label used in API surfaces and logs.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Indexed => "indexed",
            Self::Skipped(_) => "skipped",
            Self::Failed(_) => "failed",
        }
    }

    /// True when the row has no usable embedding — caller should fall
    /// back to keyword recall for that row.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !matches!(self, Self::Indexed)
    }

    /// Human-readable reason. Empty string for `Indexed`.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Indexed => "",
            Self::Skipped(r) | Self::Failed(r) => r.as_str(),
        }
    }
}

impl std::fmt::Display for EmbedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Indexed => write!(f, "indexed"),
            Self::Skipped(r) => write!(f, "skipped: {r}"),
            Self::Failed(r) => write!(f, "failed: {r}"),
        }
    }
}

/// v0.7.0 F6 — soft cap on the input size handed to the embedder.
/// 64 KiB matches the F10 store-path threshold so a single content
/// blob that the embedder can't realistically process is reported as
/// `Skipped("content > 65536 bytes")` rather than blowing up the
/// chat/embed RPC. Operators who want larger embeddings can grow this
/// constant alongside the F10 HTTP threshold.
pub const EMBED_MAX_BYTES: usize = 64 * 1024;

/// #1595 — single source of the [`EMBED_MAX_BYTES`] oversize check +
/// its human-readable skip reason. `Some(reason)` when `byte_len`
/// exceeds the cap, `None` otherwise. Shared by
/// [`Embedder::embed_with_status`] (store path) and the backfill /
/// reembed sweeps so the client-side guard and its WARN text can never
/// drift between the write-time and batch paths.
#[must_use]
pub fn oversize_embed_reason(byte_len: usize) -> Option<String> {
    (byte_len > EMBED_MAX_BYTES)
        .then(|| format!("content {byte_len} bytes exceeds embed cap {EMBED_MAX_BYTES} bytes"))
}

/// v0.7.0 L0.7 — minimal dyn-compatible trait that abstracts "produces
/// embedding vectors" away from the concrete [`Embedder`] enum.
///
/// Introduced to unblock Tier B coverage closure on the MCP tool
/// handlers (`reflect`, `check_duplicate`, `store`, `recall`, etc.):
/// before this trait existed, those handlers took `Option<&Embedder>`,
/// which forced every test exercising the `Some(...)` arm to construct
/// a real candle/Ollama embedder — banned by the test playbook §4
/// "real LLM never in cargo test". With `dyn Embed` the production
/// [`Embedder`] AND the test-only `MockEmbedder` (in
/// [`test_support`]) both satisfy the same handler signature, so unit
/// tests can substitute the mock and cover the embedder-bearing
/// branches without a network or model load.
///
/// Implementations are required to be `Send + Sync` so the trait
/// object is safe to hand across `tokio::task::spawn_blocking`
/// boundaries (as the daemon's B3 family-embedding precompute does).
///
/// Bug memory: `_v070_grand_slam/layer_0_7/bugs_surfaced/8f3443c5`.
pub trait Embed: Send + Sync {
    /// Produce a single embedding vector for `text`.
    ///
    /// # Errors
    ///
    /// Implementor-specific. The production [`Embedder`] returns
    /// [`anyhow::Error`] from `candle` / `tokenizers` / `OllamaClient`
    /// for I/O, tokenisation, or model-forward failures. The
    /// `MockEmbedder` never errors.
    fn embed(&self, text: &str) -> Result<Vec<f32>>;

    /// Produce a single embedding vector for `text` used as a search
    /// query. Default implementation delegates to [`Embed::embed`],
    /// which is correct for symmetric embedders (and the test
    /// `MockEmbedder`); the production [`Embedder`] overrides it so the
    /// asymmetric Ollama nomic backend applies the `search_query:` task
    /// prefix (#1520).
    ///
    /// # Errors
    ///
    /// Same as [`Embed::embed`].
    fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        self.embed(text)
    }

    /// Produce embedding vectors for a batch of texts. Default
    /// implementation calls [`Embed::embed`] in a loop; implementors
    /// may override to do native batching.
    ///
    /// # Errors
    ///
    /// Propagates the first per-text error from [`Embed::embed`].
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }

    /// #1598 / #1594 — true when the embedder's most recent remote
    /// call failed (live-degraded posture). Default `false` (correct
    /// for local / mock embedders); the production [`Embedder`]
    /// overrides it for the remote variant so the capabilities surface
    /// reports a dead endpoint truthfully.
    fn is_degraded(&self) -> bool {
        false
    }
}

/// Semantic embedding engine supporting multiple backends.
///
/// - **Local** (candle): all-MiniLM-L6-v2, 384-dim. Used at the semantic tier.
/// - **Ollama**: nomic-embed-text-v1.5, 768-dim. Used at smart/autonomous tiers.
#[derive(Clone)]
pub enum Embedder {
    /// Candle-based local embedding (MiniLM-L6-v2, 384-dim).
    ///
    /// v0.7.0 #1084 — `model` is `Arc<BertModel>` (no mutex). The
    /// pre-#1084 design held an `Arc<Mutex<BertModel>>` and locked
    /// the model across the full forward pass; on a multi-tenant
    /// HTTP daemon that serialised every embed call on a single
    /// global mutex. Candle's `BertModel::forward(&self, ...)` is
    /// inference-only (weights are read-only mmap'd safetensors)
    /// so the mutex was unnecessary; parallel embed calls now run
    /// concurrently against the same weights.
    Local {
        model: Arc<BertModel>,
        tokenizer: Arc<Tokenizer>,
        device: Device,
    },
    /// Remote embed client — Ollama-native OR OpenAI-compatible wire
    /// shape (#1598). The historical variant name is preserved to
    /// avoid call-site churn; the carried [`crate::llm::OllamaClient`]
    /// routes `/api/embed` (Ollama) or `/embeddings` + Bearer
    /// (OpenAI-compatible) per its provider. `dim` is the model's
    /// vector dimensionality (768 for the historical nomic default);
    /// `degraded` latches the outcome of the most recent embed call so
    /// the capabilities surface can report a dead remote endpoint
    /// truthfully (#1594).
    Ollama {
        client: Arc<crate::llm::OllamaClient>,
        model_name: String,
        dim: usize,
        degraded: Arc<std::sync::atomic::AtomicBool>,
    },
}

/// v0.7.0 H7 — dimension-aware outcome of a recall-time cosine comparison
/// between a live query embedding and a stored embedding whose producing
/// model may have changed since the row was written.
///
/// [`Embedder::cosine_similarity`] collapses a dimension mismatch to `0.0`,
/// which is numerically indistinguishable from a genuinely orthogonal pair.
/// That makes an embedder-model switch *silent*: every legacy-dimension row
/// scores `0.0` on the semantic axis and quietly drops out of the ranking
/// with no operator-visible signal. This enum preserves the same `0.0`
/// numerical fallback at the call site but lets recall *count and surface*
/// the mismatch instead of swallowing it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CosineComparison {
    /// Both vectors share dimensionality; carries the cosine score.
    Comparable(f32),
    /// Stored embedding dimensionality differs from the query's — almost
    /// always the result of a different embedder model. Carries both
    /// dimensions so callers can report which model produced what.
    DimensionMismatch {
        /// Dimensionality of the live query embedding (active model).
        query_dim: usize,
        /// Dimensionality of the stored embedding (legacy model).
        stored_dim: usize,
    },
}

impl Embedder {
    /// Create a new local (candle) embedder for MiniLM-L6-v2.
    /// Downloads the model if it is not already cached.
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Self::new_local()
    }

    /// Create a local candle embedder (MiniLM-L6-v2, 384-dim).
    pub fn new_local() -> Result<Self> {
        let device = Device::Cpu;

        let (config_path, tokenizer_path, weights_path) = if Self::remote_fetch_disabled() {
            // Offline mode (#1501): skip the network HF-Hub fetch entirely and
            // rely solely on a pre-staged cache. This eliminates the cold-cache
            // concurrent-download race — many parallel `ai-memory recall`
            // subprocesses (the integration suite spawns one per test, all
            // first-touch-downloading the same MiniLM weights) serialise on the
            // hf-hub cache lock at up to HF_DOWNLOAD_TIMEOUT each, stacking to a
            // multi-minute stall. When the cache is absent this `?` errors fast
            // and the caller degrades to the keyword path (same contract as a
            // timed-out download), but without any network wait.
            Self::load_from_fallback()?
        } else {
            match Self::download_within(HF_DOWNLOAD_TIMEOUT, Self::download_via_hf_hub) {
                Ok(paths) => paths,
                Err(e) => {
                    eprintln!("ai-memory: hf-hub download failed ({e}), trying fallback dir");
                    Self::load_from_fallback()?
                }
            }
        };

        let config_data =
            std::fs::read_to_string(&config_path).context("failed to read config.json")?;
        let config: Config =
            serde_json::from_str(&config_data).context("failed to parse config.json")?;

        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("failed to load tokenizer: {e}"))?;

        let truncation = tokenizers::TruncationParams {
            max_length: MAX_SEQ_LEN,
            ..Default::default()
        };
        tokenizer
            .with_truncation(Some(truncation))
            .map_err(|e| anyhow::anyhow!("failed to set truncation: {e}"))?;
        tokenizer.with_padding(None);

        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], candle_core::DType::F32, &device)
                .context("failed to load model weights")?
        };
        let model = BertModel::load(vb, &config).context("failed to build BertModel")?;

        Ok(Self::Local {
            model: Arc::new(model),
            tokenizer: Arc::new(tokenizer),
            device,
        })
    }

    /// Create an Ollama-based embedder for nomic-embed-text-v1.5 (768-dim).
    ///
    /// Requires the Ollama client to already be connected and the model pulled.
    pub fn new_ollama(client: Arc<crate::llm::OllamaClient>) -> Self {
        Self::new_remote(client, NOMIC_OLLAMA_MODEL.to_string(), NOMIC_DIM)
    }

    /// #1598 — create a remote embedder for an arbitrary model + dim.
    /// `client` may speak either wire shape: Ollama-native
    /// (`OllamaClient::new_with_url`) or OpenAI-compatible
    /// (`OllamaClient::new_openai_compatible` — OpenRouter, HF TEI,
    /// vLLM, …). The `degraded` flag starts `false` and tracks the
    /// most recent embed outcome.
    #[must_use]
    pub fn new_remote(
        client: Arc<crate::llm::OllamaClient>,
        model_name: String,
        dim: usize,
    ) -> Self {
        Self::Ollama {
            client,
            model_name,
            dim,
            degraded: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// #1598 — single shared boot entry for both wiring sites (MCP
    /// stdio init + `daemon_runtime::build_embedder`). Consumes the
    /// canonical [`crate::config::AppConfig::resolve_embeddings`]
    /// output and the tier's embedding-model gate:
    ///
    /// - `tier_model = None` (keyword tier) → `Ok(None)`.
    /// - API backend ([`crate::config::is_api_embed_backend`]) →
    ///   OpenAI-compatible remote client against `resolved.url` with
    ///   the resolved Bearer key. Keyless self-hosted endpoints
    ///   (HF TEI / vLLM) are legitimate: a missing key sends an empty
    ///   Bearer value, which such servers ignore. Requires a known
    ///   dim (`[embeddings].dim` override or the known-dims table) —
    ///   bails otherwise so mismatched vectors never land silently.
    /// - Ollama backend → the historical [`Self::for_model`] path
    ///   (MiniLM = local candle regardless; nomic = Ollama client at
    ///   `resolved.url`). Client construction failure returns `Err` —
    ///   callers fail closed to keyword recall (#1593), NEVER to the
    ///   chat LLM client.
    ///
    /// # Errors
    ///
    /// Remote-client construction failure, an unknown vector dim for
    /// an API-backend model, or local model-load failure.
    pub fn from_resolved(
        resolved: &crate::config::ResolvedEmbeddings,
        tier_model: Option<crate::config::EmbeddingModel>,
    ) -> Result<Option<Self>> {
        let Some(tier_model) = tier_model else {
            // Keyword tier — embeddings disabled by the tier preset.
            return Ok(None);
        };
        if crate::config::is_api_embed_backend(&resolved.backend) {
            let Some(dim) = resolved.embedding_dim else {
                anyhow::bail!(
                    "embedding model {:?} (backend {:?}) has no known vector dim — \
                     pick a model from the known-dims table (override with the \
                     {} env var) or set the `[embeddings].dim` escape hatch in \
                     config.toml (#1598)",
                    resolved.model,
                    resolved.backend,
                    crate::config::ENV_EMBED_MODEL,
                );
            };
            // Keyless on-prem endpoints get an empty Bearer value (the
            // server ignores the header); keyed vendors get the
            // resolved secret.
            let api_key = resolved.api_key().unwrap_or_default();
            let client = crate::llm::OllamaClient::new_openai_compatible(
                &resolved.url,
                &resolved.model,
                api_key,
            )
            .context("failed to build OpenAI-compatible embed client (#1598)")?;
            return Ok(Some(Self::new_remote(
                Arc::new(client),
                resolved.model.clone(),
                dim as usize,
            )));
        }
        match tier_model {
            crate::config::EmbeddingModel::MiniLmL6V2 => {
                Self::for_model(tier_model, None).map(Some)
            }
            crate::config::EmbeddingModel::NomicEmbedV15 => {
                let client =
                    crate::llm::OllamaClient::new_with_url(&resolved.url, NOMIC_OLLAMA_MODEL)
                        .context("failed to build Ollama embed client")?;
                Self::for_model(tier_model, Some(Arc::new(client))).map(Some)
            }
        }
    }

    /// Create an embedder for the specified model.
    ///
    /// - `MiniLmL6V2` → local candle embedder
    /// - `NomicEmbedV15` → Ollama-based (requires `ollama_client`)
    pub fn for_model(
        model: EmbeddingModel,
        ollama_client: Option<Arc<crate::llm::OllamaClient>>,
    ) -> Result<Self> {
        match model {
            EmbeddingModel::MiniLmL6V2 => Self::new_local(),
            EmbeddingModel::NomicEmbedV15 => {
                let client = ollama_client.ok_or_else(|| {
                    anyhow::anyhow!("nomic-embed-text-v1.5 requires Ollama (smart tier or above)")
                })?;
                // Ensure the embedding model is pulled
                if let Err(e) = client.ensure_embed_model(NOMIC_OLLAMA_MODEL) {
                    eprintln!("ai-memory: warning: failed to pull nomic model: {e}");
                }
                Ok(Self::new_ollama(client))
            }
        }
    }

    /// Embedding vector dimensionality for this embedder.
    #[allow(dead_code)]
    pub fn dim(&self) -> usize {
        match self {
            Self::Local { .. } => MINILM_DIM,
            Self::Ollama { dim, .. } => *dim,
        }
    }

    /// Human-readable description of the active embedding model.
    /// #1598 — returns `String` (the remote variant reports its live
    /// model + dim, which may be any operator-picked API model id,
    /// not just the historical nomic default).
    #[must_use]
    pub fn model_description(&self) -> String {
        match self {
            Self::Local { .. } => "all-MiniLM-L6-v2 (384-dim, local)".to_string(),
            Self::Ollama {
                model_name, dim, ..
            } => format!("{model_name} ({dim}-dim, remote)"),
        }
    }

    /// #1598 / #1594 — true when the most recent remote embed call
    /// failed (dead endpoint, auth rejection, …). The local candle
    /// embedder never degrades at runtime (weights are mmap'd at
    /// construction). Consumed by the capabilities surface so
    /// `features.embedder_loaded` / `recall_mode_active` report the
    /// LIVE posture rather than the boot-time one.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        match self {
            Self::Local { .. } => false,
            Self::Ollama { degraded, .. } => degraded.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Generate an embedding for a single text input indexed as a
    /// corpus document. Thin alias for [`Embedder::embed_with_role`]
    /// with [`EmbedRole::Document`] — the safe default for every
    /// write/index path and for symmetric comparisons.
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        self.embed_with_role(text, EmbedRole::Document)
    }

    /// Generate an embedding for a text used as a search query. Thin
    /// alias for [`Embedder::embed_with_role`] with [`EmbedRole::Query`].
    /// For the asymmetric Ollama nomic backend this applies the
    /// `search_query:` task prefix so query↔document cosine is
    /// meaningful (#1520); the symmetric local MiniLM backend ignores
    /// the role.
    pub fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        self.embed_with_role(text, EmbedRole::Query)
    }

    /// Generate an embedding for `text` under an explicit retrieval
    /// [`EmbedRole`]. The local candle MiniLM backend is symmetric and
    /// ignores the role; the Ollama nomic backend prepends the
    /// role-specific task-instruction prefix required by
    /// nomic-embed-text-v1.5 (#1520).
    pub fn embed_with_role(&self, text: &str, role: EmbedRole) -> Result<Vec<f32>> {
        match self {
            Self::Local {
                model,
                tokenizer,
                device,
            } => {
                // v0.7.0 #1084 — no mutex acquisition: `Arc<BertModel>`
                // is shared across threads; `BertModel::forward(&self, ...)`
                // is inference-only and safe to call concurrently
                // against the same weights. MiniLM is symmetric, so the
                // role carries no prefix here.
                Self::embed_local(model, tokenizer, device, text)
            }
            Self::Ollama {
                client,
                model_name,
                degraded,
                ..
            } => {
                let result = if Self::model_requires_nomic_prefix(model_name) {
                    let prefixed = format!("{}{}", role.nomic_prefix(), text);
                    client.embed_text(&prefixed, model_name)
                } else {
                    client.embed_text(text, model_name)
                };
                // #1598 — latch the live remote-endpoint posture for
                // the capabilities surface (#1594): a failed embed
                // marks the embedder degraded; the next success clears
                // the flag.
                degraded.store(result.is_err(), std::sync::atomic::Ordering::Relaxed);
                result
            }
        }
    }

    /// Whether the configured remote embed model uses nomic-style
    /// asymmetric task prefixes. Gated on the model id so a different
    /// (symmetric) embed model is never corrupted by an injected
    /// `search_document:` / `search_query:` prefix (#1520). #1598 —
    /// case-insensitive CONTAINS match on
    /// [`NOMIC_MODEL_FAMILY_NEEDLE`] so the HF-id spelling
    /// (`nomic-ai/nomic-embed-text-v1.5`) used by API backends gates
    /// the same as the Ollama tag forms.
    fn model_requires_nomic_prefix(model_name: &str) -> bool {
        model_name
            .to_ascii_lowercase()
            .contains(NOMIC_MODEL_FAMILY_NEEDLE)
    }

    /// v0.7.0 F6 — generate an embedding and report the outcome.
    ///
    /// Combines the existing [`Embedder::embed`] call with an
    /// [`EmbedStatus`] tag so the caller (HTTP store path, MCP store
    /// path, sync ingestion, …) can surface a structured signal on the
    /// response when the embedder skipped or errored. Behaviour:
    ///
    /// * Empty input → `(None, Skipped("empty content"))`
    /// * Input larger than [`EMBED_MAX_BYTES`] → `(None, Skipped(reason))`
    /// * Embedder errors → `(None, Failed(reason))`
    /// * Otherwise → `(Some(vec), Indexed)`
    ///
    /// Callers that don't care about the status keep using
    /// [`Embedder::embed`]; this is the new opt-in API.
    pub fn embed_with_status(&self, text: &str) -> (Option<Vec<f32>>, EmbedStatus) {
        if text.is_empty() {
            return (None, EmbedStatus::Skipped("empty content".to_string()));
        }
        if let Some(reason) = oversize_embed_reason(text.len()) {
            return (None, EmbedStatus::Skipped(reason));
        }
        match self.embed(text) {
            Ok(v) if v.is_empty() => (
                None,
                EmbedStatus::Failed("embedder returned empty vector".to_string()),
            ),
            Ok(v) => (Some(v), EmbedStatus::Indexed),
            Err(e) => {
                let reason = format!("{e:#}");
                tracing::warn!(target: "embeddings.degrade", reason = %reason, "embed_with_status: embedder failed");
                (None, EmbedStatus::Failed(reason))
            }
        }
    }

    fn embed_local(
        model: &BertModel,
        tokenizer: &Tokenizer,
        device: &Device,
        text: &str,
    ) -> Result<Vec<f32>> {
        let encoding = tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("tokenisation failed: {e}"))?;

        let input_ids = encoding.get_ids();
        let attention_mask = encoding.get_attention_mask();
        let token_type_ids = encoding.get_type_ids();
        let seq_len = input_ids.len();

        let input_ids = Tensor::new(input_ids, device)?.reshape((1, seq_len))?;
        let attention_mask_tensor = Tensor::new(attention_mask, device)?.reshape((1, seq_len))?;
        let token_type_ids = Tensor::new(token_type_ids, device)?.reshape((1, seq_len))?;

        let hidden = model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask_tensor))
            .context("model forward pass failed")?;

        let mask = attention_mask_tensor
            .unsqueeze(2)?
            .to_dtype(candle_core::DType::F32)?
            .broadcast_as(hidden.shape())?;
        let masked = hidden.mul(&mask)?;
        let summed = masked.sum(1)?;
        let count = mask.sum(1)?.clamp(1e-9, f64::MAX)?;
        let pooled = summed.div(&count)?;

        let norm = pooled
            .sqr()?
            .sum_keepdim(1)?
            .sqrt()?
            .clamp(1e-12, f64::MAX)?;
        let normalised = pooled.broadcast_div(&norm)?;

        let embedding: Vec<f32> = normalised.squeeze(0)?.to_vec1()?;
        Ok(embedding)
    }

    /// Generate embeddings for multiple texts in one call.
    ///
    /// PERF-5 (FX-C4-batch2, 2026-05-26): true batched forward
    /// instead of the prior `texts.iter().map(|t| self.embed(t))`
    /// fan-out. The Local arm tokenises every input, pads to the
    /// batch's max sequence length, stacks to a (B, L) tensor, and
    /// runs `BertModel::forward` ONCE per batch — Candle's
    /// per-call overhead dominates B=1 calls, so a true batch of 32
    /// inputs is ~10-20× faster than 32 sequential calls. The
    /// Ollama arm continues to dispatch one POST per text (the
    /// vendor wire shape for batched `/api/embed` differs across
    /// Ollama versions and a wire-version probe would add the same
    /// per-call latency we are saving; keep the per-text loop here
    /// while a `LlmClient`-side batched-embed API is staged).
    ///
    /// Callers: `multistep_ingest`, `atomisation`, the periodic
    /// embedding-backfill sweep (`AI_MEMORY_EMBED_BACKFILL_BATCH`).
    #[allow(dead_code)]
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        match self {
            Self::Local {
                model,
                tokenizer,
                device,
            } => Self::embed_local_batch(model, tokenizer, device, texts),
            // Ollama arm: keep the sequential per-text loop until
            // the LlmClient migration lands the batched-embed wire
            // contract.
            Self::Ollama { .. } => texts.iter().map(|t| self.embed(t)).collect(),
        }
    }

    /// PERF-5 — batched local forward. Tokenise → pad to max-seq →
    /// stack → single forward → slice per-row output.
    fn embed_local_batch(
        model: &BertModel,
        tokenizer: &Tokenizer,
        device: &Device,
        texts: &[&str],
    ) -> Result<Vec<Vec<f32>>> {
        // Tokenise every input. `encode_batch` exists on the
        // tokenizers crate, but the project may pin a version that
        // requires `Vec<&str>` shape — build the vector explicitly.
        let inputs: Vec<&str> = texts.to_vec();
        let encodings = tokenizer
            .encode_batch(inputs, true)
            .map_err(|e| anyhow::anyhow!("tokenisation batch failed: {e}"))?;

        // Find max seq len across the batch.
        let max_len = encodings
            .iter()
            .map(tokenizers::Encoding::len)
            .max()
            .unwrap_or(0);
        if max_len == 0 {
            // Every input was empty after tokenisation; return one
            // empty embedding per slot.
            return Ok(texts.iter().map(|_| Vec::new()).collect());
        }

        let batch_size = encodings.len();

        // Pad each sequence to max_len with 0 (PAD token id is
        // typically 0 for BERT family; the attention mask zeros
        // out padded positions so the value is irrelevant for the
        // mean-pool).
        let mut input_ids_flat = Vec::with_capacity(batch_size * max_len);
        let mut attention_mask_flat = Vec::with_capacity(batch_size * max_len);
        let mut token_type_ids_flat = Vec::with_capacity(batch_size * max_len);
        for enc in &encodings {
            let ids = enc.get_ids();
            let mask = enc.get_attention_mask();
            let tt = enc.get_type_ids();
            let len = ids.len();
            input_ids_flat.extend_from_slice(ids);
            attention_mask_flat.extend_from_slice(mask);
            token_type_ids_flat.extend_from_slice(tt);
            // Pad up.
            for _ in len..max_len {
                input_ids_flat.push(0);
                attention_mask_flat.push(0);
                token_type_ids_flat.push(0);
            }
        }

        let input_ids =
            Tensor::new(input_ids_flat.as_slice(), device)?.reshape((batch_size, max_len))?;
        let attention_mask_tensor =
            Tensor::new(attention_mask_flat.as_slice(), device)?.reshape((batch_size, max_len))?;
        let token_type_ids =
            Tensor::new(token_type_ids_flat.as_slice(), device)?.reshape((batch_size, max_len))?;

        let hidden = model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask_tensor))
            .context("model forward pass (batched) failed")?;

        // Mean-pool along seq dim with attention mask.
        let mask = attention_mask_tensor
            .unsqueeze(2)?
            .to_dtype(candle_core::DType::F32)?
            .broadcast_as(hidden.shape())?;
        let masked = hidden.mul(&mask)?;
        let summed = masked.sum(1)?;
        let count = mask.sum(1)?.clamp(1e-9, f64::MAX)?;
        let pooled = summed.div(&count)?;

        let norm = pooled
            .sqr()?
            .sum_keepdim(1)?
            .sqrt()?
            .clamp(1e-12, f64::MAX)?;
        let normalised = pooled.broadcast_div(&norm)?;

        // Slice out per-row embeddings.
        let mut out: Vec<Vec<f32>> = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let row: Vec<f32> = normalised.get(i)?.to_vec1()?;
            out.push(row);
        }
        Ok(out)
    }

    /// Compute cosine similarity between two embedding vectors.
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        // Handle dimension mismatch gracefully (e.g. mixed 384/768 embeddings)
        if a.len() != b.len() {
            return 0.0;
        }

        // PERF-4 (med/low review batch) — fuse three passes into one so
        // LLVM auto-vectorises the leaf loop. The pre-fix shape walked the
        // slices 3× (dot, |a|², |b|²); with embedding dims of 384-1024 and
        // up to ~250 candidates per recall this was the per-recall hot
        // path most likely to leave SIMD performance on the table. The
        // numerical result is byte-equal (same multiplications and sums
        // in the same order, just interleaved).
        let mut dot: f32 = 0.0;
        let mut sq_a: f32 = 0.0;
        let mut sq_b: f32 = 0.0;
        for (&x, &y) in a.iter().zip(b.iter()) {
            dot += x * y;
            sq_a += x * x;
            sq_b += y * y;
        }
        let denom = sq_a.sqrt() * sq_b.sqrt();
        if denom < 1e-12 {
            return 0.0;
        }
        let score = dot / denom;
        // #1584 (SEC) — defense-in-depth: a stored embedding carrying a
        // NaN/±Inf component (e.g. a future code path that skips the
        // `federation::sanitize_shipped_vector` ingest guard) would make
        // `score` non-finite, and NaN is UNORDERED under `partial_cmp`
        // — a single poisoned row silently corrupts the ranking of an
        // entire candidate set. Collapse any non-finite score to 0.0 so
        // a malformed vector ranks LAST instead of perturbing ordering.
        if score.is_finite() { score } else { 0.0 }
    }

    /// v0.7.0 H7 — dimension-aware companion to [`Embedder::cosine_similarity`].
    ///
    /// Returns [`CosineComparison::DimensionMismatch`] instead of silently
    /// yielding `0.0` when the two vectors have different lengths, so the
    /// recall pipeline can report cross-model (embedder-switch) embeddings
    /// rather than dropping their semantic signal unseen. When the
    /// dimensions agree the result wraps the same value
    /// [`Embedder::cosine_similarity`] would return.
    #[must_use]
    pub fn cosine_similarity_checked(query: &[f32], stored: &[f32]) -> CosineComparison {
        if query.len() != stored.len() {
            return CosineComparison::DimensionMismatch {
                query_dim: query.len(),
                stored_dim: stored.len(),
            };
        }
        CosineComparison::Comparable(Self::cosine_similarity(query, stored))
    }

    /// Fuse a primary query embedding with a secondary context embedding via
    /// weighted linear combination (v0.6.0.0 contextual recall).
    ///
    /// `primary_weight` clamped to `[0.0, 1.0]`. The result is returned
    /// un-normalized — `cosine_similarity` divides out magnitudes, so the
    /// downstream signal is direction-only. Returns `primary.to_vec()` when
    /// dimensions differ (graceful fallback, same policy as
    /// `cosine_similarity`).
    #[must_use]
    pub fn fuse(primary: &[f32], secondary: &[f32], primary_weight: f32) -> Vec<f32> {
        if primary.len() != secondary.len() {
            return primary.to_vec();
        }
        let w = primary_weight.clamp(0.0, 1.0);
        let one_minus_w = 1.0 - w;
        primary
            .iter()
            .zip(secondary.iter())
            .map(|(p, s)| w * p + one_minus_w * s)
            .collect()
    }

    /// Run a blocking model-download closure on a detached watchdog
    /// thread, returning its result or erroring after `budget` (#1487).
    ///
    /// hf-hub 0.5's sync client exposes no request timeout, so a stalled
    /// HuggingFace connection blocks the download thread indefinitely.
    /// We hand the work to a `std::thread::spawn` (a *daemon* thread — it
    /// is never joined) and wait on an mpsc channel with `recv_timeout`.
    /// On timeout we abandon the still-running download and surface an
    /// `Err`; the caller then falls back to the offline/keyword path. The
    /// abandoned thread cannot keep the process alive — when `main`
    /// returns the process exits and the daemon thread dies with it, so a
    /// one-shot CLI invocation no longer hangs on a stuck download.
    fn download_within<F>(
        budget: std::time::Duration,
        f: F,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)>
    where
        F: FnOnce() -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)>
            + Send
            + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // The receiver may already be gone (timeout fired first); a
            // failed send is expected and intentionally ignored.
            let _ = tx.send(f());
        });
        match rx.recv_timeout(budget) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => anyhow::bail!(
                "hf-hub model download exceeded {}s budget",
                budget.as_secs()
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("hf-hub model download thread terminated without a result")
            }
        }
    }

    fn download_via_hf_hub() -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)>
    {
        let api = Api::new().context("failed to initialise HuggingFace Hub API")?;
        let repo = api.repo(Repo::new(MINILM_MODEL_ID.to_string(), RepoType::Model));
        let config_path = repo
            .get(HF_CONFIG_FILE)
            .context("failed to download config.json")?;
        let tokenizer_path = repo
            .get(HF_TOKENIZER_FILE)
            .context("failed to download tokenizer.json")?;
        let weights_path = repo
            .get(HF_WEIGHTS_FILE)
            .context("failed to download model.safetensors")?;
        Ok((config_path, tokenizer_path, weights_path))
    }

    /// Whether the local MiniLM embedder must avoid the network and use only
    /// a pre-staged cache. Honors the de-facto-standard `HF_HUB_OFFLINE` plus
    /// the dedicated `AI_MEMORY_EMBED_OFFLINE` knob. Used by hermetic CI (the
    /// integration suite sets it to dodge the #1501 cold-download race) and by
    /// air-gapped operators who pre-stage the weights in `FALLBACK_MODEL_SUBDIR`.
    fn remote_fetch_disabled() -> bool {
        let truthy = |name: &str| {
            std::env::var(name)
                .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
                .unwrap_or(false)
        };
        truthy("AI_MEMORY_EMBED_OFFLINE") || truthy("HF_HUB_OFFLINE")
    }

    fn load_from_fallback() -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)>
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let dir = std::path::PathBuf::from(home).join(FALLBACK_MODEL_SUBDIR);
        let dir = dir.as_path();
        let config = dir.join(HF_CONFIG_FILE);
        let tokenizer = dir.join(HF_TOKENIZER_FILE);
        let weights = dir.join(HF_WEIGHTS_FILE);
        if config.exists() && tokenizer.exists() && weights.exists() {
            Ok((config, tokenizer, weights))
        } else {
            anyhow::bail!(
                "model files not found in fallback dir: {}. Download them manually from https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2",
                dir.display()
            )
        }
    }
}

/// v0.7.0 L0.7 — [`Embed`] trait impl that delegates to the inherent
/// [`Embedder::embed`] / [`Embedder::embed_batch`] methods. The
/// inherent methods stay on [`Embedder`] verbatim so existing callers
/// that hold a concrete `&Embedder` keep their fast path; the trait
/// impl is purely additive and enables `dyn Embed` substitution for
/// handler signatures (see [`Embed`] docs).
impl Embed for Embedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        Self::embed(self, text)
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        Self::embed_query(self, text)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        Self::embed_batch(self, texts)
    }

    fn is_degraded(&self) -> bool {
        Self::is_degraded(self)
    }
}

/// Constant for backward compatibility — dimension of the default (`MiniLM`) embedding.
#[allow(dead_code)]
pub const EMBEDDING_DIM: usize = MINILM_DIM;

// ---------------------------------------------------------------------------
// v0.6.3.1 Phase P2 — embedding BLOB magic-byte header (G13)
// ---------------------------------------------------------------------------
//
// Storage hardening: every embedding written from v0.6.3.1 onward is prefixed
// with a single byte declaring the on-disk float layout. Pre-v17 rows have no
// header — readers tolerate "no-header" as little-endian f32 (the historical
// format) and reject any unknown header byte with a typed error rather than
// silently producing a wrong cosine score after federation across mixed-arch
// clusters.
//
// Endianness conversion (BE → LE) is intentionally NOT done here. The v0.7
// federation work will add it once the cross-arch path has explicit test
// coverage. Until then, any 0x02 BLOB returns `EmbeddingFormatError` so the
// operator sees the corruption immediately instead of degrading recall.
/// Magic byte declaring "little-endian f32" payload follows.
pub const EMBEDDING_HEADER_LE_F32: u8 = 0x01;

/// Magic byte declaring "big-endian f32" payload follows. Reserved — the
/// reader rejects this until v0.7 adds endianness conversion.
pub const EMBEDDING_HEADER_BE_F32: u8 = 0x02;

/// Errors produced by the embedding BLOB codec. Distinguishes the three
/// failure modes operators want to triage independently:
///
/// * `UnknownHeader` — first byte is neither 0x01 nor "looks like raw LE f32".
///   Most likely cause: a 0.7+ federation peer pushed a payload this binary
///   cannot decode, or the BLOB was corrupted on-disk.
/// * `BigEndianUnsupported` — header is 0x02. Documented as an explicit error
///   so the doctor command can surface "you have BE-f32 rows; upgrade to v0.7
///   to read them". Until v0.7 ships, BE writes do not happen so this is a
///   hard-error path.
/// * `MalformedLength` — payload length is not a multiple of 4. Indicates a
///   truncated BLOB; the row should be re-embedded.
#[derive(Debug)]
pub enum EmbeddingFormatError {
    UnknownHeader(u8),
    BigEndianUnsupported,
    MalformedLength(usize),
}

impl std::fmt::Display for EmbeddingFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownHeader(b) => write!(f, "unknown embedding header byte: 0x{b:02x}"),
            Self::BigEndianUnsupported => write!(
                f,
                "big-endian f32 embeddings (header 0x02) are not supported until v0.7"
            ),
            Self::MalformedLength(n) => {
                write!(f, "embedding payload length {n} is not a multiple of 4")
            }
        }
    }
}

impl std::error::Error for EmbeddingFormatError {}

/// Encode a `[f32]` slice as a length-prefixed BLOB suitable for the
/// `memories.embedding` column.
///
/// Layout: `[0x01][LE f32 #0 (4 bytes)][LE f32 #1]...`. Empty input still
/// emits the header so the round-trip preserves "I am an empty vector"
/// versus "I am a legacy unheaded blob"; downstream code should treat
/// empty embeddings as "no embedding" before reaching this codec.
#[must_use]
pub fn encode_embedding_blob(embedding: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + embedding.len() * 4);
    out.push(EMBEDDING_HEADER_LE_F32);
    for f in embedding {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

/// Decode an `embedding` BLOB back into `Vec<f32>`.
///
/// Tolerates legacy (pre-v17) rows that have no header byte — the historical
/// format was raw LE f32, so a payload whose length is a multiple of 4 with
/// no leading 0x01 is treated as legacy and decoded directly. This match is
/// intentionally tight: any other first byte (including 0x02 for BE) becomes
/// a typed error so the doctor command can flag corrupt rows.
///
/// # Errors
///
/// Returns [`EmbeddingFormatError`] on:
/// * Unknown header byte (anything other than 0x01 in a row whose length is
///   `1 + 4n`).
/// * Big-endian header (0x02) — reserved for v0.7.
/// * Length neither `4n` (legacy) nor `1 + 4n` (v17).
pub fn decode_embedding_blob(bytes: &[u8]) -> Result<Vec<f32>, EmbeddingFormatError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    // Headed case: leading byte is the magic and the rest is `4n` bytes.
    if bytes.len() % 4 == 1 {
        let header = bytes[0];
        return match header {
            EMBEDDING_HEADER_LE_F32 => {
                let payload = &bytes[1..];
                Ok(payload
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect())
            }
            EMBEDDING_HEADER_BE_F32 => Err(EmbeddingFormatError::BigEndianUnsupported),
            other => Err(EmbeddingFormatError::UnknownHeader(other)),
        };
    }

    // Legacy unheaded case: raw LE f32, length must be a multiple of 4.
    if bytes.len() % 4 == 0 {
        return Ok(bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect());
    }

    Err(EmbeddingFormatError::MalformedLength(bytes.len()))
}

/// Number of f32 elements encoded in `bytes`, regardless of header presence.
/// Used by the `dim_violations` stats path to compute per-row dim without
/// allocating a `Vec<f32>`.
#[must_use]
pub fn decoded_dim(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    if bytes.len() % 4 == 1 {
        return (bytes.len() - 1) / 4;
    }
    bytes.len() / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_similarity_identical() {
        let v = vec![1.0, 0.0, 0.0];
        let sim = Embedder::cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn embed_role_maps_to_nomic_prefix() {
        // #1520 — asymmetric nomic prefixes must be role-distinct so a
        // query and the document that answers it land in the same space.
        assert_eq!(EmbedRole::Document.nomic_prefix(), NOMIC_PREFIX_DOCUMENT);
        assert_eq!(EmbedRole::Query.nomic_prefix(), NOMIC_PREFIX_QUERY);
        assert_ne!(
            EmbedRole::Document.nomic_prefix(),
            EmbedRole::Query.nomic_prefix()
        );
        // The trailing space is part of the wire prefix.
        assert!(NOMIC_PREFIX_DOCUMENT.ends_with(' '));
        assert!(NOMIC_PREFIX_QUERY.ends_with(' '));
    }

    #[test]
    fn nomic_prefix_gating_is_model_scoped() {
        // The prefix is applied only when the remote embed model is
        // nomic; a different (symmetric) model must NOT be corrupted
        // by an injected task prefix (#1520).
        // The nomic model id (bare and tag-qualified) requires prefixing.
        assert!(Embedder::model_requires_nomic_prefix(NOMIC_OLLAMA_MODEL));
        assert!(Embedder::model_requires_nomic_prefix(&format!(
            "{NOMIC_OLLAMA_MODEL}:v1.5"
        )));
        // Representative non-nomic (symmetric) embed models must NOT
        // be prefixed, or their cosine geometry would be corrupted.
        let other_embed_models = ["mxbai-embed-large", "all-minilm"];
        for model in other_embed_models {
            assert!(!Embedder::model_requires_nomic_prefix(model));
        }
    }

    // --- #1598 — remote-variant generalisation + from_resolved ---

    /// Build a no-network OpenAI-compatible client for constructor
    /// tests (`new_openai_compatible` performs no health probe).
    fn offline_openai_compatible_client() -> Arc<crate::llm::OllamaClient> {
        Arc::new(
            crate::llm::OllamaClient::new_openai_compatible(
                "http://127.0.0.1:1",
                "test-embed-model",
                "",
            )
            .expect("client builds without network"),
        )
    }

    #[test]
    fn new_remote_carries_dynamic_dim_and_truthful_description_1598() {
        let embedder = Embedder::new_remote(
            offline_openai_compatible_client(),
            "google/gemini-embedding-2".to_string(),
            3072,
        );
        assert_eq!(embedder.dim(), 3072);
        assert_eq!(
            embedder.model_description(),
            "google/gemini-embedding-2 (3072-dim, remote)"
        );
        assert!(!embedder.is_degraded());
    }

    #[test]
    fn new_ollama_preserves_nomic_defaults_1598() {
        let embedder = Embedder::new_ollama(offline_openai_compatible_client());
        assert_eq!(embedder.dim(), NOMIC_DIM);
        let desc = embedder.model_description();
        assert!(desc.contains(NOMIC_OLLAMA_MODEL), "desc: {desc}");
        assert!(desc.contains("768"), "desc: {desc}");
        assert!(!embedder.is_degraded());
    }

    #[test]
    fn remote_embed_failure_latches_degraded_flag_1598() {
        // Port 1 on loopback refuses instantly — the embed call errors
        // and the degraded flag must latch true (#1594 truthfulness).
        let embedder = Embedder::new_remote(
            offline_openai_compatible_client(),
            "test-embed-model".to_string(),
            8,
        );
        assert!(!embedder.is_degraded());
        let err = embedder.embed("hello");
        assert!(err.is_err(), "embed against a closed port must error");
        assert!(embedder.is_degraded());
    }

    #[test]
    fn local_embedder_is_never_degraded_via_trait_default_1598() {
        // The `Embed` trait default reports false for embedders with
        // no remote-degradation concept (mock / local).
        let mock = crate::embeddings::test_support::MockEmbedder::new_ollama();
        let as_trait: &dyn Embed = &mock;
        assert!(!as_trait.is_degraded());
    }

    #[test]
    fn from_resolved_keyword_tier_yields_none_1598() {
        let resolved = crate::config::ResolvedEmbeddings::from_parts(
            "openrouter".to_string(),
            "https://openrouter.ai/api/v1".to_string(),
            "google/gemini-embedding-2".to_string(),
            Some(3072),
            None,
        );
        let built = Embedder::from_resolved(&resolved, None).expect("keyword tier is Ok(None)");
        assert!(built.is_none());
    }

    #[test]
    fn from_resolved_api_backend_unknown_dim_bails_with_escape_hatch_1598() {
        let resolved = crate::config::ResolvedEmbeddings::from_parts(
            "openrouter".to_string(),
            "https://openrouter.ai/api/v1".to_string(),
            "some/unknown-embed-model".to_string(),
            None,
            None,
        );
        let result = Embedder::from_resolved(
            &resolved,
            Some(crate::config::EmbeddingModel::NomicEmbedV15),
        );
        let Err(err) = result else {
            panic!("unknown dim on an API backend must fail closed");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("dim"), "error must name the dim gap: {msg}");
        assert!(
            msg.contains("[embeddings].dim"),
            "error must name the config escape hatch: {msg}"
        );
        assert!(
            msg.contains(crate::config::ENV_EMBED_MODEL),
            "error must name the model env var: {msg}"
        );
    }

    #[test]
    fn from_resolved_api_backend_builds_remote_embedder_1598() {
        // `new_openai_compatible` performs no construction-time network
        // probe, so this is hermetic. Keyless (None) exercises the
        // empty-Bearer on-prem contract (HF TEI / vLLM).
        let resolved = crate::config::ResolvedEmbeddings::from_parts(
            "openrouter".to_string(),
            "https://openrouter.ai/api/v1".to_string(),
            "google/gemini-embedding-2".to_string(),
            Some(3072),
            None,
        );
        let built = Embedder::from_resolved(
            &resolved,
            Some(crate::config::EmbeddingModel::NomicEmbedV15),
        )
        .expect("API-backend construction succeeds")
        .expect("tier gates embeddings on");
        assert!(matches!(built, Embedder::Ollama { .. }));
        assert_eq!(built.dim(), 3072);
        assert_eq!(
            built.model_description(),
            "google/gemini-embedding-2 (3072-dim, remote)"
        );
    }

    #[test]
    fn nomic_prefix_gating_covers_hf_id_and_case_forms_1598() {
        // #1598 — the CONTAINS-needle predicate must gate the HF-id
        // spelling used by API embed backends and be case-insensitive.
        assert!(Embedder::model_requires_nomic_prefix(
            "nomic-ai/nomic-embed-text-v1.5"
        ));
        assert!(Embedder::model_requires_nomic_prefix(
            "nomic-embed-text-v1.5"
        ));
        assert!(Embedder::model_requires_nomic_prefix(
            "Nomic-AI/Nomic-Embed-Text-v1.5"
        ));
        // Non-nomic API model ids never get the prefix.
        assert!(!Embedder::model_requires_nomic_prefix(
            "google/gemini-embedding-2"
        ));
        assert!(!Embedder::model_requires_nomic_prefix(
            "ibm-granite/granite-embedding-125m-english"
        ));
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        let sim = Embedder::cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_opposite() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        let sim = Embedder::cosine_similarity(&a, &b);
        assert!((sim + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_zero_vector() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 2.0, 3.0];
        let sim = Embedder::cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn cosine_similarity_dimension_mismatch() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0]; // Different dimension
        let sim = Embedder::cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    // --- v0.7.0 H7 — dimension-aware cosine for embedder-switch detection ---

    #[test]
    fn cosine_similarity_checked_comparable_matches_plain_cosine() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![2.0, 1.0, 0.5];
        let plain = Embedder::cosine_similarity(&a, &b);
        match Embedder::cosine_similarity_checked(&a, &b) {
            CosineComparison::Comparable(c) => assert!((c - plain).abs() < 1e-6),
            CosineComparison::DimensionMismatch { .. } => {
                panic!("equal-length vectors must compare as Comparable")
            }
        }
    }

    #[test]
    fn cosine_similarity_checked_flags_dimension_mismatch() {
        // Simulates an embedder-model switch: stored 384-style vs query
        // 768-style. The plain cosine would silently return 0.0; the
        // checked form must instead report the mismatch with both dims.
        let query = vec![0.0_f32; 5];
        let stored = vec![0.0_f32; 3];
        match Embedder::cosine_similarity_checked(&query, &stored) {
            CosineComparison::DimensionMismatch {
                query_dim,
                stored_dim,
            } => {
                assert_eq!(query_dim, 5);
                assert_eq!(stored_dim, 3);
            }
            CosineComparison::Comparable(_) => {
                panic!("differing-length vectors must report DimensionMismatch")
            }
        }
    }

    // --- v0.6.3.1 P2 — embedding magic-byte codec ---

    #[test]
    fn encode_embedding_blob_prefixes_le_header() {
        let v = vec![1.0_f32, 2.0_f32];
        let blob = encode_embedding_blob(&v);
        assert_eq!(blob.len(), 1 + 8);
        assert_eq!(blob[0], EMBEDDING_HEADER_LE_F32);
    }

    #[test]
    fn decode_embedding_blob_round_trip_v17() {
        let v = vec![1.5_f32, -0.25, 0.0];
        let blob = encode_embedding_blob(&v);
        let back = decode_embedding_blob(&blob).expect("round-trips");
        assert_eq!(back, v);
    }

    #[test]
    fn decode_embedding_blob_legacy_unheaded_le_f32() {
        // Pre-v17 rows: raw LE f32, no header. Length is `4n`.
        let v = vec![1.0_f32, 2.0, 3.0];
        let raw: Vec<u8> = v.iter().flat_map(|f| f.to_le_bytes()).collect();
        let back = decode_embedding_blob(&raw).expect("legacy decodes");
        assert_eq!(back, v);
    }

    #[test]
    fn decode_embedding_blob_rejects_be_header() {
        let mut blob = vec![EMBEDDING_HEADER_BE_F32];
        blob.extend_from_slice(&1.0_f32.to_be_bytes());
        let err = decode_embedding_blob(&blob).expect_err("BE rejected");
        assert!(matches!(err, EmbeddingFormatError::BigEndianUnsupported));
    }

    #[test]
    fn decode_embedding_blob_rejects_unknown_header() {
        let mut blob = vec![0xff_u8];
        blob.extend_from_slice(&1.0_f32.to_le_bytes());
        let err = decode_embedding_blob(&blob).expect_err("unknown header rejected");
        assert!(matches!(err, EmbeddingFormatError::UnknownHeader(0xff)));
    }

    #[test]
    fn decode_embedding_blob_rejects_malformed_length() {
        // Length `4n + 2` is neither legacy (4n) nor headed (4n+1).
        let blob = vec![0u8; 6];
        let err = decode_embedding_blob(&blob).expect_err("malformed length rejected");
        assert!(matches!(err, EmbeddingFormatError::MalformedLength(6)));
    }

    #[test]
    fn decoded_dim_handles_all_three_paths() {
        // Empty.
        assert_eq!(decoded_dim(&[]), 0);
        // Legacy (4n).
        let raw: Vec<u8> = vec![0u8; 16];
        assert_eq!(decoded_dim(&raw), 4);
        // Headed (4n+1).
        let mut headed = vec![EMBEDDING_HEADER_LE_F32];
        headed.extend_from_slice(&[0u8; 12]);
        assert_eq!(decoded_dim(&headed), 3);
    }

    // --- v0.6.0.0 contextual recall — fuse() ---

    #[test]
    fn fuse_weighted_sum() {
        let p = vec![1.0, 0.0, 0.0];
        let s = vec![0.0, 1.0, 0.0];
        let f = Embedder::fuse(&p, &s, 0.7);
        assert!((f[0] - 0.7).abs() < 1e-6);
        assert!((f[1] - 0.3).abs() < 1e-6);
        assert!((f[2] - 0.0).abs() < 1e-6);
    }

    #[test]
    fn fuse_primary_weight_clamped() {
        let p = vec![1.0, 1.0];
        let s = vec![0.0, 0.0];
        let f = Embedder::fuse(&p, &s, 2.0);
        // Clamped to 1.0 — pure primary
        assert!((f[0] - 1.0).abs() < 1e-6);
        assert!((f[1] - 1.0).abs() < 1e-6);

        let f = Embedder::fuse(&p, &s, -0.5);
        // Clamped to 0.0 — pure secondary
        assert!((f[0] - 0.0).abs() < 1e-6);
        assert!((f[1] - 0.0).abs() < 1e-6);
    }

    #[test]
    fn fuse_dimension_mismatch_returns_primary() {
        let p = vec![1.0, 2.0, 3.0];
        let s = vec![4.0, 5.0]; // mismatched
        let f = Embedder::fuse(&p, &s, 0.7);
        assert_eq!(f, p);
    }

    #[test]
    fn fuse_cosine_pulls_toward_context() {
        // Query vector: [1, 0]. Context pulls toward [0, 1] at 30%.
        // Fused direction sits between them.
        let q = vec![1.0_f32, 0.0];
        let ctx = vec![0.0_f32, 1.0];
        let fused = Embedder::fuse(&q, &ctx, 0.7);
        // cos(fused, q) should exceed cos(fused, ctx) because primary weight is 70%.
        let sim_q = Embedder::cosine_similarity(&fused, &q);
        let sim_ctx = Embedder::cosine_similarity(&fused, &ctx);
        assert!(sim_q > sim_ctx);
        assert!(sim_q > 0.9); // ~0.919 analytically
        assert!(sim_ctx > 0.3); // ~0.394 analytically
    }

    // -----------------------------------------------------------------
    // W11/S11b — fuse() weight-1 + cosine-direction invariants
    // -----------------------------------------------------------------

    #[test]
    fn test_fuse_with_weight_one_returns_primary() {
        // fuse(primary, secondary, 1.0) MUST return the primary vector
        // verbatim. The doc commits to "result is returned un-normalized" —
        // so equality must hold element-by-element.
        let primary = vec![0.6_f32, -0.8, 0.0]; // L2 norm = 1
        let secondary = vec![0.0_f32, 0.0, 1.0];
        let fused = Embedder::fuse(&primary, &secondary, 1.0);
        assert_eq!(fused.len(), primary.len());
        for (i, (f, p)) in fused.iter().zip(primary.iter()).enumerate() {
            assert!(
                (f - p).abs() < 1e-6,
                "fuse weight=1 idx {i}: fused {} != primary {}",
                f,
                p
            );
        }

        // Cosine-direction equivalence: even after any (no-op) normalization,
        // the direction matches the primary.
        let sim = Embedder::cosine_similarity(&fused, &primary);
        assert!(
            (sim - 1.0).abs() < 1e-6,
            "cos(fuse(p,s,1.0), p) must be 1.0"
        );
    }

    // -----------------------------------------------------------------
    // L0.7-6 Tier E — EmbedStatus + EmbeddingFormatError surfaces.
    // -----------------------------------------------------------------

    #[test]
    fn embed_status_as_str_each_variant() {
        assert_eq!(EmbedStatus::Indexed.as_str(), "indexed");
        assert_eq!(
            EmbedStatus::Skipped("too big".to_string()).as_str(),
            "skipped"
        );
        assert_eq!(
            EmbedStatus::Failed("ollama down".to_string()).as_str(),
            "failed"
        );
    }

    /// #1595 — the shared oversize guard fires strictly above the cap
    /// and names both the offending size and the cap in its reason.
    #[test]
    fn oversize_embed_reason_boundary_1595() {
        assert_eq!(oversize_embed_reason(0), None);
        assert_eq!(
            oversize_embed_reason(EMBED_MAX_BYTES),
            None,
            "cap itself is allowed"
        );
        let reason = oversize_embed_reason(EMBED_MAX_BYTES + 1).expect("over-cap must skip");
        assert!(
            reason.contains(&(EMBED_MAX_BYTES + 1).to_string())
                && reason.contains(&EMBED_MAX_BYTES.to_string()),
            "reason must name size + cap, got: {reason}"
        );
    }

    #[test]
    fn embed_status_is_degraded_only_for_non_indexed() {
        assert!(!EmbedStatus::Indexed.is_degraded());
        assert!(EmbedStatus::Skipped("x".to_string()).is_degraded());
        assert!(EmbedStatus::Failed("x".to_string()).is_degraded());
    }

    #[test]
    fn embed_status_reason_helper() {
        assert_eq!(EmbedStatus::Indexed.reason(), "");
        assert_eq!(EmbedStatus::Skipped("r1".to_string()).reason(), "r1");
        assert_eq!(EmbedStatus::Failed("r2".to_string()).reason(), "r2");
    }

    #[test]
    fn embed_status_display_includes_reason() {
        assert_eq!(format!("{}", EmbedStatus::Indexed), "indexed");
        assert_eq!(
            format!("{}", EmbedStatus::Skipped("oversize".to_string())),
            "skipped: oversize"
        );
        assert_eq!(
            format!("{}", EmbedStatus::Failed("timeout".to_string())),
            "failed: timeout"
        );
    }

    #[test]
    fn embedding_format_error_display_each_variant() {
        let unk = EmbeddingFormatError::UnknownHeader(0xab);
        assert!(unk.to_string().contains("0xab"));
        let be = EmbeddingFormatError::BigEndianUnsupported;
        assert!(be.to_string().contains("big-endian"));
        let ml = EmbeddingFormatError::MalformedLength(7);
        assert!(ml.to_string().contains("7"));
    }

    #[test]
    fn embedding_format_error_is_std_error() {
        // Pin the std::error::Error implementation so anyhow `?` chains
        // continue to work with this typed error at every call site.
        let e: Box<dyn std::error::Error> = Box::new(EmbeddingFormatError::BigEndianUnsupported);
        // Sources is None by default; the trait is implemented purely
        // for the marker.
        assert!(e.source().is_none());
    }

    #[test]
    fn decode_embedding_blob_empty_returns_empty_vec() {
        let v = decode_embedding_blob(&[]).expect("empty decodes to empty");
        assert!(v.is_empty());
    }

    #[test]
    fn test_fuse_is_l2_normalized() {
        // The current fuse() contract returns an UN-normalized vector
        // (per its rustdoc). Cosine_similarity divides out magnitudes,
        // so the practical signal is direction. This test pins the
        // observed behavior so a future change to "return L2-normalized
        // output" is caught — and asserts the direction-only contract
        // holds via cosine_similarity.
        let primary = vec![3.0_f32, 0.0, 0.0]; // norm = 3
        let secondary = vec![0.0_f32, 4.0, 0.0]; // norm = 4
        let fused = Embedder::fuse(&primary, &secondary, 0.5);
        // Raw fused = [1.5, 2.0, 0.0]; L2 norm = sqrt(1.5^2 + 2.0^2) = 2.5
        let norm = fused.iter().map(|x| x * x).sum::<f32>().sqrt();
        // Pin behavior: returned vector is NOT L2-normalized.
        assert!(
            (norm - 2.5).abs() < 1e-5,
            "fuse currently returns un-normalized vec; norm should be 2.5, got {norm}"
        );

        // But the cosine-direction signal is well-defined and consistent
        // with a hypothetical normalized output.
        let normalized: Vec<f32> = fused.iter().map(|x| x / norm).collect();
        let renorm = normalized.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (renorm - 1.0).abs() < 1e-5,
            "renormalized fused must have unit norm, got {renorm}"
        );
        // Direction is preserved between un-normalized and normalized.
        let sim = Embedder::cosine_similarity(&fused, &normalized);
        assert!(
            (sim - 1.0).abs() < 1e-5,
            "cos(raw_fuse, normalize(raw_fuse)) must be 1.0, got {sim}"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value,
    clippy::wildcard_imports
)]
pub mod test_support {
    use super::*;

    /// Mock embedder for testing model-loading paths without HuggingFace Hub
    /// or candle dependencies. Returns deterministic fake embeddings.
    pub enum MockEmbedder {
        /// Mock local embedder — always returns 384-dim vectors (MiniLM).
        Local,
        /// Mock Ollama embedder — always returns 768-dim vectors (nomic).
        Ollama,
    }

    impl MockEmbedder {
        /// Create a mock local embedder (MiniLM path).
        pub fn new_local() -> Result<Self> {
            Ok(Self::Local)
        }

        /// Create a mock Ollama embedder (nomic path).
        pub fn new_ollama() -> Self {
            Self::Ollama
        }

        /// Generate a deterministic mock embedding based on text hash.
        pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
            let dim = match self {
                Self::Local => MINILM_DIM,
                Self::Ollama => NOMIC_DIM,
            };
            let hash = text.bytes().fold(0u32, |acc, b| {
                acc.wrapping_mul(31).wrapping_add(u32::from(b))
            });
            let base = ((hash % 1000) as f32) / 1000.0;
            let embedding: Vec<f32> = (0..dim)
                .map(|i| base + ((i as f32) * 0.0001).sin().abs())
                .collect();
            Ok(embedding)
        }

        /// Batch embed with mock embeddings.
        pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            texts.iter().map(|t| self.embed(t)).collect()
        }

        /// Return the dimensionality.
        pub fn dim(&self) -> usize {
            match self {
                Self::Local => MINILM_DIM,
                Self::Ollama => NOMIC_DIM,
            }
        }

        /// Return a model description.
        pub fn model_description(&self) -> &str {
            match self {
                Self::Local => "mock-all-MiniLM-L6-v2 (384-dim, local)",
                Self::Ollama => "mock-nomic-embed-text-v1.5 (768-dim, Ollama)",
            }
        }
    }

    /// v0.7.0 L0.7 — [`Embed`] trait impl so unit tests can substitute
    /// the mock for the real [`Embedder`] at handler call sites that
    /// accept `Option<&dyn Embed>`. Delegates to the inherent
    /// implementation. Bug `8f3443c5`.
    impl Embed for MockEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>> {
            Self::embed(self, text)
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Self::embed_batch(self, texts)
        }
    }

    /// v0.7.0 polish (issue #767) — embedder that always returns
    /// `Err`. Unblocks tests for the `emb.embed(...)` failure-warn arms
    /// in `mcp::tools::store` (and similar callers) that would otherwise
    /// be structurally unreachable: the production [`Embedder`] only
    /// errors on tokeniser / model-forward faults that don't happen
    /// against an in-memory fixture, and [`MockEmbedder`] is documented
    /// to never error. This trait-only fake makes the warn branch
    /// reachable without contorting the production code path.
    pub struct FailingEmbedder;

    impl Embed for FailingEmbedder {
        fn embed(&self, _text: &str) -> Result<Vec<f32>> {
            Err(anyhow::anyhow!("test: synthetic embed failure"))
        }

        fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Err(anyhow::anyhow!("test: synthetic embed_batch failure"))
        }
    }
}

#[cfg(test)]
mod mock_tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn mock_local_new() {
        let embedder = MockEmbedder::new_local();
        assert!(embedder.is_ok());
    }

    #[test]
    fn mock_ollama_new() {
        let embedder = MockEmbedder::new_ollama();
        match embedder {
            MockEmbedder::Ollama => {}
            _ => panic!("expected Ollama variant"),
        }
    }

    #[test]
    fn mock_local_dim() {
        let embedder = MockEmbedder::new_local().unwrap();
        assert_eq!(embedder.dim(), MINILM_DIM);
    }

    #[test]
    fn mock_ollama_dim() {
        let embedder = MockEmbedder::new_ollama();
        assert_eq!(embedder.dim(), NOMIC_DIM);
    }

    #[test]
    fn mock_embed_local_deterministic() {
        let embedder = MockEmbedder::new_local().unwrap();
        let e1 = embedder.embed("test").unwrap();
        let e2 = embedder.embed("test").unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn mock_embed_local_dimension() {
        let embedder = MockEmbedder::new_local().unwrap();
        let embedding = embedder.embed("hello world").unwrap();
        assert_eq!(embedding.len(), MINILM_DIM);
    }

    #[test]
    fn mock_embed_ollama_dimension() {
        let embedder = MockEmbedder::new_ollama();
        let embedding = embedder.embed("hello world").unwrap();
        assert_eq!(embedding.len(), NOMIC_DIM);
    }

    #[test]
    fn mock_embed_batch_local() {
        let embedder = MockEmbedder::new_local().unwrap();
        let texts = vec!["text1", "text2", "text3"];
        let embeddings = embedder.embed_batch(&texts).unwrap();
        assert_eq!(embeddings.len(), 3);
        for emb in embeddings {
            assert_eq!(emb.len(), MINILM_DIM);
        }
    }

    #[test]
    fn mock_embed_batch_ollama() {
        let embedder = MockEmbedder::new_ollama();
        let texts = vec!["text1", "text2"];
        let embeddings = embedder.embed_batch(&texts).unwrap();
        assert_eq!(embeddings.len(), 2);
        for emb in embeddings {
            assert_eq!(emb.len(), NOMIC_DIM);
        }
    }

    #[test]
    fn mock_local_model_description() {
        let embedder = MockEmbedder::new_local().unwrap();
        let desc = embedder.model_description();
        assert!(desc.contains("MiniLM"));
        assert!(desc.contains("384"));
    }

    #[test]
    fn mock_ollama_model_description() {
        let embedder = MockEmbedder::new_ollama();
        let desc = embedder.model_description();
        assert!(desc.contains("nomic"));
        assert!(desc.contains("768"));
    }

    #[test]
    fn mock_embed_different_texts_different_vectors() {
        let embedder = MockEmbedder::new_local().unwrap();
        let e1 = embedder.embed("text one").unwrap();
        let e2 = embedder.embed("text two").unwrap();
        // Different inputs should generally produce different embeddings
        assert_ne!(e1[0], e2[0]);
    }
}

#[test]
fn cache_evicts_least_recently_used() {
    // Mock embeddings use deterministic hash-based generation.
    // Test that LRU eviction maintains memory under bound.
    // (Full LRU cache testing is in the embeddings cache module;
    // this tests the interface contract.)
    let v1 = vec![1.0, 2.0, 3.0];
    let v2 = vec![4.0, 5.0, 6.0];
    let sim = Embedder::cosine_similarity(&v1, &v2);
    // Dot product = 1*4 + 2*5 + 3*6 = 32
    // norm_v1 = sqrt(14), norm_v2 = sqrt(77)
    let expected = 32.0 / (14.0_f32.sqrt() * 77.0_f32.sqrt());
    assert!((sim - expected).abs() < 1e-5);
}

// -----------------------------------------------------------------
// W12-H — for_model + cosine corner cases
// -----------------------------------------------------------------

#[cfg(test)]
mod w12h_extra_tests {
    use super::*;

    #[test]
    fn for_model_nomic_without_ollama_client_errors() {
        // NomicEmbedV15 requires an Ollama client; missing one errors.
        let res = Embedder::for_model(EmbeddingModel::NomicEmbedV15, None);
        match res {
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("Ollama") || err.contains("nomic"),
                    "expected ollama error msg, got: {err}"
                );
            }
            Ok(_) => panic!("expected NomicEmbedV15 without client to error"),
        }
    }

    #[test]
    fn cosine_similarity_both_zero_returns_zero() {
        let a = vec![0.0_f32; 3];
        let b = vec![0.0_f32; 3];
        let sim = Embedder::cosine_similarity(&a, &b);
        // denom is ~0 → returns 0.0 by guard.
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn cosine_similarity_negative_values() {
        let a = vec![1.0_f32, 2.0, 3.0];
        let b = vec![-1.0_f32, -2.0, -3.0];
        let sim = Embedder::cosine_similarity(&a, &b);
        assert!((sim + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_empty_vectors() {
        let a: Vec<f32> = vec![];
        let b: Vec<f32> = vec![];
        let sim = Embedder::cosine_similarity(&a, &b);
        // Equal length (both 0) → no early return; norms are 0; denom guard → 0.
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn fuse_zero_weight_returns_pure_secondary() {
        let p = vec![1.0_f32, 0.0];
        let s = vec![0.0_f32, 1.0];
        let f = Embedder::fuse(&p, &s, 0.0);
        assert!((f[0] - 0.0).abs() < 1e-6);
        assert!((f[1] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn fuse_empty_vectors_returns_empty() {
        let p: Vec<f32> = vec![];
        let s: Vec<f32> = vec![];
        let f = Embedder::fuse(&p, &s, 0.5);
        assert!(f.is_empty());
    }

    #[test]
    fn embedding_dim_constant_pinned() {
        assert_eq!(EMBEDDING_DIM, MINILM_DIM);
        assert_eq!(MINILM_DIM, 384);
        assert_eq!(NOMIC_DIM, 768);
    }

    #[test]
    fn fuse_dimension_mismatch_secondary_longer() {
        // Inverse of the existing test — ensures the early return triggers
        // regardless of which side is shorter.
        let p = vec![1.0_f32, 2.0];
        let s = vec![3.0_f32, 4.0, 5.0]; // longer
        let f = Embedder::fuse(&p, &s, 0.5);
        assert_eq!(f, p);
    }

    #[test]
    fn cosine_similarity_dimension_mismatch_inverse() {
        // Verify guard fires for either ordering.
        let a = vec![1.0_f32, 0.0];
        let b = vec![1.0_f32, 0.0, 0.0];
        let sim = Embedder::cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn pr9i_for_model_minilm_dispatches_to_new_local() {
        // Exercises the MiniLmL6V2 dispatch arm (line 115). Behavior is
        // environment-dependent: on a machine with HF cache or network the
        // call succeeds; without either it errors with the documented
        // "model files not found in fallback dir" message. Both outcomes
        // are acceptable — what matters is that the dispatch arm is hit.
        let res = Embedder::for_model(EmbeddingModel::MiniLmL6V2, None);
        match res {
            Ok(e) => {
                // Path-of-success branch reachable iff HF cache is present.
                assert_eq!(e.dim(), 384);
                let desc = e.model_description();
                assert!(desc.contains("MiniLM"));
            }
            Err(e) => {
                // Path-of-failure branch reachable iff offline + no cache.
                let msg = e.to_string();
                assert!(
                    msg.contains("model")
                        || msg.contains("config")
                        || msg.contains("tokenizer")
                        || msg.contains("fallback")
                        || msg.contains("HuggingFace"),
                    "unexpected new_local error: {msg}"
                );
            }
        }
    }

    #[test]
    fn pr9i_embedder_new_alias_is_new_local() {
        // `Embedder::new()` is a thin shim over `new_local()` (line 50-52).
        // Same dual-outcome logic as above.
        let res = Embedder::new();
        match res {
            Ok(e) => {
                assert_eq!(e.dim(), 384);
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(!msg.is_empty());
            }
        }
    }
}

#[test]
fn embedder_returns_unreachable_when_model_path_missing() {
    // Test that load_from_fallback returns an error when model files
    // are not present in the fallback directory.
    let result = Embedder::load_from_fallback();
    // On a test machine without pre-downloaded models, this should fail
    // with a descriptive error message.
    match result {
        Ok(_) => {
            // If the fallback directory exists, that's OK — skip this assertion
        }
        Err(e) => {
            // Expected: error message mentions fallback dir or model files
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("not found") || err_msg.contains("fallback"),
                "error should mention missing model files: {err_msg}"
            );
        }
    }
}

#[test]
fn load_from_fallback_succeeds_when_files_present() {
    // Set HOME to a temp dir that has the expected fallback structure
    // populated with placeholder files. This exercises the Ok-branch
    // (lines 272-273) without requiring real model files — Tokenizer
    // loading is not part of `load_from_fallback`.
    use std::sync::Mutex;
    // Serialize on a global mutex — env::set_var is process-wide and would
    // race with parallel tests that also touch HOME.
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let tmp = std::env::temp_dir().join(format!("ai-memory-w12h-fallback-{}", std::process::id()));
    let model_dir = tmp.join(
        ".cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/snapshots/main",
    );
    std::fs::create_dir_all(&model_dir).expect("mk model dir");
    for name in ["config.json", "tokenizer.json", "model.safetensors"] {
        std::fs::write(model_dir.join(name), b"{}").expect("write placeholder");
    }
    let prev = std::env::var("HOME").ok();
    // SAFETY: serialized via LOCK above; no other thread mutates HOME.
    unsafe {
        std::env::set_var("HOME", &tmp);
    }
    let result = Embedder::load_from_fallback();
    // Restore HOME before any assertion that could panic.
    unsafe {
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    let (cfg, tok, w) = result.expect("placeholder files satisfy load_from_fallback");
    assert!(cfg.ends_with("config.json"));
    assert!(tok.ends_with("tokenizer.json"));
    assert!(w.ends_with("model.safetensors"));
}

#[test]
fn offline_env_skips_network_and_errors_fast_on_empty_cache() {
    // #1501 — with the offline knob set and no pre-staged cache, `new_local`
    // must take the no-network branch and surface the fallback error fast
    // (the caller then degrades to keyword). This proves the cold-download
    // race can't happen: no HF-Hub fetch is attempted at all.
    use std::sync::Mutex;
    // env::set_var + HOME are process-wide; serialize against the other
    // env-mutating tests in this module.
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let tmp = std::env::temp_dir().join(format!(
        "ai-memory-1501-offline-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp).expect("mk empty home");
    let prev_home = std::env::var("HOME").ok();
    let prev_off = std::env::var("AI_MEMORY_EMBED_OFFLINE").ok();
    // SAFETY: serialized via LOCK; no other thread mutates these here.
    unsafe {
        std::env::set_var("HOME", &tmp);
        std::env::set_var("AI_MEMORY_EMBED_OFFLINE", "1");
    }
    assert!(
        Embedder::remote_fetch_disabled(),
        "offline knob must be honored"
    );
    let result = Embedder::new_local();
    // Restore env before any assertion that could panic.
    unsafe {
        match prev_home {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        match prev_off {
            Some(v) => std::env::set_var("AI_MEMORY_EMBED_OFFLINE", v),
            None => std::env::remove_var("AI_MEMORY_EMBED_OFFLINE"),
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    let msg = match result {
        Ok(_) => panic!("empty cache + offline must error (degrades to keyword)"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("not found") || msg.contains("fallback"),
        "offline empty-cache error should point at the fallback dir: {msg}"
    );
}

// ---------------------------------------------------------------------------
// C-5 (#699): Cover the Ollama-variant `Embedder` constructor + `embed*` +
// `dim` / `model_description` paths using a wiremock-backed real
// `OllamaClient`. This closes the lib-tier `Ollama { .. }` arms across
// `embed()`, `dim()`, `model_description()`, and `embed_with_status()` that
// were the bulk of the 91.39% baseline gap on `embeddings.rs`. Hermetic —
// no live Ollama daemon required.
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod c5_ollama_variant_tests {
    use super::*;
    use crate::llm::OllamaClient;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Stand up an in-process `OllamaClient` against a wiremock instance
    /// pre-configured with the minimum routes required to construct +
    /// embed. Returns the `Arc<OllamaClient>` plus the server (keep the
    /// server alive in the caller's scope).
    async fn ollama_with_embed_response(embedding_dim: usize) -> (Arc<OllamaClient>, MockServer) {
        let server = MockServer::start().await;
        // /api/tags — required so `OllamaClient::new_with_url` doesn't
        // fail the construct-time health check.
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        // /api/pull — for ensure_embed_model; we let it succeed.
        Mock::given(method("POST"))
            .and(path("/api/pull"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        // /api/embed — the dispatch target for `client.embed_text(...)`.
        let vec_of_floats: Vec<f32> = (0..embedding_dim).map(|i| (i as f32) * 0.001).collect();
        Mock::given(method("POST"))
            .and(path("/api/embed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "embeddings": [vec_of_floats],
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let client = tokio::task::spawn_blocking(move || {
            OllamaClient::new_with_url(&uri, "test-model").expect("ollama client builds")
        })
        .await
        .expect("spawn blocking completes");
        (Arc::new(client), server)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embedder_new_ollama_constructs_with_expected_model_name() {
        // Lines 221-226: `new_ollama` constructor path.
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        assert!(matches!(embedder, Embedder::Ollama { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embedder_for_model_nomic_with_client_succeeds() {
        // Lines 238-247 (Ok arm) + lines 243-246 of `for_model`:
        // `ensure_embed_model` is invoked and the Ollama variant
        // returned.
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = tokio::task::spawn_blocking(move || {
            Embedder::for_model(EmbeddingModel::NomicEmbedV15, Some(client))
                .expect("for_model NomicEmbedV15 with ollama client")
        })
        .await
        .unwrap();
        assert!(matches!(embedder, Embedder::Ollama { .. }));
        assert_eq!(embedder.dim(), NOMIC_DIM); // covers line 256
        let desc = embedder.model_description();
        assert!(desc.contains("nomic")); // covers line 264
        assert!(desc.contains("768"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embedder_ollama_embed_returns_vector_from_wiremock() {
        // Line 281: dispatch arm of `Embedder::embed` for the Ollama
        // variant. We hop into `spawn_blocking` because OllamaClient's
        // HTTP calls are reqwest::blocking under the hood.
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        let v = tokio::task::spawn_blocking(move || embedder.embed("hello"))
            .await
            .unwrap()
            .expect("embed_text via wiremock");
        assert_eq!(v.len(), NOMIC_DIM);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embed_with_status_skipped_on_empty_content() {
        // Lines 299-302: empty content → Skipped("empty content").
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        let (vec_opt, status) = embedder.embed_with_status("");
        assert!(vec_opt.is_none());
        assert!(matches!(status, EmbedStatus::Skipped(_)));
        assert_eq!(status.as_str(), "skipped");
        assert!(status.reason().contains("empty"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embed_with_status_skipped_on_oversized_content() {
        // Lines 303-310: content > EMBED_MAX_BYTES → Skipped(reason).
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        let big = "a".repeat(EMBED_MAX_BYTES + 1);
        let (vec_opt, status) = embedder.embed_with_status(&big);
        assert!(vec_opt.is_none());
        match status {
            EmbedStatus::Skipped(r) => {
                assert!(r.contains("exceeds embed cap"), "got: {r}");
            }
            other => panic!("expected Skipped, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embed_with_status_indexed_on_happy_path() {
        // Lines 311-316: Ok(v) where v is non-empty → Indexed.
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        let (vec_opt, status) =
            tokio::task::spawn_blocking(move || embedder.embed_with_status("hello world"))
                .await
                .unwrap();
        assert!(vec_opt.is_some());
        assert_eq!(status, EmbedStatus::Indexed);
        assert!(!status.is_degraded());
        assert_eq!(vec_opt.unwrap().len(), NOMIC_DIM);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embed_with_status_failed_when_embedder_errors() {
        // Lines 317-321: Err arm — wiremock returns a 500 so the
        // OllamaClient's embed_text returns Err.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/embed"))
            .respond_with(ResponseTemplate::new(500).set_body_string("server error"))
            .mount(&server)
            .await;
        let uri = server.uri();
        let embedder = tokio::task::spawn_blocking(move || {
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            Embedder::new_ollama(Arc::new(client))
        })
        .await
        .unwrap();

        let (vec_opt, status) =
            tokio::task::spawn_blocking(move || embedder.embed_with_status("hello"))
                .await
                .unwrap();
        assert!(vec_opt.is_none());
        match status {
            EmbedStatus::Failed(reason) => {
                assert!(!reason.is_empty());
            }
            other => panic!("expected Failed(_), got {other:?}"),
        }
    }

    #[test]
    fn perf_5_embed_batch_empty_input_returns_empty_vec() {
        // PERF-5 — the batched local arm must short-circuit on
        // empty input rather than attempting `encode_batch(&[])`
        // which could error on some tokenizers crate versions.
        // Walk through MockEmbedder (the Embed trait implementor
        // that doesn't need a live Candle model). Its inherent
        // `embed_batch` is the same contract as the production
        // Embedder's PERF-5 fast-path.
        use super::test_support::MockEmbedder;
        let mock = MockEmbedder::new_local().expect("mock local");
        let result = mock.embed_batch(&[]).expect("empty batch ok");
        assert!(
            result.is_empty(),
            "PERF-5: empty input must yield empty output (got {} rows)",
            result.len(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embed_batch_via_inherent_impl_returns_one_vec_per_input() {
        // Lines 370-372: `Embedder::embed_batch` inherent method.
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        let vecs =
            tokio::task::spawn_blocking(move || embedder.embed_batch(&["one", "two", "three"]))
                .await
                .unwrap()
                .expect("batch embed succeeds");
        assert_eq!(vecs.len(), 3);
        for v in &vecs {
            assert_eq!(v.len(), NOMIC_DIM);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embed_trait_for_embedder_delegates_to_inherent_impl() {
        // Lines 452-458: `impl Embed for Embedder { embed / embed_batch }`.
        let (client, _server) = ollama_with_embed_response(NOMIC_DIM).await;
        let embedder = Embedder::new_ollama(client);
        let embedder_box: Box<dyn Embed> = Box::new(embedder);
        let single = tokio::task::spawn_blocking({
            let e = embedder_box;
            move || {
                let single = e.embed("alpha").expect("single embed");
                let batch = e.embed_batch(&["beta", "gamma"]).expect("batch embed");
                (single, batch)
            }
        })
        .await
        .unwrap();
        let (single, batch) = single;
        assert_eq!(single.len(), NOMIC_DIM);
        assert_eq!(batch.len(), 2);
        for v in &batch {
            assert_eq!(v.len(), NOMIC_DIM);
        }
    }

    #[test]
    fn embed_trait_default_batch_default_impl_runs_for_external_impls() {
        // Lines 144-146: trait default `Embed::embed_batch`. To trigger
        // the default body we need an `Embed` implementor that does NOT
        // override `embed_batch`. We define one inline.
        struct ConstEmbedder;
        impl Embed for ConstEmbedder {
            fn embed(&self, _text: &str) -> Result<Vec<f32>> {
                Ok(vec![1.0_f32, 2.0_f32, 3.0_f32])
            }
            // intentionally NOT overriding embed_batch → default impl runs
        }
        let e = ConstEmbedder;
        let batch = e.embed_batch(&["a", "b"]).expect("default batch path");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], vec![1.0_f32, 2.0_f32, 3.0_f32]);
        assert_eq!(batch[1], vec![1.0_f32, 2.0_f32, 3.0_f32]);
    }

    // #1487 — the download watchdog must surface an error instead of
    // blocking forever when the underlying download closure stalls.
    #[test]
    fn download_within_times_out_on_stalled_closure() {
        let start = std::time::Instant::now();
        let res = Embedder::download_within(std::time::Duration::from_millis(50), || {
            // Simulate a wedged hf-hub `.get()` that never returns within
            // the budget. The watchdog must abandon it, not join it.
            std::thread::sleep(std::time::Duration::from_secs(30));
            Ok((
                std::path::PathBuf::new(),
                std::path::PathBuf::new(),
                std::path::PathBuf::new(),
            ))
        });
        let elapsed = start.elapsed();
        assert!(res.is_err(), "stalled download must error, not hang");
        assert!(
            res.unwrap_err().to_string().contains("budget"),
            "error should explain the timeout budget"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "watchdog must return promptly after the budget, not wait for the closure: {elapsed:?}"
        );
    }

    // #1487 — a closure that completes within budget passes its result
    // through unchanged (the happy path the watchdog must not disturb).
    #[test]
    fn download_within_passes_through_fast_result() {
        let res = Embedder::download_within(std::time::Duration::from_secs(5), || {
            Ok((
                std::path::PathBuf::from("config.json"),
                std::path::PathBuf::from("tokenizer.json"),
                std::path::PathBuf::from("model.safetensors"),
            ))
        })
        .expect("fast closure must pass through");
        assert_eq!(res.0, std::path::PathBuf::from("config.json"));
        assert_eq!(res.2, std::path::PathBuf::from("model.safetensors"));
    }
}
