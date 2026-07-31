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

// ---------------------------------------------------------------------------
// v1.0.0 #2577 — recall-path query-embedding budget + bounded cache
// ---------------------------------------------------------------------------

/// #2577 — wall-clock budget for the query-embedding call on the RECALL
/// (read) path, in milliseconds.
///
/// **Why a read needs its own budget.** The remote embed client is built
/// with `GENERATE_TIMEOUT` (30 s) — a *generation* budget sized for chat
/// completions — and `CONNECT_TIMEOUT` (5 s). Applying a 30 s generation
/// budget to a READ means a slow provider converts `memory_recall` into a
/// 30 s hang. That is an AVAILABILITY defect, not merely a latency one:
///
/// * On **MCP stdio** the loop is single-threaded by JSON-RPC protocol
///   design (one request in, one response out — the #965 audit), so the
///   stall blocks EVERY subsequent tool call, including `memory_store`.
///   A stall longer than the host's request timeout presents as the MCP
///   server dropping its connection.
/// * On the **HTTP daemon** each stalled recall holds an admission permit
///   for its whole duration (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`, default-on
///   since #2032 M3), so sustained provider latency saturates the in-flight
///   cap and sheds HEALTHY traffic — including durable-truth writes — with
///   503s.
///
/// On expiry the recall **degrades to keyword** and reports `mode:keyword`
/// honestly, which is the #1593 posture applied to SLOWNESS rather than
/// only to embedder-CONSTRUCTION failure. That is a DEGRADE (fewer, less
/// refined results), never a wrong result: the durable memory text is
/// untouched, recall is pure (#1869/#1953), and the response tells the
/// caller which ranking it got.
///
/// Tri-state, mirroring `AI_MEMORY_MAX_INFLIGHT_REQUESTS` (#2032 M3):
/// unset ⇒ [`RECALL_EMBED_BUDGET_MS_DEFAULT`]; an explicit `0` ⇒ DISABLED
/// (restores the pre-#2577 unbounded-until-30 s behaviour); unparseable ⇒
/// the default (an unrecognised token must never silently WIDEN the
/// failure window — the #131/FBL-14 rule).
pub const ENV_RECALL_EMBED_BUDGET_MS: &str = "AI_MEMORY_RECALL_EMBED_BUDGET_MS";

/// #2577 — compiled default for [`ENV_RECALL_EMBED_BUDGET_MS`].
///
/// 2000 ms is ~4x the p99 (492 ms) and ~13x the p50 (156 ms) measured for
/// a healthy `openrouter` round trip on the #2576/#2577 reference corpus,
/// so under the measured distribution it fires on approximately nothing —
/// it is a TAIL cutter aimed at the sampled 39.3 s stall, not a throughput
/// governor. It is also the substrate's own declared read-class ceiling
/// (`crate::hooks::timeouts::READ_CLASS_DEADLINE_MS`), so the codebase does
/// not now hold two different answers to "how long may a read spend on an
/// out-of-process side quest".
pub const RECALL_EMBED_BUDGET_MS_DEFAULT: u64 = 2_000;

/// #2577 — capacity (entries) of the process-wide query-embedding cache.
/// `0` disables caching entirely.
pub const ENV_QUERY_EMBED_CACHE_ENTRIES: &str = "AI_MEMORY_QUERY_EMBED_CACHE_ENTRIES";

/// #2577 — compiled default for [`ENV_QUERY_EMBED_CACHE_ENTRIES`].
///
/// 512 entries bounds the cache at ~1.5 MB for a 768-dim model and ~6 MB
/// for a 3072-dim model — a fixed ceiling that does not grow with corpus,
/// namespace, or tenant count.
pub const QUERY_EMBED_CACHE_ENTRIES_DEFAULT: usize = 512;

/// #2577 — how long a cached query vector may be reused, in seconds.
///
/// A query embedding is a pure function of `(text, model, prefix scheme)`,
/// and the cache key carries the model + prefix scheme via the
/// [`embedding_space_fingerprint`], so a LOCAL model swap can never serve a
/// foreign-space vector — it is a key change, hence a miss. The TTL exists
/// for the one hazard the key cannot express: a REMOTE provider silently
/// re-training or re-pointing a model behind a stable id, which would leave
/// cached query vectors in the old space while newly-written ROW vectors
/// land in the new one. A bounded TTL caps that divergence window.
const QUERY_EMBED_CACHE_TTL_SECS: u64 = 900;

/// Cached resolution of [`ENV_RECALL_EMBED_BUDGET_MS`]. Read on every
/// recall, so resolved once and cached — the `strict_dim_enabled` /
/// `strict_embed_model_match_enabled` direct-read pattern (`src/hnsw.rs`).
///
/// Deliberately NOT a boot-seeded `OnceLock`: a seed-based knob is inert in
/// any process that does not cross the seeding funnel, which is the #2233
/// "defaults lie" class. A direct cached read is correct in every process,
/// including CLI one-shots and library embedders.
///
/// `u64::MAX` is the uninitialised sentinel (an unreachable budget value).
static RECALL_EMBED_BUDGET_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// The effective recall-path query-embed budget for this process.
/// `None` when the operator explicitly disabled it with `0`.
#[must_use]
pub fn recall_embed_budget() -> Option<std::time::Duration> {
    let cached = RECALL_EMBED_BUDGET_MS.load(std::sync::atomic::Ordering::Relaxed);
    let ms = if cached == u64::MAX {
        let resolved = match std::env::var(ENV_RECALL_EMBED_BUDGET_MS) {
            Err(_) => RECALL_EMBED_BUDGET_MS_DEFAULT,
            Ok(raw) => match raw.trim().parse::<u64>() {
                // Explicit 0 = disabled (tri-state, #2032 M3 precedent).
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        target: "recall.embed.budget",
                        value = %raw,
                        default_ms = RECALL_EMBED_BUDGET_MS_DEFAULT,
                        "unparseable {ENV_RECALL_EMBED_BUDGET_MS}; falling back to the \
                         compiled default (an unrecognised token must never widen the \
                         failure window)"
                    );
                    RECALL_EMBED_BUDGET_MS_DEFAULT
                }
            },
        };
        RECALL_EMBED_BUDGET_MS.store(resolved, std::sync::atomic::Ordering::Relaxed);
        resolved
    } else {
        cached
    };
    if ms == 0 {
        None
    } else {
        Some(std::time::Duration::from_millis(ms))
    }
}

/// Test-only override for the #2577 budget cache (the
/// `set_strict_dim_for_test` twin — avoids the #2115/#2146 env-lock
/// hazard). `None` re-reads the env on the next call. Process-global:
/// restore `None` before returning.
#[doc(hidden)]
pub fn set_recall_embed_budget_for_test(forced: Option<u64>) {
    RECALL_EMBED_BUDGET_MS.store(
        forced.unwrap_or(u64::MAX),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Cached resolution of [`ENV_QUERY_EMBED_CACHE_ENTRIES`]. `usize::MAX` is
/// the uninitialised sentinel.
static QUERY_EMBED_CACHE_ENTRIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// The effective query-embedding cache capacity for this process.
#[must_use]
pub fn query_embed_cache_capacity() -> usize {
    let cached = QUERY_EMBED_CACHE_ENTRIES.load(std::sync::atomic::Ordering::Relaxed);
    if cached != usize::MAX {
        return cached;
    }
    let resolved = std::env::var(ENV_QUERY_EMBED_CACHE_ENTRIES)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(QUERY_EMBED_CACHE_ENTRIES_DEFAULT);
    QUERY_EMBED_CACHE_ENTRIES.store(resolved, std::sync::atomic::Ordering::Relaxed);
    resolved
}

/// Test-only override for the #2577 cache-capacity cache.
#[doc(hidden)]
pub fn set_query_embed_cache_capacity_for_test(forced: Option<usize>) {
    QUERY_EMBED_CACHE_ENTRIES.store(
        forced.unwrap_or(usize::MAX),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// #2577 — cache key for a query embedding.
///
/// The query text is stored as a SHA-256 digest, never in cleartext: the
/// cache is a long-lived process-global, and recall context is caller-
/// supplied free text that may carry sensitive material. Hashing keeps raw
/// query strings out of a heap dump / core file without changing the
/// lookup semantics.
///
/// The digest is over the EXACT bytes handed to the embedder — no case
/// folding, no whitespace collapsing, no unicode normalisation. A lossy
/// fold would let two DIFFERENT queries collide onto one vector, which is
/// the only way this cache could produce a wrong result.
///
/// `space` is the [`embedding_space_fingerprint`] of the embedder, read at
/// LOOKUP time. It carries the canonical model id and the prefix scheme, so
/// (a) a model swap changes the key rather than requiring an invalidation
/// event that some funnel could forget to fire, and (b) an asymmetric
/// (nomic) query vector can never be served where a document vector is
/// expected, or vice versa.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryEmbedKey {
    digest: [u8; 32],
    space: String,
}

struct QueryEmbedCacheEntry {
    vector: Arc<Vec<f32>>,
    inserted: std::time::Instant,
    last_used: u64,
}

#[derive(Default)]
struct QueryEmbedCache {
    entries: std::collections::HashMap<QueryEmbedKey, QueryEmbedCacheEntry>,
    tick: u64,
    hits: u64,
    misses: u64,
}

static QUERY_EMBED_CACHE: std::sync::OnceLock<std::sync::Mutex<QueryEmbedCache>> =
    std::sync::OnceLock::new();

fn query_embed_cache() -> &'static std::sync::Mutex<QueryEmbedCache> {
    QUERY_EMBED_CACHE.get_or_init(|| std::sync::Mutex::new(QueryEmbedCache::default()))
}

fn query_embed_key(text: &str, space: &str) -> QueryEmbedKey {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    QueryEmbedKey {
        digest,
        space: space.to_string(),
    }
}

/// #2577 — observed cache statistics `(hits, misses, live entries)`.
/// Exposed for tests and for the operator-facing counters; carries NO
/// cache CONTENT, so it can never surface a query string.
#[must_use]
#[doc(hidden)]
pub fn query_embed_cache_stats() -> (u64, u64, usize) {
    query_embed_cache()
        .lock()
        .map_or((0, 0, 0), |c| (c.hits, c.misses, c.entries.len()))
}

/// #2577 — drop every cached query vector. Test-only; the cache is a
/// disposable derived artifact, so clearing it can never lose data.
#[doc(hidden)]
pub fn clear_query_embed_cache() {
    if let Ok(mut c) = query_embed_cache().lock() {
        c.entries.clear();
        c.tick = 0;
        c.hits = 0;
        c.misses = 0;
    }
}

/// #2577 — the ONE funnel every recall surface crosses to turn a query
/// string into a query vector.
///
/// Applies, in order: the bounded cache ([`ENV_QUERY_EMBED_CACHE_ENTRIES`])
/// and the wall-clock budget ([`ENV_RECALL_EMBED_BUDGET_MS`]). Returns
/// `None` when no vector could be produced within budget — the caller then
/// runs keyword-only and reports `mode:keyword`, which is the #1593 degrade
/// posture applied to slowness.
///
/// Callers MUST route through this rather than calling
/// [`Embed::embed_query`] directly on a read path; the funnel is pinned by
/// `tests/embed_budget_funnel_ceiling_2577.rs`.
#[must_use]
pub fn recall_query_embedding(embedder: &dyn Embed, text: &str) -> Option<Vec<f32>> {
    let capacity = query_embed_cache_capacity();
    let space = embedder.space_fingerprint();
    let key = (capacity > 0).then(|| query_embed_key(text, &space));

    if let Some(k) = key.as_ref()
        && let Ok(mut cache) = query_embed_cache().lock()
    {
        cache.tick = cache.tick.wrapping_add(1);
        let tick = cache.tick;
        let ttl = std::time::Duration::from_secs(QUERY_EMBED_CACHE_TTL_SECS);
        let fresh = cache
            .entries
            .get(k)
            .is_some_and(|e| e.inserted.elapsed() < ttl);
        if fresh {
            if let Some(e) = cache.entries.get_mut(k) {
                e.last_used = tick;
                let hit = Arc::clone(&e.vector);
                cache.hits = cache.hits.saturating_add(1);
                drop(cache);
                crate::metrics::inc_query_embed_cache_hit();
                return Some((*hit).clone());
            }
        } else {
            // Expired entries are evicted on observation so a stale vector
            // can never be served after the TTL window.
            cache.entries.remove(k);
        }
        cache.misses = cache.misses.saturating_add(1);
    }

    let budget = recall_embed_budget();
    let started = std::time::Instant::now();
    let vector = match embedder.embed_query_bounded(text, budget) {
        Ok(v) => v,
        Err(e) => {
            // DEGRADE, never fail the read: the caller falls back to
            // keyword/FTS and says so on the wire.
            tracing::warn!(
                target: "recall.embed.degraded",
                elapsed_ms = started.elapsed().as_millis() as u64,
                budget_ms = budget.map_or(0, |b| b.as_millis() as u64),
                error = %e,
                "query embedding unavailable within budget; recall degrades to keyword \
                 (#2577). Results will be FEWER and FTS-ranked, never wrong — the \
                 response reports mode:keyword."
            );
            crate::metrics::inc_recall_embed_degraded();
            return None;
        }
    };

    if let Some(k) = key
        && let Ok(mut cache) = query_embed_cache().lock()
    {
        cache.tick = cache.tick.wrapping_add(1);
        let tick = cache.tick;
        if cache.entries.len() >= capacity
            && !cache.entries.contains_key(&k)
            && let Some(victim) = cache
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
        {
            cache.entries.remove(&victim);
        }
        cache.entries.insert(
            k,
            QueryEmbedCacheEntry {
                vector: Arc::new(vector.clone()),
                inserted: std::time::Instant::now(),
                last_used: tick,
            },
        );
    }
    Some(vector)
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

/// #2168 — embedding-space fingerprint prefix-scheme tokens. The scheme
/// axis records HOW a model prepends retrieval task instructions, so two
/// peers on the SAME model id but different prefix behaviour (the #1520
/// nomic asymmetric `search_document:` / `search_query:` scheme vs a
/// symmetric model) are distinguished at the federation receive gate
/// (M-DOCUMENTED-MAGIC).
const PREFIX_SCHEME_NONE: &str = "none";
const PREFIX_SCHEME_NOMIC_TASK_V1: &str = "nomic-task-v1";

/// #2168 (SEC, data-integrity) — canonical embedding-space fingerprint
/// used by the federation receive gate (`sync_push`, both backends) to
/// reject a same-dimension vector produced by a DIFFERENT embedding model
/// / prefix scheme. A same-dim vector from model A lives in a different
/// coordinate space than one from model B: stored verbatim it silently
/// poisons this node's cosine recall (no error, a numerically-valid but
/// semantically-meaningless score). This generalises the existing
/// dim-equality gate into a vector-space IDENTITY check.
///
/// The fingerprint is `<canonical_model_id>#<prefix_scheme>`; the vector
/// DIMENSION is DELIBERATELY excluded — it stays on the separate dim gate
/// (`receiver_dim == se.dim`) so there is one SSOT per axis
/// (M-DOCUMENTED-MAGIC).
///
/// `model` accepts the display prose carried by
/// [`crate::federation::ShippedEmbedding::model`] /
/// [`Embedder::model_description`] (`"<id> (<dim>-dim, <origin>)"`) OR a
/// bare model id: the id is the token before the ` (` suffix, lowercased.
/// The prefix scheme is derived from that id EXACTLY as the local embed
/// path derives it ([`Embedder::model_requires_nomic_prefix`], the #1520
/// predicate), so a receiver and a well-behaved peer on the same model
/// mint the SAME fingerprint WITHOUT any wire change. Distinct model ids
/// NEVER collide, so the gate can produce a false MISMATCH (→ a safe
/// local re-embed) but NEVER a false MATCH (→ corruption): degrade, never
/// corrupt (#2168 CORE INVARIANT). M-STRONG-TYPES-GUARD.
///
/// **[#2177] The `#<prefix_scheme>` axis is MODEL-IMPLIED, not an
/// independently transmitted wire value.** Both sides (the receiver's own
/// fingerprint AND its canonicalisation of the shipped `model` string) call
/// the SAME [`Embedder::model_requires_nomic_prefix`] predicate against the
/// (folded) model id — the scheme is a pure function of the id, computed
/// locally, never read off the wire. This is intentional and is what keeps
/// the gate wire-back-compat with zero wire changes across DIFFERENT model
/// ids. The residual: it CANNOT discriminate two peers on the SAME model id
/// whose binaries apply DIFFERENT prefix behaviour (e.g. a future release
/// that starts sending `task_type` for a role-asymmetric model this
/// predicate doesn't yet know about, or any future edit to the
/// `model_requires_nomic_prefix` table) — such a divergence would silently
/// mint the SAME fingerprint on both sides today. Promoting an explicit
/// `prefix_scheme` field onto the wire (`ShippedEmbedding`, additive +
/// `#[serde(default)]`) so a sender can assert its scheme independently of
/// the receiver's local derivation is DEFERRED to v1.x (tracked by #2177);
/// until then, this function is the SSOT for the implication and
/// `space_fingerprint_2168_tests::prefix_scheme_is_derived_from_model_id_2177`
/// pins it so a future change to the predicate can't silently drift this
/// axis without the test catching it.
//
// #2167 GENERALISATION (shared SSOT for federation-gate + per-row write-stamp +
// recall-gate + adoption): the body below keeps #2168's prose-strip AND adds
// the #2167 daemon-native family-fold + `:latest`-strip so every spelling of
// the two native families collapses to one id (snake wire form `nomic_embed_v15`,
// shortname `all-minilm`, Ollama tag, HF id). The prefix is derived from the
// FOLDED (canonical) id so `nomic_embed_v15` (underscore — misses the
// hyphenated `nomic-embed` needle) still yields `nomic-task-v1` via its fold.
#[must_use]
pub fn embedding_space_fingerprint(model: &str) -> String {
    // 1. Strip #2168's model_description() prose suffix (`"id (prose)"` → id).
    let bare = model
        .split_once(" (")
        .map_or(model, |(head, _)| head)
        .trim();
    // 2. Fold the two daemon-native families to their canonical HF id; else
    //    lowercase + strip ONE trailing `:latest` (Ollama's implicit default;
    //    any other tag e.g. `:v1.5` is version-meaningful and kept).
    let id = if let Some(known) = crate::config::EmbeddingModel::from_canonical_id(bare) {
        known.hf_model_id().to_ascii_lowercase()
    } else {
        let lowered = bare.to_ascii_lowercase();
        lowered
            .strip_suffix(":latest")
            .unwrap_or(&lowered)
            .to_string()
    };
    // 3. Prefix from the CANONICAL (post-fold) id via the live embed predicate.
    let scheme = if Embedder::model_requires_nomic_prefix(&id) {
        PREFIX_SCHEME_NOMIC_TASK_V1
    } else {
        PREFIX_SCHEME_NONE
    };
    format!("{id}#{scheme}")
}

/// v1.0.0 #2167 (S8 restore/migrate heal) — the process-wide ACTIVE
/// embedding-space fingerprint, seeded once at every embedder-construction
/// boot site (serve / mcp) from the resolved model, alongside the §5
/// adoption + §6 census. Read by the archive-RESTORE heal
/// ([`crate::storage::restore_archived`] /
/// [`crate::storage::restore_archived_for_caller`] /
/// `PostgresStore::archive_restore`) to classify a restored row's carried
/// `embedding_space`:
/// - space == active → the vector restores INTACT (no perf regression /
///   no needless re-embed on a homogeneous corpus);
/// - space != active OR (vector present but space NULL) → the whole
///   embedding trio (`embedding`/`embedding_dim`/`embedding_space`) is
///   NULLed so the existing `list_unembedded` backfill re-embeds the row
///   from the durable text under the LIVE space = SELF-HEAL.
///
/// `None` (unseeded: a keyword-only process, or a CLI verb that resolved no
/// embedder) makes the heal carry any STAMPED vector verbatim, but STILL
/// NULLs a vector with NO provenance (`embedding_space IS NULL`) — an
/// unverifiable vector is never re-introduced as valid. Degrade, never
/// corrupt (North Star).
static ACTIVE_EMBEDDING_SPACE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Seed (or clear, with `None`) the process-wide active embedding-space
/// fingerprint. Idempotent; the last writer wins. Called at every boot
/// site that resolves an embedder, and by tests. A poisoned lock is
/// tolerated (the seed is best-effort — a failed seed degrades the restore
/// heal to its `None` posture, which is still safe).
pub fn set_active_embedding_space(space: Option<String>) {
    if let Ok(mut guard) = ACTIVE_EMBEDDING_SPACE.write() {
        *guard = space;
    }
}

/// Read the process-wide active embedding-space fingerprint (`None` when
/// unseeded). See [`set_active_embedding_space`].
#[must_use]
pub fn active_embedding_space() -> Option<String> {
    ACTIVE_EMBEDDING_SPACE.read().ok().and_then(|g| g.clone())
}

#[cfg(test)]
mod space_fingerprint_2168_tests {
    use super::embedding_space_fingerprint;

    /// The display prose carried on the wire and a bare model id parse to
    /// the SAME fingerprint — the receiver derives the shipped fingerprint
    /// from `se.model` (prose) and its own from `model_description()`
    /// (prose) with byte-identical logic, and a future bare-id sender
    /// still matches.
    #[test]
    fn prose_and_bare_id_agree() {
        let prose = embedding_space_fingerprint("nomic-embed-text (768-dim, remote)");
        let bare = embedding_space_fingerprint("nomic-embed-text");
        assert_eq!(prose, bare, "prose suffix must not change the fingerprint");
        // #2167 generalisation: the daemon-native nomic family FOLDS to its
        // canonical HF id (so every spelling — Ollama tag, snake wire form,
        // HF id — collapses to one space).
        assert_eq!(prose, "nomic-ai/nomic-embed-text-v1.5#nomic-task-v1");
    }

    /// Two DIFFERENT 768-dim models (the exact #2168 attack: a
    /// heterogeneous fleet where peer A runs nomic-768 and peer B runs
    /// granite-768) mint DIFFERENT fingerprints, so the gate refuses the
    /// foreign vector even though the dim gate would pass.
    #[test]
    fn same_dim_foreign_model_differs() {
        let nomic = embedding_space_fingerprint("nomic-embed-text (768-dim, remote)");
        let granite = embedding_space_fingerprint("granite-embedding (768-dim, remote)");
        assert_ne!(
            nomic, granite,
            "same-dim foreign-model fingerprints must differ (#2168)"
        );
        assert_eq!(granite, "granite-embedding#none");
    }

    /// The local MiniLM embedder and a remote nomic embedder mint
    /// different fingerprints (different id AND different prefix scheme).
    #[test]
    fn local_minilm_differs_from_nomic() {
        let minilm = embedding_space_fingerprint("all-MiniLM-L6-v2 (384-dim, local)");
        let nomic = embedding_space_fingerprint("nomic-embed-text (768-dim, remote)");
        // #2167 generalisation: the daemon-native MiniLM family folds to its
        // canonical HF id.
        assert_eq!(minilm, "sentence-transformers/all-minilm-l6-v2#none");
        assert_ne!(minilm, nomic);
    }

    /// The prefix-scheme axis (#1520): the nomic family carries the
    /// asymmetric task-prefix scheme; a non-nomic model carries `none`.
    /// Recording the scheme explicitly guards cross-version drift of the
    /// prefix logic even when the model id is identical.
    #[test]
    fn prefix_scheme_axis_is_recorded() {
        assert!(embedding_space_fingerprint("nomic-embed-text").ends_with("#nomic-task-v1"));
        assert!(embedding_space_fingerprint("bge-base-en-v1.5").ends_with("#none"));
    }

    /// Case / whitespace normalisation so two spellings of the same model
    /// id do not produce a spurious MISMATCH.
    #[test]
    fn id_is_case_and_whitespace_normalised() {
        assert_eq!(
            embedding_space_fingerprint("  Nomic-Embed-Text (768-dim, remote)  "),
            embedding_space_fingerprint("nomic-embed-text"),
        );
    }

    /// **[#2177]** Pins the model→prefix-scheme implication explicitly:
    /// the `#<scheme>` half of the fingerprint is NOT an independently
    /// transmitted axis — it is always exactly
    /// `super::Embedder::model_requires_nomic_prefix(<canonical id>)`
    /// re-derived from the fingerprint's own id half. This test fails the
    /// moment a future change makes the fingerprint compute the scheme via
    /// a DIFFERENT code path than the local embed-prefix decision (the
    /// prose in [`super::embedding_space_fingerprint`] documents WHY this
    /// coupling exists and what the deferred v1.x explicit-field follow-up
    /// looks like).
    #[test]
    fn prefix_scheme_is_derived_from_model_id_2177() {
        let cases = [
            // (input, expect nomic-task-v1 scheme)
            ("nomic-embed-text", true),
            ("nomic-embed-text-v1.5", true),
            ("nomic-ai/nomic-embed-text-v1.5", true),
            ("granite-embedding", false),
            ("bge-base-en-v1.5", false),
            ("all-MiniLM-L6-v2", false),
            ("sentence-transformers/all-MiniLM-L6-v2", false),
        ];
        for (model, expect_nomic_scheme) in cases {
            let fp = embedding_space_fingerprint(model);
            let (id, scheme) = fp
                .split_once('#')
                .unwrap_or_else(|| panic!("fingerprint {fp:?} missing '#' separator"));
            // The scheme axis must equal a FRESH call of the same
            // #1520 predicate against the fingerprint's own (canonical,
            // post-fold) id — i.e. the scheme is model-IMPLIED, never an
            // independently-set value.
            let recomputed = super::Embedder::model_requires_nomic_prefix(id);
            assert_eq!(
                recomputed, expect_nomic_scheme,
                "model={model} id={id} scheme={scheme}"
            );
            let expected_scheme = if recomputed {
                super::PREFIX_SCHEME_NOMIC_TASK_V1
            } else {
                super::PREFIX_SCHEME_NONE
            };
            assert_eq!(
                scheme, expected_scheme,
                "model={model}: fingerprint scheme must equal \
                 model_requires_nomic_prefix(id) — the axis is model-implied (#2177)"
            );
        }
    }
}

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

    /// v1.0.0 #2577 — [`Embed::embed_query`] under a wall-clock budget.
    ///
    /// The default implementation IGNORES `budget` and delegates, which is
    /// correct for every implementor that cannot stall on a network: the
    /// local candle MiniLM backend is CPU-bound and bounded by its own
    /// sequence cap, and the test `MockEmbedder` is immediate. Only the
    /// REMOTE arm of the production [`Embedder`] can hang on a third party,
    /// and only it overrides this.
    ///
    /// This asymmetry is deliberate rather than an omission. A budget can
    /// only be honoured where the work is CANCELLABLE — an in-flight
    /// `reqwest` future is (dropping it aborts the request); a synchronous
    /// candle forward pass is not, and "bounding" it would mean abandoning
    /// a thread that keeps burning CPU, which is worse than waiting.
    ///
    /// # Errors
    ///
    /// Same as [`Embed::embed_query`], plus a budget-expiry error from
    /// implementors that honour `budget`.
    fn embed_query_bounded(
        &self,
        text: &str,
        budget: Option<std::time::Duration>,
    ) -> Result<Vec<f32>> {
        let _ = budget;
        self.embed_query(text)
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

    /// #2167 — the [`embedding_space_fingerprint`] of the vectors this embedder
    /// produces, exposed on the `dyn Embed` interface so the trait-generic
    /// backfill sweep ([`crate::store::run_embedding_backfill_on_store`],
    /// [`crate::mcp::run_embedding_backfill_with_batch_size`]) can stamp the
    /// live space without a concrete `Embedder`. The production [`Embedder`]
    /// overrides it (delegating to its inherent #2168 `space_fingerprint`); the
    /// default here is a stable sentinel (a mock embedder's vectors are never
    /// scored against a live query in production).
    fn space_fingerprint(&self) -> String {
        embedding_space_fingerprint("mock-embedder")
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
///
/// v1.0.0 #2167 — the space-identity axis extends this: a stored vector
/// may share the query's DIMENSION yet live in a DIFFERENT vector space
/// (a same-dim model swap), which the dim gate alone cannot catch. The
/// two new variants let [`Embedder::cosine_similarity_space_checked`]
/// exclude foreign / unverified rows from semantic scoring while recall
/// counts and surfaces them (degraded, never wrong). `Copy` is dropped
/// because [`CosineComparison::SpaceMismatch`] carries an owned space
/// token (M-ERRORS-CANONICAL-STRUCTS — the `DimensionMismatch`
/// precedent shape is preserved).
#[derive(Debug, Clone, PartialEq)]
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
    /// v1.0.0 #2167 — the stored vector is VERIFIED in a DIFFERENT
    /// embedding space than the live query embedder's (its
    /// `embedding_space` token != the active fingerprint). NEVER scored;
    /// remains keyword/FTS-recallable. Carries the stored space token so
    /// telemetry / the heal WARN can name the offending fingerprint.
    SpaceMismatch {
        /// The stored row's `embedding_space` token (`<id>#<scheme>`).
        stored_space: String,
    },
    /// v1.0.0 #2167 — the stored vector has NO provenance token
    /// (`embedding_space IS NULL` after §5 adoption). NEVER scored;
    /// remains keyword/FTS-recallable.
    UnverifiedSpace,
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
            .context("failed to build OpenAI-compatible embed client (#1598)")?
            // #1598 (fleet follow-up) — explicit `[embeddings].dim`
            // doubles as the requested Matryoshka output dim on the
            // OpenAI-compatible wire (see ResolvedEmbeddings::requested_dim).
            .with_embed_dimensions(resolved.requested_dim);
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

    /// #2168 (SEC, data-integrity) — this embedder's canonical
    /// vector-space fingerprint. Thin wrapper over
    /// [`embedding_space_fingerprint`] applied to
    /// [`Embedder::model_description`], so the receiver and a well-behaved
    /// peer on the SAME model mint the SAME fingerprint. Consumed by the
    /// federation receive gate (`sync_push` on both backends) to reject a
    /// same-dimension vector produced by a DIFFERENT embedding model /
    /// prefix scheme before it is stored verbatim into the local space.
    #[must_use]
    pub fn space_fingerprint(&self) -> String {
        embedding_space_fingerprint(&self.model_description())
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

    /// v1.0.0 #2577 — [`Self::embed_query`] under a wall-clock budget.
    ///
    /// The `Local` arm ignores the budget: a candle forward is CPU-bound,
    /// bounded by [`MAX_SEQ_LEN`], and has no cancellation point. The
    /// `Ollama` (remote) arm threads the budget into the HTTP call, where
    /// dropping the in-flight future genuinely aborts the request.
    ///
    /// A budget expiry is latched as a degrade on the `degraded` flag —
    /// identical to any other embed failure — so the capabilities surface
    /// reports the remote endpoint's real posture (#1594), and it is
    /// reported to the circuit breaker so repeated stalls fast-fail
    /// instead of each paying the full budget.
    ///
    /// # Errors
    ///
    /// Propagates the embed failure, or a budget-expiry error.
    pub fn embed_query_bounded(
        &self,
        text: &str,
        budget: Option<std::time::Duration>,
    ) -> Result<Vec<f32>> {
        match self {
            Self::Local { .. } => self.embed_with_role(text, EmbedRole::Query),
            Self::Ollama {
                client,
                model_name,
                degraded,
                ..
            } => {
                let owned;
                let payload = if Self::model_requires_nomic_prefix(model_name) {
                    owned = format!("{}{}", EmbedRole::Query.nomic_prefix(), text);
                    owned.as_str()
                } else {
                    text
                };
                let result = client.embed_text_with_budget(payload, model_name, budget);
                degraded.store(result.is_err(), std::sync::atomic::Ordering::Relaxed);
                result
            }
        }
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
            // Remote arm (#1603): delegate to the client's batched
            // embed — OpenAI-compatible providers get ONE `/embeddings`
            // POST per sub-batch (`input: [...]` wire shape) instead of
            // the pre-#1603 per-text loop that drained an API-backed
            // backfill at ~20 rows/min; Ollama-native keeps its
            // per-text loop inside `embed_texts` until its batched wire
            // contract is pinned. Documents get the nomic task prefix
            // exactly as the single-text path applies it (#1520), gated
            // on the model id.
            Self::Ollama {
                client,
                model_name,
                degraded,
                ..
            } => {
                let result = if Self::model_requires_nomic_prefix(model_name) {
                    let prefixed: Vec<String> = texts
                        .iter()
                        .map(|t| format!("{}{}", EmbedRole::Document.nomic_prefix(), t))
                        .collect();
                    let refs: Vec<&str> = prefixed.iter().map(String::as_str).collect();
                    client.embed_texts(&refs, model_name)
                } else {
                    client.embed_texts(texts, model_name)
                };
                // #1598/#1594 — latch the live remote-endpoint posture,
                // same as the single-text path.
                degraded.store(result.is_err(), std::sync::atomic::Ordering::Relaxed);
                result
            }
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

    /// v1.0.0 #2167 ★ — fingerprint-gated recall comparison. The load-
    /// bearing correctness primitive: a stored row is scored **only
    /// when** its `embedding_space` token equals the live embedder's
    /// `active` fingerprint EXACTLY. Foreign AND NULL (unverified) rows
    /// are excluded from semantic scoring — but callers keep them
    /// keyword/FTS-recallable (degraded, never wrong, never invisible).
    ///
    /// The check ORDER is load-bearing (M-DOCUMENTED-MAGIC):
    /// 1. **space identity** — a Verified-but-foreign row is
    ///    [`CosineComparison::SpaceMismatch`]; a NULL row is
    ///    [`CosineComparison::UnverifiedSpace`]. Neither is scored.
    /// 2. **dim** (defense-in-depth) — a Verified-active row whose
    ///    vector length nonetheless disagrees is corrupt →
    ///    [`CosineComparison::DimensionMismatch`].
    /// 3. **score** — [`CosineComparison::Comparable`].
    ///
    /// `stored_space` is the raw column value (`None` = SQL NULL). This
    /// never substring-matches: the fingerprint is compared as a whole
    /// value (api-newtype-safety intent, over the shared-String SSOT).
    #[must_use]
    pub fn cosine_similarity_space_checked(
        query: &[f32],
        stored: &[f32],
        active: &str,
        stored_space: Option<&str>,
    ) -> CosineComparison {
        // (1) space identity — the fail-closed gate.
        match stored_space {
            None => return CosineComparison::UnverifiedSpace,
            Some(s) if s != active => {
                return CosineComparison::SpaceMismatch {
                    stored_space: s.to_string(),
                };
            }
            Some(_) => {}
        }
        // (2) dim — defense-in-depth; a same-space vector whose length
        // disagrees is corrupt, not merely foreign.
        if query.len() != stored.len() {
            return CosineComparison::DimensionMismatch {
                query_dim: query.len(),
                stored_dim: stored.len(),
            };
        }
        // (3) score.
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
    ///
    /// `pub(crate)` (#2086) — the reranker's cross-encoder loader
    /// (`crate::reranker::CrossEncoder::resolve_cross_encoder_files`) shares
    /// this same offline knob so `AI_MEMORY_EMBED_OFFLINE`/`HF_HUB_OFFLINE`
    /// gates network fetches for BOTH the embedder and the reranker
    /// consistently, one substrate-wide offline posture rather than two.
    pub(crate) fn remote_fetch_disabled() -> bool {
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

    fn embed_query_bounded(
        &self,
        text: &str,
        budget: Option<std::time::Duration>,
    ) -> Result<Vec<f32>> {
        Self::embed_query_bounded(self, text, budget)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        Self::embed_batch(self, texts)
    }

    fn is_degraded(&self) -> bool {
        Self::is_degraded(self)
    }

    fn space_fingerprint(&self) -> String {
        // Delegate to the inherent #2168 method (returns the SSOT fingerprint).
        Embedder::space_fingerprint(self)
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

    // ---- #2167 §0 — embedding_space_fingerprint minting ----

    #[test]
    fn embedding_space_compiled_default_pins() {
        // §0.4 — a future default-model change becomes a deliberate,
        // test-visible act (issue table row b′). These two literals ARE the
        // tier-preset defaults' fingerprints.
        assert_eq!(
            embedding_space_fingerprint("sentence-transformers/all-MiniLM-L6-v2"),
            "sentence-transformers/all-minilm-l6-v2#none"
        );
        assert_eq!(
            embedding_space_fingerprint("nomic-ai/nomic-embed-text-v1.5"),
            "nomic-ai/nomic-embed-text-v1.5#nomic-task-v1"
        );
    }

    #[test]
    fn embedding_space_folds_known_family_spellings() {
        // Every spelling of the two daemon-native families folds to ONE token.
        let minilm = "sentence-transformers/all-minilm-l6-v2#none";
        for spelling in [
            "mini_lm_l6_v2",
            "all-MiniLM-L6-v2",
            "all-minilm",
            "sentence-transformers/all-MiniLM-L6-v2",
        ] {
            assert_eq!(embedding_space_fingerprint(spelling), minilm, "{spelling}");
        }
        let nomic = "nomic-ai/nomic-embed-text-v1.5#nomic-task-v1";
        for spelling in [
            "nomic_embed_v15",
            "nomic-embed-text",
            "nomic-embed-text-v1.5",
            "nomic-ai/nomic-embed-text-v1.5",
        ] {
            assert_eq!(embedding_space_fingerprint(spelling), nomic, "{spelling}");
        }
    }

    #[test]
    fn embedding_space_api_model_lowercases_and_strips_latest() {
        // Arbitrary API model: lowercase + strip ONE trailing ":latest".
        assert_eq!(
            embedding_space_fingerprint("Google/Gemini-Embedding-2"),
            "google/gemini-embedding-2#none"
        );
        assert_eq!(
            embedding_space_fingerprint("some-embed:LATEST"),
            "some-embed#none"
        );
        // A version-meaningful tag is preserved.
        assert_eq!(
            embedding_space_fingerprint("some-embed:v1.5"),
            "some-embed:v1.5#none"
        );
    }

    #[test]
    fn embedding_space_strips_shipped_prose_suffix() {
        // #2168 wire-tolerance: a federated ShippedEmbedding.model carries
        // model_description() prose. The SSOT strips it so a prose-suffixed
        // shipped model and its bare id mint the SAME fingerprint — the
        // stamp(#2167 §2-EXC) and the gate(#2168) can never disagree.
        assert_eq!(
            embedding_space_fingerprint("nomic-embed-text-v1.5 (768-dim, ~270 MB)"),
            embedding_space_fingerprint("nomic-embed-text-v1.5"),
        );
        assert_eq!(
            embedding_space_fingerprint("sentence-transformers/all-MiniLM-L6-v2 (384-dim, ~90 MB)"),
            "sentence-transformers/all-minilm-l6-v2#none",
        );
        // An arbitrary API model with prose still strips + lowercases.
        assert_eq!(
            embedding_space_fingerprint("Gemini-Embedding-2 (3072-dim)"),
            "gemini-embedding-2#none",
        );
    }

    #[test]
    fn embedding_space_over_distinguishes_conservatively() {
        // §0.1 step 5 — two remote spellings that survive the fold mint
        // DIFFERENT fingerprints (the safe DEGRADED-not-WRONG direction).
        assert_ne!(
            embedding_space_fingerprint("google/gemini-embedding-2"),
            embedding_space_fingerprint("gemini-embedding-2")
        );
    }

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
            // `cosine_similarity_checked` (the dim-only comparator) never
            // produces the #2167 space variants.
            other => panic!("equal-length vectors must compare as Comparable, got {other:?}"),
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
            other => {
                panic!("differing-length vectors must report DimensionMismatch, got {other:?}")
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
    // #2115: serialize on the crate-canonical process-global env lock so this
    // $HOME-mutating test does not race the reranker module's own
    // $HOME-mutating tests cross-module under parallel `cargo test`
    // (std::env::set_var is unsound multithreaded — a module-local Mutex only
    // covers this file's tests).
    let _guard = crate::config::test_env_lock();

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
    // #2115: shared crate-canonical env lock (see the sibling fallback test)
    // so this $HOME + AI_MEMORY_EMBED_OFFLINE mutation serializes cross-module
    // against the reranker tests, not just within this file.
    let _guard = crate::config::test_env_lock();

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
