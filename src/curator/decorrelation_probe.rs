// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1764 (v0.8.0 slice) — reflection-corpus DECORRELATION VISIBILITY probe.
//!
//! DeepMind "From-AGI-to-ASI" audit recommendation #1 (issue #1698) flagged a
//! correlated-failure / monoculture-bias risk: a recursive memory substrate
//! that lets ONE model family's systematic bias get laundered into
//! "reflections" and then recursively reinforced becomes an epistemic-corruption
//! vector. #1764's PRIMARY countermeasure is a write-time N≥3
//! model-family-distinct quorum that REFUSES a bias-displaced reflection unless
//! N≥3 attestation-passing, model-family-DISTINCT reflections agree.
//!
//! ## Why this module is VISIBILITY-only (not enforcement)
//!
//! The 5-agent adversarial vote (memory `4d3ea1c5`; synthesis `4a5c041f`) found
//! unanimously that the full N≥3 REFUSAL cannot honestly ship at v0.8.0:
//!
//! * There is **no model-family provenance primitive** — a reflection's only
//!   producer signals (`agent_id`, `source`, `metadata`) are caller-CLAIMED
//!   free strings, and the attestation surface binds an Ed25519 signature to an
//!   AGENT IDENTITY, never to a model family (#1719 / #1171 are unbuilt).
//! * At present single-operator swarm scale there is typically ONE model family,
//!   so an N≥3-distinct REFUSE default would either brick every reflection write
//!   (self-DOS) or — worse — stamp a false "decorrelated" badge on a monoculture
//!   (the very laundering vector the audit fears: security theater).
//!
//! So the v0.8.0 slice ships the **honest** increment: make the EXISTING latent
//! producer-correlation in the Reflection corpus *visible* (what an auditor
//! actually wants from a pre-enforcement substrate), carrying a first-class
//! caveat that distinctness here is CLAIMED, not ATTESTED. The binding write-time
//! REFUSAL is a separate, tracked v0.9 issue gated on attested model-family
//! provenance (#1719) + the heterogeneous evaluator panel (#1171).
//!
//! Read-only and `sal`-gated (operates through the [`MemoryStore`] trait, SQLite
//! *or* Postgres). Opt-in via `AI_MEMORY_REFLECT_DECORRELATION_MODE` (default
//! `off`) at the CLI wiring layer (`src/cli/curator.rs`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Used by the `sal`-gated runner and the unit tests; in a plain non-`sal`
// library build the pure analyzer doesn't reference the mode enum.
#[cfg(any(feature = "sal", test))]
use crate::config::ReflectDecorrelationMode;
use crate::models::{Memory, field_names};

/// Canonical metadata key a caller MAY set to record the model family that
/// produced a reflection. CLAIMED, not attested (nothing cryptographically
/// binds it to the model that actually generated the text) — see
/// [`CLAIMED_NOT_ATTESTED_CAVEAT`]. The probe reads it from the top-level
/// `metadata` object first, then nested under
/// [`field_names::REFLECTION_METADATA`]. The first-class `ReflectInput` field +
/// MCP param that binds this to attestation is the v0.9 enforcement lane.
pub const REFLECTION_MODEL_FAMILY_KEY: &str = "model_family";

/// Compiled default producer-dominance threshold above which the probe emits an
/// advisory (see [`crate::config::reflect_decorrelation_dominance_threshold`]).
pub const DEFAULT_DOMINANCE_THRESHOLD: f64 = 0.8;

/// Minimum number of producer-bearing reflections in a namespace before a
/// dominance figure is meaningful — below this the probe stays silent (a
/// 2-reflection corpus is trivially "dominated"). Mirrors the reflection-pass
/// ≥3 cluster floor (#666).
pub const MIN_REFLECTIONS_FLOOR: usize = 3;

/// The mandated honesty caveat carried on every advisory. At v0.8.0 producer
/// "distinctness" is CLAIMED (a self-asserted `agent_id` / `model_family`
/// string), not ATTESTED, so a LOW dominance figure does NOT prove genuine
/// model-family diversity, and a HIGH one is the real auditable signal. Attested
/// distinctness is the v0.9 enforcement lane (#1719 / #1171).
pub const CLAIMED_NOT_ATTESTED_CAVEAT: &str = "family attestation unavailable — producer diversity is CLAIMED (self-asserted \
     agent_id/model_family), not ATTESTED; this is a visibility signal, not an \
     enforced decorrelation guarantee (v0.9 #1719/#1171)";

/// `tracing` target for advisory emissions — operators route this via their log
/// sink (file / stdout / syslog) as the visibility surface. Only the
/// `sal`-gated runner emits.
#[cfg(feature = "sal")]
const TRACE_TARGET: &str = "reflection.decorrelation.advisory";

/// Extract a non-empty string value for `key` from a JSON object value.
fn metadata_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Best-available CLAIMED producer signal for a reflection, in priority order:
/// `model_family` (top-level metadata) → `model_family` (nested under
/// `reflection_metadata`) → `agent_id` → `source`. `None` only when nothing
/// identifies the producer (such rows are excluded from the dominance figure).
///
/// Every tier is self-asserted; see [`CLAIMED_NOT_ATTESTED_CAVEAT`].
#[must_use]
pub fn producer_signal(m: &Memory) -> Option<String> {
    if let Some(f) = metadata_str(&m.metadata, REFLECTION_MODEL_FAMILY_KEY) {
        return Some(f);
    }
    if let Some(rm) = m.metadata.get(field_names::REFLECTION_METADATA) {
        if let Some(f) = metadata_str(rm, REFLECTION_MODEL_FAMILY_KEY) {
            return Some(f);
        }
    }
    if let Some(a) = metadata_str(&m.metadata, "agent_id") {
        return Some(a);
    }
    let s = m.source.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Producer-dominance summary for one namespace's Reflection corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DominanceReport {
    /// Reflections with a producer signal (the denominator).
    pub total: usize,
    /// Number of distinct CLAIMED producers.
    pub distinct_producers: usize,
    /// The single most-prolific producer (lexicographically smallest on a tie,
    /// for determinism), or `None` when `total == 0`.
    pub dominant_producer: Option<String>,
    /// Reflections attributed to [`Self::dominant_producer`].
    pub dominant_count: usize,
    /// `dominant_count / total` in `[0.0, 1.0]` (`0.0` when `total == 0`).
    pub dominance_ratio: f64,
}

/// Compute the producer-dominance summary over `reflections`. Pure + total —
/// unit-testable with no live store. Rows without a [`producer_signal`] are
/// excluded from the denominator.
#[must_use]
pub fn compute_producer_dominance(reflections: &[Memory]) -> DominanceReport {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for m in reflections {
        if let Some(p) = producer_signal(m) {
            *counts.entry(p).or_insert(0) += 1;
        }
    }
    let total: usize = counts.values().sum();
    // Rank by count DESC, then producer name ASC, so ties resolve
    // deterministically regardless of HashMap iteration order.
    let mut ranked: Vec<(&String, usize)> = counts.iter().map(|(p, c)| (p, *c)).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let (dominant_producer, dominant_count) = ranked
        .first()
        .map_or((None, 0), |(p, c)| (Some((*p).clone()), *c));
    #[allow(clippy::cast_precision_loss)]
    let dominance_ratio = if total == 0 {
        0.0
    } else {
        dominant_count as f64 / total as f64
    };
    DominanceReport {
        total,
        distinct_producers: counts.len(),
        dominant_producer,
        dominant_count,
        dominance_ratio,
    }
}

/// v0.9.0 §25.3 S2 (D3-021, #1767) — outcome of the write-time
/// attested-model-family quorum check. The distinct-family count is
/// computed over ATTESTED families ONLY: caller-CLAIMED (unattested)
/// rows contribute NOTHING to the count, so an unattested monoculture can
/// never be laundered into a "diverse" verdict (the anti-theater
/// property the D3-021 acceptance mandates).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum QuorumOutcome {
    /// The corpus + incoming write span `k >= quorum_n` DISTINCT ATTESTED
    /// model families — the quorum is met.
    MeetsQuorum {
        /// The distinct attested-family count (`>= quorum_n`).
        distinct_attested_families: usize,
    },
    /// At least [`MIN_REFLECTIONS_FLOOR`] ATTESTED rows exist but they span
    /// fewer than `quorum_n` distinct families — a real, evidence-backed
    /// monoculture. This is the ONLY outcome an `enforce` mode refuses on.
    AttestedMonoculture {
        /// Distinct attested families present (`< quorum_n`).
        distinct_attested_families: usize,
        /// Total attested rows considered.
        attested_rows: usize,
    },
    /// Fewer than [`MIN_REFLECTIONS_FLOOR`] ATTESTED rows — there is not
    /// enough attested evidence to assert EITHER diversity OR monoculture.
    /// A claimed-only corpus lands here (zero attested rows) and is NEVER
    /// refused (anti-theater; the evasion asymmetry is documented below).
    InsufficientAttested {
        /// Attested rows present (`< MIN_REFLECTIONS_FLOOR`).
        attested_rows: usize,
    },
}

/// v0.9.0 §25.3 S2 (D3-021, #1767) — PURE write-time quorum decision.
///
/// `corpus_attested_families` is the multiset of ATTESTED model families
/// already present in the target namespace's reflection corpus (one entry
/// per attested row; unattested rows are NOT included by the caller).
/// `incoming_attested_family` is the incoming write's family IF (and only
/// if) it is itself attested — a claimed/unknown incoming family is
/// `None` and contributes nothing.
///
/// The distinct-family count is over the DISTINCT attested families across
/// the corpus + the incoming attested family. `quorum_n` is clamped to a
/// floor of 2 (a "quorum of 1" is meaningless).
///
/// # Evasion asymmetry (honest limitation)
///
/// Because refusal fires ONLY on `attested_rows >= MIN_REFLECTIONS_FLOOR`
/// AND `distinct < quorum_n`, an adversary can AVOID refusal simply by
/// keeping the attested-row count below the floor with UNATTESTED writes.
/// This is the deliberate fail-safe direction — the check never refuses on
/// absent evidence — but it means the gate raises the cost of a
/// monoculture, it does not make one impossible. The default-live flip
/// (enforce-as-default) is the v1.0 lane.
#[must_use]
pub fn evaluate_write_quorum(
    corpus_attested_families: &[String],
    incoming_attested_family: Option<&str>,
    quorum_n: usize,
) -> QuorumOutcome {
    use std::collections::HashSet;

    let quorum_n = quorum_n.max(2);

    // Count attested ROWS (corpus rows + the incoming row iff attested).
    let attested_rows =
        corpus_attested_families.len() + usize::from(incoming_attested_family.is_some());

    // Distinct attested families across corpus + incoming.
    let mut families: HashSet<&str> = corpus_attested_families
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(f) = incoming_attested_family {
        families.insert(f);
    }
    let distinct = families.len();

    if attested_rows < MIN_REFLECTIONS_FLOOR {
        return QuorumOutcome::InsufficientAttested { attested_rows };
    }
    if distinct >= quorum_n {
        QuorumOutcome::MeetsQuorum {
            distinct_attested_families: distinct,
        }
    } else {
        QuorumOutcome::AttestedMonoculture {
            distinct_attested_families: distinct,
            attested_rows,
        }
    }
}

/// One namespace's advisory finding — emitted only when the corpus is BOTH big
/// enough ([`MIN_REFLECTIONS_FLOOR`]) AND dominated past the threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecorrelationAdvisory {
    /// Namespace the finding is for.
    pub namespace: String,
    /// The dominance summary that triggered it.
    pub report: DominanceReport,
    /// The threshold the dominance crossed.
    pub threshold: f64,
    /// The mandated CLAIMED-not-attested caveat ([`CLAIMED_NOT_ATTESTED_CAVEAT`]).
    pub caveat: String,
    /// `true` when this namespace's probe scan hit [`PROBE_SCAN_LIMIT`] rows —
    /// the dominance figure then covers only the newest-priority window, NOT the
    /// full corpus (honest truncation, keyed on the pre-Reflection-filter row
    /// count). Additive + backward-compatible via `#[serde(default)]`
    /// (serde-default-compat); [`evaluate_namespace`] leaves it `false` and the
    /// `sal`-gated runner sets it from the raw window length.
    #[serde(default)]
    pub scan_capped: bool,
}

/// Evaluate one namespace's reflections. Returns `Some` advisory iff at least
/// [`floor`] producer-bearing reflections exist AND the dominance ratio is at or
/// above `threshold`. Pure + total.
#[must_use]
pub fn evaluate_namespace(
    reflections: &[Memory],
    namespace: &str,
    threshold: f64,
    floor: usize,
) -> Option<DecorrelationAdvisory> {
    let report = compute_producer_dominance(reflections);
    if report.total < floor {
        return None;
    }
    // `>=` with a tiny tolerance so an exact-threshold corpus triggers.
    if report.dominance_ratio + f64::EPSILON < threshold {
        return None;
    }
    Some(DecorrelationAdvisory {
        namespace: namespace.to_string(),
        report,
        threshold,
        caveat: CLAIMED_NOT_ATTESTED_CAVEAT.to_string(),
        // Pure evaluator can't see the scan window; the `sal`-gated runner
        // overrides this from the raw `list` length.
        scan_capped: false,
    })
}

/// Aggregated probe outcome, serialised for the curator log / `--json` surface.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DecorrelationProbeReport {
    /// Resolved mode (`off` / `advisory` / `enforce`) as requested. `enforce`
    /// is reported verbatim even though it ran inert-as-advisory at v0.8.0.
    pub mode: String,
    /// `true` when an `enforce` request was degraded to advisory (v0.8.0 inert).
    pub enforce_degraded_to_advisory: bool,
    /// The dominance threshold used.
    pub threshold: f64,
    /// Namespaces scanned.
    pub namespaces_scanned: usize,
    /// Producer-bearing reflections scanned across all namespaces.
    pub reflections_scanned: usize,
    /// Per-namespace advisories (corpus dominated past threshold).
    pub advisories: Vec<DecorrelationAdvisory>,
    /// Number of namespaces whose probe scan hit [`PROBE_SCAN_LIMIT`] rows
    /// (dominated or not) — the honest, backend-identical truncation surface.
    /// Additive + backward-compatible via `#[serde(default)]`.
    #[serde(default)]
    pub namespaces_capped: usize,
}

#[cfg(feature = "sal")]
use crate::store::{CallerContext, Filter, MemoryStore};

/// Upper bound on rows pulled per namespace per probe pass. Bound BY REFERENCE
/// to [`crate::storage::LIST_MAX_LIMIT`] (never a bare literal) so BOTH SAL
/// backends scan the identical newest-priority window:
/// [`crate::store::sqlite::SqliteStore`]'s `list` passes the filter limit
/// through UNCLAMPED, while `PostgresStore::list` clamps to `LIST_MAX_LIMIT`.
/// Any probe limit above that clamp made the two backends read *different*
/// windows and emit *different* advisories from identical data — the
/// RQ-PARITY-01 defect (#1872). Window identity holds modulo `updated_at`
/// ties at the cutoff: both backends `ORDER BY priority DESC, updated_at DESC`
/// (`storage/mod.rs`, `store/postgres.rs`) with no third sort key. The
/// [`DecorrelationAdvisory::scan_capped`] / [`DecorrelationProbeReport::namespaces_capped`]
/// markers key on the PRE-Reflection-filter row count (the raw `list` length),
/// surfacing honest truncation instead of silent sampling. Paging past the cap
/// needs a `Filter` offset (out of scope — #1625 lineage).
#[cfg(feature = "sal")]
const PROBE_SCAN_LIMIT: usize = crate::storage::LIST_MAX_LIMIT;

/// Run the reflection-corpus decorrelation VISIBILITY probe over `namespace`
/// (when `Some`) or every non-`_` namespace. Read-only: lists Reflection-kind
/// memories through the SAL trait, computes per-namespace producer dominance,
/// and emits a structured WARN ([`TRACE_TARGET`]) + a per-namespace advisory for
/// each corpus dominated past `threshold`.
///
/// `mode` MUST be active ([`ReflectDecorrelationMode::is_active`]); `Off` returns
/// an empty report. `Enforce` is INERT at v0.8.0 and runs as advisory (with a
/// one-shot WARN) because binding REFUSAL needs attested provenance (v0.9
/// #1719 / #1171). `agent_id` is the curator's identity (operator-class read so
/// the sweep sees every row regardless of `metadata.scope`, mirroring the
/// reflection / transcript-classify passes).
///
/// # Errors
///
/// Propagates a fatal store error (`list_namespaces`); per-namespace `list`
/// failures are collected into the report's advisories path as skipped, not
/// fatal — a single bad namespace never aborts the sweep.
#[cfg(feature = "sal")]
pub async fn run_decorrelation_probe(
    store: &dyn MemoryStore,
    agent_id: &str,
    namespace: Option<&str>,
    mode: ReflectDecorrelationMode,
    threshold: f64,
    floor: usize,
) -> anyhow::Result<DecorrelationProbeReport> {
    use crate::models::MemoryKind;

    let mut report = DecorrelationProbeReport {
        mode: mode.as_str().to_string(),
        threshold,
        ..Default::default()
    };
    if !mode.is_active() {
        return Ok(report);
    }
    if mode == ReflectDecorrelationMode::Enforce {
        report.enforce_degraded_to_advisory = true;
        tracing::warn!(
            target: TRACE_TARGET,
            "AI_MEMORY_REFLECT_DECORRELATION_MODE=enforce is INERT at v0.8.0 — running \
             ADVISORY. Write-time N≥3 model-family-distinct REFUSAL is gated on attested \
             model-family provenance (v0.9 #1719/#1171); CLAIMED distinctness cannot bind \
             a refusal without becoming security theater (5-agent vote 4d3ea1c5)."
        );
    }

    // Operator-class context so the background sweep reads every row regardless
    // of `metadata.scope` (mirrors `TranscriptClassifyPass` / the reflection
    // pass). C8 allowlisted in scripts/qc-codegraph-allowlists/for-admin-bypass.txt.
    let ctx = CallerContext::for_admin(agent_id);

    let namespaces: Vec<String> = match namespace {
        Some(ns) => vec![ns.to_string()],
        None => store
            .list_namespaces()
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .into_iter()
            .map(|nc| nc.namespace)
            .filter(|ns| !ns.starts_with('_'))
            .collect(),
    };
    report.namespaces_scanned = namespaces.len();

    for ns in &namespaces {
        let filter = Filter {
            namespace: Some(ns.clone()),
            limit: PROBE_SCAN_LIMIT,
            ..Default::default()
        };
        let memories = match store.list(&ctx, &filter).await {
            Ok(v) => v,
            // A single namespace's read failure must not abort the whole sweep.
            Err(_) => continue,
        };
        // Honest truncation marker, keyed on the PRE-Reflection-filter row count
        // (the raw window the store returned). Both backends now scan the
        // identical `PROBE_SCAN_LIMIT` window (see the const doc-comment), so
        // this fires — and the dominance denominators it qualifies match —
        // on SQLite and Postgres alike.
        let scan_capped = memories.len() == PROBE_SCAN_LIMIT;
        if scan_capped {
            report.namespaces_capped += 1;
        }
        let reflections: Vec<Memory> = memories
            .into_iter()
            .filter(|m| m.memory_kind == MemoryKind::Reflection)
            .collect();
        if let Some(mut advisory) = evaluate_namespace(&reflections, ns, threshold, floor) {
            advisory.scan_capped = scan_capped;
            report.reflections_scanned += advisory.report.total;
            tracing::warn!(
                target: TRACE_TARGET,
                namespace = %advisory.namespace,
                total = advisory.report.total,
                distinct_producers = advisory.report.distinct_producers,
                dominant_producer = advisory.report.dominant_producer.as_deref().unwrap_or("?"),
                dominance_ratio = advisory.report.dominance_ratio,
                threshold = advisory.threshold,
                scan_capped = advisory.scan_capped,
                "reflection corpus is producer-dominated past threshold — {}",
                advisory.caveat,
            );
            report.advisories.push(advisory);
        } else {
            // Still count producer-bearing reflections we scanned, for the report.
            report.reflections_scanned += compute_producer_dominance(&reflections).total;
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};

    fn fams(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    // ── v0.9.0 §25.3 S2 (D3-021) evaluate_write_quorum pure core ──────

    #[test]
    fn quorum_met_with_three_distinct_attested_families() {
        let corpus = fams(&["llama", "claude"]);
        let out = evaluate_write_quorum(&corpus, Some("gemma"), 3);
        assert_eq!(
            out,
            QuorumOutcome::MeetsQuorum {
                distinct_attested_families: 3
            }
        );
    }

    #[test]
    fn attested_monoculture_refuses_only_on_attested_evidence() {
        // 3 attested rows, all ONE family → evidence-backed monoculture.
        let corpus = fams(&["llama", "llama"]);
        let out = evaluate_write_quorum(&corpus, Some("llama"), 3);
        assert_eq!(
            out,
            QuorumOutcome::AttestedMonoculture {
                distinct_attested_families: 1,
                attested_rows: 3
            }
        );
    }

    #[test]
    fn claimed_only_corpus_is_insufficient_never_refused() {
        // Zero attested rows (all claimed → excluded by the caller): the
        // incoming is also unattested. Must be InsufficientAttested, NOT
        // a monoculture refusal — unattested rows are never laundered
        // NOR weaponized into a refusal (anti-theater).
        let out = evaluate_write_quorum(&[], None, 3);
        assert_eq!(
            out,
            QuorumOutcome::InsufficientAttested { attested_rows: 0 }
        );
    }

    #[test]
    fn below_floor_attested_is_insufficient() {
        // 2 attested rows (< MIN_REFLECTIONS_FLOOR=3) even though distinct.
        let corpus = fams(&["llama"]);
        let out = evaluate_write_quorum(&corpus, Some("claude"), 3);
        assert_eq!(
            out,
            QuorumOutcome::InsufficientAttested { attested_rows: 2 }
        );
    }

    #[test]
    fn unattested_incoming_contributes_nothing() {
        // Corpus has 3 distinct attested families → meets quorum
        // regardless of the (unattested) incoming.
        let corpus = fams(&["llama", "claude", "gemma"]);
        assert_eq!(
            evaluate_write_quorum(&corpus, None, 3),
            QuorumOutcome::MeetsQuorum {
                distinct_attested_families: 3
            }
        );
        // But with only 2 attested families + an UNATTESTED incoming,
        // the incoming cannot manufacture the third distinct family.
        let corpus2 = fams(&["llama", "claude", "llama"]);
        assert_eq!(
            evaluate_write_quorum(&corpus2, None, 3),
            QuorumOutcome::AttestedMonoculture {
                distinct_attested_families: 2,
                attested_rows: 3
            }
        );
    }

    #[test]
    fn quorum_n_clamped_to_floor_of_two() {
        // A nonsensical quorum_n=1 clamps to 2; 2 distinct attested = met.
        let corpus = fams(&["llama", "claude", "gemma"]);
        assert!(matches!(
            evaluate_write_quorum(&corpus, None, 1),
            QuorumOutcome::MeetsQuorum { .. }
        ));
    }

    /// Minimal Reflection-kind memory with the given metadata, for dominance math.
    fn refl(id: &str, metadata: serde_json::Value, source: &str) -> Memory {
        Memory {
            cid: None,
            id: id.to_string(),
            tier: Tier::Long,
            namespace: "team/eng".to_string(),
            title: format!("reflection {id}"),
            content: "c".to_string(),
            tags: Vec::new(),
            priority: 5,
            confidence: 0.9,
            source: source.to_string(),
            access_count: 0,
            created_at: "2026-06-22T00:00:00Z".to_string(),
            updated_at: "2026-06-22T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 1,
            memory_kind: MemoryKind::Reflection,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    fn by_agent(id: &str, agent: &str) -> Memory {
        refl(id, serde_json::json!({ "agent_id": agent }), "nhi")
    }

    #[test]
    fn producer_signal_priority_model_family_top_level_wins() {
        let m = refl(
            "a",
            serde_json::json!({ "model_family": "claude", "agent_id": "ai:x" }),
            "nhi",
        );
        assert_eq!(producer_signal(&m).as_deref(), Some("claude"));
    }

    #[test]
    fn producer_signal_nested_reflection_metadata_model_family() {
        let m = refl(
            "a",
            serde_json::json!({
                "agent_id": "ai:x",
                "reflection_metadata": { "model_family": "gemini" }
            }),
            "nhi",
        );
        assert_eq!(producer_signal(&m).as_deref(), Some("gemini"));
    }

    #[test]
    fn producer_signal_falls_back_to_agent_id_then_source() {
        let by_id = refl("a", serde_json::json!({ "agent_id": "ai:curator" }), "nhi");
        assert_eq!(producer_signal(&by_id).as_deref(), Some("ai:curator"));
        let by_src = refl("b", serde_json::json!({}), "nhi");
        assert_eq!(producer_signal(&by_src).as_deref(), Some("nhi"));
        let none = refl("c", serde_json::json!({}), "   ");
        assert_eq!(producer_signal(&none), None);
    }

    #[test]
    fn dominance_full_monoculture_is_one() {
        let reflections: Vec<Memory> = (0..5)
            .map(|i| by_agent(&format!("m{i}"), "ai:solo"))
            .collect();
        let r = compute_producer_dominance(&reflections);
        assert_eq!(r.total, 5);
        assert_eq!(r.distinct_producers, 1);
        assert_eq!(r.dominant_producer.as_deref(), Some("ai:solo"));
        assert_eq!(r.dominant_count, 5);
        assert!((r.dominance_ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn dominance_even_split_and_deterministic_tiebreak() {
        // 2x "alpha", 2x "beta" → ratio 0.5, tie resolves to lexicographically
        // smallest ("alpha") regardless of HashMap order.
        let reflections = vec![
            by_agent("1", "beta"),
            by_agent("2", "alpha"),
            by_agent("3", "beta"),
            by_agent("4", "alpha"),
        ];
        let r = compute_producer_dominance(&reflections);
        assert_eq!(r.total, 4);
        assert_eq!(r.distinct_producers, 2);
        assert_eq!(r.dominant_producer.as_deref(), Some("alpha"));
        assert!((r.dominance_ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn dominance_empty_is_zero() {
        let r = compute_producer_dominance(&[]);
        assert_eq!(r.total, 0);
        assert_eq!(r.distinct_producers, 0);
        assert_eq!(r.dominant_producer, None);
        assert!((r.dominance_ratio - 0.0).abs() < 1e-9);
    }

    #[test]
    fn evaluate_below_floor_is_silent() {
        // 2 reflections, fully dominated, but under MIN_REFLECTIONS_FLOOR=3.
        let reflections = vec![by_agent("1", "solo"), by_agent("2", "solo")];
        assert!(evaluate_namespace(&reflections, "team/eng", 0.8, MIN_REFLECTIONS_FLOOR).is_none());
    }

    #[test]
    fn evaluate_dominated_corpus_emits_advisory_with_caveat() {
        // 4x solo + 1x other → ratio 0.8, at threshold 0.8 → advisory.
        let mut reflections: Vec<Memory> =
            (0..4).map(|i| by_agent(&format!("s{i}"), "solo")).collect();
        reflections.push(by_agent("o", "other"));
        let adv = evaluate_namespace(&reflections, "team/eng", 0.8, MIN_REFLECTIONS_FLOOR)
            .expect("dominated corpus must emit advisory");
        assert_eq!(adv.namespace, "team/eng");
        assert_eq!(adv.report.dominant_producer.as_deref(), Some("solo"));
        assert!((adv.report.dominance_ratio - 0.8).abs() < 1e-9);
        assert_eq!(adv.caveat, CLAIMED_NOT_ATTESTED_CAVEAT);
        assert!(adv.caveat.contains("CLAIMED"));
        assert!(adv.caveat.contains("not ATTESTED") || adv.caveat.contains("not\n"));
    }

    #[test]
    fn evaluate_diverse_corpus_below_threshold_is_silent() {
        // 5 distinct producers → ratio 0.2, well below 0.8.
        let reflections: Vec<Memory> = (0..5)
            .map(|i| by_agent(&format!("m{i}"), &format!("fam{i}")))
            .collect();
        assert!(evaluate_namespace(&reflections, "team/eng", 0.8, MIN_REFLECTIONS_FLOOR).is_none());
    }

    #[test]
    fn mode_parse_and_active() {
        assert_eq!(
            ReflectDecorrelationMode::from_str_opt("ADVISORY"),
            Some(ReflectDecorrelationMode::Advisory)
        );
        assert_eq!(ReflectDecorrelationMode::from_str_opt("bogus"), None);
        assert!(!ReflectDecorrelationMode::Off.is_active());
        assert!(ReflectDecorrelationMode::Advisory.is_active());
        assert!(ReflectDecorrelationMode::Enforce.is_active());
    }
}
