// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 WT-1-D / v1.0.0 #2983-#2987 — auto-atomisation `pre_store`
//! substrate hook.
//!
//! When the namespace policy
//! [`crate::models::GovernancePolicy::auto_atomise`] resolves to a
//! non-`Off` [`crate::models::AutoAtomiseMode`] for the stored
//! memory's namespace, this hook either runs the curator pass inline
//! (`Synchronous`, MCP stdio only) or hands a job to the bounded
//! background atomise worker (`Deferred`).
//!
//! # What #2983-#2987 changed (and why)
//!
//! Until v1.0.0 this module carried a process-wide `OnceLock` dispatch
//! slot (`AUTO_ATOMISE_DISPATCH`) whose doc comment claimed the daemon
//! `serve` bootstrap installed it. **No such call ever existed** — the
//! slot had zero production callers, so every production surface
//! short-circuited with `skipped_dispatch_unset` and Batman Form-2
//! atomisation was structurally inert product-wide (#2983). The
//! remediation vote (2026-08-16, protocol `4d3ea1c5`) ruled the global
//! ABOLISHED rather than installed: it carried no information its call
//! sites did not already hold, and a boot-pinned `Arc<Atomiser>` would
//! re-commit the #2172 defect inside the SIGNED-provenance lane (a
//! revoked vendor kept being egressed to after an `[llm]` reload, while
//! the signed `atomisation_complete` payload named a `curator_model`
//! that never ran).
//!
//! The live wiring is now threaded explicitly as [`AtomiseWiring`]:
//!
//! * **MCP stdio** forwards `ToolDispatchCtx::atomise_handler` (already
//!   rebuilt on every `[llm]` hot-reload, #2172) into
//!   `dispatch_memory_store` → `handle_store`.
//! * **HTTP** owns no handler at all: the worker rebuilds the atomiser
//!   PER JOB from the live `SwappableLlm` snapshot, so staleness is
//!   structurally impossible.
//!
//! # Hard guarantees
//!
//! 1. **Non-blocking on the deferred path.** The `Deferred` arm returns
//!    after at most a token-count + policy resolution plus a
//!    non-blocking `try_send` onto a BOUNDED queue with a SINGLE
//!    consumer (#2986 — the pre-v1.0.0 form spawned one unbounded
//!    detached OS thread per over-threshold store, each opening its own
//!    connection and driving a 3-retry ~3.1 s LLM ladder).
//!
//! 2. **Notify-class.** Failures inside the worker (curator LLM
//!    unavailable, race against a concurrent atomisation, …) are logged
//!    and NEVER propagate back to the caller. The memory is already
//!    committed; a transient curator error must not surface as a write
//!    failure. `memory_atomise` (or a later store) can recover the work.
//!
//! 3. **Honest telemetry (#2987).** Every branch reports the mode that
//!    ACTUALLY RAN plus, when it differs, the CONFIGURED mode and a
//!    reason token. The outcome token never contradicts the mode label.
//!
//! 4. **Capability isolation.** Gated by the namespace policy. An
//!    operator who has not opted into `auto_atomise` on the namespace
//!    standard's `metadata.governance` sees no curator round-trips from
//!    this module, ever.
//!
//! # Wiring (the real call-site set, #2984)
//!
//! * `crate::mcp::tools::store::handle_store` — MCP stdio, sqlite only.
//! * `crate::handlers::http::try_enqueue_auto_atomise` — the HTTP
//!   `POST /api/v1/memories` create funnel, DEFERRED only, sqlite only
//!   (a postgres-backed daemon reports `skipped_backend_unsupported`;
//!   the atomiser is `rusqlite::Connection`-bound and landing atoms in a
//!   different store than their source would be mixed-state corruption).
//! * The CLI `ai-memory store` one-shot deliberately does NOT call this
//!   hook — the operator-direct substrate path stays quiet, matching the
//!   L1-6 governance-hook and quota exemptions.
//!
//! At v1.0.0, Form-2 "atoms before the response returns" is therefore an
//! **MCP-stdio + sqlite** property. Every other surface is deferred.

use std::path::Path;
use std::sync::Arc;

use crate::atomisation::{AtomiseError, Atomiser};
use crate::background::atomise_worker::{AtomiseJob, AtomiseQueue};
use crate::models::{AutoAtomiseMode, Memory};
use crate::storage as db;

/// Tracing target for the async auto-atomise hook (#1558 tracing-target SSOT).
pub(crate) const AUTO_ATOMISE_TRACE_TARGET: &str = "pre_store.auto_atomise";

/// Tracing target for the synchronous (inline) auto-atomise path
/// (#1558 tracing-target SSOT).
const AUTO_ATOMISE_SYNC_TRACE_TARGET: &str = "pre_store.auto_atomise.sync";

// ---------------------------------------------------------------------------
// #2987 — the honest-telemetry vocabulary. Named consts (never inline
// literals) so the hardcoded-literal ratchet stays clean and every
// surface — MCP envelope, HTTP envelope, doctor, tests — spells the same
// token.
// ---------------------------------------------------------------------------

/// Curator ran inline and the source was split into atoms.
pub const OUTCOME_ATOMISED: &str = "atomised";
/// Job accepted by the bounded background worker; atoms land later.
pub const OUTCOME_QUEUED: &str = "queued";
/// Bounded queue was full (or no worker wired) — DEGRADE, never a write failure.
pub const OUTCOME_SKIPPED_QUEUE_FULL: &str = "skipped_queue_full";
/// #2985 — the namespace standard requests `auto_atomise` but this daemon
/// has NO curator (no LLM wired / egress refused). Distinct from every
/// wiring-state skip so an operator can tell "misconfigured" from "absent".
pub const OUTCOME_SKIPPED_NO_CURATOR: &str = "skipped_no_curator";
/// Token count fell at or under the configured threshold.
pub const OUTCOME_SKIPPED_UNDER_THRESHOLD: &str = "skipped_under_threshold";
/// Policy resolved to `Off` for this namespace.
pub const OUTCOME_SKIPPED_POLICY_DISABLED: &str = "skipped_policy_disabled";
/// Curator returned no productive split.
pub const OUTCOME_SKIPPED_SOURCE_TOO_SMALL: &str = "skipped_source_too_small";
/// The source was already atomised (`AlreadyAtomised`).
pub const OUTCOME_SKIPPED_ALREADY_ATOMISED: &str = "skipped_already_atomised";
/// Curator error (logged, swallowed — notify-class).
pub const OUTCOME_FAILED: &str = "failed";
/// The write landed on a postgres-backed store; the atomiser is
/// `rusqlite::Connection`-bound so no job is enqueued. NEVER a
/// fall-through to a sqlite handle (atoms in a different store than
/// their source = mixed-state corruption).
pub const OUTCOME_SKIPPED_BACKEND_UNSUPPORTED: &str = "skipped_backend_unsupported";

/// Reason token: the configured mode could not run because no curator
/// is wired on this daemon.
pub const REASON_NO_CURATOR: &str = "no_curator";
/// Reason token: the bounded queue refused the job.
pub const REASON_QUEUE_FULL: &str = "queue_full";
/// Reason token: a `synchronous`-configured namespace written through the
/// HTTP funnel runs DEFERRED (holding the daemon's single sqlite handle
/// and an #2032-M3 admission permit across an LLM round trip is the
/// availability class #2587 moved auto_tag off the request path for).
pub const REASON_DEFERRED_ON_HTTP: &str = "deferred_on_http";
/// Reason token: the storage backend cannot host the atomiser.
pub const REASON_BACKEND_UNSUPPORTED: &str = "backend_unsupported";

/// Response-envelope key carrying the mode that ACTUALLY ran.
pub const FIELD_ATOMISE_MODE: &str = "atomise_mode";
/// Response-envelope key carrying the CONFIGURED mode, emitted only when
/// it differs from the mode that ran.
pub const FIELD_ATOMISE_MODE_CONFIGURED: &str = "atomise_mode_configured";
/// Response-envelope key carrying the reason `ran != configured`.
pub const FIELD_ATOMISE_MODE_REASON: &str = "atomise_mode_reason";
/// Response-envelope key carrying the terminal outcome token.
pub const FIELD_ATOMISE_OUTCOME: &str = "atomise_outcome";

/// #2987 — the honest disposition of one store's atomisation decision.
///
/// `mode_ran` is the mode that ACTUALLY executed (never a label the
/// outcome contradicts); `mode_configured` is what the namespace policy
/// asked for. When they differ, `reason` names why. This is the whole
/// contract the pre-v1.0.0 envelope violated by hardcoding
/// `atomise_mode: "synchronous"` next to `skipped_dispatch_unset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomiseDisposition {
    pub mode_ran: AutoAtomiseMode,
    pub mode_configured: AutoAtomiseMode,
    pub reason: Option<&'static str>,
    pub outcome: &'static str,
}

impl AtomiseDisposition {
    /// The mode ran exactly as configured.
    #[must_use]
    pub fn ran(mode: AutoAtomiseMode, outcome: &'static str) -> Self {
        Self {
            mode_ran: mode,
            mode_configured: mode,
            reason: None,
            outcome,
        }
    }

    /// The configured mode could not run; `mode_ran` records what did.
    #[must_use]
    pub fn diverged(
        mode_ran: AutoAtomiseMode,
        mode_configured: AutoAtomiseMode,
        reason: &'static str,
        outcome: &'static str,
    ) -> Self {
        Self {
            mode_ran,
            mode_configured,
            reason: Some(reason),
            outcome,
        }
    }

    /// Merge the disposition into a wire response object. Emits
    /// `atomise_mode` + `atomise_outcome` on EVERY branch (including
    /// `off`), and the configured-mode + reason pair only on divergence.
    pub fn merge_into_response(&self, response: &mut serde_json::Value) {
        response[FIELD_ATOMISE_MODE] = serde_json::json!(self.mode_ran.as_str());
        response[FIELD_ATOMISE_OUTCOME] = serde_json::json!(self.outcome);
        if let Some(reason) = self.reason {
            response[FIELD_ATOMISE_MODE_CONFIGURED] =
                serde_json::json!(self.mode_configured.as_str());
            response[FIELD_ATOMISE_MODE_REASON] = serde_json::json!(reason);
        }
    }
}

/// The LIVE atomisation wiring, threaded explicitly from the surface
/// that owns it. Replaces the abolished `AUTO_ATOMISE_DISPATCH`
/// process-global (#2983).
///
/// Both fields are `Option` because both absences are legitimate,
/// distinguishable production states:
///
/// * `atomiser: None` — no curator on this daemon (`LlmCurator` is the
///   only production `Curator` impl, so a keyword-tier or
///   egress-refused deployment has none). Reported as
///   [`OUTCOME_SKIPPED_NO_CURATOR`], never conflated with missing wiring.
/// * `queue: None` — no background worker on this surface (a CLI
///   one-shot, or a test scaffold). Reported as
///   [`OUTCOME_SKIPPED_QUEUE_FULL`] with a counted WARN.
#[derive(Clone, Copy, Default)]
pub struct AtomiseWiring<'a> {
    pub atomiser: Option<&'a Arc<Atomiser>>,
    pub queue: Option<&'a AtomiseQueue>,
}

impl std::fmt::Debug for AtomiseWiring<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomiseWiring")
            .field("atomiser", &self.atomiser.map(|_| "<Arc<Atomiser>>"))
            .field("queue", &self.queue.map(|_| "<AtomiseQueue>"))
            .finish()
    }
}

impl<'a> AtomiseWiring<'a> {
    /// Construct from the MCP dispatch context's live atomise handler.
    #[must_use]
    pub fn new(atomiser: Option<&'a Arc<Atomiser>>, queue: Option<&'a AtomiseQueue>) -> Self {
        Self { atomiser, queue }
    }

    /// `true` when a curator is available on this daemon — the #2985
    /// predicate. Consulted by the MCP store path BEFORE it decides
    /// whether to skip the parent's source embedding.
    #[must_use]
    pub fn has_curator(&self) -> bool {
        self.atomiser.is_some()
    }
}

/// The substrate-side auto-atomisation funnel. Called by every
/// production write path that supports atomisation, AFTER the row
/// commits, with the CONFIGURED mode already resolved by the caller
/// (the caller needs it earlier, to decide the source-embed skip).
///
/// Returns the honest [`AtomiseDisposition`] — never an error. The
/// memory is already durable at this point; atomisation is a derived,
/// regenerable concern and must never surface as a write failure.
///
/// # Logic
///
/// 1. `Off` → [`OUTCOME_SKIPPED_POLICY_DISABLED`] (mode label `off`).
/// 2. No curator → [`OUTCOME_SKIPPED_NO_CURATOR`], mode label `off`,
///    configured-mode + [`REASON_NO_CURATOR`] carried (#2985).
/// 3. Token-count `memory.content` via `cl100k_base`; `<= threshold`
///    → [`OUTCOME_SKIPPED_UNDER_THRESHOLD`] under the configured label.
/// 4. `Synchronous` → run the curator inline (retry-capped 1 by
///    default; the operator's own call, per the Q2 vote).
/// 5. `Deferred` → non-blocking `try_send` onto the bounded worker
///    queue; full/absent → [`OUTCOME_SKIPPED_QUEUE_FULL`].
#[must_use]
pub fn run_auto_atomise(
    conn: &rusqlite::Connection,
    db_path: &Path,
    memory: &Memory,
    actual_id: &str,
    calling_agent_id: &str,
    configured: AutoAtomiseMode,
    // #1579 A1 — the namespace policy the CALLER already resolved. It
    // cannot change mid-call (one synchronous connection), and walking
    // the namespace chain a second time here would quietly undo the
    // resolve-once optimisation that commit landed.
    policy: &crate::models::GovernancePolicy,
    wiring: AtomiseWiring<'_>,
) -> AtomiseDisposition {
    if configured == AutoAtomiseMode::Off {
        return AtomiseDisposition::ran(AutoAtomiseMode::Off, OUTCOME_SKIPPED_POLICY_DISABLED);
    }

    let Some(atomiser) = wiring.atomiser else {
        // #2985 — the namespace standard asks for atomisation on a
        // curator-less daemon. Loud, distinct, and NEVER a silent green:
        // there is deliberately no deterministic splitter fallback
        // (`atomise_sync` ARCHIVES the parent, so a heuristic substitute
        // is the unintentional-data-loss class — unanimously voted out).
        tracing::warn!(
            target: AUTO_ATOMISE_TRACE_TARGET,
            "namespace '{}' requests auto_atomise ({}) but this daemon has NO curator \
             (no LLM wired, or inference egress refused) — memory {} stored WITHOUT \
             atomisation. Wire an [llm] backend (a loopback Ollama satisfies the \
             certified loopback-only egress posture) or clear auto_atomise on the \
             namespace standard. See `ai-memory doctor`.",
            memory.namespace,
            configured.as_str(),
            actual_id,
        );
        crate::metrics::inc_atomise_no_curator();
        return AtomiseDisposition::diverged(
            AutoAtomiseMode::Off,
            configured,
            REASON_NO_CURATOR,
            OUTCOME_SKIPPED_NO_CURATOR,
        );
    };

    let threshold = policy.effective_auto_atomise_threshold_cl100k();
    let tokens = db::count_tokens_cl100k(&memory.content);
    if tokens <= threshold as usize {
        return AtomiseDisposition::ran(configured, OUTCOME_SKIPPED_UNDER_THRESHOLD);
    }
    let max_atom_tokens = policy.effective_auto_atomise_max_atom_tokens();

    match configured {
        AutoAtomiseMode::Off => unreachable!("Off short-circuits above"),
        AutoAtomiseMode::Synchronous => {
            // Cluster-F PERF-5 — the synchronous path is the operator's
            // OWN call on their own surface (MCP stdio), so it keeps the
            // retry budget capped at `sync_curator_max_retries` (1) to
            // bound the worst-case latency added inside `memory_store`.
            let max_retries = policy
                .effective_auto_atomise_max_retries()
                .unwrap_or_else(|| atomiser.sync_curator_max_retries());
            let outcome = run_synchronous_auto_atomise(
                conn,
                atomiser,
                actual_id,
                max_atom_tokens,
                calling_agent_id,
                max_retries,
            );
            AtomiseDisposition::ran(AutoAtomiseMode::Synchronous, outcome)
        }
        AutoAtomiseMode::Deferred => {
            let Some(queue) = wiring.queue else {
                tracing::warn!(
                    target: AUTO_ATOMISE_TRACE_TARGET,
                    "deferred auto_atomise for memory {actual_id} has NO worker queue wired \
                     — skipping (the durable write already succeeded)"
                );
                crate::metrics::inc_atomise_dropped();
                return AtomiseDisposition::diverged(
                    AutoAtomiseMode::Off,
                    AutoAtomiseMode::Deferred,
                    REASON_QUEUE_FULL,
                    OUTCOME_SKIPPED_QUEUE_FULL,
                );
            };
            let job = AtomiseJob {
                db_path: db_path.to_path_buf(),
                memory_id: actual_id.to_string(),
                namespace: memory.namespace.clone(),
                agent_id: calling_agent_id.to_string(),
                max_atom_tokens,
            };
            if queue.try_enqueue(job) {
                AtomiseDisposition::ran(AutoAtomiseMode::Deferred, OUTCOME_QUEUED)
            } else {
                AtomiseDisposition::diverged(
                    AutoAtomiseMode::Off,
                    AutoAtomiseMode::Deferred,
                    REASON_QUEUE_FULL,
                    OUTCOME_SKIPPED_QUEUE_FULL,
                )
            }
        }
    }
}

/// v0.7.x Form 2 (#755) — Synchronous-mode curator pass.
///
/// Runs INSIDE the caller's MCP handler so atoms surface in recall
/// BEFORE the `memory_store` response returns. The caller is
/// responsible for SKIPPING the source-embed step before invoking this
/// function, so the substrate honours Batman's Form 2 "decompose THEN
/// embed" criterion.
///
/// Errors are logged + swallowed per the notify-class contract — a
/// curator outage must not block the write that has already committed.
#[must_use]
pub fn run_synchronous_auto_atomise(
    conn: &rusqlite::Connection,
    atomiser: &Atomiser,
    actual_id: &str,
    max_atom_tokens: u32,
    calling_agent_id: &str,
    max_retries: u32,
) -> &'static str {
    match atomiser.atomise_sync_with_retries(
        conn,
        actual_id,
        max_atom_tokens,
        false,
        calling_agent_id,
        max_retries,
    ) {
        Ok(result) => {
            tracing::info!(
                target: AUTO_ATOMISE_SYNC_TRACE_TARGET,
                "synchronous-atomise succeeded: source={} atoms={}",
                result.source_id,
                result.atom_count,
            );
            crate::metrics::inc_atomise_applied();
            OUTCOME_ATOMISED
        }
        Err(AtomiseError::SourceTooSmall) => {
            tracing::info!(
                target: AUTO_ATOMISE_SYNC_TRACE_TARGET,
                "synchronous-atomise skipped: source={actual_id} body too small",
            );
            OUTCOME_SKIPPED_SOURCE_TOO_SMALL
        }
        Err(AtomiseError::AlreadyAtomised { .. }) => {
            tracing::info!(
                target: AUTO_ATOMISE_SYNC_TRACE_TARGET,
                "synchronous-atomise skipped: source={actual_id} already atomised",
            );
            OUTCOME_SKIPPED_ALREADY_ATOMISED
        }
        Err(e) => {
            tracing::error!(
                target: AUTO_ATOMISE_SYNC_TRACE_TARGET,
                "synchronous-atomise failed for source={actual_id}: {e:?}",
            );
            crate::metrics::inc_atomise_degraded();
            OUTCOME_FAILED
        }
    }
}

/// Background-worker entry point (the body the bounded single-consumer
/// atomise worker runs per job).
///
/// Sleeps 100 ms for the transaction-commit visibility window (matches
/// the WT-1-D brief), then opens a fresh connection and calls
/// `atomiser.atomise_sync`. Encapsulated as a free function so unit
/// tests can drive it without a worker.
///
/// Errors are logged + swallowed per the notify-class contract.
pub fn run_deferred_atomise(
    db_path: &Path,
    atomiser: &Atomiser,
    memory_id: &str,
    max_atom_tokens: u32,
    calling_agent_id: &str,
) {
    // The 100ms wait gives the originating transaction's WAL frame
    // time to checkpoint past the worker's read horizon on SQLite.
    std::thread::sleep(std::time::Duration::from_millis(100));

    let conn = match db::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "worker: failed to open db at {} for memory={}: {}",
                db_path.display(),
                memory_id,
                e
            );
            crate::metrics::inc_atomise_degraded();
            return;
        }
    };

    match atomiser.atomise_sync(&conn, memory_id, max_atom_tokens, false, calling_agent_id) {
        Ok(result) => {
            tracing::info!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation succeeded: source={} atoms={}",
                result.source_id,
                result.atom_count
            );
            crate::metrics::inc_atomise_applied();
        }
        Err(AtomiseError::AlreadyAtomised {
            source_id,
            existing_atom_ids,
        }) => {
            tracing::info!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation skipped (race): source={} already split into {} atoms",
                source_id,
                existing_atom_ids.len()
            );
        }
        Err(AtomiseError::SourceTooSmall) => {
            tracing::warn!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation skipped: source={memory_id} body fits within max_atom_tokens \
                 (curator returned no atoms)",
            );
        }
        Err(AtomiseError::CuratorFailed(reason)) => {
            tracing::error!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation curator failed for source={memory_id}: {reason} — \
                 operator may retry with `memory_atomise`",
            );
            crate::metrics::inc_atomise_degraded();
        }
        Err(AtomiseError::TierLocked) => {
            tracing::info!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation skipped: source={memory_id} tier_locked (keyword feature tier)",
            );
        }
        Err(AtomiseError::NotFound) => {
            // Race: memory was deleted between commit and drain.
            tracing::info!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation skipped: source={memory_id} not found (raced with delete?)",
            );
        }
        Err(e) => {
            tracing::error!(
                target: AUTO_ATOMISE_TRACE_TARGET,
                "auto-atomisation failed for source={memory_id}: {e:?} (full context: {e})",
            );
            crate::metrics::inc_atomise_degraded();
        }
    }
}

/// #2985 — the boot / doctor predicate: does ANY namespace standard
/// bound in this database request `auto_atomise`?
///
/// Returns the namespaces (deduped, bounded) whose resolved governance
/// policy carries a non-`Off` [`AutoAtomiseMode`]. A curator-less daemon
/// with a non-empty result is the misconfiguration #2985 filed: the knob
/// is set and structurally dead.
///
/// Deliberately NOT a check in `src/enterprise_federation_posture.rs` —
/// `ENTERPRISE_FEDERATION_CHECK_COUNT = 18` is pinned and a FAIL-capable
/// addition would flip certified deployments to exit 2, an unintended
/// re-cert event (the cert-mechanics half of the Q3 verdict).
#[must_use]
pub fn namespaces_requesting_auto_atomise(conn: &rusqlite::Connection) -> Vec<String> {
    /// Bound the scan so a huge corpus cannot turn a boot WARN into a
    /// long stall. An operator with more than this many opted-in
    /// namespaces already knows they use the feature.
    const MAX_REPORTED: usize = 32;

    let Ok(mut stmt) = conn.prepare(
        "SELECT namespace FROM namespace_meta WHERE standard_id IS NOT NULL ORDER BY namespace",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
        return Vec::new();
    };
    let namespaces: Vec<String> = rows.filter_map(Result::ok).collect();
    let mut out = Vec::new();
    for ns in namespaces {
        let policy = db::resolve_governance_policy(conn, &ns).unwrap_or_default();
        if policy.effective_auto_atomise_mode() != AutoAtomiseMode::Off {
            out.push(ns);
            if out.len() >= MAX_REPORTED {
                break;
            }
        }
    }
    out
}

/// Legacy alias retained for the deferred-enqueue outcome shape used by
/// the WT-1-D acceptance tests. Kept as a thin, honest wrapper over
/// [`run_auto_atomise`] so the historical enum stays meaningful.
#[derive(Debug, Clone)]
pub enum AutoAtomisationOutcome {
    /// Policy is `Off` / no curator / no queue. The hook short-circuits.
    Skipped { reason: &'static str },
    /// Token count fell at or under the configured threshold.
    UnderThreshold { tokens: usize, threshold: u32 },
    /// Job accepted by the bounded worker; the curator round-trip will
    /// land asynchronously.
    Enqueued {
        memory_id: String,
        namespace: String,
    },
}

/// Deferred-path entry point retained for callers that want the legacy
/// [`AutoAtomisationOutcome`] shape (the WT-1-D acceptance tests).
/// Production surfaces call [`run_auto_atomise`].
#[must_use]
pub fn maybe_enqueue_auto_atomise(
    conn: &rusqlite::Connection,
    db_path: &Path,
    memory: &Memory,
    actual_id: &str,
    calling_agent_id: &str,
    wiring: AtomiseWiring<'_>,
) -> AutoAtomisationOutcome {
    let policy = db::resolve_governance_policy(conn, &memory.namespace).unwrap_or_default();
    if !policy.effective_auto_atomise() {
        return AutoAtomisationOutcome::Skipped {
            reason: OUTCOME_SKIPPED_POLICY_DISABLED,
        };
    }
    let threshold = policy.effective_auto_atomise_threshold_cl100k();
    let tokens = db::count_tokens_cl100k(&memory.content);
    if tokens <= threshold as usize {
        return AutoAtomisationOutcome::UnderThreshold { tokens, threshold };
    }
    let disposition = run_auto_atomise(
        conn,
        db_path,
        memory,
        actual_id,
        calling_agent_id,
        AutoAtomiseMode::Deferred,
        &policy,
        wiring,
    );
    if disposition.outcome == OUTCOME_QUEUED {
        AutoAtomisationOutcome::Enqueued {
            memory_id: actual_id.to_string(),
            namespace: memory.namespace.clone(),
        }
    } else {
        AutoAtomisationOutcome::Skipped {
            reason: disposition.outcome,
        }
    }
}

/// Owned twin of [`AtomiseWiring`] for callers that must keep the
/// atomiser alive across a scope boundary (the HTTP enqueue helper
/// resolves the live atomiser from the swappable client, so it owns
/// the `Arc` rather than borrowing one).
#[derive(Clone, Default)]
pub struct OwnedAtomiseWiring {
    pub atomiser: Option<Arc<Atomiser>>,
    pub queue: Option<AtomiseQueue>,
}

impl OwnedAtomiseWiring {
    /// Borrow as an [`AtomiseWiring`].
    #[must_use]
    pub fn as_wiring(&self) -> AtomiseWiring<'_> {
        AtomiseWiring {
            atomiser: self.atomiser.as_ref(),
            queue: self.queue.as_ref(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests — exercise the policy-resolution + threshold + disposition
// logic with an injected mock curator. There is NO process-global to
// serialise against any more (#2983), so every test here is
// self-contained and order-independent — which is exactly why the old
// `known.contains(&tag)` / `dispatch_unset || policy_disabled` hedges
// (that the OnceLock forced) are GONE.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomisation::AtomiserConfig;
    use crate::atomisation::curator::{Atom, Curator, CuratorError};
    use crate::config::FeatureTier;
    use crate::models::{
        ApproverType, AtomisationPolicy, CorePolicy, GovernanceLevel, GovernancePolicy, Tier,
    };
    use chrono::Utc;
    use rusqlite::Connection;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    fn fresh_db() -> (Connection, TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ai-memory.db");
        let conn = db::open(&path).unwrap();
        (conn, dir, path)
    }

    fn make_memory(ns: &str, content: &str) -> Memory {
        let now = Utc::now().to_rfc3339();
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: format!("title-{}", uuid::Uuid::new_v4().simple()),
            content: content.to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id": "ai:test"}),
            ..Default::default()
        }
    }

    fn seed_policy(conn: &Connection, ns: &str, policy: GovernancePolicy) {
        let now = Utc::now().to_rfc3339();
        let gov_metadata = serde_json::json!({
            "agent_id": "ai:test",
            "governance": serde_json::to_value(&policy).unwrap(),
        });
        let std_mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: format!("__standard_{ns}"),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: gov_metadata,
            ..Default::default()
        };
        let std_id = db::insert(conn, &std_mem).unwrap();
        db::set_namespace_standard(conn, ns, &std_id, None).unwrap();
    }

    fn opt_in_policy(mode: Option<AutoAtomiseMode>) -> GovernancePolicy {
        GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Human,
                inherit: true,
                max_reflection_depth: None,
                required_scope: None,
            },
            atomisation: AtomisationPolicy {
                auto_atomise: Some(true),
                auto_atomise_threshold_cl100k: Some(50),
                auto_atomise_max_atom_tokens: Some(20),
                auto_atomise_max_retries: None,
                auto_atomise_mode: mode,
            },
            ..Default::default()
        }
    }

    struct SeqCurator {
        responses: StdMutex<Vec<Result<Vec<Atom>, CuratorError>>>,
    }
    impl SeqCurator {
        fn new(responses: Vec<Result<Vec<Atom>, CuratorError>>) -> Self {
            Self {
                responses: StdMutex::new(responses),
            }
        }
    }
    impl Curator for SeqCurator {
        fn decompose(
            &self,
            _body: &str,
            _max_atom_tokens: u32,
            _max_retries: u32,
        ) -> Result<Vec<Atom>, CuratorError> {
            let mut rs = self.responses.lock().unwrap();
            if rs.is_empty() {
                return Err(CuratorError::LlmUnavailable("seq exhausted".into()));
            }
            rs.remove(0)
        }
    }

    fn atomiser_with(curator: Box<dyn Curator>, tier: FeatureTier) -> Atomiser {
        Atomiser::new(curator, None, AtomiserConfig::default(), tier)
    }

    fn two_atom_atomiser() -> Arc<Atomiser> {
        Arc::new(atomiser_with(
            Box::new(SeqCurator::new(vec![Ok(vec![
                Atom {
                    text: "first atomic proposition".into(),
                },
                Atom {
                    text: "second atomic proposition".into(),
                },
            ])])),
            FeatureTier::Smart,
        ))
    }

    fn big_body() -> String {
        "proposition token padding here. ".repeat(400)
    }

    #[test]
    fn off_mode_reports_off_and_policy_disabled() {
        let (conn, _dir, path) = fresh_db();
        let mem = make_memory("off-ns", "hi");
        let d = run_auto_atomise(
            &conn,
            &path,
            &mem,
            &mem.id,
            "ai:test",
            AutoAtomiseMode::Off,
            &db::resolve_governance_policy(&conn, &mem.namespace).unwrap_or_default(),
            AtomiseWiring::default(),
        );
        assert_eq!(d.mode_ran, AutoAtomiseMode::Off);
        assert_eq!(d.outcome, OUTCOME_SKIPPED_POLICY_DISABLED);
        assert!(d.reason.is_none());
    }

    #[test]
    fn no_curator_reports_skipped_no_curator_not_a_wiring_state() {
        // #2985 — the distinct outcome token. Pre-#2983 this was
        // conflated with the (now-deleted) `skipped_dispatch_unset`.
        let (conn, _dir, path) = fresh_db();
        seed_policy(&conn, "nc-ns", opt_in_policy(None));
        let mem = make_memory("nc-ns", &big_body());
        let d = run_auto_atomise(
            &conn,
            &path,
            &mem,
            &mem.id,
            "ai:test",
            AutoAtomiseMode::Deferred,
            &db::resolve_governance_policy(&conn, &mem.namespace).unwrap_or_default(),
            AtomiseWiring::default(),
        );
        assert_eq!(d.outcome, OUTCOME_SKIPPED_NO_CURATOR);
        assert_eq!(d.mode_ran, AutoAtomiseMode::Off);
        assert_eq!(d.mode_configured, AutoAtomiseMode::Deferred);
        assert_eq!(d.reason, Some(REASON_NO_CURATOR));
    }

    #[test]
    fn under_threshold_keeps_the_configured_mode_label() {
        let (conn, _dir, path) = fresh_db();
        seed_policy(&conn, "small-ns", opt_in_policy(None));
        let atomiser = two_atom_atomiser();
        let mem = make_memory("small-ns", "hi");
        let d = run_auto_atomise(
            &conn,
            &path,
            &mem,
            &mem.id,
            "ai:test",
            AutoAtomiseMode::Deferred,
            &db::resolve_governance_policy(&conn, &mem.namespace).unwrap_or_default(),
            AtomiseWiring::new(Some(&atomiser), None),
        );
        assert_eq!(d.outcome, OUTCOME_SKIPPED_UNDER_THRESHOLD);
        assert_eq!(d.mode_ran, AutoAtomiseMode::Deferred);
        assert!(d.reason.is_none());
    }

    #[test]
    fn synchronous_mode_with_injected_curator_atomises_deterministically() {
        // The whole point of abolishing the process-global: this test
        // asserts an EXACT outcome, not a `known.contains(&tag)` hedge.
        let (conn, _dir, path) = fresh_db();
        seed_policy(
            &conn,
            "sync-ns",
            opt_in_policy(Some(AutoAtomiseMode::Synchronous)),
        );
        let atomiser = two_atom_atomiser();
        let mem = make_memory("sync-ns", &big_body());
        let id = db::insert(&conn, &mem).unwrap();
        let d = run_auto_atomise(
            &conn,
            &path,
            &mem,
            &id,
            "ai:test",
            AutoAtomiseMode::Synchronous,
            &db::resolve_governance_policy(&conn, &mem.namespace).unwrap_or_default(),
            AtomiseWiring::new(Some(&atomiser), None),
        );
        assert_eq!(d.outcome, OUTCOME_ATOMISED, "disposition: {d:?}");
        assert_eq!(d.mode_ran, AutoAtomiseMode::Synchronous);
        assert!(d.reason.is_none());
        let atoms: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                rusqlite::params![&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(atoms, 2, "the injected curator's two atoms must land");
    }

    #[test]
    fn deferred_without_a_queue_degrades_honestly() {
        let (conn, _dir, path) = fresh_db();
        seed_policy(&conn, "noq-ns", opt_in_policy(None));
        let atomiser = two_atom_atomiser();
        let mem = make_memory("noq-ns", &big_body());
        let id = db::insert(&conn, &mem).unwrap();
        let d = run_auto_atomise(
            &conn,
            &path,
            &mem,
            &id,
            "ai:test",
            AutoAtomiseMode::Deferred,
            &db::resolve_governance_policy(&conn, &mem.namespace).unwrap_or_default(),
            AtomiseWiring::new(Some(&atomiser), None),
        );
        assert_eq!(d.outcome, OUTCOME_SKIPPED_QUEUE_FULL);
        assert_eq!(d.mode_ran, AutoAtomiseMode::Off);
        assert_eq!(d.mode_configured, AutoAtomiseMode::Deferred);
        assert_eq!(d.reason, Some(REASON_QUEUE_FULL));
    }

    #[test]
    fn disposition_merges_mode_on_every_branch() {
        let mut v = serde_json::json!({});
        AtomiseDisposition::ran(AutoAtomiseMode::Off, OUTCOME_SKIPPED_POLICY_DISABLED)
            .merge_into_response(&mut v);
        assert_eq!(v[FIELD_ATOMISE_MODE], "off");
        assert_eq!(v[FIELD_ATOMISE_OUTCOME], OUTCOME_SKIPPED_POLICY_DISABLED);
        assert!(v.get(FIELD_ATOMISE_MODE_CONFIGURED).is_none());

        let mut v2 = serde_json::json!({});
        AtomiseDisposition::diverged(
            AutoAtomiseMode::Deferred,
            AutoAtomiseMode::Synchronous,
            REASON_DEFERRED_ON_HTTP,
            OUTCOME_QUEUED,
        )
        .merge_into_response(&mut v2);
        assert_eq!(v2[FIELD_ATOMISE_MODE], "deferred");
        assert_eq!(v2[FIELD_ATOMISE_MODE_CONFIGURED], "synchronous");
        assert_eq!(v2[FIELD_ATOMISE_MODE_REASON], REASON_DEFERRED_ON_HTTP);
        assert_eq!(v2[FIELD_ATOMISE_OUTCOME], OUTCOME_QUEUED);
    }

    #[test]
    fn namespaces_requesting_auto_atomise_finds_the_opt_in() {
        let (conn, _dir, _path) = fresh_db();
        seed_policy(
            &conn,
            "batman-ns",
            opt_in_policy(Some(AutoAtomiseMode::Synchronous)),
        );
        let found = namespaces_requesting_auto_atomise(&conn);
        assert!(
            found.iter().any(|n| n == "batman-ns"),
            "expected batman-ns in {found:?}"
        );
    }

    #[test]
    fn namespaces_requesting_auto_atomise_is_empty_without_opt_in() {
        let (conn, _dir, _path) = fresh_db();
        assert!(namespaces_requesting_auto_atomise(&conn).is_empty());
    }

    #[test]
    fn run_deferred_atomise_db_open_failure_is_swallowed() {
        let (_conn, dir, _path) = fresh_db();
        let file_as_parent = dir.path().join("not-a-dir");
        std::fs::write(&file_as_parent, b"x").unwrap();
        let bad_path = file_as_parent.join("child.db");
        let atomiser = atomiser_with(Box::new(SeqCurator::new(vec![])), FeatureTier::Smart);
        run_deferred_atomise(&bad_path, &atomiser, "mem-x", 200, "ai:test");
    }

    #[test]
    fn run_deferred_atomise_success_arm_lands_atoms() {
        let (conn, _dir, path) = fresh_db();
        let mem = make_memory("ns-ok", &big_body());
        let id = db::insert(&conn, &mem).unwrap();
        drop(conn);
        let atomiser = two_atom_atomiser();
        run_deferred_atomise(&path, &atomiser, &id, 50, "ai:test");
        let conn2 = db::open(&path).unwrap();
        let atom_count: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                rusqlite::params![&id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(atom_count, 2, "expected the two mock atoms");
    }

    #[test]
    fn run_deferred_atomise_not_found_and_tier_locked_arms_are_swallowed() {
        let (conn, _dir, path) = fresh_db();
        let atomiser = atomiser_with(Box::new(SeqCurator::new(vec![])), FeatureTier::Smart);
        run_deferred_atomise(&path, &atomiser, "no-such-id", 200, "ai:test");

        let mem = make_memory("ns-tier", &big_body());
        let id = db::insert(&conn, &mem).unwrap();
        drop(conn);
        let keyword = atomiser_with(Box::new(SeqCurator::new(vec![])), FeatureTier::Keyword);
        run_deferred_atomise(&path, &keyword, &id, 50, "ai:test");
    }

    #[test]
    fn maybe_enqueue_legacy_shape_reports_under_threshold() {
        let (conn, _dir, path) = fresh_db();
        seed_policy(&conn, "legacy-ns", opt_in_policy(None));
        let atomiser = two_atom_atomiser();
        let small = make_memory("legacy-ns", "hi");
        let id = db::insert(&conn, &small).unwrap();
        let outcome = maybe_enqueue_auto_atomise(
            &conn,
            &path,
            &small,
            &id,
            "ai:test",
            AtomiseWiring::new(Some(&atomiser), None),
        );
        match outcome {
            AutoAtomisationOutcome::UnderThreshold { threshold, .. } => assert_eq!(threshold, 50),
            other => panic!("expected UnderThreshold, got {other:?}"),
        }
    }

    #[test]
    fn wiring_debug_redacts_the_atomiser() {
        let atomiser = two_atom_atomiser();
        let w = AtomiseWiring::new(Some(&atomiser), None);
        let s = format!("{w:?}");
        assert!(s.contains("AtomiseWiring"));
        assert!(s.contains("<Arc<Atomiser>>"));
        assert!(w.has_curator());
        assert!(!AtomiseWiring::default().has_curator());
    }

    #[test]
    fn owned_wiring_borrows_back() {
        let owned = OwnedAtomiseWiring {
            atomiser: Some(two_atom_atomiser()),
            queue: None,
        };
        assert!(owned.as_wiring().has_curator());
        assert!(!OwnedAtomiseWiring::default().as_wiring().has_curator());
    }
}
