// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3402 — the CLI store surface's POST-INSERT namespace-policy
//! wiring.
//!
//! # The defect this closes
//!
//! `ai-memory store` called [`crate::db::insert`] and stopped. The ACL
//! half of a namespace's [`GovernancePolicy`] WAS enforced on the CLI
//! (`cli::governance::enforce`, before the insert), but the post-insert
//! half — Batman auto-atomisation — was only ever run by the MCP twin
//! (`src/mcp/tools/store/mod.rs`). So the SAME namespace standard was
//! half-applied depending on which surface the operator happened to use:
//! an over-threshold body stored through MCP came back
//! `atomised_into = 10`, and the byte-identical body stored through the
//! CLI came back with nothing. A governance policy that means different
//! things per surface is not a policy.
//!
//! # The control
//!
//! There is exactly ONE atomisation funnel in the substrate —
//! [`crate::hooks::pre_store::run_auto_atomise`] — and it is
//! surface-neutral by construction: the caller supplies an
//! [`AtomiseWiring`] and the funnel owns every mode / threshold /
//! curator-presence decision plus the honest
//! [`AtomiseDisposition`] it reports. The fix does NOT re-implement any
//! of that for the CLI; it makes the CLI a CALLER of that funnel. This
//! module owns only the part that is genuinely surface-specific: how a
//! one-shot process obtains its wiring.
//!
//! # Why a one-shot process still honours `deferred`
//!
//! [`AutoAtomiseMode::Deferred`] means "hand the curator round trip to
//! the bounded background worker". A CLI invocation has no daemon to
//! defer to and exits within milliseconds of the write, so passing
//! `queue: None` would report an honest `skipped_queue_full` and leave
//! the policy's atomisation half permanently unapplied on this surface —
//! i.e. the #3402 defect, merely better-labelled. Instead the CLI spawns
//! the SAME bounded single-consumer worker the daemon runs
//! ([`atomise_worker::spawn_joinable`]), hands the funnel its queue, and
//! then drops the producer and joins: closing the channel makes the
//! consumer's `recv` fail only AFTER every buffered job has drained, so
//! the join is a deterministic "await the drain", never a timer. The CLI
//! *is* the worker, for the lifetime of one write.
//!
//! # Fail-closed posture
//!
//! Atoms are DERIVED data; the memory TEXT is the source of truth. Every
//! path here therefore degrades rather than fails: no curator, no worker
//! thread, or a panicking worker all leave the committed row untouched
//! and surface a loud, counted, honest disposition token that
//! `ai-memory atomise <id>` can act on later. Nothing in this module can
//! turn an already-durable write into a reported failure.

use std::path::Path;
use std::sync::Arc;

use crate::atomisation::Atomiser;
use crate::background::atomise_worker::{self, AtomiserProvider};
use crate::config::AppConfig;
use crate::hooks::pre_store::{AtomiseDisposition, AtomiseWiring, run_auto_atomise};
use crate::models::{AutoAtomiseMode, GovernancePolicy, Memory};

/// Run the shared auto-atomisation funnel for one committed CLI store.
///
/// Never returns an error and never panics: the row is already durable
/// when this is called, and atomisation is a derived, regenerable
/// concern (see the module docs). The returned [`AtomiseDisposition`] is
/// the funnel's own verdict — this module never fabricates one — so the
/// `atomise_mode` / `atomise_outcome` tokens the CLI echoes are
/// byte-identical to the ones the MCP twin echoes for the same policy.
pub(crate) fn run_auto_atomise_for_cli(
    conn: &rusqlite::Connection,
    db_path: &Path,
    memory: &Memory,
    actual_id: &str,
    calling_agent_id: &str,
    policy: &GovernancePolicy,
    app_config: &AppConfig,
    // Test seam, mirroring the `curator_override` the `ai-memory atomise`
    // verb has carried since v0.7.0: production passes `None` and the
    // atomiser is resolved lazily below (never for an opted-out
    // namespace); the unit tests inject a deterministic mock so the
    // CLI-vs-MCP parity assertions need no live LLM.
    atomiser_override: Option<&Arc<Atomiser>>,
) -> AtomiseDisposition {
    let configured = policy.effective_auto_atomise_mode();
    // One binding for the shared funnel so every arm below differs ONLY
    // in the wiring it supplies — the mode, threshold, policy and
    // disposition are the funnel's business on every surface.
    let funnel = |wiring: AtomiseWiring<'_>| {
        run_auto_atomise(
            conn,
            db_path,
            memory,
            actual_id,
            calling_agent_id,
            configured,
            policy,
            wiring,
        )
    };

    if configured == AutoAtomiseMode::Off {
        // Route the opt-out through the funnel too (rather than
        // returning a locally-built disposition) so the mode label and
        // outcome token can never drift per surface — and build NO
        // curator: an opted-out namespace must not construct an LLM
        // client or evaluate the inference-plane egress gate.
        return funnel(AtomiseWiring::default());
    }

    let atomiser = match atomiser_override {
        // OWNERSHIP-21 — refcount bump, not a deep clone.
        Some(injected) => Some(Arc::clone(injected)),
        None => {
            crate::cli::commands::atomise::build_cli_atomiser(app_config, db_path, calling_agent_id)
        }
    };

    let Some(atomiser) = atomiser else {
        // No curator on this host. The funnel owns the loud, counted
        // `skipped_no_curator` verdict (#2985) — never a silent green.
        return funnel(AtomiseWiring::default());
    };

    if configured != AutoAtomiseMode::Deferred {
        return funnel(AtomiseWiring::new(Some(&atomiser), None));
    }

    // Deferred on a one-shot process — see the module docs.
    let provider_atomiser = Arc::clone(&atomiser);
    let provider: AtomiserProvider = Arc::new(move || Some(Arc::clone(&provider_atomiser)));
    let Some((queue, worker)) = atomise_worker::spawn_joinable(provider) else {
        // The OS refused the thread. Degrade through the funnel's own
        // `skipped_queue_full` arm; the durable row is untouched.
        return funnel(AtomiseWiring::new(Some(&atomiser), None));
    };
    let disposition = funnel(AtomiseWiring::new(Some(&atomiser), Some(&queue)));
    // Drop the ONLY producer, then join: `recv` returns `Err` only once
    // the buffered job has been drained, so this awaits the drain
    // deterministically instead of racing a wall-clock deadline.
    drop(queue);
    if worker.join().is_err() {
        // A panicking worker is a notify-class event: the committed row
        // is untouched and `ai-memory atomise <id>` can still recover
        // the atoms. Never escalated into a store failure.
        tracing::warn!(
            "the in-process auto_atomise worker panicked while draining memory {actual_id} \
             — the durable row is untouched; re-run `ai-memory atomise {actual_id}`"
        );
    }
    disposition
}
