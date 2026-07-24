// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2396 (finding N15) — `checkpoints::apply_inbound_resolution` must be a
//! COMPARE-AND-SWAP on `state`, not a get-then-UPDATE.
//!
//! A resolved commit-checkpoint is an AUTHORITY-granting write (the
//! separation-of-duties freeze anchor the epoch-apply consumer later trusts).
//! The documented contract for the inbound federated apply — see the
//! `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` (#125) env row and
//! `docs/federation.md` — is **first-resolution-wins**: a checkpoint already
//! resolved locally with a DIFFERENT resolution is a per-item CONFLICT (local
//! kept, counted `checkpoints_conflicted`), never an overwrite and never a
//! batch abort.
//!
//! Pre-fix the apply read the row, branched on "local is pending", then wrote
//! WITHOUT re-checking the state — a TOCTOU window in which a concurrently
//! committed local resolution was silently clobbered by the later writer.
//! These tests pin the CAS: they drive the interleaving across SEPARATE
//! sqlite connections on ONE database file (so the guard is proven at the
//! storage layer, not as a same-connection artifact) and assert the local
//! resolution survives and the loser is surfaced as a conflict.

use ai_memory::checkpoints::{
    InboundResolutionOutcome, apply_inbound_resolution, get, insert, resolve,
};
use ai_memory::models::{Checkpoint, CheckpointState, ConditionType};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Barrier};

const NS: &str = "_cp_2396";
const CP_ID: &str = "cp-2396";
const LOCAL_RESOLVER: &str = "agent-local";
const REMOTE_RESOLVER: &str = "agent-remote";
const LOCAL_VERDICT: &str = "approved-locally";
const REMOTE_VERDICT: &str = "rejected-remotely";
const RESOLVED_AT: i64 = 1_700_000_100;

fn pending(id: &str) -> Checkpoint {
    Checkpoint {
        id: id.to_string(),
        namespace: NS.to_string(),
        title: "needs approval".to_string(),
        condition_type: ConditionType::Approval,
        condition: serde_json::json!({}),
        state: CheckpointState::Pending,
        created_by: "agent-creator".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::json!({}),
    }
}

/// An inbound (already-resolved) checkpoint as it arrives on the wire.
fn inbound(id: &str, state: CheckpointState, resolved_by: &str, verdict: &str) -> Checkpoint {
    Checkpoint {
        state,
        resolved_by: Some(resolved_by.to_string()),
        resolution: Some(verdict.to_string()),
        resolution_note: Some("from peer".to_string()),
        resolved_at: Some(RESOLVED_AT),
        ..pending(id)
    }
}

fn db_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("cp-2396.db")
}

fn open_at(path: &Path) -> Connection {
    ai_memory::storage::open(path).expect("open checkpoint db")
}

/// Sequential case: an already-resolved checkpoint is NEVER overwritten by a
/// divergent inbound resolution — the local verdict stands and the inbound one
/// is surfaced as a conflict (the counter arm the receive loop tallies as
/// `checkpoints_conflicted`).
#[test]
fn resolved_checkpoint_is_not_overwritten_by_divergent_inbound_2396() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = open_at(&db_path(&dir));
    insert(&conn, &pending(CP_ID)).expect("insert pending");

    // Local operator resolves first.
    resolve(
        &conn,
        CP_ID,
        CheckpointState::Resolved,
        LOCAL_RESOLVER,
        Some(LOCAL_VERDICT),
        None,
        RESOLVED_AT,
        None,
    )
    .expect("local resolve")
    .expect("row present");

    let outcome = apply_inbound_resolution(
        &conn,
        &inbound(
            CP_ID,
            CheckpointState::Rejected,
            REMOTE_RESOLVER,
            REMOTE_VERDICT,
        ),
    )
    .expect("apply inbound");

    assert_eq!(
        outcome,
        InboundResolutionOutcome::Conflict,
        "a divergent inbound resolution must be a first-resolution-wins conflict"
    );
    let row = get(&conn, CP_ID).expect("get").expect("row present");
    assert_eq!(row.state, CheckpointState::Resolved, "local state kept");
    assert_eq!(row.resolved_by.as_deref(), Some(LOCAL_RESOLVER));
    assert_eq!(row.resolution.as_deref(), Some(LOCAL_VERDICT));
}

/// The N15 window, emulated at the caller level across two connections on one
/// DB file: the applier side observes a PENDING row (the "check"), a concurrent
/// LOCAL resolve commits on the other connection, and only then does the
/// inbound apply run (the "use"). The local resolution must survive.
#[test]
fn interleaved_local_resolve_wins_over_inbound_apply_2396() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = db_path(&dir);
    let writer = open_at(&path);
    let applier = open_at(&path);
    insert(&writer, &pending(CP_ID)).expect("insert pending");

    // T1 — the applier's read of the pending row (the TOCTOU "check").
    let observed = get(&applier, CP_ID).expect("get").expect("row present");
    assert_eq!(observed.state, CheckpointState::Pending);

    // T2 — a LOCAL resolution commits on the other connection, in the window.
    resolve(
        &writer,
        CP_ID,
        CheckpointState::Resolved,
        LOCAL_RESOLVER,
        Some(LOCAL_VERDICT),
        None,
        RESOLVED_AT,
        None,
    )
    .expect("local resolve")
    .expect("row present");

    // T3 — the applier's write (the TOCTOU "use") now runs on stale knowledge.
    let outcome = apply_inbound_resolution(
        &applier,
        &inbound(
            CP_ID,
            CheckpointState::Rejected,
            REMOTE_RESOLVER,
            REMOTE_VERDICT,
        ),
    )
    .expect("apply inbound");

    assert_eq!(
        outcome,
        InboundResolutionOutcome::Conflict,
        "the inbound applier lost the race — it must report a conflict, not overwrite"
    );
    let row = get(&writer, CP_ID).expect("get").expect("row present");
    assert_eq!(row.state, CheckpointState::Resolved);
    assert_eq!(row.resolved_by.as_deref(), Some(LOCAL_RESOLVER));
    assert_eq!(
        row.resolution.as_deref(),
        Some(LOCAL_VERDICT),
        "the authority-lane verdict must not flip after the fact"
    );
}

/// A byte-identical inbound replay of an already-applied resolution stays an
/// idempotent no-op under the CAS (the `Noop` arm must not regress into
/// `Conflict`).
#[test]
fn identical_inbound_replay_is_still_noop_2396() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = open_at(&db_path(&dir));
    let remote = inbound(
        CP_ID,
        CheckpointState::Resolved,
        REMOTE_RESOLVER,
        REMOTE_VERDICT,
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &remote).expect("first apply"),
        InboundResolutionOutcome::Applied
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &remote).expect("replay"),
        InboundResolutionOutcome::Noop
    );
}

/// Iterations of the true concurrent race — the arm that actually distinguishes
/// the CAS from the pre-fix get-then-UPDATE.
const RACE_ITERATIONS: usize = 40;

/// TRUE concurrency: two peers push DIFFERENT resolutions for the same pending
/// checkpoint at the same instant, on separate connections to one DB file.
///
/// Under the CAS, exactly ONE apply can win the pending→resolved transition, so
/// the invariant is absolute regardless of timing: exactly one `Applied`, the
/// other a `Conflict`, and the persisted row carries the WINNER's verdict.
/// Under the pre-fix get-then-UPDATE both callers could read `pending` and then
/// both UPDATE unconditionally — TWO `Applied` results with the second write
/// clobbering the first, which this assertion rejects. Repeated
/// [`RACE_ITERATIONS`] times (fresh id per round) so the pre-fix window is
/// sampled many times; post-fix it can never trip.
#[test]
fn concurrent_inbound_resolutions_cannot_both_apply_2396() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = db_path(&dir);

    for i in 0..RACE_ITERATIONS {
        let id = format!("{CP_ID}-race-{i}");
        let seed = open_at(&path);
        insert(&seed, &pending(&id)).expect("insert pending");
        drop(seed);

        let barrier = Arc::new(Barrier::new(2));
        let racers: Vec<_> = [
            (CheckpointState::Resolved, LOCAL_RESOLVER, LOCAL_VERDICT),
            (CheckpointState::Rejected, REMOTE_RESOLVER, REMOTE_VERDICT),
        ]
        .into_iter()
        .map(|(state, resolver, verdict)| {
            let path = path.clone();
            let id = id.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let conn = open_at(&path);
                let cp = inbound(&id, state, resolver, verdict);
                barrier.wait();
                let outcome = apply_inbound_resolution(&conn, &cp)
                    .expect("apply inbound must never hard-error under contention");
                (outcome, resolver, verdict)
            })
        })
        .collect();

        let results: Vec<_> = racers
            .into_iter()
            .map(|h| h.join().expect("racer thread"))
            .collect();

        let applied: Vec<_> = results
            .iter()
            .filter(|(outcome, _, _)| *outcome == InboundResolutionOutcome::Applied)
            .collect();
        assert_eq!(
            applied.len(),
            1,
            "exactly one concurrent resolution may win the pending->resolved CAS; got {results:?}"
        );
        assert!(
            results
                .iter()
                .all(|(outcome, _, _)| *outcome != InboundResolutionOutcome::Noop),
            "divergent resolutions can never be an idempotent replay; got {results:?}"
        );

        let (_, winner_resolver, winner_verdict) = applied[0];
        let conn = open_at(&path);
        let row = get(&conn, &id).expect("get").expect("row present");
        assert_eq!(
            row.resolved_by.as_deref(),
            Some(*winner_resolver),
            "the persisted row must carry the CAS winner's resolver, not a later clobber"
        );
        assert_eq!(row.resolution.as_deref(), Some(*winner_verdict));
    }
}
