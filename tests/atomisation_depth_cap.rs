// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-5 (FX-6) — regression test pinning the substrate
//! atomisation-recursion-depth cap.
//!
//! Before FX-6 the atomiser had NO explicit recursion-depth cap. Every
//! other recursive primitive in the substrate (reflect, synthesis,
//! kg-query, find-paths, cycle-check) ships with a named `pub const`
//! cap + a typed refusal slug; atomisation relied solely on
//! `AlreadyAtomised` idempotency to break a chain. A misbehaving
//! curator chain-firing fresh atomise calls (via the `pre_store`
//! auto-atomise hook on a freshly-minted atom in a namespace that
//! opted in, etc.) could therefore drive unbounded recursion + OOM.
//!
//! This file pins the contract:
//!
//! 1. [`ai_memory::atomisation::MAX_ATOMISATION_DEPTH`] is exposed as
//!    a `pub const` so callers can assert against it without
//!    duplicating the numeric value.
//! 2. The depth-guard RAII pair
//!    ([`ai_memory::atomisation::enter_atomisation_pass`] +
//!    [`ai_memory::atomisation::current_atomisation_depth`]) is
//!    publicly callable from outside the crate.
//! 3. An [`ai_memory::atomisation::Atomiser::atomise_sync`] invocation
//!    issued while the thread is already at-cap returns
//!    [`ai_memory::atomisation::AtomiseError::DepthExceeded`] with
//!    `attempted = cap + 1` and the stable
//!    `ATOMISATION_DEPTH_EXCEEDED` slug in the `Display` output.
//! 4. The refusal fires BEFORE the substrate burns any DB read / LLM
//!    round-trip (curator's `decompose` is never called) — proves the
//!    cap is the substrate-entry gate, not a post-decompose check.
//!
//! The "deepest call refuses" scenario is constructed without spinning
//! up the `pre_store` hook chain (which would require wiring a full
//! HTTP daemon / governance / signed-events scaffold for one
//! assertion). The public `enter_atomisation_pass` RAII guard is the
//! supported mechanism for callers (and tests) to drive the depth
//! counter; pre-loading the counter to `MAX_ATOMISATION_DEPTH` and
//! then calling `atomise_sync` produces the same refusal the
//! production recursive-chain-fire path would produce — both paths
//! converge on the same thread-local counter inside the atomiser.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::used_underscore_binding
)]

use std::sync::Mutex;

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{
    AtomiseError, Atomiser, AtomiserConfig, MAX_ATOMISATION_DEPTH, current_atomisation_depth,
    enter_atomisation_pass,
};
use ai_memory::config::FeatureTier;

/// Curator that records every `decompose` invocation so the test can
/// assert the substrate refused BEFORE the curator was consulted.
/// Returns trivial atoms when called (it shouldn't be, in the
/// over-cap scenario).
struct RecordingCurator {
    calls: Mutex<u32>,
}

impl RecordingCurator {
    fn new() -> Self {
        Self {
            calls: Mutex::new(0),
        }
    }

    fn call_count(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
}

impl Curator for RecordingCurator {
    fn decompose(
        &self,
        _body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        *self.calls.lock().unwrap() += 1;
        Ok(vec![
            Atom {
                text: "atom A".into(),
            },
            Atom {
                text: "atom B".into(),
            },
        ])
    }
}

// ---------------------------------------------------------------------------
// Test 1 — `pub const` exposure invariant.
// ---------------------------------------------------------------------------

#[test]
fn max_atomisation_depth_const_is_publicly_pinnable() {
    // The cap is `pub const` so callers OUTSIDE the crate (this test
    // module, downstream operator tooling) can assert against it
    // without duplicating the numeric value. Pin the value to 3 to
    // mirror the rest of the recursive-primitive discipline
    // (synthesis ships at 3; reflection's
    // `DEFAULT_REFLECTION_MAX_DEPTH_CAP` ships at 3).
    assert_eq!(MAX_ATOMISATION_DEPTH, 3);
}

// ---------------------------------------------------------------------------
// Test 2 — RAII guard publicly callable + depth tracks correctly.
// ---------------------------------------------------------------------------

#[test]
fn enter_atomisation_pass_is_publicly_callable() {
    // Fresh thread starts at depth 0.
    assert_eq!(current_atomisation_depth(), 0);

    let (d1, _g1) = enter_atomisation_pass();
    assert_eq!(d1, 1);
    assert_eq!(current_atomisation_depth(), 1);

    let (d2, _g2) = enter_atomisation_pass();
    assert_eq!(d2, 2);
    assert_eq!(current_atomisation_depth(), 2);

    // After both guards drop the depth must restore to 0 — otherwise
    // a panicking nested call would leak the higher depth into the
    // next request reusing this thread.
    drop(_g2);
    assert_eq!(current_atomisation_depth(), 1);
    drop(_g1);
    assert_eq!(current_atomisation_depth(), 0);
}

// ---------------------------------------------------------------------------
// Test 3 — atomise_sync refuses with ATOMISATION_DEPTH_EXCEEDED when
// the thread is already at-cap (the "deepest call" scenario the brief
// requires).
// ---------------------------------------------------------------------------

#[test]
fn atomise_sync_at_cap_refuses_with_atomisation_depth_exceeded() {
    // Pre-load the thread-local counter so the next
    // `atomise_sync_with_retries` entry observes depth =
    // `MAX_ATOMISATION_DEPTH + 1` and refuses on entry.
    //
    // This faithfully models the production recursive-chain-fire
    // path: in production an outer `atomise_sync` already holds the
    // depth-1 guard, its `pre_store` hook on a freshly-minted atom
    // chain-fires the auto-atomise hook which calls a nested
    // `atomise_sync` at depth-2 — same counter, same RAII discipline.
    // Driving the counter directly avoids spinning up the full
    // `pre_store` hook chain + auto-atomise dispatch + signed-events
    // scaffold for a one-line assertion.
    let _g1 = enter_atomisation_pass(); // depth 1
    let _g2 = enter_atomisation_pass(); // depth 2
    let _g3 = enter_atomisation_pass(); // depth 3 — at-cap
    assert_eq!(current_atomisation_depth(), MAX_ATOMISATION_DEPTH);

    // Build an atomiser with a curator that records calls; we expect
    // the curator to NEVER be invoked because the cap fires at the
    // substrate-entry gate, before any DB read / LLM round-trip.
    let curator = std::sync::Arc::new(RecordingCurator::new());
    let atomiser = Atomiser::new(
        Box::new(RecordingCuratorBox {
            inner: curator.clone(),
        }),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    );

    // We don't need a live DB — the depth-cap check fires BEFORE
    // `db::get(conn, source_id)`. Use an in-memory connection so the
    // test doesn't need to scaffold tempfile cleanup; even if the
    // implementation regressed to consult the DB first the in-memory
    // connection would just surface a different error variant.
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite open");

    let err = atomiser
        .atomise_sync(&conn, "some-id", 0, false, "test-agent")
        .expect_err("atomise must refuse at depth-cap");

    // Pin the typed variant + the structured payload.
    match err {
        AtomiseError::DepthExceeded { attempted, cap } => {
            assert_eq!(
                attempted,
                MAX_ATOMISATION_DEPTH + 1,
                "attempted depth must be cap+1 (the over-cap value)"
            );
            assert_eq!(cap, MAX_ATOMISATION_DEPTH);
        }
        other => panic!("expected DepthExceeded, got {other:?}"),
    }

    // Pin the stable wire slug in the Display output — MCP / HTTP
    // / CLI clients switch on this prefix.
    let err = atomiser
        .atomise_sync(&conn, "some-id", 0, false, "test-agent")
        .expect_err("atomise must refuse at depth-cap on second call too");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("ATOMISATION_DEPTH_EXCEEDED"),
        "Display must carry the stable slug; got: {rendered}"
    );

    // Curator must NEVER have been consulted — the cap fires before
    // any DB read / LLM round-trip. Pre-FX-6 (no cap), atomise would
    // have proceeded to `db::get` and either errored on NotFound or
    // entered the curator path.
    assert_eq!(
        curator.call_count(),
        0,
        "curator must not be invoked when the depth cap refuses on entry"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — under-cap calls still proceed (sanity: the cap doesn't
// strangle legitimate two-step curator hand-offs).
// ---------------------------------------------------------------------------

#[test]
fn atomise_sync_under_cap_proceeds_past_depth_check() {
    // Depth 1 — strictly under the cap. The substrate should NOT
    // refuse on the depth check; subsequent failures (NotFound on the
    // synthetic in-memory DB) are expected and OK — what we're pinning
    // is that the depth check itself returns control to the next
    // step, not that the full atomise succeeds.
    let _g1 = enter_atomisation_pass(); // depth 1
    assert_eq!(current_atomisation_depth(), 1);
    assert!(current_atomisation_depth() <= MAX_ATOMISATION_DEPTH);

    let curator = std::sync::Arc::new(RecordingCurator::new());
    let atomiser = Atomiser::new(
        Box::new(RecordingCuratorBox {
            inner: curator.clone(),
        }),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    );
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite open");

    let err = atomiser
        .atomise_sync(&conn, "missing-id", 0, false, "test-agent")
        .expect_err("in-memory db has no rows; expect NotFound or DbError");

    // The error MUST NOT be DepthExceeded — depth=1 is under the cap.
    // Anything else (NotFound, DbError from the schema-less in-memory
    // DB, etc.) confirms the depth check passed and control flowed
    // past the gate.
    assert!(
        !matches!(err, AtomiseError::DepthExceeded { .. }),
        "depth=1 is under cap=3; substrate must NOT refuse with DepthExceeded; got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — the depth counter restores to 0 after every atomise call,
// even when the call errors. Prevents a "leaked depth" failure mode
// where an erroring atomise would semi-permanently raise the
// thread-local counter and break every subsequent legitimate call on
// the same thread.
// ---------------------------------------------------------------------------

#[test]
fn depth_counter_restores_after_errored_atomise() {
    assert_eq!(current_atomisation_depth(), 0);

    let curator = std::sync::Arc::new(RecordingCurator::new());
    let atomiser = Atomiser::new(
        Box::new(RecordingCuratorBox {
            inner: curator.clone(),
        }),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    );
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite open");

    // Errors on missing row — atomiser's own RAII guard must still
    // decrement on the error path.
    let _ = atomiser.atomise_sync(&conn, "missing-id", 0, false, "test-agent");
    assert_eq!(
        current_atomisation_depth(),
        0,
        "atomiser's depth guard must restore to 0 on the error path"
    );

    // Second call's atomise still sees depth 0, not 1.
    let _ = atomiser.atomise_sync(&conn, "missing-id-2", 0, false, "test-agent");
    assert_eq!(current_atomisation_depth(), 0);
}

// ---------------------------------------------------------------------------
// Curator adapter that lets the test crate share a single
// `Arc<RecordingCurator>` across the atomiser construction (which
// takes a `Box<dyn Curator>`) and the post-call assertions.
// ---------------------------------------------------------------------------

struct RecordingCuratorBox {
    inner: std::sync::Arc<RecordingCurator>,
}

impl Curator for RecordingCuratorBox {
    fn decompose(
        &self,
        body: &str,
        max_atom_tokens: u32,
        max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        self.inner.decompose(body, max_atom_tokens, max_retries)
    }
}
