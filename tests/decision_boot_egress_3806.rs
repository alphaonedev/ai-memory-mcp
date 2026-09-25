// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1b, PIN — the PUBLIC boot chokepoint and the PUBLIC per-call
//! hook really do read `AI_MEMORY_INFERENCE_EGRESS`.
//!
//! The posture pins in `src/decision_boot.rs` drive the crate-private
//! `*_under` seams so they never mutate the process-global environment
//! (`src/**` is ONE lib test binary whose tests run in parallel threads;
//! a `set_var` there is unsound and globally visible — #3475 / #2127).
//! That leaves exactly one thing unproven: that the public entry points
//! resolve the posture from the env at all rather than hard-coding
//! `allow`. This file proves it, and it is deliberately ONE test in its
//! OWN test binary — a whole process to itself, so the env mutation has
//! no concurrent reader to victimise.
//!
//! Absence and presence are asserted on the same sink in the same body:
//! `deny` produces no provider AND a signed refusal row; the compiled
//! default produces a provider AND no row.

use std::path::Path;

use ai_memory::config::AppConfig;
use ai_memory::decision_boot::{DecisionProviderState, build_decision_provider};

const ENV_EGRESS: &str = "AI_MEMORY_INFERENCE_EGRESS";

fn remote_cfg() -> AppConfig {
    toml::from_str(
        "schema_version = 2\ntier = \"autonomous\"\n\n\
         [decision]\nprovider = \"openai-compatible\"\n\
         model = \"vendor/decider-1\"\n\
         base_url = \"https://decide.internal.example.net/v1\"\n",
    )
    .expect("corpus parses")
}

fn refusal_rows(db: &Path) -> i64 {
    if !db.exists() {
        return 0;
    }
    let conn = ai_memory::db::open(db).expect("open db for post-hoc assertion");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [ai_memory::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
        |r| r.get(0),
    )
    .expect("count signed_events rows")
}

#[test]
fn the_public_chokepoint_reads_the_egress_posture_from_the_environment_3806() {
    let root = std::env::current_dir()
        .expect("cwd")
        .join(".local-runs")
        .join("issue-3806-w1b-env");
    std::fs::create_dir_all(&root).ok();
    let holder = tempfile::Builder::new()
        .prefix("env-")
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");

    // --- ABSENCE: `deny` in the environment refuses the remote endpoint
    // and audits it.
    let denied = holder.path().join("denied.db");
    // The store every surface already holds when it reaches the
    // chokepoint; the decision lane appends to it and never creates or
    // migrates one itself (#3806 R8).
    drop(ai_memory::db::open(&denied).expect("seed the store"));
    // SAFETY: this test binary is a process of its own and contains
    // exactly one test, so there is no concurrent reader or writer of
    // the process environment.
    unsafe { std::env::set_var(ENV_EGRESS, "deny") };
    let outcome = build_decision_provider(&remote_cfg(), &denied);
    assert_eq!(
        outcome.state(),
        DecisionProviderState::RefusedByEgress,
        "the PUBLIC chokepoint must honour {ENV_EGRESS}=deny"
    );
    assert!(outcome.handle().is_none());
    assert_eq!(refusal_rows(&denied), 1);

    // A handle built earlier would also be refused per call — but under
    // `deny` no handle exists, which is the stronger property.

    // --- PRESENCE: with the knob unset (compiled default `allow`) the
    // same config constructs, and its per-call hook permits.
    let allowed = holder.path().join("allowed.db");
    // SAFETY: as above.
    unsafe { std::env::remove_var(ENV_EGRESS) };
    let outcome = build_decision_provider(&remote_cfg(), &allowed);
    assert_eq!(
        outcome.state(),
        DecisionProviderState::Constructed,
        "the compiled default posture must still construct (byte-identical legacy)"
    );
    let handle = outcome.handle().expect("allow constructs");
    assert!(
        handle.egress().check_outbound().is_ok(),
        "the PUBLIC per-call hook must permit under the default posture"
    );
    assert_eq!(refusal_rows(&allowed), 0);

    // --- And the per-call hook follows a posture tightened AFTER boot,
    // on that very handle: the hook reads the env, not a boot snapshot.
    // SAFETY: as above.
    unsafe { std::env::set_var(ENV_EGRESS, "loopback-only") };
    let refused = handle
        .egress()
        .check_outbound()
        .expect_err("a posture tightened after boot must refuse the call");
    assert_eq!(
        refused.abstain_reason(),
        ai_memory::decision::AbstainReason::EgressRefused
    );
    assert_eq!(refused.target(), "https://decide.internal.example.net/v1");

    // Leave the environment as we found it.
    // SAFETY: as above.
    unsafe { std::env::remove_var(ENV_EGRESS) };
}
