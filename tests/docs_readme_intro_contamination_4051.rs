// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4051 (residual of #3926) — the README v1.0.0 introduction said the
//! swarm-cascade MVG is "not on Postgres" and that `Contaminated` "spreads
//! on invalidate", while the Backend parity section (correctly) lists the
//! Postgres admin rewind route and the reflection-supersedes trigger. The
//! test first checks Backend parity still states those facts. RED at
//! 57014b067.

use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn issue_4051_readme_intro_agrees_with_backend_parity() {
    let readme = read("README.md");
    let intro = readme
        .lines()
        .find(|l| l.starts_with("**v1.0.0 — current release.**"))
        .expect("README v1.0.0 introduction paragraph");
    let parity_start = readme.find("### Backend parity").expect("Backend parity");
    let parity = &readme[parity_start..];
    // Code-backed facts the Backend parity section states.
    assert!(
        parity.contains("runs on BOTH backends through `POST /api/v1/memory_swarm_rewind`"),
        "precondition: Backend parity no longer lists the PG rewind route; re-verify #4051"
    );
    assert!(
        parity.contains("neither stamps on `kg_invalidate`"),
        "precondition: Backend parity no longer names the real trigger; re-verify #4051"
    );
    assert!(
        !intro.contains("not on Postgres"),
        "#4051: README intro says the swarm-cascade MVG is not on Postgres"
    );
    assert!(
        !intro.contains("spreads on invalidate"),
        "#4051: README intro says Contaminated spreads on invalidate"
    );
    assert!(
        intro.contains("POST /api/v1/memory_swarm_rewind") && intro.contains("supersedes"),
        "#4051: README intro must name the PG rewind route and the supersedes trigger"
    );
}
