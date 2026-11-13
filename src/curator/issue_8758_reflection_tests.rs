// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8758 — the reflection pass never clusters, prompts or stamps across an
//! `(namespace, owner, scope)` partition, and a derived reflection is never
//! wider than its narrowest source. A child of `reflection_pass` so the
//! pass's private `CompactionPass` steps are reachable; the grid, the
//! independent scope oracle and the recording LLM are shared with
//! `crate::curator::issue_8758_tests`.

use super::ReflectionPass;
use crate::curator::issue_8758_tests::{
    Cell, NAMESPACES, OWNERS, PRIVATE, RecordingLlm, assert_pair_table, grid, memory, scope_of,
};
use crate::models::{Memory, MemoryKind};

fn open_store() -> (crate::store::sqlite::SqliteStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = crate::store::sqlite::SqliteStore::open(dir.path().join("t.db")).expect("open");
    (store, dir)
}

#[test]
fn issue_8758_reflection_cluster_never_crosses_owner_or_scope() {
    let (store, _dir) = open_store();
    let llm = RecordingLlm::default();
    let pass = ReflectionPass::new(&store, &llm, None, None, true);
    assert_pair_table("reflection cluster", |a, b| {
        let rows = [
            memory("a", "a", a, MemoryKind::Observation, 2),
            memory("a2", "a2", a, MemoryKind::Observation, 2),
            memory("b", "b", b, MemoryKind::Observation, 2),
        ];
        pass.cluster(&rows)
            .iter()
            .any(|c| c.iter().any(|id| id == "a") && c.iter().any(|id| id == "b"))
    });
    // The eligibility gate refuses a mixed cluster even if one is handed in.
    let mixed = [
        memory("m1", "m1", grid()[1], MemoryKind::Observation, 2),
        memory("m2", "m2", grid()[1], MemoryKind::Observation, 2),
        memory("m3", "m3", grid()[5], MemoryKind::Observation, 2),
    ];
    assert!(
        !pass.eligible(&mixed),
        "#8758: mixed-scope reflection cluster"
    );
}

#[test]
fn issue_8758_reflection_never_wider_than_its_sources() {
    let (store, _dir) = open_store();
    let llm = RecordingLlm::default();
    let pass = ReflectionPass::new(&store, &llm, None, None, true);
    for (scope, want) in [
        (None, PRIVATE),
        (Some(PRIVATE), PRIVATE),
        (Some("team"), "team"),
        (Some("org"), "org"),
        (Some("collective"), "collective"),
    ] {
        let cell = Cell {
            owner: OWNERS[0],
            scope,
            namespace: NAMESPACES[0],
        };
        let rows: Vec<Memory> = ["s1", "s2", "s3"]
            .iter()
            .map(|id| memory(id, id, cell, MemoryKind::Observation, 2))
            .collect();
        let proposal = pass.summarize(&rows).expect("summarize");
        assert_eq!(
            scope_of(&proposal),
            Some(want),
            "#8758: a reflection over {scope:?} sources must inherit their scope"
        );
    }
}
