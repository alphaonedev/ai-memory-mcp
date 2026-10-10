// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7030 campaign X — data-driven fault input builder.
//!
//! Every campaign-X operation is ONE `MemoryStore` call whose row loop lives
//! inside the adapter, so a delegating fault wrapper can never reach row `k`.
//! Instead row `k` of the INPUT is made to fail identically on both backends:
//! [`poison_row`] returns a [`Poison`] whose builder methods render the same
//! deterministic inputs (fixed ids, titles and timestamps) for either store.

#![allow(dead_code)]

use ai_memory::models::{Memory, Tier};

/// Fixed RFC3339 stamp so both backends store byte-identical timestamps.
pub const STAMP: &str = "2026-10-10T00:00:00Z";
/// The agent that authors every healthy row.
pub const CALLER: &str = "ai:parity-caller";
/// The agent that owns the hidden holder row.
pub const OWNER: &str = "ai:parity-owner";

/// How row `k` is made to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoisonKind {
    /// Row `k`'s `(title, namespace)` slot is held by a QUARANTINED row of
    /// another agent (hidden on the lifecycle axis for every viewer).
    HiddenHolder,
    /// Row `k`'s `(title, namespace)` slot is held by another agent's
    /// `scope=private` row (hidden on the read-visibility axis only).
    PrivateHolder,
    /// Consolidation source `k` does not exist.
    MissingSource,
    /// Consolidation source `k` carries a stale expected version.
    StaleVersion,
}

/// A poisoned row: position plus failure kind. Pure data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poison<K = PoisonKind> {
    pub k: usize,
    pub kind: K,
}

/// Build the poison for row `k` of the input. X3-X8 define their own kind enum
/// and per-operation builders in their cell; they need not extend `PoisonKind`
/// or edit the existing holder/consolidation match arms.
#[must_use]
pub fn poison_row<K>(k: usize, kind: K) -> Poison<K> {
    Poison { k, kind }
}

/// Deterministic id of healthy row `i`.
#[must_use]
pub fn row_id(prefix: &str, i: usize) -> String {
    format!("{prefix}-row-{i:02}")
}

/// A deterministic, healthy memory.
#[must_use]
pub fn memory(id: &str, title: &str, ns: &str, agent: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("parity body for {title}"),
        priority: 5,
        confidence: 0.9,
        source: "parity".to_string(),
        created_at: STAMP.to_string(),
        updated_at: STAMP.to_string(),
        metadata: serde_json::json!({ "agent_id": agent }),
        ..Memory::default()
    }
}

impl Poison {
    /// Title of healthy row `i`.
    #[must_use]
    pub fn title(prefix: &str, i: usize) -> String {
        format!("{prefix}-title-{i:02}")
    }

    /// The pre-fault row that arms a holder poison (empty for kinds that need
    /// no holder). A quarantined holder additionally needs
    /// [`Self::quarantine_sql`] applied by the cell (the state is system-only).
    #[must_use]
    pub fn holder_seed(&self, prefix: &str, ns: &str) -> Vec<Memory> {
        match self.kind {
            PoisonKind::HiddenHolder | PoisonKind::PrivateHolder => {
                let mut h = memory(
                    &format!("{prefix}-holder"),
                    &Self::title(prefix, self.k),
                    ns,
                    OWNER,
                );
                if self.kind == PoisonKind::PrivateHolder {
                    h.metadata = serde_json::json!({ "agent_id": OWNER, "scope": "private" });
                }
                vec![h]
            }
            PoisonKind::MissingSource | PoisonKind::StaleVersion => Vec::new(),
        }
    }

    /// Raw SQL that quarantines the holder (`None` when the kind needs none).
    #[must_use]
    pub fn quarantine_sql(&self, prefix: &str) -> Option<String> {
        (self.kind == PoisonKind::HiddenHolder).then(|| {
            format!(
                "UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = '{prefix}-holder'"
            )
        })
    }

    /// `n` healthy rows; when `poisoned`, row `k` claims the holder's slot
    /// under a fresh id (so only the slot admission can refuse it).
    #[must_use]
    pub fn batch_rows(&self, prefix: &str, ns: &str, n: usize, poisoned: bool) -> Vec<Memory> {
        (0..n)
            .map(|i| {
                let title = Self::title(prefix, i);
                memory(&row_id(prefix, i), &title, ns, CALLER)
            })
            .enumerate()
            .map(|(i, m)| {
                if poisoned && i == self.k {
                    // title already equals the holder's title (same index).
                    m
                } else if !poisoned && i == self.k {
                    // healthy retry: move row k off the holder's slot.
                    let mut m = m;
                    m.title = format!("{prefix}-free-{i:02}");
                    m
                } else {
                    m
                }
            })
            .collect()
    }

    /// Consolidation inputs for sources `ids`/`versions` with source `k`
    /// poisoned per kind.
    #[must_use]
    pub fn consolidate_inputs(&self, ids: &[String], versions: &[i64]) -> (Vec<String>, Vec<i64>) {
        let mut ids = ids.to_vec();
        let mut versions = versions.to_vec();
        match self.kind {
            PoisonKind::MissingSource => ids[self.k] = format!("{}-absent", ids[self.k]),
            PoisonKind::StaleVersion => versions[self.k] += 1,
            PoisonKind::HiddenHolder | PoisonKind::PrivateHolder => {}
        }
        (ids, versions)
    }
}
