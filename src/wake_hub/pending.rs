// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coalesced offline state for the `wake-hub` (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! # Why a set and not a queue
//!
//! The rejected draft queued frames for an offline peer and dropped the oldest
//! when the ring filled. On a payload-carrying protocol that is silent data
//! loss, which the North Star forbids outright. On a wake-only protocol it is
//! merely wasteful: N wakes about the same inbox row are one fact, and the
//! durable record is the inbox row itself.
//!
//! So offline state is a COALESCED SET, never a ring:
//!
//! * `count` — how many wakes arrived (saturating; a hint, not an accounting
//!   record).
//! * `ids` — the distinct inbox-row ids, bounded per agent.
//! * `lagged` — raised the moment `ids` stops being complete. A client that
//!   sees `lagged` MUST do a catch-up inbox read instead of trusting the id
//!   set. This is the same contract the `approvals_sse` bus already uses for
//!   its `Lagged` event, so clients see one behaviour across both lanes.
//!
//! # Why entries exist only for agents that have authenticated
//!
//! A pending entry is created ONLY for an agent that has completed a hello
//! since hub start ([`PendingStore::note_known`]). Without that rule, any
//! authenticated peer could mint unbounded map entries just by addressing
//! wakes at ids it invented — an amplification the byte caps would not see
//! because each entry is individually tiny. The known-agent set is itself
//! capped, so the whole structure is bounded by
//! `max_agents * (id_bytes + max_ids * id_bytes)` and nothing a peer sends can
//! grow it past that.

use std::collections::HashMap;
use std::collections::HashSet;

use super::limits::MAX_ID_BYTES;

/// One offline agent's coalesced wake state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingSet {
    count: u64,
    ids: Vec<String>,
    lagged: bool,
}

impl PendingSet {
    /// Total wakes coalesced into this set. Saturating: a hint that overflowed
    /// `u64` is still "a lot", and saturating is what keeps it monotonic.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Distinct inbox-row ids retained.
    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Has the set stopped retaining ids? A `true` here obliges the client to
    /// do a catch-up read.
    #[must_use]
    pub const fn lagged(&self) -> bool {
        self.lagged
    }

    /// Is there anything to tell the agent about?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Record one wake. `max_ids` bounds the retained id set; past it the
    /// count keeps rising and `lagged` is raised instead of the set growing.
    fn record(&mut self, inbox_row_id: &str, max_ids: usize) {
        self.count = self.count.saturating_add(1);
        if inbox_row_id.is_empty() {
            // A wake with no row id still counts, but there is nothing to
            // coalesce on — treat it as a lagging hint so the client reads.
            self.lagged = true;
            return;
        }
        if self.ids.iter().any(|existing| existing == inbox_row_id) {
            return;
        }
        if self.ids.len() >= max_ids || inbox_row_id.len() > MAX_ID_BYTES {
            self.lagged = true;
            return;
        }
        self.ids.push(inbox_row_id.to_owned());
    }
}

/// Bounded table of coalesced offline state, keyed by agent id.
#[derive(Debug)]
pub struct PendingStore {
    max_agents: usize,
    max_ids: usize,
    known: HashSet<String>,
    sets: HashMap<String, PendingSet>,
    /// Wakes discarded because the recipient was offline AND unknown.
    dropped_unknown: u64,
    /// Agents refused a known-agent slot because the table was full.
    refused_known_slots: u64,
}

impl PendingStore {
    /// Build an empty store.
    #[must_use]
    pub fn new(max_agents: usize, max_ids: usize) -> Self {
        Self {
            max_agents,
            max_ids,
            known: HashSet::new(),
            sets: HashMap::new(),
            dropped_unknown: 0,
            refused_known_slots: 0,
        }
    }

    /// Mark an agent as known, on a successful hello. Returns `false` when the
    /// known-agent table is full: the agent still gets a live session, it just
    /// gets no offline coalescing — degrade, never refuse the session and never
    /// grow past the bound.
    pub fn note_known(&mut self, agent_id: &str) -> bool {
        if self.known.contains(agent_id) {
            return true;
        }
        if self.known.len() >= self.max_agents {
            self.refused_known_slots = self.refused_known_slots.saturating_add(1);
            return false;
        }
        self.known.insert(agent_id.to_owned());
        true
    }

    /// Coalesce one wake for an offline agent. Returns `true` when it was
    /// retained, `false` when the agent is unknown and the hint was dropped.
    pub fn record(&mut self, agent_id: &str, inbox_row_id: &str) -> bool {
        if !self.known.contains(agent_id) {
            self.dropped_unknown = self.dropped_unknown.saturating_add(1);
            return false;
        }
        self.sets
            .entry(agent_id.to_owned())
            .or_default()
            .record(inbox_row_id, self.max_ids);
        true
    }

    /// Take and clear an agent's pending state, on reconnect.
    pub fn take(&mut self, agent_id: &str) -> PendingSet {
        self.sets.remove(agent_id).unwrap_or_default()
    }

    /// Is this agent known to the hub?
    #[must_use]
    pub fn is_known(&self, agent_id: &str) -> bool {
        self.known.contains(agent_id)
    }

    /// Number of agents currently holding pending state.
    #[must_use]
    pub fn tracked_agents(&self) -> usize {
        self.sets.len()
    }

    /// Wakes dropped because the recipient was offline and unknown.
    #[must_use]
    pub const fn dropped_unknown(&self) -> u64 {
        self.dropped_unknown
    }

    /// Known-agent slots refused because the table was at its cap.
    #[must_use]
    pub const fn refused_known_slots(&self) -> u64 {
        self.refused_known_slots
    }

    /// Forget an agent entirely, on a signed `depart`.
    pub fn forget(&mut self, agent_id: &str) {
        self.known.remove(agent_id);
        self.sets.remove(agent_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PendingStore {
        let mut s = PendingStore::new(4, 3);
        assert!(s.note_known("a"));
        s
    }

    #[test]
    fn wakes_for_the_same_row_coalesce_to_one_id() {
        let mut s = store();
        for _ in 0..10 {
            assert!(s.record("a", "row-1"));
        }
        let p = s.take("a");
        assert_eq!(
            p.count(),
            10,
            "the count is the hint, and it keeps counting"
        );
        assert_eq!(p.ids(), ["row-1"], "the id set coalesces");
        assert!(!p.lagged());
    }

    #[test]
    fn the_id_set_is_bounded_and_raises_lagged_instead_of_growing() {
        let mut s = store();
        for i in 0..10 {
            assert!(s.record("a", &format!("row-{i}")));
        }
        let p = s.take("a");
        assert_eq!(p.count(), 10);
        assert_eq!(p.ids().len(), 3, "bounded at max_ids");
        assert!(
            p.lagged(),
            "an incomplete id set MUST be advertised so the client does a catch-up read"
        );
    }

    #[test]
    fn taking_clears_the_set() {
        let mut s = store();
        assert!(s.record("a", "row-1"));
        assert!(!s.take("a").is_empty());
        assert!(s.take("a").is_empty(), "a second take must be empty");
    }

    #[test]
    fn an_unknown_recipient_cannot_mint_an_entry() {
        let mut s = store();
        assert!(
            !s.record("never-said-hello", "row-1"),
            "a forged `to` must not create pending state"
        );
        assert_eq!(s.tracked_agents(), 0);
        assert_eq!(s.dropped_unknown(), 1);
    }

    #[test]
    fn the_known_agent_table_is_capped() {
        let mut s = PendingStore::new(2, 3);
        assert!(s.note_known("a"));
        assert!(s.note_known("b"));
        assert!(!s.note_known("c"), "past the cap the slot is refused");
        assert!(s.note_known("a"), "an already-known agent is idempotent");
        assert_eq!(s.refused_known_slots(), 1);
        assert!(!s.is_known("c"));
    }

    #[test]
    fn an_over_long_row_id_lags_instead_of_being_stored() {
        let mut s = store();
        let long = "r".repeat(MAX_ID_BYTES + 1);
        assert!(s.record("a", &long));
        let p = s.take("a");
        assert!(p.ids().is_empty());
        assert!(p.lagged());
        assert_eq!(p.count(), 1);
    }

    #[test]
    fn an_empty_row_id_counts_but_lags() {
        let mut s = store();
        assert!(s.record("a", ""));
        let p = s.take("a");
        assert_eq!(p.count(), 1);
        assert!(p.ids().is_empty());
        assert!(p.lagged());
    }

    #[test]
    fn depart_forgets_the_agent_entirely() {
        let mut s = store();
        assert!(s.record("a", "row-1"));
        s.forget("a");
        assert!(!s.is_known("a"));
        assert!(s.take("a").is_empty());
        assert!(
            !s.record("a", "row-2"),
            "a departed agent is no longer known"
        );
    }
}
