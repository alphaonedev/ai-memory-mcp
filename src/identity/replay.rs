// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! H5 (v0.7.0 round-2) — Ed25519 verify-link replay protection.
//!
//! `POST /api/v1/links/verify` accepts the *same* `(link_id, signature)`
//! pair on every call by construction — Ed25519 signatures are
//! re-verifiable in perpetuity, that's the whole point of the
//! algorithm. The replay window only appears when an operator wires
//! the verify endpoint into a higher-level protocol (proof-of-claim
//! workflow, federation handshake, etc.) where the verify call itself
//! is an authentication primitive: the attacker captures a single
//! successful `verify_link` request and replays it indefinitely.
//!
//! The mitigation is straightforward: every verify request carries a
//! caller-supplied `verification_nonce` (UUID v4 expected — we don't
//! enforce the format, only uniqueness). Hash
//! `(link_id, signature, nonce)` into a 32-byte SHA-256 fingerprint
//! and check against a bounded in-memory LRU. First-time fingerprints
//! get cached and the verify proceeds; repeats produce 409 Conflict.
//!
//! # Memory bound (partitioned — #2032 LM3, 5-agent vote `4d3ea1c5`)
//!
//! The cache is a two-level partitioned structure identical in shape to
//! [`FederationNonceCache`]: an outer `Mutex<HashMap<caller_id, slot>>`
//! where each slot is a per-caller `HashSet` + FIFO `VecDeque` capped at
//! [`VERIFY_REPLAY_CAPACITY_PER_CALLER`] (10 000) fingerprints, and an outer
//! LRU that bounds the number of distinct caller partitions to
//! [`VERIFY_REPLAY_MAX_CALLERS`] (1024), evicting the least-recently-touched
//! caller when a new caller pushes past the ceiling. Worst-case resident
//! memory is ~320 KB/caller × 1024 ≈ 320 MB, the same envelope
//! `FederationNonceCache` already accepts.
//!
//! Pre-#2032 the cache was ONE global 100 000-entry FIFO shared across every
//! caller, so any caller submitting 100 000+ unique fingerprints could evict
//! a *victim's* fingerprint and re-open the victim's replay window (the
//! "eviction-flush attack" this doc used to concede). Partitioning by caller
//! closes that: one caller can now only evict its OWN fingerprints.
//!
//! # Threat model
//!
//! The cache is a defense **within a single daemon process**. Across
//! restarts, the cache is empty — a replay attacker who waits past
//! the restart wins. Cross-process clustering (multiple daemons
//! behind a load balancer) is also out of scope: each replica has its
//! own cache. Either limitation is acceptable because:
//!
//! 1. The verify endpoint is GET-equivalent semantically (no
//!    persistent state changes), and operators wiring it into an
//!    auth flow already need to layer their own freshness checks on
//!    top — the nonce check raises the cost of trivial replay
//!    without claiming to be a complete authentication primitive.
//! 2. A Redis or DB-backed cache would be appropriate for a true
//!    distributed deployment; disk persistence for THIS cache is a
//!    tracked follow-up (deferred — the federation nonce cache's #1255
//!    persistence path is the precedent to mirror).

use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

/// The tracing target of every replay-cache log line in this module.
const REPLAY_LOG_TARGET: &str = "ai_memory::identity::replay";

/// #2032 LM3 (class-a, 5-agent vote `4d3ea1c5`) — per-CALLER FIFO bound for
/// the replay-protection cache. Mirrors [`FEDERATION_NONCE_CAPACITY_PER_PEER`]
/// (10 000): each caller partition holds at most this many
/// `(link_id, signature, nonce)` fingerprints before FIFO-evicting its own
/// oldest. Because the cache is now partitioned by caller, an attacker who
/// floods 10 000+ unique fingerprints only exhausts THEIR OWN slot — they can
/// no longer flush a victim's fingerprint (the pre-#2032 single-global-FIFO
/// eviction-flush attack). Was `SEEN_VERIFICATIONS_CAPACITY = 100_000` on the
/// single global cache.
pub const VERIFY_REPLAY_CAPACITY_PER_CALLER: usize = 10_000;

/// #2032 LM3 (class-a, 5-agent vote `4d3ea1c5`) — outer-HashMap LRU bound on
/// the number of distinct caller partitions. Mirrors
/// [`FEDERATION_NONCE_MAX_PEERS`] (1024): each caller slot costs ~320 KB at
/// full per-caller capacity, so the ceiling caps the worst-case footprint at
/// ~320 KB × 1024 ≈ 320 MB. When a NEW caller pushes past the ceiling the
/// least-recently-touched caller slot is evicted.
pub const VERIFY_REPLAY_MAX_CALLERS: usize = 1024;

/// #2032 LM3 — per-caller replay slot: the same O(1) `HashSet` + FIFO
/// `VecDeque` shape as [`PeerNonceSlot`], plus a monotonic `last_touch`
/// stamp so the outer LRU can pick the least-recently-touched caller to
/// evict. The two collections are kept in lockstep: `seen.insert(fp)` ↔
/// `order.push_back(fp)`, `seen.remove(&evicted)` ↔ `order.pop_front()`.
#[derive(Debug, Default)]
struct CallerReplaySlot {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    last_touch: u64,
}

/// #2032 LM3 (class-a, 5-agent vote `4d3ea1c5`) — per-caller partitioned
/// bounded FIFO cache of `(link_id, signature, nonce)` SHA-256 fingerprints,
/// structurally identical to [`FederationNonceCache`] but keyed on a CALLER
/// partition id instead of a peer id and without the (deferred) disk
/// persistence. Cheap to clone (it's behind an `Arc` in the daemon's
/// `AppState`); the inner mutex serialises every insert/lookup so the cache
/// is safe to share across handler invocations.
///
/// Partitioning by caller is the LM3 hardening: one caller can only evict its
/// OWN fingerprints, so it can no longer flush a victim's fingerprint to
/// re-open the victim's replay window.
#[derive(Debug, Default)]
pub struct ReplayCache {
    inner: Mutex<HashMap<String, CallerReplaySlot>>,
    /// Monotonic touch counter. Advances on every `record_and_check`; each
    /// caller slot stamps its `last_touch` with the value at insert/update
    /// time so the outer LRU can evict the slot with the smallest value.
    touch_counter: AtomicU64,
    /// Cumulative count of per-caller FIFO fingerprint evictions since
    /// process boot. Non-zero values mean SOME caller hit its per-caller
    /// ceiling and dropped its own oldest fingerprints — a paging signal for
    /// verify-flow load, no longer a cross-caller flush signal. Surfaced via
    /// [`Self::evictions_since_boot`].
    evictions: AtomicU64,
    /// Cumulative count of outer-LRU caller-slot evictions since boot.
    /// Non-zero means caller churn hit [`VERIFY_REPLAY_MAX_CALLERS`] and
    /// dropped an older caller's slot. Surfaced via
    /// [`Self::caller_evictions_since_boot`].
    caller_evictions: AtomicU64,
}

impl ReplayCache {
    /// Fresh empty cache at the documented per-caller capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fingerprint `(link_id, signature, nonce)` within `caller_id`'s
    /// partition and check membership. Returns [`ReplayDecision::Replay`] if
    /// the fingerprint has been seen before for THIS caller — the caller
    /// should reject the request as a replay. Returns [`ReplayDecision::Fresh`]
    /// on the first seen value AND inserts it as a side effect.
    ///
    /// `caller_id` partitions the cache (#2032 LM3): fingerprints are isolated
    /// per caller, so one caller flooding fresh fingerprints can only evict
    /// its OWN slot. The callers pass the HTTP-resolved agent id (or a fresh
    /// `anonymous:req-<uuid8>` — an anonymous partition can only evict
    /// itself). The nonce is still the per-request anti-replay token; the
    /// wire caller is responsible for producing it and for choosing whether
    /// to bypass this check when the request omits it (back-compat mode).
    pub fn record_and_check(
        &self,
        caller_id: &str,
        link_id: &str,
        signature: &[u8],
        nonce: &str,
    ) -> ReplayDecision {
        let fp = Self::fingerprint(link_id, signature, nonce);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned mutex means a prior insert panicked; we'd
            // rather degrade open (no replay protection) than crash
            // the daemon. Surface via the return enum so the caller
            // can log it.
            Err(p) => p.into_inner(),
        };
        // #2032 LM3 — bound the outer HashMap to VERIFY_REPLAY_MAX_CALLERS.
        // When the incoming caller is a NEW entry AND the map is at the
        // ceiling, evict the least-recently-touched caller (LRU) before
        // inserting. Re-touch of an existing caller is free (no eviction).
        if !guard.contains_key(caller_id) && guard.len() >= VERIFY_REPLAY_MAX_CALLERS {
            if let Some((evict_id, _)) = guard
                .iter()
                .min_by_key(|(_, s)| s.last_touch)
                .map(|(k, s)| (k.clone(), s.last_touch))
            {
                guard.remove(&evict_id);
                self.caller_evictions.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: REPLAY_LOG_TARGET,
                    evicted_caller = %evict_id,
                    "ReplayCache: at caller ceiling ({}); evicted LRU caller slot to make \
                     room (#2032 LM3). Operator-visible via caller_evictions_since_boot().",
                    VERIFY_REPLAY_MAX_CALLERS,
                );
            }
        }
        let touch = self.touch_counter.fetch_add(1, Ordering::Relaxed);
        let slot = guard.entry(caller_id.to_string()).or_default();
        slot.last_touch = touch;
        // O(1) HashSet membership check (per-caller).
        if slot.seen.contains(&fp) {
            return ReplayDecision::Replay;
        }
        if slot.order.len() >= VERIFY_REPLAY_CAPACITY_PER_CALLER {
            // Per-caller FIFO eviction: the caller's oldest fingerprint is
            // dropped to make room. Keep `seen` + `order` in lockstep.
            if let Some(evicted) = slot.order.pop_front() {
                slot.seen.remove(&evicted);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        slot.order.push_back(fp);
        slot.seen.insert(fp);
        ReplayDecision::Fresh
    }

    /// Total currently-cached fingerprints across every caller partition.
    /// Useful for tests and for a future metrics exporter.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.values().map(|s| s.order.len()).sum())
            .unwrap_or(0)
    }

    /// Whether the cache is empty. Trivial helper to satisfy clippy
    /// (`len_zero`) on the few call sites that care.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// #2032 LM3 — distinct caller partitions currently resident.
    #[must_use]
    pub fn caller_count(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// #2032 LM3 — cached fingerprints for one caller partition.
    #[must_use]
    pub fn len_for_caller(&self, caller_id: &str) -> usize {
        self.inner
            .lock()
            .map(|g| g.get(caller_id).map_or(0, |s| s.order.len()))
            .unwrap_or(0)
    }

    /// Cumulative number of per-caller FIFO fingerprint evictions since
    /// process boot. Non-zero values mean SOME caller hit its per-caller
    /// ceiling and dropped its own oldest fingerprints — a verify-flow load
    /// signal (no longer the cross-caller flush signal it was pre-#2032).
    #[must_use]
    pub fn evictions_since_boot(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// #2032 LM3 — cumulative number of outer-LRU caller-slot evictions
    /// (a new caller pushed the partition count past
    /// [`VERIFY_REPLAY_MAX_CALLERS`]). Operators page on sustained growth.
    #[must_use]
    pub fn caller_evictions_since_boot(&self) -> u64 {
        self.caller_evictions.load(Ordering::Relaxed)
    }

    /// Compute the 32-byte SHA-256 fingerprint over the three-element
    /// tuple. Public for tests; not exported via `pub mod`. The caller
    /// partition id is NOT part of the fingerprint — it is the outer
    /// HashMap key (so two different callers presenting the same tuple are
    /// both `Fresh`, which is correct: cross-caller identical tuples are
    /// not a replay of one authenticated principal's request).
    fn fingerprint(link_id: &str, signature: &[u8], nonce: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Length prefix every component so concatenation is unambiguous
        // — preempts the `("a", "bc")` vs `("ab", "c")` collision class.
        let lid = link_id.as_bytes();
        let sig = signature;
        let non = nonce.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((lid.len() as u32).to_be_bytes());
        hasher.update(lid);
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((sig.len() as u32).to_be_bytes());
        hasher.update(sig);
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((non.len() as u32).to_be_bytes());
        hasher.update(non);
        hasher.finalize().into()
    }
}

/// Result of [`ReplayCache::record_and_check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    /// First time we've seen this `(link_id, signature, nonce)` tuple
    /// in the current daemon process. The fingerprint was inserted.
    Fresh,
    /// Identical fingerprint has been seen before. Caller must reject.
    Replay,
    /// #9192 (C3) — the durable nonce store could not answer (database
    /// error, lost table, failed commit). Nothing was admitted and nothing
    /// was cached; the caller refuses with 503 `nonce_store_unavailable`
    /// (never with a replay 401, never by admitting the request). Only the
    /// federation nonce paths return it; [`ReplayCache`] never does.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every test threads a caller partition id (#2032 LM3). A single
    // caller reproduces the pre-#2032 single-partition behaviour.
    const C: &str = "caller-a";

    #[test]
    fn first_seen_returns_fresh() {
        let cache = ReplayCache::new();
        let d = cache.record_and_check(C, "link-a", b"sig", "nonce-1");
        assert_eq!(d, ReplayDecision::Fresh);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.len_for_caller(C), 1);
    }

    #[test]
    fn exact_repeat_returns_replay() {
        let cache = ReplayCache::new();
        assert_eq!(
            cache.record_and_check(C, "link-a", b"sig", "nonce-1"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.record_and_check(C, "link-a", b"sig", "nonce-1"),
            ReplayDecision::Replay
        );
        // Replay doesn't grow the cache.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn different_nonces_for_same_link_and_sig_are_fresh() {
        // Verifying the SAME link with the SAME signature but a fresh
        // nonce on each call must always succeed — the nonce is a
        // per-request anti-replay token, not a per-link state.
        let cache = ReplayCache::new();
        assert_eq!(
            cache.record_and_check(C, "link-a", b"sig", "nonce-1"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.record_and_check(C, "link-a", b"sig", "nonce-2"),
            ReplayDecision::Fresh
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn different_links_with_same_nonce_are_fresh() {
        // A nonce collision across different link_ids is benign —
        // they hash to different fingerprints. (Operators are
        // advised to use UUID v4 nonces; we don't enforce.)
        let cache = ReplayCache::new();
        assert_eq!(
            cache.record_and_check(C, "link-a", b"sig", "nonce"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.record_and_check(C, "link-b", b"sig", "nonce"),
            ReplayDecision::Fresh
        );
    }

    #[test]
    fn fifo_eviction_at_per_caller_capacity() {
        let cache = ReplayCache::new();
        // Fill one caller to its per-caller capacity.
        for i in 0..VERIFY_REPLAY_CAPACITY_PER_CALLER {
            assert_eq!(
                cache.record_and_check(C, "link", b"sig", &format!("nonce-{i}")),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(cache.len_for_caller(C), VERIFY_REPLAY_CAPACITY_PER_CALLER);
        // One more push evicts the caller's oldest entry (nonce-0).
        assert_eq!(
            cache.record_and_check(C, "link", b"sig", "nonce-new"),
            ReplayDecision::Fresh
        );
        assert_eq!(cache.len_for_caller(C), VERIFY_REPLAY_CAPACITY_PER_CALLER);
        // The evicted nonce-0 is now "unseen" again — replay
        // protection is best-effort, not unbounded.
        assert_eq!(
            cache.record_and_check(C, "link", b"sig", "nonce-0"),
            ReplayDecision::Fresh
        );
    }

    #[test]
    fn length_prefixed_fingerprint_avoids_concatenation_collision() {
        // ("ab", "c") and ("a", "bc") would have the same byte
        // concatenation if we didn't length-prefix each field.
        let fp1 = ReplayCache::fingerprint("ab", b"c", "");
        let fp2 = ReplayCache::fingerprint("a", b"bc", "");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn is_empty_starts_true() {
        let cache = ReplayCache::new();
        assert!(cache.is_empty());
        let _ = cache.record_and_check(C, "a", b"b", "c");
        assert!(!cache.is_empty());
    }

    // -----------------------------------------------------------------
    // v0.7.0 #1033 (Agent-5 #4) + #2032 LM3 regression coverage
    // -----------------------------------------------------------------

    #[test]
    fn evictions_counter_starts_at_zero() {
        // Fresh cache reports zero evictions.
        let cache = ReplayCache::new();
        assert_eq!(cache.evictions_since_boot(), 0);
        assert_eq!(cache.caller_evictions_since_boot(), 0);
        // Insert below the ceiling — no eviction.
        for i in 0..16 {
            let _ = cache.record_and_check(C, "l", b"s", &format!("n{i}"));
        }
        assert_eq!(cache.evictions_since_boot(), 0);
    }

    #[test]
    fn evictions_counter_bumps_on_per_caller_capacity_overflow() {
        // Drive one caller's insertions to per-caller capacity + N and
        // assert the eviction counter sees exactly N bumps. Non-zero
        // values mean SOME caller hit its ceiling and dropped its own
        // oldest fingerprints (a verify-flow load signal). The FIRST
        // eviction happens when `order.len() >= CAPACITY` AND a new
        // fingerprint arrives.
        let cache = ReplayCache::new();
        for i in 0..VERIFY_REPLAY_CAPACITY_PER_CALLER {
            assert_eq!(
                cache.record_and_check(C, "l", b"s", &format!("n{i}")),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(
            cache.evictions_since_boot(),
            0,
            "no evictions at exactly capacity"
        );
        // One more push: the caller's oldest entry is evicted.
        assert_eq!(
            cache.record_and_check(C, "l", b"s", "n-new-1"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.evictions_since_boot(),
            1,
            "exactly one eviction at capacity+1"
        );
        // Another push: another eviction.
        assert_eq!(
            cache.record_and_check(C, "l", b"s", "n-new-2"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.evictions_since_boot(),
            2,
            "two evictions at capacity+2"
        );
    }

    #[test]
    fn o1_lookup_under_sustained_load() {
        // Pre-#1033 each `record_and_check` ran an O(N)
        // `VecDeque::iter().any(...)` scan. The HashSet membership
        // replacement is O(1). Pin the algorithmic contract by timing N
        // inserts and asserting the total stays well below a per-insert
        // ceiling that would FAIL if the implementation regressed to O(N).
        let cache = ReplayCache::new();
        let start = std::time::Instant::now();
        for i in 0..5_000 {
            let _ = cache.record_and_check(C, "link", b"sig", &format!("n{i}"));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "5000 record_and_check calls MUST complete in <500ms (HashSet lookup). \
             O(N) shape would take seconds; got {elapsed:?}"
        );
    }

    // -----------------------------------------------------------------
    // #2032 LM3 (class-a, 5-agent vote `4d3ea1c5`) — partition hardening.
    // Ported from `FederationNonceCache`'s outer-LRU test + the NEW
    // cross-caller isolation invariant.
    // -----------------------------------------------------------------

    #[test]
    fn outer_lru_evicts_least_recently_touched() {
        // When the caller HashMap hits VERIFY_REPLAY_MAX_CALLERS, a NEW
        // caller's insert evicts the least-recently-touched caller slot
        // (ported from FederationNonceCache::
        // outer_lru_evicts_least_recently_touched_at_ceiling_1038).
        let cache = ReplayCache::new();
        // Fill to exactly the caller ceiling.
        for i in 0..VERIFY_REPLAY_MAX_CALLERS {
            let _ = cache.record_and_check(&format!("caller-{i}"), "l", b"s", "n");
        }
        assert_eq!(cache.caller_count(), VERIFY_REPLAY_MAX_CALLERS);
        assert_eq!(cache.caller_evictions_since_boot(), 0);
        // Touch caller-0 to make it most-recently-touched; caller-1 is
        // now the LRU candidate.
        let _ = cache.record_and_check("caller-0", "l", b"s", "n2");
        // Push a NEW caller past the ceiling — caller-1 (LRU) is evicted.
        assert_eq!(
            cache.record_and_check("caller-new", "l", b"s", "n"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.caller_count(),
            VERIFY_REPLAY_MAX_CALLERS,
            "#2032 LM3: at ceiling the outer HashMap must stay at VERIFY_REPLAY_MAX_CALLERS"
        );
        assert_eq!(
            cache.caller_evictions_since_boot(),
            1,
            "#2032 LM3: exactly one caller-slot eviction must have fired"
        );
        // caller-1 (LRU) is gone; caller-0 (recently touched) survives.
        assert_eq!(cache.len_for_caller("caller-1"), 0);
        assert!(cache.len_for_caller("caller-0") > 0);
    }

    #[test]
    fn one_caller_cannot_evict_anothers_fingerprint() {
        // The core LM3 invariant. Caller-B records a fingerprint; caller-A
        // then floods PAST its own per-caller capacity. Because the cache
        // is partitioned by caller, caller-A's flood evicts only caller-A's
        // OWN fingerprints — caller-B's earlier fingerprint is untouched and
        // still returns Replay on re-presentation. Pre-#2032 (one global
        // FIFO) caller-A's flood would have evicted caller-B's fingerprint,
        // re-opening caller-B's replay window (the eviction-flush attack).
        let cache = ReplayCache::new();

        // Caller-B's victim fingerprint.
        assert_eq!(
            cache.record_and_check("caller-b", "link-victim", b"sig", "nonce-victim"),
            ReplayDecision::Fresh
        );

        // Caller-A floods to per-caller capacity + 1 (one FIFO eviction
        // WITHIN caller-A's own slot).
        for i in 0..=VERIFY_REPLAY_CAPACITY_PER_CALLER {
            assert_eq!(
                cache.record_and_check("caller-a", "link-flood", b"sig", &format!("nonce-{i}")),
                ReplayDecision::Fresh
            );
        }
        // Caller-A DID evict — but only its own oldest fingerprint.
        assert!(
            cache.evictions_since_boot() >= 1,
            "caller-a's flood must have evicted (its OWN) fingerprints"
        );
        assert_eq!(
            cache.len_for_caller("caller-b"),
            1,
            "#2032 LM3: caller-b's partition is untouched by caller-a's flood"
        );

        // Caller-B re-presents its original tuple → STILL a Replay.
        assert_eq!(
            cache.record_and_check("caller-b", "link-victim", b"sig", "nonce-victim"),
            ReplayDecision::Replay,
            "#2032 LM3: one caller MUST NOT be able to evict another caller's fingerprint"
        );
    }
}

// ---------------------------------------------------------------------------
// #9192 (C2 + C3) — federation nonce claims: key-lifetime replay protection
// ---------------------------------------------------------------------------
//
// Ruling R (PR #9187 review r1, 3-agent vote 71472661; wire envelope #9234):
// the signed federation nonce carries no time, so the replay window is the
// lifetime of the signing key and an accepted nonce is NEVER forgotten. The
// authoritative record is one row per accepted `(key_fp, nonce_fp)` pair in the
// store's `federation_nonce_claims` table (schema v103). Its PRIMARY KEY is the
// atomic arbiter: ONE `INSERT ... ON CONFLICT DO NOTHING` decides — one row
// inserted means this request claimed the nonce, zero rows means some earlier
// request (on any daemon over the store) already did, and an error means the
// store could not answer. Nothing prunes, deletes or selects-then-inserts.
//
// The claim is at-most-once: a request whose claim committed but whose handler
// then failed (or whose future was dropped) has burned its nonce, and the
// sender must re-sign with a fresh one. That is the safe direction.
//
// [`FederationNonceCache`] is a BOUNDED, per-process cache in front of that
// table and nothing more. Every check calls the store; the cache is filled only
// after the store has answered; eviction drops cache entries, never rows.
//
// Growth (#9192, measured at 100 000 claim rows, PK index included): sqlite
// 162 bytes per row (rowid table plus the PRIMARY KEY index, measured with
// `dbstat`), PostgreSQL 18 235 bytes per row (`pg_total_relation_size`, heap
// plus PK index). One row per accepted signed push AND per signed
// `GET /sync/since` (a catch-up poller at one GET per peer per 30 s adds about
// 2 880 rows per peer per day: about 0.47 MB sqlite, 0.68 MB PostgreSQL).

/// v0.7.0 #922 / #9192 — per-key bound of the in-process CACHE.
///
/// It bounds memory only. A nonce that falls out of the cache is still
/// refused, because every check consults the claims store (Ruling R).
pub const FEDERATION_NONCE_CAPACITY_PER_PEER: usize = 10_000;

/// v0.7.0 #922 / #9192 — number of signing-key slots the CACHE keeps before it
/// drops the least-recently-touched slot. Dropping a slot drops cache entries,
/// never claim rows.
pub const FEDERATION_NONCE_MAX_PEERS: usize = 1024;

/// #9192 item 6 — the largest `X-Memory-Nonce` (or per-op transition nonce,
/// base64) a receiver accepts. Outbound peers send a hyphenated UUID (36 bytes)
/// and a transition nonce is 16-32 random bytes (24-44 base64 bytes); 256 is
/// several times the largest legitimate form and keeps a hostile peer from
/// making the receiver hash and store an arbitrarily large header. An oversize
/// nonce is refused with 401 BEFORE any claim, so it adds no row.
pub const FEDERATION_NONCE_MAX_BYTES: usize = 256;

/// #9192 item 1 — domain separator of the fingerprint of a verifying key.
const NONCE_KEY_DOMAIN: &[u8] = b"ai-memory/federation-nonce-key/v1\0";

/// #9192 item 1 — domain separator of the namespace of a nonce whose request
/// was NOT signature-verified (permissive `AI_MEMORY_FED_REQUIRE_SIG=0`). It
/// cannot collide with a key namespace (different domain, same hash).
const NONCE_UNVERIFIED_PEER_DOMAIN: &[u8] = b"ai-memory/federation-nonce-unverified-peer/v1\0";

/// #9192 — the read-only lookup in the legacy v51 `federation_nonce_cache`
/// table: a nonce a pre-v103 receiver accepted is still a replay. That table
/// is never written, pruned or deleted from any more.
const SQL_LEGACY_NONCE_LOOKUP: &str =
    "SELECT 1 FROM federation_nonce_cache WHERE peer_id = ?1 AND fingerprint = ?2";

/// #9192 — the one statement that decides a sqlite claim (PK is the arbiter).
const SQL_CLAIM_NONCE: &str = "INSERT INTO federation_nonce_claims \
     (key_fp, nonce_fp, accepted_at) VALUES (?1, ?2, ?3) \
     ON CONFLICT (key_fp, nonce_fp) DO NOTHING";

/// #9192 — why a nonce cannot be turned into a claim key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceKeyError {
    /// The nonce is empty.
    NonceEmpty,
    /// The nonce is longer than [`FEDERATION_NONCE_MAX_BYTES`].
    NonceTooLong {
        /// The refused nonce length in bytes.
        len: usize,
    },
    /// The peer id does not fit the length prefix (over 4 GiB).
    PeerIdTooLong,
}

impl std::fmt::Display for NonceKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonceEmpty => f.write_str("federation nonce is empty"),
            Self::NonceTooLong { len } => write!(
                f,
                "federation nonce is {len} bytes, over the {FEDERATION_NONCE_MAX_BYTES}-byte bound"
            ),
            Self::PeerIdTooLong => f.write_str("federation peer id does not fit a u32 length"),
        }
    }
}

impl std::error::Error for NonceKeyError {}

/// Hash `bytes` behind its big-endian `u32` length (PERF-07: checked).
fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Option<()> {
    let len = u32::try_from(bytes.len()).ok()?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Some(())
}

/// Refuse an empty or oversize nonce before anything hashes or stores it.
///
/// # Errors
/// [`NonceKeyError::NonceEmpty`] or [`NonceKeyError::NonceTooLong`].
pub fn check_nonce_len(nonce: &str) -> Result<(), NonceKeyError> {
    match nonce.len() {
        0 => Err(NonceKeyError::NonceEmpty),
        len if len > FEDERATION_NONCE_MAX_BYTES => Err(NonceKeyError::NonceTooLong { len }),
        _ => Ok(()),
    }
}

/// #9192 item 1 — the identity of one nonce claim: the namespace (`key_fp`, the
/// fingerprint of the key that verified the request), the nonce (`nonce_fp`),
/// and the v51 legacy fingerprint looked up read-only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonceClaimKey {
    key_fp: [u8; 32],
    nonce_fp: [u8; 32],
    legacy_peer_id: String,
    legacy_fp: [u8; 32],
}

impl NonceClaimKey {
    /// The claim key of `nonce` on a request whose signature VERIFIED against
    /// `verifying_key` (the raw 32 Ed25519 public-key bytes). The namespace is
    /// the key, so push and GET share it, and removing then re-adding the peer
    /// with the same key keeps every earlier nonce refused. `peer_id` only
    /// selects the legacy v51 rows.
    ///
    /// # Errors
    /// See [`check_nonce_len`]; [`NonceKeyError::PeerIdTooLong`].
    pub fn for_verifying_key(
        verifying_key: &[u8; 32],
        peer_id: &str,
        nonce: &str,
    ) -> Result<Self, NonceKeyError> {
        let mut hasher = Sha256::new();
        hasher.update(NONCE_KEY_DOMAIN);
        hasher.update(verifying_key);
        Self::build(hasher.finalize().into(), peer_id, nonce)
    }

    /// The claim key of `nonce` on a request that was NOT signature-verified
    /// (the permissive posture): the namespace is the asserted peer id, under
    /// its own domain so it can never alias a key namespace.
    ///
    /// # Errors
    /// See [`check_nonce_len`]; [`NonceKeyError::PeerIdTooLong`].
    pub fn for_unverified_peer(peer_id: &str, nonce: &str) -> Result<Self, NonceKeyError> {
        let mut hasher = Sha256::new();
        hasher.update(NONCE_UNVERIFIED_PEER_DOMAIN);
        update_length_prefixed(&mut hasher, peer_id.as_bytes())
            .ok_or(NonceKeyError::PeerIdTooLong)?;
        Self::build(hasher.finalize().into(), peer_id, nonce)
    }

    fn build(key_fp: [u8; 32], peer_id: &str, nonce: &str) -> Result<Self, NonceKeyError> {
        check_nonce_len(nonce)?;
        let mut hasher = Sha256::new();
        update_length_prefixed(&mut hasher, nonce.as_bytes())
            .ok_or(NonceKeyError::NonceTooLong { len: nonce.len() })?;
        let legacy_fp = legacy_fingerprint(peer_id, nonce).ok_or(NonceKeyError::PeerIdTooLong)?;
        Ok(Self {
            key_fp,
            nonce_fp: hasher.finalize().into(),
            legacy_peer_id: peer_id.to_string(),
            legacy_fp,
        })
    }

    /// The namespace fingerprint (`federation_nonce_claims.key_fp`).
    #[must_use]
    pub fn key_fp(&self) -> &[u8; 32] {
        &self.key_fp
    }

    /// The nonce fingerprint (`federation_nonce_claims.nonce_fp`).
    #[must_use]
    pub fn nonce_fp(&self) -> &[u8; 32] {
        &self.nonce_fp
    }

    /// The peer id the legacy v51 lookup is scoped to.
    #[must_use]
    pub fn legacy_peer_id(&self) -> &str {
        &self.legacy_peer_id
    }

    /// The legacy v51 `federation_nonce_cache.fingerprint`.
    #[must_use]
    pub fn legacy_fingerprint(&self) -> &[u8; 32] {
        &self.legacy_fp
    }
}

/// The v51 fingerprint: `SHA-256(u32 BE len(peer) || peer || u32 BE len(nonce) || nonce)`.
/// Kept byte-identical so the read-only legacy lookup finds pre-v103 rows.
fn legacy_fingerprint(peer_id: &str, nonce: &str) -> Option<[u8; 32]> {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, peer_id.as_bytes())?;
    update_length_prefixed(&mut hasher, nonce.as_bytes())?;
    Some(hasher.finalize().into())
}

/// #9192 item 2 — what the claims store answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceClaim {
    /// This call inserted the row: the nonce was never accepted before.
    Claimed,
    /// The row (or a legacy v51 row) already exists: a replay.
    AlreadyClaimed,
}

/// #9192 — the sqlite claim: the read-only legacy lookup, then the one
/// deciding `INSERT ... ON CONFLICT DO NOTHING` (one row = claimed). Shared by
/// the daemon's own connection and [`crate::store::MemoryStore::federation_nonce_claim`]
/// on the sqlite adapter, so the backend has one decision path.
///
/// # Errors
/// Propagates the `rusqlite` error; the caller maps it to
/// [`ReplayDecision::Unavailable`] (503), never to a decision.
pub(crate) fn claim_nonce_sqlite(
    conn: &rusqlite::Connection,
    key: &NonceClaimKey,
) -> rusqlite::Result<NonceClaim> {
    use rusqlite::OptionalExtension as _;
    let legacy: Option<i64> = conn
        .query_row(
            SQL_LEGACY_NONCE_LOOKUP,
            rusqlite::params![key.legacy_peer_id, key.legacy_fp.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if legacy.is_some() {
        return Ok(NonceClaim::AlreadyClaimed);
    }
    let inserted = conn.execute(
        SQL_CLAIM_NONCE,
        rusqlite::params![
            key.key_fp.as_slice(),
            key.nonce_fp.as_slice(),
            chrono::Utc::now().timestamp()
        ],
    )?;
    Ok(if inserted == 1 {
        NonceClaim::Claimed
    } else {
        NonceClaim::AlreadyClaimed
    })
}

/// One signing key's cached nonces (FIFO order for the per-key bound).
#[derive(Debug, Default)]
struct KeyNonceSlot {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    last_touch: u64,
}

#[derive(Debug, Default)]
struct NonceCacheState {
    slots: HashMap<[u8; 32], KeyNonceSlot>,
    touch: u64,
}

/// #9192 — the bounded per-process cache in front of the nonce claims store.
///
/// A check ALWAYS asks the store (`decision:` always call the store over a
/// cache short-circuit, because a store outage must refuse a cached nonce with
/// 503 too). The cache is filled only after the store answered `Claimed` or
/// `AlreadyClaimed`, under one lock with no `.await` (CONCURRENCY-20), so a
/// dropped future leaves no entry (CONCURRENCY-23 by construction:
/// `decision:` fill-after-answer over a provisional entry plus a drop guard).
/// A cache hit whose store answer is `Claimed` (the store lost the row, e.g.
/// a restored database) is refused as a replay.
#[derive(Debug)]
pub struct FederationNonceCache {
    /// `None` = no cache (store only).
    per_key_cap: Option<NonZeroUsize>,
    state: Mutex<NonceCacheState>,
    peer_evictions: AtomicU64,
}

impl Default for FederationNonceCache {
    fn default() -> Self {
        Self::with_capacity(FEDERATION_NONCE_CAPACITY_PER_PEER)
    }
}

impl FederationNonceCache {
    /// A cache bounded at [`FEDERATION_NONCE_CAPACITY_PER_PEER`] per key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache bounded at `per_key_cap` entries per key; `0` is valid and
    /// means no cache (every check is decided by the store alone).
    #[must_use]
    pub fn with_capacity(per_key_cap: usize) -> Self {
        Self {
            per_key_cap: NonZeroUsize::new(per_key_cap),
            state: Mutex::new(NonceCacheState::default()),
            peer_evictions: AtomicU64::new(0),
        }
    }

    /// Decide `key` through a sqlite connection the caller already holds (the
    /// sqlite federation paths hold the daemon connection). Synchronous: no
    /// `.await` exists between the claim and the cache fill.
    #[must_use]
    pub fn check_with_conn(
        &self,
        conn: &rusqlite::Connection,
        key: &NonceClaimKey,
    ) -> ReplayDecision {
        let answer = claim_nonce_sqlite(conn, key)
            .inspect_err(|e| log_store_unavailable(key, e))
            .ok();
        self.settle(key, answer)
    }

    /// Decide `key` through the SAL store (the PostgreSQL federation paths).
    /// Cancel-safe: the cache is touched only after the store answered.
    #[cfg(feature = "sal")]
    pub async fn check_store(
        &self,
        store: &dyn crate::store::MemoryStore,
        key: &NonceClaimKey,
    ) -> ReplayDecision {
        let answer = store
            .federation_nonce_claim(key)
            .await
            .inspect_err(|e| log_store_unavailable(key, e))
            .ok();
        self.settle(key, answer)
    }

    /// Fold the store's answer (`None` = it could not answer) into a decision
    /// and, only on an answer, the cache.
    fn settle(&self, key: &NonceClaimKey, answer: Option<NonceClaim>) -> ReplayDecision {
        let Some(answer) = answer else {
            crate::metrics::inc_federation_nonce_store_unavailable();
            return ReplayDecision::Unavailable;
        };
        let Some(cap) = self.per_key_cap else {
            return match answer {
                NonceClaim::Claimed => ReplayDecision::Fresh,
                NonceClaim::AlreadyClaimed => ReplayDecision::Replay,
            };
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hit = state
            .slots
            .get(&key.key_fp)
            .is_some_and(|slot| slot.seen.contains(&key.nonce_fp));
        let decision = match (answer, hit) {
            (NonceClaim::Claimed, false) => ReplayDecision::Fresh,
            (NonceClaim::Claimed, true) | (NonceClaim::AlreadyClaimed, _) => ReplayDecision::Replay,
        };
        if !hit {
            self.fill(&mut state, key, cap);
        }
        decision
    }

    /// Insert `key` into its slot, evicting CACHE entries only.
    fn fill(&self, state: &mut NonceCacheState, key: &NonceClaimKey, cap: NonZeroUsize) {
        state.touch = state.touch.saturating_add(1);
        let touch = state.touch;
        if !state.slots.contains_key(&key.key_fp) && state.slots.len() >= FEDERATION_NONCE_MAX_PEERS
        {
            let coldest = state
                .slots
                .iter()
                .min_by_key(|(_, slot)| slot.last_touch)
                .map(|(fp, _)| *fp);
            if let Some(coldest) = coldest {
                state.slots.remove(&coldest);
                self.peer_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        let slot = state.slots.entry(key.key_fp).or_default();
        slot.last_touch = touch;
        if slot.seen.insert(key.nonce_fp) {
            slot.order.push_back(key.nonce_fp);
        }
        while slot.order.len() > cap.get() {
            if let Some(oldest) = slot.order.pop_front() {
                slot.seen.remove(&oldest);
            }
        }
    }

    /// Whether `key` is in the CACHE (diagnostics and tests; never a decision).
    #[must_use]
    pub fn is_cached(&self, key: &NonceClaimKey) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .get(&key.key_fp)
            .is_some_and(|slot| slot.seen.contains(&key.nonce_fp))
    }

    /// Number of key slots in the cache.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .len()
    }

    /// Cached nonces of the key whose fingerprint is `key_fp`.
    #[must_use]
    pub fn len_for_key(&self, key_fp: &[u8; 32]) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots
            .get(key_fp)
            .map_or(0, |slot| slot.order.len())
    }

    /// Key slots dropped from the cache since boot (never claim rows).
    #[must_use]
    pub fn peer_evictions_since_boot(&self) -> u64 {
        self.peer_evictions.load(Ordering::Relaxed)
    }

    /// The per-key cache bound (`0` = no cache).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.per_key_cap.map_or(0, NonZeroUsize::get)
    }
}

/// One WARN per claim the store could not decide (no nonce bytes logged).
fn log_store_unavailable(key: &NonceClaimKey, err: &dyn std::fmt::Display) {
    tracing::warn!(
        target: REPLAY_LOG_TARGET,
        peer_id = %key.legacy_peer_id,
        error = %err,
        "federation.nonce.store_unavailable: the nonce claims store could not answer; \
         refusing with 503 and admitting nothing (#9192)"
    );
}

#[cfg(test)]
mod federation_nonce_cache_tests {
    use super::*;

    /// Seed of every nonce these unit cells mint (#9192 item 9).
    const UNIT_SEED: &str = "nonce-9192-unit";
    /// The cache bounds every invariant cell runs over (#9192 test a).
    const CAPS: [usize; 4] = [0, 1, 3, FEDERATION_NONCE_CAPACITY_PER_PEER];
    /// Two fixed verifying keys (raw Ed25519 public-key bytes).
    const KEY_A: [u8; 32] = [0xA1; 32];
    const KEY_B: [u8; 32] = [0xB2; 32];
    /// The peer id the cells claim as.
    const PEER: &str = "ai:peer-9192-unit";
    /// The claims table (schema v103).
    const CLAIMS_TABLE: &str = "federation_nonce_claims";
    /// Racing claimants of one nonce (#9192 test d).
    const RACERS: usize = 8;
    /// The 100K-claim cell's size and wall-clock ceiling (#9192 test k). The
    /// claims share one transaction, so the ceiling bounds the algorithm, not
    /// the host disk's commit latency.
    const BULK_CLAIMS: u64 = 100_000;
    const BULK_CEILING: std::time::Duration = std::time::Duration::from_secs(300);
    /// Growth ratchet: bytes per claim row, PRIMARY KEY index included.
    const BYTES_PER_ROW_CEILING: u64 = 256;

    /// Deterministic nonce `i` of `seed` (#9192 item 9).
    fn test_nonce(seed: &str, i: u64) -> String {
        format!("{seed}-{i:016x}")
    }

    fn key(verifying_key: &[u8; 32], i: u64) -> NonceClaimKey {
        NonceClaimKey::for_verifying_key(verifying_key, PEER, &test_nonce(UNIT_SEED, i))
            .expect("claim key")
    }

    /// The `i`-th of many distinct verifying keys.
    fn nth_key(i: u64) -> [u8; 32] {
        let mut k = [0_u8; 32];
        k[..8].copy_from_slice(&i.to_be_bytes());
        k
    }

    fn scratch() -> tempfile::TempDir {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
        std::fs::create_dir_all(&root).expect("scratch root");
        tempfile::Builder::new()
            .prefix("nonce-9192-unit-")
            .tempdir_in(&root)
            .expect("scratch dir")
    }

    /// A migrated database file and one connection on it.
    fn store_conn(dir: &tempfile::TempDir) -> (std::path::PathBuf, rusqlite::Connection) {
        let path = dir.path().join("ai-memory.db");
        let conn = crate::db::open(&path).expect("db::open");
        (path, conn)
    }

    fn rows(conn: &rusqlite::Connection) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {CLAIMS_TABLE}"), [], |r| {
            r.get(0)
        })
        .expect("count claims")
    }

    fn as_u64(n: usize) -> u64 {
        u64::try_from(n).expect("usize fits u64")
    }

    /// (a) + (b) — for every cache bound (0 included): cap+1 accepted nonces,
    /// then nonce 0 is a replay; again after a restart (a fresh cache over the
    /// same store) and after more keys than [`FEDERATION_NONCE_MAX_PEERS`].
    #[test]
    fn accepted_nonce_is_refused_for_every_cap_restart_and_peer_count_9192() {
        for cap in CAPS {
            let dir = scratch();
            let (_path, conn) = store_conn(&dir);
            let cache = FederationNonceCache::with_capacity(cap);
            assert_eq!(cache.capacity(), cap, "cap {cap}: the bound is honoured");
            let accepted = as_u64(cap) + 1;
            for i in 0..accepted {
                assert_eq!(
                    cache.check_with_conn(&conn, &key(&KEY_A, i)),
                    ReplayDecision::Fresh,
                    "cap {cap}: nonce {i} is fresh"
                );
            }
            assert!(
                cache.len_for_key(key(&KEY_A, 0).key_fp()) <= cap,
                "cap {cap}: the cache stays bounded"
            );
            assert_eq!(
                cache.check_with_conn(&conn, &key(&KEY_A, 0)),
                ReplayDecision::Replay,
                "cap {cap}: nonce 0 after cap+1 accepted nonces"
            );
            let restarted = FederationNonceCache::with_capacity(cap);
            for i in [0, accepted - 1] {
                assert_eq!(
                    restarted.check_with_conn(&conn, &key(&KEY_A, i)),
                    ReplayDecision::Replay,
                    "cap {cap}: nonce {i} after a restart"
                );
            }
            if cap <= 3 {
                let peers = as_u64(FEDERATION_NONCE_MAX_PEERS) + 1;
                for p in 1..=peers {
                    let k = NonceClaimKey::for_verifying_key(&nth_key(p), PEER, "flood")
                        .expect("flood key");
                    assert_eq!(restarted.check_with_conn(&conn, &k), ReplayDecision::Fresh);
                }
                assert!(restarted.peer_count() <= FEDERATION_NONCE_MAX_PEERS);
                assert_eq!(
                    restarted.check_with_conn(&conn, &key(&KEY_A, 0)),
                    ReplayDecision::Replay,
                    "cap {cap}: nonce 0 after more keys than the slot bound"
                );
            }
            assert_eq!(
                rows(&conn),
                i64::try_from(accepted).expect("i64")
                    + if cap <= 3 {
                        i64::try_from(FEDERATION_NONCE_MAX_PEERS).expect("i64") + 1
                    } else {
                        0
                    }
            );
        }
    }

    /// (b) — a zero bound is a store-only checker, never an error.
    #[test]
    fn zero_cap_caches_nothing_and_still_refuses_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let cache = FederationNonceCache::with_capacity(0);
        assert_eq!(
            cache.check_with_conn(&conn, &key(&KEY_A, 1)),
            ReplayDecision::Fresh
        );
        assert_eq!(cache.peer_count(), 0, "cap 0 keeps no slot");
        assert!(!cache.is_cached(&key(&KEY_A, 1)));
        assert_eq!(
            cache.check_with_conn(&conn, &key(&KEY_A, 1)),
            ReplayDecision::Replay
        );
    }

    /// (c) — two handles (two daemons) over one store: whichever claims first
    /// wins, the other refuses, and the claimant still refuses its own replay.
    #[test]
    fn two_handles_over_one_store_admit_a_nonce_once_9192() {
        let dir = scratch();
        let (path, conn_a) = store_conn(&dir);
        let conn_b = crate::db::open(&path).expect("second handle");
        let (a, b) = (FederationNonceCache::new(), FederationNonceCache::new());
        for i in 0..16 {
            let (first, second) = if i % 2 == 0 {
                ((&a, &conn_a), (&b, &conn_b))
            } else {
                ((&b, &conn_b), (&a, &conn_a))
            };
            let k = key(&KEY_A, i);
            assert_eq!(first.0.check_with_conn(first.1, &k), ReplayDecision::Fresh);
            assert_eq!(
                second.0.check_with_conn(second.1, &k),
                ReplayDecision::Replay
            );
            assert_eq!(first.0.check_with_conn(first.1, &k), ReplayDecision::Replay);
        }
    }

    /// (d) — RACERS threads, each its own connection and cache, claim one
    /// nonce at once: exactly one Fresh, at cap 0 and at the default bound.
    #[test]
    fn concurrent_identical_claims_admit_exactly_one_9192() {
        for cap in [0, FEDERATION_NONCE_CAPACITY_PER_PEER] {
            let dir = scratch();
            let (path, _conn) = store_conn(&dir);
            let conns: Vec<_> = (0..RACERS)
                .map(|_| crate::db::open(&path).expect("racer handle"))
                .collect();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(RACERS));
            let handles: Vec<_> = conns
                .into_iter()
                .map(|conn| {
                    let barrier = std::sync::Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let cache = FederationNonceCache::with_capacity(cap);
                        barrier.wait();
                        cache.check_with_conn(&conn, &key(&KEY_A, 42))
                    })
                })
                .collect();
            let decisions: Vec<_> = handles
                .into_iter()
                .map(|h| h.join().expect("racer"))
                .collect();
            let fresh = decisions
                .iter()
                .filter(|d| **d == ReplayDecision::Fresh)
                .count();
            let replay = decisions
                .iter()
                .filter(|d| **d == ReplayDecision::Replay)
                .count();
            assert_eq!((fresh, replay), (1, RACERS - 1), "cap {cap}: {decisions:?}");
        }
    }

    /// (e) — the store cannot answer: a new AND an already-cached nonce are
    /// `Unavailable` (never Replay, never Fresh), the new one leaves no cache
    /// entry, the counter moves once per refusal, and nothing is written.
    #[test]
    fn store_outage_is_unavailable_for_cached_and_new_nonces_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let cache = FederationNonceCache::new();
        let cached = key(&KEY_A, 1);
        assert_eq!(cache.check_with_conn(&conn, &cached), ReplayDecision::Fresh);
        conn.execute_batch(&format!("DROP TABLE {CLAIMS_TABLE}"))
            .expect("break the store");
        let before = crate::metrics::federation_nonce_store_unavailable_count();
        let fresh = key(&KEY_A, 2);
        assert_eq!(
            cache.check_with_conn(&conn, &cached),
            ReplayDecision::Unavailable
        );
        assert_eq!(
            cache.check_with_conn(&conn, &fresh),
            ReplayDecision::Unavailable
        );
        assert!(
            !cache.is_cached(&fresh),
            "an unanswered claim caches nothing"
        );
        assert_eq!(
            crate::metrics::federation_nonce_store_unavailable_count() - before,
            2
        );
    }

    /// (e) commit-error cell — the deciding INSERT itself fails (a trigger
    /// aborts it): `Unavailable`, no row, no cache entry.
    #[test]
    fn failing_claim_insert_is_unavailable_and_writes_nothing_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        conn.execute_batch(&format!(
            "CREATE TRIGGER nonce_9192_abort BEFORE INSERT ON {CLAIMS_TABLE} \
             BEGIN SELECT RAISE(ABORT, 'forced claim failure'); END"
        ))
        .expect("arm the failure");
        let cache = FederationNonceCache::new();
        let k = key(&KEY_A, 3);
        assert_eq!(
            cache.check_with_conn(&conn, &k),
            ReplayDecision::Unavailable
        );
        assert!(!cache.is_cached(&k));
        assert_eq!(rows(&conn), 0);
        conn.execute_batch("DROP TRIGGER nonce_9192_abort")
            .expect("disarm");
        assert_eq!(
            cache.check_with_conn(&conn, &k),
            ReplayDecision::Fresh,
            "after recovery the never-admitted nonce is claimable"
        );
    }

    /// (j) — a nonce in the legacy v51 table is a replay; nothing is written
    /// to either table and the legacy row is never deleted.
    #[test]
    fn legacy_v51_row_is_a_replay_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let nonce = test_nonce(UNIT_SEED, 9);
        let k = NonceClaimKey::for_verifying_key(&KEY_A, PEER, &nonce).expect("key");
        conn.execute(
            "INSERT INTO federation_nonce_cache (peer_id, fingerprint, last_touch, inserted_at) \
             VALUES (?1, ?2, 0, '2026-01-01T00:00:00+00:00')",
            rusqlite::params![PEER, k.legacy_fingerprint().as_slice()],
        )
        .expect("seed a v51 row");
        for cap in [0, FEDERATION_NONCE_CAPACITY_PER_PEER] {
            let cache = FederationNonceCache::with_capacity(cap);
            assert_eq!(
                cache.check_with_conn(&conn, &k),
                ReplayDecision::Replay,
                "cap {cap}"
            );
        }
        assert_eq!(rows(&conn), 0);
        let legacy: i64 = conn
            .query_row("SELECT COUNT(*) FROM federation_nonce_cache", [], |r| {
                r.get(0)
            })
            .expect("legacy count");
        assert_eq!(legacy, 1, "the legacy row is read-only");
    }

    /// The legacy fingerprint stays byte-identical to the v51 formula.
    #[test]
    fn legacy_fingerprint_matches_the_v51_formula_9192() {
        let mut h = Sha256::new();
        h.update(4_u32.to_be_bytes());
        h.update(b"peer");
        h.update(5_u32.to_be_bytes());
        h.update(b"nonce");
        let want: [u8; 32] = h.finalize().into();
        let k = NonceClaimKey::for_unverified_peer("peer", "nonce").expect("key");
        assert_eq!(k.legacy_fingerprint(), &want);
    }

    /// (g) + item 1 — the namespace is the key: one key under two peer ids is
    /// one namespace; two keys are two; a verified key never aliases the
    /// unverified-peer namespace.
    #[test]
    fn namespace_is_the_verifying_key_9192() {
        let n = test_nonce(UNIT_SEED, 5);
        let a1 = NonceClaimKey::for_verifying_key(&KEY_A, "ai:one", &n).expect("a1");
        let a2 = NonceClaimKey::for_verifying_key(&KEY_A, "ai:two", &n).expect("a2");
        let b = NonceClaimKey::for_verifying_key(&KEY_B, "ai:one", &n).expect("b");
        let u = NonceClaimKey::for_unverified_peer("ai:one", &n).expect("u");
        assert_eq!(a1.key_fp(), a2.key_fp());
        assert_eq!(a1.nonce_fp(), a2.nonce_fp());
        assert_ne!(a1.key_fp(), b.key_fp());
        assert_ne!(a1.key_fp(), u.key_fp());
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let cache = FederationNonceCache::new();
        assert_eq!(cache.check_with_conn(&conn, &a1), ReplayDecision::Fresh);
        assert_eq!(
            FederationNonceCache::new().check_with_conn(&conn, &a2),
            ReplayDecision::Replay,
            "the same key re-added under another peer id"
        );
        assert_eq!(cache.check_with_conn(&conn, &b), ReplayDecision::Fresh);
    }

    /// Item 6 — the nonce bound: exactly MAX bytes is accepted, MAX+1 and an
    /// empty nonce are typed errors.
    #[test]
    fn nonce_length_bound_is_exact_9192() {
        let at = "n".repeat(FEDERATION_NONCE_MAX_BYTES);
        let over = "n".repeat(FEDERATION_NONCE_MAX_BYTES + 1);
        assert!(NonceClaimKey::for_verifying_key(&KEY_A, PEER, &at).is_ok());
        assert_eq!(
            NonceClaimKey::for_verifying_key(&KEY_A, PEER, &over),
            Err(NonceKeyError::NonceTooLong {
                len: FEDERATION_NONCE_MAX_BYTES + 1
            })
        );
        assert_eq!(
            NonceClaimKey::for_unverified_peer(PEER, ""),
            Err(NonceKeyError::NonceEmpty)
        );
        assert_eq!(
            check_nonce_len(&over),
            Err(NonceKeyError::NonceTooLong {
                len: FEDERATION_NONCE_MAX_BYTES + 1
            })
        );
    }

    /// FIFO and slot eviction drop CACHE entries only: an evicted nonce is
    /// still refused because the store still holds its row.
    #[test]
    fn cache_eviction_never_forgets_a_claim_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let cache = FederationNonceCache::with_capacity(1);
        let first = key(&KEY_A, 0);
        assert_eq!(cache.check_with_conn(&conn, &first), ReplayDecision::Fresh);
        assert_eq!(
            cache.check_with_conn(&conn, &key(&KEY_A, 1)),
            ReplayDecision::Fresh
        );
        assert!(!cache.is_cached(&first), "FIFO dropped the cache entry");
        assert_eq!(cache.check_with_conn(&conn, &first), ReplayDecision::Replay);
        let before = cache.peer_evictions_since_boot();
        for p in 1..=as_u64(FEDERATION_NONCE_MAX_PEERS) {
            let k = NonceClaimKey::for_verifying_key(&nth_key(p), PEER, "slot").expect("key");
            assert_eq!(cache.check_with_conn(&conn, &k), ReplayDecision::Fresh);
        }
        assert!(
            cache.peer_evictions_since_boot() > before,
            "a slot was dropped"
        );
        assert_eq!(cache.check_with_conn(&conn, &first), ReplayDecision::Replay);
    }

    /// A cache hit the store answers `Claimed` for (the store lost the row,
    /// e.g. a restored database) is refused, never admitted twice.
    #[test]
    fn cache_hit_with_a_lost_row_is_a_replay_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let cache = FederationNonceCache::new();
        let k = key(&KEY_A, 4);
        assert_eq!(cache.check_with_conn(&conn, &k), ReplayDecision::Fresh);
        conn.execute_batch(&format!("DELETE FROM {CLAIMS_TABLE}"))
            .expect("simulate a restore");
        assert_eq!(cache.check_with_conn(&conn, &k), ReplayDecision::Replay);
    }

    /// (k) — 100 000 distinct claims on one key stay linear: every one is
    /// fresh, one row each, under a fixed wall-clock ceiling.
    #[test]
    fn hundred_thousand_claims_stay_bounded_9192() {
        let dir = scratch();
        let (_path, conn) = store_conn(&dir);
        let cache = FederationNonceCache::new();
        let started = std::time::Instant::now();
        conn.execute_batch("BEGIN").expect("batch");
        for i in 0..BULK_CLAIMS {
            assert_eq!(
                cache.check_with_conn(&conn, &key(&KEY_A, i)),
                ReplayDecision::Fresh
            );
        }
        conn.execute_batch("COMMIT").expect("commit");
        let elapsed = started.elapsed();
        assert!(
            elapsed < BULK_CEILING,
            "{BULK_CLAIMS} claims took {elapsed:?}"
        );
        assert_eq!(rows(&conn), i64::try_from(BULK_CLAIMS).expect("i64"));
        assert_eq!(
            cache.len_for_key(key(&KEY_A, 0).key_fp()),
            FEDERATION_NONCE_CAPACITY_PER_PEER
        );
        assert_eq!(
            cache.check_with_conn(&conn, &key(&KEY_A, 0)),
            ReplayDecision::Replay
        );
        // Growth: the rowid table plus its PRIMARY KEY autoindex.
        let bytes: i64 = conn
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name = ?1 \
                 OR name = 'sqlite_autoindex_' || ?1 || '_1'",
                [CLAIMS_TABLE],
                |r| r.get(0),
            )
            .expect("dbstat");
        let per_row = u64::try_from(bytes).expect("non-negative size") / BULK_CLAIMS;
        eprintln!("#9192 sqlite growth: {bytes} bytes, {per_row} bytes/row, {elapsed:?}");
        assert!(
            per_row <= BYTES_PER_ROW_CEILING,
            "{per_row} bytes per claim row exceeds {BYTES_PER_ROW_CEILING}"
        );
    }
}
