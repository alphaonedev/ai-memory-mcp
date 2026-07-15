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
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

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
                    target: "ai_memory::identity::replay",
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
// v0.7.0 #922 — federation per-peer nonce replay cache
// ---------------------------------------------------------------------------

/// v0.7.0 #922 — per-peer LRU bound.
///
/// v0.7.0 #1061 (Agent-2 #8) — known limitation: the per-peer cap
/// is 10000 fingerprints with FIFO eviction. An enrolled peer
/// (or an attacker with a past key compromise) can submit 10001
/// fresh-nonce signed pushes to evict `nonce-0`, then re-send the
/// captured `(body, sig, nonce-0)` tuple — no longer in cache,
/// accepted as fresh. With Ed25519 sigs that never expire, the
/// replay window stays open for the lifetime of the key.
///
/// The v0.7.0 mitigations are:
///   - Per-peer partitioning (#922): an attacker can only flood
///     THEIR OWN slot, not cross-peer entries (so the threat is
///     scoped to compromised-key scenarios, not broad DoS).
///   - Outer LRU + peer ceiling (#1038): bounds the total memory
///     footprint at ~320 MB worst-case.
///   - Cache capacity bumped 10× via #1033 (10000-per-peer slot
///     size set here).
///
/// The deeper v0.8 fix (per Agent-2's recommendation) is to bind
/// nonce freshness to a strictly-monotonic peer-side counter (or
/// include a receiver clock-window) so any nonce older than the
/// highest-seen value for the peer is refused regardless of cache
/// membership. That requires a protocol change (peer-side
/// counter persistence + clock-skew handling) and is tracked as
/// a v0.8 federation hardening follow-up. For v0.7.0 the
/// flush-attack surface is documented as a KNOWN limitation
/// gated by per-peer-key compromise.
pub const FEDERATION_NONCE_CAPACITY_PER_PEER: usize = 10_000;

/// v0.7.0 #1038 (Agent-5 #5) — outer-HashMap LRU bound on the
/// `FederationNonceCache`. Each enrolled peer's slot costs
/// ~320 KB (10k × 32-byte fingerprints in both the HashSet and
/// the VecDeque); a long-lived daemon that rotates peers (operator
/// adds + removes peers in `AI_MEMORY_FED_PEER_ATTESTATION`)
/// leaves old peer-id slots resident forever pre-#1038. The
/// ceiling caps the worst-case footprint at ~320 KB × 1024 =
/// ~320 MB — well within process budget for any realistic
/// deployment (operator-scale is ~10-100 peers; we leave 10× headroom).
/// Eviction picks the least-recently-touched peer when a new peer
/// pushes past the ceiling.
pub const FEDERATION_NONCE_MAX_PEERS: usize = 1024;

/// v0.7.0 #1033 (federation parity) — same O(1) `HashSet + VecDeque`
/// shape as `ReplayCacheInner`, applied per-peer so each peer's
/// freshness check runs in O(1) instead of the pre-#1033 O(N) linear
/// scan. The per-peer partitioning (already in place pre-#1033)
/// limits cross-peer eviction so an attacker can only evict THEIR
/// OWN entries — a weaker threat than the un-partitioned
/// ReplayCache, but the perf gain matters under sustained federation
/// load.
///
/// v0.7.0 #1038 — `last_touch` tracks the monotonic counter at the
/// last `record_and_check` for this peer. The outer LRU evicts the
/// slot with the smallest `last_touch` when at the
/// `FEDERATION_NONCE_MAX_PEERS` ceiling. Using a u64 counter
/// instead of `Instant` keeps the comparison O(1) and the eviction
/// path lock-free of clock reads.
#[derive(Debug, Default)]
struct PeerNonceSlot {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    last_touch: u64,
}

/// v0.7.0 #922 — per-peer bounded FIFO cache of `(peer_id, nonce)`.
#[derive(Debug, Default)]
pub struct FederationNonceCache {
    inner: Mutex<HashMap<String, PeerNonceSlot>>,
    /// v0.7.0 #1038 — monotonic touch counter. Advances on every
    /// `record_and_check`; each peer slot stamps its `last_touch`
    /// with the value at insert/update time. The outer LRU
    /// eviction picks the slot with the smallest value.
    touch_counter: std::sync::atomic::AtomicU64,
    /// v0.7.0 #1038 — cumulative count of peer-slot evictions
    /// since boot. Non-zero values mean the outer LRU dropped a
    /// peer to make room — operator-visible via `peer_evictions_since_boot()`.
    peer_evictions: std::sync::atomic::AtomicU64,
    /// #1255 (MED, 2026-05-25) — when `Some`, every Fresh
    /// fingerprint is persisted to the `federation_nonce_cache`
    /// table in the ai-memory sqlite DB on this path AND the
    /// cache hydrates from the same table on construction. When
    /// `None` the cache is in-memory only and a daemon restart
    /// opens a fresh replay window (pre-#1255 behaviour, preserved
    /// for test harnesses and for any caller that opts out).
    db_path: Option<PathBuf>,
}

/// #1690 — prune the on-disk `federation_nonce_cache` to the newest
/// `per_peer_cap` rows per peer (deleting the rest), bounding the table
/// to the same ceiling the in-memory cache enforces. Idempotent: on an
/// already-bounded table it deletes zero rows. Extracted as a free fn so
/// it is testable with a small cap without seeding 10k rows. The window
/// `ROW_NUMBER() OVER (PARTITION BY peer_id ORDER BY last_touch DESC)`
/// keeps the most-recently-touched rows; the WITHOUT-ROWID PK
/// `(peer_id, fingerprint)` keys the delete.
///
/// # Errors
/// Propagates the underlying `rusqlite` error on SQL failure.
fn prune_nonce_cache_to_per_peer_cap(
    conn: &rusqlite::Connection,
    per_peer_cap: usize,
) -> rusqlite::Result<usize> {
    #[allow(clippy::cast_possible_wrap)]
    let cap = per_peer_cap as i64;
    conn.execute(
        "DELETE FROM federation_nonce_cache
         WHERE (peer_id, fingerprint) IN (
             SELECT peer_id, fingerprint FROM (
                 SELECT peer_id, fingerprint,
                        ROW_NUMBER() OVER (
                            PARTITION BY peer_id ORDER BY last_touch DESC
                        ) AS rn
                 FROM federation_nonce_cache
             ) WHERE rn > ?1
         )",
        rusqlite::params![cap],
    )
}

impl FederationNonceCache {
    /// Fresh empty cache. In-memory only — the cache resets on every
    /// daemon restart. Prefer [`Self::new_with_db_persistence`] in
    /// production: pre-#1255 the in-memory-only cache opened a
    /// replay window on every restart.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// #1255 (MED, 2026-05-25) — persistence-enabled constructor.
    ///
    /// Opens the ai-memory sqlite DB at `db_path` (runs migrations
    /// to ensure the `federation_nonce_cache` table is present),
    /// rehydrates the in-memory cache from the persisted rows
    /// (oldest `last_touch` first so the in-process LRU ordering
    /// matches the on-disk order), and arms the cache so every
    /// subsequent `Fresh` fingerprint is persisted to disk.
    ///
    /// Construction errors out if the DB cannot be opened or
    /// migrated — operators want loud failure here, not a silent
    /// fallback to in-memory mode that re-opens the replay window.
    ///
    /// # Errors
    ///
    /// Returns an error if the DB cannot be opened or the load
    /// query fails.
    pub fn new_with_db_persistence(db_path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let db_path = db_path.into();
        let cache = Self {
            inner: Mutex::new(HashMap::new()),
            touch_counter: AtomicU64::new(0),
            peer_evictions: AtomicU64::new(0),
            db_path: Some(db_path.clone()),
        };
        cache.hydrate_from_disk(&db_path)?;
        Ok(cache)
    }

    /// #1255 — read every persisted `(peer_id, fingerprint,
    /// last_touch)` triple from disk and seed the in-memory cache.
    /// Iterates oldest-touch first so the on-disk LRU ordering
    /// becomes the in-process FIFO ordering for the per-peer
    /// `VecDeque`s. The post-load `touch_counter` is bumped past
    /// the largest observed `last_touch` so subsequent inserts
    /// stay monotonic against the rehydrated state.
    fn hydrate_from_disk(&self, db_path: &Path) -> anyhow::Result<()> {
        // Use `crate::db::open` which runs migrations on first open.
        // This guarantees the `federation_nonce_cache` table exists
        // even on a pre-v51 DB (the v51 migration is replay-safe).
        let conn = crate::db::open(db_path)
            .map_err(|e| anyhow::anyhow!("FederationNonceCache: open ai-memory db: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT peer_id, fingerprint, last_touch
             FROM federation_nonce_cache
             ORDER BY last_touch ASC",
        )?;
        let mut max_touch: u64 = 0;
        let rows = stmt.query_map([], |row| {
            let peer_id: String = row.get(0)?;
            let fp_bytes: Vec<u8> = row.get(1)?;
            let last_touch: i64 = row.get(2)?;
            Ok((peer_id, fp_bytes, last_touch))
        })?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("FederationNonceCache: hydration mutex poisoned"))?;
        for row in rows {
            let (peer_id, fp_bytes, last_touch) = row?;
            // Coerce the 32-byte fingerprint back from the blob.
            // Rows with non-32-byte blobs are skipped + warn-logged —
            // they cannot have been produced by any v0.7.x writer,
            // so they are forensic noise we don't want to crash on.
            let fp: [u8; 32] = match fp_bytes.as_slice().try_into() {
                Ok(fp) => fp,
                Err(_) => {
                    tracing::warn!(
                        target: "ai_memory::identity::replay",
                        peer_id = %peer_id,
                        len = fp_bytes.len(),
                        "FederationNonceCache: skipping persisted row with non-32-byte \
                         fingerprint blob (forensic noise; not produced by any v0.7.x writer)",
                    );
                    continue;
                }
            };
            #[allow(clippy::cast_sign_loss)]
            let touch_u64 = last_touch.max(0) as u64;
            if touch_u64 > max_touch {
                max_touch = touch_u64;
            }
            let slot = guard.entry(peer_id).or_default();
            // Honour the per-peer cap on hydration: oldest rows are
            // dropped silently when the on-disk persistence holds
            // more rows than `FEDERATION_NONCE_CAPACITY_PER_PEER`.
            // (Shouldn't happen in practice — the persistence layer
            // mirrors the in-memory cap — but defensive on operator
            // hand-rolled DBs.)
            if slot.order.len() >= FEDERATION_NONCE_CAPACITY_PER_PEER {
                if let Some(evicted) = slot.order.pop_front() {
                    slot.seen.remove(&evicted);
                }
            }
            slot.order.push_back(fp);
            slot.seen.insert(fp);
            slot.last_touch = touch_u64;
        }
        drop(guard);
        // `rows` was consumed by the `for` loop above; dropping `stmt`
        // releases its borrow on `conn` before the prune `execute`.
        drop(stmt);

        // #1690 — repair legacy on-disk bloat from the pre-delete-on-evict
        // era. Before the eviction-prune fix, the table grew without
        // bound; delete-on-evict stops FURTHER growth but never shrinks
        // rows belonging to peers that have since gone silent, so such a
        // DB would re-scan all of them on every boot. The in-memory cap
        // above already bounds RAM (per-peer overflow is dropped on
        // load), so this one-time prune converges the DISK to the same
        // bound: keep the newest `FEDERATION_NONCE_CAPACITY_PER_PEER`
        // rows per peer, delete the rest. Idempotent — on an
        // already-bounded table it deletes zero rows. WITHOUT ROWID PK is
        // (peer_id, fingerprint), so the window prune keys on that pair.
        match prune_nonce_cache_to_per_peer_cap(&conn, FEDERATION_NONCE_CAPACITY_PER_PEER) {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                target: "ai_memory::identity::replay",
                "FederationNonceCache: pruned {n} over-cap disk row(s) on hydration \
                 (#1690 legacy-bloat repair); disk now bounded to the per-peer cap"
            ),
            Err(e) => tracing::warn!(
                target: "ai_memory::identity::replay",
                err = %e,
                "FederationNonceCache: hydration over-cap prune failed (non-fatal; in-memory \
                 cache still bounded)"
            ),
        }

        // Advance the in-process touch counter past every observed
        // last_touch so the next insert is monotonic.
        self.touch_counter
            .store(max_touch.saturating_add(1), Ordering::Relaxed);
        Ok(())
    }

    /// #1255 — persist one `(peer_id, fingerprint, last_touch)`
    /// triple to disk. Called from the Fresh arm of
    /// `record_and_check` when `db_path.is_some()`. The INSERT OR
    /// REPLACE shape keeps the row's `last_touch` in lockstep with
    /// the in-memory cache on every re-touch path (currently the
    /// `record_and_check` Fresh path only inserts; re-touch on
    /// existing fingerprints surfaces as `Replay` and skips the
    /// persistence call, which is fine — the original row remains).
    /// Persistence errors are warn-logged and swallowed: an
    /// operator-disk-full or transient db lock failure should not
    /// be a 500 on every federated push. The in-memory cap still
    /// holds, so a persistence outage degrades gracefully to
    /// pre-#1255 behaviour (replay window opens on next restart).
    fn persist_fingerprint_and_evict(
        &self,
        peer_id: &str,
        fp: &[u8; 32],
        last_touch: u64,
        evicted_fp: Option<&[u8; 32]>,
        evicted_peer: Option<&str>,
    ) {
        let Some(path) = self.db_path.as_deref() else {
            return;
        };
        // `crate::db::open` runs migrations + is cheap on a warm
        // SQLite WAL connection; the persistence rate is bounded by
        // federated-POST throughput (sub-Hz on any realistic mesh).
        let conn = match crate::db::open(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    target: "ai_memory::identity::replay",
                    peer_id = %peer_id,
                    path = %path.display(),
                    err = %e,
                    "FederationNonceCache: persist open failed; in-memory cache still holds \
                     (#1255 graceful degradation)",
                );
                return;
            }
        };
        // `i64::try_from` is safe because `touch_counter` advances
        // at most once per record_and_check; a daemon would need to
        // sustain >2^63 federated pushes/sec to overflow, which is
        // not a real shape.
        #[allow(clippy::cast_possible_wrap)]
        let last_touch_i64 = last_touch as i64;
        let now = chrono::Utc::now().to_rfc3339();
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO federation_nonce_cache
             (peer_id, fingerprint, last_touch, inserted_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![peer_id, fp.as_slice(), last_touch_i64, now],
        ) {
            tracing::warn!(
                target: "ai_memory::identity::replay",
                peer_id = %peer_id,
                err = %e,
                "FederationNonceCache: persist insert failed; in-memory cache still holds \
                 (#1255 graceful degradation)",
            );
        }
        // #1690 — delete-on-evict: prune the disk rows the in-memory LRU
        // just evicted so the table stays bounded by the same ceiling as
        // the in-memory cache. Best-effort on the SAME connection as the
        // INSERT above; a failed DELETE only leaves a dead row (the
        // in-memory cap still bounds the replay check), so it is
        // warn-logged and swallowed like the INSERT.
        if let Some(efp) = evicted_fp {
            if let Err(e) = conn.execute(
                "DELETE FROM federation_nonce_cache WHERE peer_id = ?1 AND fingerprint = ?2",
                rusqlite::params![peer_id, efp.as_slice()],
            ) {
                tracing::warn!(
                    target: "ai_memory::identity::replay",
                    peer_id = %peer_id,
                    err = %e,
                    "FederationNonceCache: evicted-fingerprint delete failed; disk row lingers \
                     (#1690 graceful degradation)",
                );
            }
        }
        if let Some(ep) = evicted_peer {
            if let Err(e) = conn.execute(
                "DELETE FROM federation_nonce_cache WHERE peer_id = ?1",
                rusqlite::params![ep],
            ) {
                tracing::warn!(
                    target: "ai_memory::identity::replay",
                    evicted_peer = %ep,
                    err = %e,
                    "FederationNonceCache: evicted-peer delete failed; disk rows linger \
                     (#1690 graceful degradation)",
                );
            }
        }
    }

    /// Check + record `(peer_id, nonce)`.
    pub fn record_and_check(&self, peer_id: &str, nonce: &str) -> ReplayDecision {
        use std::sync::atomic::Ordering;
        let fp = Self::fingerprint(peer_id, nonce);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // #1690 — capture in-memory evictions so the disk mirror is
        // pruned in lockstep (delete-on-evict). Without this the disk
        // `federation_nonce_cache` table grew unbounded: every Fresh
        // nonce INSERTs a row, but the in-memory LRU evictions (per-peer
        // FIFO + outer peer-slot LRU) never deleted the disk counterpart,
        // so a long-lived high-throughput peer accumulated millions of
        // dead rows while the in-memory cache stayed bounded. Both
        // deletes ride the SAME connection-open as the persist below
        // (see `persist_fingerprint_and_evict`), so the hot-path disk
        // I/O rate is unchanged.
        let mut evicted_peer: Option<String> = None;
        // v0.7.0 #1038 — bound the outer HashMap to
        // `FEDERATION_NONCE_MAX_PEERS`. When the incoming peer is a
        // NEW entry AND the map is at the ceiling, evict the
        // least-recently-touched peer (LRU) before inserting.
        // Skip the eviction when the peer already exists (re-touch
        // is free).
        if !guard.contains_key(peer_id) && guard.len() >= FEDERATION_NONCE_MAX_PEERS {
            // Find the smallest `last_touch` to pick the LRU peer.
            if let Some((evict_id, _)) = guard
                .iter()
                .min_by_key(|(_, s)| s.last_touch)
                .map(|(k, s)| (k.clone(), s.last_touch))
            {
                guard.remove(&evict_id);
                self.peer_evictions.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "ai_memory::identity::replay",
                    evicted_peer = %evict_id,
                    "FederationNonceCache: at peer ceiling ({}); evicted LRU peer slot to make \
                     room. Operator-visible via peer_evictions_since_boot() (#1038).",
                    FEDERATION_NONCE_MAX_PEERS,
                );
                evicted_peer = Some(evict_id);
            }
        }
        let touch = self.touch_counter.fetch_add(1, Ordering::Relaxed);
        let slot = guard.entry(peer_id.to_string()).or_default();
        slot.last_touch = touch;
        // v0.7.0 #1033 — O(1) HashSet membership replaces O(N) scan.
        if slot.seen.contains(&fp) {
            return ReplayDecision::Replay;
        }
        let mut evicted_fp: Option<[u8; 32]> = None;
        if slot.order.len() >= FEDERATION_NONCE_CAPACITY_PER_PEER {
            // Keep `seen` + `order` in lockstep on FIFO eviction.
            if let Some(evicted) = slot.order.pop_front() {
                slot.seen.remove(&evicted);
                evicted_fp = Some(evicted);
            }
        }
        slot.order.push_back(fp);
        slot.seen.insert(fp);
        // Release the inner mutex before doing disk I/O so a slow
        // SQLite WAL fsync doesn't block sibling
        // `record_and_check` calls. The persistence call itself
        // opens its own connection (no shared state).
        drop(guard);
        // #1255 — persist the new fingerprint to disk so a daemon
        // restart doesn't re-open the replay window. #1690 — and prune
        // the rows the in-memory cache just evicted so the disk mirror
        // stays bounded. Both ride one connection-open; failures are
        // warn-logged and swallowed (graceful degradation to the
        // in-memory-only pre-#1255 posture).
        self.persist_fingerprint_and_evict(
            peer_id,
            &fp,
            touch,
            evicted_fp.as_ref(),
            evicted_peer.as_deref(),
        );
        ReplayDecision::Fresh
    }

    /// v0.7.0 #1038 — cumulative number of peer-slot evictions
    /// (outer LRU). Non-zero means peer churn caused the outer
    /// HashMap to hit `FEDERATION_NONCE_MAX_PEERS` and drop an
    /// older peer's slot. Operators page on sustained growth.
    #[must_use]
    pub fn peer_evictions_since_boot(&self) -> u64 {
        self.peer_evictions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Distinct peers with at least one cached fingerprint.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Cached fingerprints for `peer_id`.
    #[must_use]
    pub fn len_for_peer(&self, peer_id: &str) -> usize {
        self.inner
            .lock()
            .map(|g| g.get(peer_id).map_or(0, |s| s.order.len()))
            .unwrap_or(0)
    }

    fn fingerprint(peer_id: &str, nonce: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let pid = peer_id.as_bytes();
        let non = nonce.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((pid.len() as u32).to_be_bytes());
        hasher.update(pid);
        #[allow(clippy::cast_possible_truncation)]
        hasher.update((non.len() as u32).to_be_bytes());
        hasher.update(non);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod federation_nonce_cache_tests {
    use super::*;

    #[test]
    fn first_seen_returns_fresh() {
        let cache = FederationNonceCache::new();
        assert_eq!(cache.record_and_check("p", "n"), ReplayDecision::Fresh);
        assert_eq!(cache.len_for_peer("p"), 1);
    }

    #[test]
    fn exact_repeat_returns_replay() {
        let cache = FederationNonceCache::new();
        assert_eq!(cache.record_and_check("p", "n"), ReplayDecision::Fresh);
        assert_eq!(cache.record_and_check("p", "n"), ReplayDecision::Replay);
        assert_eq!(cache.len_for_peer("p"), 1);
    }

    #[test]
    fn different_peers_can_use_same_nonce() {
        let cache = FederationNonceCache::new();
        assert_eq!(cache.record_and_check("a", "s"), ReplayDecision::Fresh);
        assert_eq!(cache.record_and_check("b", "s"), ReplayDecision::Fresh);
        assert_eq!(cache.peer_count(), 2);
    }

    #[test]
    fn fifo_eviction_at_per_peer_capacity() {
        let cache = FederationNonceCache::new();
        for i in 0..FEDERATION_NONCE_CAPACITY_PER_PEER {
            assert_eq!(
                cache.record_and_check("p", &format!("n-{i}")),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(cache.len_for_peer("p"), FEDERATION_NONCE_CAPACITY_PER_PEER);
        assert_eq!(cache.record_and_check("p", "n-new"), ReplayDecision::Fresh);
        assert_eq!(cache.record_and_check("p", "n-0"), ReplayDecision::Fresh);
    }

    #[test]
    fn peer_count_evictions_counter_starts_at_zero_1038() {
        // v0.7.0 #1038 — fresh cache reports zero peer-slot evictions.
        let cache = FederationNonceCache::new();
        assert_eq!(cache.peer_evictions_since_boot(), 0);
        // Insert below the peer ceiling — no eviction.
        for i in 0..32 {
            let _ = cache.record_and_check(&format!("peer-{i}"), "n");
        }
        assert_eq!(cache.peer_count(), 32);
        assert_eq!(cache.peer_evictions_since_boot(), 0);
    }

    #[test]
    fn outer_lru_evicts_least_recently_touched_at_ceiling_1038() {
        // v0.7.0 #1038 (Agent-5 #5) — when the FederationNonceCache
        // HashMap hits FEDERATION_NONCE_MAX_PEERS, a NEW peer's
        // insert evicts the least-recently-touched peer slot.
        // Pre-#1038 the HashMap was unbounded; a daemon that rotated
        // peers (operator config churn) accumulated ~320 KB per
        // ever-enrolled peer indefinitely.
        let cache = FederationNonceCache::new();
        // Fill to exactly the peer ceiling.
        for i in 0..FEDERATION_NONCE_MAX_PEERS {
            let _ = cache.record_and_check(&format!("peer-{i}"), "n");
        }
        assert_eq!(cache.peer_count(), FEDERATION_NONCE_MAX_PEERS);
        assert_eq!(cache.peer_evictions_since_boot(), 0);
        // Touch peer-0 to make it the most-recently-touched
        // (advances its last_touch); peer-1 is now the LRU
        // candidate.
        let _ = cache.record_and_check("peer-0", "n2");
        // Push a NEW peer past the ceiling — peer-1 (the LRU)
        // should be evicted.
        assert_eq!(
            cache.record_and_check("peer-new", "n"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.peer_count(),
            FEDERATION_NONCE_MAX_PEERS,
            "#1038: at ceiling the outer HashMap must stay at FEDERATION_NONCE_MAX_PEERS"
        );
        assert_eq!(
            cache.peer_evictions_since_boot(),
            1,
            "#1038: exactly one peer-slot eviction must have fired"
        );
        // peer-1 (LRU) is gone — recording for it again returns
        // Fresh (the cache forgot the prior fingerprints).
        assert_eq!(cache.len_for_peer("peer-1"), 0);
        // peer-0 (recently touched) is still present.
        assert!(cache.len_for_peer("peer-0") > 0);
    }

    #[test]
    fn re_touch_existing_peer_does_not_trigger_eviction_1038() {
        // v0.7.0 #1038 — re-touching an existing peer at the
        // ceiling MUST NOT trigger an eviction (LRU bookkeeping
        // only fires on NEW peer inserts past the ceiling).
        let cache = FederationNonceCache::new();
        for i in 0..FEDERATION_NONCE_MAX_PEERS {
            let _ = cache.record_and_check(&format!("peer-{i}"), "n");
        }
        let before = cache.peer_evictions_since_boot();
        // Re-touch every existing peer — no NEW peer inserts.
        for i in 0..FEDERATION_NONCE_MAX_PEERS {
            let _ = cache.record_and_check(&format!("peer-{i}"), &format!("n2-{i}"));
        }
        assert_eq!(
            cache.peer_evictions_since_boot(),
            before,
            "#1038: re-touching existing peers MUST NOT trigger LRU eviction"
        );
        assert_eq!(cache.peer_count(), FEDERATION_NONCE_MAX_PEERS);
    }

    /// #1255 (MED, 2026-05-25) — regression: a nonce that landed in
    /// the cache before a daemon restart must STILL be rejected as
    /// a replay after the restart. Pre-#1255 every restart opened a
    /// fresh in-memory window, so any captured `(body, sig, nonce)`
    /// tuple could be replayed once the daemon bounced.
    ///
    /// Simulates the restart by dropping the first
    /// `FederationNonceCache` and constructing a second one against
    /// the SAME `db_path`. The hydration step on the second cache
    /// reloads every persisted fingerprint, so the same `(peer_id,
    /// nonce)` MUST surface as `Replay` on the second cache.
    #[test]
    fn issue_1255_nonce_persists_across_recreated_cache() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let db_path = tmp.path().to_path_buf();

        // First cache — accept the nonce as Fresh, persisting it.
        let cache_a = FederationNonceCache::new_with_db_persistence(&db_path)
            .expect("first cache must open the DB and run v51 migration");
        assert_eq!(
            cache_a.record_and_check("peer-1255", "n-1255"),
            ReplayDecision::Fresh,
            "#1255: first observation of (peer, nonce) is Fresh"
        );
        // A second observation in the SAME process is Replay
        // (in-memory cache holds independent of disk persistence).
        assert_eq!(
            cache_a.record_and_check("peer-1255", "n-1255"),
            ReplayDecision::Replay,
            "#1255: in-process re-observation is Replay (sanity)"
        );
        drop(cache_a);

        // Second cache — simulate daemon restart against the same
        // DB. Hydration must replay the persisted fingerprint into
        // the in-memory set so the SAME (peer, nonce) is REJECTED.
        let cache_b = FederationNonceCache::new_with_db_persistence(&db_path)
            .expect("second cache must hydrate from the same DB");
        assert_eq!(
            cache_b.record_and_check("peer-1255", "n-1255"),
            ReplayDecision::Replay,
            "#1255: persistence is load-bearing — a daemon restart must NOT \
             reopen the replay window for a previously-seen nonce"
        );
        // A NEW (peer, nonce) under the second cache is Fresh — the
        // hydration didn't accidentally over-block.
        assert_eq!(
            cache_b.record_and_check("peer-1255", "n-different"),
            ReplayDecision::Fresh,
            "#1255: hydration must NOT over-block on unrelated nonces"
        );
        // The hydrated cache still tracks at least the one peer
        // from before (sanity on `len_for_peer`).
        assert!(
            cache_b.len_for_peer("peer-1255") >= 1,
            "#1255: hydrated cache must retain the persisted fingerprint count"
        );
    }

    /// #1690 — delete-on-evict keeps the disk `federation_nonce_cache`
    /// table bounded by the same ceiling as the in-memory LRU. Pre-fix
    /// the table was INSERT-only, so a long-lived high-throughput peer
    /// grew it without bound while the in-memory cache stayed capped.
    /// Drives the private persist+evict path directly (the per-peer FIFO
    /// cap is 10k and the outer cap is 1024, both too large to trigger
    /// via `record_and_check` in a unit test) and counts disk rows.
    #[test]
    fn issue_1690_eviction_prunes_disk_mirror() {
        fn disk_row_count(path: &std::path::Path) -> i64 {
            let conn = crate::db::open(path).expect("open nonce db");
            conn.query_row("SELECT COUNT(*) FROM federation_nonce_cache", [], |r| {
                r.get(0)
            })
            .expect("count rows")
        }

        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let db_path = tmp.path().to_path_buf();
        let cache = FederationNonceCache::new_with_db_persistence(&db_path)
            .expect("open + migrate nonce db");

        // Two fresh fingerprints for one peer → two disk rows.
        let fp_a = FederationNonceCache::fingerprint("peer-x", "nonce-a");
        let fp_b = FederationNonceCache::fingerprint("peer-x", "nonce-b");
        cache.persist_fingerprint_and_evict("peer-x", &fp_a, 1, None, None);
        cache.persist_fingerprint_and_evict("peer-x", &fp_b, 2, None, None);
        assert_eq!(disk_row_count(&db_path), 2, "two inserts → two rows");

        // Per-peer FIFO eviction: inserting fp_c while evicting fp_a must
        // delete fp_a's disk row → still 2 rows (fp_b + fp_c), not 3.
        let fp_c = FederationNonceCache::fingerprint("peer-x", "nonce-c");
        cache.persist_fingerprint_and_evict("peer-x", &fp_c, 3, Some(&fp_a), None);
        assert_eq!(
            disk_row_count(&db_path),
            2,
            "#1690: a per-peer FIFO eviction must delete the evicted disk row"
        );

        // Add a second peer, then an outer-LRU peer eviction of peer-x
        // must wipe ALL of peer-x's disk rows.
        let fp_y = FederationNonceCache::fingerprint("peer-y", "n");
        cache.persist_fingerprint_and_evict("peer-y", &fp_y, 4, None, None);
        assert_eq!(disk_row_count(&db_path), 3, "peer-y row added → three rows");
        let fp_z = FederationNonceCache::fingerprint("peer-z", "n");
        cache.persist_fingerprint_and_evict("peer-z", &fp_z, 5, None, Some("peer-x"));
        assert_eq!(
            disk_row_count(&db_path),
            2,
            "#1690: an outer-LRU peer eviction must delete every disk row for that peer \
             (peer-x's 2 rows gone, peer-y + peer-z remain)"
        );
    }

    #[test]
    fn issue_1690_prune_nonce_cache_keeps_newest_per_peer() {
        // #1690 — the hydration-time legacy-bloat repair keeps the newest
        // `cap` rows per peer and deletes the rest. Tested with a small
        // cap so we don't seed 10k rows.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = crate::db::open(tmp.path()).expect("open + migrate");
        // peer-a: 4 rows (last_touch 1..4); peer-b: 2 rows (5..6).
        for (peer, touch) in [
            ("peer-a", 1),
            ("peer-a", 2),
            ("peer-a", 3),
            ("peer-a", 4),
            ("peer-b", 5),
            ("peer-b", 6),
        ] {
            let fp = FederationNonceCache::fingerprint(peer, &format!("n{touch}"));
            conn.execute(
                "INSERT INTO federation_nonce_cache (peer_id, fingerprint, last_touch, inserted_at)
                 VALUES (?1, ?2, ?3, '2026-01-01T00:00:00Z')",
                rusqlite::params![peer, fp.as_slice(), touch],
            )
            .unwrap();
        }
        // Prune to cap=2 per peer: peer-a drops its 2 oldest (touch 1,2),
        // peer-b is already within cap (untouched).
        let deleted = prune_nonce_cache_to_per_peer_cap(&conn, 2).expect("prune");
        assert_eq!(deleted, 2, "#1690: peer-a's 2 over-cap rows deleted");
        let a_left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM federation_nonce_cache WHERE peer_id='peer-a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let b_left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM federation_nonce_cache WHERE peer_id='peer-b'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(a_left, 2, "peer-a bounded to cap");
        assert_eq!(b_left, 2, "peer-b within cap, untouched");
        // The newest peer-a rows (touch 3,4) survived; the oldest (1,2) went.
        let min_touch_a: i64 = conn
            .query_row(
                "SELECT MIN(last_touch) FROM federation_nonce_cache WHERE peer_id='peer-a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(min_touch_a, 3, "the oldest rows were the ones pruned");
        // Idempotent: a second prune deletes nothing.
        assert_eq!(prune_nonce_cache_to_per_peer_cap(&conn, 2).unwrap(), 0);
    }

    /// #1255 — graceful degradation: persistence open errors do NOT
    /// crash the cache. A broken DB path surfaces as a
    /// constructor-time `Err`; callers (today: only the production
    /// daemon bootstrap) get a clear error and fall back to either
    /// retrying with the right path OR booting with the in-memory
    /// constructor [`Self::new`].
    #[test]
    fn issue_1255_persistence_constructor_surfaces_open_errors() {
        // Point at a path that cannot exist as a sqlite DB (a directory).
        let dir = tempfile::TempDir::new().unwrap();
        // Passing the directory itself as a path. SQLite's `open_with_flags`
        // refuses to open a directory as a database file.
        let res = FederationNonceCache::new_with_db_persistence(dir.path().to_path_buf());
        assert!(
            res.is_err(),
            "#1255: a non-DB path must surface as a constructor Err so operators \
             see the persistence failure rather than silently falling back"
        );
    }
}
