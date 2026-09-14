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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

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

/// #3662 — one tracing target for the nonce-cache observability sites
/// added by that issue (the hardcoded-literal gate is a ratchet: new
/// sites must reference a const, not repeat the string).
const TRACE_TARGET: &str = "ai_memory::identity::replay";

/// #3662 — how long restart protection may be LOST (persistence
/// degraded, or never opened) before the loss is classified as
/// actionable. A single failed INSERT during a WAL checkpoint or a
/// transient lock is not an incident: the next Fresh nonce re-tries and
/// flips the state back to durable. Sustained loss past this window
/// means every restart re-opens the replay window for every peer, which
/// IS an incident. Aligned with `daemon_runtime::PULL_CURSOR_FUTURE_SKEW_SECS`
/// (5 minutes) so the two federation-freshness thresholds read the same.
pub const NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS: u64 = 5 * (crate::SECS_PER_MINUTE as u64);

/// #3662 — the closed set of persistence operations the
/// `FederationNonceCache` performs against its sqlite mirror. Each has
/// its own failure counter (in-process AND the `op` label of
/// `ai_memory_federation_nonce_cache_persistence_failed_total`) so an
/// operator can tell "cannot open the database" from "the evicted-row
/// DELETE keeps failing" without reading logs. The label set is closed:
/// no tenant string, peer id or path ever reaches a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoncePersistenceOp {
    /// `crate::db::open` on the mirror path (boot hydration or per-write).
    Open,
    /// `INSERT OR REPLACE` of a Fresh fingerprint.
    Insert,
    /// `DELETE` of the fingerprint the per-peer FIFO just evicted.
    DeleteFingerprint,
    /// `DELETE` of every row of the peer slot the outer LRU just evicted.
    DeletePeer,
    /// The #1690 over-cap prune that runs once on hydration.
    HydratePrune,
}

impl NoncePersistenceOp {
    /// Every op, in counter-slot order. Used to pre-touch the labelled
    /// metric family at registration so each series renders as a
    /// measured `0` from boot instead of being absent until it fails.
    pub const ALL: [Self; 5] = [
        Self::Open,
        Self::Insert,
        Self::DeleteFingerprint,
        Self::DeletePeer,
        Self::HydratePrune,
    ];

    /// Stable metric-label / JSON-key spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Insert => "insert",
            Self::DeleteFingerprint => "delete_fingerprint",
            Self::DeletePeer => "delete_peer",
            Self::HydratePrune => "hydrate_prune",
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::Open => 0,
            Self::Insert => 1,
            Self::DeleteFingerprint => 2,
            Self::DeletePeer => 3,
            Self::HydratePrune => 4,
        }
    }
}

/// #3662 — the persistence posture of a `FederationNonceCache`, as
/// measured from the outcome of its LAST persistence interaction. Also
/// the value of the `ai_memory_federation_nonce_cache_persistence_state`
/// gauge (`0` / `1` / `2` in declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoncePersistenceState {
    /// No mirror path was configured (`FederationNonceCache::new`).
    /// Restart protection is DISABLED by construction; a daemon restart
    /// re-opens the replay window. Production never builds this shape —
    /// it is the harness / opt-out posture.
    MemoryOnly = 0,
    /// A mirror path is configured and the last persistence interaction
    /// succeeded: Fresh fingerprints reach disk and survive a restart.
    Durable = 1,
    /// A mirror path is configured (or was intended) and the last
    /// persistence interaction FAILED, or the mirror could not be opened
    /// at boot. The in-memory bound still holds, so replay refusal keeps
    /// working within this process, but restart protection is LOST until
    /// a later write succeeds.
    Degraded = 2,
}

impl NoncePersistenceState {
    /// Stable JSON spelling (matches the serde rename).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryOnly => "memory_only",
            Self::Durable => "durable",
            Self::Degraded => "degraded",
        }
    }

    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Durable,
            2 => Self::Degraded,
            _ => Self::MemoryOnly,
        }
    }
}

/// #3662 — what a daemon restart would do to the replay window, derived
/// from [`NoncePersistenceState`]. This is the operator-facing
/// classification: `lost` for longer than
/// [`NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS`] is actionable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartProtection {
    /// Persistence was never configured for this cache.
    Disabled,
    /// Fingerprints are reaching the disk mirror.
    Durable,
    /// Persistence was configured but is not currently working.
    Lost,
}

/// #3662 — the persistence half of [`NonceCacheHealth`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NoncePersistenceHealth {
    /// Measured from the last persistence interaction.
    pub state: NoncePersistenceState,
    /// Derived classification (see [`RestartProtection`]).
    pub restart_protection: RestartProtection,
    /// Why protection is not `durable`, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// Failures since boot, by operation (every op always present).
    pub failures_by_op: Vec<(&'static str, u64)>,
    /// Sum of `failures_by_op`.
    pub failures_total: u64,
    /// Unix seconds of the last fully successful persistence write
    /// (INSERT plus any evict DELETEs). `None` = no write has succeeded
    /// since boot — a rehydrated-but-idle cache reports `None` honestly.
    pub last_success_at_seconds: Option<u64>,
    /// Unix seconds of the last failed persistence operation.
    pub last_failure_at_seconds: Option<u64>,
    /// Unix seconds at which the current `lost` stretch began.
    pub degraded_since_at_seconds: Option<u64>,
    /// `now - degraded_since` while `lost`.
    pub degraded_for_seconds: Option<u64>,
    /// `true` once protection has been `lost` for at least
    /// [`NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS`].
    pub actionable: bool,
}

/// #3662 — a point-in-time, fully measured snapshot of a
/// [`FederationNonceCache`]. Every number is read from the cache's own
/// atomics or the in-memory map; nothing is estimated. Carries no peer
/// id, path or tenant string, so it is safe to embed in `/health`
/// unchanged. `to_signal_json` renders it in the #3646 signal-object
/// shape (`state: "available"` plus additive `value` / freshness fields)
/// so the `federation.nonce_cache` field that #3646 reports as
/// `not_yet_instrumented` can be replaced by this object in place.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NonceCacheHealth {
    /// Peer slots currently resident.
    pub peers: u64,
    /// The outer LRU ceiling (`FEDERATION_NONCE_MAX_PEERS`).
    pub max_peers: u64,
    /// Fingerprints resident across all peers.
    pub fingerprints: u64,
    /// The per-peer FIFO ceiling (`FEDERATION_NONCE_CAPACITY_PER_PEER`).
    pub per_peer_capacity: u64,
    /// Outer-LRU peer-slot evictions since boot (#1038).
    pub peer_evictions_total: u64,
    /// Per-peer FIFO fingerprint evictions since boot.
    pub fingerprint_evictions_total: u64,
    /// `ReplayDecision::Replay` outcomes since boot — refused requests.
    pub replay_refusals_total: u64,
    /// Persistence posture.
    pub persistence: NoncePersistenceHealth,
    /// The unix second this snapshot was taken at.
    pub observed_at_seconds: u64,
}

impl NonceCacheHealth {
    /// Reason spelling for the boot-time fallback.
    pub const REASON_OPEN_FAILED_AT_BOOT: &'static str = "persistence_open_failed_at_boot";
    /// Reason spelling for a per-write failure after a working boot.
    pub const REASON_WRITE_FAILED: &'static str = "persistence_write_failed";
    /// Reason spelling for the opt-out constructor.
    pub const REASON_DISABLED: &'static str = "persistence_disabled";

    /// The #3646 signal-object rendering: an instrumented field keeps
    /// the `state` discriminator and adds `value` + freshness; it never
    /// collapses to a bare number.
    #[must_use]
    pub fn to_signal_json(&self) -> serde_json::Value {
        let failures: serde_json::Map<String, serde_json::Value> = self
            .persistence
            .failures_by_op
            .iter()
            .map(|(op, n)| ((*op).to_string(), serde_json::Value::from(*n)))
            .collect();
        serde_json::json!({
            "state": "available",
            "observed_at_seconds": self.observed_at_seconds,
            "value": {
                "peers": self.peers,
                "max_peers": self.max_peers,
                "fingerprints": self.fingerprints,
                "per_peer_capacity": self.per_peer_capacity,
                "peer_evictions_total": self.peer_evictions_total,
                "fingerprint_evictions_total": self.fingerprint_evictions_total,
                "replay_refusals_total": self.replay_refusals_total,
                "persistence": {
                    "state": self.persistence.state,
                    "restart_protection": self.persistence.restart_protection,
                    "reason": self.persistence.reason,
                    "failures_by_op": failures,
                    "failures_total": self.persistence.failures_total,
                    "last_success_at_seconds": self.persistence.last_success_at_seconds,
                    "last_failure_at_seconds": self.persistence.last_failure_at_seconds,
                    "degraded_since_at_seconds": self.persistence.degraded_since_at_seconds,
                    "degraded_for_seconds": self.persistence.degraded_for_seconds,
                    "actionable": self.persistence.actionable,
                },
            },
        })
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

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
    /// #3662 — `ReplayDecision::Replay` outcomes since boot.
    replay_refusals: AtomicU64,
    /// #3662 — per-peer FIFO fingerprint evictions since boot (the
    /// inner-cap twin of `peer_evictions`, which was the only eviction
    /// counted pre-#3662).
    fingerprint_evictions: AtomicU64,
    /// #3662 — fingerprints resident across all peer slots, maintained
    /// in lockstep with the map so occupancy is O(1) to read.
    fingerprints_total: AtomicU64,
    /// #3662 — persistence failures since boot, one slot per
    /// [`NoncePersistenceOp`] (`NoncePersistenceOp::slot`).
    persistence_failures: [AtomicU64; 5],
    /// #3662 — [`NoncePersistenceState`] as `u8`, measured from the
    /// outcome of the last persistence interaction.
    persistence_state: AtomicU8,
    /// #3662 — unix seconds of the last fully successful persistence
    /// write; `0` = none since boot.
    last_persist_ok_unix: AtomicU64,
    /// #3662 — unix seconds of the last failed persistence op; `0` = none.
    last_persist_fail_unix: AtomicU64,
    /// #3662 — unix seconds at which the current degraded stretch began;
    /// `0` = not degraded.
    degraded_since_unix: AtomicU64,
    /// #3662 — set by `new_after_persistence_open_failure`: the daemon
    /// WANTED persistence and could not open the mirror at boot.
    boot_open_failed: AtomicBool,
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
        let cache = Self::default();
        cache.publish_gauges();
        cache
    }

    /// #3662 — the daemon's boot fallback. Use this — not [`Self::new`]
    /// — when [`Self::new_with_db_persistence`] failed: the resulting
    /// cache is in-memory only exactly like `new()`, but it REPORTS that
    /// posture as `degraded` / restart protection `lost` with reason
    /// `persistence_open_failed_at_boot`, counts one `open` failure, and
    /// starts the actionable clock. Pre-#3662 the fallback was
    /// indistinguishable from a healthy cache on every surface but the
    /// boot log line.
    #[must_use]
    pub fn new_after_persistence_open_failure() -> Self {
        let cache = Self::default();
        cache.boot_open_failed.store(true, Ordering::Relaxed);
        cache.note_persistence_failure(NoncePersistenceOp::Open);
        cache.publish_gauges();
        cache
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
            db_path: Some(db_path.clone()),
            // #3662 — a configured mirror starts `Durable`; the first
            // failed interaction flips it. Hydration failure below returns
            // `Err` and the caller decides (the daemon falls back via
            // `new_after_persistence_open_failure`).
            persistence_state: AtomicU8::new(NoncePersistenceState::Durable as u8),
            ..Self::default()
        };
        cache.hydrate_from_disk(&db_path)?;
        cache.publish_gauges();
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
        // #3662 — occupancy is measured from the map, not the row count:
        // over-cap rows dropped above must not be counted.
        let resident: usize = guard.values().map(|s| s.order.len()).sum();
        self.fingerprints_total
            .store(resident as u64, Ordering::Relaxed);
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
            Err(e) => {
                // #3662 — counted, not just logged: a mirror that refuses
                // DELETE at boot will refuse it on every eviction too.
                self.note_persistence_failure(NoncePersistenceOp::HydratePrune);
                tracing::warn!(
                    target: TRACE_TARGET,
                    err = %e,
                    "FederationNonceCache: hydration over-cap prune failed (non-fatal; in-memory \
                     cache still bounded)"
                );
            }
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
                // #3662 — every swallowed failure is now COUNTED and flips
                // the persistence state to `degraded`, so the "graceful"
                // degradation is visible on /health, /metrics and doctor
                // instead of only in a WARN line nobody is tailing.
                self.note_persistence_failure(NoncePersistenceOp::Open);
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer_id = %peer_id,
                    path = %path.display(),
                    err = %e,
                    "FederationNonceCache: persist open failed; in-memory cache still holds \
                     (#1255 graceful degradation; restart protection LOST until a write succeeds, #3662)",
                );
                return;
            }
        };
        let mut all_ok = true;
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
            all_ok = false;
            self.note_persistence_failure(NoncePersistenceOp::Insert);
            tracing::warn!(
                target: TRACE_TARGET,
                peer_id = %peer_id,
                err = %e,
                "FederationNonceCache: persist insert failed; in-memory cache still holds \
                 (#1255 graceful degradation; counted #3662)",
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
                all_ok = false;
                self.note_persistence_failure(NoncePersistenceOp::DeleteFingerprint);
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer_id = %peer_id,
                    err = %e,
                    "FederationNonceCache: evicted-fingerprint delete failed; disk row lingers \
                     (#1690 graceful degradation; counted #3662)",
                );
            }
        }
        if let Some(ep) = evicted_peer {
            if let Err(e) = conn.execute(
                "DELETE FROM federation_nonce_cache WHERE peer_id = ?1",
                rusqlite::params![ep],
            ) {
                all_ok = false;
                self.note_persistence_failure(NoncePersistenceOp::DeletePeer);
                tracing::warn!(
                    target: TRACE_TARGET,
                    evicted_peer = %ep,
                    err = %e,
                    "FederationNonceCache: evicted-peer delete failed; disk rows linger \
                     (#1690 graceful degradation; counted #3662)",
                );
            }
        }
        if all_ok {
            self.note_persistence_ok();
        }
    }

    /// #3662 — record one failed persistence op: bump its counter (in
    /// process and on `/metrics`), stamp the failure instant, and flip
    /// the state to `Degraded`, starting the actionable clock if this is
    /// the first failure of the current stretch.
    fn note_persistence_failure(&self, op: NoncePersistenceOp) {
        let now = unix_now_secs();
        self.persistence_failures[op.slot()].fetch_add(1, Ordering::Relaxed);
        self.last_persist_fail_unix.store(now, Ordering::Relaxed);
        let was = self
            .persistence_state
            .swap(NoncePersistenceState::Degraded as u8, Ordering::Relaxed);
        if was != NoncePersistenceState::Degraded as u8 {
            self.degraded_since_unix.store(now, Ordering::Relaxed);
        }
        let m = crate::metrics::registry();
        m.federation_nonce_cache_persistence_failed_total
            .with_label_values(&[op.as_str()])
            .inc();
        m.federation_nonce_cache_persistence_state
            .set(i64::from(NoncePersistenceState::Degraded as u8));
    }

    /// #3662 — record one fully successful persistence write: stamp the
    /// instant and return the state to `Durable` (ending any degraded
    /// stretch — a later failure starts a fresh clock).
    fn note_persistence_ok(&self) {
        let now = unix_now_secs();
        self.last_persist_ok_unix.store(now, Ordering::Relaxed);
        self.persistence_state
            .store(NoncePersistenceState::Durable as u8, Ordering::Relaxed);
        self.degraded_since_unix.store(0, Ordering::Relaxed);
        let m = crate::metrics::registry();
        m.federation_nonce_cache_persistence_state
            .set(i64::from(NoncePersistenceState::Durable as u8));
        // #3662 (review fold) — the FIRST successful write creates the
        // series; before that a scrape carries no timestamp at all.
        #[allow(clippy::cast_possible_wrap)]
        m.federation_nonce_cache_last_persisted_at_seconds
            .with_label_values(&[])
            .set(now as i64);
    }

    /// #3662 — push the occupancy / capacity / state gauges to
    /// `/metrics`. Counters are incremented at their event sites; gauges
    /// are set here from the cache's own atomics, so a scrape never sees
    /// a value this cache did not measure. Called at construction and
    /// after every `record_and_check`.
    fn publish_gauges(&self) {
        let m = crate::metrics::registry();
        #[allow(clippy::cast_possible_wrap)]
        {
            m.federation_nonce_cache_peers.set(self.peer_count() as i64);
            m.federation_nonce_cache_fingerprints
                .set(self.fingerprints_total.load(Ordering::Relaxed) as i64);
            m.federation_nonce_cache_peer_capacity
                .set(FEDERATION_NONCE_MAX_PEERS as i64);
            m.federation_nonce_cache_per_peer_capacity
                .set(FEDERATION_NONCE_CAPACITY_PER_PEER as i64);
            // #3662 (review fold) — never publish a "0 = never" timestamp:
            // the series exists only once a successful write has stamped it.
            let last_ok = self.last_persist_ok_unix.load(Ordering::Relaxed);
            if last_ok != 0 {
                m.federation_nonce_cache_last_persisted_at_seconds
                    .with_label_values(&[])
                    .set(last_ok as i64);
            }
        }
        m.federation_nonce_cache_persistence_state
            .set(i64::from(self.persistence_state.load(Ordering::Relaxed)));
    }

    /// #3662 — the measured persistence posture of this cache.
    #[must_use]
    pub fn persistence_state(&self) -> NoncePersistenceState {
        NoncePersistenceState::from_u8(self.persistence_state.load(Ordering::Relaxed))
    }

    /// #3662 — replay refusals since boot.
    #[must_use]
    pub fn replay_refusals_since_boot(&self) -> u64 {
        self.replay_refusals.load(Ordering::Relaxed)
    }

    /// #3662 — per-peer FIFO fingerprint evictions since boot.
    #[must_use]
    pub fn fingerprint_evictions_since_boot(&self) -> u64 {
        self.fingerprint_evictions.load(Ordering::Relaxed)
    }

    /// #3662 — failures since boot for one persistence op.
    #[must_use]
    pub fn persistence_failures(&self, op: NoncePersistenceOp) -> u64 {
        self.persistence_failures[op.slot()].load(Ordering::Relaxed)
    }

    /// #3662 — a fully measured snapshot, as of `now_unix` (injected so
    /// the actionable classification is testable without sleeping).
    #[must_use]
    pub fn health_at(&self, now_unix: u64) -> NonceCacheHealth {
        let nz = |v: u64| if v == 0 { None } else { Some(v) };
        let state = self.persistence_state();
        let (restart_protection, reason) = match state {
            NoncePersistenceState::MemoryOnly => (
                RestartProtection::Disabled,
                Some(NonceCacheHealth::REASON_DISABLED),
            ),
            NoncePersistenceState::Durable => (RestartProtection::Durable, None),
            NoncePersistenceState::Degraded => (
                RestartProtection::Lost,
                Some(
                    if self.boot_open_failed.load(Ordering::Relaxed)
                        && self.last_persist_ok_unix.load(Ordering::Relaxed) == 0
                    {
                        NonceCacheHealth::REASON_OPEN_FAILED_AT_BOOT
                    } else {
                        NonceCacheHealth::REASON_WRITE_FAILED
                    },
                ),
            ),
        };
        let degraded_since = nz(self.degraded_since_unix.load(Ordering::Relaxed));
        let degraded_for = degraded_since.map(|s| now_unix.saturating_sub(s));
        let failures_by_op: Vec<(&'static str, u64)> = NoncePersistenceOp::ALL
            .iter()
            .map(|op| (op.as_str(), self.persistence_failures(*op)))
            .collect();
        let failures_total = failures_by_op.iter().map(|(_, n)| *n).sum();
        NonceCacheHealth {
            peers: self.peer_count() as u64,
            max_peers: FEDERATION_NONCE_MAX_PEERS as u64,
            fingerprints: self.fingerprints_total.load(Ordering::Relaxed),
            per_peer_capacity: FEDERATION_NONCE_CAPACITY_PER_PEER as u64,
            peer_evictions_total: self.peer_evictions_since_boot(),
            fingerprint_evictions_total: self.fingerprint_evictions_since_boot(),
            replay_refusals_total: self.replay_refusals_since_boot(),
            persistence: NoncePersistenceHealth {
                state,
                restart_protection,
                reason,
                failures_by_op,
                failures_total,
                last_success_at_seconds: nz(self.last_persist_ok_unix.load(Ordering::Relaxed)),
                last_failure_at_seconds: nz(self.last_persist_fail_unix.load(Ordering::Relaxed)),
                degraded_since_at_seconds: degraded_since,
                degraded_for_seconds: degraded_for,
                actionable: restart_protection == RestartProtection::Lost
                    && degraded_for.is_some_and(|d| d >= NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS),
            },
            observed_at_seconds: now_unix,
        }
    }

    /// #3662 — [`Self::health_at`] at the wall clock.
    #[must_use]
    pub fn health(&self) -> NonceCacheHealth {
        self.health_at(unix_now_secs())
    }

    /// Check + record `(peer_id, nonce)`.
    pub fn record_and_check(&self, peer_id: &str, nonce: &str) -> ReplayDecision {
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
                if let Some(slot) = guard.remove(&evict_id) {
                    // #3662 — occupancy drops by the evicted slot's rows.
                    self.fingerprints_total
                        .fetch_sub(slot.order.len() as u64, Ordering::Relaxed);
                }
                self.peer_evictions.fetch_add(1, Ordering::Relaxed);
                crate::metrics::registry()
                    .federation_nonce_cache_peer_evictions_total
                    .inc();
                tracing::warn!(
                    target: TRACE_TARGET,
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
            // #3662 — a refused replay is a measured security event, not
            // only a per-request WARN at the handler.
            self.replay_refusals.fetch_add(1, Ordering::Relaxed);
            drop(guard);
            crate::metrics::registry()
                .federation_nonce_cache_replay_refused_total
                .inc();
            self.publish_gauges();
            return ReplayDecision::Replay;
        }
        let mut evicted_fp: Option<[u8; 32]> = None;
        if slot.order.len() >= FEDERATION_NONCE_CAPACITY_PER_PEER {
            // Keep `seen` + `order` in lockstep on FIFO eviction.
            if let Some(evicted) = slot.order.pop_front() {
                slot.seen.remove(&evicted);
                evicted_fp = Some(evicted);
                // #3662 — the inner-cap eviction was uncounted pre-#3662;
                // a peer cycling its FIFO is exactly the flush-attack
                // shape the capacity comment above describes.
                self.fingerprint_evictions.fetch_add(1, Ordering::Relaxed);
                self.fingerprints_total.fetch_sub(1, Ordering::Relaxed);
                crate::metrics::registry()
                    .federation_nonce_cache_fingerprint_evictions_total
                    .inc();
            }
        }
        slot.order.push_back(fp);
        slot.seen.insert(fp);
        self.fingerprints_total.fetch_add(1, Ordering::Relaxed);
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
        self.publish_gauges();
        ReplayDecision::Fresh
    }

    /// v0.7.0 #1038 — cumulative number of peer-slot evictions
    /// (outer LRU). Non-zero means peer churn caused the outer
    /// HashMap to hit `FEDERATION_NONCE_MAX_PEERS` and drop an
    /// older peer's slot. Operators page on sustained growth.
    #[must_use]
    pub fn peer_evictions_since_boot(&self) -> u64 {
        self.peer_evictions.load(Ordering::Relaxed)
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
    // ---- #3662 — nonce-cache health contract -------------------------------

    #[test]
    fn replay_refusal_and_fifo_eviction_are_counted_3662() {
        let cache = FederationNonceCache::new();
        let m = crate::metrics::registry();
        let refused_before = m.federation_nonce_cache_replay_refused_total.get();
        let evicted_before = m.federation_nonce_cache_fingerprint_evictions_total.get();
        for i in 0..FEDERATION_NONCE_CAPACITY_PER_PEER {
            assert_eq!(
                cache.record_and_check("p", &format!("n-{i}")),
                ReplayDecision::Fresh
            );
        }
        let h = cache.health_at(1);
        assert_eq!(h.peers, 1);
        assert_eq!(h.fingerprints, FEDERATION_NONCE_CAPACITY_PER_PEER as u64);
        assert_eq!(h.fingerprint_evictions_total, 0);
        assert_eq!(h.replay_refusals_total, 0);
        // One past the cap: FIFO evicts n-0 — counted (pre-#3662 it was not).
        assert_eq!(cache.record_and_check("p", "n-new"), ReplayDecision::Fresh);
        // A replay — counted (pre-#3662 only a handler WARN).
        assert_eq!(cache.record_and_check("p", "n-new"), ReplayDecision::Replay);
        let h = cache.health_at(1);
        assert_eq!(
            h.fingerprint_evictions_total, 1,
            "#3662: FIFO eviction counted"
        );
        assert_eq!(h.replay_refusals_total, 1, "#3662: replay refusal counted");
        assert_eq!(
            h.fingerprints, FEDERATION_NONCE_CAPACITY_PER_PEER as u64,
            "occupancy stays at the cap after evict+insert"
        );
        assert!(m.federation_nonce_cache_replay_refused_total.get() > refused_before);
        assert!(m.federation_nonce_cache_fingerprint_evictions_total.get() > evicted_before);
    }

    #[test]
    fn peer_eviction_reduces_measured_occupancy_3662() {
        let cache = FederationNonceCache::new();
        for i in 0..FEDERATION_NONCE_MAX_PEERS {
            let _ = cache.record_and_check(&format!("peer-{i}"), "n");
        }
        // peer-0 gets 3 fingerprints and the freshest touch on a different
        // peer so that peer-0 is not the LRU.
        let _ = cache.record_and_check("peer-0", "n2");
        let _ = cache.record_and_check("peer-0", "n3");
        let h = cache.health_at(1);
        assert_eq!(h.peers, FEDERATION_NONCE_MAX_PEERS as u64);
        assert_eq!(h.fingerprints, FEDERATION_NONCE_MAX_PEERS as u64 + 2);
        // A new peer evicts the LRU slot (one fingerprint).
        assert_eq!(
            cache.record_and_check("peer-new", "n"),
            ReplayDecision::Fresh
        );
        let h = cache.health_at(1);
        assert_eq!(h.peer_evictions_total, 1);
        assert_eq!(h.peers, FEDERATION_NONCE_MAX_PEERS as u64);
        assert_eq!(
            h.fingerprints,
            FEDERATION_NONCE_MAX_PEERS as u64 + 2,
            "evicted slot's rows leave the occupancy, the new peer's row enters"
        );
    }

    #[test]
    fn memory_only_cache_reports_protection_disabled_3662() {
        let cache = FederationNonceCache::new();
        let h = cache.health_at(1);
        assert_eq!(h.persistence.state, NoncePersistenceState::MemoryOnly);
        assert_eq!(
            h.persistence.restart_protection,
            RestartProtection::Disabled
        );
        assert_eq!(
            h.persistence.reason,
            Some(NonceCacheHealth::REASON_DISABLED)
        );
        assert_eq!(h.persistence.last_success_at_seconds, None);
        assert!(!h.persistence.actionable);
        let j = h.to_signal_json();
        assert_eq!(j["state"], "available");
        assert_eq!(j["value"]["persistence"]["state"], "memory_only");
        assert_eq!(j["value"]["persistence"]["restart_protection"], "disabled");
        assert_eq!(j["value"]["max_peers"], FEDERATION_NONCE_MAX_PEERS as u64);
        assert_eq!(j["value"]["persistence"]["failures_by_op"]["open"], 0);
    }

    #[test]
    fn boot_open_failure_is_lost_protection_and_actionable_when_sustained_3662() {
        let cache = FederationNonceCache::new_after_persistence_open_failure();
        assert_eq!(cache.persistence_state(), NoncePersistenceState::Degraded);
        assert_eq!(cache.persistence_failures(NoncePersistenceOp::Open), 1);
        let since = cache
            .health_at(0)
            .persistence
            .degraded_since_at_seconds
            .expect("degraded clock started at construction");
        // Just under the window: lost, but not yet actionable.
        let h = cache.health_at(since + NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS - 1);
        assert_eq!(h.persistence.restart_protection, RestartProtection::Lost);
        assert_eq!(
            h.persistence.reason,
            Some(NonceCacheHealth::REASON_OPEN_FAILED_AT_BOOT)
        );
        assert!(!h.persistence.actionable);
        // At the window: actionable.
        let h = cache.health_at(since + NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS);
        assert!(
            h.persistence.actionable,
            "#3662: sustained loss is actionable"
        );
        assert_eq!(
            h.persistence.degraded_for_seconds,
            Some(NONCE_PERSISTENCE_LOSS_ACTIONABLE_SECS)
        );
        assert_eq!(h.persistence.failures_total, 1);
        // Replay refusal keeps working in-process while protection is lost.
        assert_eq!(cache.record_and_check("p", "n"), ReplayDecision::Fresh);
        assert_eq!(cache.record_and_check("p", "n"), ReplayDecision::Replay);
    }

    #[test]
    fn persistence_write_failure_flips_to_degraded_and_recovers_3662() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("nonce-3662.db");
        let cache =
            FederationNonceCache::new_with_db_persistence(&db_path).expect("open + migrate");
        assert_eq!(cache.persistence_state(), NoncePersistenceState::Durable);
        assert_eq!(
            cache.health_at(1).persistence.last_success_at_seconds,
            None,
            "hydrated-but-idle: no write has succeeded yet, and the snapshot says so"
        );
        assert_eq!(cache.record_and_check("p", "n-1"), ReplayDecision::Fresh);
        let h = cache.health_at(1);
        assert_eq!(h.persistence.state, NoncePersistenceState::Durable);
        assert_eq!(h.persistence.restart_protection, RestartProtection::Durable);
        assert!(h.persistence.last_success_at_seconds.is_some());
        assert_eq!(h.persistence.failures_total, 0);

        // Break the mirror: replace the database file with a directory so
        // `db::open` fails on the next Fresh nonce.
        std::fs::remove_file(&db_path).expect("remove db");
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.path().join(format!("nonce-3662.db{suffix}")));
        }
        std::fs::create_dir(&db_path).expect("shadow dir");
        assert_eq!(
            cache.record_and_check("p", "n-2"),
            ReplayDecision::Fresh,
            "the in-memory cache still admits while persistence is broken"
        );
        let h = cache.health_at(1);
        assert_eq!(h.persistence.state, NoncePersistenceState::Degraded);
        assert_eq!(h.persistence.restart_protection, RestartProtection::Lost);
        assert_eq!(
            h.persistence.reason,
            Some(NonceCacheHealth::REASON_WRITE_FAILED)
        );
        assert_eq!(cache.persistence_failures(NoncePersistenceOp::Open), 1);
        assert!(h.persistence.last_failure_at_seconds.is_some());
        assert!(h.persistence.degraded_since_at_seconds.is_some());
        // (#3662 review) no pin on the process-global state GAUGE here: every
        // cache instance publishes it, so under parallel tests it is not
        // this cache's value; the cache-local assertions above are the pin.

        // Repair: remove the shadow directory; the next write re-creates the
        // database and the state returns to durable.
        std::fs::remove_dir(&db_path).expect("remove shadow dir");
        assert_eq!(cache.record_and_check("p", "n-3"), ReplayDecision::Fresh);
        let h = cache.health_at(1);
        assert_eq!(h.persistence.state, NoncePersistenceState::Durable);
        assert_eq!(h.persistence.restart_protection, RestartProtection::Durable);
        assert_eq!(h.persistence.degraded_since_at_seconds, None);
        assert_eq!(h.persistence.failures_total, 1, "history is kept");
    }

    #[test]
    fn persistence_op_labels_are_closed_and_stable_3662() {
        let labels: Vec<&str> = NoncePersistenceOp::ALL
            .iter()
            .map(|op| op.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "open",
                "insert",
                "delete_fingerprint",
                "delete_peer",
                "hydrate_prune"
            ]
        );
        let slots: Vec<usize> = NoncePersistenceOp::ALL.iter().map(|op| op.slot()).collect();
        assert_eq!(slots, [0, 1, 2, 3, 4]);
    }

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
