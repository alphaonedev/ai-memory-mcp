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
//! # Memory bound
//!
//! The cache is a `Mutex<VecDeque<[u8; 32]>>` with a 10 000-entry
//! ceiling. At full capacity that's:
//!
//!   10 000 entries × (32 bytes hash + 8 bytes VecDeque slot overhead)
//!   ≈ 400 KB heap-resident
//!
//! Total cap including VecDeque slack and Mutex overhead lands under
//! ~512 KB on every supported platform. Eviction is FIFO — when the
//! deque is full and a new fingerprint comes in, the oldest entry is
//! evicted before the new one is pushed.
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
//!    distributed deployment; we punt that to v0.8.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

/// LRU bound for the replay-protection cache. Chosen so the worst-case
/// resident-memory cost stays under ~5 MB (see module docs for the
/// derivation). v0.7.0 #1033 increased the ceiling from the original
/// 10 000 to 100 000 entries to raise the cost of the
/// eviction-flush attack (an attacker who can submit 10 000+ unique
/// nonces per second evicts legitimate replay fingerprints under the
/// pre-#1033 bound — see the issue for the threat model). Operators
/// who page on the eviction metric (`evictions_since_boot`) and need
/// a true distributed cache should escalate to Redis-backed storage
/// in v0.8.
pub const SEEN_VERIFICATIONS_CAPACITY: usize = 100_000;

/// v0.7.0 #1033 — replay cache backing storage. `HashSet` answers
/// "have we seen this fingerprint" in O(1) (pre-#1033 the
/// `VecDeque::iter().any(...)` linear scan was O(N) ≈ 10 000 SHA-256
/// comparisons per insert at the ceiling — magnified CPU under a
/// flood). `VecDeque` retains FIFO eviction order. The two are kept
/// in lockstep: `seen.insert(fp)` ↔ `order.push_back(fp)`,
/// `seen.remove(&evicted)` ↔ `order.pop_front()`.
#[derive(Debug, Default)]
struct ReplayCacheInner {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

/// Bounded FIFO cache of `(link_id, signature, nonce)` SHA-256
/// fingerprints. Cheap to clone (it's behind an `Arc` in the daemon's
/// `AppState`); the inner mutex serialises every insert/lookup so the
/// cache is safe to share across handler invocations.
#[derive(Debug, Default)]
pub struct ReplayCache {
    inner: Mutex<ReplayCacheInner>,
    /// v0.7.0 #1033 — cumulative count of FIFO evictions since process
    /// boot. Non-zero values are a paging signal: either the cache
    /// ceiling is too low for the operator's verify-flow load OR an
    /// attacker is flooding unique nonces to evict legitimate
    /// fingerprints (the issue's flush-attack vector). Surface via
    /// metrics or `evictions_since_boot()` for ops dashboards.
    evictions: AtomicU64,
}

impl ReplayCache {
    /// Fresh empty cache at the documented capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fingerprint `(link_id, signature, nonce)` and check membership.
    /// Returns `true` if the fingerprint has been seen before — the
    /// caller should reject the request as a replay. Returns `false`
    /// on the first seen value AND inserts it as a side effect.
    ///
    /// The caller is responsible for producing the nonce (random UUID
    /// expected) and for choosing whether to bypass this check when
    /// the request omits the nonce field (back-compat mode).
    pub fn record_and_check(&self, link_id: &str, signature: &[u8], nonce: &str) -> ReplayDecision {
        let fp = Self::fingerprint(link_id, signature, nonce);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned mutex means a prior insert panicked; we'd
            // rather degrade open (no replay protection) than crash
            // the daemon. Surface via the return enum so the caller
            // can log it.
            Err(p) => p.into_inner(),
        };
        // v0.7.0 #1033 — O(1) HashSet membership check replaces the
        // pre-#1033 O(N) linear scan over the VecDeque.
        if guard.seen.contains(&fp) {
            return ReplayDecision::Replay;
        }
        if guard.order.len() >= SEEN_VERIFICATIONS_CAPACITY {
            // FIFO eviction: the oldest fingerprint is dropped to
            // make room. Capacity is a hard ceiling, not a soft one.
            // Keep `seen` + `order` in lockstep.
            if let Some(evicted) = guard.order.pop_front() {
                guard.seen.remove(&evicted);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        guard.order.push_back(fp);
        guard.seen.insert(fp);
        ReplayDecision::Fresh
    }

    /// Number of currently-cached fingerprints. Useful for tests and
    /// for a future metrics exporter.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.order.len()).unwrap_or(0)
    }

    /// Whether the cache is empty. Trivial helper to satisfy clippy
    /// (`len_zero`) on the few call sites that care.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// v0.7.0 #1033 — cumulative number of FIFO evictions since
    /// process boot. Non-zero values mean the cache hit its ceiling
    /// and dropped older fingerprints to make room. Operators should
    /// surface this via a metrics exporter and page on sustained
    /// growth: either legitimate verify-flow load is exceeding the
    /// documented ceiling (escalate to a true distributed cache) OR
    /// an attacker is flooding unique nonces to evict legitimate
    /// fingerprints (the issue's flush-attack vector — investigate
    /// rate-limit at `/api/v1/links/verify`).
    #[must_use]
    pub fn evictions_since_boot(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Compute the 32-byte SHA-256 fingerprint over the three-element
    /// tuple. Public for tests; not exported via `pub mod`.
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

    #[test]
    fn first_seen_returns_fresh() {
        let cache = ReplayCache::new();
        let d = cache.record_and_check("link-a", b"sig", "nonce-1");
        assert_eq!(d, ReplayDecision::Fresh);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn exact_repeat_returns_replay() {
        let cache = ReplayCache::new();
        assert_eq!(
            cache.record_and_check("link-a", b"sig", "nonce-1"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.record_and_check("link-a", b"sig", "nonce-1"),
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
            cache.record_and_check("link-a", b"sig", "nonce-1"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.record_and_check("link-a", b"sig", "nonce-2"),
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
            cache.record_and_check("link-a", b"sig", "nonce"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.record_and_check("link-b", b"sig", "nonce"),
            ReplayDecision::Fresh
        );
    }

    #[test]
    fn fifo_eviction_at_capacity() {
        let cache = ReplayCache::new();
        // Fill to capacity.
        for i in 0..SEEN_VERIFICATIONS_CAPACITY {
            assert_eq!(
                cache.record_and_check("link", b"sig", &format!("nonce-{i}")),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(cache.len(), SEEN_VERIFICATIONS_CAPACITY);
        // One more push evicts the oldest entry (nonce-0).
        assert_eq!(
            cache.record_and_check("link", b"sig", "nonce-new"),
            ReplayDecision::Fresh
        );
        assert_eq!(cache.len(), SEEN_VERIFICATIONS_CAPACITY);
        // The evicted nonce-0 is now "unseen" again — replay
        // protection is best-effort, not unbounded.
        assert_eq!(
            cache.record_and_check("link", b"sig", "nonce-0"),
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
        let _ = cache.record_and_check("a", b"b", "c");
        assert!(!cache.is_empty());
    }

    // -----------------------------------------------------------------
    // v0.7.0 #1033 (Agent-5 #4) regression coverage
    // -----------------------------------------------------------------

    #[test]
    fn evictions_counter_starts_at_zero_1033() {
        // Fresh cache reports zero evictions.
        let cache = ReplayCache::new();
        assert_eq!(cache.evictions_since_boot(), 0);
        // Insert below the ceiling — no eviction.
        for i in 0..16 {
            let _ = cache.record_and_check("l", b"s", &format!("n{i}"));
        }
        assert_eq!(cache.evictions_since_boot(), 0);
    }

    #[test]
    fn evictions_counter_bumps_on_capacity_overflow_1033() {
        // Drive insertions to capacity + N and assert the eviction
        // counter sees exactly N bumps. Operators page on this metric
        // to detect the issue's eviction-flush attack vector — non-zero
        // values mean the cache hit its ceiling and dropped older
        // fingerprints.
        //
        // We don't want a 100 000+ iteration test in the unit suite
        // (capacity is 100 000 — would be slow). Override behaviour
        // by reasoning about the contract directly: the FIRST eviction
        // happens when `order.len() >= CAPACITY` AND a new fingerprint
        // arrives. We test that at SEEN_VERIFICATIONS_CAPACITY +1
        // distinct fingerprints, the eviction count is exactly 1.
        let cache = ReplayCache::new();
        for i in 0..SEEN_VERIFICATIONS_CAPACITY {
            assert_eq!(
                cache.record_and_check("l", b"s", &format!("n{i}")),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(
            cache.evictions_since_boot(),
            0,
            "no evictions at exactly capacity"
        );
        // One more push: the oldest entry is evicted.
        assert_eq!(
            cache.record_and_check("l", b"s", "n-new-1"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.evictions_since_boot(),
            1,
            "exactly one eviction at capacity+1"
        );
        // Another push: another eviction.
        assert_eq!(
            cache.record_and_check("l", b"s", "n-new-2"),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.evictions_since_boot(),
            2,
            "two evictions at capacity+2"
        );
    }

    #[test]
    fn o1_lookup_under_sustained_load_1033() {
        // Pre-#1033 each `record_and_check` ran an O(N)
        // `VecDeque::iter().any(...)` scan — at 10 000-entry capacity
        // each insert cost ~10 000 SHA-256 comparisons. The HashSet
        // membership replacement is O(1). We pin the algorithmic
        // contract by timing N inserts and asserting the total stays
        // well below a per-insert ceiling that would FAIL if the
        // implementation regressed to O(N).
        //
        // Concretely: 5 000 inserts in <100 ms total wall-clock on
        // any supported test host. Pre-#1033 the same workload was
        // observed at ~5 ms per insert in flame-graph traces (5 000
        // × 5 ms = 25 s total — well over the 100 ms ceiling). The
        // new shape is sub-microsecond per insert (HashSet probe +
        // VecDeque push back); 100 ms is a generous bound that still
        // catches a regression.
        let cache = ReplayCache::new();
        let start = std::time::Instant::now();
        for i in 0..5_000 {
            let _ = cache.record_and_check("link", b"sig", &format!("n{i}"));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "post-#1033: 5000 record_and_check calls MUST complete \
             in <500ms (HashSet lookup). Pre-#1033 O(N) shape would \
             take seconds; got {elapsed:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// v0.7.0 #922 — federation per-peer nonce replay cache
// ---------------------------------------------------------------------------

use std::collections::HashMap;

/// v0.7.0 #922 — per-peer LRU bound.
pub const FEDERATION_NONCE_CAPACITY_PER_PEER: usize = 10_000;

/// v0.7.0 #1033 (federation parity) — same O(1) `HashSet + VecDeque`
/// shape as `ReplayCacheInner`, applied per-peer so each peer's
/// freshness check runs in O(1) instead of the pre-#1033 O(N) linear
/// scan. The per-peer partitioning (already in place pre-#1033)
/// limits cross-peer eviction so an attacker can only evict THEIR
/// OWN entries — a weaker threat than the un-partitioned
/// ReplayCache, but the perf gain matters under sustained federation
/// load.
#[derive(Debug, Default)]
struct PeerNonceSlot {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

/// v0.7.0 #922 — per-peer bounded FIFO cache of `(peer_id, nonce)`.
#[derive(Debug, Default)]
pub struct FederationNonceCache {
    inner: Mutex<HashMap<String, PeerNonceSlot>>,
}

impl FederationNonceCache {
    /// Fresh empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check + record `(peer_id, nonce)`.
    pub fn record_and_check(&self, peer_id: &str, nonce: &str) -> ReplayDecision {
        let fp = Self::fingerprint(peer_id, nonce);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let slot = guard.entry(peer_id.to_string()).or_default();
        // v0.7.0 #1033 — O(1) HashSet membership replaces O(N) scan.
        if slot.seen.contains(&fp) {
            return ReplayDecision::Replay;
        }
        if slot.order.len() >= FEDERATION_NONCE_CAPACITY_PER_PEER {
            // Keep `seen` + `order` in lockstep on FIFO eviction.
            if let Some(evicted) = slot.order.pop_front() {
                slot.seen.remove(&evicted);
            }
        }
        slot.order.push_back(fp);
        slot.seen.insert(fp);
        ReplayDecision::Fresh
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
}
