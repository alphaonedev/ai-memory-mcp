// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` session table, sharded routing and topic fan-out (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! # No `.await` under a lock
//!
//! Every lock in this module is a `std::sync::Mutex` and every critical
//! section is straight-line, allocation-light and synchronous. Enqueue uses
//! `mpsc::Sender::try_send`, which never suspends: a full queue is an
//! immediate `507` to the SENDER, not backpressure applied to the router. The
//! two tables are never locked at the same time — a fan-out reads the topic
//! shard, RELEASES it, and only then takes route shards — so there is no lock
//! order to get wrong (`CONCURRENCY-04`, `CONCURRENCY-20`).
//!
//! # Bounded in bytes, not frames
//!
//! Each recipient carries a frame-count bound (the channel) AND a byte bound
//! (`queued_bytes` vs `queue_cap_bytes`), and every enqueue also reserves
//! against the hub-wide [`EgressBudget`]. All three must admit the frame or it
//! is refused; the reservation is released by the writer task once the bytes
//! have actually reached the peer.
//!
//! # Refcounted fan-out
//!
//! A topic wake is encoded ONCE and the resulting [`Bytes`] is cloned per
//! recipient — a refcount bump, not a copy — so a 256-way fan-out costs one
//! buffer, not 256.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use tokio::sync::{Notify, mpsc};

use super::limits::{EgressBudget, MAX_TOPICS_PER_SESSION, ROUTING_SHARDS};
use super::metrics::HubMetrics;
use super::pending::{PendingSet, PendingStore};

/// Opaque per-connection handle. `0` is never allocated, so it can stand for
/// "no session" without a sentinel type.
pub type SessionId = u32;

/// What one delivery attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Handed to the recipient's writer task.
    Delivered,
    /// Recipient is offline but known; the hint was coalesced into its pending
    /// set.
    Coalesced,
    /// Recipient is offline and has never authenticated: nothing to coalesce
    /// onto, so the hint was dropped. The inbox row and the backstop poll are
    /// unaffected.
    DroppedUnknown,
    /// A queue or the hub-wide egress budget is full. Reported to the sender as
    /// `507`.
    Overflow,
}

/// Per-recipient egress accounting handed to that recipient's writer task.
#[derive(Debug)]
pub struct EgressAccount {
    queued_bytes: AtomicUsize,
}

impl EgressAccount {
    /// A fresh, empty account.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queued_bytes: AtomicUsize::new(0),
        }
    }

    /// Bytes currently queued for this recipient.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued_bytes.load(Ordering::Acquire)
    }

    /// Release `n` bytes once written to the peer. Saturating, so an accounting
    /// slip degrades the cap rather than disabling it.
    pub fn release(&self, n: usize) {
        let _ = self
            .queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some(cur.saturating_sub(n))
            });
    }

    /// Reserve `n` bytes against `cap`. Returns `false` (charging nothing) when
    /// the reservation would cross the cap.
    fn try_reserve(&self, n: usize, cap: usize) -> bool {
        self.queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                let next = cur.checked_add(n)?;
                if next > cap { None } else { Some(next) }
            })
            .is_ok()
    }
}

impl Default for EgressAccount {
    fn default() -> Self {
        Self::new()
    }
}

/// One item on a connection's writer channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    /// An encoded frame to write.
    Frame(Bytes),
    /// Flush what is queued, shut the write half down, and stop. Used to end a
    /// displaced session and to drain on SIGTERM.
    Close,
}

/// The write side of one connection, with its byte accounting.
///
/// Every enqueue — a routed wake, a handshake frame, a refusal — goes through
/// [`Self::try_enqueue`], so the per-recipient and hub-wide byte budgets see
/// EVERY byte the hub queues, not just the routed ones.
#[derive(Debug, Clone)]
pub struct EgressHandle {
    tx: mpsc::Sender<Egress>,
    account: Arc<EgressAccount>,
    egress: Arc<EgressBudget>,
    closer: Arc<Notify>,
    cap_bytes: usize,
}

impl EgressHandle {
    /// Build a handle around a writer channel.
    #[must_use]
    pub fn new(
        tx: mpsc::Sender<Egress>,
        account: Arc<EgressAccount>,
        egress: Arc<EgressBudget>,
        closer: Arc<Notify>,
        cap_bytes: usize,
    ) -> Self {
        Self {
            tx,
            account,
            egress,
            closer,
            cap_bytes,
        }
    }

    /// Reserve and enqueue one frame. Returns `false` — having charged nothing
    /// — when the per-recipient byte cap, the hub-wide budget or the channel
    /// depth refuses it. The caller then answers the SENDER with `507`.
    ///
    /// Synchronous by construction: `try_send` never suspends, so this is
    /// callable from inside a lock (`CONCURRENCY-20`).
    pub fn try_enqueue(&self, frame: Bytes) -> bool {
        let len = frame.len();
        if !self.account.try_reserve(len, self.cap_bytes) {
            return false;
        }
        if !self.egress.try_reserve(len) {
            self.account.release(len);
            return false;
        }
        if self.tx.try_send(Egress::Frame(frame)).is_err() {
            self.account.release(len);
            self.egress.release(len);
            return false;
        }
        true
    }

    /// Ask this connection to flush and close. Best-effort and idempotent.
    pub fn request_close(&self) {
        let _ = self.tx.try_send(Egress::Close);
        self.closer.notify_one();
    }

    /// The reader task's wake-up for an externally requested close.
    #[must_use]
    pub fn closer(&self) -> &Arc<Notify> {
        &self.closer
    }

    /// Bytes currently queued for this connection.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.account.queued()
    }
}

/// A live recipient.
#[derive(Debug, Clone)]
struct Route {
    session: SessionId,
    handle: EgressHandle,
}

/// The displaced session, when a second hello claims an agent id.
#[derive(Debug)]
pub struct Displaced {
    /// Handle of the session being replaced.
    pub session: SessionId,
    /// Its write side, so the caller can send it a `409` and close it.
    pub handle: EgressHandle,
}

/// `u32` session-handle allocator with reuse.
///
/// Handles are reused from a free list rather than counting up forever, so a
/// long-lived hub cannot exhaust the space and start refusing connections. Stale
/// handles are structurally harmless: routing is keyed by agent id, a handle
/// only ever lives inside its own connection task, and every removal is a
/// compare-and-remove against the stored handle.
#[derive(Debug, Default)]
struct SessionAllocator {
    next: SessionId,
    free: Vec<SessionId>,
}

impl SessionAllocator {
    fn alloc(&mut self) -> Option<SessionId> {
        if let Some(id) = self.free.pop() {
            return Some(id);
        }
        let id = self.next.checked_add(1)?;
        self.next = id;
        Some(id)
    }

    fn release(&mut self, id: SessionId) {
        if id != 0 {
            self.free.push(id);
        }
    }
}

/// Sharded routing table, topic index, session allocator and offline state.
#[derive(Debug)]
pub struct Router {
    routes: Box<[Mutex<HashMap<String, Route>>]>,
    topics: Box<[Mutex<HashMap<String, HashSet<String>>>]>,
    pending: Mutex<PendingStore>,
    sessions: Mutex<SessionAllocator>,
    egress: Arc<EgressBudget>,
    metrics: Arc<HubMetrics>,
    queue_frames: usize,
    queue_cap_bytes: usize,
}

impl Router {
    /// Build a router.
    #[must_use]
    pub fn new(
        queue_frames: usize,
        queue_cap_bytes: usize,
        egress: Arc<EgressBudget>,
        pending: PendingStore,
        metrics: Arc<HubMetrics>,
    ) -> Self {
        let routes = (0..ROUTING_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let topics = (0..ROUTING_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            routes,
            topics,
            pending: Mutex::new(pending),
            sessions: Mutex::new(SessionAllocator::default()),
            egress,
            metrics,
            queue_frames,
            queue_cap_bytes,
        }
    }

    /// The hub-wide egress budget, shared with every writer task.
    #[must_use]
    pub fn egress(&self) -> &Arc<EgressBudget> {
        &self.egress
    }

    /// Frame-count depth for a new recipient channel.
    #[must_use]
    pub const fn queue_frames(&self) -> usize {
        self.queue_frames
    }

    /// Per-recipient byte ceiling for a new recipient channel.
    #[must_use]
    pub const fn queue_cap_bytes(&self) -> usize {
        self.queue_cap_bytes
    }

    /// Allocate a session handle. `None` means the `u32` space is exhausted,
    /// which the caller must treat as a refusal, never as handle reuse.
    pub fn alloc_session(&self) -> Option<SessionId> {
        lock(&self.sessions).alloc()
    }

    /// Return a session handle to the free list.
    pub fn release_session(&self, id: SessionId) {
        lock(&self.sessions).release(id);
    }

    /// Bind `agent_id` to a live session, returning any session it displaced.
    pub fn register(
        &self,
        agent_id: &str,
        session: SessionId,
        handle: EgressHandle,
    ) -> Option<Displaced> {
        let mut shard = lock(&self.routes[shard_of(agent_id)]);
        let prior = shard.insert(agent_id.to_owned(), Route { session, handle });
        prior.map(|p| {
            self.metrics.sessions_replaced();
            Displaced {
                session: p.session,
                handle: p.handle,
            }
        })
    }

    /// Remove `agent_id`'s route, but ONLY if it is still the one `session`
    /// installed.
    ///
    /// The compare is what makes a replaced session safe to clean up: without
    /// it, a slow teardown of the displaced connection would delete the route
    /// its replacement had already installed, silently blackholing the agent.
    pub fn unregister(&self, agent_id: &str, session: SessionId) -> bool {
        let mut shard = lock(&self.routes[shard_of(agent_id)]);
        match shard.get(agent_id) {
            Some(r) if r.session == session => {
                shard.remove(agent_id);
                true
            }
            _ => false,
        }
    }

    /// Is this agent currently connected?
    #[must_use]
    pub fn is_online(&self, agent_id: &str) -> bool {
        lock(&self.routes[shard_of(agent_id)]).contains_key(agent_id)
    }

    /// Add topics to an agent's subscription set.
    ///
    /// Returns `false` and changes NOTHING when the result would exceed
    /// [`MAX_TOPICS_PER_SESSION`] — a subscription is refused whole rather than
    /// silently truncated, so a client is never left believing it is listening
    /// to a topic the hub dropped.
    pub fn subscribe(&self, agent_id: &str, topics: &[String]) -> bool {
        if self.subscription_count(agent_id) + topics.len() > MAX_TOPICS_PER_SESSION {
            return false;
        }
        for t in topics {
            lock(&self.topics[shard_of(t)])
                .entry(t.clone())
                .or_default()
                .insert(agent_id.to_owned());
        }
        true
    }

    /// Remove topics from an agent's subscription set.
    pub fn unsubscribe(&self, agent_id: &str, topics: &[String]) {
        for t in topics {
            let mut shard = lock(&self.topics[shard_of(t)]);
            if let Some(subs) = shard.get_mut(t) {
                subs.remove(agent_id);
                if subs.is_empty() {
                    shard.remove(t);
                }
            }
        }
    }

    /// Drop every subscription held by an agent, on disconnect.
    pub fn unsubscribe_all(&self, agent_id: &str) {
        for shard in &self.topics {
            let mut guard = lock(shard);
            guard.retain(|_, subs| {
                subs.remove(agent_id);
                !subs.is_empty()
            });
        }
    }

    /// How many topics is this agent subscribed to?
    #[must_use]
    pub fn subscription_count(&self, agent_id: &str) -> usize {
        self.topics
            .iter()
            .map(|shard| {
                lock(shard)
                    .values()
                    .filter(|subs| subs.contains(agent_id))
                    .count()
            })
            .sum()
    }

    /// Subscribers of `topic`, excluding `exclude` (a sender is never woken by
    /// its own broadcast).
    ///
    /// The list is materialised under the topic lock and returned by value so
    /// the caller can deliver with NO lock held.
    #[must_use]
    pub fn topic_recipients(&self, topic: &str, exclude: &str) -> Vec<String> {
        let shard = lock(&self.topics[shard_of(topic)]);
        shard.get(topic).map_or_else(Vec::new, |subs| {
            subs.iter()
                .filter(|a| a.as_str() != exclude)
                .cloned()
                .collect()
        })
    }

    /// Deliver one already-encoded frame to one agent.
    ///
    /// `inbox_row_id` is the coalescing key used when the agent is offline; it
    /// is read from the wake metadata by the caller so this function never
    /// parses a payload.
    pub fn deliver(&self, agent_id: &str, frame: &Bytes, inbox_row_id: &str) -> Delivery {
        // --- route shard: synchronous, no await, released before anything else
        let online = {
            let shard = lock(&self.routes[shard_of(agent_id)]);
            shard.get(agent_id).map(|route| {
                if route.handle.try_enqueue(frame.clone()) {
                    Delivery::Delivered
                } else {
                    Delivery::Overflow
                }
            })
        };
        if let Some(outcome) = online {
            if outcome == Delivery::Overflow {
                self.metrics.overflow();
            }
            return outcome;
        }

        // --- offline: coalesce, never queue a payload
        let recorded = lock(&self.pending).record(agent_id, inbox_row_id);
        if recorded {
            self.metrics.pending_coalesced();
            Delivery::Coalesced
        } else {
            self.metrics.pending_dropped_unknown();
            Delivery::DroppedUnknown
        }
    }

    /// Mark an agent known to the offline table, on a verified hello.
    pub fn note_known(&self, agent_id: &str) -> bool {
        lock(&self.pending).note_known(agent_id)
    }

    /// Take an agent's coalesced offline state, on reconnect.
    pub fn take_pending(&self, agent_id: &str) -> PendingSet {
        lock(&self.pending).take(agent_id)
    }

    /// Forget an agent entirely, on a signed `depart`.
    pub fn forget(&self, agent_id: &str) {
        lock(&self.pending).forget(agent_id);
        self.unsubscribe_all(agent_id);
    }

    /// Agents currently holding offline state.
    #[must_use]
    pub fn tracked_offline_agents(&self) -> usize {
        lock(&self.pending).tracked_agents()
    }
}

/// Take a lock, recovering from poisoning.
///
/// A panic in one connection task must not wedge the whole hub
/// (`CONCURRENCY-18`). Every critical section here is a straight-line map
/// mutation with no partially-applied multi-step invariant, so the data behind
/// a poisoned lock is consistent and recovery is the correct call — degrade,
/// never stop routing.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Shard index for a key. `ROUTING_SHARDS` is a power of two, so the mask is a
/// cheap and unbiased reduction of the hash.
fn shard_of(key: &str) -> usize {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    let bits = usize::try_from(h.finish()).unwrap_or(usize::MAX);
    bits % ROUTING_SHARDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake_hub::limits::{DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS};

    fn router(queue_frames: usize, queue_bytes: usize, global: usize) -> Arc<Router> {
        Arc::new(Router::new(
            queue_frames,
            queue_bytes,
            Arc::new(EgressBudget::new(global)),
            PendingStore::new(DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS),
            Arc::new(HubMetrics::default()),
        ))
    }

    struct Recipient {
        rx: mpsc::Receiver<Egress>,
        account: Arc<EgressAccount>,
    }

    impl Recipient {
        fn next_frame(&mut self) -> Option<Bytes> {
            match self.rx.try_recv() {
                Ok(Egress::Frame(b)) => Some(b),
                _ => None,
            }
        }
    }

    fn connect(r: &Router, agent: &str) -> (SessionId, Recipient) {
        let session = r.alloc_session().expect("session");
        let (tx, rx) = mpsc::channel(r.queue_frames());
        let account = Arc::new(EgressAccount::new());
        let handle = EgressHandle::new(
            tx,
            Arc::clone(&account),
            Arc::clone(r.egress()),
            Arc::new(Notify::new()),
            r.queue_cap_bytes(),
        );
        r.register(agent, session, handle);
        r.note_known(agent);
        (session, Recipient { rx, account })
    }

    fn frame(n: usize) -> Bytes {
        Bytes::from(vec![7u8; n])
    }

    #[test]
    fn session_handles_are_reused_so_the_space_cannot_be_exhausted() {
        let r = router(4, 4_096, 1 << 20);
        let a = r.alloc_session().unwrap();
        let b = r.alloc_session().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, 0, "0 is reserved for `no session`");
        r.release_session(a);
        assert_eq!(r.alloc_session(), Some(a), "a released handle is reused");
    }

    #[test]
    fn delivery_to_an_online_agent_reaches_its_queue() {
        let r = router(4, 4_096, 1 << 20);
        let (_s, mut rec) = connect(&r, "a");
        assert_eq!(r.deliver("a", &frame(10), "row-1"), Delivery::Delivered);
        assert_eq!(rec.next_frame().expect("queued"), frame(10));
        assert_eq!(
            rec.account.queued(),
            10,
            "bytes stay reserved until written"
        );
        rec.account.release(10);
        assert_eq!(rec.account.queued(), 0);
    }

    #[test]
    fn an_offline_known_agent_coalesces_and_an_unknown_one_is_dropped() {
        let r = router(4, 4_096, 1 << 20);
        let (session, _rec) = connect(&r, "a");
        assert!(r.unregister("a", session));
        assert_eq!(r.deliver("a", &frame(10), "row-1"), Delivery::Coalesced);
        assert_eq!(r.deliver("a", &frame(10), "row-1"), Delivery::Coalesced);
        let p = r.take_pending("a");
        assert_eq!(p.count(), 2);
        assert_eq!(p.ids(), ["row-1"]);

        assert_eq!(
            r.deliver("never-hello", &frame(10), "row-1"),
            Delivery::DroppedUnknown
        );
    }

    #[test]
    fn the_per_recipient_byte_cap_refuses_before_the_frame_cap_would() {
        // 100 frames of depth, but only 25 bytes of budget.
        let r = router(100, 25, 1 << 20);
        let (_s, _rec) = connect(&r, "a");
        assert_eq!(r.deliver("a", &frame(10), "r"), Delivery::Delivered);
        assert_eq!(r.deliver("a", &frame(10), "r"), Delivery::Delivered);
        assert_eq!(
            r.deliver("a", &frame(10), "r"),
            Delivery::Overflow,
            "the BYTE cap is what bounds memory, not the frame count"
        );
    }

    #[test]
    fn the_global_egress_cap_refuses_across_recipients() {
        let r = router(100, 1_000, 25);
        let (_sa, _ra) = connect(&r, "a");
        let (_sb, _rb) = connect(&r, "b");
        assert_eq!(r.deliver("a", &frame(20), "r"), Delivery::Delivered);
        assert_eq!(
            r.deliver("b", &frame(20), "r"),
            Delivery::Overflow,
            "one recipient must not be able to exhaust the hub for another"
        );
        assert_eq!(
            r.egress().used(),
            20,
            "a refused reservation charges nothing"
        );
    }

    #[test]
    fn the_frame_cap_refuses_a_slow_consumer() {
        let r = router(2, 1 << 20, 1 << 20);
        let (_s, _rec) = connect(&r, "a");
        assert_eq!(r.deliver("a", &frame(1), "r"), Delivery::Delivered);
        assert_eq!(r.deliver("a", &frame(1), "r"), Delivery::Delivered);
        assert_eq!(r.deliver("a", &frame(1), "r"), Delivery::Overflow);
    }

    #[test]
    fn a_replaced_session_is_reported_and_its_teardown_cannot_delete_the_new_route() {
        let r = router(4, 4_096, 1 << 20);
        let (old_session, _old) = connect(&r, "a");
        let (new_session, mut new_rec) = connect(&r, "a");
        assert_ne!(old_session, new_session);

        // The displaced connection tears down AFTER its replacement registered.
        assert!(
            !r.unregister("a", old_session),
            "a stale session must not remove the live route"
        );
        assert_eq!(r.deliver("a", &frame(4), "r"), Delivery::Delivered);
        assert!(
            new_rec.next_frame().is_some(),
            "the live session still receives"
        );
        assert!(r.unregister("a", new_session));
    }

    #[test]
    fn topic_fanout_excludes_the_sender_and_shares_one_buffer() {
        let r = router(8, 1 << 16, 1 << 20);
        let mut recipients = Vec::new();
        for i in 0..64 {
            let name = format!("agent-{i}");
            let (_s, rec) = connect(&r, &name);
            recipients.push((name, rec));
        }
        let names: Vec<String> = recipients.iter().map(|(n, _)| n.clone()).collect();
        for n in &names {
            assert!(r.subscribe(n, &["#hive".to_string()]));
        }

        let payload = frame(32);
        let targets = r.topic_recipients("#hive", "agent-0");
        assert_eq!(
            targets.len(),
            63,
            "the sender is never woken by its own wake"
        );
        for t in &targets {
            assert_eq!(r.deliver(t, &payload, "row-1"), Delivery::Delivered);
        }
        for (name, rec) in &mut recipients {
            let got = rec.next_frame();
            if name == "agent-0" {
                assert!(got.is_none());
            } else {
                assert_eq!(got.expect("fan-out"), payload);
            }
        }
    }

    #[test]
    fn per_recipient_ordering_is_preserved() {
        let r = router(64, 1 << 16, 1 << 20);
        let (_s, mut rec) = connect(&r, "a");
        for i in 0..32u8 {
            assert_eq!(
                r.deliver("a", &Bytes::from(vec![i]), "r"),
                Delivery::Delivered
            );
        }
        for i in 0..32u8 {
            assert_eq!(rec.next_frame().expect("in order"), Bytes::from(vec![i]));
        }
    }

    #[test]
    fn a_subscription_over_the_session_cap_is_refused_whole() {
        let r = router(4, 4_096, 1 << 20);
        let (_s, _rec) = connect(&r, "a");
        let first: Vec<String> = (0..MAX_TOPICS_PER_SESSION)
            .map(|i| format!("#t{i}"))
            .collect();
        assert!(r.subscribe("a", &first));
        assert_eq!(r.subscription_count("a"), MAX_TOPICS_PER_SESSION);
        assert!(
            !r.subscribe("a", &["#one-too-many".to_string()]),
            "over the cap the subscribe is refused"
        );
        assert_eq!(
            r.subscription_count("a"),
            MAX_TOPICS_PER_SESSION,
            "and nothing changed"
        );
    }

    #[test]
    fn disconnect_drops_every_subscription() {
        let r = router(4, 4_096, 1 << 20);
        let (_s, _rec) = connect(&r, "a");
        assert!(r.subscribe("a", &["#hive".to_string(), "#swarm".to_string()]));
        r.unsubscribe_all("a");
        assert_eq!(r.subscription_count("a"), 0);
        assert!(r.topic_recipients("#hive", "").is_empty());
    }

    #[test]
    fn unsubscribe_removes_only_the_named_topics() {
        let r = router(4, 4_096, 1 << 20);
        let (_s, _rec) = connect(&r, "a");
        assert!(r.subscribe("a", &["#hive".to_string(), "#swarm".to_string()]));
        r.unsubscribe("a", &["#hive".to_string()]);
        assert!(r.topic_recipients("#hive", "").is_empty());
        assert_eq!(r.topic_recipients("#swarm", ""), ["a"]);
    }

    #[test]
    fn shards_are_stable_and_in_range() {
        for i in 0..1_000 {
            let k = format!("agent-{i}");
            assert!(shard_of(&k) < ROUTING_SHARDS);
            assert_eq!(shard_of(&k), shard_of(&k));
        }
    }
}
