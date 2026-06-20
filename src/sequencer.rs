// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar-3 R6 (#1719 item 4a / epic #1709) — quorum-elected
//! sequencer: the **leadership state machine** (pure).
//!
//! R6 ("total-order operation agreement") is built as a quorum-elected
//! sequencer (5-agent vote `4d3ea1c5`, decision memory `b8b4817e`):
//! a leader is elected via a time-based lease and assigns a monotonic
//! `(term, seq)` to each coordination operation; the assignment is
//! committed through a W-of-N quorum that **fences stale leaders by
//! `term`**.
//!
//! ## What this module is
//!
//! The complete in-process R6 primitive, in three layers:
//!
//! * **4a — leadership** ([`SequencerState`]): a monotonic `term` + the
//!   current leader; [`SequencerState::evaluate`] lifts the proven
//!   [`crate::actions::lease_acquire`] gate (`expires_at > now && holder !=
//!   candidate` ⇒ conflict) to the sequencer term.
//! * **4b — safety** ([`AcceptorState`] + [`commit_assignment`]): the
//!   term-fence. Each quorum peer rejects an assignment whose `term` is
//!   below its `max_term_seen`, so a deposed leader cannot collect `W`
//!   acks. This — NOT the lease — is what prevents two live leaders from
//!   both committing.
//! * **4c — integration** ([`Sequencer`] + [`committed_assignment_event`]):
//!   the full round (acquire leadership → assign `(term, seq)` → commit
//!   through the term-fenced quorum) and the durable, append-only,
//!   hash-chained `signed_events` record of the agreed total order
//!   (commit-once / never-retract).
//!
//! **The lease is a LIVENESS optimization only — it is NOT the safety
//! boundary.** A GC-paused leader whose lease has not yet expired on its
//! own clock can still believe it holds leadership; the *safety* boundary
//! that prevents two live leaders from both committing is the
//! **term-fence at the quorum** (4b, #1759): every `(term, seq)`
//! assignment must be accepted by a W-of-N quorum that persists the
//! highest `term` it has seen and rejects any assignment carrying a lower
//! `term`. The `term` minted here is that fencing token. Persisting the
//! leader-lease to a table + wiring the committed order into the
//! `signed_events` append-only log lands in 4c (#1760).
//!
//! Pure: no I/O, no clock reads — `now` is injected — so every branch
//! (fresh election, renew, conflict, expiry-steal, term-bump) is
//! deterministically unit-testable with no real timers.

use crate::models::action::Lease;
use crate::signed_events::{SignedEvent, payload_hash};

/// `signed_events.event_type` for an R6-committed `(term, seq)` assignment
/// (#1760). The append-only chain of these events is the durable,
/// tamper-evident record of the agreed total order.
pub const R6_ASSIGNMENT_COMMITTED_EVENT: &str = "r6.assignment.committed";

/// The sequencer's leadership view: a monotonically-increasing `term` and
/// the current leader's holder id.
///
/// `term` increments every time leadership changes hands (a new holder
/// acquires after the prior lease expired). It is the **fencing token**
/// the 4b quorum uses to reject a deposed leader's `(term, seq)`
/// assignments. The [`Default`] (`term == 0`, `leader == None`) is the
/// pre-election initial state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequencerState {
    /// Monotonic leadership epoch — the fencing token. Never decreases.
    pub term: i64,
    /// The current leader's holder id, or `None` before the first election.
    pub leader: Option<String>,
}

/// The verdict of evaluating a leadership-acquisition attempt against the
/// current [`SequencerState`] and the existing lease (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeadershipOutcome {
    /// `candidate` acquired (or won) leadership; carries the new,
    /// bumped `term` (the fencing token for this leadership epoch).
    Acquired {
        /// The new leadership epoch — `prior term + 1`.
        term: i64,
    },
    /// `candidate` already held leadership and renewed it; `term`
    /// unchanged (leadership did not change hands).
    Renewed {
        /// The unchanged leadership epoch.
        term: i64,
    },
    /// A non-expired lease held by a different holder blocks acquisition;
    /// the state is unchanged.
    Conflict {
        /// The holder that currently owns the non-expired lease.
        current_leader: String,
    },
}

impl SequencerState {
    /// Evaluate a leadership-acquisition attempt by `candidate` at `now`
    /// against the current state and the `existing` leases-row snapshot
    /// (if one exists). **Pure** — does not mutate; the caller applies the
    /// verdict via [`SequencerState::apply`].
    ///
    /// Mirrors [`crate::actions::lease_acquire`] and lifts it to the term:
    ///
    /// * a non-expired lease held by a DIFFERENT holder ⇒
    ///   [`LeadershipOutcome::Conflict`] (no leadership change);
    /// * the current leader re-acquiring (same holder) ⇒
    ///   [`LeadershipOutcome::Renewed`], `term` UNCHANGED;
    /// * an expired/absent lease taken by a NEW holder ⇒
    ///   [`LeadershipOutcome::Acquired`] with `term` BUMPED by 1, fencing
    ///   the prior leader.
    #[must_use]
    pub fn evaluate(
        &self,
        existing: Option<&Lease>,
        candidate: &str,
        now: i64,
    ) -> LeadershipOutcome {
        // Liveness gate (mirrors `lease_acquire`): a non-expired lease held
        // by another holder blocks acquisition. NOTE: this is liveness, not
        // safety — the term-fence at the 4b quorum is the safety boundary.
        if let Some(l) = existing
            && l.expires_at > now
            && l.holder != candidate
        {
            return LeadershipOutcome::Conflict {
                current_leader: l.holder.clone(),
            };
        }
        // The current leader re-acquiring (renew, or re-take its own
        // expired lease) keeps the term — leadership did not change hands.
        if self.leader.as_deref() == Some(candidate) {
            return LeadershipOutcome::Renewed { term: self.term };
        }
        // A new holder takes leadership ⇒ bump the term to fence the prior
        // leader. `term` is monotonic: this is the only path that changes it.
        LeadershipOutcome::Acquired {
            term: self.term + 1,
        }
    }

    /// Apply an [`SequencerState::evaluate`] verdict, advancing the state.
    /// Only [`LeadershipOutcome::Acquired`] mutates (new leader + bumped
    /// term); [`LeadershipOutcome::Renewed`] / [`LeadershipOutcome::Conflict`]
    /// leave the state untouched.
    pub fn apply(&mut self, outcome: &LeadershipOutcome, candidate: &str) {
        if let LeadershipOutcome::Acquired { term } = outcome {
            self.term = *term;
            self.leader = Some(candidate.to_string());
        }
    }

    /// Convenience: [`evaluate`](SequencerState::evaluate) then
    /// [`apply`](SequencerState::apply) in one call, returning the verdict.
    pub fn acquire(
        &mut self,
        existing: Option<&Lease>,
        candidate: &str,
        now: i64,
    ) -> LeadershipOutcome {
        let outcome = self.evaluate(existing, candidate, now);
        self.apply(&outcome, candidate);
        outcome
    }
}

/// One acceptor's persisted fencing state (#1759 / R6 item 4b): the
/// highest leadership `term` this acceptor has acknowledged.
///
/// This is the **safety boundary** of R6 (NOT the time-based lease, which
/// is liveness only). Each peer in the quorum holds an `AcceptorState`;
/// before acking a leader's `(term, seq)` assignment it votes via
/// [`AcceptorState::vote`], which advances `max_term_seen` on an ack and
/// rejects any stale term. Once a quorum has advanced to term `T` (by
/// acking the new leader), a deposed leader proposing `T' < T` cannot
/// collect `W` acks — its assignment never commits — closing the
/// two-live-leaders split-brain hole that the lease alone cannot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptorState {
    /// Highest leadership `term` acknowledged by this acceptor. Monotonic.
    pub max_term_seen: i64,
}

/// An acceptor's vote on a proposed leadership `term`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptorVote {
    /// The proposed term was `>= max_term_seen`; the acceptor advanced its
    /// `max_term_seen` to the proposed term and ACKed.
    Ack,
    /// The proposed term was stale (`< max_term_seen`); rejected. Carries
    /// the acceptor's current `max_term_seen` so the stale leader learns
    /// the newer term and steps down.
    RejectStaleTerm {
        /// The acceptor's current (higher) `max_term_seen`.
        max_term_seen: i64,
    },
}

impl AcceptorState {
    /// Vote on a proposed leadership `term`. A term `>= max_term_seen` is
    /// accepted (advancing `max_term_seen` — the fencing bump); a stale
    /// term (`< max_term_seen`) is rejected with no state change.
    pub fn vote(&mut self, proposed_term: i64) -> AcceptorVote {
        if proposed_term >= self.max_term_seen {
            self.max_term_seen = proposed_term;
            AcceptorVote::Ack
        } else {
            AcceptorVote::RejectStaleTerm {
                max_term_seen: self.max_term_seen,
            }
        }
    }
}

/// Verdict of a quorum-committed `(term, seq)` assignment attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentOutcome {
    /// `>= W` term-fenced acceptors ACKed → the assignment is committed.
    Committed {
        /// The committed leadership epoch.
        term: i64,
        /// The committed sequence slot (the agreed total order).
        seq: i64,
        /// How many acceptors ACKed (`>= W`).
        acks: usize,
    },
    /// Fewer than `W` acceptors ACKed — a stale term was rejected by the
    /// up-to-date quorum, or too many peers were unreachable.
    Rejected {
        /// The proposed (rejected) leadership epoch.
        term: i64,
        /// How many acceptors ACKed (`< W`).
        acks: usize,
        /// The required ack count `W`.
        needed: usize,
    },
}

/// Drive one quorum round to commit a `(term, seq)` assignment (#1759 / R6
/// item 4b): every acceptor in `quorum` votes (term-fenced via
/// [`AcceptorState::vote`]); an [`AcceptorVote::Ack`] counts toward `W`.
/// Commits iff `acks >= w`.
///
/// **Pure** — this is the W-of-N quorum lifted to the VALUE level (the
/// genuine net-new beyond a bare ack-count: it enforces "`W` acceptors
/// AGREED on this term's assignment", not merely "`W` answered"). A stale
/// leader whose `term` is below the quorum's `max_term_seen` collects
/// fewer than `W` acks and is `Rejected`, so two leaders can never both
/// commit. Wiring acceptor votes over the network into the leader's
/// [`crate::replication::AckTracker`] + the `signed_events` ordered log is
/// 4c (#1760).
#[must_use]
pub fn commit_assignment(
    quorum: &mut [AcceptorState],
    term: i64,
    seq: i64,
    w: usize,
) -> AssignmentOutcome {
    let mut acks = 0usize;
    for acceptor in quorum.iter_mut() {
        if acceptor.vote(term) == AcceptorVote::Ack {
            acks += 1;
        }
    }
    if acks >= w {
        AssignmentOutcome::Committed { term, seq, acks }
    } else {
        AssignmentOutcome::Rejected {
            term,
            acks,
            needed: w,
        }
    }
}

/// A committed R6 assignment (#1760): the operation `op` was agreed to
/// occupy slot `seq` under leadership epoch `term`. The pair `(term, seq)`
/// is the agreed TOTAL ORDER key — ordered by `term`, then `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAssignment {
    /// The leadership epoch that committed this assignment.
    pub term: i64,
    /// The slot within the epoch (per-`term` monotonic from 0).
    pub seq: i64,
    /// The committed operation payload.
    pub op: String,
}

/// The R6 quorum-elected sequencer (#1760 item 4c) — the in-process
/// integration of the leadership state machine (4a) and the term-fenced
/// W-of-N quorum (4b).
///
/// A node runs [`Sequencer::commit_op`] to propose an operation: it
/// acquires/renews leadership via the lease (liveness), assigns the next
/// `(term, seq)`, and commits the assignment through the term-fenced
/// quorum (safety). On success the committed `(term, seq, op)` is appended
/// to the `signed_events` log via [`committed_assignment_event`] — the
/// append-only, hash-chained chain of those events IS the durable,
/// tamper-evident agreed total order (commit-once / never-retract, so the
/// chain is never broken by a leader change).
///
/// **Boundary (documented per the vote `4d3ea1c5`):** this is a
/// quorum-ordered + leader-serialized + term-fenced total order. It is
/// NOT partition-linearizable beyond the term-fence — under a partition a
/// minority leader simply cannot commit (it never reaches `W`). The
/// leadership `term` is recoverable from the log (the max committed term),
/// so no separate leader-lease table is persisted; a wire transport / SAL
/// surface binds when a real R6 consumer lands.
#[derive(Debug, Clone, Default)]
pub struct Sequencer {
    /// Leadership view (4a).
    pub state: SequencerState,
    /// Next slot to assign within the current `term`. Reset on each
    /// leadership change so every epoch has its own `seq` space.
    next_seq: i64,
}

impl Sequencer {
    /// A fresh sequencer (no leader, term 0).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run one R6 round for `candidate` proposing `op` against the `quorum`
    /// of acceptors (each term-fenced) requiring `w` acks, at injected
    /// `now` with the current leader-`lease` snapshot.
    ///
    /// Returns the [`CommittedAssignment`] on success, or `None` when
    /// `candidate` is not the leader (a live lease is held by another) or
    /// the quorum rejected the assignment (a stale `term` was fenced, or
    /// too few acceptors were reachable). Pure — no I/O, `now` injected.
    pub fn commit_op(
        &mut self,
        quorum: &mut [AcceptorState],
        lease: Option<&Lease>,
        candidate: &str,
        op: &str,
        w: usize,
        now: i64,
    ) -> Option<CommittedAssignment> {
        let term = match self.state.evaluate(lease, candidate, now) {
            // A live lease held by another holder ⇒ not the leader.
            LeadershipOutcome::Conflict { .. } => return None,
            // Leadership changed hands ⇒ a NEW epoch. The term is GLOBAL,
            // not node-local: a new leader fences the prior one by claiming
            // strictly above the quorum's highest acknowledged term (so a
            // fresh node taking over does not collide with the prior term).
            // A fresh per-`term` seq space starts at 0.
            LeadershipOutcome::Acquired { .. } => {
                let quorum_max = quorum.iter().map(|a| a.max_term_seen).max().unwrap_or(0);
                let new_term = quorum_max.max(self.state.term) + 1;
                self.state.term = new_term;
                self.state.leader = Some(candidate.to_string());
                self.next_seq = 0;
                new_term
            }
            // The current leader re-acquiring keeps its OWN epoch's term —
            // a deposed leader that still believes it leads (clock skew)
            // therefore proposes its STALE term and is fenced by the quorum.
            LeadershipOutcome::Renewed { .. } => self.state.term,
        };
        let seq = self.next_seq;
        match commit_assignment(quorum, term, seq, w) {
            AssignmentOutcome::Committed { .. } => {
                self.next_seq += 1;
                Some(CommittedAssignment {
                    term,
                    seq,
                    op: op.to_string(),
                })
            }
            AssignmentOutcome::Rejected { .. } => None,
        }
    }
}

/// Build the append-ready [`SignedEvent`] for a committed R6 assignment
/// (#1760): a deterministic id `r6:<term>:<seq>` (one per slot, so the
/// `signed_events` `(id)` PK enforces the commit-once / single-value
/// invariant), the `payload_hash` over the canonical `(term, seq, op)`
/// bytes, and the [`R6_ASSIGNMENT_COMMITTED_EVENT`] type. `prev_hash` and
/// `sequence` are left empty for [`crate::signed_events::append_signed_event`]
/// to fill (the hash chain + monotonic rank). Unsigned by default; the
/// daemon signing key is applied by the append path when present.
#[must_use]
pub fn committed_assignment_event(
    agent_id: &str,
    assignment: &CommittedAssignment,
    timestamp: &str,
) -> SignedEvent {
    let canonical = format!(
        "{}\u{0}{}\u{0}{}",
        assignment.term, assignment.seq, assignment.op
    );
    SignedEvent {
        id: format!("r6:{}:{}", assignment.term, assignment.seq),
        agent_id: agent_id.to_string(),
        event_type: R6_ASSIGNMENT_COMMITTED_EVENT.to_string(),
        payload_hash: payload_hash(canonical.as_bytes()),
        attest_level: "unsigned".to_string(),
        timestamp: timestamp.to_string(),
        ..SignedEvent::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(holder: &str, expires_at: i64) -> Lease {
        Lease {
            action_id: "_seq_leader:default".to_string(),
            holder: holder.to_string(),
            acquired_at: 0,
            expires_at,
            heartbeat_at: 0,
        }
    }

    #[test]
    fn fresh_election_acquires_term_1() {
        let mut s = SequencerState::default();
        let out = s.acquire(None, "node-a", 100);
        assert_eq!(out, LeadershipOutcome::Acquired { term: 1 });
        assert_eq!(s.term, 1);
        assert_eq!(s.leader.as_deref(), Some("node-a"));
    }

    #[test]
    fn same_leader_renew_keeps_term() {
        let mut s = SequencerState::default();
        s.acquire(None, "node-a", 100); // term 1
        // Lease still held by node-a, not expired (expires 200 > now 150).
        let out = s.acquire(Some(&lease("node-a", 200)), "node-a", 150);
        assert_eq!(out, LeadershipOutcome::Renewed { term: 1 });
        assert_eq!(s.term, 1, "renew does not bump the term");
        assert_eq!(s.leader.as_deref(), Some("node-a"));
    }

    #[test]
    fn non_expired_lease_by_other_conflicts() {
        let mut s = SequencerState::default();
        s.acquire(None, "node-a", 100); // term 1, leader a
        // node-b tries while a's lease is live (expires 200 > now 150).
        let out = s.acquire(Some(&lease("node-a", 200)), "node-b", 150);
        assert_eq!(
            out,
            LeadershipOutcome::Conflict {
                current_leader: "node-a".to_string()
            }
        );
        // State unchanged — b did not win.
        assert_eq!(s.term, 1);
        assert_eq!(s.leader.as_deref(), Some("node-a"));
    }

    #[test]
    fn expiry_steal_by_new_holder_bumps_term() {
        let mut s = SequencerState::default();
        s.acquire(None, "node-a", 100); // term 1, leader a
        // a's lease expired (expires 200 <= now 250); b takes leadership.
        let out = s.acquire(Some(&lease("node-a", 200)), "node-b", 250);
        assert_eq!(out, LeadershipOutcome::Acquired { term: 2 });
        assert_eq!(s.term, 2, "leadership change fences the prior leader");
        assert_eq!(s.leader.as_deref(), Some("node-b"));
    }

    #[test]
    fn same_holder_reacquires_expired_lease_keeps_term() {
        let mut s = SequencerState::default();
        s.acquire(None, "node-a", 100); // term 1
        // a's own lease expired but a re-takes it — leadership did not
        // change hands, so the term is preserved.
        let out = s.acquire(Some(&lease("node-a", 200)), "node-a", 250);
        assert_eq!(out, LeadershipOutcome::Renewed { term: 1 });
        assert_eq!(s.term, 1);
    }

    #[test]
    fn term_is_monotonic_across_leadership_changes() {
        let mut s = SequencerState::default();
        s.acquire(None, "node-a", 100); // term 1
        s.acquire(Some(&lease("node-a", 200)), "node-b", 250); // term 2
        s.acquire(Some(&lease("node-b", 400)), "node-c", 450); // term 3
        assert_eq!(s.term, 3);
        assert_eq!(s.leader.as_deref(), Some("node-c"));
        // A conflict in between never regresses the term.
        let out = s.acquire(Some(&lease("node-c", 600)), "node-a", 500);
        assert!(matches!(out, LeadershipOutcome::Conflict { .. }));
        assert_eq!(s.term, 3, "a blocked acquisition never changes the term");
    }

    #[test]
    fn evaluate_is_pure_apply_is_separate() {
        let s = SequencerState::default();
        let out = s.evaluate(None, "node-a", 100);
        // evaluate did not mutate.
        assert_eq!(s.term, 0);
        assert_eq!(s.leader, None);
        assert_eq!(out, LeadershipOutcome::Acquired { term: 1 });
    }

    // ---- 4b: acceptor term-fence + quorum-committed assignment --------

    #[test]
    fn acceptor_acks_equal_or_newer_term_and_advances() {
        let mut a = AcceptorState::default(); // max 0
        assert_eq!(a.vote(1), AcceptorVote::Ack);
        assert_eq!(a.max_term_seen, 1);
        // Equal term still acks (idempotent re-propose), max unchanged.
        assert_eq!(a.vote(1), AcceptorVote::Ack);
        assert_eq!(a.max_term_seen, 1);
        // Newer term acks + advances.
        assert_eq!(a.vote(5), AcceptorVote::Ack);
        assert_eq!(a.max_term_seen, 5);
    }

    #[test]
    fn acceptor_rejects_stale_term_without_state_change() {
        let mut a = AcceptorState::default();
        a.vote(3); // max 3
        assert_eq!(
            a.vote(2),
            AcceptorVote::RejectStaleTerm { max_term_seen: 3 }
        );
        assert_eq!(a.max_term_seen, 3, "a stale vote does not change the max");
    }

    #[test]
    fn commit_assignment_commits_with_quorum() {
        let mut q = vec![AcceptorState::default(); 3];
        let out = commit_assignment(&mut q, 1, 10, 2);
        assert_eq!(
            out,
            AssignmentOutcome::Committed {
                term: 1,
                seq: 10,
                acks: 3
            }
        );
        // All acceptors advanced to term 1.
        assert!(q.iter().all(|a| a.max_term_seen == 1));
    }

    #[test]
    fn commit_assignment_rejected_below_w() {
        // A 3-node quorum already advanced to term 2; a stale term-1
        // proposal is rejected by all → 0 acks < W=2.
        let mut q = vec![AcceptorState { max_term_seen: 2 }; 3];
        let out = commit_assignment(&mut q, 1, 10, 2);
        assert_eq!(
            out,
            AssignmentOutcome::Rejected {
                term: 1,
                acks: 0,
                needed: 2
            }
        );
    }

    #[test]
    fn two_leaders_only_one_commits_a_slot() {
        // The load-bearing R6 SAFETY property: once a quorum has advanced
        // to a new leader's term, the deposed leader cannot commit.
        let mut q = vec![AcceptorState::default(); 3]; // 3 acceptors, W = majority = 2
        let w = 2;

        // Leader A (term 1) commits seq 10.
        assert!(matches!(
            commit_assignment(&mut q, 1, 10, w),
            AssignmentOutcome::Committed { .. }
        ));

        // Leadership changes — Leader B (term 2) commits seq 11; the quorum
        // advances to term 2.
        assert!(matches!(
            commit_assignment(&mut q, 2, 11, w),
            AssignmentOutcome::Committed { .. }
        ));

        // Deposed Leader A (still on term 1) tries to commit again — every
        // up-to-date acceptor rejects the stale term, so A cannot reach W.
        let stale = commit_assignment(&mut q, 1, 12, w);
        assert!(
            matches!(stale, AssignmentOutcome::Rejected { acks: 0, .. }),
            "a deposed leader's stale-term assignment must NOT commit, got {stale:?}"
        );
    }

    #[test]
    fn partial_quorum_partition_does_not_commit() {
        // Only 1 of 3 acceptors reachable (the other two never vote) →
        // 1 ack < W=2 → not committed (no false commit under partition).
        let mut reachable = vec![AcceptorState::default(); 1];
        let out = commit_assignment(&mut reachable, 1, 10, 2);
        assert!(matches!(
            out,
            AssignmentOutcome::Rejected {
                acks: 1,
                needed: 2,
                ..
            }
        ));
    }

    // ---- 4c: Sequencer integration + durable-log event + interleaving --

    fn lease_of(holder: &str, expires_at: i64) -> Lease {
        Lease {
            action_id: "_seq_leader:default".to_string(),
            holder: holder.to_string(),
            acquired_at: 0,
            expires_at,
            heartbeat_at: 0,
        }
    }

    #[test]
    fn sequencer_commits_ops_in_per_term_order() {
        let mut q = vec![AcceptorState::default(); 3];
        let mut s = Sequencer::new();
        let a = s.commit_op(&mut q, None, "A", "op1", 2, 100).unwrap();
        let b = s
            .commit_op(&mut q, Some(&lease_of("A", 500)), "A", "op2", 2, 150)
            .unwrap();
        let c = s
            .commit_op(&mut q, Some(&lease_of("A", 500)), "A", "op3", 2, 200)
            .unwrap();
        assert_eq!((a.term, a.seq, a.op.as_str()), (1, 0, "op1"));
        assert_eq!((b.term, b.seq, b.op.as_str()), (1, 1, "op2"));
        assert_eq!((c.term, c.seq, c.op.as_str()), (1, 2, "op3"));
    }

    #[test]
    fn sequencer_non_leader_does_not_commit() {
        let mut q = vec![AcceptorState::default(); 3];
        // A holds a live lease; B is not the leader → no commit.
        let mut b = Sequencer::new();
        let out = b.commit_op(&mut q, Some(&lease_of("A", 500)), "B", "op", 2, 100);
        assert!(out.is_none());
    }

    #[test]
    fn sequencer_new_term_resets_seq_space() {
        let mut q = vec![AcceptorState::default(); 3];
        let mut a = Sequencer::new();
        a.commit_op(&mut q, None, "A", "op1", 2, 100); // (1, 0)
        a.commit_op(&mut q, Some(&lease_of("A", 200)), "A", "op2", 2, 150); // (1, 1)
        // B takes over (A's lease expired) → new term 2, seq resets to 0.
        let mut b = Sequencer::new();
        let first = b
            .commit_op(&mut q, Some(&lease_of("A", 200)), "B", "op3", 2, 250)
            .unwrap();
        assert_eq!(
            (first.term, first.seq),
            (2, 0),
            "new leadership epoch restarts the seq space"
        );
    }

    #[test]
    fn committed_assignment_event_is_deterministic_per_slot() {
        let asg = CommittedAssignment {
            term: 2,
            seq: 5,
            op: "op-x".to_string(),
        };
        let e1 = committed_assignment_event("node-a", &asg, "2026-06-20T00:00:00+00:00");
        let e2 = committed_assignment_event("node-a", &asg, "2026-06-20T00:00:00+00:00");
        // Deterministic id pins one event per (term, seq) slot (the
        // signed_events PK then enforces commit-once at the DB).
        assert_eq!(e1.id, "r6:2:5");
        assert_eq!(e1.event_type, R6_ASSIGNMENT_COMMITTED_EVENT);
        assert_eq!(e1.payload_hash.len(), 32, "sha256 digest");
        assert_eq!(
            e1.payload_hash, e2.payload_hash,
            "stable hash for the same assignment"
        );
        // prev_hash / sequence left empty for the append path to fill.
        assert!(e1.prev_hash.is_empty());
        assert_eq!(e1.sequence, 0);
    }

    /// The load-bearing R6 end-to-end SAFETY proof (the vote's interleaving
    /// requirement): a deposed leader that STILL BELIEVES it holds
    /// leadership (clock skew — it sees its own lease as live) is fenced by
    /// the quorum's `term`, not the lease, so it cannot commit; and no two
    /// committed assignments ever share a `(term, seq)` slot.
    #[test]
    fn interleaving_deposed_leader_is_fenced_by_quorum_term() {
        let mut quorum = vec![AcceptorState::default(); 3];
        let w = 2;
        let mut committed: Vec<(i64, i64)> = Vec::new();

        // A leads at term 1, commits (1, 0).
        let mut a = Sequencer::new();
        let c1 = a.commit_op(&mut quorum, None, "A", "op1", w, 100).unwrap();
        committed.push((c1.term, c1.seq));

        // B takes leadership (A's lease expired at 200, now 250), term 2,
        // commits (2, 0) — the quorum advances its max_term to 2.
        let mut b = Sequencer::new();
        let c2 = b
            .commit_op(&mut quorum, Some(&lease_of("A", 200)), "B", "op2", w, 250)
            .unwrap();
        committed.push((c2.term, c2.seq));

        // DEPOSED A still thinks it is leader: clock skew makes its OWN
        // lease look live (now 150 < expires 200), so the liveness gate
        // passes (A "renews") and A proposes again at its stale term 1.
        // The quorum's term-fence (max_term = 2) REJECTS it → not committed.
        let fenced = a.commit_op(&mut quorum, Some(&lease_of("A", 200)), "A", "op3", w, 150);
        assert!(
            fenced.is_none(),
            "a deposed leader's stale-term op MUST be fenced by the quorum (not the lease), got {fenced:?}"
        );

        // Single total order: every committed slot is unique.
        let mut sorted = committed.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            committed.len(),
            "no two committed assignments may share a (term, seq) slot"
        );
        assert_eq!(committed, vec![(1, 0), (2, 0)]);
    }
}
