// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3654 — per-peer fan-out tasks that keep their peer on failure.
//!
//! Every `broadcast_*_quorum` lane spawns one task per peer into a
//! `JoinSet<(peer_id, outcome)>`. The peer id rides in the task's OUTPUT, so a
//! task that panicked or was cancelled — the one case where there is no
//! output — surfaced as a bare `JoinError` and the lanes logged
//! "peer join error" with no idea which peer it was.
//!
//! [`PeerTasks`] records the task id -> peer mapping at spawn time, so the
//! failure is attributed without the task's cooperation, and records the
//! failure against the peer's push freshness. Spawning without naming the peer
//! is not possible through this type.

use std::collections::HashMap;
use std::future::Future;

use tokio::task::{Id, JoinError, JoinSet};

/// Label used only if a finished task's id was somehow never registered.
/// Unreachable through [`PeerTasks::spawn`]; kept so a bookkeeping bug
/// degrades to an honest "unattributed" rather than a panic.
const UNATTRIBUTED_PEER: &str = "<unattributed>";

/// A fan-out task failure that still knows its peer.
#[derive(Debug)]
pub(super) struct PeerJoinError {
    /// `PeerEndpoint::id` of the peer whose task failed.
    pub peer_id: String,
    /// The underlying task failure.
    pub error: JoinError,
}

impl std::fmt::Display for PeerJoinError {
    /// Renders the peer's [`super::freshness::peer_label`], never the raw id:
    /// legacy and test configurations have used the peer URL as the id, and a
    /// URL can carry credentials. `peer_id` stays on the struct for routing.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "peer {}: {}",
            super::freshness::peer_label(&self.peer_id),
            self.error
        )
    }
}

impl std::error::Error for PeerJoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// A `JoinSet` of per-peer fan-out tasks.
pub(super) struct PeerTasks<T> {
    set: JoinSet<T>,
    peers: HashMap<Id, String>,
}

impl<T: Send + 'static> PeerTasks<T> {
    pub(super) fn new() -> Self {
        Self {
            set: JoinSet::new(),
            peers: HashMap::new(),
        }
    }

    /// Spawn `task` on behalf of `peer_id`.
    pub(super) fn spawn<F>(&mut self, peer_id: String, task: F)
    where
        F: Future<Output = T> + Send + 'static,
    {
        let handle = self.set.spawn(task);
        self.peers.insert(handle.id(), peer_id);
    }

    /// Next finished task. A failed task comes back as a [`PeerJoinError`]
    /// naming its peer, and the failure is recorded against that peer's push
    /// freshness.
    pub(super) async fn join_next(&mut self) -> Option<Result<T, PeerJoinError>> {
        match self.set.join_next_with_id().await? {
            Ok((id, value)) => {
                self.peers.remove(&id);
                Some(Ok(value))
            }
            Err(error) => {
                let peer_id = self
                    .peers
                    .remove(&error.id())
                    .unwrap_or_else(|| UNATTRIBUTED_PEER.to_string());
                super::freshness::record(
                    &peer_id,
                    super::freshness::Direction::Push,
                    super::freshness::Observation::Failure(
                        super::freshness::FailureClass::TaskFailed,
                    ),
                );
                Some(Err(PeerJoinError { peer_id, error }))
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicked_task_is_attributed_to_its_peer() {
        // A URL-shaped id with credentials: the Display must not render it.
        let peer = format!(
            "https://operator:hunter2@join-{}.example:9077",
            uuid::Uuid::new_v4()
        );
        let mut tasks: PeerTasks<u8> = PeerTasks::new();
        tasks.spawn("healthy".to_string(), async { 7 });
        tasks.spawn(peer.clone(), async { panic!("fan-out task blew up") });
        let mut ok = Vec::new();
        let mut failed = Vec::new();
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(v) => ok.push(v),
                Err(e) => failed.push(e),
            }
        }
        assert_eq!(ok, vec![7]);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].peer_id, peer);
        assert!(failed[0].error.is_panic());
        let rendered = failed[0].to_string();
        let label = super::super::freshness::peer_label(&peer);
        assert!(
            rendered.starts_with(&format!("peer {label}: ")),
            "{rendered}"
        );
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains(".example"), "{rendered}");
        let fresh = super::super::freshness::snapshot_for(&peer).expect("failure recorded");
        assert_eq!(fresh.push.consecutive_failures, 1);
        assert_eq!(fresh.push.last_failure_class, Some("task_failed"));
        assert!(tasks.is_empty());
    }
}
