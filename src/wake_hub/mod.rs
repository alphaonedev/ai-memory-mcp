// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` — a same-host, content-free agent wake plane
//! (issue [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467),
//! EPIC [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! # What it is
//!
//! A Unix-domain-socket switch that pushes a bounded, content-free WAKE HINT to
//! agents on this host, so a recipient learns "you have inbox row X" in about a
//! millisecond instead of on its next three-minute poll.
//!
//! # What it is NOT — the contract that makes it safe
//!
//! * **It carries no message bodies.** Structurally: the v1 protocol has no
//!   `request` / `reply` / `notify` kinds (their wire numbers are refused by
//!   name), and the largest routed payload is a 256-byte
//!   [`frame::WakeMeta`] hint of `{inbox_row_id, namespace, sender, digest,
//!   seq_high_watermark}`.
//! * **It holds no durable truth.** The ai-memory inbox row is the record; the
//!   wake is a hint; a `<=60 s` backstop poll remains the guarantee. Losing the
//!   hub degrades wake LATENCY and nothing else, which is why every limit here
//!   may drop a hint but none may ever produce a wrong result.
//! * **It is not a second identity registry.** Peer admission is the kernel's
//!   `SO_PEERCRED` (Linux) / `LOCAL_PEERPID` + `getpeereid` (macOS); agent
//!   admission is a scoped `a2a-hub/join/v1` delegation from the enrolled
//!   ai-memory key, verified behind [`identity::HelloVerifier`]. The verifier
//!   shipped by THIS issue is [`identity::DenyAllVerifier`] — it refuses every
//!   hello, because the delegation lands in
//!   [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468) and a
//!   hub that admitted unauthenticated peers "until identity lands" would be
//!   exactly the fail-open default the North Star forbids.
//! * **It never touches the store.** No `db::open`, no SQL, no Postgres path,
//!   no filesystem state beyond its own socket — so the `postgres://`
//!   phantom-sqlite class (#2490 / #2572) is structurally out of reach.
//!
//! # Module map
//!
//! | Module | Owns |
//! |---|---|
//! | [`limits`] | every bound, in bytes; the token bucket; the global egress budget |
//! | [`frame`] | the wire format, the kinds, the error codes |
//! | [`codec`] | `LengthDelimitedCodec` with the one `max_frame_length` |
//! | [`identity`] | the two admission traits and the domain-separated transcripts |
//! | [`routing`] | sharded session/topic tables, per-recipient queues, fan-out |
//! | [`pending`] | the coalesced offline set |
//! | [`startup`] | the peer-pid probe, the fd budget, the socket posture |
//! | [`server`] | listener, accept loop, drain |
//! | `conn` | one connection's state machine |
//! | [`metrics`] | counters, gauges and latency histograms for every refusal and delivery path |
//! | [`histogram`] | the fixed-bucket, allocation-free latency histogram those read |
//! | [`health`] | the `--health` probe: an ordinary client that reads the challenge and leaves |
//!
//! # Testing
//!
//! There is deliberately no CLI flag that swaps the verifier out. Tests drive
//! the hub through [`server::WakeHub::bind`] with their own
//! [`identity::HelloVerifier`] implementation, so the shipped binary has no
//! bypass to find.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rand_core::RngCore;

use identity::{DenyAllVerifier, HelloVerifier, PeerAuthorizer, SameUidAuthorizer};
use limits::{
    DEFAULT_GLOBAL_EGRESS_BYTES, DEFAULT_HANDSHAKE_TIMEOUT_MS, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS, DEFAULT_RATE_BURST,
    DEFAULT_RATE_TOKENS_PER_SEC, DEFAULT_RECIPIENT_QUEUE_BYTES, DEFAULT_RECIPIENT_QUEUE_FRAMES,
    DEFAULT_RECONNECT_BASE_MS, DEFAULT_RECONNECT_JITTER_MS, EgressBudget, HELLO_NONCE_BYTES,
    PREAUTH_RATE_BURST, PREAUTH_RATE_TOKENS_PER_SEC,
};
use metrics::{HubCensus, HubMetrics, MetricsSnapshot};
use pending::PendingStore;
use routing::Router;

/// v1.0.0 #3504 — the live hub's store-free allowlist resolver: the
/// permission-checked, inode/mtime-keyed reuse of the parsed snapshot that
/// [`delegation_verifier::AllowlistCache`] represents, plus the snapshot-age
/// posture `wake-hub --posture` reports.
pub mod allowlist_reload;
pub mod codec;
mod conn;
/// v1.0.0 #3468 — the scoped `a2a-hub/join/v1` delegation verifier that
/// replaces [`identity::DenyAllVerifier`] in production. Holds only public
/// material. Refreshed public snapshots, bounded certificate expiry and
/// audit-spine events provide revocation.
pub mod delegation_verifier;
pub mod frame;
/// v1.0.0 #3471 — the `wake-hub --health` probe. An ordinary client that reads
/// the hub's opening challenge and leaves; deliberately NOT a privileged side
/// channel and NOT a bypass of the peer-credential gate.
pub mod health;
/// v1.0.0 #3471 — fixed-bucket, allocation-free latency histograms. The ops
/// surface must not be something the hub can be made to allocate.
pub mod histogram;
pub mod identity;
pub mod limits;
pub mod metrics;
pub mod pending;
pub mod routing;
pub mod server;
pub mod startup;

pub use server::WakeHub;

/// Default socket file name inside the hub's runtime directory.
pub const SOCKET_FILE_NAME: &str = "wake-hub.sock";

/// Default hub identifier, bound into every handshake transcript.
pub const DEFAULT_HUB_ID: &str = "ai-memory-wake-hub";

/// Operator-tunable hub parameters. Every field has a bounded default from
/// [`limits`]; nothing here is unbounded and nothing defaults to permissive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubConfig {
    /// Unix socket to listen on. Its parent directory must be owner-only.
    pub socket_path: PathBuf,
    /// This hub's identifier, bound into the hello and membership transcripts
    /// so a signature for one hub cannot be replayed at another.
    pub hub_id: String,
    /// Hard connection ceiling, further clamped by `RLIMIT_NOFILE` at start-up.
    pub max_connections: usize,
    /// Per-recipient queue depth in frames.
    pub queue_frames: usize,
    /// Per-recipient queue ceiling in bytes.
    pub queue_bytes: usize,
    /// Hub-wide ceiling on queued egress bytes.
    pub global_egress_bytes: usize,
    /// Authenticated frames per second, per connection.
    pub rate_per_sec: u32,
    /// Authenticated burst, per connection.
    pub rate_burst: u32,
    /// Pre-authentication frames per second.
    pub preauth_rate_per_sec: u32,
    /// Pre-authentication burst.
    pub preauth_burst: u32,
    /// Deadline for completing the handshake.
    pub handshake_timeout: Duration,
    /// Agents for which coalesced offline state is retained.
    pub pending_max_agents: usize,
    /// Inbox-row ids retained per offline agent.
    pub pending_max_ids: usize,
    /// Base reconnect backoff advertised in `welcome`, in milliseconds.
    pub reconnect_base_ms: u32,
    /// Reconnect jitter span advertised in `welcome`, in milliseconds. Clients
    /// wait `base + rand(0, jitter)` so a hub restart does not produce a
    /// synchronised 256-way handshake blast.
    pub reconnect_jitter_ms: u32,
    /// Derived allowlist cache of enrolled agent keys (#3468). `None` means no
    /// allowlist is configured, so the hub admits nobody — the fail-closed
    /// default, not a degraded mode to be worked around.
    pub allowlist_path: Option<PathBuf>,
}

impl HubConfig {
    /// The default socket path: the platform runtime directory when there is
    /// one, else `~/.ai-memory`.
    ///
    /// # Errors
    ///
    /// Fails when neither a runtime directory nor a home directory can be
    /// resolved — the hub then has nowhere private to put a socket and must not
    /// guess (a guessed path in a shared directory is a world-reachable hub).
    pub fn default_socket_path() -> anyhow::Result<PathBuf> {
        let base = dirs::runtime_dir()
            .map(|d| d.join("ai-memory"))
            .or_else(|| dirs::home_dir().map(|h| h.join(".ai-memory")))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "wake-hub: neither a runtime directory nor a home directory could be \
                     resolved, so there is nowhere private to place the socket. Pass \
                     --socket explicitly."
                )
            })?;
        Ok(base.join(SOCKET_FILE_NAME))
    }

    /// Defaults with an explicit socket path.
    #[must_use]
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            hub_id: DEFAULT_HUB_ID.to_string(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            queue_frames: DEFAULT_RECIPIENT_QUEUE_FRAMES,
            queue_bytes: DEFAULT_RECIPIENT_QUEUE_BYTES,
            global_egress_bytes: DEFAULT_GLOBAL_EGRESS_BYTES,
            rate_per_sec: DEFAULT_RATE_TOKENS_PER_SEC,
            rate_burst: DEFAULT_RATE_BURST,
            preauth_rate_per_sec: PREAUTH_RATE_TOKENS_PER_SEC,
            preauth_burst: PREAUTH_RATE_BURST,
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            pending_max_agents: DEFAULT_PENDING_MAX_AGENTS,
            pending_max_ids: DEFAULT_PENDING_MAX_IDS,
            reconnect_base_ms: DEFAULT_RECONNECT_BASE_MS,
            reconnect_jitter_ms: DEFAULT_RECONNECT_JITTER_MS,
            allowlist_path: None,
        }
    }
}

/// The injected admission gates.
///
/// Both default to the production choice: same-uid peers only, and NO hello
/// accepted until the scoped delegation lands in #3468.
#[derive(Clone)]
pub struct HubDeps {
    /// Kernel-attested peer-credential gate.
    pub peer_authorizer: Arc<dyn PeerAuthorizer>,
    /// Cryptographic handshake gate.
    pub verifier: Arc<dyn HelloVerifier>,
}

impl Default for HubDeps {
    fn default() -> Self {
        Self {
            peer_authorizer: Arc::new(SameUidAuthorizer::for_current_process()),
            verifier: Arc::new(DenyAllVerifier),
        }
    }
}

impl std::fmt::Debug for HubDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the gates themselves: a Debug line is a log line, and a
        // verifier's internals may hold key material.
        f.debug_struct("HubDeps")
            .field("peer_authorizer", &"<dyn PeerAuthorizer>")
            .field("verifier", &"<dyn HelloVerifier>")
            .finish()
    }
}

/// Everything shared by the accept loop and every connection task.
#[derive(Debug)]
pub struct HubState {
    cfg: HubConfig,
    deps: HubDeps,
    /// `Arc` because the substrate wake sink of
    /// [#3469](https://github.com/alphaonedev/ai-memory-mcp/issues/3469) holds
    /// the router for the life of the process, independently of the hub value
    /// that [`server::WakeHub::serve`] consumes.
    router: Arc<Router>,
    metrics: Arc<HubMetrics>,
}

impl HubState {
    /// Build the shared state from a config and its gates.
    #[must_use]
    pub fn new(cfg: HubConfig, deps: HubDeps) -> Self {
        let metrics = Arc::new(HubMetrics::default());
        let router = Router::new(
            cfg.queue_frames,
            cfg.queue_bytes,
            Arc::new(EgressBudget::new(cfg.global_egress_bytes)),
            PendingStore::new(cfg.pending_max_agents, cfg.pending_max_ids),
            Arc::clone(&metrics),
        );
        Self {
            cfg,
            deps,
            router: Arc::new(router),
            metrics,
        }
    }

    /// A fresh per-connection challenge nonce from the platform CSPRNG.
    #[must_use]
    pub fn new_nonce(&self) -> [u8; HELLO_NONCE_BYTES] {
        let mut nonce = [0u8; HELLO_NONCE_BYTES];
        rand_core::OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Snapshot every counter, gauge and histogram.
    ///
    /// The per-recipient gauges are COMPUTED here from the routing table
    /// (#3471) rather than maintained as a side table, so the hub keeps no
    /// per-agent metrics structure that a churn of agent ids could grow.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let census = self.router.queue_census();
        self.metrics.snapshot_with(HubCensus {
            egress_bytes_current: self.router.egress().used(),
            recipients_current: census.recipients,
            queued_bytes_current: census.queued_bytes,
            queued_frames_current: census.queued_frames,
            slow_consumers_current: census.slow_consumers,
        })
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(&self) -> &HubConfig {
        &self.cfg
    }

    /// The routing table, shared.
    ///
    /// Handed out so a CO-HOSTED hub can be fed from the in-process
    /// `agent_notified` bus (#3469) through the SAME `Router::deliver`
    /// injection point a peer-relayed wake uses — one set of queue, byte-cap,
    /// egress-budget and offline-coalescing rules for both, rather than a
    /// second privileged path into the hub.
    #[must_use]
    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded_and_non_permissive() {
        let cfg = HubConfig::with_socket_path(PathBuf::from("/tmp/x.sock"));
        assert!(cfg.max_connections > 0);
        assert!(cfg.queue_bytes > 0);
        assert!(cfg.global_egress_bytes >= cfg.queue_bytes);
        assert!(cfg.rate_burst >= cfg.rate_per_sec);
        assert!(
            cfg.preauth_burst < cfg.rate_burst,
            "an unauthenticated peer must never get the authenticated budget"
        );
        assert!(cfg.handshake_timeout > Duration::ZERO);
        assert!(cfg.reconnect_jitter_ms > 0, "reconnects must be jittered");
    }

    #[test]
    fn nonces_are_fresh_per_call() {
        let state = HubState::new(
            HubConfig::with_socket_path(PathBuf::from("/tmp/x.sock")),
            HubDeps::default(),
        );
        let a = state.new_nonce();
        let b = state.new_nonce();
        assert_ne!(a, b, "a reused challenge would make hello replayable");
        assert_ne!(a, [0u8; HELLO_NONCE_BYTES]);
    }

    #[test]
    fn the_default_verifier_refuses_every_hello() {
        use crate::wake_hub::identity::{DenyReason, HelloRequest, PeerCred};
        let deps = HubDeps::default();
        let topics: Vec<String> = Vec::new();
        let nonce = [3u8; HELLO_NONCE_BYTES];
        let req = HelloRequest {
            hub_id: DEFAULT_HUB_ID,
            nonce: &nonce,
            claimed_agent_id: "a",
            pubkey: &[0u8; 32],
            signature: &[0u8; 64],
            delegation: &[],
            topics: &topics,
            peer: PeerCred {
                uid: 0,
                gid: 0,
                pid: Some(1),
            },
        };
        assert_eq!(
            deps.verifier.verify(&req),
            Err(DenyReason::IdentityNotConfigured),
            "the shipped hub must not admit anyone until #3468 lands"
        );
    }

    #[test]
    fn debug_never_renders_the_gates() {
        let rendered = format!("{:?}", HubDeps::default());
        assert!(rendered.contains("<dyn HelloVerifier>"));
    }
}
