// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` bounded-resource SSOT (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467), EPIC
//! [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! EVERY quantity the hub can be made to allocate is named here and bounded in
//! BYTES, not in frames. The rust-a2a 2x3 adversarial vote rejected the
//! original spec precisely because its queues were frame-counted (512 MiB of
//! reachable queue at 256 agents), its online egress was unbounded, and its
//! flat "100 frames/s" cap could not see fan-out amplification. This module is
//! the single place those four defects are fixed, so a reviewer can audit the
//! whole memory envelope by reading one file.
//!
//! North Star: the hub carries NO durable truth — the ai-memory inbox row is
//! the record and a <=60 s backstop poll is the guarantee — so every limit here
//! DEGRADES (refuse loudly to the sender, coalesce, or drop a hint) and never
//! corrupts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Wire envelope
// ---------------------------------------------------------------------------

/// Magic prefix on every frame body. Present INSIDE the length-delimited body
/// (the `u32` length prefix belongs to the codec) so a mis-framed or hostile
/// stream is rejected on the first frame instead of being interpreted.
pub const WIRE_MAGIC: [u8; 4] = *b"AWH1";

/// Protocol version. A frame carrying anything else is refused, never
/// best-effort parsed.
pub const WIRE_VERSION: u8 = 1;

/// Fixed header size in bytes: magic(4) + version(1) + kind(1) + flags(1)
/// + `from_len`(1) + `to_len`(1) + reserved(1) + `payload_len`(2) + `ts_ms`(8)
/// + `ttl_ms`(4).
pub const FRAME_HEADER_BYTES: usize = 24;

/// Maximum agent-id / topic length in bytes. The vote's item 7 fixed this at
/// "refuse ids over the limit instead of truncating"; ai-memory ids go to 128,
/// so 128 is the ceiling and 129 is a `400`, never a silent truncation.
pub const MAX_ID_BYTES: usize = 128;

/// Maximum `wake` metadata payload. The normative contract caps the
/// content-free hint `{inbox_row_id, namespace, sender, digest,
/// seq_high_watermark}` at 256 bytes.
pub const MAX_WAKE_META_BYTES: usize = 256;

/// Maximum payload of the handshake/subscription frame class
/// (`hello` / `join` / `depart` / `subscribe` / `unsubscribe`).
///
/// 2026-09-03 (#3468, Fable-approved): raised 1_024 -> 1_536 to admit the
/// scoped `a2a-hub/join/v1` delegation a `hello` now carries. At 1_024 the
/// budget was 32-byte key + 64-byte signature + up to 521 bytes of topics,
/// leaving ~15 bytes — not enough for a ~390-byte delegation, and shrinking
/// the topic allowance instead would have made the wire depend on how many
/// topics an agent happens to want. The routed classes are UNCHANGED: a
/// `wake` still cannot exceed [`MAX_WAKE_META_BYTES`] and a `ping` still
/// cannot exceed [`MAX_LIVENESS_PAYLOAD_BYTES`], so the fan-out envelope this
/// governs did not move.
pub const MAX_PAYLOAD_BYTES: usize = 1_536;

/// Maximum payload of a liveness frame (`ping` / `pong`). Named rather than a
/// bare literal at the match site so the hardcoded-literal gate has one
/// definition to point at.
pub const MAX_LIVENESS_PAYLOAD_BYTES: usize = 32;

/// Absolute frame ceiling handed to `LengthDelimitedCodec::max_frame_length`.
/// Derived, never hand-typed, so the codec bound and the field bounds cannot
/// drift apart.
pub const MAX_FRAME_BYTES: usize = FRAME_HEADER_BYTES + (2 * MAX_ID_BYTES) + MAX_PAYLOAD_BYTES;

/// Maximum topics a single `hello` / `subscribe` frame may assert.
pub const MAX_TOPICS_PER_FRAME: usize = 8;

/// Maximum topic length in bytes, including the leading `#`.
pub const MAX_TOPIC_BYTES: usize = 64;

/// Maximum topics one session may hold subscribed at once. A session that
/// tries to exceed it gets `403`, never a silently-truncated subscription.
pub const MAX_TOPICS_PER_SESSION: usize = 32;

/// v1.0.0 [#3505](https://github.com/alphaonedev/ai-memory-mcp/issues/3505) —
/// hard ceiling on the PROVEN readable-namespace set the derived allowlist
/// snapshot carries for ONE agent.
///
/// Tied to [`MAX_TOPICS_PER_SESSION`] on purpose: a session can never hold
/// more subscriptions than that, so carrying more proven namespaces than a
/// session could ever use buys nothing and only grows the snapshot every hello
/// re-reads. The exporter REFUSES to publish a set larger than this rather
/// than truncating one — a truncation would be silent, and which of an
/// agent's namespaces survived would then depend on ordering, which is exactly
/// the property #3504 refused to accept for "which key is trusted".
pub const MAX_READABLE_NAMESPACES: usize = MAX_TOPICS_PER_SESSION;

/// v1.0.0 #3505 — longest namespace a proven-read entry may carry, in bytes.
///
/// A topic is `#` + the namespace and is itself bounded by
/// [`MAX_TOPIC_BYTES`], so a longer namespace could never be subscribed to;
/// carrying one would be dead weight the hub must still parse.
pub const MAX_READABLE_NAMESPACE_BYTES: usize = MAX_TOPIC_BYTES - 1;

/// Length of the hub-issued handshake nonce, in bytes.
pub const HELLO_NONCE_BYTES: usize = 32;

/// Length of an Ed25519 public key, in bytes.
pub const PUBKEY_BYTES: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_BYTES: usize = 64;

/// Maximum encoded size of the scoped `a2a-hub/join/v1` delegation a `hello`
/// carries (#3468). Derived from the delegation's own element bounds:
/// version(1) + principal(1+128) + scope(1+32) + delegate key(32)
/// + hub id(1+64) + not_before(1+32) + not_after(1+32) + signature(64).
pub const MAX_DELEGATION_WIRE_BYTES: usize = 1 + 129 + 33 + 32 + 65 + 33 + 33 + 64;

/// Length of the content digest carried in `wake` metadata (SHA-256). A wake
/// carries the DIGEST of the inbox body, never the body.
pub const WAKE_DIGEST_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Steady-state frame budget per authenticated connection, in frames/second.
pub const DEFAULT_RATE_TOKENS_PER_SEC: u32 = 500;

/// Burst budget per authenticated connection, in frames.
pub const DEFAULT_RATE_BURST: u32 = 2_000;

/// Steady-state frame budget BEFORE the hello completes. A pre-auth peer gets
/// a handful of frames and a deadline, never the authenticated budget.
pub const PREAUTH_RATE_TOKENS_PER_SEC: u32 = 4;

/// Burst budget before the hello completes, in frames.
pub const PREAUTH_RATE_BURST: u32 = 8;

/// Wall-clock deadline for completing the handshake, in milliseconds. A peer
/// that holds a connection open without authenticating is dropped.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Queues and connection envelope
// ---------------------------------------------------------------------------

/// Per-recipient queue depth in FRAMES. Belt to the byte cap's braces: both
/// must hold for an enqueue to succeed.
pub const DEFAULT_RECIPIENT_QUEUE_FRAMES: usize = 256;

/// Per-recipient queue ceiling in BYTES — the bound that actually caps memory.
pub const DEFAULT_RECIPIENT_QUEUE_BYTES: usize = 64 * 1_024;

/// Hub-wide ceiling on bytes queued for egress across every recipient.
/// 32 MiB at the default 256-connection ceiling.
pub const DEFAULT_GLOBAL_EGRESS_BYTES: usize = 32 * 1_024 * 1_024;

/// Default hard connection ceiling. Matches the 128-256 agents-per-instance
/// target the capacity model was built against.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Refuse to start if the fd budget cannot support at least this many
/// connections. macOS's default 256-fd `RLIMIT_NOFILE` lands EMFILE at exactly
/// the target scale, which is why this is a start-up refusal and not a runtime
/// surprise.
pub const MIN_CONNECTION_CEILING: usize = 8;

/// File descriptors reserved for everything that is not a peer connection
/// (listener, log files, the process's own std streams, headroom).
pub const FD_HEADROOM: u64 = 32;

/// Soft `RLIMIT_NOFILE` the hub tries to raise itself to at start-up, capped by
/// the inherited hard limit. Never lowers an already-higher soft limit.
pub const DESIRED_NOFILE: u64 = 4_096;

/// Shard count for the routing and topic tables. Power of two; sized so 256
/// connections spread thinly enough that a shard lock is never a queue.
pub const ROUTING_SHARDS: usize = 16;

// ---------------------------------------------------------------------------
// Shutdown drain (#3471)
// ---------------------------------------------------------------------------

/// Wall-clock deadline, in milliseconds, for the SIGTERM/SIGINT drain.
///
/// On a shutdown signal the hub stops accepting, asks every session to flush
/// what it has already queued, and waits AT MOST this long for the connection
/// gauge to reach zero before exiting 0 regardless. The bound is the point:
/// an unbounded drain is a hung `systemctl stop` that ends in `SIGKILL`, which
/// is strictly worse than a bounded one because the operator loses the clean
/// socket unlink too.
///
/// Nothing content-bearing is emitted during the drain — the hub carries no
/// durable truth, so there is nothing to flush TO. What the deadline buys is
/// the chance for already-queued hints to land and for peers to observe a
/// clean close instead of a reset, after which the `<=60 s` backstop poll is
/// the guarantee exactly as it is at every other moment.
///
/// 5 s sits under systemd's default 90 s `TimeoutStopSec` and under launchd's
/// 20 s `SIGTERM` grace with room to spare, so neither supervisor ever has to
/// escalate to `SIGKILL`.
pub const DRAIN_DEADLINE_MS: u64 = 5_000;

/// Poll interval, in milliseconds, while waiting for the drain to complete.
/// Short enough that a fast drain is not padded to the deadline, long enough
/// that the wait is not a spin.
pub const DRAIN_POLL_MS: u64 = 10;

// ---------------------------------------------------------------------------
// Ops / observability (#3471)
// ---------------------------------------------------------------------------

/// Percentage of its per-recipient byte cap at or above which a recipient is
/// counted as a SLOW CONSUMER.
///
/// A slow consumer is not yet an error — nothing has been dropped — but it is
/// the leading indicator of the drop that follows, which is precisely the
/// signal an operator needs BEFORE the queue overflows. Half the cap is the
/// point at which one more burst of the same size would refuse.
pub const SLOW_CONSUMER_PERCENT: usize = 50;

/// Wall-clock budget, in milliseconds, for the whole `wake-hub --health`
/// probe: connect, read the hub's challenge, close.
///
/// Bounded because the probe is what a supervisor runs (`ExecStartPost`, a
/// launchd watchdog, a monitoring cron); a probe that can hang forever against
/// a wedged hub would pin the supervisor instead of reporting the fault it
/// exists to report.
pub const HEALTH_PROBE_TIMEOUT_MS: u64 = 2_000;

// ---------------------------------------------------------------------------
// Derived allowlist snapshot reuse (#3504)
// ---------------------------------------------------------------------------

/// How long a PARSED allowlist snapshot may be reused before the hub reads and
/// re-parses the file, even when the file's identity (device, inode, mtime,
/// size) has not moved.
///
/// # Why a TTL at all, when the inode/mtime key already exists
///
/// Every call still opens the file and re-checks owner + exact `0600` +
/// regular-file through that descriptor, and any change of device, inode,
/// mtime or size forces a re-read — so a REPLACED snapshot is picked up on the
/// next call regardless of this value. What the TTL bounds is the one case the
/// identity key cannot see: an in-place rewrite that lands on the same inode
/// with a byte-identical size and a timestamp the filesystem did not advance.
/// That needs write access to a `0600` file already owned by the hub's own
/// uid, so it is not an escalation — but "trusted forever" is not a property
/// worth having in an authority path, and two seconds is cheap.
///
/// # Why two seconds
///
/// It must be well under [`crate::identity::hub_cache::MAX_CACHE_AGE_SECS`]
/// (60 s), which is the ceiling past which a snapshot is refused outright —
/// and it is, by 30x. The `refreshed_at` age is re-checked on EVERY call
/// including a cache hit, so this constant can never extend the life of a
/// stale snapshot; it only decides how often the JSON is re-parsed. At the
/// 256-connection ceiling the 1 Hz per-session `Conn::revalidate` was 256
/// parses/second; keyed reuse with this TTL makes it at most one parse every
/// two seconds, a ~500x reduction, while a replaced file still takes effect
/// within the same one-second revalidation it always did.
pub const ALLOWLIST_CACHE_TTL: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Offline (pending) state
// ---------------------------------------------------------------------------

/// Maximum agents for which a coalesced pending set is retained. Entries are
/// created ONLY for agents that have completed a hello since hub start, so a
/// forged `to` can never grow this table.
pub const DEFAULT_PENDING_MAX_AGENTS: usize = 1_024;

/// Maximum inbox-row ids retained per offline agent. Past this the set keeps
/// counting and raises its `lagged` marker instead of growing — roughly 4 KiB
/// per agent, and NEVER a payload ring.
pub const DEFAULT_PENDING_MAX_IDS: usize = 64;

// ---------------------------------------------------------------------------
// Reconnect guidance (carried in `welcome`)
// ---------------------------------------------------------------------------

/// Base reconnect backoff advertised to clients, in milliseconds.
pub const DEFAULT_RECONNECT_BASE_MS: u32 = 250;

/// Reconnect jitter span advertised to clients, in milliseconds. A client is
/// told to wait `base + rand(0, jitter)` so 256 agents do not re-handshake in
/// lockstep after a hub restart.
pub const DEFAULT_RECONNECT_JITTER_MS: u32 = 750;

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// Milli-tokens per whole token. The bucket is integer-only: floats would make
/// the limiter's behaviour depend on rounding, and `PERF-25` bars float
/// comparison from decision logic.
const MILLI: u64 = 1_000;

/// Integer token bucket: `rate` tokens/second, `burst` capacity, charged in
/// whole tokens.
///
/// `now` is a parameter on every method rather than read from the clock inside,
/// so the limiter is deterministically unit-testable (rust-1.98 `TEST-01`) and
/// a caller can charge fan-out against the SAME instant it routed at.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity_milli: u64,
    tokens_milli: u64,
    rate_per_sec: u64,
    last: Instant,
}

impl TokenBucket {
    /// Build a full bucket.
    #[must_use]
    pub fn new(rate_per_sec: u32, burst: u32, now: Instant) -> Self {
        let capacity_milli = u64::from(burst).saturating_mul(MILLI);
        Self {
            capacity_milli,
            tokens_milli: capacity_milli,
            rate_per_sec: u64::from(rate_per_sec),
            last: now,
        }
    }

    /// Refill for elapsed wall-clock time, advancing the accounting mark by
    /// exactly the whole milliseconds consumed so sub-millisecond remainder is
    /// carried rather than discarded (no slow drift against the nominal rate).
    fn refill(&mut self, now: Instant) {
        let elapsed_ms_u128 = now.saturating_duration_since(self.last).as_millis();
        let Ok(elapsed_ms) = u64::try_from(elapsed_ms_u128) else {
            // Absurd clock jump: refill fully and resynchronise. Degrade, never
            // panic (`PERF-07`: no `as` narrowing).
            self.tokens_milli = self.capacity_milli;
            self.last = now;
            return;
        };
        if elapsed_ms == 0 {
            return;
        }
        // tokens gained = rate * elapsed_ms / 1000, i.e. milli-tokens gained
        // = rate * elapsed_ms exactly.
        let gained = self.rate_per_sec.saturating_mul(elapsed_ms);
        self.tokens_milli = self
            .tokens_milli
            .saturating_add(gained)
            .min(self.capacity_milli);
        self.last = self
            .last
            .checked_add(Duration::from_millis(elapsed_ms))
            .unwrap_or(now);
    }

    /// Charge `cost` whole tokens. Returns `false` (and charges nothing) when
    /// the bucket cannot cover the cost — the caller then refuses LOUDLY to the
    /// sender rather than silently dropping.
    pub fn try_take(&mut self, cost: u32, now: Instant) -> bool {
        self.refill(now);
        let cost_milli = u64::from(cost).saturating_mul(MILLI);
        if cost_milli > self.capacity_milli {
            // A single charge larger than the whole burst can never be
            // satisfied; refuse instead of stalling forever.
            return false;
        }
        if self.tokens_milli < cost_milli {
            return false;
        }
        self.tokens_milli -= cost_milli;
        true
    }

    /// Whole tokens currently available. Test/metric surface only.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.tokens_milli / MILLI
    }
}

// ---------------------------------------------------------------------------
// Global egress budget
// ---------------------------------------------------------------------------

/// Hub-wide byte budget for queued-but-not-yet-written egress.
///
/// Reservation is a CAS loop, so an over-cap reservation is REFUSED rather than
/// admitted-then-corrected: at no point is `used` allowed to exceed `cap`.
#[derive(Debug)]
pub struct EgressBudget {
    cap: usize,
    used: AtomicUsize,
}

impl EgressBudget {
    /// Build a budget with a hard ceiling of `cap` bytes.
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            cap,
            used: AtomicUsize::new(0),
        }
    }

    /// Reserve `n` bytes. Returns `false` when the reservation would cross the
    /// cap; nothing is charged in that case.
    pub fn try_reserve(&self, n: usize) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                let next = cur.checked_add(n)?;
                if next > self.cap { None } else { Some(next) }
            })
            .is_ok()
    }

    /// Return `n` reserved bytes once they have been written to the peer.
    /// Saturating: an accounting bug degrades the budget, it never underflows
    /// into a huge value that would disable the cap.
    pub fn release(&self, n: usize) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some(cur.saturating_sub(n))
            });
    }

    /// Bytes currently reserved.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Configured ceiling in bytes.
    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_frame_bytes_is_derived_from_the_field_bounds() {
        assert_eq!(MAX_FRAME_BYTES, 24 + 256 + 1_536);
        // Every per-kind payload bound must fit inside the codec ceiling.
        assert!(MAX_WAKE_META_BYTES <= MAX_PAYLOAD_BYTES);
        assert!(FRAME_HEADER_BYTES + (2 * MAX_ID_BYTES) + MAX_PAYLOAD_BYTES <= MAX_FRAME_BYTES);
    }

    #[test]
    fn hello_payload_bound_admits_the_largest_legal_hello() {
        // key + signature + the 2-byte-prefixed delegation + the topic list.
        let largest = PUBKEY_BYTES
            + SIGNATURE_BYTES
            + 2
            + MAX_DELEGATION_WIRE_BYTES
            + 1
            + MAX_TOPICS_PER_FRAME * (1 + MAX_TOPIC_BYTES);
        assert!(
            largest <= MAX_PAYLOAD_BYTES,
            "largest legal hello ({largest} B) must fit MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES} B)"
        );
    }

    #[test]
    fn raising_the_handshake_budget_did_not_widen_the_routed_classes() {
        // #3468 raised MAX_PAYLOAD_BYTES for the handshake class only. The
        // classes that actually fan out must not have moved with it, or the
        // memory envelope the byte budgets bound would have silently grown.
        assert_eq!(MAX_WAKE_META_BYTES, 256);
        assert_eq!(MAX_LIVENESS_PAYLOAD_BYTES, 32);
        assert!(MAX_WAKE_META_BYTES < MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn the_allowlist_cache_ttl_stays_well_under_the_snapshot_expiry_3504() {
        // The TTL governs re-PARSING only. It must stay far below the age at
        // which a snapshot is refused outright, so that no arrangement of the
        // two can let an expired snapshot be served from memory.
        let max_age = u64::try_from(crate::identity::hub_cache::MAX_CACHE_AGE_SECS)
            .expect("the snapshot expiry is a positive number of seconds");
        assert!(
            ALLOWLIST_CACHE_TTL.as_secs() > 0,
            "a zero TTL would re-parse on every hello, which is the defect #3504 fixes"
        );
        assert!(
            ALLOWLIST_CACHE_TTL.as_secs() * 10 <= max_age,
            "the reuse TTL ({}s) must stay an order of magnitude under the {max_age}s \
             snapshot expiry",
            ALLOWLIST_CACHE_TTL.as_secs()
        );
    }

    #[test]
    fn token_bucket_starts_full_and_drains() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(500, 2_000, t0);
        assert_eq!(b.available(), 2_000);
        assert!(b.try_take(2_000, t0));
        assert_eq!(b.available(), 0);
        assert!(!b.try_take(1, t0), "an empty bucket must refuse");
    }

    #[test]
    fn token_bucket_refills_at_the_nominal_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(500, 2_000, t0);
        assert!(b.try_take(2_000, t0));
        // 1 s at 500/s -> 500 tokens back, never more than the burst.
        assert!(b.try_take(500, t0 + Duration::from_secs(1)));
        assert_eq!(b.available(), 0);
        // 10 s would mint 5_000 tokens; the burst caps it at 2_000.
        b.refill(t0 + Duration::from_secs(11));
        assert_eq!(b.available(), 2_000);
    }

    #[test]
    fn token_bucket_carries_sub_millisecond_remainder() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1_000, 10, t0);
        assert!(b.try_take(10, t0));
        // Ten 100-microsecond steps must mint exactly one token in total, not
        // zero (which is what resetting `last` to `now` on every call would do).
        let mut t = t0;
        for _ in 0..10 {
            t += Duration::from_micros(100);
            b.refill(t);
        }
        assert_eq!(b.available(), 1);
    }

    #[test]
    fn token_bucket_refuses_a_charge_larger_than_the_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(500, 2_000, t0);
        assert!(
            !b.try_take(2_001, t0),
            "a fan-out wider than the burst must be refused, not stall forever"
        );
        assert_eq!(b.available(), 2_000, "a refused charge must cost nothing");
    }

    #[test]
    fn egress_budget_refuses_at_the_cap_and_charges_nothing() {
        let b = EgressBudget::new(1_000);
        assert!(b.try_reserve(600));
        assert!(!b.try_reserve(500));
        assert_eq!(b.used(), 600, "a refused reservation must charge nothing");
        assert!(b.try_reserve(400));
        assert_eq!(b.used(), 1_000);
        b.release(1_000);
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn egress_budget_release_saturates_instead_of_underflowing() {
        let b = EgressBudget::new(1_000);
        b.release(10_000);
        assert_eq!(b.used(), 0);
        assert!(b.try_reserve(1_000));
    }
}
