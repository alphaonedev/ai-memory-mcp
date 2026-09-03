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

/// Maximum payload of ANY frame kind. `hello` is the largest (32-byte public
/// key + 64-byte signature + the asserted topic list).
pub const MAX_PAYLOAD_BYTES: usize = 1_024;

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

/// Length of the hub-issued handshake nonce, in bytes.
pub const HELLO_NONCE_BYTES: usize = 32;

/// Length of an Ed25519 public key, in bytes.
pub const PUBKEY_BYTES: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_BYTES: usize = 64;

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
        assert_eq!(MAX_FRAME_BYTES, 24 + 256 + 1_024);
        // Every per-kind payload bound must fit inside the codec ceiling.
        assert!(MAX_WAKE_META_BYTES <= MAX_PAYLOAD_BYTES);
        assert!(FRAME_HEADER_BYTES + (2 * MAX_ID_BYTES) + MAX_PAYLOAD_BYTES <= MAX_FRAME_BYTES);
    }

    #[test]
    fn hello_payload_bound_admits_the_largest_legal_hello() {
        let largest =
            PUBKEY_BYTES + SIGNATURE_BYTES + 1 + MAX_TOPICS_PER_FRAME * (1 + MAX_TOPIC_BYTES);
        assert!(
            largest <= MAX_PAYLOAD_BYTES,
            "largest legal hello ({largest} B) must fit MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES} B)"
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
