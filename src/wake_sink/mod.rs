// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the bridge from the `agent_notified` wake bus to the
//! `ai-memory wake-hub` (EPIC
//! [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! # What this module is
//!
//! [`crate::inbox_wake`] (#3465) publishes one content-free frame per
//! committed notify and exposes a fire-and-forget
//! [`crate::inbox_wake::InboxWakeSink`] seam.
//! [`crate::wake_hub`] (#3467) is a same-host switch that pushes a bounded
//! wake HINT to a connected agent. This module is the wire between them, in
//! the two deployment shapes the EPIC allows:
//!
//! * [`in_process`] — the hub is CO-HOSTED with the daemon. The encoded frame
//!   goes straight to [`crate::wake_hub::routing::Router::deliver`], the same
//!   injection point a hub connection's own `route_wake` uses, so a substrate
//!   wake and a peer-relayed one are indistinguishable downstream and obey the
//!   same per-recipient queue, byte cap, egress budget and coalesced pending
//!   set. `deliver` is a lock plus a `try_send` with no `.await`, which is what
//!   makes it legal on the bus pump (`CONCURRENCY-20`, `CONCURRENCY-22`).
//! * [`uds`] — the hub runs as a SEPARATE process. The daemon-side forwarder is
//!   an ordinary hub client over the hub's Unix domain socket: the same
//!   handshake, the same `u32`-big-endian framing and the same
//!   [`crate::wake_hub::limits::MAX_FRAME_BYTES`] ceiling
//!   [`crate::wake_hub::codec`] enforces. No privileged side channel into the
//!   router.
//!
//! # Never the webhook lane
//!
//! Nothing here reads [`crate::subscriptions`]. Sourcing an agent's
//! latency-critical wake from the operator egress lane would make one slow
//! operator webhook the recipient's wake latency; #3465 states the rule and
//! this module is where it would have been easiest to break.
//!
//! # Never the body
//!
//! The routed payload is a [`crate::wake_hub::frame::WakeMeta`] —
//! `{inbox_row_id, namespace, sender, digest, seq_high_watermark}` and nothing
//! else. The body reaches only the emitter, which digests it; neither the bus
//! frame this module reads nor the wake frame it writes has a field that could
//! hold one.
//!
//! # Who may receive which wake
//!
//! A substrate wake is addressed DIRECTLY to the recipient agent id and never
//! to a `#topic`. The hub's route table is keyed by the identity a hello
//! authenticated, so a wake for `X` can only ever land on a session that
//! authenticated AS `X` — own-inbox only, which is exactly the scope
//! [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)'s
//! delegation verifier grants until
//! [#3505](https://github.com/alphaonedev/ai-memory-mcp/issues/3505) widens it.
//! A topic-shaped, reserved, empty or over-long recipient is REFUSED and
//! counted, never coerced into something routable.
//!
//! # Degrade, never corrupt
//!
//! Every path here may drop a hint; none may produce a wrong one. The durable
//! inbox row is already committed before a wake fires, so a slow or absent hub
//! must never block a notify, fail it, or apply backpressure to it. Every drop
//! lands on its own [`SinkMetrics`] counter — a hub that silently stopped
//! waking anyone must not look like a quiet fleet.
//!
//! # The backstop is what makes all of that safe
//!
//! **Normative:** a client of this plane MUST keep polling its inbox at least
//! once every [`BACKSTOP_POLL_MAX`]. The wake is a latency optimisation and
//! nothing more; the durable inbox row is the record. A lost wake therefore
//! degrades to "learned it on the next poll", never to "message lost" — and
//! [`crate::wake_hub::frame::WakeMeta::seq_high_watermark`] lets a client that
//! sees a gap collapse that wait to ONE catch-up inbox read.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use crate::inbox_wake::InboxEvent;
use crate::wake_hub::frame::{Frame, FrameError, Kind, WakeMeta, is_topic};
use crate::wake_hub::limits::{MAX_ID_BYTES, WAKE_DIGEST_BYTES};

pub mod in_process;
pub mod uds;

/// The longest a client of the wake plane may go between inbox polls.
///
/// **Normative.** The hub carries no durable truth: it may drop a hint under
/// any of its bounds, and the process hosting it may be absent entirely.
/// Bounding the backstop poll is what turns every "may drop" in this module and
/// in [`crate::wake_hub`] into a bounded LATENCY cost instead of an unbounded
/// correctness one. Sixty seconds is the ceiling, not the target: a client that
/// sees a [`crate::wake_hub::frame::WakeMeta::seq_high_watermark`] gap should
/// read immediately rather than wait it out.
pub const BACKSTOP_POLL_MAX: std::time::Duration = std::time::Duration::from_secs(60);

/// Label [`crate::write_events::content_digest`] puts in front of the hex
/// digest on the bus. The hub carries the 32 RAW bytes instead, so this module
/// is where the two representations meet.
pub const CONTENT_DIGEST_PREFIX: &str = "sha256:";

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a bus event could not be turned into a routable wake.
///
/// Both variants are DROPS, never failures reported upstream: the notify they
/// describe is already committed and the recipient's backstop poll still finds
/// the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkRefusal {
    /// The recipient is not something this plane may address.
    Unaddressable(&'static str),
    /// The frame would not encode within the hub's own bounds.
    Unencodable(FrameError),
}

impl std::fmt::Display for SinkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unaddressable(why) => write!(f, "unaddressable recipient: {why}"),
            Self::Unencodable(e) => write!(f, "wake could not be encoded: {e}"),
        }
    }
}

impl std::error::Error for SinkRefusal {}

// ---------------------------------------------------------------------------
// Building a substrate wake
// ---------------------------------------------------------------------------

/// One bus event, translated into everything the hub needs to route it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateWake {
    /// The inbox owner. The ONLY agent this frame may reach.
    pub recipient: String,
    /// Coalescing key used when the recipient is offline. Read from the
    /// metadata here so the router never parses a payload.
    pub inbox_row_id: String,
    /// The encoded `wake` frame, ready for the hub's length-delimited codec.
    pub frame: Bytes,
    /// `true` when a field had to be shed to fit
    /// [`crate::wake_hub::limits::MAX_WAKE_META_BYTES`].
    pub shed: bool,
}

/// The raw SHA-256 the hub carries, from the `sha256:<hex>` form on the bus.
///
/// A digest that is absent, unlabelled, non-hex or the wrong width degrades to
/// EMPTY — which [`WakeMeta`] explicitly permits — rather than costing the
/// recipient its wake. The digest is a de-duplication aid the recipient
/// re-derives from the row it reads back; the row id is the part it cannot do
/// without.
#[must_use]
pub fn digest_bytes(content_digest: &str) -> Vec<u8> {
    let Some(hex_part) = content_digest.strip_prefix(CONTENT_DIGEST_PREFIX) else {
        return Vec::new();
    };
    match hex::decode(hex_part) {
        Ok(raw) if raw.len() == WAKE_DIGEST_BYTES => raw,
        _ => Vec::new(),
    }
}

/// The metadata a substrate wake carries: exactly the five documented fields.
#[must_use]
pub fn wake_meta_for(event: &InboxEvent) -> WakeMeta {
    let InboxEvent::AgentNotified {
        inbox_row_id,
        namespace,
        sender_agent_id,
        content_digest,
        seq,
        ..
    } = event;
    WakeMeta {
        inbox_row_id: inbox_row_id.clone(),
        namespace: namespace.clone(),
        sender: sender_agent_id.clone(),
        digest: digest_bytes(content_digest),
        // The producer's HOST-WIDE wake sequence, not a per-recipient inbox
        // depth — see the field's own documentation. A sink-side per-recipient
        // counter would be strictly WORSE: when the broadcast receiver lags it
        // never sees the dropped frames, so it would hand clients contiguous
        // numbers across a real gap.
        seq_high_watermark: *seq,
    }
}

/// Encode `meta`, shedding fields in a fixed order until it fits.
///
/// An ai-memory namespace plus a 128-byte agent id is already larger than
/// [`crate::wake_hub::limits::MAX_WAKE_META_BYTES`], so the ladder is reachable
/// in production, not theoretical. It sheds `sender`, then `namespace`, then
/// `digest`, and ALWAYS keeps `inbox_row_id` and `seq_high_watermark` — the two
/// fields a recipient actually needs to act. A hint that will not fit even then
/// is refused rather than truncated: a truncated row id points at the wrong
/// row, which is a wrong result, and this plane may only ever produce fewer
/// results.
fn encode_meta_with_shedding(meta: &WakeMeta) -> Result<(Bytes, bool), FrameError> {
    if let Ok(full) = meta.encode() {
        return Ok((full, false));
    }
    let mut candidate = meta.clone();
    candidate.sender.clear();
    if let Ok(bytes) = candidate.encode() {
        return Ok((bytes, true));
    }
    candidate.namespace.clear();
    if let Ok(bytes) = candidate.encode() {
        return Ok((bytes, true));
    }
    candidate.digest.clear();
    // The minimal form is `inbox_row_id` + the watermark. If THAT will not
    // encode, the row id itself is over the wire bound and the only honest
    // answer is a refusal.
    candidate.encode().map(|bytes| (bytes, true))
}

/// Turn one bus event into a routable substrate wake.
///
/// # Errors
///
/// [`SinkRefusal::Unaddressable`] when the recipient is empty, over-long, a
/// `#topic`, or a [`crate::validate::RESERVED_AGENT_IDS`] name (no wire caller
/// can own an inbox under a reserved name, so a wake addressed to one is a bug
/// or a forgery, never mail); [`SinkRefusal::Unencodable`] when the frame would
/// violate one of the hub's own wire bounds.
pub fn build_substrate_wake(event: &InboxEvent) -> Result<SubstrateWake, SinkRefusal> {
    let recipient = event.recipient_agent_id();
    if recipient.is_empty() {
        return Err(SinkRefusal::Unaddressable("empty recipient"));
    }
    if recipient.len() > MAX_ID_BYTES {
        return Err(SinkRefusal::Unaddressable(
            "recipient id over the wire bound",
        ));
    }
    // A substrate wake is ALWAYS direct. Routing one through the topic table
    // would make delivery depend on a mutable subscription set instead of on
    // the identity a hello authenticated, which is the whole own-inbox-only
    // property (#3468, until #3505).
    if is_topic(recipient) {
        return Err(SinkRefusal::Unaddressable(
            "recipient is a topic; substrate wakes are direct only",
        ));
    }
    if crate::validate::RESERVED_AGENT_IDS.contains(&recipient) {
        return Err(SinkRefusal::Unaddressable(
            "recipient is a reserved internal name",
        ));
    }

    let meta = wake_meta_for(event);
    let (payload, shed) = encode_meta_with_shedding(&meta).map_err(SinkRefusal::Unencodable)?;
    let frame = Frame::new(
        Kind::Wake,
        crate::identity::sentinels::WAKE_HUB_PRODUCER,
        recipient,
        payload,
    )
    .encode()
    .map_err(SinkRefusal::Unencodable)?;
    Ok(SubstrateWake {
        recipient: recipient.to_owned(),
        inbox_row_id: meta.inbox_row_id,
        frame,
        shed,
    })
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Snapshot of one sink's counters.
///
/// Every field except [`Self::wakes_seen`], [`Self::delivered`],
/// [`Self::coalesced`] and [`Self::meta_shed`] is a DROP with its own cause, so
/// an operator can tell a quiet fleet from a hub that stopped waking anyone.
/// [`Self::total_dropped`] is the sum of exactly those drop fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinkMetricsSnapshot {
    /// Bus frames this sink was handed.
    pub wakes_seen: u64,
    /// Handed to a live recipient's writer queue.
    pub delivered: u64,
    /// Recipient offline but known: coalesced into its pending set.
    pub coalesced: u64,
    /// Recipient offline and never seen: nothing to coalesce onto.
    pub dropped_unknown: u64,
    /// A recipient queue or the hub-wide egress budget was full.
    pub dropped_overflow: u64,
    /// The recipient was not something this plane may address.
    pub dropped_unaddressable: u64,
    /// The frame would have violated one of the hub's own wire bounds.
    pub dropped_unencodable: u64,
    /// The bounded hand-off channel to the forwarder was full.
    pub dropped_transport_full: u64,
    /// No hub connection was up to carry the frame.
    pub dropped_hub_down: u64,
    /// Wakes the BUS dropped before this sink saw them (`on_lagged`).
    pub bus_lagged: u64,
    /// Hints that had to shed a field to fit the metadata cap.
    pub meta_shed: u64,
}

impl SinkMetricsSnapshot {
    /// Every wake this sink failed to hand onward, whatever the cause.
    #[must_use]
    pub const fn total_dropped(&self) -> u64 {
        self.dropped_unknown
            .saturating_add(self.dropped_overflow)
            .saturating_add(self.dropped_unaddressable)
            .saturating_add(self.dropped_unencodable)
            .saturating_add(self.dropped_transport_full)
            .saturating_add(self.dropped_hub_down)
            .saturating_add(self.bus_lagged)
    }
}

/// Live counters for one wake sink.
///
/// All `Relaxed` (`CONCURRENCY-07`): independent statistics, nothing is
/// published through them.
#[derive(Debug, Default)]
pub struct SinkMetrics {
    wakes_seen: AtomicU64,
    delivered: AtomicU64,
    coalesced: AtomicU64,
    dropped_unknown: AtomicU64,
    dropped_overflow: AtomicU64,
    dropped_unaddressable: AtomicU64,
    dropped_unencodable: AtomicU64,
    dropped_transport_full: AtomicU64,
    dropped_hub_down: AtomicU64,
    bus_lagged: AtomicU64,
    meta_shed: AtomicU64,
}

macro_rules! bump {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Increment the `", stringify!($name), "` counter.")]
            pub fn $name(&self) {
                self.$name.fetch_add(1, Ordering::Relaxed);
            }
        )+
    };
}

impl SinkMetrics {
    bump!(
        wakes_seen,
        delivered,
        coalesced,
        dropped_unknown,
        dropped_overflow,
        dropped_unaddressable,
        dropped_unencodable,
        dropped_transport_full,
        dropped_hub_down,
        meta_shed,
    );

    /// Record `missed` frames the BUS dropped before this sink saw them.
    pub fn bus_lagged(&self, missed: u64) {
        self.bus_lagged.fetch_add(missed, Ordering::Relaxed);
    }

    /// Read every counter.
    #[must_use]
    pub fn snapshot(&self) -> SinkMetricsSnapshot {
        SinkMetricsSnapshot {
            wakes_seen: self.wakes_seen.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            dropped_unknown: self.dropped_unknown.load(Ordering::Relaxed),
            dropped_overflow: self.dropped_overflow.load(Ordering::Relaxed),
            dropped_unaddressable: self.dropped_unaddressable.load(Ordering::Relaxed),
            dropped_unencodable: self.dropped_unencodable.load(Ordering::Relaxed),
            dropped_transport_full: self.dropped_transport_full.load(Ordering::Relaxed),
            dropped_hub_down: self.dropped_hub_down.load(Ordering::Relaxed),
            bus_lagged: self.bus_lagged.load(Ordering::Relaxed),
            meta_shed: self.meta_shed.load(Ordering::Relaxed),
        }
    }
}

/// A recipient id that is safe to put in a log line.
///
/// A refusal log names the id it refused, and that id reaches an operator's
/// terminal and log file. An id that failed the shape check may hold a control
/// character or an ANSI escape, which could forge a log line or drive a
/// terminal sequence — the same hazard `wake_hub::frame` refuses at its parse
/// boundary. Anything that would not pass the shape check is rendered as its
/// LENGTH instead of its bytes.
fn loggable_recipient(recipient: &str) -> std::borrow::Cow<'_, str> {
    if crate::validate::validate_agent_id_shape(recipient).is_ok() {
        std::borrow::Cow::Borrowed(recipient)
    } else {
        std::borrow::Cow::Owned(format!("<unprintable id, {} bytes>", recipient.len()))
    }
}

/// Log a refusal and charge it to the right counter.
///
/// Shared by both sinks so the two transports cannot drift in what they call a
/// drop.
fn record_refusal(metrics: &SinkMetrics, recipient: &str, refusal: &SinkRefusal) {
    match refusal {
        SinkRefusal::Unaddressable(_) => metrics.dropped_unaddressable(),
        SinkRefusal::Unencodable(_) => metrics.dropped_unencodable(),
    }
    tracing::warn!(
        recipient = %loggable_recipient(recipient),
        "wake sink: hint dropped — {refusal}; the recipient still finds the row on \
         its backstop poll"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake_hub::limits::MAX_WAKE_META_BYTES;

    pub(super) fn event(recipient: &str, digest: &str) -> InboxEvent {
        InboxEvent::AgentNotified {
            seq: 42,
            recipient_agent_id: recipient.into(),
            correlation_id: "sha256:corr".into(),
            inbox_row_id: "row-3469".into(),
            namespace: "_inbox/bob".into(),
            sender_agent_id: "ai:alice".into(),
            content_digest: digest.into(),
            notified_at: "2026-09-05T00:00:00Z".into(),
        }
    }

    fn good_digest() -> String {
        format!("{CONTENT_DIGEST_PREFIX}{}", "ab".repeat(WAKE_DIGEST_BYTES))
    }

    #[test]
    fn the_backstop_ceiling_is_normative_and_bounded_3469() {
        assert_eq!(BACKSTOP_POLL_MAX, std::time::Duration::from_secs(60));
        assert!(BACKSTOP_POLL_MAX <= std::time::Duration::from_secs(60));
    }

    #[test]
    fn a_labelled_hex_digest_becomes_the_hubs_raw_bytes_3469() {
        let raw = digest_bytes(&good_digest());
        assert_eq!(raw.len(), WAKE_DIGEST_BYTES);
        assert_eq!(raw[0], 0xab);
    }

    #[test]
    fn a_malformed_digest_degrades_to_empty_rather_than_costing_the_wake_3469() {
        // Unlabelled, non-hex, wrong width, empty: all degrade, none refuse.
        for bad in [
            "deadbeef",
            "sha256:zzzz",
            "sha256:ab",
            "",
            "sha512:00112233",
        ] {
            assert!(digest_bytes(bad).is_empty(), "expected empty for {bad}");
        }
        let wake = build_substrate_wake(&event("bob", "sha256:zzzz")).expect("still routable");
        assert_eq!(wake.recipient, "bob");
    }

    #[test]
    fn the_metadata_is_exactly_the_five_documented_fields_3469() {
        let meta = wake_meta_for(&event("bob", &good_digest()));
        assert_eq!(meta.inbox_row_id, "row-3469");
        assert_eq!(meta.namespace, "_inbox/bob");
        assert_eq!(meta.sender, "ai:alice");
        assert_eq!(meta.digest.len(), WAKE_DIGEST_BYTES);
        assert_eq!(meta.seq_high_watermark, 42);
    }

    #[test]
    fn a_substrate_wake_is_stamped_with_the_reserved_producer_id_3469() {
        let wake = build_substrate_wake(&event("bob", &good_digest())).expect("routable");
        let decoded = Frame::decode(&wake.frame).expect("decode");
        assert_eq!(decoded.kind, Kind::Wake);
        assert_eq!(
            decoded.from,
            crate::identity::sentinels::WAKE_HUB_PRODUCER,
            "a substrate wake must NOT claim the notifying agent's identity"
        );
        assert_eq!(decoded.to, "bob");
        assert!(!decoded.to_is_topic());
        let meta = WakeMeta::decode(&decoded.payload).expect("meta");
        assert_eq!(meta.sender, "ai:alice", "the real sender rides in metadata");
    }

    #[test]
    fn the_producer_id_is_reserved_so_no_wire_caller_can_forge_one_3469() {
        assert!(
            crate::validate::validate_agent_id(crate::identity::sentinels::WAKE_HUB_PRODUCER)
                .is_err()
        );
    }

    #[test]
    fn neither_body_nor_title_can_reach_the_wire_3469() {
        // The bus frame itself has no body field (#3465), so the strongest
        // statement available here is that nothing the sink emits echoes any
        // caller content it was given.
        let secret = "SUPER-SECRET-NOTIFY-BODY-3469";
        let mut ev = event("bob", &good_digest());
        let InboxEvent::AgentNotified { correlation_id, .. } = &mut ev;
        *correlation_id = secret.into();
        let wake = build_substrate_wake(&ev).expect("routable");
        assert!(
            !String::from_utf8_lossy(&wake.frame).contains(secret),
            "no caller-supplied content may ride the wake plane"
        );
    }

    #[test]
    fn a_topic_recipient_is_refused_not_coerced_3469() {
        let err = build_substrate_wake(&event("#_inbox/bob", &good_digest()))
            .expect_err("a topic is not an inbox owner");
        assert!(matches!(err, SinkRefusal::Unaddressable(_)), "{err}");
    }

    #[test]
    fn an_empty_reserved_or_over_long_recipient_is_refused_3469() {
        for bad in [
            String::new(),
            crate::identity::sentinels::DAEMON_PRINCIPAL.to_owned(),
            crate::identity::sentinels::WAKE_HUB_PRODUCER.to_owned(),
            "x".repeat(MAX_ID_BYTES + 1),
        ] {
            let err = build_substrate_wake(&event(&bad, &good_digest()))
                .expect_err("a wake must never be addressed to this");
            assert!(matches!(err, SinkRefusal::Unaddressable(_)), "{err}");
        }
    }

    #[test]
    fn an_over_long_hint_sheds_fields_but_never_the_row_id_3469() {
        let mut ev = event("bob", &good_digest());
        let InboxEvent::AgentNotified {
            namespace,
            sender_agent_id,
            ..
        } = &mut ev;
        *namespace = format!("_inbox/{}", "n".repeat(120));
        *sender_agent_id = "s".repeat(MAX_ID_BYTES);
        let wake = build_substrate_wake(&ev).expect("must still route");
        assert!(wake.shed, "this hint cannot fit whole");
        let decoded = Frame::decode(&wake.frame).expect("decode");
        assert!(decoded.payload.len() <= MAX_WAKE_META_BYTES);
        let meta = WakeMeta::decode(&decoded.payload).expect("meta");
        assert_eq!(
            meta.inbox_row_id, "row-3469",
            "the row id is the one field that may never be shed"
        );
        assert_eq!(meta.seq_high_watermark, 42, "nor the self-heal watermark");
        assert!(meta.sender.is_empty(), "sender sheds first");
    }

    #[test]
    fn an_unencodable_row_id_is_refused_rather_than_truncated_3469() {
        let mut ev = event("bob", &good_digest());
        let InboxEvent::AgentNotified { inbox_row_id, .. } = &mut ev;
        *inbox_row_id = "r".repeat(MAX_WAKE_META_BYTES + 1);
        let err = build_substrate_wake(&ev).expect_err("a truncated row id is a WRONG result");
        assert!(matches!(err, SinkRefusal::Unencodable(_)), "{err}");
    }

    #[test]
    fn every_drop_lands_on_its_own_counter_3469() {
        let m = SinkMetrics::default();
        assert_eq!(m.snapshot(), SinkMetricsSnapshot::default());
        m.wakes_seen();
        m.delivered();
        m.coalesced();
        m.dropped_unknown();
        m.dropped_overflow();
        m.dropped_unaddressable();
        m.dropped_unencodable();
        m.dropped_transport_full();
        m.dropped_hub_down();
        m.meta_shed();
        m.bus_lagged(7);
        let s = m.snapshot();
        assert_eq!(s.wakes_seen, 1);
        assert_eq!(s.delivered, 1);
        assert_eq!(s.coalesced, 1);
        assert_eq!(s.bus_lagged, 7);
        assert_eq!(s.meta_shed, 1);
        // 6 single drops + 7 lagged; delivered/coalesced/seen/shed are not drops.
        assert_eq!(s.total_dropped(), 13);
    }

    #[test]
    fn an_unprintable_recipient_never_reaches_a_log_line_3469() {
        // A control character or an ANSI escape in an id reaches an operator's
        // terminal; render the length instead of the bytes.
        let forged = "bob\u{1b}[2Kfake-log-line";
        let rendered = loggable_recipient(forged);
        assert!(!rendered.contains('\u{1b}'), "{rendered}");
        assert!(rendered.starts_with("<unprintable id"), "{rendered}");
        // A well-shaped id is still named in full.
        assert_eq!(loggable_recipient("ai:alice"), "ai:alice");
    }

    #[test]
    fn a_refusal_is_charged_to_the_matching_counter_3469() {
        let m = SinkMetrics::default();
        record_refusal(&m, "bob", &SinkRefusal::Unaddressable("topic"));
        record_refusal(&m, "bob", &SinkRefusal::Unencodable(FrameError::BadMagic));
        let s = m.snapshot();
        assert_eq!(s.dropped_unaddressable, 1);
        assert_eq!(s.dropped_unencodable, 1);
    }
}
