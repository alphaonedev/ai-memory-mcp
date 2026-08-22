// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2672 — TYPED push-DLQ error class.
//!
//! # The defect this closes
//!
//! Two independent behaviours used to key off SUBSTRINGS of
//! `federation_push_dlq.last_error`, a human-readable diagnostic string:
//!
//! - `reset_throttled_quarantine` matched `last_error LIKE '%429%'` on BOTH
//!   backends and set `attempt_count = 0`;
//! - `classify_quarantine_cause`'s first arm was `last_error.contains("429")
//!   => "quota"`.
//!
//! `sync::success_report_non_ack_reason` interpolates a count read VERBATIM
//! out of the peer's own JSON response body into that same string. A peer
//! answering **HTTP 200** with `{"skipped": 429}` therefore minted
//! `"peer 2xx but 429 item(s) skipped …"`, which matched both. Its rows had
//! their attempt budget reset on every sweep, so they could never reach
//! `MAX_REPLAY_ATTEMPTS` and never quarantine — defeating the very ceiling
//! #1544 introduced to stop unbounded no-op POST amplification — and the
//! operator was misdirected to "raise the daily quota". Any count containing
//! the digits worked (`429`, `1429`, `4290`); the peer never had to send a
//! real 429. The same laundering reached `400` / `401` / `403` / `422`.
//!
//! # The fix
//!
//! The retry/label signal is now carried STRUCTURALLY by a typed
//! [`DlqErrorClass`], decided from facts a peer cannot choose — the real HTTP
//! status line, or the local call site — and never re-derived from prose.
//!
//! The class is persisted as a RESERVED TAG at the FRONT of `last_error`:
//!
//! ```text
//! [ai-memory:class=throttle] http 429 Too Many Requests
//! [ai-memory:class=peer_refused] peer 2xx but 429 item(s) skipped (refused/not applied by receiver)
//! ```
//!
//! **Why a leading tag is not steerable** (unlike the `%429%` substring it
//! replaces): the tag is written by THIS process, FIRST, before any
//! peer-derived text; every peer-influenced byte can only ever appear AFTER
//! it. The SQL predicate is an ANCHORED `LIKE '[ai-memory:class=throttle]%'`,
//! so peer content is structurally outside the matched region. A peer that
//! echoes the literal tag inside its own count cannot: the two peer-supplied
//! fields (`skipped`, `unsupported_on_postgres`) are parsed with `as_u64`, so
//! they can only contribute DIGITS.
//!
//! **Why not a new column:** a `federation_push_dlq.error_class` column would
//! be the textbook shape, but it costs a schema-version bump on BOTH ladders
//! (sqlite + postgres) plus every pinned schema-version test, for a signal
//! that the reserved prefix already carries un-forgeably. The typed enum IS
//! the SSOT here; the prefix is only its wire encoding. Should the column ever
//! land, [`DlqErrorClass`] is the value it stores and the parse/stamp pair are
//! the only two call sites to retarget.
//!
//! # Legacy (pre-#2672) rows
//!
//! Rows enqueued by an older binary carry NO tag. They keep the historical
//! substring classifier (`classify_quarantine_cause`'s legacy arm) and the
//! legacy `%429%` reset arm, both guarded by `NOT LIKE '[ai-memory:class=%'`
//! so they can only ever match UNTAGGED rows. A peer-steered row minted by
//! THIS binary is always tagged, so it can never reach the legacy arm — the
//! laundering surface is closed for every row this binary writes, and no
//! in-flight upgrade backlog is stranded.

/// Reserved opening delimiter of the class tag. Chosen so it cannot collide
/// with any human reason text produced elsewhere in the fanout, and contains
/// no SQL `LIKE` wildcard (`%` / `_`) so the anchored predicates below need no
/// `ESCAPE` clause.
pub(super) const CLASS_TAG_OPEN: &str = "[ai-memory:class=";

/// Reserved closing delimiter (plus the single separating space).
pub(super) const CLASS_TAG_CLOSE: &str = "] ";

/// Anchored `LIKE` pattern matching a THROTTLE-classed row. Used by
/// `reset_throttled_quarantine` on both backends in place of the steerable
/// `'%429%'`.
pub(super) const SQL_LIKE_CLASS_THROTTLE: &str = "[ai-memory:class=throttle]%";

/// Anchored `LIKE` pattern matching ANY tagged row. Used with `NOT LIKE` to
/// scope the legacy substring arm to pre-#2672 rows only.
pub(super) const SQL_LIKE_ANY_CLASS_TAG: &str = "[ai-memory:class=%";

/// v1.0.0 #2672 — the typed, peer-unforgeable reason a push-DLQ row is
/// pending or quarantined.
///
/// Decided from the real HTTP status line or the local call site — NEVER from
/// the text of an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DlqErrorClass {
    /// Peer answered HTTP 429. Retryable on its own once the quota window
    /// rolls — the ONLY class `reset_throttled_quarantine` un-quarantines.
    Throttle,
    /// Peer answered 401/403 — the enrolment / auth signal.
    UnenrolledPeer,
    /// Peer answered 400/422 — a structurally un-appliable row.
    Permanent,
    /// Peer answered 2xx but its own report counted items it structurally
    /// cannot apply (`unsupported_on_postgres > 0`). Not a transient flap.
    PeerUnsupported,
    /// Peer answered 2xx but its own report counted refused items
    /// (`skipped > 0`). The count is the peer's; it steers NOTHING here.
    PeerRefused,
    /// Peer acked but rewrote the id.
    IdDrift,
    /// The row's peer is no longer in `FederationConfig`.
    PeerRemoved,
    /// Transport-level failure (connect/TLS/timeout) — no HTTP status.
    Network,
    /// Locally queued, not yet attempted.
    Queued,
    /// Anything else (including a peer status outside the classified set).
    Other,
}

/// CLOSED-set quarantine-cause labels (bounded Prometheus label cardinality).
///
/// Named consts rather than scattered string literals: three of them double as
/// the class WIRE TAG, so the pm-v3.1 no-scattered-literals discipline demands
/// exactly one definition site per value.
pub(super) const CAUSE_QUOTA: &str = "quota";
/// See [`CAUSE_QUOTA`]. Also the `Permanent` / `PeerUnsupported` wire tag half.
pub(super) const CAUSE_PERMANENT: &str = "permanent";
/// See [`CAUSE_QUOTA`]. Doubles as the `UnenrolledPeer` wire tag.
pub(super) const CAUSE_UNENROLLED_PEER: &str = "unenrolled_peer";
/// See [`CAUSE_QUOTA`]. Doubles as the `PeerRemoved` wire tag.
pub(super) const CAUSE_PEER_REMOVED: &str = "peer_removed";
/// See [`CAUSE_QUOTA`]. Doubles as the `IdDrift` wire tag.
pub(super) const CAUSE_ID_DRIFT: &str = "id_drift";
/// See [`CAUSE_QUOTA`]. The honest catch-all.
pub(super) const CAUSE_OTHER: &str = "other";

impl DlqErrorClass {
    /// Every variant, in tag order. The SSOT [`Self::from_tag`] scans so the
    /// tag spelling lives in exactly ONE place ([`Self::as_tag`]).
    const ALL: [DlqErrorClass; 10] = [
        DlqErrorClass::Throttle,
        DlqErrorClass::UnenrolledPeer,
        DlqErrorClass::Permanent,
        DlqErrorClass::PeerUnsupported,
        DlqErrorClass::PeerRefused,
        DlqErrorClass::IdDrift,
        DlqErrorClass::PeerRemoved,
        DlqErrorClass::Network,
        DlqErrorClass::Queued,
        DlqErrorClass::Other,
    ];

    /// Stable wire tag. Never renamed: it is persisted in `last_error`.
    pub(super) fn as_tag(self) -> &'static str {
        match self {
            DlqErrorClass::Throttle => "throttle",
            DlqErrorClass::UnenrolledPeer => CAUSE_UNENROLLED_PEER,
            DlqErrorClass::Permanent => CAUSE_PERMANENT,
            DlqErrorClass::PeerUnsupported => "peer_unsupported",
            DlqErrorClass::PeerRefused => "peer_refused",
            DlqErrorClass::IdDrift => CAUSE_ID_DRIFT,
            DlqErrorClass::PeerRemoved => CAUSE_PEER_REMOVED,
            DlqErrorClass::Network => "network",
            DlqErrorClass::Queued => "queued",
            DlqErrorClass::Other => CAUSE_OTHER,
        }
    }

    /// Inverse of [`Self::as_tag`]. An unrecognised tag (a row written by a
    /// NEWER binary that added a class) reads as [`DlqErrorClass::Other`]
    /// rather than falling through to the legacy substring classifier — a
    /// tagged row is never re-interpreted as prose.
    fn from_tag(tag: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|c| c.as_tag() == tag)
            .unwrap_or(DlqErrorClass::Other)
    }

    /// The CLOSED-set quarantine-cause label this class maps to.
    ///
    /// Preserves the historical label vocabulary exactly (bounded Prometheus
    /// label cardinality), but derives it from the typed class instead of
    /// grepping prose.
    pub(super) fn quarantine_cause(self) -> &'static str {
        match self {
            DlqErrorClass::Throttle => CAUSE_QUOTA,
            DlqErrorClass::UnenrolledPeer => CAUSE_UNENROLLED_PEER,
            DlqErrorClass::Permanent | DlqErrorClass::PeerUnsupported => CAUSE_PERMANENT,
            DlqErrorClass::IdDrift => CAUSE_ID_DRIFT,
            DlqErrorClass::PeerRemoved => CAUSE_PEER_REMOVED,
            DlqErrorClass::PeerRefused
            | DlqErrorClass::Network
            | DlqErrorClass::Queued
            | DlqErrorClass::Other => CAUSE_OTHER,
        }
    }

    /// Classify a NON-2xx peer response from its REAL HTTP status — the one
    /// fact in this pipeline the peer cannot launder through a body field.
    ///
    /// Mirrors the historical substring arms one-for-one so the emitted
    /// labels are unchanged for every honest peer.
    pub(super) fn from_http_status(status: u16) -> Self {
        match status {
            429 => DlqErrorClass::Throttle,
            401 | 403 => DlqErrorClass::UnenrolledPeer,
            400 | 422 => DlqErrorClass::Permanent,
            _ => DlqErrorClass::Other,
        }
    }

    /// Encode `self` as the reserved leading tag on `reason`.
    ///
    /// The tag is written FIRST, so any peer-derived bytes inside `reason`
    /// land strictly after it and can never participate in the anchored SQL
    /// predicate or the tag parse.
    pub(super) fn stamp(self, reason: &str) -> String {
        format!(
            "{CLASS_TAG_OPEN}{tag}{CLASS_TAG_CLOSE}{reason}",
            tag = self.as_tag()
        )
    }
}

/// Split a persisted `last_error` into `(class, detail)`.
///
/// Returns `None` for an UNTAGGED (pre-#2672 / locally-authored) string, which
/// the caller routes to the legacy substring classifier.
pub(super) fn parse(last_error: &str) -> Option<(DlqErrorClass, &str)> {
    let rest = last_error.strip_prefix(CLASS_TAG_OPEN)?;
    let (tag, detail) = rest.split_once(CLASS_TAG_CLOSE)?;
    // A tag body containing the delimiters would mean the string was not
    // produced by `stamp`; refuse to read it as typed.
    if tag.contains(CLASS_TAG_OPEN) || tag.contains(']') {
        return None;
    }
    Some((DlqErrorClass::from_tag(tag), detail))
}

/// The human-readable half of a persisted `last_error` (the whole string when
/// untagged). Used where only the prose matters — operator log lines and the
/// #2442 legacy-peer annotation, which must keep the class tag LEADING.
pub(super) fn detail_of(last_error: &str) -> &str {
    parse(last_error).map_or(last_error, |(_, detail)| detail)
}

/// The class of a persisted `last_error`, or [`DlqErrorClass::Other`] when it
/// is untagged. Used when re-stamping a row whose original class must be
/// preserved (the #2442 legacy-peer annotation).
pub(super) fn class_of(last_error: &str) -> DlqErrorClass {
    parse(last_error).map_or(DlqErrorClass::Other, |(class, _)| class)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2672 — the exact attack from the issue: a peer answering 200 with
    /// `{"skipped": 429}` must NOT classify as a throttle, and its persisted
    /// row must NOT match the anchored throttle predicate.
    #[test]
    fn peer_supplied_429_count_cannot_forge_a_throttle_2672() {
        let laundered = DlqErrorClass::PeerRefused
            .stamp("peer 2xx but 429 item(s) skipped (refused/not applied by receiver)");
        let (class, detail) = parse(&laundered).expect("stamped string parses");
        assert_eq!(class, DlqErrorClass::PeerRefused);
        assert!(detail.contains("429"), "the diagnostic count is preserved");
        assert_eq!(class.quarantine_cause(), CAUSE_OTHER);
        // The anchored SQL pattern is a prefix match; emulate it here.
        let throttle_prefix = SQL_LIKE_CLASS_THROTTLE.trim_end_matches('%');
        assert!(
            !laundered.starts_with(throttle_prefix),
            "a peer-chosen count must never satisfy the throttle predicate"
        );
        // A REAL 429 does.
        let real = DlqErrorClass::from_http_status(429).stamp("http 429 Too Many Requests");
        assert!(real.starts_with(throttle_prefix));
        assert_eq!(DlqErrorClass::from_http_status(429), DlqErrorClass::Throttle);
    }

    /// Every tag round-trips, and the legacy label vocabulary is preserved.
    #[test]
    fn class_tags_round_trip_and_map_to_the_closed_label_set_2672() {
        for class in [
            DlqErrorClass::Throttle,
            DlqErrorClass::UnenrolledPeer,
            DlqErrorClass::Permanent,
            DlqErrorClass::PeerUnsupported,
            DlqErrorClass::PeerRefused,
            DlqErrorClass::IdDrift,
            DlqErrorClass::PeerRemoved,
            DlqErrorClass::Network,
            DlqErrorClass::Queued,
            DlqErrorClass::Other,
        ] {
            let s = class.stamp("detail text");
            assert_eq!(parse(&s), Some((class, "detail text")));
            assert_eq!(class_of(&s), class);
            assert_eq!(detail_of(&s), "detail text");
            assert!(
                [
                    CAUSE_QUOTA,
                    CAUSE_UNENROLLED_PEER,
                    CAUSE_PERMANENT,
                    CAUSE_ID_DRIFT,
                    CAUSE_PEER_REMOVED,
                    CAUSE_OTHER
                ]
                .contains(&class.quarantine_cause()),
                "label must stay inside the closed set"
            );
        }
    }

    /// An untagged (legacy) string is reported as untagged so the caller can
    /// route it to the historical classifier.
    #[test]
    fn untagged_legacy_strings_are_not_parsed_as_typed_2672() {
        assert_eq!(parse("http 429 Too Many Requests"), None);
        assert_eq!(detail_of("http 429 Too Many Requests"), "http 429 Too Many Requests");
        assert_eq!(class_of("http 429 Too Many Requests"), DlqErrorClass::Other);
        // A malformed tag body is not read as typed either.
        assert_eq!(parse("[ai-memory:class=a]b] x"), None);
    }

    /// The tag carries no SQL `LIKE` wildcard, so the anchored predicates
    /// need no `ESCAPE` clause on either backend.
    #[test]
    fn class_tag_contains_no_like_wildcards_2672() {
        for pat in [
            CLASS_TAG_OPEN,
            CLASS_TAG_CLOSE,
            SQL_LIKE_CLASS_THROTTLE.trim_end_matches('%'),
            SQL_LIKE_ANY_CLASS_TAG.trim_end_matches('%'),
        ] {
            assert!(!pat.contains('%'), "{pat:?} must not contain %");
            assert!(!pat.contains('_'), "{pat:?} must not contain _");
        }
    }

    /// A status the classifier does not name must degrade to `other`, never
    /// to a retry-resetting throttle.
    #[test]
    fn unclassified_statuses_degrade_to_other_2672() {
        for status in [500u16, 502, 503, 418] {
            assert_eq!(DlqErrorClass::from_http_status(status), DlqErrorClass::Other);
        }
        assert_eq!(
            DlqErrorClass::from_http_status(401),
            DlqErrorClass::UnenrolledPeer
        );
        assert_eq!(DlqErrorClass::from_http_status(422), DlqErrorClass::Permanent);
    }
}
