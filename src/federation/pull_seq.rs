// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9082 — the puller half of the serving-assigned sequence walk.
//!
//! Every `/sync/since` puller sends `after_seq` (its stored `last_seq`
//! against that peer, 0 when none) beside `since`. A peer that answers with
//! `next_seq` walked its own `memories.sync_seq`, so the puller resolves a
//! sequence cursor ([`crate::federation::pull_cursor::PullCursorTracker::resolve_seq`])
//! and stores it in `sync_pull_seq`; the timestamp cursor in `sync_state` is
//! left alone. A peer that answers without `next_seq` (an older build) is
//! pulled on the timestamp path exactly as before, with no probe.
//!
//! The reply is untrusted input: [`SeqReply::parse`] bounds every field and a
//! malformed reply applies nothing and moves no cursor.

use crate::federation::pull_cursor::PullCursorTracker;
use crate::models::field_names;
use crate::storage::sync_seq::PullSeqCursor;

/// The longest `seq_epoch` accepted from a peer (the serving node mints 32
/// hex characters; the bound keeps a hostile peer from storing an unbounded
/// string in `sync_pull_seq`).
pub(crate) const SEQ_EPOCH_MAX_LEN: usize = 64;

/// A peer's answer on the sequence walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeqReply {
    /// The `after_seq` the peer walked from.
    pub(crate) effective_after: i64,
    /// The highest sequence the peer examined for this page.
    pub(crate) next_seq: i64,
    /// The peer's numbering epoch.
    pub(crate) epoch: String,
}

/// How a `/sync/since` reply relates to the sequence walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeqParse {
    /// No `next_seq`: an older peer, pull on the timestamp path.
    Absent,
    /// A well-formed sequence answer.
    Seq(SeqReply),
    /// `next_seq` present but the answer is not a valid sequence answer.
    Malformed(&'static str),
}

fn non_negative(body: &serde_json::Value, key: &str) -> Option<i64> {
    body.get(key)
        .and_then(serde_json::Value::as_i64)
        .filter(|v| *v >= 0)
}

impl SeqReply {
    /// Classify `body`, the reply to a request that sent `sent_after`.
    ///
    /// The peer may walk from `sent_after` or, after its own reset, from 0;
    /// any other `after_seq`, a negative or non-integer value, a `next_seq`
    /// below the walked `after_seq`, or an epoch that is empty, longer than
    /// [`SEQ_EPOCH_MAX_LEN`] or not ASCII alphanumeric is `Malformed`.
    pub(crate) fn parse(body: &serde_json::Value, sent_after: i64) -> SeqParse {
        let Some(raw_next) = body.get(field_names::NEXT_SEQ).filter(|v| !v.is_null()) else {
            return SeqParse::Absent;
        };
        let Some(next_seq) = raw_next.as_i64().filter(|v| *v >= 0) else {
            return SeqParse::Malformed("next_seq is not an integer >= 0");
        };
        let Some(effective_after) = non_negative(body, field_names::AFTER_SEQ) else {
            return SeqParse::Malformed("after_seq is missing or not an integer >= 0");
        };
        if effective_after != sent_after && effective_after != 0 {
            return SeqParse::Malformed("after_seq is neither the sent value nor 0");
        }
        if next_seq < effective_after {
            return SeqParse::Malformed("next_seq is below the walked after_seq");
        }
        let Some(epoch) = body.get(field_names::SEQ_EPOCH).and_then(|v| v.as_str()) else {
            return SeqParse::Malformed("seq_epoch is missing or not a string");
        };
        if epoch.is_empty()
            || epoch.len() > SEQ_EPOCH_MAX_LEN
            || !epoch.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return SeqParse::Malformed("seq_epoch is not 1..=64 ASCII alphanumerics");
        }
        SeqParse::Seq(Self {
            effective_after,
            next_seq,
            epoch: epoch.to_string(),
        })
    }

    /// `true` when the stored cursor was taken under another epoch and the
    /// peer walked from a non-zero `after_seq`: the rows between 0 and that
    /// value in the NEW numbering were never offered, so the walk restarts
    /// at 0.
    pub(crate) fn needs_rewalk(&self, stored: &PullSeqCursor) -> bool {
        self.effective_after != 0 && stored.seq_epoch.as_deref().is_some_and(|e| e != self.epoch)
    }
}

/// Load the stored sequence cursor; a read failure is logged and walks from
/// 0 (a re-walk is idempotent, a skipped row is not).
pub(crate) fn load_cursor(
    conn: &rusqlite::Connection,
    local_id: &str,
    peer: &str,
) -> PullSeqCursor {
    crate::storage::sync_seq::sync_pull_seq_get(conn, local_id, peer).unwrap_or_else(|e| {
        tracing::warn!(
            target: crate::federation::SCOPE_TRACE_TARGET,
            peer = %peer,
            error = %e,
            "pull: sync_pull_seq read failed; walking from 0 (#9082)"
        );
        PullSeqCursor::default()
    })
}

/// Persist the sequence cursor; a failure is logged (the next window
/// re-walks from the old value, which is idempotent).
pub(crate) fn store_cursor(
    conn: &rusqlite::Connection,
    local_id: &str,
    peer: &str,
    last_seq: i64,
    epoch: &str,
) {
    if let Err(e) =
        crate::storage::sync_seq::sync_pull_seq_set(conn, local_id, peer, last_seq, epoch)
    {
        tracing::warn!(
            target: crate::federation::SCOPE_TRACE_TARGET,
            peer = %peer,
            error = %e,
            "pull: sync_pull_seq write failed; the window is re-walked (#9082)"
        );
    }
}

/// Log a malformed sequence answer (the window applies nothing).
pub(crate) fn log_malformed(peer: &str, why: &str) {
    tracing::warn!(
        target: crate::federation::SCOPE_TRACE_TARGET,
        peer = %peer,
        reason = why,
        "pull: malformed sequence answer; nothing applied, no cursor moved (#9082)"
    );
}

/// The walk a `/sync/since` window was answered on: `Some` is the sequence
/// walk (the reply and the cursor the request was sent with), `None` the
/// timestamp path of an older peer.
pub(crate) type SeqWindow = Option<(SeqReply, PullSeqCursor)>;

/// Classify `body`, the reply to a request sent with `stored`. `None` is a
/// malformed sequence answer (logged here); the caller applies nothing and
/// moves no cursor.
pub(crate) fn classify(
    body: &serde_json::Value,
    stored: PullSeqCursor,
    peer: &str,
) -> Option<SeqWindow> {
    match SeqReply::parse(body, stored.after_seq()) {
        SeqParse::Absent => Some(None),
        SeqParse::Seq(reply) => Some(Some((reply, stored))),
        SeqParse::Malformed(why) => {
            log_malformed(peer, why);
            None
        }
    }
}

/// The tracker for a window on either walk.
pub(crate) fn tracker_for(
    seq: &SeqWindow,
    since: Option<String>,
    page_limit: usize,
) -> PullCursorTracker {
    if seq.is_some() {
        PullCursorTracker::new_seq(page_limit)
    } else {
        PullCursorTracker::new(since, page_limit)
    }
}

/// Resolve the window's cursor and persist it: the sequence cursor in
/// `sync_pull_seq` when the peer walked its sequence (the timestamp cursor
/// is left alone; a write failure is logged and the window is re-walked),
/// else the halt-gated, clock-bounded timestamp cursor in `sync_state`.
///
/// # Errors
///
/// The `sync_state` write error on the timestamp path.
pub(crate) fn persist_cursor(
    conn: &rusqlite::Connection,
    tracker: &mut PullCursorTracker,
    seq: &SeqWindow,
    next_since: Option<&str>,
    returned: usize,
    local_id: &str,
    peer: &str,
) -> anyhow::Result<()> {
    if let Some((reply, stored)) = seq {
        let value = tracker.resolve_seq(
            reply.effective_after,
            reply.next_seq,
            returned,
            reply.needs_rewalk(stored),
            peer,
        );
        store_cursor(conn, local_id, peer, value, &reply.epoch);
    } else if let Some(ts) = tracker.resolve(next_since, returned, peer) {
        crate::db::sync_state_observe(conn, local_id, peer, &ts)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SEQ_EPOCH_MAX_LEN, SeqParse, SeqReply};
    use crate::storage::sync_seq::PullSeqCursor;
    use serde_json::json;

    const EPOCH: &str = "0123456789abcdef0123456789abcdef";

    fn reply(after: i64, next: i64) -> SeqReply {
        SeqReply {
            effective_after: after,
            next_seq: next,
            epoch: EPOCH.to_string(),
        }
    }

    #[test]
    fn parse_table_9082() {
        let long = "a".repeat(SEQ_EPOCH_MAX_LEN + 1);
        let cases: Vec<(serde_json::Value, i64, SeqParse)> = vec![
            (json!({"next_since": null}), 5, SeqParse::Absent),
            (json!({"next_seq": null}), 5, SeqParse::Absent),
            (
                json!({"next_seq": 9, "after_seq": 5, "seq_epoch": EPOCH}),
                5,
                SeqParse::Seq(reply(5, 9)),
            ),
            (
                json!({"next_seq": 3, "after_seq": 0, "seq_epoch": EPOCH}),
                5,
                SeqParse::Seq(reply(0, 3)),
            ),
            (
                json!({"next_seq": -1, "after_seq": 0, "seq_epoch": EPOCH}),
                0,
                SeqParse::Malformed("next_seq is not an integer >= 0"),
            ),
            (
                json!({"next_seq": "9", "after_seq": 0, "seq_epoch": EPOCH}),
                0,
                SeqParse::Malformed("next_seq is not an integer >= 0"),
            ),
            (
                json!({"next_seq": 9, "seq_epoch": EPOCH}),
                0,
                SeqParse::Malformed("after_seq is missing or not an integer >= 0"),
            ),
            (
                json!({"next_seq": 9, "after_seq": 4, "seq_epoch": EPOCH}),
                5,
                SeqParse::Malformed("after_seq is neither the sent value nor 0"),
            ),
            (
                json!({"next_seq": 4, "after_seq": 5, "seq_epoch": EPOCH}),
                5,
                SeqParse::Malformed("next_seq is below the walked after_seq"),
            ),
            (
                json!({"next_seq": 9, "after_seq": 5}),
                5,
                SeqParse::Malformed("seq_epoch is missing or not a string"),
            ),
            (
                json!({"next_seq": 9, "after_seq": 5, "seq_epoch": ""}),
                5,
                SeqParse::Malformed("seq_epoch is not 1..=64 ASCII alphanumerics"),
            ),
            (
                json!({"next_seq": 9, "after_seq": 5, "seq_epoch": long}),
                5,
                SeqParse::Malformed("seq_epoch is not 1..=64 ASCII alphanumerics"),
            ),
            (
                json!({"next_seq": 9, "after_seq": 5, "seq_epoch": "ab\ncd"}),
                5,
                SeqParse::Malformed("seq_epoch is not 1..=64 ASCII alphanumerics"),
            ),
        ];
        for (body, sent, want) in cases {
            assert_eq!(SeqReply::parse(&body, sent), want, "body {body}");
        }
    }

    #[test]
    fn foreign_epoch_rewalks_from_zero_9082() {
        let stored = PullSeqCursor {
            last_seq: Some(5),
            seq_epoch: Some("other".to_string()),
        };
        assert!(reply(5, 9).needs_rewalk(&stored));
        // The peer already walked from 0 under its new epoch: keep the walk.
        assert!(!reply(0, 3).needs_rewalk(&stored));
        let same = PullSeqCursor {
            last_seq: Some(5),
            seq_epoch: Some(EPOCH.to_string()),
        };
        assert!(!reply(5, 9).needs_rewalk(&same));
        assert!(!reply(5, 9).needs_rewalk(&PullSeqCursor::default()));
    }
}
