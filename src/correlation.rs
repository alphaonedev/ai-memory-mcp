// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3663 — operation correlation across the transport, storage, federation
//! and wake boundaries.
//!
//! # The problem
//!
//! Every boundary had a useful LOCAL identifier (the MCP `rpc_id`, the
//! signed-event id and sequence, the federation peer and memory id, the inbox
//! row id and wake sequence), but nothing tied them to the operation that
//! caused them. An operator could not follow one request to its signed write,
//! its peer apply, its notification and the recipient's read using telemetry
//! alone. A memory id alone conflates retries and successive mutations.
//!
//! # The control
//!
//! 1. **Operation id.** [`mint_op_id`] returns a fixed-length, random, opaque
//!    id minted by the substrate at each ingress (an HTTP request, an MCP
//!    `tools/call`). It is never derived from content, ids or caller input, so
//!    it is privacy-safe and bounded, and it is never a metric label: it lives
//!    only in a tracing span field ([`OP_ID_FIELD`]). Every event emitted
//!    inside the span inherits it, in both the text and the JSON formatter.
//! 2. **Span propagation.** Work that leaves the request task (federation
//!    fan-out tasks, the detached post-quorum drain, the blocking DB workers)
//!    re-enters the parent span through [`spawn_in_set`] / [`spawn_detached`]
//!    or an explicit `Span::current()` capture, so its events keep the id.
//! 3. **Hop mappings.** Each boundary logs, under [`TARGET`], the pair
//!    (current operation, hop identifier), using identifiers that are ALREADY
//!    authenticated or persisted — so no wire field and no schema change is
//!    needed:
//!    - signed write: the signed-event id, sequence and event type at append;
//!    - federation: [`push_ref`] of the `X-Memory-Nonce`, logged by the sender
//!      at dispatch and by the receiver on `/sync/push` (the nonce is bound
//!      into the Ed25519 signature input, so the join is authenticated);
//!    - wake: the inbox row id at notify publish and at the recipient's read.
//!
//! An operator filters on `target = ai_memory::correlation` and joins
//! `op_id → event id / push_ref / inbox row id → op_id` across processes and
//! nodes.

use std::future::Future;

use sha2::{Digest, Sha256};
use tracing::Instrument;

/// Tracing target of every hop-mapping event. Operators filter on it
/// (`RUST_LOG=ai_memory::correlation=info`) to extract the join table.
pub const TARGET: &str = "ai_memory::correlation";

/// The span field name that carries the operation id.
pub const OP_ID_FIELD: &str = "op_id";

/// Hex length of a minted operation id (64 random bits).
pub const OP_ID_HEX_LEN: usize = 16;

/// Hex length of a [`push_ref`] (the first 64 bits of the SHA-256).
pub const PUSH_REF_HEX_LEN: usize = 16;

/// Upper bound on the inbox row ids listed in one recipient-read event, so a
/// large inbox page cannot produce an unbounded log line. The event always
/// carries the full count.
pub const MAX_LOGGED_ROW_IDS: usize = 32;

/// Mint a fresh operation id: [`OP_ID_HEX_LEN`] lowercase hex characters of
/// OS randomness (the leading 64 bits of a UUIDv4's random payload).
#[must_use]
pub fn mint_op_id() -> String {
    let mut id = uuid::Uuid::new_v4().simple().to_string();
    id.truncate(OP_ID_HEX_LEN);
    id
}

/// Stable, privacy-safe reference to one federation push: the first
/// [`PUSH_REF_HEX_LEN`] hex characters of SHA-256 over the `X-Memory-Nonce`
/// value. The sender and the receiver compute the same reference from the
/// same header, so the pair joins across nodes without logging the replay
/// token itself.
#[must_use]
pub fn push_ref(nonce: &str) -> String {
    let digest = Sha256::digest(nonce.as_bytes());
    let mut out = hex::encode(digest);
    out.truncate(PUSH_REF_HEX_LEN);
    out
}

/// Spawn `fut` onto `set` inside the CURRENT span, so events emitted by the
/// task keep the caller's operation id. A plain `JoinSet::spawn` starts the
/// task with no span at all.
pub fn spawn_in_set<T, F>(set: &mut tokio::task::JoinSet<T>, fut: F) -> tokio::task::AbortHandle
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    set.spawn(fut.in_current_span())
}

/// Fire-and-forget `tokio::spawn` inside the CURRENT span (see
/// [`spawn_in_set`]). The handle is dropped, which detaches the task exactly
/// as the plain `tokio::spawn(..);` statements this replaces did.
pub fn spawn_detached<F>(fut: F)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    drop(tokio::spawn(fut.in_current_span()));
}

/// Bounded view of a list of inbox row ids for a recipient-read event: at
/// most [`MAX_LOGGED_ROW_IDS`] ids, comma-joined.
#[must_use]
pub fn bounded_row_ids<'a, I>(ids: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    ids.into_iter()
        .take(MAX_LOGGED_ROW_IDS)
        .collect::<Vec<_>>()
        .join(",")
}

/// `tower_http` span maker for the HTTP daemon: an INFO-level
/// `http_request` span carrying the method, the URI PATH (never the query
/// string, which can carry caller data) and a fresh operation id.
///
/// The `tower_http` default span is DEBUG, so under the default `info`
/// filter it was disabled and HTTP events carried no request context at all.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpOpSpan;

impl<B> tower_http::trace::MakeSpan<B> for HttpOpSpan {
    fn make_span(&mut self, request: &axum::http::Request<B>) -> tracing::Span {
        tracing::info_span!(
            "http_request",
            method = %request.method(),
            path = %request.uri().path(),
            op_id = %mint_op_id(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_id_is_fixed_length_lowercase_hex_and_fresh() {
        let a = mint_op_id();
        let b = mint_op_id();
        assert_eq!(a.len(), OP_ID_HEX_LEN, "op id `{a}`");
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "op id `{a}` is not lowercase hex"
        );
        assert_ne!(a, b, "two minted op ids collided");
    }

    #[test]
    fn push_ref_is_deterministic_bounded_and_not_the_nonce() {
        let nonce = "0b3c1f7e-6d2a-4e5b-9c8d-7a6f5e4d3c2b";
        let r = push_ref(nonce);
        assert_eq!(r, push_ref(nonce), "sender and receiver must agree");
        assert_eq!(r.len(), PUSH_REF_HEX_LEN);
        assert!(!nonce.contains(&r), "the reference must not echo the nonce");
        assert_ne!(r, push_ref("another-nonce"));
    }

    #[test]
    fn bounded_row_ids_caps_the_list() {
        let ids: Vec<String> = (0..MAX_LOGGED_ROW_IDS + 5)
            .map(|i| format!("r{i}"))
            .collect();
        let out = bounded_row_ids(ids.iter().map(String::as_str));
        assert_eq!(out.split(',').count(), MAX_LOGGED_ROW_IDS);
        assert!(out.starts_with("r0,r1,"));
        assert_eq!(bounded_row_ids(std::iter::empty()), "");
    }

    #[tokio::test]
    async fn spawned_tasks_inherit_the_parent_span() {
        // A registry assigns span ids; the default current-thread test
        // runtime keeps every task on this thread, where the guard applies.
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry());
        let span = tracing::info_span!("parent_op", op_id = "fixed");
        let parent = span.id();
        assert!(parent.is_some(), "the registry must enable the span");
        let (inner, detached, bare) = async {
            let mut set = tokio::task::JoinSet::new();
            spawn_in_set(&mut set, async { tracing::Span::current().id() });
            let inner = set.join_next().await;
            let (tx, rx) = tokio::sync::oneshot::channel();
            spawn_detached(async move {
                let _ = tx.send(tracing::Span::current().id());
            });
            let detached = rx.await;
            // Control: a plain spawn starts outside the span.
            let bare = tokio::spawn(async { tracing::Span::current().id() }).await;
            (inner, detached, bare)
        }
        .instrument(span)
        .await;
        assert_eq!(inner.and_then(Result::ok).flatten(), parent);
        assert_eq!(detached.ok().flatten(), parent);
        assert_eq!(
            bare.ok().flatten(),
            None,
            "control: plain spawn has no span"
        );
    }
}
