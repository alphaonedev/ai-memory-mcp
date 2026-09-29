// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4033 (SEC, CWE-770) — the ONE byte-capped reader for every
//! federation HTTP response body this node reads from a peer.
//!
//! # The defect this closes
//!
//! #1928 capped the `/sync/since` PULL reader (a `Content-Length` pre-check
//! plus a per-chunk accumulator), but the PUSH readers kept buffering the
//! peer's whole response: `post_once` (the per-row fanout AND the push-DLQ
//! replay) called `resp.json()` on a 2xx and `resp.bytes()` on an error, and
//! `bulk_catchup_push` called `resp.bytes()` on both arms. The federation
//! client carries request/connect timeouts but no response-size bound, and a
//! timeout bounds TIME, not BYTES — so a faulty or compromised enrolled peer
//! (in scope per the #1928 threat model) could drive unbounded allocation in
//! the SENDING daemon. The `ai-memory sync-daemon` pull (`resp.json()`) had
//! the same shape.
//!
//! # The fix
//!
//! [`read_body_capped`] is the single accumulator: an early `Content-Length`
//! rejection for an honest oversize peer, then per-chunk accounting that stops
//! reading the moment the NEXT chunk would cross the cap, so a lying peer is
//! cut off mid-transfer and at most `cap` bytes are ever held. The result is
//! TYPED ([`BodyReadError::TooLarge`] vs [`BodyReadError::Transport`]) so a
//! caller can refuse an oversize body specifically — the push lanes must NOT
//! let it fall through their legacy "unparseable 2xx = ack" compatibility arm
//! (an oversize reply is not a well-formed legacy peer; acking it would meet
//! quorum and retire DLQ rows on a response the node never read).

/// #1928 — hard ceiling on a `/sync/since` catch-up response body (the pull
/// lanes: the `serve` catch-up puller and the `sync-daemon` pull). A page of
/// up to 10 000 full rows legitimately runs to tens of MiB.
pub(crate) const MAX_SYNC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// #4033 — hard ceiling on a `/sync/push` RESPONSE body (the per-row fanout,
/// the push-DLQ replay and the bulk catch-up batch lane). The receiver answers
/// a push with a small JSON count report (`applied` / `noop` / `skipped` / …),
/// a few hundred bytes; 1 MiB leaves three orders of magnitude of headroom
/// while bounding what a hostile peer can make this node hold.
pub(crate) const MAX_PUSH_RESPONSE_BYTES: usize = 1024 * 1024;

/// Why a capped body read did not produce the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyReadError {
    /// The body is larger than the cap: either the peer DECLARED a larger
    /// `Content-Length` (rejected before a byte is read) or it streamed past
    /// the cap (the read stopped at the chunk that would have crossed it).
    TooLarge {
        /// The cap that was exceeded.
        cap: usize,
        /// The peer's declared `Content-Length`, when it sent one.
        declared: Option<u64>,
    },
    /// The transport failed mid-body (reset, timeout, malformed chunking).
    /// Carries a classified, URL-free description.
    Transport(String),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge {
                cap,
                declared: Some(len),
            } => write!(
                f,
                "peer response too large: Content-Length {len} exceeds cap of {cap} bytes"
            ),
            Self::TooLarge {
                cap,
                declared: None,
            } => write!(
                f,
                "peer response exceeded cap of {cap} bytes while streaming"
            ),
            Self::Transport(detail) => write!(f, "reading peer response body: {detail}"),
        }
    }
}

impl std::error::Error for BodyReadError {}

/// #4033 — read a peer response body, holding at most `cap` bytes.
///
/// # Errors
///
/// [`BodyReadError::TooLarge`] when the declared or streamed length exceeds
/// `cap`; [`BodyReadError::Transport`] when a chunk read fails.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, BodyReadError> {
    let declared = resp.content_length();
    if let Some(len) = declared
        && len > u64::try_from(cap).unwrap_or(u64::MAX)
    {
        return Err(BodyReadError::TooLarge {
            cap,
            declared: Some(len),
        });
    }
    // Pre-size from an honest declared length (already proven <= cap), never
    // from the cap itself: an empty/short body must not reserve 1 MiB.
    let hint = declared
        .and_then(|len| usize::try_from(len).ok())
        .unwrap_or(0);
    let mut buf: Vec<u8> = Vec::with_capacity(hint);
    loop {
        let chunk = match resp.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Ok(buf),
            // #3710 — classified at the origin; a reqwest error's Display
            // names the full request URL and must never be rendered.
            Err(e) => {
                return Err(BodyReadError::Transport(
                    crate::url_display::network_failure(&e),
                ));
            }
        };
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(BodyReadError::TooLarge {
                cap,
                declared: None,
            });
        }
        buf.extend_from_slice(&chunk);
    }
}

/// #4033 — the `/sync/push` response cap in force. Production is always
/// [`MAX_PUSH_RESPONSE_BYTES`]; a `test-support` build may lower it so a
/// regression test can exercise the cap without streaming a real MiB.
pub(crate) fn push_response_cap() -> usize {
    #[cfg(any(test, feature = "test-support"))]
    {
        let over = test_cap::PUSH_CAP_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
        if over != 0 {
            return over;
        }
    }
    MAX_PUSH_RESPONSE_BYTES
}

/// #4033 — the `/sync/since` pull response cap in force (see
/// [`push_response_cap`] for the test seam).
pub(crate) fn sync_response_cap() -> usize {
    #[cfg(any(test, feature = "test-support"))]
    {
        let over = test_cap::SYNC_CAP_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
        if over != 0 {
            return over;
        }
    }
    MAX_SYNC_RESPONSE_BYTES
}

/// Test-only cap overrides (`test-support`). `0` means "no override".
#[cfg(any(test, feature = "test-support"))]
pub mod test_cap {
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) static PUSH_CAP_OVERRIDE: AtomicUsize = AtomicUsize::new(0);
    pub(super) static SYNC_CAP_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

    /// Lower (or, with `0`, restore) the `/sync/push` response cap.
    pub fn set_push_response_cap(cap: usize) {
        PUSH_CAP_OVERRIDE.store(cap, Ordering::Relaxed);
    }

    /// Lower (or, with `0`, restore) the `/sync/since` response cap.
    pub fn set_sync_response_cap(cap: usize) {
        SYNC_CAP_OVERRIDE.store(cap, Ordering::Relaxed);
    }
}
