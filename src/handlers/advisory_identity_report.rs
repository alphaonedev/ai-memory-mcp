//! #9341 vote condition B-8 (3-agent vote (71472661)) — the Advisory arm of
//! the identity funnel REPORTS a shared-key caller that names an agent it has
//! not proven; it never refuses (only Enforce refuses, see
//! [`super::authority::refuse_unproven_named_principal`]).
//!
//! The report is a `WARN` on the authz trace target, emitted once per
//! (presented key, claimed id) pair, plus a process-wide counter that counts
//! every such request. Nothing is persisted: no audit-chain row, no signed
//! event (a persisted event would be a format commitment the vote declined).
//!
//! Bounds: the dedup set holds at most [`ADVISORY_UNPROVEN_DEDUP_CAP`]
//! fixed-size digests, so a caller cycling claimed ids cannot grow memory
//! without limit; once full, a new pair is counted but not logged. The
//! claimed id is logged escaped and cut at [`CLAIMED_ID_LOG_MAX_CHARS`], and
//! the presented key is never logged (only its digest is held in memory).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};

use sha2::{Digest, Sha256};

use crate::config::HttpIdentityMode;
use crate::identity::authority::Authority;

/// The most (key, claimed id) digests the dedup set holds (32 bytes each, so
/// the set is bounded near 128 KiB plus table overhead).
pub const ADVISORY_UNPROVEN_DEDUP_CAP: usize = 4096;

/// The most characters of a claimed id written to the log line.
pub const CLAIMED_ID_LOG_MAX_CHARS: usize = 128;

/// Domain separator between the key digest and the claimed id in a dedup
/// digest, so (`k`, `ab`) and (`ka`, `b`) can never collide.
const DEDUP_DOMAIN_SEPARATOR: u8 = 0;

static ADVISORY_UNPROVEN_TOTAL: AtomicU64 = AtomicU64::new(0);
static ADVISORY_UNPROVEN_SEEN: LazyLock<Mutex<HashSet<[u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Every Advisory request so far that named an unproven agent with a key.
#[must_use]
pub fn advisory_unproven_total() -> u64 {
    ADVISORY_UNPROVEN_TOTAL.load(Ordering::Relaxed)
}

/// The claimed id as written to the log: at most
/// [`CLAIMED_ID_LOG_MAX_CHARS`] characters, every control byte, newline,
/// escape (ANSI) byte, quote and non-ASCII character escaped with
/// `char::escape_default`, and a cut marker when the id was longer.
#[must_use]
pub fn claimed_id_for_log(claimed: &str) -> String {
    let mut out: String = claimed
        .chars()
        .take(CLAIMED_ID_LOG_MAX_CHARS)
        .flat_map(char::escape_default)
        .collect();
    if claimed.chars().nth(CLAIMED_ID_LOG_MAX_CHARS).is_some() {
        out.push_str("...(cut)");
    }
    out
}

fn dedup_digest(presented_key: &str, claimed: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(Sha256::digest(presented_key.as_bytes()));
    h.update([DEDUP_DOMAIN_SEPARATOR]);
    h.update(claimed.as_bytes());
    h.finalize().into()
}

/// Record one observation. `Some(escaped id)` when this pair is new and the
/// WARN is due; `None` when it was already reported or the set is full.
/// The counter rises on every call.
#[must_use]
pub fn observe_unproven_claim(presented_key: &str, claimed: &str) -> Option<String> {
    ADVISORY_UNPROVEN_TOTAL.fetch_add(1, Ordering::Relaxed);
    let digest = dedup_digest(presented_key, claimed);
    let mut seen = ADVISORY_UNPROVEN_SEEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if seen.contains(&digest) || seen.len() >= ADVISORY_UNPROVEN_DEDUP_CAP {
        return None;
    }
    seen.insert(digest);
    drop(seen);
    Some(claimed_id_for_log(claimed))
}

/// The Advisory arm. Reports (never refuses) a request that presents a key,
/// names a non-empty agent id and is not key- or certificate-bound.
pub fn report_unproven_named_principal(
    mode: HttpIdentityMode,
    presented_key: Option<&str>,
    header_agent_id: Option<&str>,
    authority: &Authority,
    endpoint: &str,
) {
    if mode != HttpIdentityMode::Advisory || authority.binding().is_key_bound() {
        return;
    }
    let (Some(key), Some(claimed)) = (presented_key, header_agent_id) else {
        return;
    };
    if claimed.is_empty() {
        return;
    }
    if let Some(claimed_escaped) = observe_unproven_claim(key, claimed) {
        tracing::warn!(
            target: super::AUTHZ_TRACE_TARGET,
            endpoint,
            claimed_agent_id = %claimed_escaped,
            advisory_unproven_total = advisory_unproven_total(),
            "#9341 advisory: a shared-key caller named an agent it has not proven \
             (Enforce would refuse; enrol per-agent keys or map certificates)"
        );
    }
}
