//! #9996 — the sync-daemon push lane, split out of `daemon_runtime.rs`
//! (QUAL-10) when it gained the sender-side outbound scope.
//!
//! One push window per cycle: the local rows updated since the peer's push
//! cursor, cut to the peer's [`PeerOutboundScope`] before they reach the wire.
//!
//! ## Cursor rules (vote V2-9996 C-7)
//!
//! - A [`PeerOutboundScope::Deny`] peer keeps its cursor, so granting a scope
//!   later sends the history written while it was denied.
//! - A window with nothing in scope advances the cursor, so a narrowed peer
//!   never stalls on rows that are not its own.
//! - A narrowed peer (a scope that is not all-namespaces) is re-scanned from
//!   the start of history once per sync-daemon process: the scope is read at
//!   start, so a scope widened by a restart sends the rows the old cut left
//!   out. The receiver applies `insert_if_newer`, so the rows it already holds
//!   are no-ops. The re-scan walks one window per cycle and ends at the
//!   stored cursor, where the normal lane takes over.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use anyhow::Result;

use super::outbound_scope::{self, OutboundRefusal, PeerOutboundScope};
use crate::db;
use crate::models::field_names;

/// The lane name the sync-daemon push reports outbound refusals under.
pub const SYNC_DAEMON_PUSH_LANE: &str = "sync_daemon_push";

/// Per-process re-scan state of one `(db, agent, peer)` push cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Rescan {
    /// Re-scanning; the next window starts after this timestamp (`None`:
    /// the start of history).
    From(Option<String>),
    /// The re-scan reached the stored cursor; the normal lane runs.
    Done,
}

/// The re-scan table. One entry per peer of a running sync daemon, so it is
/// bounded by the configured peer list.
static RESCAN: Mutex<BTreeMap<String, Rescan>> = Mutex::new(BTreeMap::new());

fn rescan_key(db_path: &Path, agent_id: &str, peer_key: &str) -> String {
    format!("{}\u{0}{agent_id}\u{0}{peer_key}", db_path.display())
}

/// The cursor this cycle reads from, and whether it is a re-scan window.
fn read_cursor(
    key: &str,
    scope: &PeerOutboundScope,
    stored: Option<String>,
) -> (Option<String>, bool) {
    let narrowed = matches!(scope, PeerOutboundScope::Namespaces(_)) && !scope.is_all();
    let Some(stored_at) = stored.as_deref() else {
        return (stored, false);
    };
    if !narrowed {
        return (stored, false);
    }
    let mut table = RESCAN.lock().unwrap_or_else(PoisonError::into_inner);
    let state = table
        .entry(key.to_string())
        .or_insert_with(|| Rescan::From(None))
        .clone();
    match state {
        Rescan::Done => (stored, false),
        Rescan::From(Some(at)) if at.as_str() >= stored_at => {
            table.insert(key.to_string(), Rescan::Done);
            (stored, false)
        }
        Rescan::From(from) => (from, true),
    }
}

/// Move the re-scan past a window that was read (and sent, or found to hold
/// nothing in scope). An empty window ends it.
fn advance_rescan(key: &str, latest: Option<&str>) {
    let mut table = RESCAN.lock().unwrap_or_else(PoisonError::into_inner);
    let next = latest.map_or(Rescan::Done, |at| Rescan::From(Some(at.to_string())));
    table.insert(key.to_string(), next);
}

/// One push window to `peer_url`. Returns the number of memories sent; an
/// outbound refusal sends nothing and is `Ok(0)`.
///
/// # Errors
///
/// A database error, a transport failure or a non-2xx answer. The cursor
/// and the re-scan stay where they were, so the window is sent again.
#[allow(clippy::too_many_arguments)]
pub async fn push_window(
    client: &reqwest::Client,
    db_path: &Path,
    local_agent_id: &str,
    peer_url: &str,
    peer_key: &str,
    api_key: Option<&str>,
    batch_size: usize,
    scope: &PeerOutboundScope,
) -> Result<usize> {
    let key = rescan_key(db_path, local_agent_id, peer_key);
    let stored = {
        let conn = db::open(db_path)?;
        db::sync_state_last_pushed(&conn, local_agent_id, peer_key)
    };
    let (since, rescanning) = read_cursor(&key, scope, stored);
    let outgoing = {
        let conn = db::open(db_path)?;
        db::memories_updated_since(&conn, since.as_deref(), batch_size)?
    };
    let latest_pushed = outgoing.last().map(|m| m.updated_at.clone());
    if outgoing.is_empty() {
        if rescanning {
            advance_rescan(&key, None);
        }
        return Ok(0);
    }

    let body = serde_json::json!({
        (field_names::SENDER_AGENT_ID): local_agent_id,
        "sender_clock": { "entries": {} },
        "memories": outgoing,
        "dry_run": false,
    });
    let peer_id = super::peer::stable_peer_id(peer_url);
    let scoped = match outbound_scope::admit_recorded(&peer_id, scope, &body) {
        Ok(scoped) => scoped,
        Err(refusal) => {
            outbound_scope::note_refusal_public(&peer_id, SYNC_DAEMON_PUSH_LANE, &refusal);
            if refusal == OutboundRefusal::NothingInScope
                && let Some(at) = latest_pushed.as_deref()
            {
                let conn = db::open(db_path)?;
                db::sync_state_record_push(&conn, local_agent_id, peer_key, at)?;
                if rescanning {
                    advance_rescan(&key, Some(at));
                }
            }
            tracing::info!(
                "sync-daemon: peer={peer_key} pushed=0 ({})",
                refusal.reason()
            );
            return Ok(0);
        }
    };
    // #2297 — serialise the body ONCE so the signature input matches the
    // wire bytes the receiver sees. Sending via `.body(bytes)` + explicit
    // content-type (rather than `.json(&body)`, which re-serialises)
    // guarantees the signed bytes are byte-identical to what the receiver's
    // `verify_signature_or_reject` reads — the same discipline the working
    // /sync/push client uses (`src/federation/sync.rs`).
    let body_bytes = serde_json::to_vec(scoped.body())?;
    // v0.7.0 #238 — attach `x-peer-id` so the receiver attests
    // body.sender_agent_id against our wire-level peer identity.
    let mut req = client
        .post(format!("{peer_url}/api/v1/sync/push"))
        .header(crate::HEADER_AGENT_ID, local_agent_id)
        .header(super::peer_attestation::PEER_ID_HEADER, local_agent_id)
        .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
        .body(body_bytes.clone());
    if let Some(key) = api_key {
        req = req.header(crate::HEADER_API_KEY, key);
    }
    // #2297 — sign the outbound /sync/push POST body with the daemon signing
    // key (loaded from local_agent_id's on-disk keypair) so an ENROLLED peer
    // accepts the push under the default AI_MEMORY_FED_REQUIRE_SIG=1 posture —
    // the receiver's verify_signature_or_reject gate otherwise refuses an
    // enrolled peer's unsigned POST with 401 x_memory_sig_missing. This is the
    // PUSH sibling of the #2290/#2296 pull-side signing: mirrors the working
    // /sync/push client (`src/federation/sync.rs`) — signs
    // `body_bytes || 0x00 || nonce` per the #922 nonce binding + attaches the
    // X-Memory-Sig / X-Memory-Nonce headers. Unsigned when no key is on disk
    // (preserves the permissive / unenrolled posture).
    let push_signing_key = crate::governance::audit::load_daemon_signing_key(local_agent_id)
        .ok()
        .flatten();
    if let Some(sk) = push_signing_key.as_ref() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let sig_header = super::signing::sign_body_with_nonce_header(sk, &body_bytes, &nonce);
        req = req
            .header(super::signing::SIGNATURE_HEADER, sig_header)
            .header(super::signing::NONCE_HEADER, nonce);
    }
    let resp = req.send().await.map_err(|e| {
        anyhow::anyhow!(
            "sync-daemon: push {}",
            crate::url_display::network_failure(&e)
        )
    })?;
    if !resp.status().is_success() {
        anyhow::bail!("sync-daemon: push status {}", resp.status());
    }
    let sent = scoped
        .body()
        .get("memories")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    if let Some(at) = latest_pushed.as_deref() {
        let conn = db::open(db_path)?;
        db::sync_state_record_push(&conn, local_agent_id, peer_key, at)?;
        if rescanning {
            advance_rescan(&key, Some(at));
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn narrowed() -> PeerOutboundScope {
        PeerOutboundScope::Namespaces(vec!["team/a/**".to_string()])
    }

    #[test]
    fn deny_and_all_scopes_read_the_stored_cursor_9996() {
        let stored = Some("2026-01-02T00:00:00Z".to_string());
        for scope in [PeerOutboundScope::Deny, PeerOutboundScope::all_explicit()] {
            assert_eq!(
                read_cursor("k-deny-all-9996", &scope, stored.clone()),
                (stored.clone(), false)
            );
        }
    }

    #[test]
    fn narrowed_scope_rescans_from_history_then_hands_back_9996() {
        let key = "k-rescan-9996";
        let stored = Some("2026-01-03T00:00:00Z".to_string());
        assert_eq!(read_cursor(key, &narrowed(), stored.clone()), (None, true));
        advance_rescan(key, Some("2026-01-01T00:00:00Z"));
        assert_eq!(
            read_cursor(key, &narrowed(), stored.clone()),
            (Some("2026-01-01T00:00:00Z".to_string()), true)
        );
        advance_rescan(key, Some("2026-01-03T00:00:00Z"));
        assert_eq!(
            read_cursor(key, &narrowed(), stored.clone()),
            (stored.clone(), false)
        );
        assert_eq!(
            read_cursor(key, &narrowed(), stored.clone()),
            (stored, false)
        );
    }

    #[test]
    fn empty_rescan_window_ends_the_rescan_9996() {
        let key = "k-empty-9996";
        let stored = Some("2026-01-03T00:00:00Z".to_string());
        assert_eq!(read_cursor(key, &narrowed(), stored.clone()), (None, true));
        advance_rescan(key, None);
        assert_eq!(
            read_cursor(key, &narrowed(), stored.clone()),
            (stored, false)
        );
    }

    #[test]
    fn never_pushed_peer_reads_from_history_without_rescan_9996() {
        assert_eq!(
            read_cursor("k-fresh-9996", &narrowed(), None),
            (None, false)
        );
    }
}
