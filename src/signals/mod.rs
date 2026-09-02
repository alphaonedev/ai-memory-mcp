// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — signed-signal sqlite free-functions.
//!
//! These operate on a raw [`rusqlite::Connection`] so BOTH the SAL
//! [`crate::store::sqlite::SqliteStore`] adapter (which delegates here) AND
//! the future MCP stdio `memory_signal_*` tool handlers (which hold a bare
//! `Connection`, not a SAL store) share one implementation — exactly the
//! split [`crate::actions`] uses for the coordination-action surface. The
//! postgres adapter keeps its own sqlx-native path in `crate::store::postgres`.
//!
//! v0.8.0 Pillar-1 (#1709) signing: [`sign_into`] populates a [`Signal`]'s
//! `signature` (64-byte Ed25519 over the canonical signal content) +
//! `sender_pubkey` (the signer's 32-byte public key); [`verify`] re-derives
//! the same canonical bytes and checks the signature. The persistence
//! free-functions above store / read those byte vectors verbatim — a signal
//! written with empty `signature` / `sender_pubkey` is simply unsigned.

use crate::identity::keypair::AgentKeypair;
use crate::identity::sign::{SignableSignal, sign_signal};
use crate::identity::verify::verify_signal;
use crate::models::{Signal, SignalType};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

/// #1714 / #1722 — `signed_events` audit-chain event type for an outbound
/// coordination signal send. Back-compat re-export of the SSOT
/// [`crate::coordination_audit::SIGNAL_SEND`] (the slug moved into the
/// shared coordination-audit module in #1722); existing call sites that
/// reference `crate::signals::SIGNAL_SEND_EVENT_TYPE` keep compiling.
pub use crate::coordination_audit::SIGNAL_SEND as SIGNAL_SEND_EVENT_TYPE;

/// SHA-256 over the signal body's canonical JSON string's UTF-8 bytes. This is
/// the bounded payload the signature commits to (the same bound the persona /
/// write signers use for their body hashes), so the signed envelope stays
/// ~200 bytes regardless of body length.
fn body_sha256(signal: &Signal) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signal.body.to_string().as_bytes());
    hasher.finalize().into()
}

/// Build the [`SignableSignal`] view of a [`Signal`] — the immutable fields the
/// signature commits to, borrowing from `signal` and the precomputed
/// `body_hash`. Shared by [`sign_into`] (outbound) and [`verify`] (inbound) so
/// both commit to byte-identical canonical bytes.
fn signable<'a>(signal: &'a Signal, body_hash: &'a [u8; 32]) -> SignableSignal<'a> {
    SignableSignal {
        id: &signal.id,
        namespace: &signal.namespace,
        from_agent: &signal.from_agent,
        to_agent: signal.to_agent.as_deref(),
        subject: &signal.subject,
        body_sha256: body_hash,
        signal_type: signal.signal_type.as_str(),
        in_reply_to: signal.in_reply_to.as_deref(),
        correlation_id: signal.correlation_id.as_deref(),
        created_at: signal.created_at,
    }
}

/// Sign `signal` in place with `keypair`'s private key.
///
/// Hashes the body, builds the [`SignableSignal`] view, signs the canonical
/// CBOR via [`sign_signal`], then sets `signal.signature` to the 64-byte
/// signature and `signal.sender_pubkey` to the signer's 32 public-key bytes.
///
/// # Errors
/// Returns the [`sign_signal`] error when `keypair` is public-only
/// (`can_sign() == false`) or the CBOR encode fails.
pub fn sign_into(signal: &mut Signal, keypair: &AgentKeypair) -> anyhow::Result<()> {
    let body_hash = body_sha256(signal);
    let sig = sign_signal(keypair, &signable(signal, &body_hash))?;
    signal.signature = sig;
    signal.sender_pubkey = keypair.public.to_bytes().to_vec();
    Ok(())
}

/// Verify a signal's Ed25519 signature against its embedded `sender_pubkey`.
///
/// Returns `false` for an unsigned signal (empty `signature` OR empty
/// `sender_pubkey`) and for any signature that does not validate against the
/// re-derived canonical bytes. Never panics.
#[must_use]
pub fn verify(signal: &Signal) -> bool {
    if signal.signature.is_empty() || signal.sender_pubkey.is_empty() {
        return false;
    }
    let body_hash = body_sha256(signal);
    verify_signal(
        &signable(signal, &body_hash),
        &signal.signature,
        &signal.sender_pubkey,
    )
}

/// Verify a signal's Ed25519 signature against an EXPLICITLY supplied public
/// key — the locally-**enrolled** key of `signal.from_agent` — rather than the
/// wire-embedded `sender_pubkey`.
///
/// #1843 (v0.8.1) — the federation receive path's strict-mode author binding.
/// [`verify`] proves the holder of the wire `sender_pubkey` signed the signal,
/// but a relaying peer controls that field, so it does not bind `from_agent` to
/// an attested identity. This re-derives the exact canonical bytes [`sign_into`]
/// signed and checks the signature against the caller-supplied enrolled key
/// (binds `from_agent → enrolled key`, the same gate the transition lane applies
/// to `claimed_by`). Returns `false` — never panics — for an unsigned signal
/// (empty `signature`) and for any key/signature that does not validate.
#[must_use]
pub fn verify_with_key(signal: &Signal, pubkey: &[u8]) -> bool {
    if signal.signature.is_empty() {
        return false;
    }
    let body_hash = body_sha256(signal);
    verify_signal(&signable(signal, &body_hash), &signal.signature, pubkey)
}

/// SELECT column list for the `signals` table, in the canonical order
/// [`row_to_signal`] expects. One definition shared by every signal read.
pub const SIGNAL_SELECT_SQL: &str = "SELECT id, namespace, from_agent, to_agent, subject, body, \
     signal_type, in_reply_to, correlation_id, reference_ids, created_at, expires_at, \
     delivered_at, read_at, acknowledged_at, signature, sender_pubkey FROM signals";

/// Map a `rusqlite` row (the [`SIGNAL_SELECT_SQL`] column order) to a
/// [`Signal`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_signal(r: &rusqlite::Row<'_>) -> rusqlite::Result<Signal> {
    Ok(Signal {
        id: r.get(0)?,
        namespace: r.get(1)?,
        from_agent: r.get(2)?,
        to_agent: r.get(3)?,
        subject: r.get(4)?,
        body: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or(serde_json::Value::Null),
        signal_type: SignalType::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
        in_reply_to: r.get(7)?,
        correlation_id: r.get(8)?,
        reference_ids: serde_json::from_str(&r.get::<_, String>(9)?)
            .unwrap_or(serde_json::Value::Null),
        created_at: r.get(10)?,
        expires_at: r.get(11)?,
        delivered_at: r.get(12)?,
        read_at: r.get(13)?,
        acknowledged_at: r.get(14)?,
        signature: r.get::<_, Vec<u8>>(15)?,
        sender_pubkey: r.get::<_, Vec<u8>>(16)?,
    })
}

/// Insert a signal. Returns the signal id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn insert(conn: &Connection, signal: &Signal) -> rusqlite::Result<String> {
    crate::storage::record_stop::gate_storage_conn_rusqlite(conn)?;
    conn.execute(
        "INSERT INTO signals \
            (id, namespace, from_agent, to_agent, subject, body, signal_type, \
             in_reply_to, correlation_id, reference_ids, created_at, expires_at, \
             delivered_at, read_at, acknowledged_at, signature, sender_pubkey) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            signal.id,
            signal.namespace,
            signal.from_agent,
            signal.to_agent,
            signal.subject,
            signal.body.to_string(),
            signal.signal_type.as_str(),
            signal.in_reply_to,
            signal.correlation_id,
            signal.reference_ids.to_string(),
            signal.created_at,
            signal.expires_at,
            signal.delivered_at,
            signal.read_at,
            signal.acknowledged_at,
            signal.signature,
            signal.sender_pubkey,
        ],
    )?;
    Ok(signal.id.clone())
}

/// Fetch a signal by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn get(conn: &Connection, id: &str) -> rusqlite::Result<Option<Signal>> {
    conn.query_row(
        &format!("{SIGNAL_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_signal,
    )
    .optional()
}

/// List a namespace inbox, newest-first, capped at `limit`. When `to_agent`
/// is `Some`, returns both direct messages (`to_agent = ?2`) and broadcasts
/// (`to_agent IS NULL`); when `None`, returns every signal in the namespace.
///
/// #3011 — ACKNOWLEDGED signals are excluded (`acknowledged_at IS NULL`): an
/// inbox that keeps re-returning acked signals re-serves the same work forever.
/// Use [`thread`] / [`get`] to read an already-acked signal by correlation / id.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn list_inbox(
    conn: &Connection,
    namespace: &str,
    to_agent: Option<&str>,
    limit: usize,
) -> rusqlite::Result<Vec<Signal>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{SIGNAL_SELECT_SQL} WHERE namespace = ? AND acknowledged_at IS NULL");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(agent) = to_agent {
        sql.push_str(" AND (to_agent = ? OR to_agent IS NULL)");
        binds.push(Box::new(agent.to_string()));
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_signal,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Every signal sharing a `correlation_id`, oldest-first (thread order).
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn thread(conn: &Connection, correlation_id: &str) -> rusqlite::Result<Vec<Signal>> {
    let mut stmt = conn.prepare(&format!(
        "{SIGNAL_SELECT_SQL} WHERE correlation_id = ?1 ORDER BY created_at ASC"
    ))?;
    let rows = stmt.query_map(params![correlation_id], row_to_signal)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// #3011 — retention: delete every signal whose caller-declared `expires_at`
/// has passed (`expires_at IS NOT NULL AND expires_at <= now`). Only
/// caller-declared-ephemeral signals are reaped, so this is intended TTL
/// expiry, never unintentional loss of a durable record. Returns the number of
/// rows deleted. Driven best-effort from the `db::gc` chokepoint so every gc
/// topology (serve daemon, MCP stdio, CLI) prunes without a background loop.
///
/// The blanket time-based retention of the OTHER coordination tables (acked /
/// non-expiring signals, terminal actions, resolved checkpoints, routine_runs)
/// is DEFERRED: resolved checkpoints are attested separation-of-duties freeze
/// anchors, so their retention posture is a data-integrity (T3/T4) design call
/// that needs a 5-agent vote + an archive-before-delete design, not a raw
/// `DELETE`. See the #3011 report note.
///
/// # Errors
/// Propagates the `rusqlite` delete error.
pub fn prune_expired(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    crate::storage::record_stop::gate_storage_conn_rusqlite(conn)?;
    let n = conn.execute(
        "DELETE FROM signals WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        params![now],
    )?;
    Ok(n)
}

/// Stamp `delivered_at` on a signal once. Returns `true` when this call set
/// the timestamp, `false` when it was already delivered (or no row matched).
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn mark_delivered(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<bool> {
    crate::storage::record_stop::gate_storage_conn_rusqlite(conn)?;
    let n = conn.execute(
        "UPDATE signals SET delivered_at = ?1 WHERE id = ?2 AND delivered_at IS NULL",
        params![now, id],
    )?;
    Ok(n > 0)
}

/// Stamp `read_at` on a signal once. Returns `true` when this call set the
/// timestamp, `false` when it was already read (or no row matched).
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn mark_read(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<bool> {
    crate::storage::record_stop::gate_storage_conn_rusqlite(conn)?;
    let n = conn.execute(
        "UPDATE signals SET read_at = ?1 WHERE id = ?2 AND read_at IS NULL",
        params![now, id],
    )?;
    Ok(n > 0)
}

/// #3364 — why a signal acknowledgement was REFUSED.
///
/// `memory_signal_ack` carried NO authorization: any co-located agent could
/// stamp `acknowledged_at` on a signal addressed to somebody else. Two things
/// made that worse than a nuisance:
///
/// - the `memory_signal_inbox` surface is UNACKED-ONLY (#3171), so a wrongful
///   ack makes the message VANISH from its real addressee's inbox — silent
///   coordination-message loss, not merely a wrong flag;
/// - the handler had no actor, so the `coordination.signal_ack` audit row was
///   attributed to the signal's `to_agent`. The tamper-evident record NAMED
///   THE VICTIM as the acknowledger, which is worse than no record at all: an
///   auditor reading the chain is told alice acked when bob did.
///
/// The refusal is a typed error (not a `String`) so the MCP, and any future
/// HTTP/SAL, lane can render or classify it without re-parsing prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckDenied {
    /// The resolved caller is not the signal's addressee. The addressee is
    /// deliberately NOT echoed back: a refused caller learns only that it may
    /// not ack this id, never who the message was for.
    NotAddressee {
        /// The signal the caller tried to acknowledge.
        signal_id: String,
        /// The RESOLVED caller identity (never a caller-asserted body value).
        caller: String,
    },
    /// The signal is a namespace BROADCAST (`to_agent` NULL or blank), so it
    /// has no addressee to bind an acknowledgement to. `acknowledged_at` is a
    /// single column on the row, so letting any one recipient ack a broadcast
    /// would hide it from EVERY other recipient's (unacked-only) inbox.
    Broadcast {
        /// The broadcast signal the caller tried to acknowledge.
        signal_id: String,
    },
}

impl std::fmt::Display for AckDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAddressee { signal_id, caller } => write!(
                f,
                "refused signal_ack {signal_id}: caller {caller} is not the addressee of this \
                 signal — only the agent a signal is addressed to may acknowledge it"
            ),
            Self::Broadcast { signal_id } => write!(
                f,
                "refused signal_ack {signal_id}: a namespace broadcast has no addressee, so no \
                 single agent may acknowledge it on behalf of the namespace"
            ),
        }
    }
}

impl std::error::Error for AckDenied {}

/// #3364 — THE authorization decision for a signal acknowledgement.
///
/// Side-effect-free and backend-agnostic on purpose: it takes the STORED
/// signal (the durable truth — never a caller-supplied echo of it) and the
/// RESOLVED caller identity, so the sqlite MCP lane and any future
/// HTTP/SAL lane can share one verdict instead of re-deriving it. Callers
/// must load the row and run this BEFORE stamping anything.
///
/// Fail-closed: a signal with no addressee (a namespace broadcast, or a blank
/// `to_agent`) is refused rather than acked by whoever asked first. Both sides
/// are compared trimmed, so trailing whitespace in a stored `to_agent` cannot
/// lock its own addressee out.
///
/// # Errors
/// [`AckDenied::NotAddressee`] when the caller is not the addressee;
/// [`AckDenied::Broadcast`] when the signal has no addressee at all.
pub fn authorize_ack(signal: &Signal, caller: &str) -> Result<(), AckDenied> {
    let addressee = signal
        .to_agent
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty());
    let Some(addressee) = addressee else {
        return Err(AckDenied::Broadcast {
            signal_id: signal.id.clone(),
        });
    };
    if addressee == caller.trim() {
        Ok(())
    } else {
        Err(AckDenied::NotAddressee {
            signal_id: signal.id.clone(),
            caller: caller.to_string(),
        })
    }
}

/// Stamp `acknowledged_at` on a signal once. Returns `true` when this call set
/// the timestamp, `false` when it was already acked (or no row matched).
///
/// **Authorization is NOT enforced here** — this is the raw stamp. Every
/// caller must first load the row and clear it through [`authorize_ack`]
/// (#3364); a bare `false` return cannot distinguish "already acked" from
/// "not yours", which is exactly the silent no-op the refusal must replace.
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn mark_acked(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<bool> {
    crate::storage::record_stop::gate_storage_conn_rusqlite(conn)?;
    let n = conn.execute(
        "UPDATE signals SET acknowledged_at = ?1 WHERE id = ?2 AND acknowledged_at IS NULL",
        params![now, id],
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn sample(id: &str) -> Signal {
        Signal {
            id: id.to_string(),
            namespace: "_sig".to_string(),
            from_agent: "agent-from".to_string(),
            to_agent: Some("agent-to".to_string()),
            subject: "s".to_string(),
            body: serde_json::json!({"k": "v"}),
            signal_type: SignalType::Notify,
            in_reply_to: None,
            correlation_id: None,
            reference_ids: serde_json::json!([]),
            created_at: 1_700_000_000,
            expires_at: None,
            delivered_at: None,
            read_at: None,
            acknowledged_at: None,
            signature: vec![],
            sender_pubkey: vec![],
        }
    }

    #[test]
    fn insert_then_get_roundtrips() {
        let conn = fresh();
        let id = insert(&conn, &sample("s1")).unwrap();
        assert_eq!(id, "s1");
        let got = get(&conn, "s1").unwrap().expect("present");
        assert_eq!(got.namespace, "_sig");
        assert_eq!(got.from_agent, "agent-from");
        assert_eq!(got.to_agent.as_deref(), Some("agent-to"));
        assert_eq!(got.signal_type, SignalType::Notify);
        assert_eq!(got.body, serde_json::json!({"k": "v"}));
        assert_eq!(got.reference_ids, serde_json::json!([]));
        assert!(got.signature.is_empty());
        assert!(got.sender_pubkey.is_empty());
        assert!(get(&conn, "missing").unwrap().is_none());
    }

    #[test]
    fn list_inbox_sees_direct_and_broadcast() {
        let conn = fresh();
        // Direct message to agent-to.
        insert(&conn, &sample("direct")).unwrap();
        // Broadcast (to_agent NULL) in the same namespace.
        let mut bcast = sample("bcast");
        bcast.to_agent = None;
        bcast.signal_type = SignalType::Broadcast;
        bcast.created_at = 1_700_000_100;
        insert(&conn, &bcast).unwrap();
        // A message addressed to a DIFFERENT agent must not surface.
        let mut other = sample("other");
        other.to_agent = Some("agent-elsewhere".to_string());
        insert(&conn, &other).unwrap();

        let inbox = list_inbox(&conn, "_sig", Some("agent-to"), 50).unwrap();
        let ids: Vec<&str> = inbox.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"direct"), "direct message visible");
        assert!(ids.contains(&"bcast"), "broadcast visible");
        assert!(!ids.contains(&"other"), "other-agent message hidden");
        // Newest-first ordering: the broadcast (later created_at) leads.
        assert_eq!(inbox[0].id, "bcast");

        // to_agent = None returns every signal in the namespace.
        let all = list_inbox(&conn, "_sig", None, 50).unwrap();
        assert_eq!(all.len(), 3);
    }

    /// #3011 — acknowledged signals are excluded from the inbox (an acked inbox
    /// that re-returns the same signal re-serves the same work forever).
    #[test]
    fn list_inbox_excludes_acked_signals_3011() {
        let conn = fresh();
        insert(&conn, &sample("unacked")).unwrap();
        let mut acked = sample("acked");
        acked.created_at = 1_700_000_100;
        insert(&conn, &acked).unwrap();
        assert!(mark_acked(&conn, "acked", 1_700_000_200).unwrap());

        let inbox = list_inbox(&conn, "_sig", Some("agent-to"), 50).unwrap();
        let ids: Vec<&str> = inbox.iter().map(|s| s.id.as_str()).collect();
        assert!(
            ids.contains(&"unacked"),
            "an unacked signal is in the inbox"
        );
        assert!(
            !ids.contains(&"acked"),
            "an acked signal is excluded from the inbox"
        );
        // The namespace-wide view (to_agent = None) also excludes acked signals.
        let all = list_inbox(&conn, "_sig", None, 50).unwrap();
        assert_eq!(all.len(), 1, "only the unacked signal remains in the inbox");
    }

    /// #3011 — `prune_expired` reaps ONLY caller-declared-ephemeral signals whose
    /// `expires_at` has passed; non-expiring + future-expiring signals survive.
    #[test]
    fn prune_expired_reaps_only_expired_signals_3011() {
        let conn = fresh();
        insert(&conn, &sample("keep")).unwrap();
        let mut future = sample("future");
        future.expires_at = Some(2_000_000_000);
        insert(&conn, &future).unwrap();
        let mut past = sample("past");
        past.expires_at = Some(1_000_000_000);
        insert(&conn, &past).unwrap();

        let n = prune_expired(&conn, 1_700_000_000).unwrap();
        assert_eq!(n, 1, "only the past-expiry signal is reaped");
        assert!(
            get(&conn, "keep").unwrap().is_some(),
            "non-expiring survives"
        );
        assert!(
            get(&conn, "future").unwrap().is_some(),
            "future-expiring survives"
        );
        assert!(
            get(&conn, "past").unwrap().is_none(),
            "past-expiring reaped"
        );
    }

    #[test]
    fn thread_groups_by_correlation_id() {
        let conn = fresh();
        let mut a = sample("t-a");
        a.correlation_id = Some("corr-1".to_string());
        a.created_at = 1_700_000_000;
        insert(&conn, &a).unwrap();
        let mut b = sample("t-b");
        b.correlation_id = Some("corr-1".to_string());
        b.created_at = 1_700_000_050;
        insert(&conn, &b).unwrap();
        // Different correlation id — must not appear in the thread.
        let mut c = sample("t-c");
        c.correlation_id = Some("corr-2".to_string());
        insert(&conn, &c).unwrap();

        let t = thread(&conn, "corr-1").unwrap();
        assert_eq!(t.len(), 2);
        // Oldest-first ordering.
        assert_eq!(t[0].id, "t-a");
        assert_eq!(t[1].id, "t-b");
    }

    #[test]
    fn mark_lifecycle_flips_once() {
        let conn = fresh();
        insert(&conn, &sample("m1")).unwrap();

        // delivered: first call flips, second is a no-op.
        assert!(mark_delivered(&conn, "m1", 1_700_000_010).unwrap());
        assert!(!mark_delivered(&conn, "m1", 1_700_000_020).unwrap());
        // read: first call flips, second is a no-op.
        assert!(mark_read(&conn, "m1", 1_700_000_030).unwrap());
        assert!(!mark_read(&conn, "m1", 1_700_000_040).unwrap());
        // acked: first call flips, second is a no-op.
        assert!(mark_acked(&conn, "m1", 1_700_000_050).unwrap());
        assert!(!mark_acked(&conn, "m1", 1_700_000_060).unwrap());

        let got = get(&conn, "m1").unwrap().expect("present");
        assert_eq!(got.delivered_at, Some(1_700_000_010));
        assert_eq!(got.read_at, Some(1_700_000_030));
        assert_eq!(got.acknowledged_at, Some(1_700_000_050));

        // A missing row never flips.
        assert!(!mark_delivered(&conn, "missing", 1_700_000_070).unwrap());
    }

    // -----------------------------------------------------------------
    // v0.8.0 Pillar-1 (#1709) — sign_into / verify
    // -----------------------------------------------------------------

    #[test]
    fn sign_into_then_verify_round_trips() {
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let mut signal = sample("signed-1");
        // Unsigned out of the gate.
        assert!(!verify(&signal), "unsigned signal must not verify");

        sign_into(&mut signal, &kp).expect("sign_into ok");
        assert_eq!(signal.signature.len(), 64, "Ed25519 signature is 64 bytes");
        assert_eq!(signal.sender_pubkey.len(), 32, "pubkey is 32 bytes");
        assert!(verify(&signal), "freshly-signed signal must verify");
    }

    #[test]
    fn tampering_subject_after_signing_fails_verify() {
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let mut signal = sample("signed-2");
        sign_into(&mut signal, &kp).expect("sign_into ok");
        assert!(verify(&signal));
        // Mutate a signed field — the signature no longer matches.
        signal.subject = "tampered subject".to_string();
        assert!(!verify(&signal), "tampered subject must fail verify");
    }

    #[test]
    fn unsigned_signal_does_not_verify() {
        let signal = sample("unsigned-1");
        // sample() leaves signature + sender_pubkey empty.
        assert!(signal.signature.is_empty());
        assert!(signal.sender_pubkey.is_empty());
        assert!(!verify(&signal), "empty-signature signal must not verify");
    }

    #[test]
    fn sign_into_refuses_public_only_keypair() {
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let pub_only = crate::identity::keypair::AgentKeypair {
            agent_id: "ai:curator".to_string(),
            public: kp.public,
            private: None,
        };
        let mut signal = sample("signed-3");
        let err = sign_into(&mut signal, &pub_only).unwrap_err();
        assert!(format!("{err:#}").contains("no private key"));
    }

    #[test]
    fn signed_signal_survives_db_round_trip() {
        // sign_into → insert → get → verify still holds: the stored byte
        // vectors round-trip losslessly.
        let conn = fresh();
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let mut signal = sample("signed-db");
        sign_into(&mut signal, &kp).expect("sign_into ok");
        insert(&conn, &signal).unwrap();
        let got = get(&conn, "signed-db").unwrap().expect("present");
        assert!(verify(&got), "signal read back from the DB must verify");
    }

    // ---- #3364 authorize_ack ------------------------------------------------

    /// #3364 ALLOWED path — the addressee (and only trivial whitespace
    /// differences around it) clears the gate.
    #[test]
    fn authorize_ack_allows_the_addressee_3364() {
        let mut s = sample("a1");
        s.to_agent = Some("ai:alice".to_string());
        assert_eq!(authorize_ack(&s, "ai:alice"), Ok(()));
        // Trimmed on both sides so stored/caller whitespace cannot lock the
        // legitimate addressee out of its own message.
        assert_eq!(authorize_ack(&s, "  ai:alice  "), Ok(()));
        s.to_agent = Some(" ai:alice ".to_string());
        assert_eq!(authorize_ack(&s, "ai:alice"), Ok(()));
    }

    /// #3364 DENIED path — anyone who is not the addressee is refused, and a
    /// signal with NO addressee (broadcast, or a blank `to_agent`) is refused
    /// outright rather than acked by whoever asks first.
    #[test]
    fn authorize_ack_refuses_non_addressee_and_broadcast_3364() {
        let mut s = sample("a2");
        s.to_agent = Some("ai:alice".to_string());
        assert_eq!(
            authorize_ack(&s, "ai:bob"),
            Err(AckDenied::NotAddressee {
                signal_id: "a2".to_string(),
                caller: "ai:bob".to_string(),
            })
        );
        // Case is significant — agent ids are case-sensitive everywhere else.
        assert!(authorize_ack(&s, "AI:ALICE").is_err());
        // An empty caller can never be an addressee.
        assert!(authorize_ack(&s, "").is_err());

        for no_addressee in [None, Some(String::new()), Some("   ".to_string())] {
            s.to_agent = no_addressee.clone();
            assert_eq!(
                authorize_ack(&s, "ai:alice"),
                Err(AckDenied::Broadcast {
                    signal_id: "a2".to_string()
                }),
                "to_agent={no_addressee:?} has no addressee to bind an ack to"
            );
        }
    }

    /// #3364 — the refusal renders an operator-actionable reason and, for the
    /// non-addressee case, does NOT disclose who the signal was addressed to.
    #[test]
    fn ack_denied_display_does_not_disclose_the_addressee_3364() {
        let mut s = sample("a3");
        s.to_agent = Some("ai:alice".to_string());
        let rendered = authorize_ack(&s, "ai:bob").unwrap_err().to_string();
        assert!(rendered.contains("ai:bob"), "names the caller: {rendered}");
        assert!(
            !rendered.contains("ai:alice"),
            "must not disclose the addressee: {rendered}"
        );
    }
}
