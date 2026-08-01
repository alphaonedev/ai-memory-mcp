// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2446 — the local **erasure outbox**: durable, network-free
//! propagation of an MCP / CLI erasure into the federation mesh.
//!
//! ## The defect this closes
//!
//! `sync::broadcast_delete_quorum` has exactly ONE production caller —
//! the HTTP `DELETE /api/v1/memories/{id}` handler. Every other erasure
//! funnel is purely local:
//!
//! - MCP `memory_delete` (`mcp::tools::delete::handle_delete`)
//! - MCP `memory_forget` (`mcp::tools::forget::handle_forget`)
//! - CLI `delete` (`cli::crud::cmd_delete`) and `forget`
//!   (`cli::forget::cmd_forget`)
//!
//! An agent calling `memory_forget` over MCP therefore deleted locally,
//! got `success`, and every federated replica kept the row — re-serving
//! it and, on a later catch-up, LWW-resurrecting it. That is a GDPR
//! Article 17 erasure failure AND a permanent replica divergence.
//!
//! ## Why an outbox and not an inline broadcast
//!
//! Decided by a 9-lens 3x3 adversarial vote (citing `4d3ea1c5`): **option
//! B — a durable outbox drained by the daemon's existing federation
//! worker — 8 of 9 lenses.** The two binding reasons:
//!
//! 1. **Inline is structurally blocked.** `FederationConfig::build` is
//!    called in exactly one place, `daemon_runtime::bootstrap_serve` (the
//!    HTTP `serve` command). `AppState.federation` is an HTTP-only
//!    struct; `ai-memory mcp` and the CLI never construct or receive one.
//! 2. **Inline is behaviourally wrong.** A blocking quorum broadcast
//!    inside the single-threaded JSON-RPC stdio loop (#965) would stall
//!    EVERY subsequent tool call including `memory_store` — precisely the
//!    #2577 failure mode whose fix had to introduce a hard budget.
//!
//! The outbox keeps MCP / CLI erasure **local, always-succeeding and
//! network-free** while the daemon does the paced, resumable, retryable
//! propagation.
//!
//! ## Why no schema migration
//!
//! `federation_push_dlq` already exists on BOTH backends at schema v48
//! (`migrations/sqlite/0041_v07_federation_push_dlq.sql` +
//! `store::postgres::migrate_v48`) with a partial-unique index on
//! `(memory_id, peer_id) WHERE replayed_at IS NULL`, a paced + resumable
//! replay worker with quarantine + metrics, and an operator-documented
//! drain procedure. That IS an outbox. The only gap is that an MCP / CLI
//! process does not know the peer list, so it cannot key a row per peer.
//!
//! Resolution: the erasure funnels insert ONE row under the reserved
//! sentinel peer id [`ALL_PEERS_SENTINEL_PEER_ID`], meaning "fan out to
//! every currently-configured peer". `push_dlq::replay_once` expands that
//! sentinel into per-peer rows on its first drain tick, after which every
//! downstream mechanism (attempt budget, quarantine, cause labels, depth
//! gauge, operator drain) is the existing machinery, unchanged.
//!
//! The sentinel cannot collide with a real per-peer row for the same
//! `memory_id`: the partial-unique index is keyed on the PAIR, and
//! `ALL_PEERS_SENTINEL_PEER_ID` is not a producible `PeerEndpoint::id`
//! under any derivation. `push_dlq` additionally re-checks that at
//! expansion time and refuses (fail-closed) rather than mis-fanning-out.
//!
//! ## Bound on an unconfigured deployment (no unbounded growth)
//!
//! A row is written **only when the local database carries the
//! drainability marker** ([`mark_federation_drainable`]), which
//! `daemon_runtime::bootstrap_serve` stamps on EVERY boot where — and
//! only where — a federated `serve` will actually drain THIS database:
//! federation configured (`--quorum-writes > 0` + peers) AND the push-DLQ
//! sink resolved to the SQLite sink over this same file. Every other boot
//! **clears** it. Consequences:
//!
//! - A single-node / MCP-only deployment (the overwhelmingly common case)
//!   never stamps the marker, so it writes **zero** rows, forever.
//! - An operator who turns federation OFF has the marker cleared on the
//!   next `serve` boot, so accumulation stops at the erasures performed
//!   between the two boots — bounded by operator action, not by time.
//! - A postgres-backed `serve` does NOT stamp it: it drains the POSTGRES
//!   `federation_push_dlq`, never this sqlite file, so promising
//!   propagation would be a lie. See the module docs of
//!   `federation::push_dlq` and the #2446 PR body for the full statement.
//!
//! The marker is a SIDECAR beside the database file, not a row in
//! `federation_push_dlq` — see [`MARKER_SUFFIX`] for why that is a
//! correctness-relevant choice and not a stylistic one.
//!
//! ## Failure posture
//!
//! Every function here is **best-effort and infallible to the caller**: a
//! previously-local, always-succeeding erasure must never begin returning
//! errors because federation is unhealthy. A write failure is logged at
//! `warn` and swallowed. The durable truth (the memory TEXT) has already
//! been erased locally by the time these run; the outbox row is a
//! *propagation* record, never the erasure itself.

use rusqlite::Connection;

/// Tracing target for the erasure-outbox write side. #1558
/// tracing-target SSOT.
pub(crate) const ERASURE_OUTBOX_TRACE_TARGET: &str = "ai_memory::federation::erasure_outbox";

/// Reserved `peer_id` meaning "fan out to every currently-configured
/// peer". Expanded into per-peer rows by `push_dlq::replay_once` on the
/// first drain tick.
///
/// Deliberately not a producible `PeerEndpoint::id`: the historical form
/// is `peer-{i}` and the #2442 successor derives from the peer URL —
/// neither can produce a double-underscore-fenced reserved token. The
/// expansion path re-verifies this against the LIVE peer set and refuses
/// rather than fanning out ambiguously.
pub const ALL_PEERS_SENTINEL_PEER_ID: &str = "__ai_memory_all_peers__";

/// Filename suffix of the drainability MARKER, a sidecar beside the
/// sqlite database file (`<db>.federation-outbox`).
///
/// **Why not a row in `federation_push_dlq`.** A marker row would have to
/// pre-set `replayed_at` so the pending-queue queries and the partial
/// unique index ignore it — but ALL THREE indexes on that table are
/// partial `WHERE replayed_at IS NULL`, so such a row is invisible to
/// every index and each probe degrades to a FULL TABLE SCAN. That probe
/// runs on every MCP / CLI erasure and once on the `serve` boot path
/// under the shared writer mutex, and the #1535 atlas-corpus burst left
/// ~75k rows in this table — a scan per erasure would be a hot-path
/// regression on the exact operation this module makes durable. Giving
/// the marker its own index would mean a schema change, and creating one
/// outside the migration ladder is precisely the bootstrap-vs-ladder
/// divergence the #2424 guardrail exists to prevent.
///
/// A sidecar makes the probe ONE `stat` — O(1), independent of DLQ depth
/// — and it is also the more honest home: drainability describes THIS
/// HOST's daemon topology, not the corpus. A database copied or restored
/// elsewhere correctly does not inherit it, and the next `serve` boot on
/// the new host decides afresh.
const MARKER_SUFFIX: &str = ".federation-outbox";

/// `last_error` text stamped on a freshly-queued sentinel row.
///
/// Load-bearing beyond observability: this string is what
/// `push_dlq::classify_quarantine_cause` would see if a sentinel ever
/// reached the quarantine ceiling. It deliberately contains NONE of that
/// classifier's tokens (`429`, `401`, `403`, `400`, `422`, `signature`,
/// `schema`, `id_drift`, `no longer in FederationConfig`, or either
/// `CAUSE_*` constant), so the row classifies as the honest catch-all
/// `other` instead of lying about a quota / auth / permanent cause.
const QUEUED_LAST_ERROR: &str = "queued by the local erasure outbox (#2446); awaiting fan-out";

/// Upper bound on ids enqueued from ONE bulk `forget`.
///
/// A bulk forget is unbounded by construction (`namespace` + `pattern` +
/// `tier` can match the whole corpus), and the id set must be materialised
/// before the DELETE commits. 100k ids is ~3 MB transient and comfortably
/// covers real corpora; exceeding it emits a LOUD warn naming the exact
/// residual rather than silently under-propagating.
pub const MAX_ERASURE_IDS_PER_CALL: usize = 100_000;

/// Surface tags recorded on a queued erasure. Observability only (they
/// ride in the row's `last_error` prose), but hoisted to named consts so
/// the tag strings live at ONE site per the pm-v3.1 no-hardcoded-literal
/// discipline.
pub mod surfaces {
    /// MCP `memory_delete`.
    pub const MCP_DELETE: &str = "mcp:memory_delete";
    /// MCP `memory_forget`.
    pub const MCP_FORGET: &str = "mcp:memory_forget";
    /// CLI `ai-memory delete`.
    pub const CLI_DELETE: &str = "cli:delete";
    /// CLI `ai-memory forget`.
    pub const CLI_FORGET: &str = "cli:forget";
}

/// Build the canonical federated-deletion body for `memory_id`.
///
/// Shape-identical to the body `sync::broadcast_delete_quorum` POSTs, so
/// an expanded per-peer row is indistinguishable from one the delete
/// lane's own DLQ landing pass (#2498 / PR #2662) would have written for
/// the same `(memory_id, peer_id)` — the two converge on the partial
/// unique index instead of fighting over it.
///
/// `sender_agent_id` is supplied by the DAEMON at expansion time: the
/// MCP / CLI writer genuinely does not know the federation identity, so
/// the queued sentinel payload omits it rather than guessing.
#[must_use]
pub fn deletion_body(sender_agent_id: &str, memory_id: &str) -> serde_json::Value {
    serde_json::json!({
        (crate::models::field_names::SENDER_AGENT_ID): sender_agent_id,
        "memories": [],
        "deletions": [memory_id],
        "dry_run": false,
    })
}

/// The payload persisted on a queued sentinel row — the deletion body
/// WITHOUT a sender identity (see [`deletion_body`]). Kept as a real,
/// inspectable body so an operator draining the DLQ by hand sees exactly
/// what is pending.
fn queued_payload(memory_id: &str) -> serde_json::Value {
    serde_json::json!({
        "memories": [],
        "deletions": [memory_id],
        "dry_run": false,
    })
}

/// Resolve the sidecar marker path for the database `conn` is open on.
///
/// `None` for a connection with no on-disk file (`:memory:`, a temporary
/// database) — such a deployment can never be drained by a separate
/// `serve` process anyway, so it is correctly never drainable.
fn marker_path(conn: &Connection) -> Option<std::path::PathBuf> {
    let path = conn.path()?;
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    let mut name = std::ffi::OsString::from(std::path::Path::new(path).file_name()?);
    name.push(MARKER_SUFFIX);
    Some(std::path::Path::new(path).with_file_name(name))
}

/// Stamp the drainability marker: "a federated, `--features sal`,
/// sqlite-backed `serve` drains the `federation_push_dlq` of THIS
/// database file".
///
/// Idempotent. The contents are OBSERVABILITY ONLY — every consumer
/// checks EXISTENCE — so a torn write can never change a verdict.
///
/// # Errors
///
/// Propagates the I/O error (unwritable directory, no resolvable path);
/// the caller logs and continues — a marker write failure must never
/// prevent the daemon from starting.
pub fn mark_federation_drainable(conn: &Connection, peer_count: usize) -> std::io::Result<()> {
    let path = marker_path(conn).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "erasure outbox: the connection has no on-disk database file to mark",
        )
    })?;
    let body = serde_json::json!({
        "peer_count": peer_count,
        "stamped_at": chrono::Utc::now().to_rfc3339(),
        "note": MARKER_NOTE,
    })
    .to_string();
    std::fs::write(path, body)
}

/// Explanatory text carried inside the marker file so an operator who
/// finds it beside their database immediately understands what it is.
const MARKER_NOTE: &str = "#2446 erasure-outbox drainability marker: MCP/CLI erasures on this database queue for \
     federated fan-out while this file exists. Written and removed by `ai-memory serve` at boot; \
     safe to delete (the next serve boot re-decides).";

/// Apply the boot-time drainability verdict: stamp the marker when
/// `drainable_peers` is `Some(n)` (a federated, `--features sal`,
/// sqlite-backed `serve` will drain THIS database), clear it otherwise.
///
/// Infallible + best-effort: a marker write failure degrades to
/// "erasures stay local-only" with a loud WARN, never a boot failure.
///
/// **Runs on the `serve` BOOT PATH, before the daemon binds and reports
/// ready**, so its cost is bounded by construction and not by argument:
/// the unfederated case (the overwhelmingly common one) is a single
/// `stat` and returns without touching the filesystem again; the
/// federated case adds one small `write`. Neither touches the database,
/// so neither can contend the shared writer mutex or scan
/// `federation_push_dlq` — which an earlier in-table marker did, since
/// all three indexes on that table are partial `WHERE replayed_at IS
/// NULL` (see [`MARKER_SUFFIX`]).
///
/// Called once from `daemon_runtime::bootstrap_serve`.
pub fn apply_drainability(conn: &Connection, drainable_peers: Option<usize>) {
    if drainable_peers.is_none() && !is_drainable(conn) {
        return;
    }
    match drainable_peers {
        Some(peer_count) => match mark_federation_drainable(conn, peer_count) {
            Ok(()) => tracing::info!(
                target: ERASURE_OUTBOX_TRACE_TARGET,
                peer_count,
                "federation erasure outbox ENABLED: MCP/CLI erasures on this database queue \
                 for fan-out to {peer_count} peer(s) (#2446)"
            ),
            Err(e) => tracing::warn!(
                target: ERASURE_OUTBOX_TRACE_TARGET,
                "federation erasure outbox: could not stamp the drainability marker; MCP/CLI \
                 erasures stay LOCAL-ONLY until the next successful serve boot (#2446): {e}"
            ),
        },
        None => match clear_federation_drainable(conn) {
            Ok(true) => tracing::info!(
                target: ERASURE_OUTBOX_TRACE_TARGET,
                "federation erasure outbox DISABLED for this database (federation off, \
                 postgres-backed, or a non-sal build): cleared the drainability marker so \
                 MCP/CLI erasures stop queueing (#2446)"
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                target: ERASURE_OUTBOX_TRACE_TARGET,
                "federation erasure outbox: could not clear the drainability marker (#2446): {e}"
            ),
        },
    }
}

/// Remove the drainability marker: this database is NOT drained by a
/// federated sqlite-backed `serve`.
///
/// # Errors
///
/// Propagates the rusqlite error; the caller logs and continues.
pub fn clear_federation_drainable(conn: &Connection) -> std::io::Result<bool> {
    let Some(path) = marker_path(conn) else {
        return Ok(false);
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Is this database drained by a federated, sqlite-backed `serve`?
///
/// ONE `stat` — O(1), independent of `federation_push_dlq` depth. That
/// bound is the point: this runs on every MCP / CLI erasure.
///
/// Any failure to resolve resolves to `false` — fail-quiet in the "write
/// nothing" direction, which is the safe one: the local erasure already
/// committed and an unqueued row can be re-issued, whereas a bogus queued
/// row cannot be distinguished from a real pending erasure.
#[must_use]
pub fn is_drainable(conn: &Connection) -> bool {
    marker_path(conn).is_some_and(|p| p.exists())
}

/// Queue ONE erased memory id for federated fan-out. Best-effort and
/// infallible: returns `true` when a row was written.
///
/// Callers invoke this AFTER the local erasure has committed.
pub fn enqueue_erasure(conn: &Connection, memory_id: &str, surface: &str) -> bool {
    if !is_drainable(conn) {
        return false;
    }
    enqueue_unchecked(conn, memory_id, surface)
}

/// Queue a batch of erased memory ids (the bulk `forget` shape).
/// Best-effort and infallible: returns the number of rows written.
///
/// The drainability probe runs ONCE for the whole batch.
pub fn enqueue_erasures(conn: &Connection, memory_ids: &[String], surface: &str) -> usize {
    if memory_ids.is_empty() || !is_drainable(conn) {
        return 0;
    }
    let mut written = 0usize;
    for id in memory_ids {
        if enqueue_unchecked(conn, id, surface) {
            written += 1;
        }
    }
    if written > 0 {
        tracing::info!(
            target: ERASURE_OUTBOX_TRACE_TARGET,
            surface,
            queued = written,
            requested = memory_ids.len(),
            "erasure outbox: queued {written} erasure(s) from {surface} for federated fan-out \
             (#2446)",
        );
    }
    written
}

/// Resolve the FULL id set a bulk `forget` is about to erase, for the
/// erasure outbox. Returns empty when the deployment is not drainable
/// (so an unfederated deployment pays nothing beyond one indexed probe)
/// or when the filter set is the one `forget` itself refuses.
///
/// Callers MUST invoke this BEFORE the delete commits, on the SAME
/// connection, so the id set cannot drift between the SELECT and the
/// DELETE (`db::forget` holds `BEGIN IMMEDIATE` internally, and both MCP
/// and CLI dispatch is synchronous).
#[must_use]
pub fn collect_forget_ids(
    conn: &Connection,
    namespace: Option<&str>,
    pattern: Option<&str>,
    tier: Option<&crate::models::Tier>,
    owner: Option<&str>,
) -> Vec<String> {
    if !is_drainable(conn) {
        return Vec::new();
    }
    // Over-fetch by one so truncation is detectable without a second
    // COUNT (the #1602 preview's idiom).
    let probe = MAX_ERASURE_IDS_PER_CALL.saturating_add(1);
    let matched = match owner {
        Some(c) => crate::db::forget_matches_for_caller(conn, namespace, pattern, tier, probe, c),
        None => crate::db::forget_matches(conn, namespace, pattern, tier, probe),
    };
    let mut rows = match matched {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: ERASURE_OUTBOX_TRACE_TARGET,
                "erasure outbox: could not resolve the forget id set; the local forget \
                 STANDS but will not propagate until re-issued: {e}",
            );
            return Vec::new();
        }
    };
    if rows.len() > MAX_ERASURE_IDS_PER_CALL {
        // LOUD rather than a silent partial propagation — the operator
        // needs to know exactly which erasures did not queue.
        tracing::error!(
            target: ERASURE_OUTBOX_TRACE_TARGET,
            cap = MAX_ERASURE_IDS_PER_CALL,
            "erasure outbox: a bulk forget matched MORE than {MAX_ERASURE_IDS_PER_CALL} rows; \
             only the first {MAX_ERASURE_IDS_PER_CALL} are queued for federated fan-out. The \
             remainder are erased LOCALLY but will NOT propagate — re-issue the forget in \
             smaller batches to erase them on peers (#2446)",
        );
        rows.truncate(MAX_ERASURE_IDS_PER_CALL);
    }
    rows.into_iter().map(|m| m.id).collect()
}

/// Insert one sentinel row, assuming drainability has already been
/// established. Swallows and logs any failure.
fn enqueue_unchecked(conn: &Connection, memory_id: &str, surface: &str) -> bool {
    let now = chrono::Utc::now().to_rfc3339();
    let payload = queued_payload(memory_id).to_string();
    // ON CONFLICT mirrors `push_dlq`'s enqueue: two erasures of the same
    // id coalesce onto ONE pending row rather than stacking duplicates.
    // `attempt_count` is deliberately NOT bumped on conflict — a sentinel
    // is never POSTed, so burning its attempt budget would quarantine a
    // perfectly valid erasure that simply got requested twice.
    let last_error = format!("{QUEUED_LAST_ERROR} (surface: {surface})");
    let res = conn.execute(
        "INSERT INTO federation_push_dlq \
             (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
         VALUES (?1, ?2, ?3, 1, ?4, ?5) \
         ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS NULL \
         DO UPDATE SET last_error = excluded.last_error, \
                       payload_json = excluded.payload_json",
        rusqlite::params![
            memory_id,
            ALL_PEERS_SENTINEL_PEER_ID,
            payload,
            last_error,
            now
        ],
    );
    match res {
        Ok(_) => true,
        Err(e) => {
            // Never propagate: the local erasure already committed and
            // MUST keep reporting success (#2446 requirement — a
            // previously-local operation must not start failing because
            // federation is unhealthy).
            tracing::warn!(
                target: ERASURE_OUTBOX_TRACE_TARGET,
                memory_id,
                surface,
                "erasure outbox: failed to queue federated erasure for {memory_id} \
                 from {surface}; the local erasure STANDS but will not propagate \
                 until re-issued: {e}",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A FILE-backed database (never `:memory:`): the drainability marker
    /// is a sidecar beside the db file, so a memoryless connection is by
    /// design never drainable.
    fn db() -> (tempfile::TempDir, Connection) {
        let tmp = tempfile::Builder::new()
            .prefix("erasure-outbox-2446-")
            .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
            .expect("create .local-runs tempdir");
        let conn = Connection::open(tmp.path().join("m.db")).expect("open file-backed db");
        conn.execute_batch(
            "CREATE TABLE federation_push_dlq (
                 id             INTEGER PRIMARY KEY AUTOINCREMENT,
                 memory_id      TEXT NOT NULL,
                 peer_id        TEXT NOT NULL,
                 payload_json   TEXT NOT NULL,
                 attempt_count  INTEGER NOT NULL DEFAULT 1,
                 last_error     TEXT NOT NULL,
                 failed_at      TEXT NOT NULL,
                 replayed_at    TEXT NULL
             );
             CREATE UNIQUE INDEX idx_federation_push_dlq_pending_uniq
                 ON federation_push_dlq(memory_id, peer_id)
                 WHERE replayed_at IS NULL;",
        )
        .expect("create dlq table");
        (tmp, conn)
    }

    fn pending_count(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM federation_push_dlq WHERE replayed_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// The reserved tokens are WIRE-STABLE: `tests/federation_erasure_replication_2446.rs`
    /// mirrors them as literals so that suite compiles at the parent
    /// commit (R-203), and an operator draining the DLQ by hand greps for
    /// them. Changing one silently would desynchronise both.
    #[test]
    fn reserved_tokens_are_wire_stable() {
        assert_eq!(ALL_PEERS_SENTINEL_PEER_ID, "__ai_memory_all_peers__");
        assert_eq!(MARKER_SUFFIX, ".federation-outbox");
    }

    /// The marker never enters `federation_push_dlq`, so it can never be
    /// scanned for, counted by the depth gauge, or drained. Pins the
    /// property the sidecar exists to guarantee.
    #[test]
    fn the_marker_never_lands_in_the_dlq_table() {
        let (_tmp, conn) = db();
        mark_federation_drainable(&conn, 3).unwrap();
        assert!(is_drainable(&conn));
        let all: i64 = conn
            .query_row("SELECT COUNT(*) FROM federation_push_dlq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            all, 0,
            "the marker must not be a row in the DLQ table at all"
        );
    }

    /// A connection with no on-disk file can never be drainable — a
    /// separate `serve` process could not share it anyway.
    #[test]
    fn a_memory_backed_connection_is_never_drainable() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(!is_drainable(&conn));
        assert!(mark_federation_drainable(&conn, 1).is_err());
        assert!(!clear_federation_drainable(&conn).unwrap());
    }

    /// The heart of the #2446 bound: with NO marker, an erasure writes
    /// nothing at all. A single-node MCP deployment can never accumulate.
    #[test]
    fn erasure_writes_nothing_without_the_drainability_marker() {
        let (_tmp, conn) = db();
        assert!(!is_drainable(&conn));
        assert!(!enqueue_erasure(&conn, "m-1", "mcp:memory_delete"));
        assert_eq!(
            enqueue_erasures(&conn, &["m-2".into(), "m-3".into()], "cli:forget"),
            0
        );
        assert_eq!(
            pending_count(&conn),
            0,
            "an unconfigured deployment must accumulate ZERO outbox rows"
        );
    }

    /// Stamping is idempotent and clearing is exact.
    #[test]
    fn marker_stamp_is_idempotent_and_clear_is_exact() {
        let (_tmp, conn) = db();
        mark_federation_drainable(&conn, 3).unwrap();
        assert!(is_drainable(&conn));
        mark_federation_drainable(&conn, 4).unwrap();
        assert!(
            is_drainable(&conn),
            "re-stamping replaces rather than stacks"
        );
        assert_eq!(
            pending_count(&conn),
            0,
            "and never enters the pending queue"
        );
        assert!(clear_federation_drainable(&conn).unwrap());
        assert!(!is_drainable(&conn));
        assert!(
            !clear_federation_drainable(&conn).unwrap(),
            "clearing an absent marker is a no-op, not an error"
        );
    }

    /// A queued erasure lands exactly one pending sentinel row carrying a
    /// real deletion body, and a repeat erasure of the same id coalesces
    /// WITHOUT burning the attempt budget.
    #[test]
    fn queued_erasure_lands_one_sentinel_row_and_coalesces() {
        let (_tmp, conn) = db();
        mark_federation_drainable(&conn, 1).unwrap();
        assert!(enqueue_erasure(&conn, "m-1", "mcp:memory_forget"));
        assert!(enqueue_erasure(&conn, "m-1", "mcp:memory_forget"));
        assert_eq!(pending_count(&conn), 1, "repeat erasure coalesces");
        let (peer_id, payload, attempts): (String, String, i32) = conn
            .query_row(
                "SELECT peer_id, payload_json, attempt_count FROM federation_push_dlq \
                 WHERE memory_id = 'm-1' AND replayed_at IS NULL",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(peer_id, ALL_PEERS_SENTINEL_PEER_ID);
        assert_eq!(
            attempts, 1,
            "a sentinel is never POSTed, so a repeat erasure must not burn its \
             quarantine budget"
        );
        let body: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(body["deletions"], serde_json::json!(["m-1"]));
    }

    /// The sentinel and a REAL per-peer row for the SAME memory id
    /// coexist: the partial unique index is keyed on the PAIR.
    #[test]
    fn sentinel_does_not_collide_with_a_real_per_peer_row() {
        let (_tmp, conn) = db();
        mark_federation_drainable(&conn, 1).unwrap();
        conn.execute(
            "INSERT INTO federation_push_dlq \
                 (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
             VALUES ('m-1', 'peer-0', '{}', 1, 'boom', '2026-07-30T00:00:00Z')",
            [],
        )
        .unwrap();
        assert!(enqueue_erasure(&conn, "m-1", "cli:delete"));
        assert_eq!(
            pending_count(&conn),
            2,
            "sentinel + real per-peer row for the same memory must coexist"
        );
    }

    /// The queued `last_error` must not trip any `classify_quarantine_cause`
    /// token — a sentinel that ever quarantines classifies as the honest
    /// catch-all, never as a fabricated quota / auth / permanent cause.
    #[test]
    fn queued_last_error_does_not_lie_to_the_cause_classifier() {
        let mut texts = vec![QUEUED_LAST_ERROR.to_string()];
        for surface in [
            surfaces::MCP_DELETE,
            surfaces::MCP_FORGET,
            surfaces::CLI_DELETE,
            surfaces::CLI_FORGET,
        ] {
            texts.push(format!("{QUEUED_LAST_ERROR} (surface: {surface})"));
        }
        for text in &texts {
            for token in [
                "429",
                "401",
                "403",
                "400",
                "422",
                "signature",
                "schema",
                "id_drift",
                "no longer in FederationConfig",
            ] {
                assert!(
                    !text.contains(token),
                    "{text:?} must not contain the classifier token {token:?}"
                );
            }
        }
    }

    /// An unwritable DLQ table must NOT make erasure fail — the local
    /// erasure has already committed and must keep reporting success.
    #[test]
    fn a_broken_outbox_never_fails_the_erasure() {
        let (_tmp, conn) = db();
        mark_federation_drainable(&conn, 1).unwrap();
        conn.execute_batch("DROP TABLE federation_push_dlq;")
            .unwrap();
        // No panic, no error type: just `false`.
        assert!(!enqueue_erasure(&conn, "m-1", "mcp:memory_delete"));
        assert_eq!(enqueue_erasures(&conn, &["m-2".into()], "cli:forget"), 0);
    }

    /// The daemon-side body carries the live sender identity and is
    /// shape-identical to `broadcast_delete_quorum`'s.
    #[test]
    fn deletion_body_matches_the_broadcast_shape() {
        let body = deletion_body("host:leader", "m-9");
        assert_eq!(
            body[crate::models::field_names::SENDER_AGENT_ID],
            "host:leader"
        );
        assert_eq!(body["memories"], serde_json::json!([]));
        assert_eq!(body["deletions"], serde_json::json!(["m-9"]));
        assert_eq!(body["dry_run"], serde_json::json!(false));
    }
}
