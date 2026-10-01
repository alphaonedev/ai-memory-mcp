// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4199 A1 (GOD ruling on the 5-agent vote `4d3ea1c5`) — the postgres twin of
//! [`crate::governance::audit::record_forensic_sink_unavailable`]: attest a
//! forensic-sink outage in the `signed_events` chain of a postgres-backed
//! daemon, so the signed outage row the vote made "none optional" is not
//! missing on postgres.
//!
//! # Parity contract with the sqlite recorder
//!
//! The payload hash, the dedupe window and the dedupe comparison are the SAME
//! functions both backends call
//! ([`crate::governance::audit::forensic_outage_key`],
//! [`crate::governance::audit::forensic_outage_day`],
//! [`crate::governance::audit::is_duplicate_forensic_outage`]), and the row is
//! built with the same `with_daemon_signature` idiom the sqlite funnel uses.
//! Only the query dialect differs.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits at its `qual_10_module_size_ceiling` budget;
//! the `swarm_rewind.rs` / `reown_3124.rs` precedent.

use sqlx::Row;

use super::{PgSignedEventInsert, PostgresStore, pg_append_signed_event_with_chain};
use crate::governance::audit::{
    ForensicTailUnreadable, forensic_outage_day, forensic_outage_key, is_duplicate_forensic_outage,
};
use crate::signed_events::event_types::FORENSIC_SINK_UNAVAILABLE;

/// The newest outage row's payload hash (the dedupe comparand).
const SQL_NEWEST_OUTAGE: &str = "SELECT payload_hash FROM signed_events \
     WHERE event_type = $1 ORDER BY sequence DESC LIMIT 1";

impl PostgresStore {
    /// #4199 A1 — append the signed `audit.forensic_sink_unavailable` row to
    /// this store's `signed_events` chain, unless the newest outage row
    /// already records the same `(day, path, cause)`. Returns whether a row
    /// was appended.
    ///
    /// # Errors
    /// The dedupe read or the chain append failed.
    pub async fn try_record_forensic_sink_unavailable(
        &self,
        err: &ForensicTailUnreadable,
    ) -> Result<bool, sqlx::Error> {
        let key = forensic_outage_key(err, &forensic_outage_day());
        let newest: Option<Vec<u8>> = sqlx::query(SQL_NEWEST_OUTAGE)
            .bind(FORENSIC_SINK_UNAVAILABLE)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| row.try_get(0))
            .transpose()?;
        if is_duplicate_forensic_outage(newest.as_deref(), &key) {
            return Ok(false);
        }
        let ts = chrono::Utc::now();
        let event = crate::signed_events::SignedEvent::with_daemon_signature(
            key,
            crate::identity::sentinels::DAEMON_PRINCIPAL.to_string(),
            FORENSIC_SINK_UNAVAILABLE.to_string(),
            ts.to_rfc3339(),
            None,
        );
        let row = PgSignedEventInsert {
            id: &event.id,
            agent_id: &event.agent_id,
            event_type: &event.event_type,
            payload_hash: &event.payload_hash,
            signature: event.signature.as_deref(),
            attest_level: &event.attest_level,
            timestamp: ts,
            cause_hash: None,
        };
        pg_append_signed_event_with_chain(&self.pool, row).await?;
        Ok(true)
    }

    /// #4199 A1 — called once the store has connected (and migrated): attest
    /// every outage the boot path deferred because this process's store is
    /// postgres. Any process that opens a postgres store drains the queue, so
    /// `serve` and every other postgres-backed verb attest into the chain they
    /// actually use.
    pub(super) async fn attest_deferred_forensic_outages(&self) {
        for outage in crate::governance::audit::take_deferred_forensic_outages() {
            self.record_forensic_sink_unavailable(&outage).await;
        }
    }

    /// #4199 A1 — best-effort: a failed append is an ERROR on stderr and in
    /// the log, and never takes the process down (the degraded boot already
    /// happened).
    pub async fn record_forensic_sink_unavailable(&self, err: &ForensicTailUnreadable) {
        if let Err(e) = self.try_record_forensic_sink_unavailable(err).await {
            eprintln!(
                "ai-memory: ERROR: the forensic-sink outage was NOT recorded in the postgres \
                 signed_events chain: {e}"
            );
            tracing::error!(
                target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                "forensic-sink outage not recorded in postgres signed_events: {e}"
            );
        }
    }
}
