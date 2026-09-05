// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL source and audit twin for the store-free wake-hub cache.

use super::{PgSignedEventInsert, PostgresStore, pg_append_signed_event_with_chain_in_tx};
use crate::store::MemoryStore as _;
use crate::wake_hub::delegation_verifier::{ALLOWLIST_FILE_VERSION, AllowlistFile};
use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

impl PostgresStore {
    /// Derive the same public v97 snapshot as the SQLite exporter.
    ///
    /// # Errors
    /// Any source lookup failure prevents cache publication.
    pub async fn derive_hub_cache(&self, agents: &[String]) -> Result<AllowlistFile> {
        let now = chrono::Utc::now().to_rfc3339();
        // #3505 — the SAME derivation the sqlite exporter runs: the agent's own
        // #1921 team / unit / org prefixes, through the shared
        // `crate::visibility::namespace_read_scope_prefixes`. Two backends, one
        // predicate — the #951 rule — and NO corpus-wide namespace scan on
        // either, so the 30 s refresher's cost does not grow with the store.
        let mut entries = Vec::with_capacity(agents.len());
        for agent in agents {
            crate::validate::validate_agent_id_shape(agent)?;
            let history = self.agent_pubkey_versions(agent).await?;
            crate::storage::select_agent_pubkey_version_at(&history, &now)?;
            if crate::identity::hub_authority::current_issuer(agent, &history, &now).is_err() {
                continue;
            }
            let revoked: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT instance_key_id FROM agent_subkey_certs WHERE principal = $1 AND revoked = TRUE",
            ).bind(agent).fetch_all(self.pool()).await?;
            let readable = crate::identity::hub_cache::readable_prefixes_for(agent);
            entries.push(crate::identity::hub_cache::entry(
                agent,
                &history,
                revoked
                    .into_iter()
                    .map(|key| URL_SAFE_NO_PAD.encode(key))
                    .collect(),
                readable,
                &now,
            )?);
        }
        Ok(AllowlistFile {
            version: ALLOWLIST_FILE_VERSION,
            refreshed_at: Some(now),
            agents: entries,
        })
    }

    /// Append allow/revoke intent to the canonical audit spine before publication.
    ///
    /// # Errors
    /// Record-stop or an append/commit failure prevents publication.
    pub async fn audit_hub_cache(
        &self,
        previous: Option<&AllowlistFile>,
        next: &AllowlistFile,
    ) -> Result<()> {
        self.gate_record_stop().await?;
        let mut tx = self.pool().begin().await?;
        for event in crate::identity::hub_cache::events(previous, next)? {
            pg_append_signed_event_with_chain_in_tx(
                &mut tx,
                PgSignedEventInsert {
                    id: &event.id,
                    agent_id: &event.agent_id,
                    event_type: &event.event_type,
                    payload_hash: &event.payload_hash,
                    signature: event.signature.as_deref(),
                    attest_level: &event.attest_level,
                    timestamp: chrono::DateTime::parse_from_rfc3339(&event.timestamp)?.to_utc(),
                    cause_hash: None,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
