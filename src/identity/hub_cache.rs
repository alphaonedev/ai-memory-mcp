// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Derive the wake hub's public cache from the durable v97 identity root.

use anyhow::{Context as _, Result};
use std::path::Path;

use crate::wake_hub::delegation_verifier::{ALLOWLIST_FILE_VERSION, AllowlistEntry, AllowlistFile};

/// Maximum age of a public identity snapshot; refresh before this expires.
pub const MAX_CACHE_AGE_SECS: i64 = 60;
/// Audit event for an exported allow decision.
pub const HUB_ALLOW_EVENT: &str = "identity.hub_allow";
/// Audit event for removal of a previously exported allow decision.
pub const HUB_REVOKE_EVENT: &str = "identity.hub_revoke";

/// Derive one entry from a durable history snapshot.
///
/// # Errors
/// Refuses missing, unproven, closed, malformed or future history.
pub fn entry(
    agent_id: &str,
    history: &[crate::storage::AgentPubkeyVersion],
    mut revoked_keys: Vec<String>,
    now: &str,
) -> Result<AllowlistEntry> {
    super::hub_authority::current_issuer(agent_id, history, now)?;
    revoked_keys.sort();
    revoked_keys.dedup();
    let current = history.last().context("missing current hub root")?;
    Ok(AllowlistEntry {
        agent_id: agent_id.to_owned(),
        pubkey_b64: current.pubkey_b64.clone(),
        bind_authority: current.bind_authority.clone(),
        bound_at: current.bound_at.clone(),
        revoked_keys,
    })
}

/// Export selected principals from SQLite. Revoked/unproven principals are
/// omitted, so a refresh removes their authority instead of keeping stale data.
///
/// # Errors
/// Propagates storage errors; an incomplete read never produces a cache.
pub fn derive_sqlite(conn: &rusqlite::Connection, agents: &[String]) -> Result<AllowlistFile> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = chrono::Utc::now().to_rfc3339();
    let mut entries = Vec::with_capacity(agents.len());
    for agent in agents {
        crate::validate::validate_agent_id_shape(agent)?;
        let history = crate::db::agent_pubkey_versions(conn, agent)?;
        crate::storage::select_agent_pubkey_version_at(&history, &now)?;
        if super::hub_authority::current_issuer(agent, &history, &now).is_err() {
            continue;
        }
        let revoked = crate::db::list_subkey_certs(conn, Some(agent))?
            .into_iter()
            .filter(|cert| cert.revoked)
            .map(|cert| URL_SAFE_NO_PAD.encode(cert.instance_key_id))
            .collect();
        entries.push(entry(agent, &history, revoked, &now)?);
    }
    Ok(AllowlistFile {
        version: ALLOWLIST_FILE_VERSION,
        refreshed_at: Some(now),
        agents: entries,
    })
}

/// Audit a snapshot before publishing it. Both allows and removed principals
/// bind the complete new public snapshot hash into the existing audit spine.
///
/// # Errors
/// A stopped record plane or failed audit append prevents publication.
pub fn audit_sqlite(
    conn: &rusqlite::Connection,
    previous: Option<&AllowlistFile>,
    next: &AllowlistFile,
) -> Result<()> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let tx = crate::storage::connection::WriteTxn::begin(conn)?;
    for event in events(previous, next)? {
        crate::signed_events::append_signed_event_no_tx(conn, &event)?;
    }
    tx.commit()?;
    Ok(())
}

/// Build the same identity-only audit events for either backend.
///
/// # Errors
/// Propagates snapshot encoding errors.
pub fn events(
    previous: Option<&AllowlistFile>,
    next: &AllowlistFile,
) -> Result<Vec<crate::signed_events::SignedEvent>> {
    let hash = crate::signed_events::payload_hash(&serde_json::to_vec(next)?);
    let mut events = Vec::new();
    if let Some(previous) = previous {
        for entry in &previous.agents {
            if !next.agents.iter().any(|new| {
                new.agent_id == entry.agent_id
                    && new.pubkey_b64 == entry.pubkey_b64
                    && new.revoked_keys == entry.revoked_keys
            }) {
                events.push(crate::signed_events::SignedEvent::with_daemon_signature(
                    hash.clone(),
                    entry.agent_id.clone(),
                    HUB_REVOKE_EVENT.to_owned(),
                    chrono::Utc::now().to_rfc3339(),
                    None,
                ));
            }
        }
    }
    for entry in &next.agents {
        if previous.is_some_and(|previous| previous.agents.contains(entry)) {
            continue;
        }
        events.push(crate::signed_events::SignedEvent::with_daemon_signature(
            hash.clone(),
            entry.agent_id.clone(),
            HUB_ALLOW_EVENT.to_owned(),
            chrono::Utc::now().to_rfc3339(),
            None,
        ));
    }
    Ok(events)
}

/// Publish a public snapshot atomically with mode 0600 on the new inode.
///
/// # Errors
/// Any create, encode, flush or rename failure prevents publication.
pub fn publish(path: &Path, snapshot: &AllowlistFile) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(&serde_json::to_vec(snapshot)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}
