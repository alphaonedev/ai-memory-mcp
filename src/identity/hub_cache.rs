// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Derive the wake hub's public cache from the durable v97 identity root.

use anyhow::{Context as _, Result};
use std::path::Path;

use crate::wake_hub::delegation_verifier::{
    ALLOWLIST_FILE_VERSION, AllowlistEntry, AllowlistFile, DAEMON_KEY_DIR_AUTHORITY,
};

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
    readable_prefixes: Vec<String>,
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
        readable_prefixes,
    })
}

/// v1.0.0 [#3505](https://github.com/alphaonedev/ai-memory-mcp/issues/3505) —
/// the read PREFIXES `agent_id` PROVABLY holds.
///
/// The derivation is [`crate::visibility::namespace_read_scope_prefixes`],
/// which is the store's OWN #1921 read scope expressed as its `team` / `unit`
/// / `org` ancestors. It is reused, never re-derived: a second copy of a
/// visibility predicate is the #951 defect this codebase has already paid for
/// twice. The hub then admits a namespace with the store's own containment
/// test ([`crate::visibility::namespace_subtree_contains`]) plus the #3348
/// substrate exclusion, so the two halves of the proof are both the shared
/// predicate and nothing re-widens.
///
/// # Why prefixes, and not an expanded list
///
/// The set is a property of the agent's OWN ID — at most
/// [`crate::wake_hub::limits::MAX_READABLE_PREFIXES`] entries, forever. An
/// expanded list would instead be a property of the CORPUS: it would grow as
/// namespaces are created, an org-level agent would eventually exceed any
/// fixed ceiling, and refusing that export would publish NOTHING — after which
/// the snapshot ages out and the hub refuses EVERY hello. That is a
/// fleet-wide availability failure caused by ordinary corpus growth, so the
/// bound has to be one the corpus cannot move. This function issues no query
/// and so cannot fail.
#[must_use]
pub fn readable_prefixes_for(agent_id: &str) -> Vec<String> {
    // Already bounded by construction: `namespace_read_scope_prefixes` takes
    // `NAMESPACE_READ_SCOPE_DEPTH`, which IS the hub's ceiling. Sorted +
    // deduplicated so the snapshot is byte-stable across refreshes that
    // changed nothing — an unstable ordering would republish a new inode every
    // cycle and defeat #3504's reuse.
    let mut prefixes = crate::visibility::namespace_read_scope_prefixes(agent_id);
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

/// v1.0.0 #3469 — the store-free `wake-hub-producer` row, derived from this
/// host's key directory rather than from the v97 ledger.
///
/// # Why this cannot come from the store
///
/// [`derive_sqlite`] resolves each principal through
/// [`super::hub_authority::current_issuer`], which needs a v97 key history.
/// `wake-hub-producer` is a RESERVED id
/// ([`crate::validate::RESERVED_AGENT_IDS`]) with no store row and no enrolled
/// root of its own — deliberately, so that no second identity root exists — so
/// asking the store for it yields an empty history and the principal is
/// SILENTLY OMITTED by the `continue` in that loop. This function is the honest
/// alternative: it reads only `daemon.pub`, states its provenance as
/// [`DAEMON_KEY_DIR_AUTHORITY`], and is reachable only from an explicit
/// operator switch.
///
/// # What it reads, and what it never touches
///
/// The PUBLIC half only, through [`crate::identity::keypair::load_public`].
/// The daemon's private key is never opened here, and no other agent's key
/// material is consulted.
///
/// # Errors
///
/// Refuses when the host has no `daemon.pub` — an operator asking to publish a
/// binding for a key that does not exist has made a mistake worth stopping on,
/// not a row worth inventing.
pub fn daemon_producer_entry(key_dir: &Path, now: &str) -> Result<AllowlistEntry> {
    let public = crate::identity::keypair::load_public(
        crate::identity::keypair::DAEMON_KEYPAIR_LABEL,
        key_dir,
    )
    .with_context(|| {
        format!(
            "identity hub-cache --daemon-producer: no `{}` public key in {}. Start the \
             daemon once so it generates its enrolled keypair, or pre-stage one, then \
             re-run.",
            crate::identity::keypair::DAEMON_KEYPAIR_LABEL,
            key_dir.display()
        )
    })?;
    Ok(AllowlistEntry {
        agent_id: crate::identity::sentinels::WAKE_HUB_PRODUCER.to_owned(),
        pubkey_b64: crate::identity::keypair::encode_public_base64(&public),
        bind_authority: DAEMON_KEY_DIR_AUTHORITY.to_owned(),
        // The instant the operator asserted the binding. The hub refuses a
        // delegation ISSUED before this (`AllowlistCache::check_delegate`), so
        // stamping it now — never backdating — keeps that ordering meaningful.
        bound_at: now.to_owned(),
        revoked_keys: Vec::new(),
        // #3505 — the reserved producer's id carries no `/`, so it has no
        // team / unit / org ancestor and proves no namespace read scope. Its
        // only authority stays "may deliver a content-free wake hint addressed
        // to an agent's own inbox": with an empty prefix set it cannot
        // SUBSCRIBE to a namespace topic and — since the send gate applies the
        // same proof — cannot ADDRESS one either.
        readable_prefixes: Vec::new(),
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
    // #3505 — the proven read scope is derived from each agent's OWN ID, so
    // this export issues NO corpus-wide namespace scan: the refresher runs
    // every 30 s, and a `GROUP BY namespace` over `memories` on that cadence
    // is a cost that grows with the corpus for a result that does not.
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
        let readable = readable_prefixes_for(agent);
        entries.push(entry(agent, &history, revoked, readable, &now)?);
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
                    // #3505 — a NARROWED proven-prefix set is a revocation of
                    // topic authority, so it rides the same audit spine as a
                    // revoked key. Without this the removal side would be
                    // silent while the grant side (struct equality, below)
                    // already fires.
                    && new.readable_prefixes == entry.readable_prefixes
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake_hub::delegation_verifier::RootBindAuthority;

    fn key_dir_with_daemon_key() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let kp = crate::identity::keypair::generate(crate::identity::keypair::DAEMON_KEYPAIR_LABEL)
            .expect("generate");
        crate::identity::keypair::save(&kp, dir.path()).expect("save");
        dir
    }

    /// ALLOWED: the producer row names the reserved principal, carries THIS
    /// host's daemon public key, and states its provenance honestly.
    #[test]
    fn the_producer_row_binds_the_reserved_name_to_the_daemon_public_key_3469() {
        let dir = key_dir_with_daemon_key();
        let expected = crate::identity::keypair::load_public(
            crate::identity::keypair::DAEMON_KEYPAIR_LABEL,
            dir.path(),
        )
        .expect("load public");
        let now = chrono::Utc::now().to_rfc3339();

        let row = daemon_producer_entry(dir.path(), &now).expect("derive the producer row");
        assert_eq!(row.agent_id, crate::identity::sentinels::WAKE_HUB_PRODUCER);
        assert_eq!(
            row.pubkey_b64,
            crate::identity::keypair::encode_public_base64(&expected)
        );
        assert_eq!(row.bind_authority, DAEMON_KEY_DIR_AUTHORITY);
        assert_eq!(row.bound_at, now);
        assert!(row.revoked_keys.is_empty());
        // And the hub accepts that authority for this principal only.
        let authority = RootBindAuthority::from_column(&row.bind_authority);
        assert!(authority.may_delegate_for(&row.agent_id));
        assert!(!authority.may_delegate_for("ai:alice"));
        assert!(
            !authority.may_delegate(),
            "the row must not claim a proven authority it does not have"
        );
    }

    /// DENIED: no daemon key on this host means no row — an operator asking to
    /// publish a binding for a key that does not exist has made a mistake
    /// worth stopping on, not a row worth inventing.
    #[test]
    fn an_absent_daemon_key_refuses_rather_than_inventing_a_row_3469() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = daemon_producer_entry(dir.path(), &chrono::Utc::now().to_rfc3339())
            .expect_err("no key, no row");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("--daemon-producer"), "{rendered}");
    }

    /// The row is derived from PUBLIC material only: it is still produced when
    /// the private half is absent, so publishing an allowlist never requires
    /// the daemon's signing key to be readable.
    #[test]
    fn the_producer_row_needs_only_public_material_3469() {
        let dir = key_dir_with_daemon_key();
        std::fs::remove_file(dir.path().join(format!(
            "{}.priv",
            crate::identity::keypair::DAEMON_KEYPAIR_LABEL
        )))
        .expect("drop the private half");
        daemon_producer_entry(dir.path(), &chrono::Utc::now().to_rfc3339())
            .expect("the public half is all this needs");
    }

    /// The producer row rides the SAME audit spine as a store-derived one: it
    /// produces an allow event when it appears and a revoke event when it is
    /// dropped from the next snapshot.
    #[test]
    fn the_producer_row_is_audited_like_any_other_grant_3469() {
        let dir = key_dir_with_daemon_key();
        let now = chrono::Utc::now().to_rfc3339();
        let row = daemon_producer_entry(dir.path(), &now).expect("row");
        let with_producer = AllowlistFile {
            version: ALLOWLIST_FILE_VERSION,
            refreshed_at: Some(now.clone()),
            agents: vec![row],
        };
        let without = AllowlistFile {
            version: ALLOWLIST_FILE_VERSION,
            refreshed_at: Some(now),
            agents: Vec::new(),
        };

        let granted = events(Some(&without), &with_producer).expect("events");
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].event_type, HUB_ALLOW_EVENT);
        assert_eq!(
            granted[0].agent_id,
            crate::identity::sentinels::WAKE_HUB_PRODUCER
        );

        let revoked = events(Some(&with_producer), &without).expect("events");
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].event_type, HUB_REVOKE_EVENT);
        assert_eq!(
            revoked[0].agent_id,
            crate::identity::sentinels::WAKE_HUB_PRODUCER
        );
    }
}
