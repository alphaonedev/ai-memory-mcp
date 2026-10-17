// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7111 — the sqlite consolidate funnel's DESTINATION slot: the upsert
//! statement for the summary row and the title-slot admission that runs before
//! it. Split out of `storage/mod.rs` (QUAL-10 ceiling) with no behaviour of its
//! own beyond postgres parity: an occupied live `(title, namespace)` slot is
//! merged into in place, a hidden holder refuses typed and unnamed.

use anyhow::Result;
use rusqlite::Connection;

use super::{ConflictError, InsertConflictArm, title_slot_holder};

/// #7111 — the consolidation summary's upsert statement: the raw `INSERT`
/// `consolidate_with_expected_versions` always ran, plus the postgres-parity
/// `ON CONFLICT` arm so an occupied destination `(title, namespace)` merges in
/// place instead of failing with a UNIQUE violation. The arm mirrors the
/// postgres consolidate upsert (content, envelope, tags, priority, confidence,
/// kind, source, access count and `updated_at` move to the summary; the
/// genesis `cid` pair, the lifecycle state and the existing row's provenance
/// metadata keys survive) and shares the conflict target and the in-statement
/// merge backstop with every other create funnel, so a hidden holder is never
/// updated.
pub(super) static CONSOLIDATE_UPSERT_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(
    || {
        // APPEND-ONLY-SANCTIONED (#1823 G6 / #2948 / #7111) — the destination
        // overwrite is recorded by the SUPERSEDE leaf the caller emits.
        format!(
        "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, confidence, source, access_count, created_at, updated_at, expires_at, metadata, confidence_source, cid, cid_genesis, encrypted_envelope, memory_kind)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?17, ?8, ?9, ?10, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?18)
         {conflict_target} DO UPDATE SET
            cid = memories.cid,
            cid_genesis = memories.cid_genesis,
            content = excluded.content,
            encrypted_envelope = excluded.encrypted_envelope,
            tags = excluded.tags,
            priority = excluded.priority,
            confidence = excluded.confidence,
            memory_kind = excluded.memory_kind,
            source = excluded.source,
            access_count = excluded.access_count,
            tier = CASE WHEN excluded.tier = 'long' THEN 'long'
                        WHEN memories.tier = 'long' THEN 'long'
                        WHEN excluded.tier = 'mid' THEN 'mid'
                        ELSE memories.tier END,
            expires_at = CASE WHEN excluded.tier = 'long' OR memories.tier = 'long' THEN NULL
                              ELSE MAX(COALESCE(excluded.expires_at, memories.expires_at),
                                       COALESCE(memories.expires_at, excluded.expires_at)) END,
            updated_at = excluded.updated_at,
            version = memories.version + 1,
            metadata = CASE WHEN {unstamped_owner}
                THEN json_remove(json_patch(
                    excluded.metadata,
                    COALESCE(
                        (SELECT json_group_object(key, value)
                         FROM json_each(memories.metadata)
                         WHERE key IN ('agent_id', 'derived_from', 'consolidated_from_agents', 'agent_pubkey', 'pubkey_bound_at')),
                        '{{}}'
                    )
                ), '$.agent_id')
                ELSE json_patch(
                    excluded.metadata,
                    COALESCE(
                        (SELECT json_group_object(key, value)
                         FROM json_each(memories.metadata)
                         WHERE key IN ('agent_id', 'derived_from', 'consolidated_from_agents', 'agent_pubkey', 'pubkey_bound_at')),
                        '{{}}'
                    )
                ) END
         {merge_backstop}
         RETURNING id",
        conflict_target = crate::models::TITLE_SLOT_CONFLICT_TARGET,
        merge_backstop = crate::models::title_slot_merge_backstop("memories"),
        unstamped_owner = crate::identity::owner_stamp::sqlite_unstamped_predicate(
            crate::identity::owner_stamp::UPSERT_SURVIVING_METADATA_COL,
        ),
    )
    },
);

/// Title-slot admission for the consolidation summary, the sqlite twin of
/// postgres `pg_title_slot_admission(.., Merge, ..)` (#3690 / #3695): a hidden
/// holder of the summary's title refuses the consolidation typed and UNNAMED
/// (empty id) BEFORE any source is touched. A tenant consolidate admits against
/// the consolidator's own scope; a substrate one has no viewer. Returns the
/// destination's pre-image `version` when the append-only spine is armed and a
/// live holder exists (the SUPERSEDE leaf records it, #2948), else `None`.
///
/// # Errors
///
/// A typed [`ConflictError`] for a refused holder; otherwise the holder probe's
/// database error.
pub(super) fn admit_destination(
    conn: &Connection,
    title: &str,
    namespace: &str,
    new_id: &str,
    viewer: Option<&str>,
) -> Result<Option<i64>> {
    let slot_holder = title_slot_holder(conn, title, namespace, viewer)?;
    let facts = crate::visibility::TitleSlotFacts {
        holder: slot_holder.as_ref().map(|h| (h.id.clone(), h.admission)),
        same_id_hidden: None,
    };
    if let crate::visibility::TitleSlotDisposition::Refuse { named } =
        crate::visibility::title_slot_disposition(InsertConflictArm::Merge, new_id, &facts)
    {
        return Err(ConflictError {
            existing_id: named.unwrap_or_default(),
            title: title.to_string(),
            namespace: namespace.to_string(),
        }
        .into());
    }
    Ok(if crate::config::append_only_enabled() {
        slot_holder.as_ref().map(|h| h.version)
    } else {
        None
    })
}
