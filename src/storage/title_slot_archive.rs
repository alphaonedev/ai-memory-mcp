// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4206 — the sqlite title-slot federation-merge pre-image helpers: the probe
//! of the `(title, namespace)` row a newer-wins upsert may overwrite and the
//! `federation_merge` archive snapshot of its text. Own child module so
//! `src/storage/mod.rs` stays under its qual_10 module-size ceiling.

use super::*;

/// v1.0.0 #2954 / #4206 — the pre-merge image of the `(title, namespace)` row a
/// federation newer-wins upsert ([`insert_if_newer`]) is about to overwrite.
/// Read under the SAME `BEGIN IMMEDIATE` write lock as the upsert (so the probe
/// cannot race it). Identity/version plus the durable-content columns needed
/// to decide whether the overwrite changes the row's text — the
/// plaintext/placeholder `content`, its at-rest `encrypted_envelope` and the
/// owner the envelope is sealed to. Feeds BOTH the #4206 pre-merge archive
/// snapshot (always) and the #2954 SUPERSEDE leaf (armed spine only).
pub(super) struct FederationMergePreimage {
    /// The surviving local row's `updated_at` (the primary LWW key the
    /// `CASE WHEN excluded.updated_at > memories.updated_at` arm compares).
    pub(super) updated_at: String,
    /// The surviving local row's `id` (the `excluded.id > memories.id`
    /// equal-timestamp tiebreak operand).
    pub(super) id: String,
    /// The pre-supersede `version` recorded as the leaf's `prior_version`.
    pub(super) version: i64,
    /// The stored `content` column (plaintext when encryption is off, the
    /// placeholder when on) — compared against the value about to be stored to
    /// decide whether the overwrite actually CHANGED durable content.
    pub(super) content: String,
    /// The stored at-rest ciphertext envelope (NULL when encryption is off).
    pub(super) encrypted_envelope: Option<Vec<u8>>,
    /// #4206 — the row's `metadata.agent_id`, the identity its envelope is
    /// sealed to (`""` for an unowned / legacy row).
    owner_agent_id: String,
}

impl FederationMergePreimage {
    /// The inbound row wins the LWW tiebreak — byte-for-byte the same total
    /// order the `ON CONFLICT … CASE` arm of [`INSERT_IF_NEWER_SQL`] applies
    /// (`updated_at` as TEXT, then `id`).
    pub(super) fn inbound_wins(&self, mem: &Memory) -> bool {
        mem.updated_at.as_str() > self.updated_at.as_str()
            || (mem.updated_at == self.updated_at && mem.id.as_str() > self.id.as_str())
    }

    /// #4206 — `true` when the upsert will actually change the row's logical
    /// text: the inbound row wins the tiebreak AND its plaintext differs from
    /// the stored plaintext. Compared BEFORE sealing (a fresh seal has a fresh
    /// nonce, so envelope bytes always differ), so a no-change replay never
    /// replaces the last recoverable preimage. A stored envelope that cannot
    /// be opened counts as changed (over-approximate: snapshot, never skip).
    fn text_overwritten_by(&self, mem: &Memory) -> bool {
        self.inbound_wins(mem)
            && preimage_plaintext(
                &self.content,
                self.encrypted_envelope.as_deref(),
                &self.owner_agent_id,
            )
            .as_deref()
                != Some(mem.content.as_str())
    }
}

/// #4206 — the logical (plaintext) text of a stored row: the `content` column
/// when there is no at-rest envelope, else the envelope opened under the row's
/// owner. `None` when the envelope cannot be opened (lost key, erased or
/// corrupt) — callers treat that as "unknown, assume changed".
pub(crate) fn preimage_plaintext(
    content: &str,
    envelope: Option<&[u8]>,
    owner_agent_id: &str,
) -> Option<String> {
    match envelope {
        None => Some(content.to_owned()),
        Some(bytes) => crate::encryption::open_content(bytes, owner_agent_id).ok(),
    }
}

/// #4206 — snapshot the `(title, namespace)` row a federation newer-wins
/// upsert is about to overwrite into `archived_memories`
/// (`archive_reason = federation_merge`, keyed by the LOCAL row's id), in the
/// caller's open write transaction and BEFORE the upsert, so the pre-merge text
/// stays recoverable. The same-id lane has done this since #1773
/// ([`overwrite_full_row_by_id`]); the title-slot lane (an inbound id absent
/// locally, including the #3699 cross-id fold) did not, so a newer peer row
/// permanently replaced local text. Fires only when the text actually changes
/// ([`FederationMergePreimage::text_overwritten_by`]); a losing inbound or a
/// no-change replay archives nothing and leaves an earlier snapshot in place.
///
/// # Errors
///
/// Propagates the archive INSERT error; the caller rolls back its transaction.
pub(super) fn snapshot_title_slot_preimage_if_overwritten(
    conn: &Connection,
    pre: Option<&FederationMergePreimage>,
    mem: &Memory,
) -> Result<()> {
    match pre {
        Some(pre) if pre.text_overwritten_by(mem) => {
            archive_memory_insert_only(conn, &pre.id, field_names::ARCHIVE_REASON_FEDERATION_MERGE)
        }
        _ => Ok(()),
    }
}

/// v1.0.0 #2954 / #4206 — probe the `(title, namespace)` row
/// [`insert_if_newer`]'s newer-wins upsert may overwrite, under the caller's
/// open `BEGIN IMMEDIATE` write lock. Returns `None` when no live row holds
/// `(title, namespace)` (a fresh INSERT, which destroys nothing). Always read
/// (#4206: the pre-merge archive snapshot needs it whether or not the
/// append-only spine is armed). The write lock is what makes the probe atomic
/// with the upsert that follows.
///
/// # Errors
///
/// Propagates the lookup error; the caller rolls back its transaction.
pub(super) fn probe_federation_merge_preimage(
    conn: &Connection,
    title: &str,
    namespace: &str,
) -> Result<Option<FederationMergePreimage>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        &format!(
            "SELECT updated_at, id, version, content, encrypted_envelope, metadata \
             FROM memories WHERE title = ?1 AND namespace = ?2 AND {}",
            crate::models::TITLE_SLOT_INDEX_PREDICATE
        ),
        params![title, namespace],
        |r| {
            Ok(FederationMergePreimage {
                updated_at: r.get(0)?,
                id: r.get(1)?,
                version: r.get(2)?,
                content: r.get(3)?,
                encrypted_envelope: r.get(4)?,
                // Parsed in Rust, not `json_extract`: a malformed or
                // non-string `agent_id` reads as unowned (the envelope then
                // fails to open → "changed" → snapshot), never as a probe error
                // that would wedge every merge into this title slot.
                owner_agent_id: serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(5)?)
                    .ok()
                    .and_then(|m| m.get("agent_id")?.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            })
        },
    )
    .optional()
    .map_err(Into::into)
}
