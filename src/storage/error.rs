// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Typed substrate-layer error envelope (issue #962).
//!
//! Before this module, `src/storage/` returned `anyhow::Result<T>` and
//! emitted `anyhow::bail!("memory not found: …")` etc. Handlers downcast
//! to error strings (`msg.contains("ambiguous ID prefix")`) and lost
//! typed information at every layer transition. This module captures
//! the substrate's refusal categories as discriminable variants so the
//! HTTP / MCP / CLI surfaces can pattern-match instead of string-match.
//!
//! Wire shape is preserved: `StorageError` is wrapped via
//! `anyhow::Error::new(StorageError::…)` so the existing
//! `anyhow::Result<T>` return type stays unchanged, and the handler
//! layer's `MemoryError::from(anyhow::Error)` impl downcasts to map each
//! variant to the right HTTP status. This is the same pattern used by
//! [`super::GovernanceRefusal`], [`super::ConflictError`], and
//! [`super::VersionConflict`].

/// Identifies which end of a link a missing-memory refusal refers to.
/// `None` is reserved for memory-not-found errors that are not part of
/// a link operation. The `Source` and `Target` variants preserve the
/// pre-#962 user-facing error prefixes ("source memory not found: …" /
/// "target memory not found: …") so existing string-matching consumers
/// keep working through the typed enum's Display impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEnd {
    Source,
    Target,
}

/// Error prefix emitted when `validate_link_pre_create` rejects a
/// `reflects_on` edge that would close a cycle in the reflection graph.
/// HTTP / SAL response mappers look for this prefix to surface 409
/// CONFLICT; MCP surfaces it as a plain text error. Centralised so all
/// three entry points stay in lockstep with [`StorageError::LinkReflectionCycle`].
pub const LINK_CYCLE_ERR_PREFIX: &str = "link refused: reflection cycle";

/// Error prefix emitted when the K9 permission pipeline returns `Deny`
/// for a link write. HTTP / SAL response mappers translate this to 403
/// FORBIDDEN. Paired with [`StorageError::LinkPermissionDenied`].
pub const LINK_PERMISSION_DENIED_ERR_PREFIX: &str = "link denied by permission rule";

/// Typed substrate-layer error categories. Each variant maps to a
/// canonical HTTP status via `MemoryError::from(anyhow::Error)` and
/// preserves the original `bail!()` message verbatim via Display so
/// downstream `.to_string().starts_with(...)` and `.contains(...)`
/// consumers keep working through the typed layer.
#[derive(Debug, Clone)]
pub enum StorageError {
    /// Memory id (or link source/target memory id) does not resolve to
    /// a row. `role = None` is the bare lookup ("memory not found:
    /// `<id>`"); `role = Some(Source|Target)` qualifies the message for
    /// link-creation paths.
    MemoryNotFound { id: String, role: Option<LinkEnd> },

    /// Pending-action lookup miss in the approvals path.
    PendingActionNotFound { pending_id: String },

    /// Truncated id prefix matches multiple memories. The full
    /// candidate list is surfaced so the caller can retry with a
    /// longer prefix.
    AmbiguousIdPrefix {
        prefix: String,
        candidates: Vec<String>,
    },

    /// Caller-supplied argument failed substrate validation. Covers
    /// max_depth bounds, older_than_days sign, namespace shape,
    /// action_type, reflect-payload shape, and similar simple
    /// validations that map to HTTP 400.
    InvalidArgument { reason: String },

    /// Pending action exists but cannot be executed in its current
    /// status (substrate refuses to execute non-approved actions).
    PendingActionStateInvalid {
        #[allow(dead_code)] // Carried for future typed handlers.
        pending_id: String,
        status: String,
    },

    /// Substrate-level link permission denied (governance Deny, or
    /// Ask→Deny because the storage layer has no Ask channel).
    /// Display starts with [`LINK_PERMISSION_DENIED_ERR_PREFIX`].
    LinkPermissionDenied { reason: String },

    /// Adding the proposed `reflects_on` edge would close a cycle in
    /// the reflection DAG. Display starts with [`LINK_CYCLE_ERR_PREFIX`].
    LinkReflectionCycle {
        source_id: String,
        target_id: String,
    },

    /// Approver-on-behalf laundering refused (S5-H4): the claimed
    /// payload `agent_id` does not match the original `requested_by`.
    ApproverLaundering {
        pending_id: String,
        claimed: String,
        requester: String,
    },

    /// Title / uniqueness conflict (existing memory or entity collision
    /// in the same namespace, or backend exhaustion of versioned-title
    /// suffixes within the cap).
    UniqueConflict { reason: String },

    /// Restore-from-archive would overwrite an active-table row. The
    /// caller must explicitly delete the active row first or restore
    /// to a different id.
    ArchiveRestoreCollision { id: String },

    /// Archive supersede transaction did not affect the expected row.
    /// Either the archive row vanished between read and write, or the
    /// DB is corrupt.
    ArchiveSupersedeFailed { archived_id: String },

    /// SQLCipher build started without `AI_MEMORY_DB_PASSPHRASE`.
    /// Fatal at boot; surfaces as an `apply_sqlcipher_key` refusal.
    SqlcipherMissingPassphrase,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemoryNotFound { id, role: None } => write!(f, "memory not found: {id}"),
            Self::MemoryNotFound {
                id,
                role: Some(LinkEnd::Source),
            } => write!(f, "source memory not found: {id}"),
            Self::MemoryNotFound {
                id,
                role: Some(LinkEnd::Target),
            } => write!(f, "target memory not found: {id}"),
            Self::PendingActionNotFound { pending_id } => {
                write!(f, "pending action not found: {pending_id}")
            }
            Self::AmbiguousIdPrefix { prefix, candidates } => write!(
                f,
                "ambiguous ID prefix '{prefix}': {n} matches\n{ids}",
                n = candidates.len(),
                ids = candidates.join("\n"),
            ),
            Self::InvalidArgument { reason } => write!(f, "{reason}"),
            Self::PendingActionStateInvalid { status, .. } => {
                write!(f, "cannot execute non-approved action (status={status})")
            }
            Self::LinkPermissionDenied { reason } => {
                write!(f, "{LINK_PERMISSION_DENIED_ERR_PREFIX}: {reason}")
            }
            Self::LinkReflectionCycle {
                source_id,
                target_id,
            } => write!(
                f,
                "{LINK_CYCLE_ERR_PREFIX}: \
                 {source_id} --reflects_on--> {target_id} would close a cycle",
            ),
            Self::ApproverLaundering {
                pending_id,
                claimed,
                requester,
            } => write!(
                f,
                "approver-on-behalf laundering refused: payload agent_id '{claimed}' \
                 != requested_by '{requester}' (pending_id={pending_id})",
            ),
            Self::UniqueConflict { reason } => write!(f, "{reason}"),
            Self::ArchiveRestoreCollision { id } => write!(
                f,
                "cannot restore: memory {id} already exists in active table (would overwrite)",
            ),
            Self::ArchiveSupersedeFailed { archived_id } => {
                write!(f, "supersede archive failed for {archived_id}")
            }
            Self::SqlcipherMissingPassphrase => write!(
                f,
                "sqlcipher build requires AI_MEMORY_DB_PASSPHRASE \
                 (set via --db-passphrase-file <path>)",
            ),
        }
    }
}

impl std::error::Error for StorageError {}

impl StorageError {
    /// ARCH-9 (FX-C4-batch2, 2026-05-26) — canonical stable error
    /// slug for each variant.
    ///
    /// Returns a `&'static str` that mirrors the
    /// [`crate::errors::MemoryError::code`] discipline. The slug is
    /// the load-bearing key for cross-surface (HTTP/MCP/CLI) parity
    /// tests and for structured-trace fields. Adding a variant
    /// requires extending this match — the
    /// `#[deny(unreachable_patterns)]` attribute on the outer match
    /// catches dead arms; the test `arch_9_storage_error_slug_*`
    /// in [`crate::errors::error_codes::tests`] pins the slug-set against a
    /// regression.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MemoryNotFound { .. } => crate::errors::error_codes::NOT_FOUND,
            Self::PendingActionNotFound { .. } => {
                crate::errors::error_codes::PENDING_ACTION_NOT_FOUND
            }
            Self::AmbiguousIdPrefix { .. } => crate::errors::error_codes::AMBIGUOUS_ID_PREFIX,
            Self::InvalidArgument { .. } => crate::errors::error_codes::INVALID_ARGUMENT,
            Self::PendingActionStateInvalid { .. } => {
                crate::errors::error_codes::PENDING_ACTION_STATE_INVALID
            }
            Self::LinkPermissionDenied { .. } => crate::errors::error_codes::LINK_PERMISSION_DENIED,
            Self::LinkReflectionCycle { .. } => crate::errors::error_codes::LINK_REFLECTION_CYCLE,
            Self::ApproverLaundering { .. } => crate::errors::error_codes::APPROVER_LAUNDERING,
            Self::UniqueConflict { .. } => crate::errors::error_codes::UNIQUE_CONFLICT,
            Self::ArchiveRestoreCollision { .. } => {
                crate::errors::error_codes::ARCHIVE_RESTORE_COLLISION
            }
            Self::ArchiveSupersedeFailed { .. } => {
                crate::errors::error_codes::ARCHIVE_SUPERSEDE_FAILED
            }
            Self::SqlcipherMissingPassphrase => {
                crate::errors::error_codes::SQLCIPHER_MISSING_PASSPHRASE
            }
        }
    }
}

// Note: `anyhow::Error::from<E: StdError>` already covers `StorageError`
// via the blanket impl, so an explicit `From<StorageError> for
// anyhow::Error` would conflict. Substrate code wraps via the explicit
// `anyhow::Error::new(StorageError::…)` constructor for clarity at the
// call sites, but `?` + `Into` also work transparently.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_memory_not_found_bare() {
        let e = StorageError::MemoryNotFound {
            id: "abc123".into(),
            role: None,
        };
        assert_eq!(e.to_string(), "memory not found: abc123");
    }

    #[test]
    fn display_memory_not_found_source() {
        let e = StorageError::MemoryNotFound {
            id: "src1".into(),
            role: Some(LinkEnd::Source),
        };
        assert_eq!(e.to_string(), "source memory not found: src1");
    }

    #[test]
    fn display_memory_not_found_target() {
        let e = StorageError::MemoryNotFound {
            id: "tgt1".into(),
            role: Some(LinkEnd::Target),
        };
        assert_eq!(e.to_string(), "target memory not found: tgt1");
    }

    #[test]
    fn display_pending_action_not_found() {
        let e = StorageError::PendingActionNotFound {
            pending_id: "pa-7".into(),
        };
        assert_eq!(e.to_string(), "pending action not found: pa-7");
    }

    #[test]
    fn display_ambiguous_id_prefix_preserves_legacy_format() {
        let e = StorageError::AmbiguousIdPrefix {
            prefix: "ab".into(),
            candidates: vec!["abc1".into(), "abc2".into()],
        };
        // The legacy bail! format `"ambiguous ID prefix 'X': N matches\n<ids>"`
        // is preserved so existing `.to_string().contains("ambiguous ID prefix")`
        // call sites continue to match through the typed envelope.
        assert_eq!(
            e.to_string(),
            "ambiguous ID prefix 'ab': 2 matches\nabc1\nabc2",
        );
    }

    #[test]
    fn display_invalid_argument_passes_reason_through() {
        let e = StorageError::InvalidArgument {
            reason: "max_depth must be >= 1".into(),
        };
        assert_eq!(e.to_string(), "max_depth must be >= 1");
    }

    #[test]
    fn display_pending_action_state_invalid() {
        let e = StorageError::PendingActionStateInvalid {
            pending_id: "pa-9".into(),
            status: "rejected".into(),
        };
        assert_eq!(
            e.to_string(),
            "cannot execute non-approved action (status=rejected)",
        );
    }

    #[test]
    fn display_link_permission_denied_starts_with_canonical_prefix() {
        let e = StorageError::LinkPermissionDenied {
            reason: "rule R042 fired".into(),
        };
        let s = e.to_string();
        assert!(
            s.starts_with(LINK_PERMISSION_DENIED_ERR_PREFIX),
            "expected canonical prefix, got: {s}",
        );
        assert_eq!(
            s,
            format!("{LINK_PERMISSION_DENIED_ERR_PREFIX}: rule R042 fired")
        );
    }

    #[test]
    fn display_link_reflection_cycle_starts_with_canonical_prefix() {
        let e = StorageError::LinkReflectionCycle {
            source_id: "a".into(),
            target_id: "b".into(),
        };
        let s = e.to_string();
        assert!(
            s.starts_with(LINK_CYCLE_ERR_PREFIX),
            "expected canonical prefix, got: {s}",
        );
        assert!(s.contains("a --reflects_on--> b"));
    }

    #[test]
    fn display_approver_laundering_includes_all_fields() {
        let e = StorageError::ApproverLaundering {
            pending_id: "pa-1".into(),
            claimed: "agent-x".into(),
            requester: "agent-y".into(),
        };
        let s = e.to_string();
        assert!(s.contains("'agent-x'"));
        assert!(s.contains("'agent-y'"));
        assert!(s.contains("pending_id=pa-1"));
    }

    #[test]
    fn display_unique_conflict_passes_reason_through() {
        let e = StorageError::UniqueConflict {
            reason: "title 'X' already exists".into(),
        };
        assert_eq!(e.to_string(), "title 'X' already exists");
    }

    #[test]
    fn display_archive_restore_collision_format() {
        let e = StorageError::ArchiveRestoreCollision { id: "m1".into() };
        assert_eq!(
            e.to_string(),
            "cannot restore: memory m1 already exists in active table (would overwrite)",
        );
    }

    #[test]
    fn display_archive_supersede_failed_format() {
        let e = StorageError::ArchiveSupersedeFailed {
            archived_id: "arch-7".into(),
        };
        assert_eq!(e.to_string(), "supersede archive failed for arch-7");
    }

    #[test]
    fn display_sqlcipher_missing_passphrase_format() {
        let e = StorageError::SqlcipherMissingPassphrase;
        assert!(e.to_string().contains("AI_MEMORY_DB_PASSPHRASE"));
        assert!(e.to_string().contains("--db-passphrase-file"));
    }

    #[test]
    fn anyhow_from_storage_error_roundtrip_preserves_downcast() {
        // Wrap via the same constructor substrate code uses
        // (anyhow's blanket `From<E: StdError>` impl is what materially
        // moves the value into the chain; we test that downcast still
        // recovers the typed variant on the other side).
        let e: anyhow::Error = anyhow::Error::new(StorageError::MemoryNotFound {
            id: "id1".into(),
            role: None,
        });
        let recovered = e
            .downcast_ref::<StorageError>()
            .expect("typed error must survive anyhow round-trip");
        assert!(matches!(recovered, StorageError::MemoryNotFound { .. }));
    }
}
