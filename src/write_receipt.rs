// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3555: durability evidence for a completed write, separate from stored data.

use anyhow::{Context as _, Result, bail};
use serde::Serialize;
use serde_json::Value;

/// Explicit operator attestation that replicated writes have backup coverage.
/// Only the exact value `attested` enables the backup class, and only after
/// this write has received a remote acknowledgement. This is a posture
/// attestation, not evidence that an asynchronous backup contains this write.
pub const BACKUP_ATTESTATION_ENV: &str = "AI_MEMORY_BACKUP_POSTURE_ATTESTATION";

/// Evidence declared in a write response. Never persisted on a memory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteDurability {
    durability_class: String,
    fsync: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_acks: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_n: Option<usize>,
}

impl std::fmt::Display for WriteDurability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "durability_class={} fsync={}",
            self.durability_class, self.fsync
        )
    }
}

impl WriteDurability {
    /// Observe the live SQLite connection, never the configured default.
    ///
    /// # Errors
    /// Fails if the synchronous PRAGMA cannot be read or is unrecognised.
    pub fn sqlite(conn: &rusqlite::Connection) -> Result<Self> {
        let level = crate::storage::live_synchronous(conn)?;
        Ok(Self::local(level.fsync_cadence()))
    }

    fn local(fsync: &str) -> Self {
        Self {
            durability_class: crate::storage::DURABILITY_CLASS_LOCAL_ONLY.to_owned(),
            fsync: fsync.to_owned(),
            quorum_acks: None,
            quorum_n: None,
        }
    }

    /// Interpret PostgreSQL's observed local commit settings. Native standby
    /// configuration alone does not prove a count of acknowledgements.
    ///
    /// # Errors
    /// Rejects unknown settings rather than asserting per-commit durability.
    pub fn postgres(fsync: &str, synchronous_commit: &str) -> Result<Self> {
        if !matches!(
            synchronous_commit,
            "off" | "local" | "on" | "remote_write" | "remote_apply"
        ) {
            bail!("unrecognised PostgreSQL synchronous_commit setting");
        }
        let cadence = match (fsync, synchronous_commit) {
            ("off", _) => "never (OS write-back only)",
            ("on", "off") => "asynchronous WAL flush",
            ("on", "local" | "on" | "remote_write" | "remote_apply") => "per-commit",
            _ => bail!("unrecognised PostgreSQL commit durability settings"),
        };
        Ok(Self::local(cadence))
    }

    /// Add a successful operation's actual acknowledgement count, including
    /// the local node. A configured policy without a successful verdict is
    /// insufficient. `backup_attested` is an explicit operator assertion.
    ///
    /// # Errors
    /// Refuses counts outside `1 <= required <= acknowledged <= replicas`.
    pub fn with_quorum(
        mut self,
        required: usize,
        acknowledged: usize,
        replicas: usize,
        backup_attested: bool,
    ) -> Result<Self> {
        if required == 0 || required > acknowledged || acknowledged > replicas {
            bail!("invalid write acknowledgement evidence");
        }
        self.quorum_acks = Some(acknowledged);
        self.quorum_n = Some(replicas);
        if acknowledged > 1 {
            self.durability_class = if backup_attested {
                "replicated+backup".to_owned()
            } else {
                format!("quorum {acknowledged}-of-{replicas}")
            };
        }
        Ok(self)
    }

    /// Merge evidence into an object receipt, preserving its existing fields.
    ///
    /// # Errors
    /// Fails for a non-object receipt or a serialization failure.
    pub fn attach(&self, receipt: &mut Value) -> Result<()> {
        let fields = serde_json::to_value(self)?;
        let fields = fields.as_object().context("durability must be an object")?;
        let object = receipt
            .as_object_mut()
            .context("write receipt must be an object")?;
        object.extend(fields.clone());
        Ok(())
    }
}
