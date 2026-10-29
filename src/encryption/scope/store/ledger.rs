// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — the per-namespace audit log of the scope-key ledger and the
//! in-memory ledger entry of the file store's cache (rulings R3 and R11).
//!
//! Every mutation of a namespace's reader set or key generation (mint,
//! add recipient, remove recipient, supersede) appends one [`AuditEntry`].
//! The log is append-only and hash-chained: entry `n` carries the SHA-256 of
//! the exact line of entry `n - 1`, its `seq` is dense from 1 and its
//! `previous_epoch` must equal the namespace's current epoch at the head. A
//! load replays the chain and cross-checks it with the records (epoch count,
//! each epoch's key id and key check, recipient fingerprints and escrow
//! fingerprint), so a record edited outside the store, a whole record
//! substituted from public inputs (a fresh key wrapped to the same readers
//! and escrow key), a removed or reordered entry, or a mutation that never
//! reached the log fails closed. An entry naming a different key id or key
//! check for an epoch the log already holds is refused (ruling R13: the E2
//! signature over the entry must cover the key, not only public inputs).
//!
//! The ledger head ([`LedgerHead`]) is the number of entries. It is the
//! version the cache freshness check compares (R11): a lookup that must be at
//! least as fresh as a head a peer advertised refuses with
//! [`ScopeKeyStoreError::SealedForeign`] while the cache is older.
//!
//! E1 authority is the process boundary (owner-only `0o700` key directory
//! chain, local writers only); signed, operator-authorised reader-set changes
//! are enforced at the E2 mTLS `/keys/scope` gate (D3).

use super::{ScopeKeyRecord, ScopeKeyStoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The version of one namespace's scope-key ledger: its audit entry count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerHead(pub u64);

impl std::fmt::Display for LedgerHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What one audit entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    /// The epoch-1 key was minted.
    Mint,
    /// A reader stanza was added to an epoch.
    AddRecipient,
    /// A reader stanza was removed from an epoch.
    RemoveRecipient,
    /// The next epoch was minted and the previous one closed.
    Supersede,
}

/// One append-only audit entry of a namespace's scope-key ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    /// 1-based position in the log.
    pub seq: u64,
    /// The mutation.
    pub action: AuditAction,
    /// Agent id of the process that made it (who).
    pub actor: String,
    /// The namespace.
    pub namespace: String,
    /// The epoch the mutation touched.
    pub epoch: u32,
    /// The namespace's current epoch before the mutation (0 before the mint).
    pub previous_epoch: u32,
    /// The namespace's current epoch after the mutation.
    pub new_epoch: u32,
    /// Hex key id of `epoch` (R13).
    pub key_id: String,
    /// Hex `key_check` of `epoch` (R13): binds the entry to the key itself.
    pub key_check: String,
    /// KEK fingerprint added or removed (recipient changes only).
    pub subject: Option<String>,
    /// Sorted KEK fingerprints of `epoch` after the mutation.
    pub recipients: Vec<String>,
    /// Escrow recovery-key fingerprint of `epoch`.
    pub recovery_fingerprint: String,
    /// RFC 3339 time of the mutation.
    pub at: String,
    /// Hex SHA-256 of the previous entry's line; empty for `seq` 1.
    pub prev_sha256: String,
}

/// Sorted KEK fingerprints of a record.
pub(super) fn recipient_fingerprints(record: &ScopeKeyRecord) -> Vec<String> {
    let mut out: Vec<String> = record
        .recipients
        .iter()
        .map(|s| s.kek_fingerprint.clone())
        .collect();
    out.sort_unstable();
    out
}

/// What a mutator asks [`NamespaceLedger::entry_for`] to record.
pub(super) struct Change<'a> {
    pub(super) action: AuditAction,
    pub(super) actor: &'a str,
    pub(super) record: &'a ScopeKeyRecord,
    pub(super) subject: Option<String>,
    pub(super) at: String,
}

/// One namespace's records and audit log, as the cache holds them.
#[derive(Clone, Debug, Default)]
pub(super) struct NamespaceLedger {
    /// Records, index `i` holding epoch `i + 1`.
    pub(super) records: Vec<ScopeKeyRecord>,
    /// The audit log, in order.
    pub(super) audit: Vec<AuditEntry>,
    /// Current epoch according to the audit chain.
    chain_epoch: u32,
    /// Hex SHA-256 of the last audit line.
    last_line_sha256: String,
}

fn line_sha256(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

impl NamespaceLedger {
    /// The ledger version.
    pub(super) fn head(&self) -> LedgerHead {
        LedgerHead(u64::try_from(self.audit.len()).unwrap_or(u64::MAX))
    }

    /// The namespace, from the first record.
    pub(super) fn namespace(&self) -> Option<&str> {
        self.records.first().map(|r| r.namespace.as_str())
    }

    /// The current epoch per the audit chain (0 before the mint).
    pub(super) fn current_epoch(&self) -> u32 {
        self.chain_epoch
    }

    fn mismatch(namespace: &str, detail: impl Into<String>) -> ScopeKeyStoreError {
        ScopeKeyStoreError::AuditChainMismatch {
            namespace: namespace.to_string(),
            detail: detail.into(),
        }
    }

    /// The next entry for `change`, pointing at the current head.
    pub(super) fn entry_for(&self, change: &Change<'_>) -> AuditEntry {
        let new_epoch = match change.action {
            AuditAction::Mint | AuditAction::Supersede => change.record.epoch,
            AuditAction::AddRecipient | AuditAction::RemoveRecipient => self.chain_epoch,
        };
        AuditEntry {
            seq: self.head().0.saturating_add(1),
            action: change.action,
            actor: change.actor.to_string(),
            namespace: change.record.namespace.clone(),
            epoch: change.record.epoch,
            previous_epoch: self.chain_epoch,
            new_epoch,
            key_id: change.record.key_id.clone(),
            key_check: change.record.key_check.clone(),
            subject: change.subject.clone(),
            recipients: recipient_fingerprints(change.record),
            recovery_fingerprint: change.record.escrow.recovery_fingerprint.clone(),
            at: change.at.clone(),
            prev_sha256: self.last_line_sha256.clone(),
        }
    }

    /// Verify `entry` extends this chain, append it and return its line.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::AuditChainMismatch`] when the entry's `seq`,
    /// previous-entry hash, previous-epoch pointer, namespace or epoch
    /// transition does not follow from the head.
    pub(super) fn append(&mut self, entry: AuditEntry) -> Result<String, ScopeKeyStoreError> {
        let line = serde_json::to_string(&entry)
            .map_err(|e| Self::mismatch(&entry.namespace, format!("unserialisable entry: {e}")))?;
        self.append_line(entry, &line)?;
        Ok(line)
    }

    fn append_line(&mut self, entry: AuditEntry, line: &str) -> Result<(), ScopeKeyStoreError> {
        let ns = entry.namespace.as_str();
        let expected_seq = self.head().0.saturating_add(1);
        if entry.seq != expected_seq {
            return Err(Self::mismatch(
                ns,
                format!("entry seq {} at head {}", entry.seq, self.head()),
            ));
        }
        if entry.prev_sha256 != self.last_line_sha256 {
            return Err(Self::mismatch(
                ns,
                format!("entry {} does not chain to the previous entry", entry.seq),
            ));
        }
        if entry.previous_epoch != self.chain_epoch {
            return Err(Self::mismatch(
                ns,
                format!(
                    "entry {} names previous epoch {}, the head is at epoch {}",
                    entry.seq, entry.previous_epoch, self.chain_epoch
                ),
            ));
        }
        if let Some(first) = self.audit.first()
            && first.namespace != entry.namespace
        {
            return Err(Self::mismatch(ns, "entry namespace differs from the log"));
        }
        if let Some(earlier) = self.audit.iter().find(|e| e.epoch == entry.epoch)
            && (earlier.key_id != entry.key_id || earlier.key_check != entry.key_check)
        {
            return Err(Self::mismatch(
                ns,
                format!(
                    "entry {} names another key for epoch {} than entry {}",
                    entry.seq, entry.epoch, earlier.seq
                ),
            ));
        }
        let next = self.chain_epoch.checked_add(1);
        let transition_ok = match entry.action {
            AuditAction::Mint => self.chain_epoch == 0 && entry.new_epoch == 1 && entry.epoch == 1,
            AuditAction::Supersede => {
                self.chain_epoch > 0
                    && Some(entry.new_epoch) == next
                    && entry.epoch == entry.new_epoch
            }
            AuditAction::AddRecipient | AuditAction::RemoveRecipient => {
                entry.new_epoch == self.chain_epoch
                    && entry.epoch >= 1
                    && entry.epoch <= self.chain_epoch
                    && entry.subject.is_some()
            }
        };
        if !transition_ok {
            return Err(Self::mismatch(
                ns,
                format!(
                    "entry {} ({:?}) is not a valid transition from epoch {}",
                    entry.seq, entry.action, self.chain_epoch
                ),
            ));
        }
        self.chain_epoch = entry.new_epoch;
        self.last_line_sha256 = line_sha256(line);
        self.audit.push(entry);
        Ok(())
    }

    /// Rebuild a ledger from its records and the text of its audit log, and
    /// cross-check them.
    ///
    /// # Errors
    /// A torn, malformed or broken chain, or records that disagree with it.
    pub(super) fn replay(
        records: Vec<ScopeKeyRecord>,
        log: &str,
    ) -> Result<Self, ScopeKeyStoreError> {
        let namespace = records
            .first()
            .map(|r| r.namespace.clone())
            .unwrap_or_default();
        let mut ledger = Self::default();
        if !log.is_empty() && !log.ends_with('\n') {
            return Err(Self::mismatch(&namespace, "the last audit line is torn"));
        }
        for line in log.lines() {
            let entry: AuditEntry = serde_json::from_str(line)
                .map_err(|e| Self::mismatch(&namespace, format!("malformed audit line: {e}")))?;
            ledger.append_line(entry, line)?;
        }
        ledger.records = records;
        ledger.check_records(&namespace)?;
        Ok(ledger)
    }

    /// The records agree with the audit chain.
    fn check_records(&self, namespace: &str) -> Result<(), ScopeKeyStoreError> {
        let epochs = u32::try_from(self.records.len()).unwrap_or(u32::MAX);
        if epochs != self.chain_epoch {
            return Err(Self::mismatch(
                namespace,
                format!(
                    "{epochs} records on disk, the audit log accounts for {}",
                    self.chain_epoch
                ),
            ));
        }
        if self.audit.first().is_some_and(|e| e.namespace != namespace) {
            return Err(Self::mismatch(
                namespace,
                "audit log names another namespace",
            ));
        }
        for record in &self.records {
            let Some(last) = self.audit.iter().rev().find(|e| e.epoch == record.epoch) else {
                return Err(Self::mismatch(
                    namespace,
                    format!("epoch {} has no audit entry", record.epoch),
                ));
            };
            if last.recipients != recipient_fingerprints(record) {
                return Err(Self::mismatch(
                    namespace,
                    format!(
                        "epoch {} readers differ from its last audit entry {}",
                        record.epoch, last.seq
                    ),
                ));
            }
            if last.key_id != record.key_id || last.key_check != record.key_check {
                return Err(Self::mismatch(
                    namespace,
                    format!(
                        "epoch {} key differs from its last audit entry {}",
                        record.epoch, last.seq
                    ),
                ));
            }
            if last.recovery_fingerprint != record.escrow.recovery_fingerprint {
                return Err(Self::mismatch(
                    namespace,
                    format!("epoch {} escrow differs from its audit entry", record.epoch),
                ));
            }
        }
        Ok(())
    }

    /// Replace or push the record of its epoch.
    pub(super) fn put_record(&mut self, record: ScopeKeyRecord) {
        let index = usize::try_from(record.epoch.saturating_sub(1)).unwrap_or(usize::MAX);
        if let Some(slot) = self.records.get_mut(index) {
            *slot = record;
        } else {
            self.records.push(record);
        }
    }
}
