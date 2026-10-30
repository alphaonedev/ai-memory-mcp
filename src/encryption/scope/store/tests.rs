// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — scope-key store, stanza, escrow, audit-log and cache tests.
//! TEST material only: every key here is generated at random inside the test.

use super::*;
use crate::encryption::scope::{
    RecordBinding, ScopeEnvelopeError, open_content_scoped_in, open_scoped, scope_envelope_error,
    seal_scoped,
};
use rand_core::OsRng;

fn sandbox() -> tempfile::TempDir {
    let t = tempfile::tempdir().expect("tempdir under TMPDIR");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod sandbox");
    }
    t
}

const ACTOR: &str = "node-test-8278";

fn open_store(dir: &Path) -> FileScopeKeyStore {
    FileScopeKeyStore::open(dir.to_path_buf(), ACTOR).expect("open store")
}

/// A random TEST node keypair (never written to disk, never cached).
fn test_node(agent_id: &str) -> Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    Keypair {
        agent_id: agent_id.to_string(),
        public: PublicKey::from(&secret),
        secret,
    }
}

/// Enrol a random TEST recovery key in `dir`; returns its private half.
fn enrol_test_recovery(dir: &Path) -> StaticSecret {
    let secret = StaticSecret::random_from_rng(OsRng);
    escrow::enroll_recovery_pubkey(dir, &PublicKey::from(&secret)).expect("enrol recovery key");
    secret
}

fn store_refusal(err: &anyhow::Error) -> ScopeKeyStoreError {
    scope_key_store_error(err)
        .cloned()
        .unwrap_or_else(|| panic!("expected a typed ScopeKeyStoreError, got: {err:#}"))
}

fn row<'a>(memory_id: &'a str, namespace: &'a str) -> RecordBinding<'a> {
    RecordBinding::new(memory_id, namespace)
}

const NS: &str = "test/e2e-store-8278";

fn minted(store: &FileScopeKeyStore, readers: &[&Keypair]) -> ScopeKeyRecord {
    let readers: Vec<ReaderKek> = readers.iter().map(|k| ReaderKek::from_keypair(k)).collect();
    match store.mint(NS, &readers).expect("mint") {
        MintOutcome::Minted(record) => record,
        MintOutcome::Existing(_) => panic!("expected a fresh mint"),
    }
}

fn kek_fp(node: &Keypair) -> String {
    ReaderKek::from_keypair(node).fingerprint()
}

#[test]
fn scope_key_mint_writes_private_record_with_escrow_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let record = minted(&store, &[&node]);
    assert_eq!(record.epoch, 1);
    assert_eq!(record.namespace, NS);
    assert_eq!(record.recipients.len(), 1);
    assert!(record.superseded_at.is_none());
    #[cfg(unix)]
    for path in [store.record_path(NS, 1), store.audit_path(NS)] {
        use std::os::unix::fs::PermissionsExt as _;
        assert!(path.starts_with(dir.path().join(SCOPE_KEY_SUBDIR)));
        let mode = std::fs::metadata(&path)
            .expect("ledger file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{} must be owner-only", path.display());
    }
    assert_eq!(store.load_current(NS).expect("load"), Some(record.clone()));
    assert_eq!(
        store
            .load_by_key_id(NS, &record.key_ref().expect("ref"))
            .expect("by id"),
        Some(record)
    );
}

#[test]
fn scope_key_mint_refused_without_recovery_key_8278() {
    let dir = sandbox();
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let err = store
        .mint(NS, &[ReaderKek::from_keypair(&node)])
        .expect_err("no recovery key, no mint");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::EscrowUnavailable { .. }
    ));
    assert_eq!(
        store.load_current(NS).expect("load"),
        None,
        "nothing written"
    );
    assert!(store.audit_log(NS).expect("audit").is_empty());
    let err = store.mint(NS, &[]).expect_err("no reader, no mint");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::NoRecipients { .. }
    ));
}

#[test]
fn scope_key_mint_is_idempotent_and_serialised_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let reader = ReaderKek::from_keypair(&node);
    let outcomes: Vec<MintOutcome> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| s.spawn(|| store.mint(NS, std::slice::from_ref(&reader)).expect("mint")))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mint thread"))
            .collect()
    });
    let fresh = outcomes
        .iter()
        .filter(|o| matches!(o, MintOutcome::Minted(_)))
        .count();
    assert_eq!(fresh, 1, "exactly one concurrent mint creates the key");
    let ids: std::collections::HashSet<&str> = outcomes
        .iter()
        .map(|o| o.record().key_id.as_str())
        .collect();
    assert_eq!(ids.len(), 1, "every caller sees the one key");
    assert_eq!(store.history(NS).expect("history").len(), 1);
    assert_eq!(store.ledger_head(NS).expect("head"), LedgerHead(1));
}

#[test]
fn scope_key_reader_opens_non_reader_cannot_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let reader = test_node("node-reader");
    let outsider = test_node("node-outsider");
    let record = minted(&store, &[&reader]);
    let key = record.unwrap_for(&reader).expect("reader unwraps");
    let sealed = seal_scoped("readers only", &key, row("mem-1", NS)).expect("seal");
    assert_eq!(
        open_content_scoped_in(&sealed, &reader, &store, row("mem-1", NS)).expect("reader"),
        "readers only"
    );
    let err = open_content_scoped_in(&sealed, &outsider, &store, row("mem-1", NS))
        .expect_err("non-reader must not open");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::NotAReader { .. }
    ));
}

#[test]
fn scope_open_unknown_key_is_typed_unknown_key_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let reader = test_node("node-reader");
    let record = minted(&store, &[&reader]);
    // An epoch the ledger does not hold, in a namespace it does.
    let future = ScopeKey::generate(
        NS,
        ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch: record.epoch + 1,
        },
    );
    let sealed = seal_scoped("future epoch", &future, row("mem-u", NS)).expect("seal");
    let err = open_content_scoped_in(&sealed, &reader, &store, row("mem-u", NS))
        .expect_err("unknown epoch must not open");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::UnknownKey { .. }
    ));
    // A namespace with no ledger at all.
    let other = "test/no-ledger-8278";
    let stray = ScopeKey::generate(
        other,
        ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch: 1,
        },
    );
    let sealed = seal_scoped("no ledger", &stray, row("mem-v", other)).expect("seal");
    let err = open_content_scoped_in(&sealed, &reader, &store, row("mem-v", other))
        .expect_err("no ledger must not open");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::UnknownKey { .. }
    ));
}

#[test]
fn scope_key_add_then_remove_reader_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let first = test_node("node-first");
    let second = test_node("node-second");
    let record = minted(&store, &[&first]);
    let key = record.unwrap_for(&first).expect("first unwraps");
    let sealed = seal_scoped("shared later", &key, row("mem-2", NS)).expect("seal");
    let second_kek = ReaderKek::from_keypair(&second);

    assert_eq!(
        store.add_recipient(&key, &second_kek).expect("add"),
        RecipientChange::Added
    );
    assert_eq!(
        store.add_recipient(&key, &second_kek).expect("add again"),
        RecipientChange::AlreadyPresent
    );
    assert_eq!(
        open_content_scoped_in(&sealed, &second, &store, row("mem-2", NS)).expect("added reader"),
        "shared later"
    );

    assert_eq!(
        store
            .remove_recipient(NS, 1, &second_kek.fingerprint())
            .expect("remove"),
        RecipientChange::Removed
    );
    let err = open_content_scoped_in(&sealed, &second, &store, row("mem-2", NS))
        .expect_err("removed reader no longer pulls the key");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::NotAReader { .. }
    ));
    assert_eq!(
        store
            .remove_recipient(NS, 1, &second_kek.fingerprint())
            .expect("remove again"),
        RecipientChange::Absent
    );
    let err = store
        .remove_recipient(NS, 1, &kek_fp(&first))
        .expect_err("last reader stays");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::LastRecipient { .. }
    ));
}

#[test]
fn scope_key_add_recipient_refuses_a_key_failing_the_check_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let first = test_node("node-first");
    let record = minted(&store, &[&first]);
    let forged = ScopeKey::generate(NS, record.key_ref().expect("ref"));
    let err = store
        .add_recipient(&forged, &ReaderKek::from_keypair(&test_node("node-x")))
        .expect_err("a key that is not the record's key is refused");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::StanzaBindingMismatch { .. }
    ));
    assert_eq!(store.ledger_head(NS).expect("head"), LedgerHead(1));
}

#[test]
fn scope_key_supersede_keeps_old_rows_on_old_key_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let stays = test_node("node-stays");
    let revoked = test_node("node-revoked");
    let first = minted(&store, &[&stays, &revoked]);
    let old_key = first.unwrap_for(&stays).expect("epoch 1");
    let old_row = seal_scoped("before rotation", &old_key, row("mem-old", NS)).expect("seal");

    let second = store
        .supersede(NS, &[ReaderKek::from_keypair(&stays)])
        .expect("supersede");
    assert_eq!(second.epoch, 2);
    assert_ne!(second.key_id, first.key_id);
    let history = store.history(NS).expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].superseded_at.as_deref(),
        Some(second.created_at.as_str()),
        "half-open windows meet exactly"
    );
    assert_eq!(
        store.load_current(NS).expect("current"),
        Some(second.clone())
    );

    let new_key = second.unwrap_for(&stays).expect("epoch 2");
    let new_row = seal_scoped("after rotation", &new_key, row("mem-new", NS)).expect("seal");
    assert_eq!(
        open_content_scoped_in(&old_row, &stays, &store, row("mem-old", NS)).expect("old row"),
        "before rotation"
    );
    assert_eq!(
        open_content_scoped_in(&new_row, &stays, &store, row("mem-new", NS)).expect("new row"),
        "after rotation"
    );
    // The new key does not open the old row and vice versa.
    let err = open_scoped(&old_row, &new_key, row("mem-old", NS)).expect_err("old row, new key");
    assert!(matches!(
        scope_envelope_error(&err),
        Some(ScopeEnvelopeError::KeyMismatch { .. })
    ));
    // The revoked reader keeps epoch 1 (rotation of old rows is the D5 job)
    // but holds nothing for epoch 2.
    let err = open_content_scoped_in(&new_row, &revoked, &store, row("mem-new", NS))
        .expect_err("revoked reader gets no new key");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::NotAReader { .. }
    ));
}

#[test]
fn scope_key_supersede_refuses_a_changed_recovery_key_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    minted(&store, &[&node]);
    // Another recovery key now enrolled (the explicit rotation path, #3717,
    // is the only legitimate way; this simulates its file landing).
    let other = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    crate::identity::keypair::write_with_mode(
        &escrow::recovery_pub_path(dir.path()),
        other.as_bytes(),
        0o644,
    )
    .expect("replace TEST recovery key");
    let err = store
        .supersede(NS, &[ReaderKek::from_keypair(&node)])
        .expect_err("escrow chain must not fork");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::RecoveryKeyChanged { .. }
    ));
    assert_eq!(
        store.history(NS).expect("history").len(),
        1,
        "nothing written"
    );
    assert_eq!(store.ledger_head(NS).expect("head"), LedgerHead(1));
}

#[test]
fn scope_key_escrow_recover_round_trip_8278() {
    let dir = sandbox();
    let recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let lost = test_node("node-lost");
    let record = minted(&store, &[&lost]);
    let original = record.unwrap_for(&lost).expect("unwrap");
    let sealed =
        seal_scoped("survives a lost node key", &original, row("mem-3", NS)).expect("seal");

    // The real recovery path: the recovery private key alone yields a scope
    // key that opens the content row.
    let recovered = record.recover_with(&recovery).expect("escrow recover");
    assert_eq!(
        open_scoped(&sealed, &recovered, row("mem-3", NS)).expect("recovered key opens the row"),
        "survives a lost node key"
    );
    // Re-grant to the node's replacement KEK, which then opens the row.
    let replacement = test_node("node-lost");
    assert_eq!(
        store
            .add_recipient(&recovered, &ReaderKek::from_keypair(&replacement))
            .expect("regrant"),
        RecipientChange::Added
    );
    assert_eq!(
        open_content_scoped_in(&sealed, &replacement, &store, row("mem-3", NS)).expect("open"),
        "survives a lost node key"
    );
    let wrong = StaticSecret::random_from_rng(OsRng);
    let err = record.recover_with(&wrong).expect_err("wrong recovery key");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::RecoveryKeyMismatch { .. }
    ));
}

#[test]
fn scope_key_stanza_moved_between_records_refused_8278() {
    let dir = sandbox();
    let recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let reader = ReaderKek::from_keypair(&node);
    let a = store
        .mint("test/ns-a-8278", std::slice::from_ref(&reader))
        .expect("mint a")
        .record()
        .clone();
    let mut b = store
        .mint("test/ns-b-8278", std::slice::from_ref(&reader))
        .expect("mint b")
        .record()
        .clone();
    // A stanza that genuinely unwraps under this KEK, but for another key.
    b.recipients[0].wrapped = a.recipients[0].wrapped.clone();
    let err = b
        .unwrap_for(&node)
        .expect_err("stanza of another namespace");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::StanzaBindingMismatch { .. }
    ));
    // The escrow stanza of `a`, opened with the genuinely enrolled recovery
    // key: it decrypts, and the id binding refuses it.
    b.escrow.wrapped = a.escrow.wrapped.clone();
    let err = b
        .recover_with(&recovery)
        .expect_err("escrow stanza of another namespace");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::StanzaBindingMismatch { .. }
    ));
}

#[test]
fn scope_key_audit_records_every_mutation_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let first = test_node("node-first");
    let second = test_node("node-second");
    let record = minted(&store, &[&first]);
    let key = record.unwrap_for(&first).expect("unwrap");
    store
        .add_recipient(&key, &ReaderKek::from_keypair(&second))
        .expect("add");
    store
        .remove_recipient(NS, 1, &kek_fp(&second))
        .expect("remove");
    let next = store
        .supersede(NS, &[ReaderKek::from_keypair(&first)])
        .expect("supersede");

    let log = store.audit_log(NS).expect("audit");
    let shape: Vec<(u64, AuditAction, u32, u32, u32, Option<String>)> = log
        .iter()
        .map(|e| {
            (
                e.seq,
                e.action,
                e.epoch,
                e.previous_epoch,
                e.new_epoch,
                e.subject.clone(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            (1, AuditAction::Mint, 1, 0, 1, None),
            (2, AuditAction::AddRecipient, 1, 1, 1, Some(kek_fp(&second))),
            (
                3,
                AuditAction::RemoveRecipient,
                1,
                1,
                1,
                Some(kek_fp(&second))
            ),
            (4, AuditAction::Supersede, 2, 1, 2, None),
        ],
        "one entry per mutation, in order"
    );
    for entry in &log {
        assert_eq!(entry.actor, ACTOR);
        assert_eq!(entry.namespace, NS);
        assert_eq!(
            entry.recovery_fingerprint,
            record.escrow.recovery_fingerprint
        );
        assert!(chrono::DateTime::parse_from_rfc3339(&entry.at).is_ok());
    }
    assert!(log[0].prev_sha256.is_empty());
    assert!(
        log[1..].iter().all(|e| e.prev_sha256.len() == 64),
        "hash chained"
    );
    assert_eq!(log[1].recipients.len(), 2);
    assert_eq!(log[3].recipients, vec![kek_fp(&first)]);
    assert_eq!(store.ledger_head(NS).expect("head"), LedgerHead(4));
    // The cold store replays to the same log and records.
    let fresh = open_store(dir.path());
    assert_eq!(fresh.audit_log(NS).expect("replayed"), log);
    assert_eq!(fresh.load_current(NS).expect("current"), Some(next));
}

#[test]
fn scope_key_audit_refuses_a_wrong_previous_epoch_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let record = minted(&store, &[&node]);
    let mut ledger = store.load_namespace_locked(NS).expect("ledger");
    let mut next = record.clone();
    next.epoch = 2;
    let change = Change {
        action: AuditAction::Supersede,
        actor: ACTOR,
        record: &next,
        subject: None,
        at: now_rfc3339(),
    };
    let good = ledger.entry_for(&change);
    assert_eq!(good.previous_epoch, 1, "the entry points at the head");

    let mut stale = good.clone();
    stale.previous_epoch = 0;
    assert!(matches!(
        ledger.append(stale.clone()),
        Err(ScopeKeyStoreError::AuditChainMismatch { .. })
    ));
    let mut skipped = good.clone();
    skipped.seq += 1;
    assert!(matches!(
        ledger.append(skipped),
        Err(ScopeKeyStoreError::AuditChainMismatch { .. })
    ));
    assert_eq!(ledger.head(), LedgerHead(1), "refusals append nothing");

    // The same entry landing on disk outside the store fails closed on load.
    let line = serde_json::to_string(&stale).expect("line");
    store
        .append_audit_line(NS, &line)
        .expect("append TEST line");
    store.refresh_from_ledger().expect("refresh");
    assert!(matches!(
        store_refusal(&store.history(NS).expect_err("broken chain")),
        ScopeKeyStoreError::AuditChainMismatch { .. }
    ));
    assert!(
        store.namespace_is_e2e(NS),
        "an unreadable ledger stays end-to-end"
    );
}

#[test]
fn scope_key_namespace_is_e2e_iff_ledger_has_an_epoch_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    assert!(!store.namespace_is_e2e(NS), "no ledger: not end-to-end");
    let node = test_node("node-a");
    minted(&store, &[&node]);
    assert!(store.namespace_is_e2e(NS), "one epoch: end-to-end");
    assert!(!store.namespace_is_e2e("test/plain-8278"));
    assert!(
        open_store(dir.path()).namespace_is_e2e(NS),
        "cold store agrees"
    );
}

#[test]
fn scope_key_store_writes_through_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let writer = open_store(dir.path());
    let node = test_node("node-a");
    let record = minted(&writer, &[&node]);
    // The mutating store answers from its cache at once: no reload.
    assert_eq!(
        writer.load_current(NS).expect("cached"),
        Some(record.clone())
    );
    assert_eq!(writer.ledger_head(NS).expect("head"), LedgerHead(1));
    // The files already hold it: a store opened afterwards sees the same.
    let later = open_store(dir.path());
    assert_eq!(later.load_current(NS).expect("cold"), Some(record));
    assert_eq!(later.ledger_head(NS).expect("head"), LedgerHead(1));
}

#[test]
fn scope_key_stale_cache_refuses_sealed_foreign_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let stale = open_store(dir.path());
    let writer = open_store(dir.path());
    let node = test_node("node-a");
    let record = minted(&writer, &[&node]);
    let key_ref = record.key_ref().expect("ref");
    let required = writer.ledger_head(NS).expect("head");

    let err = stale
        .load_by_key_id_fresh(NS, &key_ref, required)
        .expect_err("a cache older than the required head must not answer");
    assert_eq!(
        store_refusal(&err),
        ScopeKeyStoreError::SealedForeign {
            namespace: NS.to_string(),
            cached_head: 0,
            required_head: 1,
        }
    );
    stale.refresh_from_ledger().expect("refresh");
    assert_eq!(
        stale
            .load_by_key_id_fresh(NS, &key_ref, required)
            .expect("fresh now"),
        Some(record)
    );
}

#[test]
fn scope_key_record_tamper_and_gaps_fail_closed_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let record = minted(&store, &[&node]);
    let path = store.record_path(NS, 1);
    let refreshed_refusal = |what: &str| {
        store.refresh_from_ledger().expect("refresh");
        store_refusal(&store.load_current(NS).expect_err(what))
    };
    let restore = || {
        store.write_record(&record).expect("restore");
        store.refresh_from_ledger().expect("refresh");
        assert_eq!(
            store.load_current(NS).expect("healed"),
            Some(record.clone())
        );
    };

    // An envelope naming another key id for an epoch the ledger holds.
    let foreign = ScopeKeyRef {
        key_id: ScopeKeyId::random(),
        epoch: record.epoch,
    };
    let err = store
        .load_by_key_id(NS, &foreign)
        .expect_err("foreign key id at a held epoch");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::KeyIdMismatch { .. }
    ));

    // A record whose key id was rewritten disagrees with the key id its
    // audit entry binds (R13), so the ledger refuses it at load, before any
    // envelope key compare.
    let mut forged = record.clone();
    forged.key_id = ScopeKeyId::random().to_hex();
    store.write_record(&forged).expect("write forged");
    store.refresh_from_ledger().expect("refresh");
    let err = store
        .load_by_key_id(NS, &record.key_ref().expect("ref"))
        .expect_err("divergent key id");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::AuditChainMismatch { .. }
    ));
    restore();

    // A reader added outside the store disagrees with the audit log.
    let mut widened = record.clone();
    widened.recipients.push(RecipientStanza {
        agent_id: "node-intruder".to_string(),
        kek_fingerprint: kek_fp(&test_node("node-intruder")),
        wrapped: record.recipients[0].wrapped.clone(),
    });
    store.write_record(&widened).expect("write widened");
    assert!(matches!(
        refreshed_refusal("reader set off the log"),
        ScopeKeyStoreError::AuditChainMismatch { .. }
    ));
    restore();

    // Malformed JSON.
    crate::identity::keypair::write_with_mode(&path, b"{not json", 0o600).expect("write junk");
    assert!(matches!(
        refreshed_refusal("junk"),
        ScopeKeyStoreError::RecordCorrupt { .. }
    ));
    restore();

    // Group/other access, and a link in place of the file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            refreshed_refusal("loose mode"),
            ScopeKeyStoreError::RecordCorrupt { .. }
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let moved = dir.path().join("moved-record-8278.json");
        std::fs::rename(&path, &moved).expect("move record");
        std::os::unix::fs::symlink(&moved, &path).expect("link record");
        assert!(matches!(
            refreshed_refusal("symlinked record"),
            ScopeKeyStoreError::RecordCorrupt { .. }
        ));
        std::fs::remove_file(&path).expect("remove link");
        std::fs::rename(&moved, &path).expect("move back");
        restore();
    }

    // An audit line removed (the log no longer accounts for the record).
    let audit = store.audit_path(NS);
    let log = std::fs::read(&audit).expect("audit bytes");
    crate::identity::keypair::write_with_mode(&audit, b"", 0o600).expect("truncate audit");
    assert!(matches!(
        refreshed_refusal("emptied audit log"),
        ScopeKeyStoreError::RecordCorrupt { .. } | ScopeKeyStoreError::AuditChainMismatch { .. }
    ));
    crate::identity::keypair::write_with_mode(&audit, &log, 0o600).expect("restore audit");
    restore();

    // A missing generation is a lost key, never flattened.
    let mut third = record.clone();
    third.epoch = 3;
    store.write_record(&third).expect("write epoch 3");
    store.refresh_from_ledger().expect("refresh");
    assert!(matches!(
        store_refusal(&store.history(NS).expect_err("gap at epoch 2")),
        ScopeKeyStoreError::RecordCorrupt { .. }
    ));
    std::fs::remove_file(store.record_path(NS, 3)).expect("remove epoch 3");
    restore();
}

/// Removes the TEST namespace's files from the shared default key directory.
fn remove_seeded(store: &FileScopeKeyStore, namespace: &str) {
    std::fs::remove_file(store.record_path(namespace, 1)).expect("clean up TEST record");
    std::fs::remove_file(store.audit_path(namespace)).expect("clean up TEST audit log");
}

#[test]
fn open_content_bound_opens_scope_row_from_the_key_dir_8278() {
    // The production funnel: `open_content_bound` resolves the agent KEK and
    // the file store from the (test-isolated) default key directory.
    let agent = "scope-bound-funnel-8278";
    let kp = crate::encryption::get_or_create_keypair(agent).expect("keypair");
    let key_dir = crate::encryption::keypair_persist_dir().expect("key dir");
    let store = FileScopeKeyStore::open(key_dir, agent).expect("open store");
    let namespace = format!("test/bound-funnel-8278-{}", ScopeKeyId::random());
    // TEST recovery key generated here and never enrolled in the shared dir.
    let recovery = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    let key = ScopeKey::generate(
        &namespace,
        ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch: 1,
        },
    );
    let record = build_record(
        &key,
        &[ReaderKek::from_keypair(&kp)],
        &recovery,
        now_rfc3339(),
    )
    .expect("record");
    store.seed_minted_for_test(&record).expect("seed record");
    let sealed = seal_scoped("bound funnel", &key, row("mem-f", &namespace)).expect("seal");
    let opened = crate::encryption::open_content_bound(&sealed, agent, row("mem-f", &namespace));
    let moved = crate::encryption::open_content_bound(&sealed, agent, row("mem-g", &namespace));
    remove_seeded(&store, &namespace);
    assert_eq!(opened.expect("bound open"), "bound funnel");
    let err = moved.expect_err("another row id");
    assert!(matches!(
        scope_envelope_error(&err),
        Some(ScopeEnvelopeError::Authentication)
    ));
}

#[test]
fn open_content_bound_unknown_key_is_typed_8278() {
    let agent = "scope-bound-unknown-8278";
    crate::encryption::get_or_create_keypair(agent).expect("keypair");
    let namespace = format!("test/bound-unknown-8278-{}", ScopeKeyId::random());
    let key = ScopeKey::generate(
        &namespace,
        ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch: 1,
        },
    );
    let sealed = seal_scoped("no record", &key, row("mem-k", &namespace)).expect("seal");
    let err = crate::encryption::open_content_bound(&sealed, agent, row("mem-k", &namespace))
        .expect_err("a key the ledger does not hold must not open");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::UnknownKey { .. }
    ));
}

/// R13 (security r2 M2): a whole-record substitute built only from public
/// inputs (the readers' and the recovery key's public halves, the public key
/// id) must not load: the audit entry binds the key id and the key check.
#[test]
fn scope_key_audit_refuses_whole_record_substitution_8278() {
    let dir = sandbox();
    let recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let record = minted(&store, &[&node]);
    let readers = [ReaderKek::from_keypair(&node)];
    let recovery_public = PublicKey::from(&recovery);
    let fresh_ref = ScopeKeyRef {
        key_id: ScopeKeyId::random(),
        epoch: record.epoch,
    };
    // Case 1: a fresh key id; case 2: the record's own (public) key id.
    for key_ref in [fresh_ref, record.key_ref().expect("ref")] {
        let forged_key = ScopeKey::generate(NS, key_ref);
        let substitute = build_record(
            &forged_key,
            &readers,
            &recovery_public,
            record.created_at.clone(),
        )
        .expect("substitute from public inputs");
        assert_ne!(substitute.key_check, record.key_check);
        store.write_record(&substitute).expect("write substitute");
        store.refresh_from_ledger().expect("refresh");
        let err = store
            .load_current(NS)
            .expect_err("a substituted key must not load");
        assert!(matches!(
            store_refusal(&err),
            ScopeKeyStoreError::AuditChainMismatch { .. }
        ));
        store.write_record(&record).expect("restore");
        store.refresh_from_ledger().expect("refresh");
        assert_eq!(
            store.load_current(NS).expect("healed"),
            Some(record.clone())
        );
    }
}

/// R14 (security r2 L1): an edit to a middle audit line breaks the hash
/// chain at the next line and fails closed with the typed chain error.
#[test]
fn scope_key_audit_refuses_an_edited_middle_line_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let node = test_node("node-a");
    let second = test_node("node-b");
    let record = minted(&store, &[&node]);
    let key = record.unwrap_for(&node).expect("unwrap");
    store
        .add_recipient(&key, &ReaderKek::from_keypair(&second))
        .expect("add");
    store
        .remove_recipient(NS, 1, &kek_fp(&second))
        .expect("remove");
    assert_eq!(store.ledger_head(NS).expect("head"), LedgerHead(3));
    let path = store.audit_path(NS);
    let text = std::fs::read_to_string(&path).expect("read audit");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut middle: serde_json::Value = serde_json::from_str(&lines[1]).expect("middle line");
    middle["at"] = serde_json::Value::String("2001-01-01T00:00:00+00:00".to_string());
    lines[1] = serde_json::to_string(&middle).expect("edited line");
    let edited = format!("{}\n", lines.join("\n"));
    crate::identity::keypair::write_with_mode(&path, edited.as_bytes(), 0o600)
        .expect("write edited audit");
    store.refresh_from_ledger().expect("refresh");
    assert!(matches!(
        store_refusal(&store.history(NS).expect_err("edited middle line")),
        ScopeKeyStoreError::AuditChainMismatch { .. }
    ));
    assert!(
        store.namespace_is_e2e(NS),
        "a broken ledger stays end-to-end"
    );
}

/// R14 (security r2 INFO): the stanza plaintext is id-bound. A stanza for
/// another key id, epoch or same-length namespace does not parse, even when
/// its length is right (defence in depth beside the key check).
#[test]
fn scope_key_stanza_plaintext_prefix_is_bound_8278() {
    let key_ref = ScopeKeyRef {
        key_id: ScopeKeyId::random(),
        epoch: 4,
    };
    let key = ScopeKey::generate(NS, key_ref);
    let plaintext = stanza_plaintext(&key).expect("stanza plaintext");
    assert!(parse_stanza_plaintext(&plaintext, key_ref, NS).is_some());
    let other_id = ScopeKeyRef {
        key_id: ScopeKeyId::random(),
        epoch: 4,
    };
    let other_epoch = ScopeKeyRef {
        key_id: key_ref.key_id,
        epoch: 5,
    };
    let same_len_ns = "test/e2e-store-9999";
    assert_eq!(same_len_ns.len(), NS.len());
    assert!(parse_stanza_plaintext(&plaintext, other_id, NS).is_none());
    assert!(parse_stanza_plaintext(&plaintext, other_epoch, NS).is_none());
    assert!(parse_stanza_plaintext(&plaintext, key_ref, same_len_ns).is_none());
}

/// R17 (code r2 C2): a store opened before another writer minted epoch 1 in
/// the same key directory answers the marker from the cold store on a cache
/// miss, without an explicit refresh.
#[test]
fn scope_key_namespace_marker_refreshes_on_cache_miss_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let early = open_store(dir.path());
    assert!(!early.namespace_is_e2e(NS), "no ledger yet");
    let writer = open_store(dir.path());
    let node = test_node("node-a");
    minted(&writer, &[&node]);
    assert!(
        early.namespace_is_e2e(NS),
        "a store opened before another writer minted must answer end-to-end"
    );
    assert!(!early.namespace_is_e2e("test/plain-8278"));
}

/// Code r3 F2 / security r3 S2: a key directory this process can no longer
/// traverse answers end-to-end on a cache miss (fail closed), never the
/// plaintext answer, even when another store minted epoch 1 earlier.
#[cfg(unix)]
#[test]
fn scope_key_namespace_marker_fails_closed_on_unreadable_key_dir_8278() {
    use std::os::unix::fs::PermissionsExt as _;
    /// Restores the sandbox mode even when an assertion below fails.
    struct RestoreMode<'a>(&'a Path);
    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    // SAFETY: `geteuid` has no preconditions and only reads a process property.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root ignores directory modes, so mode 0o000 cannot deny the read");
        return;
    }
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let early = open_store(dir.path());
    assert!(!early.namespace_is_e2e(NS), "no ledger yet");
    minted(&open_store(dir.path()), &[&test_node("node-a")]);
    let _restore = RestoreMode(dir.path());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000))
        .expect("make the key dir untraversable");
    assert!(
        early.namespace_is_e2e(NS),
        "an unreadable key dir must answer end-to-end (fail closed)"
    );
}

/// Sets a directory mode and restores `0o700` on drop, so a failing
/// assertion never leaves the sandbox untraversable.
#[cfg(unix)]
struct DirModeGuard(PathBuf);

#[cfg(unix)]
impl DirModeGuard {
    fn set(dir: PathBuf, mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
            .expect("set the scope-key dir mode");
        Self(dir)
    }
}

#[cfg(unix)]
impl Drop for DirModeGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// `true` when the test runs as root, which ignores directory modes.
#[cfg(unix)]
fn running_as_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and only reads a process property.
    unsafe { libc::geteuid() == 0 }
}

/// A store opened (and asked) before another store minted `NS` in `dir`, so
/// its next marker query is a cold cache miss.
fn cold_store_after_mint(dir: &Path) -> FileScopeKeyStore {
    let early = open_store(dir);
    assert!(!early.namespace_is_e2e(NS), "no ledger yet");
    minted(&open_store(dir), &[&test_node("node-a")]);
    early
}

/// Asserts the cold marker of `NS` fails closed on an error branch: the
/// answer is end-to-end and the reload itself refuses (never `Ok(false)`).
fn assert_marker_refuses(store: &FileScopeKeyStore, case: &str) {
    assert!(store.namespace_is_e2e(NS), "{case}: must answer end-to-end");
    let reload = store.reload_marker(&FileScopeKeyStore::slug(NS));
    assert!(
        reload.is_err(),
        "{case}: the reload must refuse: {reload:?}"
    );
}

/// Security r4 S5: the key dir replaced by a dangling link is not "absent"
/// (`symlink_metadata` sees the link); taking the lock then refuses.
#[cfg(unix)]
#[test]
fn scope_key_namespace_marker_fails_closed_on_dangling_key_dir_link_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let early = cold_store_after_mint(dir.path());
    let scope_dir = early.scope_dir();
    std::fs::rename(&scope_dir, dir.path().join("scope-keys-moved"))
        .expect("move the key dir away");
    std::os::unix::fs::symlink(dir.path().join("absent-target"), &scope_dir)
        .expect("dangling link in the key dir's place");
    assert_marker_refuses(&early, "dangling link");
}

/// Security r4 S5: a key dir whose lock cannot be taken (mode 0o000, the
/// parent stays traversable) answers end-to-end.
#[cfg(unix)]
#[test]
fn scope_key_namespace_marker_fails_closed_when_the_lock_fails_8278() {
    if running_as_root() {
        eprintln!("skipped: root ignores directory modes, so mode 0o000 cannot deny the lock");
        return;
    }
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let early = cold_store_after_mint(dir.path());
    let _mode = DirModeGuard::set(early.scope_dir(), 0o000);
    assert_marker_refuses(&early, "lock failure");
}

/// Security r4 S5: a key dir that can be locked but not listed (mode 0o300:
/// write and search, no read) answers end-to-end.
#[cfg(unix)]
#[test]
fn scope_key_namespace_marker_fails_closed_when_the_listing_fails_8278() {
    if running_as_root() {
        eprintln!("skipped: root ignores directory modes, so mode 0o300 cannot deny the listing");
        return;
    }
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let early = cold_store_after_mint(dir.path());
    let _mode = DirModeGuard::set(early.scope_dir(), 0o300);
    assert_marker_refuses(&early, "listing failure");
}

/// Security r4 S5: a garbled audit ledger read on a cold cache miss answers
/// end-to-end (the failed verification is cached as a refusal).
#[test]
fn scope_key_namespace_marker_fails_closed_on_a_garbled_ledger_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let early = cold_store_after_mint(dir.path());
    crate::identity::keypair::write_with_mode(&early.audit_path(NS), b"not an audit line\n", 0o600)
        .expect("garble the audit log");
    assert!(early.namespace_is_e2e(NS), "garbled ledger: end-to-end");
    assert!(
        matches!(early.reload_marker(&FileScopeKeyStore::slug(NS)), Ok(true)),
        "garbled ledger: the reload answers end-to-end"
    );
}

/// The ledger of `NS` straight from disk, with its current record.
fn disk_ledger(store: &FileScopeKeyStore) -> (NamespaceLedger, ScopeKeyRecord) {
    let ledger = store.load_namespace_locked(NS).expect("ledger");
    let record = ledger.records.last().cloned().expect("record");
    (ledger, record)
}

/// Code r3 F4 / security r3 S3a: an appended entry for an epoch already in
/// the log must name the same key; another key id or another key check is
/// refused with the typed chain error.
#[test]
fn scope_key_audit_append_refuses_another_key_for_a_known_epoch_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    minted(&store, &[&test_node("node-a")]);
    let (ledger, record) = disk_ledger(&store);
    let change = Change {
        action: AuditAction::AddRecipient,
        actor: ACTOR,
        record: &record,
        subject: Some(kek_fp(&test_node("node-b"))),
        at: record.created_at.clone(),
    };
    let honest = ledger.entry_for(&change);
    assert!(
        ledger.clone().append(honest.clone()).is_ok(),
        "the same key appends"
    );
    let other_id = AuditEntry {
        key_id: ScopeKeyId::random().to_hex(),
        ..honest.clone()
    };
    let other_check = AuditEntry {
        key_check: "00".repeat(32),
        ..honest
    };
    for (case, entry) in [("key_id", other_id), ("key_check", other_check)] {
        let err = ledger.clone().append(entry).expect_err(case);
        assert!(
            matches!(err, ScopeKeyStoreError::AuditChainMismatch { .. }),
            "{case}: {err:?}"
        );
    }
}

/// Security r3 S3b: a record whose escrow stanza names another recovery
/// fingerprint than its audit entry does not load.
#[test]
fn scope_key_record_with_another_recovery_fingerprint_is_refused_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = open_store(dir.path());
    let record = minted(&store, &[&test_node("node-a")]);
    let other = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    let mut moved = record.clone();
    moved.escrow.recovery_fingerprint = fingerprint_public_bytes(other.as_bytes());
    assert_ne!(
        moved.escrow.recovery_fingerprint,
        record.escrow.recovery_fingerprint
    );
    store.write_record(&moved).expect("write record");
    store.refresh_from_ledger().expect("refresh");
    let err = store
        .load_current(NS)
        .expect_err("another recovery fingerprint");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::AuditChainMismatch { .. }
    ));
}
