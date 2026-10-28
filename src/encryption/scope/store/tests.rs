// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — scope-key store, stanza and escrow tests. TEST material only:
//! every key here is generated at random inside the test.

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
    RecordBinding {
        memory_id,
        namespace,
    }
}

const NS: &str = "test/e2e-store-8278";

fn minted(store: &FileScopeKeyStore, readers: &[&Keypair]) -> ScopeKeyRecord {
    let readers: Vec<ReaderKek> = readers.iter().map(|k| ReaderKek::from_keypair(k)).collect();
    match store.mint(NS, &readers).expect("mint") {
        MintOutcome::Minted(record) => record,
        MintOutcome::Existing(_) => panic!("expected a fresh mint"),
    }
}

#[test]
fn scope_key_mint_writes_private_record_with_escrow_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
    let node = test_node("node-a");
    let record = minted(&store, &[&node]);
    assert_eq!(record.epoch, 1);
    assert_eq!(record.namespace, NS);
    assert_eq!(record.recipients.len(), 1);
    assert!(record.superseded_at.is_none());
    let path = store.record_path(NS, 1);
    assert!(path.starts_with(dir.path().join(SCOPE_KEY_SUBDIR)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("record")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "record file must be owner-only");
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
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
}

#[test]
fn scope_key_reader_opens_non_reader_cannot_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
fn scope_key_add_then_remove_reader_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
        .remove_recipient(NS, 1, &ReaderKek::from_keypair(&first).fingerprint())
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
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
}

#[test]
fn scope_key_supersede_keeps_old_rows_on_old_key_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
fn scope_key_escrow_recover_round_trip_8278() {
    let dir = sandbox();
    let recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
    let lost = test_node("node-lost");
    let record = minted(&store, &[&lost]);
    let original = record.unwrap_for(&lost).expect("unwrap");
    let sealed =
        seal_scoped("survives a lost node key", &original, row("mem-3", NS)).expect("seal");

    let recovered = record.recover_with(&recovery).expect("escrow recover");
    assert_eq!(recovered.secret_bytes(), original.secret_bytes());
    assert_eq!(recovered.key_ref(), original.key_ref());
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
    let _recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
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
    b.escrow.wrapped = a.escrow.wrapped.clone();
    let err = b
        .recover_with(&enrol_test_recovery_noop(&a))
        .expect_err("recovery fingerprint gate first");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::RecoveryKeyMismatch { .. }
    ));
}

/// A random recovery secret that is NOT the enrolled one.
fn enrol_test_recovery_noop(_record: &ScopeKeyRecord) -> StaticSecret {
    StaticSecret::random_from_rng(OsRng)
}

#[test]
fn scope_key_record_tamper_and_gaps_fail_closed_8278() {
    let dir = sandbox();
    let _recovery = enrol_test_recovery(dir.path());
    let store = FileScopeKeyStore::new(dir.path().to_path_buf());
    let node = test_node("node-a");
    let record = minted(&store, &[&node]);
    let path = store.record_path(NS, 1);

    // A record whose key id was rewritten no longer matches an envelope's key.
    let mut forged = record.clone();
    forged.key_id = ScopeKeyId::random().to_hex();
    store.write_record(&forged).expect("write forged");
    let err = store
        .load_by_key_id(NS, &record.key_ref().expect("ref"))
        .expect_err("divergent key id");
    assert!(matches!(
        store_refusal(&err),
        ScopeKeyStoreError::KeyIdMismatch { .. }
    ));
    store.write_record(&record).expect("restore");

    // Malformed JSON.
    crate::identity::keypair::write_with_mode(&path, b"{not json", 0o600).expect("write junk");
    assert!(matches!(
        store_refusal(&store.load_current(NS).expect_err("junk")),
        ScopeKeyStoreError::RecordCorrupt { .. }
    ));
    store.write_record(&record).expect("restore");

    // Group/other access.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            store_refusal(&store.load_current(NS).expect_err("loose mode")),
            ScopeKeyStoreError::RecordCorrupt { .. }
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    // A missing generation is a lost key, never flattened.
    let mut third = record.clone();
    third.epoch = 3;
    store.write_record(&third).expect("write epoch 3");
    assert!(matches!(
        store_refusal(&store.history(NS).expect_err("gap at epoch 2")),
        ScopeKeyStoreError::RecordCorrupt { .. }
    ));
    std::fs::remove_file(store.record_path(NS, 3)).expect("remove epoch 3");
    assert_eq!(store.load_current(NS).expect("healed"), Some(record));
}

#[test]
fn open_content_bound_opens_scope_row_from_the_key_dir_8278() {
    // The production funnel: `open_content_bound` resolves the agent KEK and
    // the file store from the (test-isolated) default key directory.
    let agent = "scope-bound-funnel-8278";
    let kp = crate::encryption::get_or_create_keypair(agent).expect("keypair");
    let key_dir = crate::encryption::keypair_persist_dir().expect("key dir");
    let store = FileScopeKeyStore::new(key_dir);
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
    store.write_record(&record).expect("write record");
    let sealed = seal_scoped("bound funnel", &key, row("mem-f", &namespace)).expect("seal");
    assert_eq!(
        crate::encryption::open_content_bound(&sealed, agent, row("mem-f", &namespace))
            .expect("bound open"),
        "bound funnel"
    );
    let err = crate::encryption::open_content_bound(&sealed, agent, row("mem-g", &namespace))
        .expect_err("another row id");
    assert!(matches!(
        scope_envelope_error(&err),
        Some(ScopeEnvelopeError::Authentication)
    ));
    std::fs::remove_file(store.record_path(&namespace, 1)).expect("clean up TEST record");
}
