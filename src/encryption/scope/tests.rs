// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — `0x05` scope envelope tests. TEST material only: every key
//! here is generated at random inside the test.

use super::*;
use crate::encryption::{
    crypto_erase_marker, envelope_is_crypto_erasable, get_or_create_keypair, open_content,
    open_content_bound, seal_content_per_record,
};

const NS: &str = "test/e2e-8278";

fn test_key(namespace: &str, epoch: u32) -> ScopeKey {
    ScopeKey::generate(
        namespace,
        ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch,
        },
    )
}

fn row<'a>(memory_id: &'a str, namespace: &'a str) -> RecordBinding<'a> {
    RecordBinding {
        memory_id,
        namespace,
    }
}

fn refusal(err: &anyhow::Error) -> ScopeEnvelopeError {
    scope_envelope_error(err)
        .cloned()
        .unwrap_or_else(|| panic!("expected a typed ScopeEnvelopeError, got: {err:#}"))
}

#[test]
fn scope_envelope_round_trips_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped("end-to-end content #8278", &key, row("mem-a", NS)).expect("seal");
    assert_eq!(sealed[0], SCOPE_ENVELOPE_VERSION);
    assert_eq!(
        open_scoped(&sealed, &key, row("mem-a", NS)).expect("open"),
        "end-to-end content #8278"
    );
}

#[test]
fn scope_envelope_layout_is_fixed_header_then_inner_ct_8278() {
    let key = test_key(NS, 7);
    let content = "layout";
    let sealed = seal_scoped(content, &key, row("mem-l", NS)).expect("seal");
    assert_eq!(SCOPE_HEADER_LEN, 1 + 16 + 4 + 16 + 12 + 48 + 12);
    assert_eq!(sealed.len(), SCOPE_HEADER_LEN + content.len() + TAG_LEN);
    let named = parse_scope_header(&sealed).expect("header");
    assert_eq!(named, key.key_ref());
    assert_eq!(&sealed[OFF_KEY_ID..OFF_EPOCH], &key.key_ref().key_id.0);
    assert_eq!(&sealed[OFF_EPOCH..OFF_SALT], &7u32.to_be_bytes());
    // Two seals of the same content never share salt, nonces or ciphertext.
    let again = seal_scoped(content, &key, row("mem-l", NS)).expect("seal");
    assert_ne!(sealed[OFF_SALT..], again[OFF_SALT..]);
}

#[test]
fn scope_envelope_refuses_ciphertext_swapped_between_rows_8278() {
    let key = test_key(NS, 1);
    let a = seal_scoped("row A secret", &key, row("mem-a", NS)).expect("seal a");
    let b = seal_scoped("row B secret", &key, row("mem-b", NS)).expect("seal b");
    // Row A's whole envelope presented as row B.
    let err = open_scoped(&a, &key, row("mem-b", NS)).expect_err("moved row must not open");
    assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
    // Row A's header (wrapped DEK) spliced onto row B's inner ciphertext.
    let mut spliced = a[..SCOPE_HEADER_LEN].to_vec();
    spliced.extend_from_slice(&b[SCOPE_HEADER_LEN..]);
    for id in ["mem-a", "mem-b"] {
        let err = open_scoped(&spliced, &key, row(id, NS)).expect_err("splice must not open");
        assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
    }
}

#[test]
fn scope_envelope_refuses_changed_namespace_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped("namespace bound", &key, row("mem-n", NS)).expect("seal");
    let err = open_scoped(&sealed, &key, row("mem-n", "test/other-8278")).expect_err("renamed");
    assert!(matches!(
        refusal(&err),
        ScopeEnvelopeError::NamespaceMismatch { .. }
    ));
    // The AEAD binding alone refuses it too (no pre-check in the way).
    let err = open_with_secret(&sealed, key.secret_bytes(), row("mem-n", "test/other-8278"))
        .expect_err("AAD binds the namespace");
    assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
    // Length-prefixing: moving bytes between memory id and namespace fails.
    let err = open_with_secret(&sealed, key.secret_bytes(), row("mem-ntest/", "e2e-8278"))
        .expect_err("length-prefixed binding");
    assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
}

#[test]
fn scope_envelope_refuses_changed_epoch_and_key_id_8278() {
    let key = test_key(NS, 3);
    let sealed = seal_scoped("epoch bound", &key, row("mem-e", NS)).expect("seal");
    let mut bumped = sealed.clone();
    bumped[OFF_EPOCH..OFF_SALT].copy_from_slice(&4u32.to_be_bytes());
    let err = open_scoped(&bumped, &key, row("mem-e", NS)).expect_err("epoch edited");
    assert!(matches!(
        refusal(&err),
        ScopeEnvelopeError::KeyMismatch { .. }
    ));
    let err = open_with_secret(&bumped, key.secret_bytes(), row("mem-e", NS))
        .expect_err("AAD + KDF bind the epoch");
    assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
    let mut renamed = sealed;
    renamed[OFF_KEY_ID] ^= 0x01;
    let err = open_with_secret(&renamed, key.secret_bytes(), row("mem-e", NS))
        .expect_err("AAD + KDF bind the key id");
    assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
}

#[test]
fn scope_envelope_refuses_every_single_bit_flip_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped("tamper evident", &key, row("mem-t", NS)).expect("seal");
    for i in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[i] ^= 0x40;
        assert!(
            open_scoped(&tampered, &key, row("mem-t", NS)).is_err(),
            "byte {i} flipped must not open"
        );
    }
}

#[test]
fn scope_envelope_wrong_key_refused_8278() {
    let key = test_key(NS, 1);
    let other = ScopeKey::generate(NS, key.key_ref());
    let sealed = seal_scoped("wrong key", &key, row("mem-w", NS)).expect("seal");
    let err = open_scoped(&sealed, &other, row("mem-w", NS)).expect_err("other secret");
    assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
}

#[test]
fn scope_seal_refuses_row_outside_key_namespace_8278() {
    let key = test_key(NS, 1);
    let err = seal_scoped("misfiled", &key, row("mem-x", "test/other-8278")).expect_err("refuse");
    assert!(matches!(
        refusal(&err),
        ScopeEnvelopeError::NamespaceMismatch { .. }
    ));
}

#[test]
fn scope_envelope_truncated_fails_closed_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped("", &key, row("mem-z", NS)).expect("seal empty content");
    assert_eq!(sealed.len(), SCOPE_ENVELOPE_MIN_LEN);
    assert_eq!(
        open_scoped(&sealed, &key, row("mem-z", NS)).expect("open"),
        ""
    );
    for len in [0, 1, SCOPE_HEADER_LEN, SCOPE_ENVELOPE_MIN_LEN - 1] {
        let err = open_scoped(&sealed[..len], &key, row("mem-z", NS)).expect_err("truncated");
        assert!(matches!(
            refusal(&err),
            ScopeEnvelopeError::Truncated { .. }
        ));
    }
}

#[test]
fn scope_envelope_unknown_version_fails_closed_8278() {
    let key = test_key(NS, 1);
    let mut sealed = seal_scoped("future", &key, row("mem-u", NS)).expect("seal");
    sealed[0] = 0x06;
    let err = parse_scope_header(&sealed).expect_err("0x06 is not a scope envelope");
    assert_eq!(
        refusal(&err),
        ScopeEnvelopeError::WrongVersion { got: 0x06 }
    );
    for open in [
        open_content(&sealed, "scope-unknown-version-8278"),
        open_content_bound(&sealed, "scope-unknown-version-8278", row("mem-u", NS)),
    ] {
        let err = open.expect_err("unknown version must fail closed");
        assert!(
            format!("{err:#}").contains("unknown envelope version"),
            "typed unknown-version refusal, got: {err:#}"
        );
    }
}

#[test]
fn open_content_refuses_unbound_scope_envelope_typed_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped("bound only", &key, row("mem-b", NS)).expect("seal");
    let err = open_content(&sealed, "scope-unbound-8278").expect_err("no binding, no open");
    assert_eq!(refusal(&err), ScopeEnvelopeError::BindingRequired);
}

#[test]
fn scope_envelope_is_crypto_erasable_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped("shred me", &key, row("mem-s", NS)).expect("seal");
    assert!(envelope_is_crypto_erasable(&sealed));
    let erased = crypto_erase_marker();
    let err = open_content_bound(&erased, "scope-erase-8278", row("mem-s", NS))
        .expect_err("erased stays erased");
    assert!(format!("{err:#}").contains("crypto-erased"), "{err:#}");
    // The scope key is still in hand, yet nothing of the record remains.
    assert!(open_scoped(&erased, &key, row("mem-s", NS)).is_err());
}

#[test]
fn per_record_0x03_rows_still_open_via_bound_path_8278() {
    let agent = "scope-regression-0x03-8278";
    let kp = get_or_create_keypair(agent).expect("keypair");
    let sealed = seal_content_per_record("0x03 regression", &kp.public).expect("seal");
    assert_eq!(
        open_content(&sealed, agent).expect("open"),
        "0x03 regression"
    );
    assert_eq!(
        open_content_bound(&sealed, agent, row("mem-r", NS)).expect("bound open"),
        "0x03 regression"
    );
}

#[test]
fn scope_key_zeroizes_and_redacts_8278() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ScopeKey>();
    let mut key = test_key(NS, 1);
    assert_ne!(key.secret_bytes(), &[0u8; SCOPE_KEY_LEN]);
    let rendered = format!("{key:?}");
    assert!(rendered.contains(crate::REDACTED_PLACEHOLDER));
    assert!(!rendered.contains(&hex::encode(key.secret_bytes())));
    key.zeroize();
    assert_eq!(key.secret_bytes(), &[0u8; SCOPE_KEY_LEN]);
    assert_eq!(key.namespace(), NS, "identity fields are not secret");
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
    #[test]
    fn scope_envelope_round_trips_random_lengths_8278(
        content in ".{0,2048}",
        memory_id in "[a-z0-9-]{1,40}",
        namespace in "[a-z0-9/_-]{1,64}",
        epoch in 1u32..u32::MAX,
        flip in proptest::prelude::any::<proptest::sample::Index>(),
    ) {
        let key = test_key(&namespace, epoch);
        let sealed = seal_scoped(&content, &key, row(&memory_id, &namespace)).expect("seal");
        proptest::prop_assert_eq!(sealed.len(), SCOPE_HEADER_LEN + content.len() + TAG_LEN);
        let opened = open_scoped(&sealed, &key, row(&memory_id, &namespace)).expect("open");
        proptest::prop_assert_eq!(&opened, &content);
        let mut tampered = sealed;
        let at = flip.index(tampered.len());
        tampered[at] ^= 0x01;
        proptest::prop_assert!(open_scoped(&tampered, &key, row(&memory_id, &namespace)).is_err());
    }
}
