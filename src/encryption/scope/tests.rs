// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — `0x05` scope envelope tests. TEST material only: every key
//! here is generated at random inside the test.

use super::*;
use crate::encryption::{
    crypto_erase_marker, envelope_is_crypto_erasable, get_or_create_keypair, open_content,
    open_content_bound, seal_content_per_record,
};
use sha2::{Digest as _, Sha256};

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
    RecordBinding::new(memory_id, namespace, 1)
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
    // Two seals of the same content share no random field: each one is
    // checked on its own, so a constant salt or nonce cannot hide behind a
    // differing neighbour.
    let again = seal_scoped(content, &key, row("mem-l", NS)).expect("seal");
    let fields = [
        ("wrap salt", OFF_SALT, OFF_WRAP_NONCE),
        ("wrap nonce", OFF_WRAP_NONCE, OFF_WRAPPED),
        ("wrapped DEK", OFF_WRAPPED, OFF_INNER_NONCE),
        ("inner nonce", OFF_INNER_NONCE, SCOPE_HEADER_LEN),
        ("inner ciphertext", SCOPE_HEADER_LEN, sealed.len()),
    ];
    for (name, start, end) in fields {
        assert_ne!(sealed[start..end], again[start..end], "{name} repeated");
    }
}

#[test]
fn scope_envelope_refuses_older_row_version_8278() {
    let key = test_key(NS, 1);
    let sealed = seal_scoped(
        "version 1 content",
        &key,
        RecordBinding::new("mem-v", NS, 1),
    )
    .expect("seal");
    assert_eq!(
        open_scoped(&sealed, &key, RecordBinding::new("mem-v", NS, 1)).expect("same version"),
        "version 1 content"
    );
    for newer in [2, i64::MAX] {
        let err = open_scoped(&sealed, &key, RecordBinding::new("mem-v", NS, newer))
            .expect_err("an older envelope under a newer row version must not open");
        assert_eq!(refusal(&err), ScopeEnvelopeError::Authentication);
    }
}

const KAT_NS: &str = "test/kat-8278";
const KAT_MEMORY_ID: &str = "mem-kat";
const KAT_EPOCH: u32 = 3;
const KAT_ROW_VERSION: i64 = 7;
const KAT_CONTENT: &str = "known answer #8278";
/// Expected values, computed independently of this crate (Python
/// `cryptography`: HKDF-SHA256 and ChaCha20-Poly1305) from the same inputs.
const KAT_WRAP_AAD: &str = "01054c47463e6b7ed21881e2861ff46b04b600000003000000076d656d2d6b61740000000d746573742f6b61742d383237380000000000000007";
const KAT_CONTENT_AAD: &str = "02054c47463e6b7ed21881e2861ff46b04b600000003000000076d656d2d6b61740000000d746573742f6b61742d383237380000000000000007";
const KAT_OKM: &str = "4646030666175724ba4a7341744114dc6544487cf9663060a7c7994b2023d413";
const KAT_ENVELOPE: &str = "054c47463e6b7ed21881e2861ff46b04b600000003e0cb9169fff94df3a7d30c3f8ef1f53cad28efb547f47f4211997cf553b646cc498d4dac5e94d2d1133c16fd19402f9c614c349f6a8bdc13497d2d258ae7f25040e73881ee6cbd91d5e55a103ffce1c4627aa7919b7ae3550813d939d3080695a77d03335b5dcbc6a0fd901e2e17657a722f0fa7642526d9fc9f";

/// A deterministic KAT input: the first `N` bytes of SHA-256 of a label.
fn kat_draw<const N: usize>(name: &str) -> [u8; N] {
    let digest = Sha256::digest(format!("kat-8278/{name}").as_bytes());
    std::array::from_fn(|i| digest[i])
}

#[test]
fn scope_envelope_known_answer_vector_8278() {
    let key_ref = ScopeKeyRef {
        key_id: ScopeKeyId(kat_draw("key-id")),
        epoch: KAT_EPOCH,
    };
    let key = ScopeKey::from_parts(KAT_NS, key_ref, kat_draw("scope-key"));
    let material = SealMaterial {
        salt: kat_draw("salt"),
        wrap_nonce: kat_draw("wrap-nonce"),
        inner_nonce: kat_draw("inner-nonce"),
        dek: kat_draw("dek"),
    };
    let binding = RecordBinding::new(KAT_MEMORY_ID, KAT_NS, KAT_ROW_VERSION);

    let wrap_aad = binding_aad(AAD_ROLE_DEK_WRAP, key_ref, binding).expect("wrap aad");
    let content_aad = binding_aad(AAD_ROLE_CONTENT, key_ref, binding).expect("content aad");
    assert_eq!(hex::encode(&wrap_aad), KAT_WRAP_AAD);
    assert_eq!(hex::encode(&content_aad), KAT_CONTENT_AAD);
    let okm = derive_wrap_key(key.secret_bytes(), &material.salt, key_ref).expect("okm");
    assert_eq!(hex::encode(okm.as_slice()), KAT_OKM);
    let sealed = seal_with_material(KAT_CONTENT, &key, binding, &material).expect("seal");
    assert_eq!(hex::encode(&sealed), KAT_ENVELOPE);
    assert_eq!(
        open_scoped(&sealed, &key, binding).expect("open"),
        KAT_CONTENT
    );

    // Flipping either role byte changes the vector: the stored wrapped DEK
    // and inner ciphertext do not verify under the other role, and sealing
    // under it gives different bytes.
    let wrapped = &sealed[OFF_WRAPPED..OFF_INNER_NONCE];
    let inner = &sealed[SCOPE_HEADER_LEN..];
    let cases = [
        (
            &okm,
            &material.wrap_nonce,
            &wrap_aad,
            wrapped,
            &material.dek[..],
        ),
        (
            Key::from_slice(&material.dek),
            &material.inner_nonce,
            &content_aad,
            inner,
            KAT_CONTENT.as_bytes(),
        ),
    ];
    for (cipher_key, nonce, aad, stored, plaintext) in cases {
        let mut flipped = aad.clone();
        flipped[0] = if flipped[0] == AAD_ROLE_DEK_WRAP {
            AAD_ROLE_CONTENT
        } else {
            AAD_ROLE_DEK_WRAP
        };
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce = Nonce::from_slice(nonce);
        assert!(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: stored,
                        aad: &flipped,
                    },
                )
                .is_err(),
            "stored ciphertext verifies under the flipped role"
        );
        let resealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &flipped,
                },
            )
            .expect("encrypt");
        assert_ne!(
            resealed.as_slice(),
            stored,
            "flipped role gives the same vector"
        );
    }
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
    let future = SCOPE_ENVELOPE_VERSION.wrapping_add(1);
    sealed[0] = future;
    let err = parse_scope_header(&sealed).expect_err("the next version is not a scope envelope");
    assert_eq!(
        refusal(&err),
        ScopeEnvelopeError::WrongVersion { got: future }
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
