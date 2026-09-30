// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4074 — the hex decoders refuse non-ASCII input without panicking.

use super::*;

/// #4074 — a non-ASCII value whose BYTE length is even must be refused
/// with `Err`, never panic by slicing inside a UTF-8 code point. The
/// signed-`+` shape `u8::from_str_radix` accepts is not hex either.
#[test]
fn validate_hmac_secret_hex_rejects_non_ascii_without_panic_4074() {
    for bad in [
        "\u{1F600}",
        "a\u{20AC}",
        "\u{e9}\u{e9}",
        "dead\u{1F600}beef",
        "abc",
        "+f+f",
        "0x",
    ] {
        let got = std::panic::catch_unwind(|| validate_hmac_secret_hex(Some(bad)));
        let res = got.unwrap_or_else(|_| panic!("#4074: validator panicked on {bad:?}"));
        assert!(res.is_err(), "#4074: {bad:?} must be refused");
        assert!(hex_decode(bad).is_none(), "#4074: {bad:?} must not decode");
    }
    assert_eq!(hex_decode("DeAdBeEf"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(hex_decode(""), Some(Vec::new()));
    assert!(validate_hmac_secret_hex(Some(&"0f".repeat(32))).is_ok());
}

/// #4074 — the runtime signer shares `hex_decode`; a non-ASCII key (a
/// replicated `secret_hash` is peer-supplied on Postgres) must take the
/// documented raw-bytes fallback, not unwind the dispatch worker.
#[test]
fn hmac_sha256_hex_non_ascii_key_does_not_panic_4074() {
    let sig = std::panic::catch_unwind(|| hmac_sha256_hex("\u{1F600}", "hello"))
        .unwrap_or_else(|_| panic!("#4074: hmac_sha256_hex panicked on a non-ASCII key"));
    assert_eq!(sig.len(), 64);
}
