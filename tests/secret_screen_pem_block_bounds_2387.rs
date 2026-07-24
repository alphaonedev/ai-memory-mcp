// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2387 — `redact_pem_blocks` per-block span bounding. Pre-fix the PEM
//! redaction scanned for the SECOND `PRIVATE KEY-----` occurrence after ANY
//! `-----BEGIN` across the WHOLE remainder, so (a) a certificate followed by
//! a private key folded into ONE redacted span (the cert + intervening prose
//! wiped), and (b) a non-key `BEGIN` block appearing AFTER a key block hit
//! the no-footer fallback and wiped the ENTIRE remainder including
//! non-secret prose. Both shapes are funnel-FORCED on the
//! federation-receive / import redact path (`redact_for_storage` — `refuse`
//! degrades to `redact` there), so the over-redaction destroyed non-secret
//! durable content and produced durable replica divergence (HIGH
//! data-integrity). The fix bounds every redacted span to its OWN
//! `BEGIN…END` block: only private-key blocks are masked; non-key PEM
//! blocks and all surrounding prose survive byte-for-byte, and a truncated
//! key block (no footer) is masked only up to the next `-----BEGIN`.

use ai_memory::secret_screen::{REDACTION_PLACEHOLDER, ScreenOutcome, screen};

const KEY_BODY: &str = "MIIEkeybytesAAAABBBBCCCC";
const CERT_BODY: &str = "MIIBcertpayloadDDDDEEEE";
const CERT_BLOCK_PREFIX: &str = "-----BEGIN CERTIFICATE-----";
const CERT_BLOCK_SUFFIX: &str = "-----END CERTIFICATE-----";

fn key_block() -> String {
    format!("-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----")
}

fn cert_block() -> String {
    format!("{CERT_BLOCK_PREFIX}\n{CERT_BODY}\n{CERT_BLOCK_SUFFIX}")
}

fn redacted_of(content: &str) -> String {
    match screen(content) {
        ScreenOutcome::Clean => panic!("expected a Hit for content carrying a private key"),
        ScreenOutcome::Hit { redacted, .. } => redacted,
    }
}

/// The exact #2387 tail-wipe shape: [private key block] + [prose] +
/// [non-key BEGIN CERTIFICATE block] + [more prose]. Only the private-key
/// bytes may be masked; the prose and the certificate must survive.
#[test]
fn key_then_prose_then_cert_then_prose_masks_only_the_key_2387() {
    let content = format!(
        "{}\nprose-between-blocks stays\n{}\ntrailing prose also stays",
        key_block(),
        cert_block()
    );
    let r = redacted_of(&content);
    assert_eq!(
        r.matches(REDACTION_PLACEHOLDER).count(),
        1,
        "exactly the one key block is masked: {r}"
    );
    assert!(!r.contains(KEY_BODY), "key bytes must be gone: {r}");
    assert!(
        r.contains("prose-between-blocks stays"),
        "prose between the key and the cert must survive: {r}"
    );
    assert!(
        r.contains("trailing prose also stays"),
        "prose after the cert must survive (pre-fix the whole remainder was wiped): {r}"
    );
    assert!(
        r.contains(CERT_BLOCK_PREFIX) && r.contains(CERT_BODY) && r.contains(CERT_BLOCK_SUFFIX),
        "the non-key certificate block must survive intact: {r}"
    );
}

/// The #2387 fold shape: a certificate BEFORE a private key. Pre-fix the
/// scan treated the key's header/footer as the cert block's first/second
/// END markers and redacted from the cert's `BEGIN` through the key's
/// footer — one folded span wiping the cert + the prose between them.
#[test]
fn cert_then_key_do_not_fold_into_one_span_2387() {
    let content = format!(
        "leading prose\n{}\nmiddle prose survives\n{}\ntail prose",
        cert_block(),
        key_block()
    );
    let r = redacted_of(&content);
    assert_eq!(
        r.matches(REDACTION_PLACEHOLDER).count(),
        1,
        "exactly the one key block is masked: {r}"
    );
    assert!(!r.contains(KEY_BODY), "key bytes must be gone: {r}");
    assert!(
        r.contains(CERT_BLOCK_PREFIX) && r.contains(CERT_BODY) && r.contains(CERT_BLOCK_SUFFIX),
        "the certificate must NOT be folded into the key's span: {r}"
    );
    assert!(
        r.contains("leading prose")
            && r.contains("middle prose survives")
            && r.contains("tail prose"),
        "all prose must survive: {r}"
    );
}

/// A truncated key block (header, no footer) is masked only up to the next
/// `-----BEGIN` — it can never swallow a later block or the tail.
#[test]
fn truncated_key_block_never_swallows_a_later_block_2387() {
    let content = format!(
        "-----BEGIN EC PRIVATE KEY-----\n{KEY_BODY}\n{}\nafter-cert prose",
        cert_block()
    );
    let r = redacted_of(&content);
    assert!(
        !r.contains(KEY_BODY),
        "truncated key bytes must be gone: {r}"
    );
    assert!(
        r.contains(CERT_BLOCK_PREFIX) && r.contains(CERT_BODY) && r.contains(CERT_BLOCK_SUFFIX),
        "the certificate after a truncated key must survive: {r}"
    );
    assert!(
        r.contains("after-cert prose"),
        "the tail must survive the truncated-paste fallback: {r}"
    );
}
