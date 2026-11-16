//! PR 9390 L1 — the claimed-identifier field of a forensic row: escaped,
//! one line, bounded, cut on an escape boundary, linear in its input.

use super::{FORENSIC_CLAIMED_CUT_MARKER, FORENSIC_IDENT_MAX_LEN, escape_claimed_ident};

/// Table: (claim, exact escaped form).
const ESCAPES_9390: &[(&str, &str)] = &[
    ("bob", "bob"),
    ("bob\n", "bob\\n"),
    ("bob\u{7}x", "bob\\u{7}x"),
    ("a\tb\rc", "a\\tb\\rc"),
    ("q\"uote", "q\\\"uote"),
    ("back\\slash", "back\\\\slash"),
    ("é", "\\u{e9}"),
    ("\u{202e}rtl", "\\u{202e}rtl"),
    ("", ""),
];

#[test]
fn escape_claimed_ident_table_9390() {
    for (claim, want) in ESCAPES_9390 {
        let got = escape_claimed_ident(claim);
        assert_eq!(&got, want, "claim {claim:?}");
        assert!(
            got.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
            "{got:?}"
        );
    }
}

#[test]
fn escape_claimed_ident_is_bounded_and_linear_9390() {
    const BIG: usize = 100_000;
    for unit in ["z", "\n", "é", "\u{10ffff}"] {
        let claim = unit.repeat(BIG);
        let started = std::time::Instant::now();
        let got = escape_claimed_ident(&claim);
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(2),
            "{unit:?} took {took:?}"
        );
        assert!(
            got.len() <= FORENSIC_IDENT_MAX_LEN,
            "{unit:?}: {}",
            got.len()
        );
        assert!(
            got.ends_with(FORENSIC_CLAIMED_CUT_MARKER),
            "{unit:?} is cut"
        );
        // The kept prefix is whole escapes of `unit`, never a split one.
        let kept = &got[..got.len() - FORENSIC_CLAIMED_CUT_MARKER.len()];
        let piece = escape_claimed_ident(unit);
        assert_eq!(
            kept.len() % piece.len(),
            0,
            "{unit:?} cut mid-escape: {kept:?}"
        );
        assert!(kept.split(piece.as_str()).all(str::is_empty), "{unit:?}");
    }
}

#[test]
fn escape_claimed_ident_at_the_limit_is_not_cut_9390() {
    let exact = "y".repeat(FORENSIC_IDENT_MAX_LEN);
    assert_eq!(escape_claimed_ident(&exact), exact);
    let over = "y".repeat(FORENSIC_IDENT_MAX_LEN + 1);
    let got = escape_claimed_ident(&over);
    assert_eq!(got.len(), FORENSIC_IDENT_MAX_LEN);
    assert!(got.ends_with(FORENSIC_CLAIMED_CUT_MARKER));
}
