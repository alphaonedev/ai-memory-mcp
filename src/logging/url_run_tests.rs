//! #8674: exact output and real elapsed cost for the complete operator masker.

use std::time::{Duration, Instant};

const SMALL_BYTES: usize = 100_000;
const DOUBLE_BYTES: usize = SMALL_BYTES * 2;
const LARGE_BYTES: usize = 1_000_000;
const SMALL_CEILING: Duration = Duration::from_millis(250);
const LARGE_CEILING: Duration = Duration::from_millis(2_500);
const SAMPLES: usize = 3;
const DOUBLING_LIMIT: u32 = 3;
const SHAPES: &[(&str, &str, &str)] = &[
    ("userinfo", "http://u@a.io)", "http://****@a.io)"),
    ("password", "http://u:p@a.io)", "http://****@a.io)"),
    ("plain", "http://a.io)", "http://a.io)"),
    ("quote", "http://u@a.io'", "http://****@a.io'"),
    ("paren", "http://user@b.io)", "http://****@b.io)"),
    ("angle", "http://u@a.io>", "http://****@a.io>"),
    ("port", "http://u@a.io:80)", "http://****@a.io:80)"),
];

fn measure(label: &str, piece: &str, expected: &str, bytes: usize) -> Duration {
    let count = bytes.div_ceil(piece.len());
    let input = piece.repeat(count);
    let expected = expected.repeat(count);
    let elapsed = (0..SAMPLES)
        .map(|_| {
            let started = Instant::now();
            let output = super::map_urls_in_message(std::hint::black_box(&input), str::to_owned);
            let elapsed = started.elapsed();
            let ceiling = if bytes == SMALL_BYTES {
                SMALL_CEILING
            } else {
                LARGE_CEILING
            };
            assert!(
                elapsed < ceiling,
                "#8674 {label}: bytes={bytes} elapsed={elapsed:?} ceiling={ceiling:?}"
            );
            assert_eq!(
                output, expected,
                "#8674 {label}: exact output at {bytes} bytes"
            );
            elapsed
        })
        .min()
        .expect("positive named sample count");
    println!("#8674 {label}: bytes={} minimum={elapsed:?}", input.len());
    elapsed
}

#[test]
fn whitespace_free_url_runs_are_linear_8674() {
    for &(label, input, expected) in SHAPES {
        let small = measure(label, input, expected, SMALL_BYTES);
        let double = measure(label, input, expected, DOUBLE_BYTES);
        assert!(
            double < small * DOUBLING_LIMIT,
            "#8674 {label}: x2 cost must stay below x3: {small:?} -> {double:?}"
        );
        measure(label, input, expected, LARGE_BYTES);
    }
}

#[test]
fn ended_url_does_not_own_later_credential_lines_8674() {
    const CASES: &[(&str, &str)] = &[
        (
            "https://db.invalid\npassword=private",
            "https://db.invalid\npassword=****",
        ),
        (
            "https://db.invalid\r\ntoken=private",
            "https://db.invalid\r\ntoken=****",
        ),
        (
            "https://db.invalid/path\npassword=private\nlimit=10",
            "https://db.invalid/path\npassword=****\nlimit=10",
        ),
        (
            "https://db.invalid\nhttps://password:private@other.invalid\npassword=private",
            "https://db.invalid\nhttps://****@other.invalid\npassword=****",
        ),
    ];
    for &(input, expected) in CASES {
        assert_eq!(
            super::map_urls_in_message(input, str::to_owned),
            expected,
            "#8674: ended URL ownership must reset"
        );
    }
}

#[test]
fn oversized_url_run_is_discarded_without_splitting_utf8_8674() {
    const LONG_CHARS: usize = 10_000;
    const TAIL: &str = "\nlimit=10";
    for prefix in ["https://", "https://u:", "https://u@", "https://h/path?"] {
        for repeated in ["x", "λ", "🦀"] {
            let input = format!("{prefix}{}{TAIL}", repeated.repeat(LONG_CHARS));
            assert_eq!(
                super::map_urls_in_message(&input, str::to_owned),
                format!("https://****{TAIL}"),
                "#8674: oversize run is wholly private and newline suffix survives"
            );
        }
    }
}
