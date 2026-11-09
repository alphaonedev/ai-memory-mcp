//! #8674: exact output and real elapsed cost for the complete operator masker.

use std::time::{Duration, Instant};

const SMALL_BYTES: usize = 100_000;
const DOUBLE_BYTES: usize = SMALL_BYTES * 2;
const LARGE_BYTES: usize = 1_000_000;
/// Gross backstops only: at least 10x the measured debug cost, so host load
/// cannot trip them while the old quadratic (about 20 s at 100K) still does.
const GROSS_SMALL_CEILING: Duration = Duration::from_millis(2_500);
const GROSS_LARGE_CEILING: Duration = Duration::from_secs(25);
const SAMPLES: usize = 3;
/// Primary timing invariant: time(2N) / time(N) stays below this; a quadratic gives about 4.
const DOUBLING_LIMIT: u32 = 3;
/// Primary op-count invariant: scanner work at 2N stays below this multiple of work at N.
const WORK_DOUBLING_NUMERATOR: usize = 5;
const WORK_DOUBLING_DENOMINATOR: usize = 2;
const SHAPES: &[(&str, &str, &str)] = &[
    ("userinfo", "http://u@a.io)", "http://****@a.io)"),
    ("password", "http://u:p@a.io)", "http://****@a.io)"),
    ("plain", "http://a.io)", "http://a.io)"),
    ("quote", "http://u@a.io'", "http://****@a.io'"),
    ("paren", "http://user@b.io)", "http://****@b.io)"),
    ("angle", "http://u@a.io>", "http://****@a.io>"),
    ("port", "http://u@a.io:80)", "http://****@a.io:80)"),
];

/// Minimum elapsed time over `samples` runs; every run asserts the exact output.
/// The only absolute bound here is the gross backstop, never a tight ceiling.
fn measure(
    label: &str,
    piece: &str,
    expected: &str,
    bytes: usize,
    samples: usize,
    gross: Duration,
) -> Duration {
    let count = bytes.div_ceil(piece.len());
    let input = piece.repeat(count);
    let expected = expected.repeat(count);
    let elapsed = (0..samples)
        .map(|_| {
            let started = Instant::now();
            let output = super::map_urls_in_message(std::hint::black_box(&input), str::to_owned);
            let elapsed = started.elapsed();
            assert!(
                elapsed < gross,
                "#8674 {label}: bytes={bytes} elapsed={elapsed:?} gross backstop={gross:?}"
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

/// Scanner bytes examined for one run, from the existing test-only counter.
fn work(piece: &str, bytes: usize) -> usize {
    let input = piece.repeat(bytes.div_ceil(piece.len()));
    super::masking_cost_tests::reset_visited();
    std::hint::black_box(super::map_urls_in_message(
        std::hint::black_box(&input),
        str::to_owned,
    ));
    super::masking_cost_tests::total_visited()
}

#[test]
fn whitespace_free_url_runs_are_linear_8674() {
    for &(label, input, expected) in SHAPES {
        let small = measure(
            label,
            input,
            expected,
            SMALL_BYTES,
            SAMPLES,
            GROSS_SMALL_CEILING,
        );
        let double = measure(
            label,
            input,
            expected,
            DOUBLE_BYTES,
            SAMPLES,
            GROSS_SMALL_CEILING,
        );
        println!("#8674 {label}: doubling ratio {double:?} / {small:?}");
        assert!(
            double < small * DOUBLING_LIMIT,
            "#8674 {label}: x2 cost must stay below x{DOUBLING_LIMIT}: {small:?} -> {double:?}"
        );
        measure(label, input, expected, LARGE_BYTES, 1, GROSS_LARGE_CEILING);
    }
}

#[test]
fn whitespace_free_url_run_work_is_linear_8674() {
    for &(label, input, _) in SHAPES {
        let small = work(input, SMALL_BYTES);
        let double = work(input, DOUBLE_BYTES);
        println!("#8674 {label}: scanner work {small} -> {double}");
        assert!(
            small > 0,
            "#8674 {label}: the work counter must observe the scan"
        );
        assert!(
            double * WORK_DOUBLING_DENOMINATOR < small * WORK_DOUBLING_NUMERATOR,
            "#8674 {label}: doubling the input caused superlinear scanner work: {small} -> {double}"
        );
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
