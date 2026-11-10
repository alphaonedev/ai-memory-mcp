//! #8674: load-robust clock ratio for every operator-log scanner entry.
//!
//! The op-count tests in `scan_work_tests` see only charged work; this guard sees
//! any work, charged or not. The 100K and 1M inputs are timed interleaved, so a
//! load spike hits both sizes alike, and the minimum of each size is compared:
//! linear work measures about x10.4 and a quadratic scan about x30.
//! A ratio in the grey zone between them gets more pairs, so load noise drops out.

use std::time::{Duration, Instant};

const SMALL_BYTES: usize = 100_000;
const LARGE_BYTES: usize = 1_000_000;
/// Base interleaved pairs; each pair times one small and one large input.
const ROUNDS: usize = 5;
/// `min(1M) / min(100K)` stays below this: linear work measures x10.4, a quadratic scan x30.
const RATIO_LIMIT: u32 = 20;
/// Hundredths of a ratio at or above which more pairs are measured: well above linear x10.4,
/// well below quadratic x30, so only load noise sits here and more samples lower it.
const GREY_ZONE_HUNDREDTHS: u128 = 1_200;
/// Pair cap for that resampling; a quadratic scan stays near x30 however often it is timed.
const MAX_PAIRS: usize = 12;
const SHAPES: &[(&str, &str)] = &[
    ("userinfo", "http://u@a)"),
    ("credential lines", "password=private\n"),
];

/// Integer hundredths of `large / small`.
fn ratio_hundredths(small: Duration, large: Duration) -> u128 {
    large.as_nanos().saturating_mul(100) / small.as_nanos().max(1)
}

fn time_pair(inputs: &[String; 2], fastest: &mut [Duration; 2], scan: &impl Fn(&str) -> String) {
    for (input, best) in inputs.iter().zip(fastest.iter_mut()) {
        let started = Instant::now();
        let masked = std::hint::black_box(scan(std::hint::black_box(input)));
        *best = (*best).min(started.elapsed());
        drop(masked);
    }
}

fn assert_scanner_ratio(name: &str, scan: impl Fn(&str) -> String) {
    for (shape, piece) in SHAPES {
        let inputs = [SMALL_BYTES, LARGE_BYTES].map(|bytes| piece.repeat(bytes / piece.len()));
        let mut fastest = [Duration::MAX; 2];
        let mut pairs = 0;
        while pairs < ROUNDS
            || (pairs < MAX_PAIRS
                && ratio_hundredths(fastest[0], fastest[1]) >= GREY_ZONE_HUNDREDTHS)
        {
            time_pair(&inputs, &mut fastest, &scan);
            pairs += 1;
        }
        let [small, large] = fastest;
        let hundredths = ratio_hundredths(small, large);
        println!(
            "#8674 timing {name} [{shape}] min100K={small:?} min1M={large:?} ratio={}.{:02} \
             pairs={pairs}",
            hundredths / 100,
            hundredths % 100
        );
        assert!(
            large < small.saturating_mul(RATIO_LIMIT),
            "#8674 {name} [{shape}]: min(1M) {large:?} is not below {RATIO_LIMIT} x min(100K) \
             {small:?} after {pairs} pairs; the scanner does superlinear work"
        );
    }
}

#[test]
fn connection_option_scanner_time_is_linear_8674() {
    assert_scanner_ratio(
        "redact_connection_options",
        super::redact_connection_options,
    );
}

#[test]
fn bare_target_scanner_time_is_linear_8674() {
    assert_scanner_ratio("redact_bare_targets", super::redact_bare_targets);
}

#[test]
fn url_userinfo_scanner_time_is_linear_8674() {
    assert_scanner_ratio("url userinfo scanner", super::url_userinfo_scanner_8674);
}

#[test]
fn operator_url_scanner_time_is_linear_8674() {
    assert_scanner_ratio("map_urls_in_message", |msg| {
        super::map_urls_in_message(msg, str::to_owned)
    });
}
