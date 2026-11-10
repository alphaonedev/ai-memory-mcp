//! #8674 / #8820: coarse wall-clock quadratic detector for every operator-log scanner entry.
//!
//! The proof of linearity is the deterministic op-count in `scan_work_tests`; it gives the same
//! verdict at any machine load. This guard only sees what a counter cannot, uncharged work, and
//! it cannot separate noise from a modest superlinear cost: a loaded macOS runner measured a
//! linear scanner at x24.4 (run 42845848659, load1 about 24). So the bound sits between that
//! noise and a quadratic scan. The 100K and 1M inputs are timed interleaved, so a load spike hits
//! both sizes alike, and the minimum of each size is compared: linear work measures x10.4 quiet
//! and up to x24.4 loaded, a quadratic scan about x100 (x10 input, x10 cost per byte).
//! A ratio in the grey zone above linear gets more pairs, so load noise drops out.
//! The scans run on one worker thread and each wait has an absolute bound, so a hang fails the
//! named test.

use std::sync::mpsc;
use std::time::{Duration, Instant};

const SMALL_BYTES: usize = 100_000;
const LARGE_BYTES: usize = 1_000_000;
/// Base interleaved pairs; each pair times one small and one large input.
const ROUNDS: usize = 5;
/// `min(1M) / min(100K)` stays below this. Linear work measured x10.4 quiet and at most x24.4
/// under load (#8820); a quadratic scan is about x100. 50 is twice the worst linear noise and
/// half the quadratic ratio; the exact linearity verdict is the op-count, not this ratio.
const QUADRATIC_RATIO_LIMIT: u32 = 50;
/// Hundredths of a ratio at or above which more pairs are measured: well above linear x10.4,
/// well below the limit, so only load noise sits here and more samples lower it.
const GREY_ZONE_HUNDREDTHS: u128 = 1_200;
/// Pair cap for that resampling; a quadratic scan stays near x100 however often it is timed.
const MAX_PAIRS: usize = 12;
/// One linear 1M scan takes about 1 s in a loaded debug build; a scan still running at this
/// bound is cut off and fails, instead of running until the CI shard watchdog kills it.
const MEASUREMENT_TIMEOUT: Duration = Duration::from_secs(30);
const SHAPES: &[(&str, &str)] = &[
    ("userinfo", "http://u@a)"),
    ("credential lines", "password=private\n"),
];

/// Integer hundredths of `large / small`.
fn ratio_hundredths(small: Duration, large: Duration) -> u128 {
    large.as_nanos().saturating_mul(100) / small.as_nanos().max(1)
}

/// One long-lived thread that times `scan` on the input index it is sent, so every measurement
/// runs on the same warm thread while the caller waits for it under `MEASUREMENT_TIMEOUT`.
struct Timer {
    lens: [usize; 2],
    requests: mpsc::Sender<usize>,
    replies: mpsc::Receiver<Duration>,
}

impl Timer {
    fn spawn(inputs: [String; 2], scan: fn(&str) -> String) -> Self {
        let lens = inputs.each_ref().map(String::len);
        let (requests, request_rx) = mpsc::channel::<usize>();
        let (reply_tx, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for index in request_rx {
                let started = Instant::now();
                let masked = std::hint::black_box(scan(std::hint::black_box(&inputs[index])));
                let elapsed = started.elapsed();
                drop(masked);
                if reply_tx.send(elapsed).is_err() {
                    break;
                }
            }
        });
        Self {
            lens,
            requests,
            replies,
        }
    }

    fn time(&self, name: &str, shape: &str, index: usize) -> Duration {
        let bytes = self.lens[index];
        let waited = Instant::now();
        let reply = match self.requests.send(index) {
            Ok(()) => self.replies.recv_timeout(MEASUREMENT_TIMEOUT),
            Err(_) => Err(mpsc::RecvTimeoutError::Disconnected),
        };
        match reply {
            Ok(elapsed) => elapsed,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                "#8674 {name} [{shape}]: one {bytes}-byte scan ran {:?} without finishing, over \
                 the {MEASUREMENT_TIMEOUT:?} bound; the scanner does superlinear work or hangs",
                waited.elapsed()
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("#8674 {name} [{shape}]: the {bytes}-byte scan thread panicked")
            }
        }
    }
}

fn assert_scanner_ratio(name: &str, scan: fn(&str) -> String) {
    for (shape, piece) in SHAPES {
        let inputs = [SMALL_BYTES, LARGE_BYTES].map(|bytes| piece.repeat(bytes / piece.len()));
        let timer = Timer::spawn(inputs, scan);
        let mut fastest = [Duration::MAX; 2];
        let mut pairs = 0;
        while pairs < ROUNDS
            || (pairs < MAX_PAIRS
                && ratio_hundredths(fastest[0], fastest[1]) >= GREY_ZONE_HUNDREDTHS)
        {
            for (index, best) in fastest.iter_mut().enumerate() {
                *best = (*best).min(timer.time(name, shape, index));
            }
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
            large < small.saturating_mul(QUADRATIC_RATIO_LIMIT),
            "#8674 {name} [{shape}]: min(1M) {large:?} is not below {QUADRATIC_RATIO_LIMIT} x min(100K) \
             {small:?} after {pairs} pairs; the scanner does quadratic work"
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
