//! #8674: every scanner on the operator log path is linear by construction.
//! The thread-local counter in `masking_cost_tests` is charged with the bytes
//! each search examines, so host load and parallel tests cannot move a count.

use super::masking_cost_tests::{reset_visited, total_visited};

/// Input sizes in bytes; each is `GROWTH` times the previous one.
const SIZES: [usize; 3] = [10_000, 100_000, 1_000_000];
const GROWTH: usize = 10;
/// Work at `GROWTH` times the input stays within this multiple of the smaller
/// work: x10 plus the rounding of whole repeated pieces. A rescan gives x100.
const LINEAR_WORK_RATIO_LIMIT: usize = 11;
/// No scanner charges more than this many examined bytes per input byte. The
/// largest honest charge is a key normalized once and searched for each of the
/// 20 contained credential nouns: about 25 per byte in the option scanner and 30
/// for the composed operator masker, which also runs the bare-target and URL passes.
const MAX_WORK_PER_BYTE: usize = 32;

/// `(label, prefix, repeated piece, suffix)`: the adversarial shapes of #8674.
const SHAPES: &[(&str, &str, &str, &str)] = &[
    ("userinfo", "", "http://u@a)", ""),
    ("user:pass", "", "http://u:p@a)", ""),
    ("unclosed paren", "", "(http://u@a/p(", ""),
    ("quote", "", "http://u@a'", ""),
    ("angle", "", "http://u@a>", ""),
    ("port", "", "http://u@a:80)", ""),
    ("nested schemes", "", "http://a://b@c://", ""),
    ("whitespace-free authority", "https://", "a=1:", ""),
    ("colon authority", "https://", ":", ""),
    ("ambiguous options", "https://user:secret ", "limit=10 ", ""),
    ("credential lines", "", "password=private\n", ""),
    ("quoted credential", "", "token: 'a\\'b' ", ""),
    ("quoted keys", "", "'k'=\"v\":", ""),
    ("bare targets", "", "u:p@h x ", ""),
    ("bare target lines", "", "u:p@h x\n", ""),
    ("plain words", "", "word ", ""),
    ("long key", "", "a", "=x"),
    ("multibyte", "", "\u{3bb}://\u{1f980}@\u{e9}:\u{fc} ", ""),
];

/// Bytes charged to the counter for one call of `scan` on `input`.
fn work(scan: fn(&str) -> String, input: &str) -> usize {
    reset_visited();
    std::hint::black_box(scan(std::hint::black_box(input)));
    total_visited()
}

fn assert_scanner_linear(name: &str, scan: fn(&str) -> String) {
    for &(shape, prefix, piece, suffix) in SHAPES {
        let mut previous: Option<usize> = None;
        for bytes in SIZES {
            let input = format!(
                "{prefix}{}{suffix}",
                piece.repeat(bytes.div_ceil(piece.len()))
            );
            let spent = work(scan, &input);
            println!(
                "#8674 work {name} [{shape}] bytes={} work={spent}",
                input.len()
            );
            assert!(
                spent > 0,
                "#8674 {name} [{shape}]: the work counter must observe the scan"
            );
            assert!(
                spent <= input.len() * MAX_WORK_PER_BYTE,
                "#8674 {name} [{shape}]: {spent} examined bytes exceed \
                 {MAX_WORK_PER_BYTE} per input byte at {} bytes",
                input.len()
            );
            if let Some(smaller) = previous {
                assert!(
                    spent <= smaller * LINEAR_WORK_RATIO_LIMIT,
                    "#8674 {name} [{shape}]: x{GROWTH} input grew work beyond \
                     x{LINEAR_WORK_RATIO_LIMIT}: {smaller} -> {spent}"
                );
            }
            previous = Some(spent);
        }
    }
}

#[test]
fn credential_option_scan_work_is_linear_8674() {
    assert_scanner_linear(
        "redact_connection_options",
        super::redact_connection_options,
    );
}

#[test]
fn bare_target_scan_work_is_linear_8674() {
    assert_scanner_linear("redact_bare_targets", super::redact_bare_targets);
}

#[test]
fn url_password_scan_work_is_linear_8674() {
    assert_scanner_linear("url userinfo scanner", super::url_userinfo_scanner_8674);
}

#[test]
fn operator_url_scan_work_is_linear_8674() {
    assert_scanner_linear("map_urls_in_message", |msg| {
        super::map_urls_in_message(msg, str::to_owned)
    });
}

/// The bounds above are a proof only if every byte a scanner reads is charged.
#[test]
fn work_counter_observes_every_examined_byte_8674() {
    const TAIL: usize = 10_000;
    const URL_TAIL: usize = super::url_scan::MAX_OPERATOR_URL_RUN_BYTES / 2;
    // Below the cap, the authority loop reads the whole whitespace-free tail
    // before it ends the run at ')'.
    let url = format!("http://u@a){}", "x".repeat(URL_TAIL));
    reset_visited();
    let run = super::url_scan::next_url_run(&url);
    assert!(
        run.is_some_and(|run| !run.capped && run.span.end < URL_TAIL),
        "#8674: run ends at ')'"
    );
    let charged = total_visited();
    assert!(
        charged >= URL_TAIL,
        "#8674 next_url_run: bytes read past the run end are charged: {charged}"
    );
    // The separator loop visits a key once and normalization visits it again.
    let key = format!("{}=x", "a".repeat(TAIL));
    let charged = work(super::redact_connection_options, &key);
    assert!(
        charged >= 2 * TAIL,
        "#8674 credential_key: normalization is charged: {charged}"
    );
    // Bare targets search the line for its end and its last '@', then each token.
    let words = "word ".repeat(TAIL);
    let charged = work(super::redact_bare_targets, &words);
    assert!(
        charged >= 3 * words.len(),
        "#8674 redact_bare_targets: own searches are charged: {charged}"
    );
    // The password masker searches the run again for its authority and userinfo.
    let userinfo = format!("http://{}@h", "a".repeat(URL_TAIL));
    let charged = work(super::url_userinfo_scanner_8674, &userinfo);
    assert!(
        charged >= 2 * URL_TAIL,
        "#8674 url userinfo scanner: its searches are charged: {charged}"
    );
}
