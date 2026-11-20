//! #9599 — the secret screen must stay linear in its input.
//!
//! Invariant: no screened input up to the content cap (and beyond it, at
//! 128 KiB) costs more than `SCAN_COST_PER_BYTE_CEILING` examined bytes per
//! input byte plus a fixed floor, and doubling the input at most doubles the
//! cost (plus slack). The cost is the deterministic op count every detector
//! reports to [`super::scan_meter`]; a loose wall-clock ceiling backs it up
//! for the uninstrumented string building.
//!
//! Preservation: [`reference`] is a verbatim copy of the detectors as they
//! stood at the #9599 base (chain tip 6c67b17b). Every detector must report
//! exactly the same outcome (kinds AND redacted text) as that copy over a
//! generated corpus, so the linear rewrite never drops, narrows or skips a
//! detection (that would be fail-open).

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// The content cap the write path enforces.
const CONTENT_CAP_BYTES: usize = crate::models::MAX_CONTENT_SIZE;
/// A 100K+ input, past the cap (federation / import fields are screened too).
const LARGE_INPUT_BYTES: usize = 128 * 1024;
/// Half of [`LARGE_INPUT_BYTES`] for the doubling check.
const HALF_INPUT_BYTES: usize = LARGE_INPUT_BYTES / 2;
/// Linear ceiling: examined bytes per input byte for one full `screen` call.
/// The densest legitimate cost is one entropy confirmation (256 histogram
/// bins) per 3-byte `sk-` candidate (~86 per byte) plus one pass per
/// detector; 160 is that bound with headroom. A quadratic detector exceeds
/// it by orders of magnitude at the cap.
const SCAN_COST_PER_BYTE_CEILING: u64 = 160;
/// Fixed floor added to every ceiling (per-call constant work).
const SCAN_COST_FIXED_FLOOR: u64 = 4096;
/// Doubling check: `cost(2n) * DOUBLING_DEN <= cost(n) * DOUBLING_NUM + floor`
/// (a ratio of 2.25; a quadratic detector shows about 4).
const DOUBLING_NUM: u64 = 9;
const DOUBLING_DEN: u64 = 4;
/// Wall-clock backstop for one `screen` call on a debug build.
const WALL_CEILING: Duration = Duration::from_secs(10);
/// Generated preservation corpus size and per-case fragment cap.
const CORPUS_CASES: usize = 6000;
const CORPUS_MAX_FRAGMENTS: u64 = 24;
/// Deterministic corpus seed.
const CORPUS_SEED: u64 = 0x9599_5EC2_E75C_2EE1;
/// Mid-size shape length for the reference comparison (the reference is
/// quadratic, so it is compared at a size it finishes quickly).
const REFERENCE_SHAPE_BYTES: usize = 3000;

/// The worst-case repeating units, one or more per detector, plus mixed
/// and multi-byte shapes (char boundaries).
const SHAPE_UNITS: &[(&str, &str)] = &[
    ("github_pat_ repeated", "github_pat_"),
    ("ghp_ repeated", "ghp_"),
    ("sk- repeated", "sk-"),
    ("xai- repeated", "xai-"),
    ("Bearer repeated", "Bearer "),
    ("sk- low-entropy filler", "sk-aaaaaaaaaaaaaaaaaaaaaaa"),
    ("ghp_ low-entropy filler", "ghp_bbbbbbbbbbbbbbbbbbbbbbbbb"),
    ("AKIA non-key body", "AKIAa"),
    ("AKIA repeated", "AKIA"),
    ("eyJ repeated", "eyJ"),
    ("eyJ dotted segments", "eyJabcdefgh."),
    ("eyJ short dotted", "eyJ."),
    ("PEM begin repeated", "-----BEGIN"),
    ("PEM key header repeated", "-----BEGIN PRIVATE KEY-----"),
    ("PEM key marker repeated", "PRIVATE KEY-----"),
    ("mixed prefixes", "sk-ghp_xai-eyJAKIAagithub_pat_"),
    ("mixed with dots", "sk-.eyJ.ghp_.AKIAa.xai-."),
    ("token chars only", "aZ09-_+/.="),
    ("multibyte between prefixes", "sk-\u{e9}ghp_\u{65e5}\u{672c}eyJ\u{20ac}"),
    ("multibyte after long run", "sk-sk-sk-sk-sk-sk-sk-sk-sk-sk-\u{1d11e}"),
    ("multibyte only", "\u{e9}\u{65e5}\u{20ac}\u{1d11e}"),
];

/// `unit` repeated, truncated to at most `len` bytes on a char boundary.
fn repeat_to(unit: &str, len: usize) -> String {
    let mut s = unit.repeat(len / unit.len() + 1);
    let mut cut = len.min(s.len());
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s
}

/// Run one metered `screen` with `budget`; returns (cost, elapsed, outcome)
/// or `None` when the meter's budget panic fired.
fn metered_screen(input: &str, budget: u64) -> (u64, Duration, Option<ScreenOutcome>) {
    scan_meter::arm(budget);
    let started = Instant::now();
    let outcome = catch_unwind(AssertUnwindSafe(|| screen(input))).ok();
    let elapsed = started.elapsed();
    let cost = scan_meter::disarm();
    (cost, elapsed, outcome)
}

fn linear_ceiling(len: usize) -> u64 {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    len.saturating_mul(SCAN_COST_PER_BYTE_CEILING)
        .saturating_add(SCAN_COST_FIXED_FLOOR)
}

#[test]
fn screen_cost_is_linear_up_to_content_cap_9599() {
    let mut violations = Vec::new();
    for &(name, unit) in SHAPE_UNITS {
        for len in [CONTENT_CAP_BYTES, LARGE_INPUT_BYTES] {
            let input = repeat_to(unit, len);
            let ceiling = linear_ceiling(input.len());
            let (cost, elapsed, outcome) = metered_screen(&input, ceiling);
            if outcome.is_none() || cost > ceiling || elapsed > WALL_CEILING {
                violations.push(format!(
                    "{name} @ {} bytes: cost {cost} (ceiling {ceiling}), {elapsed:?} (wall ceiling \
                     {WALL_CEILING:?}), finished={}",
                    input.len(),
                    outcome.is_some()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "#9599 secret screen exceeded the linear bound:\n{}",
        violations.join("\n")
    );
}

#[test]
fn screen_cost_doubling_is_linear_9599() {
    let mut violations = Vec::new();
    for &(name, unit) in SHAPE_UNITS {
        let half = repeat_to(unit, HALF_INPUT_BYTES);
        let full = repeat_to(unit, LARGE_INPUT_BYTES);
        let (half_cost, _, half_out) = metered_screen(&half, linear_ceiling(half.len()));
        let (full_cost, _, full_out) = metered_screen(&full, linear_ceiling(full.len()));
        let bound = half_cost
            .saturating_mul(DOUBLING_NUM)
            .saturating_add(SCAN_COST_FIXED_FLOOR.saturating_mul(DOUBLING_DEN));
        if half_out.is_none()
            || full_out.is_none()
            || full_cost.saturating_mul(DOUBLING_DEN) > bound
        {
            violations.push(format!(
                "{name}: cost {half_cost} @ {} bytes -> {full_cost} @ {} bytes (finished {} / {})",
                half.len(),
                full.len(),
                half_out.is_some(),
                full_out.is_some()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "#9599 secret screen cost grows faster than linear when the input doubles:\n{}",
        violations.join("\n")
    );
}

/// xorshift64* — deterministic, dependency-free corpus generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        let idx = usize::try_from(self.below(items.len() as u64)).unwrap_or(0);
        items[idx]
    }

    /// `len` bytes drawn from `alphabet` (ASCII).
    fn run(&mut self, alphabet: &[u8], len: u64) -> String {
        (0..len)
            .map(|_| {
                let idx = usize::try_from(self.below(alphabet.len() as u64)).unwrap_or(0);
                char::from(alphabet[idx])
            })
            .collect()
    }
}

const HIGH_ENTROPY_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LOW_ENTROPY_ALPHABET: &[u8] = b"ab";

const FRAGMENTS: &[&str] = &[
    "github_pat_",
    "ghp_",
    "sk-",
    "xai-",
    "Bearer ",
    "AKIA",
    "eyJ",
    ".",
    " ",
    "\n",
    "-----BEGIN",
    " RSA PRIVATE KEY-----",
    "PRIVATE KEY-----",
    "-----END",
    "CERTIFICATE-----",
    "\u{e9}",
    "\u{65e5}\u{672c}",
    "\u{1d11e}",
    "=",
    "/",
    "+",
];

/// One generated case: a mix of detector prefixes, separators, multi-byte
/// text and high- / low-entropy token runs, so every detector both fires
/// and is near-missed.
fn generated_case(rng: &mut Rng) -> String {
    let mut s = String::new();
    let fragments = 1 + rng.below(CORPUS_MAX_FRAGMENTS);
    for _ in 0..fragments {
        match rng.below(8) {
            0 | 1 => s.push_str(rng.pick(FRAGMENTS)),
            2 => {
                let len = 4 + rng.below(36);
                s.push_str(&rng.run(HIGH_ENTROPY_ALPHABET, len));
            }
            3 => {
                let len = 1 + rng.below(60);
                s.push_str(&rng.run(LOW_ENTROPY_ALPHABET, len));
            }
            4 => {
                s.push_str("AKIA");
                let len = 12 + rng.below(8);
                s.push_str(&rng.run(UPPER_ALNUM, len));
            }
            5 => {
                s.push_str("eyJ");
                for seg in 0..(1 + rng.below(4)) {
                    if seg > 0 {
                        s.push('.');
                    }
                    let len = 5 + rng.below(8);
                    s.push_str(&rng.run(HIGH_ENTROPY_ALPHABET, len));
                }
            }
            6 => {
                s.push_str(rng.pick(&["sk-", "ghp_", "xai-", "Bearer ", "github_pat_"]));
                let len = 10 + rng.below(30);
                s.push_str(&rng.run(HIGH_ENTROPY_ALPHABET, len));
            }
            _ => {
                let len = 1 + rng.below(40);
                s.push_str(&"a".repeat(usize::try_from(len).unwrap_or(1)));
            }
        }
    }
    s
}

/// Shapes where a later candidate inside the SAME token run is a secret
/// although an earlier candidate of that run is not — a rewrite that skips
/// the rest of a run after one negative verdict misses them.
fn same_run_late_secret_cases() -> Vec<String> {
    let mut rng = Rng(CORPUS_SEED ^ 0x5A5A);
    let secret = rng.run(HIGH_ENTROPY_ALPHABET, 28);
    let jwt = format!(
        "eyJ{}.{}.{}",
        rng.run(HIGH_ENTROPY_ALPHABET, 12),
        rng.run(HIGH_ENTROPY_ALPHABET, 12),
        rng.run(HIGH_ENTROPY_ALPHABET, 12)
    );
    let filler = "a".repeat(200);
    vec![
        format!("sk-{filler}sk-{secret}"),
        format!("ghp_{filler}ghp_{secret}"),
        format!("xai-{filler}xai-{secret} tail"),
        format!("github_pat_{filler}github_pat_{secret}"),
        format!("eyJaaaaaaaa.bbbbbbbb.{jwt}"),
        format!("eyJaaaaaaaa.bbbbbbbb.cccccccc.{jwt} and more"),
        format!("AKIAa{filler}AKIA{}", rng.run(UPPER_ALNUM, 16)),
        format!("\u{e9}sk-{filler}sk-{secret}\u{65e5}"),
    ]
}

#[test]
fn screen_detections_match_reference_9599() {
    let mut rng = Rng(CORPUS_SEED);
    let mut cases: Vec<String> = (0..CORPUS_CASES).map(|_| generated_case(&mut rng)).collect();
    cases.extend(same_run_late_secret_cases());
    for &(_, unit) in SHAPE_UNITS {
        cases.push(repeat_to(unit, REFERENCE_SHAPE_BYTES));
    }
    let mut fired: Vec<&'static str> = Vec::new();
    for case in &cases {
        let expected = reference::screen(case);
        let actual = screen(case);
        assert_eq!(actual, expected, "#9599 detection drift on input {case:?}");
        if let ScreenOutcome::Hit { kinds, .. } = actual {
            fired.extend(kinds);
        }
    }
    // Break-it guard: the corpus must make every detector fire, or the
    // comparison above proves nothing for the detector that never did.
    for kind in [
        KIND_PEM_PRIVATE_KEY,
        KIND_AWS_ACCESS_KEY,
        KIND_GITHUB_TOKEN,
        KIND_OPENAI_KEY,
        KIND_XAI_KEY,
        KIND_JWT,
        KIND_BEARER_TOKEN,
    ] {
        assert!(fired.contains(&kind), "corpus never fired detector {kind}");
    }
}

#[test]
fn same_run_late_secrets_still_detected_9599() {
    for case in same_run_late_secret_cases() {
        let ScreenOutcome::Hit { redacted, .. } = screen(&case) else {
            panic!("#9599 late secret in a run was not detected: {case:?}");
        };
        assert!(
            redacted.contains(REDACTION_PLACEHOLDER),
            "#9599 late secret not redacted: {redacted:?}"
        );
    }
}

/// Verbatim copy of the detectors at the #9599 base (chain tip 6c67b17b),
/// metering removed. The preservation oracle; never called outside tests.
mod reference {
    use super::super::{
        AWS_AKIA_PREFIX, AWS_KEY_BODY_LEN, BEARER_PREFIX, GITHUB_FINEGRAINED_PREFIX,
        GITHUB_PAT_PREFIX, KIND_AWS_ACCESS_KEY, KIND_BEARER_TOKEN, KIND_GITHUB_TOKEN, KIND_JWT,
        KIND_OPENAI_KEY, KIND_PEM_PRIVATE_KEY, KIND_XAI_KEY, MIN_PREFIXED_TOKEN_LEN,
        MIN_TOKEN_ENTROPY_BITS, OPENAI_KEY_PREFIX, PEM_BEGIN_MARKER, PEM_PRIVATE_KEY_MARKER,
        REDACTION_PLACEHOLDER, ScreenOutcome, XAI_KEY_PREFIX,
    };

    pub(super) fn screen(content: &str) -> ScreenOutcome {
        let mut kinds: Vec<&'static str> = Vec::new();
        let mut redacted = content.to_string();
        if content.contains(PEM_BEGIN_MARKER) && content.contains(PEM_PRIVATE_KEY_MARKER) {
            kinds.push(KIND_PEM_PRIVATE_KEY);
            redacted = redact_pem_blocks(&redacted);
        }
        let prefix_detectors: [(&str, &'static str); 5] = [
            (GITHUB_FINEGRAINED_PREFIX, KIND_GITHUB_TOKEN),
            (GITHUB_PAT_PREFIX, KIND_GITHUB_TOKEN),
            (OPENAI_KEY_PREFIX, KIND_OPENAI_KEY),
            (XAI_KEY_PREFIX, KIND_XAI_KEY),
            (BEARER_PREFIX, KIND_BEARER_TOKEN),
        ];
        for (prefix, kind) in prefix_detectors {
            if let Some(redacted_after) =
                redact_prefixed_tokens(&redacted, prefix, kind, &mut kinds)
            {
                redacted = redacted_after;
            }
        }
        if let Some(after) = redact_aws_keys(&redacted, &mut kinds) {
            redacted = after;
        }
        if let Some(after) = redact_jwts(&redacted, &mut kinds) {
            redacted = after;
        }
        if kinds.is_empty() {
            ScreenOutcome::Clean
        } else {
            kinds.sort_unstable();
            kinds.dedup();
            ScreenOutcome::Hit { kinds, redacted }
        }
    }

    fn shannon_entropy_bits(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts = [0usize; 256];
        for b in s.bytes() {
            counts[b as usize] += 1;
        }
        let len = s.len() as f64;
        let mut h = 0.0;
        for &c in counts.iter() {
            if c > 0 {
                let p = c as f64 / len;
                h -= p * p.log2();
            }
        }
        h
    }

    fn is_token_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '.' | '=')
    }

    fn token_at(content: &str, start: usize) -> &str {
        let bytes = content.as_bytes();
        let mut end = start;
        while end < bytes.len() && is_token_char(bytes[end] as char) {
            end += 1;
        }
        &content[start..end]
    }

    fn redact_prefixed_tokens(
        content: &str,
        prefix: &str,
        kind: &'static str,
        kinds: &mut Vec<&'static str>,
    ) -> Option<String> {
        let mut out = String::with_capacity(content.len());
        let mut search_from = 0usize;
        let mut hit = false;
        while let Some(rel) = content[search_from..].find(prefix) {
            let pfx_start = search_from + rel;
            let token_start = pfx_start + prefix.len();
            let token = token_at(content, token_start);
            if token.len() >= MIN_PREFIXED_TOKEN_LEN
                && shannon_entropy_bits(token) >= MIN_TOKEN_ENTROPY_BITS
            {
                out.push_str(&content[search_from..pfx_start]);
                out.push_str(REDACTION_PLACEHOLDER);
                search_from = token_start + token.len();
                hit = true;
            } else {
                out.push_str(&content[search_from..token_start]);
                search_from = token_start;
            }
        }
        if hit {
            out.push_str(&content[search_from..]);
            kinds.push(kind);
            Some(out)
        } else {
            None
        }
    }

    fn redact_aws_keys(content: &str, kinds: &mut Vec<&'static str>) -> Option<String> {
        let mut out = String::with_capacity(content.len());
        let mut search_from = 0usize;
        let mut hit = false;
        while let Some(rel) = content[search_from..].find(AWS_AKIA_PREFIX) {
            let start = search_from + rel;
            let body_start = start + AWS_AKIA_PREFIX.len();
            let body = token_at(content, body_start);
            let is_key = body.len() >= AWS_KEY_BODY_LEN
                && body[..AWS_KEY_BODY_LEN]
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if is_key {
                out.push_str(&content[search_from..start]);
                out.push_str(REDACTION_PLACEHOLDER);
                search_from = body_start + AWS_KEY_BODY_LEN;
                hit = true;
            } else {
                out.push_str(&content[search_from..body_start]);
                search_from = body_start;
            }
        }
        if hit {
            out.push_str(&content[search_from..]);
            kinds.push(KIND_AWS_ACCESS_KEY);
            Some(out)
        } else {
            None
        }
    }

    fn looks_like_jwt(token: &str) -> bool {
        const JWT_HEADER_MARKER: &str = "eyJ";
        const MIN_SEG_LEN: usize = 8;
        if !token.starts_with(JWT_HEADER_MARKER) {
            return false;
        }
        let mut n = 0usize;
        for seg in token.split('.') {
            if seg.len() < MIN_SEG_LEN {
                return false;
            }
            n += 1;
            if n > 3 {
                return false;
            }
        }
        n == 3
    }

    fn redact_jwts(content: &str, kinds: &mut Vec<&'static str>) -> Option<String> {
        const JWT_HEADER_MARKER: &str = "eyJ";
        let mut out = String::with_capacity(content.len());
        let mut search_from = 0usize;
        let mut hit = false;
        while let Some(rel) = content[search_from..].find(JWT_HEADER_MARKER) {
            let start = search_from + rel;
            let token = token_at(content, start);
            if looks_like_jwt(token) {
                out.push_str(&content[search_from..start]);
                out.push_str(REDACTION_PLACEHOLDER);
                search_from = start + token.len();
                hit = true;
            } else {
                out.push_str(&content[search_from..start + JWT_HEADER_MARKER.len()]);
                search_from = start + JWT_HEADER_MARKER.len();
            }
        }
        if hit {
            out.push_str(&content[search_from..]);
            kinds.push(KIND_JWT);
            Some(out)
        } else {
            None
        }
    }

    fn redact_pem_blocks(content: &str) -> String {
        let mut out = String::with_capacity(content.len());
        let mut rest = content;
        while let Some(begin) = rest.find(PEM_BEGIN_MARKER) {
            out.push_str(&rest[..begin]);
            rest = &rest[begin..];
            let region_end = rest[PEM_BEGIN_MARKER.len()..]
                .find(PEM_BEGIN_MARKER)
                .map_or(rest.len(), |rel| PEM_BEGIN_MARKER.len() + rel);
            let region = &rest[..region_end];
            let mut key_markers = region.match_indices(PEM_PRIVATE_KEY_MARKER);
            let header = key_markers.next();
            let footer = key_markers.next();
            match (header, footer) {
                (Some(_), Some((footer_at, _))) => {
                    out.push_str(REDACTION_PLACEHOLDER);
                    rest = &rest[footer_at + PEM_PRIVATE_KEY_MARKER.len()..];
                }
                (Some(_), None) => {
                    out.push_str(REDACTION_PLACEHOLDER);
                    rest = &rest[region_end..];
                }
                (None, _) => {
                    out.push_str(region);
                    rest = &rest[region_end..];
                }
            }
        }
        out.push_str(rest);
        out
    }
}
