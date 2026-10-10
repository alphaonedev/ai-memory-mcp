// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6601 #6602 #6603 #6604 — guard for `CodeQL` `rust/cleartext-logging`
//! (same class as #6098; Refs #6163 #6351). Each alerted site is a test whose
//! assertion or panic message interpolated a value `CodeQL` treats as sensitive:
//! a fixture DSN secret and the captured log sink (#6601), the secret-screen
//! output that would carry the fixture key bytes on a regression (#6602), the
//! backend-derived hub allowlist entry handed out of the derived snapshot
//! (#6603), and recipient ids (#6604). The fixtures are fake placeholders, but
//! the alert clears only when the sink no longer carries the tainted binding.
//!
//! This guard reads each alerted file and fails while an alerted message still
//! interpolates the flagged binding. The assertion CONDITIONS are not checked
//! here; they stay byte-identical in the fixed files.

use std::path::Path;

fn source(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The text of `fn <name>` up to the first line that is exactly `}` at the
/// item's own indentation (top-level item: column 0).
fn top_level_fn_body<'a>(src: &'a str, rel: &str, name: &str) -> &'a str {
    let header = format!("fn {name}(");
    let start = src
        .find(&header)
        .unwrap_or_else(|| panic!("{rel}: `fn {name}` not found"));
    let rest = &src[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{rel}: end of `fn {name}` not found"));
    &rest[..end]
}

/// Every `{binding}` / `{binding:?}` interpolation of `binding` in `text`.
fn interpolations(text: &str, binding: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        for form in [format!("{{{binding}}}"), format!("{{{binding}:")] {
            if line.contains(&form) {
                hits.push(format!("line +{lineno}: `{}`", line.trim()));
            }
        }
    }
    hits
}

const PG_DSN: &str = "tests/pg_dsn_screen_3674.rs";
const PEM: &str = "tests/secret_screen_pem_block_bounds_2387.rs";
const WAKE_HUB: &str = "tests/wake_hub_write_authority_3578.rs";
const WAKE_SEQ: &str = "tests/wake_seq_per_recipient_4125.rs";

/// #6601 (alert 390): `assert_no_secret` must not print the fixture secret or
/// the captured sink.
#[test]
fn pg_dsn_screen_no_secret_or_sink_in_message_6601() {
    let src = source(PG_DSN);
    let body = top_level_fn_body(&src, PG_DSN, "assert_no_secret");
    let mut hits = interpolations(body, "secret");
    hits.extend(interpolations(body, "sink"));
    assert!(
        hits.is_empty(),
        "{PG_DSN}: assert_no_secret message still interpolates the secret or sink:\n{}",
        hits.join("\n")
    );
}

/// #6602 (alerts 105-114, 177, 178): no message may print the screen output.
#[test]
fn pem_block_bounds_no_redacted_output_in_messages_6602() {
    let src = source(PEM);
    let hits = interpolations(&src, "r");
    assert!(
        hits.is_empty(),
        "{PEM}: {} message(s) still interpolate the screen output `r`:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// #6603 (alert 104): the derived allowlist entry must not be pulled out of the
/// snapshot with `Vec::remove`, whose panic path is the flagged site; the
/// structural form is checked because the alerted line carries no format
/// string to inspect.
#[test]
fn wake_hub_derived_entry_not_taken_by_remove_6603() {
    let src = source(WAKE_HUB);
    let body = top_level_fn_body(
        &src,
        WAKE_HUB,
        "sqlite_mcp_http_hub_credential_and_write_authority_3578",
    );
    assert!(
        !body.contains("agents.remove("),
        "{WAKE_HUB}: the SQLite twin still takes the derived entry with `agents.remove(..)`"
    );
}

/// #6604 (alerts 391, 392): `watermark_for` must not print the recipient id.
#[test]
fn wake_seq_no_recipient_in_message_6604() {
    let src = source(WAKE_SEQ);
    let body = top_level_fn_body(&src, WAKE_SEQ, "watermark_for");
    let hits = interpolations(body, "recipient");
    assert!(
        hits.is_empty(),
        "{WAKE_SEQ}: watermark_for message still interpolates the recipient id:\n{}",
        hits.join("\n")
    );
}
