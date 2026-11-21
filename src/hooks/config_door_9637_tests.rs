// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9637 — the hooks-file door: exact refusal text for every shape the
//! schema does not know, for control characters in keys and values, for the
//! message cap, for an input of 100K+ characters, for a FIFO and for a file
//! over the size cap. The expected strings are written out by hand; none is
//! computed from the loader.

use super::*;

/// The full `[[hook]]` row with `event` on line 2 and `fail_mode` on line 9.
const ROW: &str = "[[hook]]\nevent = \"pre_store\"\ncommand = \"/bin/true\"\npriority = 0\n\
                   timeout_ms = 1000\nmode = \"exec\"\nenabled = true\nnamespace = \"*\"\n\
                   fail_mode = \"closed\"\n";

/// The unknown-variant reason for an `event` value on line 2, cut at the
/// 200-character message cap: the kind and the static expected set only.
const UNKNOWN_EVENT: &str = "hooks.toml parse error at line 2, column 9: unknown variant, \
     expected one of `pre_store`, `post_store`, `post_recall`, `post_search`, `pre_delete`, \
     `post_delete`, `pre_promote`, `post_promote`, `pre_link`, `post_link`, `pre_consolidate`, \
     `post_";

/// The size of a scanner input for the time bound (at least 100K).
const BIG_INPUT_CHARS: usize = 100_000;
/// Wall-clock ceiling for one load of a [`BIG_INPUT_CHARS`] input.
const BIG_INPUT_CEILING: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a FIFO load may take before the test calls it a wait.
const FIFO_CEILING: std::time::Duration = std::time::Duration::from_secs(5);

fn scratch() -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/hooks-door-9637");
    std::fs::create_dir_all(&root).expect("create scratch root");
    tempfile::Builder::new()
        .prefix("door2-")
        .tempdir_in(&root)
        .expect("scratch dir")
}

/// A character that must never reach an operator line raw: a control
/// character, or one that changes how the text around it is shown
/// (bidirectional overrides and isolates, zero-width characters, line and
/// paragraph separators, the byte-order mark). Written out here, not taken
/// from the loader.
fn is_raw_display_hazard(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn refusal(src: &str) -> String {
    HookConfig::load_from_str(src)
        .expect_err("the fixture must be refused")
        .to_string()
}

/// Finding 1: a key or table the schema does not know is refused with the
/// exact kind and the static expected set, never dropped.
#[test]
fn unknown_keys_and_tables_are_refused_with_the_exact_reason_9637() {
    let rows: &[(&str, String, &str)] = &[
        (
            "misspelt_table",
            ROW.replace("[[hook]]", "[[hooks]]"),
            "hooks.toml parse error at line 1, column 3: unknown field, expected `hook`",
        ),
        (
            "misspelt_fail_mode",
            ROW.replace("fail_mode", "fail_mod"),
            "hooks.toml parse error at line 9, column 1: unknown field, expected one of \
             `event`, `command`, `priority`, `timeout_ms`, `mode`, `enabled`, `namespace`, \
             `fail_mode`",
        ),
        (
            "unknown_top_level_key",
            format!("enforce = true\n{ROW}"),
            "hooks.toml parse error at line 1, column 1: unknown field, expected `hook`",
        ),
        (
            "key_quoting_the_separator",
            "\"a, expected `x`\" = 1\n".to_owned(),
            "hooks.toml parse error at line 1, column 1: unknown field, expected `hook`",
        ),
    ];
    for (name, src, want) in rows {
        assert_eq!(refusal(src), *want, "row {name}");
    }
    // The row without the misspelling loads: the refusal is the key, not the row.
    assert_eq!(HookConfig::load_from_str(ROW).expect("valid row").len(), 1);
}

/// Finding 2: an ESC or a newline in a key or a value never reaches the
/// operator line raw. A key is escaped, a value is never echoed.
#[test]
fn control_characters_in_keys_and_values_are_escaped_or_dropped_9637() {
    let rows: &[(&str, String, &str)] = &[
        (
            "esc_in_key",
            "[\"x\\u001by\"]\na = 1\na = 2\n".to_owned(),
            "hooks.toml parse error at line 3, column 1: duplicate key `a` in table `x\\u{1b}y`",
        ),
        (
            "newline_in_key",
            "[\"x\\ny\"]\na = 1\na = 2\n".to_owned(),
            "hooks.toml parse error at line 3, column 1: duplicate key `a` in table `x\\ny`",
        ),
        (
            "backslash_in_key",
            "[\"x\\\\y\"]\na = 1\na = 2\n".to_owned(),
            "hooks.toml parse error at line 3, column 1: duplicate key `a` in table `x\\\\y`",
        ),
        (
            "bidi_override_in_key",
            "[\"x\\u202Ey\"]\na = 1\na = 2\n".to_owned(),
            "hooks.toml parse error at line 3, column 1: duplicate key `a` in table `x\\u{202e}y`",
        ),
        (
            "esc_in_value",
            ROW.replace("\"pre_store\"", "\"x\\u001b\""),
            UNKNOWN_EVENT,
        ),
        (
            "newline_in_value",
            ROW.replace("\"pre_store\"", "\"x\\ny\""),
            UNKNOWN_EVENT,
        ),
        (
            "esc_in_unknown_key",
            "\"k\\u001b\" = 1\n".to_owned(),
            "hooks.toml parse error at line 1, column 1: unknown field, expected `hook`",
        ),
    ];
    for (name, src, want) in rows {
        let got = refusal(src);
        assert_eq!(got, *want, "row {name}");
        assert!(
            !got.chars().any(is_raw_display_hazard),
            "row {name}: raw control or display-altering character in {got:?}"
        );
    }
}

/// Finding 5: the parser message is cut at exactly 200 characters, between
/// whole characters and whole escape units.
#[test]
fn the_parser_message_is_cut_at_exactly_200_characters_9637() {
    const PREFIX: &str = "hooks.toml parse error at line 2, column 1: ";
    let dup = |key: &str| format!("\"{key}\" = 1\n\"{key}\" = 2\n");

    // "duplicate key `" is 15 characters, so 185 key characters fill the cap.
    let got = refusal(&dup(&"a".repeat(300)));
    assert_eq!(got, format!("{PREFIX}duplicate key `{}", "a".repeat(185)));

    // A multibyte character is never split: 185 whole characters.
    let got = refusal(&dup(&"\u{e9}".repeat(300)));
    assert_eq!(
        got,
        format!("{PREFIX}duplicate key `{}", "\u{e9}".repeat(185))
    );

    // An escape unit that would cross the cap is dropped whole: 15 + 184 = 199.
    let got = refusal(&dup(&format!("{}\\u001b", "a".repeat(184))));
    assert_eq!(got, format!("{PREFIX}duplicate key `{}", "a".repeat(184)));

    // Under the cap nothing is cut.
    let got = refusal(&dup("k"));
    assert_eq!(got, format!("{PREFIX}duplicate key `k` in document root"));
}

/// Finding 5: a 100K-character key and value are refused with the exact
/// reason inside the wall-clock ceiling (no quadratic scan of the message).
#[test]
fn a_100k_key_or_value_is_refused_in_bounded_time_9637() {
    let rows: &[(&str, String, &str)] = &[
        (
            "big_unknown_key",
            format!("{} = 1\n", "k".repeat(BIG_INPUT_CHARS)),
            "hooks.toml parse error at line 1, column 1: unknown field, expected `hook`",
        ),
        (
            "big_event_value",
            ROW.replace(
                "\"pre_store\"",
                &format!("\"{}\"", "x".repeat(BIG_INPUT_CHARS)),
            ),
            UNKNOWN_EVENT,
        ),
        (
            "big_duplicate_key",
            format!("{k} = 1\n{k} = 2\n", k = "d".repeat(BIG_INPUT_CHARS)),
            "",
        ),
    ];
    for (name, src, want) in rows {
        let start = std::time::Instant::now();
        let got = refusal(src);
        let took = start.elapsed();
        assert!(took < BIG_INPUT_CEILING, "row {name}: took {took:?}");
        if want.is_empty() {
            assert_eq!(
                got,
                format!(
                    "hooks.toml parse error at line 2, column 1: duplicate key `{}",
                    "d".repeat(185)
                ),
                "row {name}"
            );
        } else {
            assert_eq!(got, *want, "row {name}");
        }
    }
}

/// Finding 3: a FIFO at the hooks path is refused at once as not a regular
/// file; the open does not wait for a writer.
#[cfg(unix)]
#[test]
fn a_fifo_is_refused_without_waiting_for_a_writer_9637() {
    let dir = scratch();
    let p = dir.path().join("hooks.toml");
    let c_path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the
    // call; mkfifo(3) only reads it.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());

    let (tx, rx) = std::sync::mpsc::channel();
    let probe = p.clone();
    std::thread::spawn(move || {
        let got = HookConfig::try_load_from_optional(&probe).map(|h| h.map(|v| v.len()));
        tx.send(got.map_err(|e| e.to_string())).ok();
    });
    let got = rx
        .recv_timeout(FIFO_CEILING)
        .expect("the FIFO load must return inside the ceiling, not wait for a writer");
    assert_eq!(
        got,
        Err(format!(
            "hooks file {} cannot be loaded: hooks.toml read error: not a regular file",
            p.display()
        ))
    );
}

/// Finding 5: a file of exactly the cap loads; one byte more is refused with
/// the exact reason.
#[test]
fn the_size_cap_is_exact_9637() {
    let dir = scratch();
    let p = dir.path().join("hooks.toml");
    let cap = usize::try_from(MAX_HOOKS_FILE_BYTES).expect("cap fits usize");

    std::fs::write(&p, vec![b'#'; cap]).expect("write cap-sized file");
    let hooks = HookConfig::try_load_from_optional(&p)
        .expect("a file of exactly the cap loads")
        .expect("Some");
    assert!(hooks.is_empty());

    std::fs::write(&p, vec![b'#'; cap + 1]).expect("write cap-plus-one file");
    let err = HookConfig::try_load_from_optional(&p).expect_err("cap plus one refuses");
    assert_eq!(
        err.to_string(),
        format!(
            "hooks file {} cannot be loaded: hooks.toml read error: file is larger than 1048576 bytes",
            p.display()
        )
    );
}
