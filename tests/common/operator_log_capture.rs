// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

pub const FIXTURE_PASSWORD: &str = "fixture-only-6822";
pub const FIXTURE_QUERY: &str = "fixture-query-6822";
pub const FIXTURE_FRAGMENT: &str = "fixture-fragment-6822";
const HOSTILE_CONTROLS: &str = "caller\0\nforged\r\t\x1b[31m\u{85}\u{2028}\u{2029}\u{202e}";
pub const CONTROL_PAIRS: &[(char, &str)] = &[
    ('\0', "\\0"),
    ('\n', "\\n"),
    ('\r', "\\r"),
    ('\t', "\\t"),
    ('\u{1b}', "\\u{1b}"),
    ('\u{85}', "\\u{85}"),
    ('\u{2028}', "\\u{2028}"),
    ('\u{2029}', "\\u{2029}"),
    ('\u{202e}', "\\u{202e}"),
];

pub fn hostile_detail() -> String {
    let mut url = reqwest::Url::parse("https://example.invalid/path").expect("fixture URL");
    url.set_username("fixture").expect("fixture username");
    url.set_password(Some(FIXTURE_PASSWORD))
        .expect("fixture password");
    url.set_query(Some(FIXTURE_QUERY));
    url.set_fragment(Some(FIXTURE_FRAGMENT));
    format!("{HOSTILE_CONTROLS} {url}")
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn captured<T>(operation: impl FnOnce() -> T) -> (T, String) {
    let sink = Capture::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, operation);
    let bytes = sink.0.lock().expect("capture lock").clone();
    (result, String::from_utf8(bytes).expect("UTF-8 log"))
}
