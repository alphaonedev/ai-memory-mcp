// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

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
