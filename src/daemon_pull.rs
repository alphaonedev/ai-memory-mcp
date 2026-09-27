// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/// Minimal URL-component encoder — only the characters the sync-daemon
/// queries actually emit (RFC3339 timestamps with `:` and `+`, and
/// agent ids with `:`/`@`/`/`). Mirror of the pre-W6
/// `main.rs::urlencoding_minimal`.
pub(super) fn urlencoding_minimal(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Mirrors the pre-W6 `main.rs::SyncSinceResponse` — the fields we
/// deserialize from the peer's `/api/v1/sync/since` body. `count` and
/// `limit` are present in the wire payload but unused on the receive
/// side; allowed to be dead so `clippy::pedantic` doesn't trip.
#[derive(serde::Deserialize)]
#[allow(clippy::option_option)] // Wire absence and an explicit null are different cursor commands.
pub(super) struct SyncSinceResponse {
    #[allow(dead_code)]
    pub(super) count: usize,
    #[allow(dead_code)]
    pub(super) limit: usize,
    pub(super) memories: Vec<crate::models::Memory>,
    /// #2441 — the peer's PULL CURSOR, derived from the rows it
    /// EXAMINED rather than the rows it projected. Absent on a
    /// pre-#2441 peer (`#[serde(default)]` → `None`), in which case
    /// [`super::sync_cycle_once`] falls back to the legacy
    /// `memories.last().updated_at` so a mixed-version mesh keeps
    /// working exactly as before.
    #[serde(default, deserialize_with = "deserialize_present_pull_cursor")]
    pub(super) next_since: Option<Option<String>>,
}

// Serde's nested Option alone also collapses null into None. Invoking this
// deserializer only for a present field preserves the explicit hold signal.
#[allow(clippy::option_option)] // Preserve field presence independently of its nullable value.
fn deserialize_present_pull_cursor<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Option<String> as serde::Deserialize>::deserialize(deserializer).map(Some)
}
