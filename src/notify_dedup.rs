// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8487 — the optional sender idempotency key on `memory_notify`.
//!
//! A sender that retries a notify (a network timeout, an agent restart, an
//! at-least-once queue) would otherwise deliver the same message twice: every
//! delivery is a NEW inbox row (#3639). A sender may now attach an
//! `idempotency_key`; the server remembers `(sender, target, key)` in the
//! `notify_dedup` table, written in the SAME transaction as the inbox row, and
//! answers a retry with the ORIGINAL row id and `dedup_hit: true`. The same
//! key with a different message is a typed conflict that carries the original
//! id. The sender is ALWAYS the server-resolved caller, never a request
//! field, so one agent can never replay (or probe) another agent's keys.
//!
//! This module holds the backend-neutral pieces shared by sqlite and
//! postgres: the key validator, the content fingerprint and the probe
//! classification. The sqlite funnel is `crate::storage::notify_dedup`; the
//! postgres funnel is `crate::store::postgres::notify_dedup`.
//!
//! Decision shape: 3-agent vote (6def5ab6).

use crate::models::Tier;
use sha2::{Digest, Sha256};

/// Maximum accepted key length, in bytes, after trimming.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// Why an `idempotency_key` was refused. The rendering never echoes the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidIdempotencyKey {
    /// Empty (or whitespace only) after trimming.
    Empty,
    /// Longer than [`MAX_IDEMPOTENCY_KEY_BYTES`] after trimming.
    TooLong,
    /// Holds a character outside `[A-Za-z0-9._:-]`.
    BadCharset,
}

impl std::fmt::Display for InvalidIdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed text per variant: the key itself is never rendered.
        f.write_str(match self {
            Self::Empty => "idempotency_key cannot be empty",
            Self::TooLong => "idempotency_key exceeds max length of 128 bytes",
            Self::BadCharset => {
                "idempotency_key contains an invalid character (allowed: A-Z a-z 0-9 . _ : -)"
            }
        })
    }
}

impl std::error::Error for InvalidIdempotencyKey {}

/// Validate a caller-supplied key and return it trimmed.
///
/// Runs before any quota charge or database write on every surface.
///
/// # Errors
///
/// [`InvalidIdempotencyKey`] when the trimmed key is empty, longer than
/// [`MAX_IDEMPOTENCY_KEY_BYTES`] bytes, or holds a character outside
/// `[A-Za-z0-9._:-]`.
pub fn validate_idempotency_key(raw: &str) -> Result<String, InvalidIdempotencyKey> {
    let key = raw.trim();
    if key.is_empty() {
        return Err(InvalidIdempotencyKey::Empty);
    }
    if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(InvalidIdempotencyKey::TooLong);
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(InvalidIdempotencyKey::BadCharset);
    }
    Ok(key.to_owned())
}

/// The content fingerprint stored beside a key and compared on a retry.
///
/// SHA-256 over exactly these five fields, in this order, each as a
/// big-endian `u64` byte length followed by its UTF-8 bytes (so a boundary
/// shift between two fields cannot collide): the target agent id, the
/// subject, the payload, the priority AFTER the `[1, 10]` clamp (decimal),
/// and the tier AFTER the default (`Tier::as_str`). `why_trace` and every
/// server-minted value (row id, timestamps) are deliberately NOT part of it:
/// a retry may legitimately differ in rationale, and a server-minted value
/// would make every retry look different. Pinned by
/// `tests/notify_idempotency_key_8487.rs`.
#[must_use]
pub fn content_digest(
    target_agent_id: &str,
    title: &str,
    payload: &str,
    priority: i32,
    tier: &Tier,
) -> String {
    let priority = priority.to_string();
    let mut hasher = Sha256::new();
    for field in [target_agent_id, title, payload, &priority, tier.as_str()] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// What the probe found for `(sender, target, key)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupVerdict {
    /// No row: this is a first delivery.
    Miss,
    /// A row with the same fingerprint: answer with the original id.
    Hit {
        /// The original inbox row id.
        id: String,
    },
    /// A row with a different fingerprint: the key was used for another
    /// message.
    Conflict {
        /// The original inbox row id.
        id: String,
    },
}

/// Classify a probe result (`(memory_id, content_digest)`) against the
/// fingerprint of the delivery being attempted.
#[must_use]
pub fn classify(existing: Option<(String, String)>, digest: &str) -> DedupVerdict {
    match existing {
        None => DedupVerdict::Miss,
        Some((id, stored)) if stored == digest => DedupVerdict::Hit { id },
        Some((id, _)) => DedupVerdict::Conflict { id },
    }
}
