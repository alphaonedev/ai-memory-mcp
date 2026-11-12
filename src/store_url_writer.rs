// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4600 — store-URL resolution for the one-shot writer verbs
//! (`schema-init`, `quarantine`, `recover-previous-session`).
//!
//! The shared ladder [`crate::store_url::resolve_store_url`] lets a set
//! `AI_MEMORY_STORE_URL_FILE` or `AI_MEMORY_STORE_URL` channel win over an
//! explicit `--store-url`. For a daemon boot that is the documented
//! precedence (tracked separately in #9202). For a one-shot writer it means
//! an exported channel silently redirects a write away from the store the
//! operator named on the command line. This funnel refuses that case:
//!
//! - no `--store-url`: the shared ladder, unchanged (FILE, then ENV);
//! - `--store-url` and no channel set: the flag;
//! - `--store-url` equal to every set channel: accepted;
//! - `--store-url` differing from a set channel: [`StoreUrlConflict`], which
//!   names channels only, never a URL or a credential.
//!
//! The argv-credential warning goes to stderr here, because these verbs
//! install no console tracing subscriber
//! (`daemon_runtime::command_installs_console_subscriber`), so the ladder's
//! `tracing::warn!` would be dropped (`migrate::resolve_endpoint` precedent).

use anyhow::Result;

use crate::store_url::{
    STORE_URL_ENV, STORE_URL_FILE_ENV, resolve_store_url, store_url_from_file,
    url_carries_credentials,
};

/// The flag name the refusal and the warning cite.
pub const STORE_URL_FLAG: &str = "--store-url";

/// stderr warning when `--store-url` carries a credential (#1927 / #4600).
/// Names the flag and the safer channels; never the URL.
pub const ARGV_CREDENTIAL_WARNING: &str = "warning: --store-url carries a password in argv, \
     which is exposed via world-readable /proc/<pid>/cmdline and `ps auxww` to any local UID \
     (#4600). Prefer AI_MEMORY_STORE_URL_FILE (a 0600 file holding the URL) or \
     AI_MEMORY_STORE_URL instead.";

/// An explicit `--store-url` disagrees with a set non-argv channel.
///
/// Carries the env-var NAMES of the disagreeing channels only, so its
/// rendering can never echo a URL or a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreUrlConflict {
    channels: Vec<&'static str>,
}

impl StoreUrlConflict {
    /// The env-var names of the channels that differ from the flag, in
    /// ladder order (FILE first).
    #[must_use]
    pub fn channels(&self) -> &[&'static str] {
        &self.channels
    }
}

impl std::fmt::Display for StoreUrlConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing {STORE_URL_FLAG}: it differs from the store URL set by {}; pass the same \
             URL on both, or drop one of them, so the write cannot reach a store you did not \
             name (#4600)",
            self.channels.join(" and ")
        )
    }
}

impl std::error::Error for StoreUrlConflict {}

/// The FILE channel, read with the shared 0600 enforcement.
fn file_channel() -> Result<Option<String>> {
    match std::env::var(STORE_URL_FILE_ENV) {
        Ok(path) if !path.trim().is_empty() => Ok(Some(store_url_from_file(
            std::path::Path::new(path.trim()),
        )?)),
        _ => Ok(None),
    }
}

/// The ENV channel, trimmed; empty counts as unset (ladder parity).
fn env_channel() -> Option<String> {
    std::env::var(STORE_URL_ENV)
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
}

/// Resolve the store URL for a one-shot writer verb.
///
/// # Errors
///
/// [`StoreUrlConflict`] when `flag` differs from a set FILE or ENV channel;
/// every error of [`resolve_store_url`] / [`store_url_from_file`] (lax or
/// empty URL file) unchanged.
pub fn resolve(flag: Option<&str>) -> Result<Option<String>> {
    let Some(flag) = flag else {
        return resolve_store_url(None);
    };
    let wanted = flag.trim();
    let mut channels = Vec::new();
    if file_channel()?.is_some_and(|u| u != wanted) {
        channels.push(STORE_URL_FILE_ENV);
    }
    if env_channel().is_some_and(|u| u != wanted) {
        channels.push(STORE_URL_ENV);
    }
    if !channels.is_empty() {
        return Err(StoreUrlConflict { channels }.into());
    }
    if url_carries_credentials(flag) {
        eprintln!("{ARGV_CREDENTIAL_WARNING}");
    }
    Ok(Some(flag.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_message_names_channels_only_4600() {
        let both = StoreUrlConflict {
            channels: vec![STORE_URL_FILE_ENV, STORE_URL_ENV],
        };
        assert_eq!(
            both.to_string(),
            "refusing --store-url: it differs from the store URL set by \
             AI_MEMORY_STORE_URL_FILE and AI_MEMORY_STORE_URL; pass the same URL on both, or \
             drop one of them, so the write cannot reach a store you did not name (#4600)"
        );
        assert_eq!(both.channels(), [STORE_URL_FILE_ENV, STORE_URL_ENV]);
    }

    #[test]
    fn warning_names_no_url_4600() {
        assert!(!ARGV_CREDENTIAL_WARNING.contains("://"));
        assert!(ARGV_CREDENTIAL_WARNING.contains(STORE_URL_FILE_ENV));
    }
}
