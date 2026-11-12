// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4600 — store-URL resolution for the one-shot writer verbs
//! (`schema-init`, `quarantine`, `recover-previous-session`).
//!
//! The shared ladder [`crate::store_url::resolve_store_url`] picks the first
//! set channel (`AI_MEMORY_STORE_URL_FILE`, then `AI_MEMORY_STORE_URL`, then
//! `--store-url`). For a daemon boot and the read verbs that is the documented
//! precedence (one order for all callers is tracked in #9202). For a one-shot
//! writer a silent pick means an exported channel can redirect a write away
//! from the store the operator named. This funnel refuses that case
//! (3-agent vote 71472661, A 3-0):
//!
//! - no channel set: `Ok(None)` (the caller keeps its local `--db` default);
//! - one channel set, or every set channel byte-equal: that value;
//! - any two SET channels that differ: [`StoreUrlConflict`], which names the
//!   two channels only, never a URL or a credential.
//!
//! "Same store" is exact byte equality (vote condition V-1): no URL
//! normalisation, no origin compare. The FILE value is read by the shared
//! 0600 reader [`store_url_from_file`], which trims the file's surrounding
//! whitespace (its trailing newline); ENV and the flag are compared raw. A SET
//! file channel that is unreadable, lax or empty is an error and never falls
//! through to ENV or the flag (V-2). An empty or blank env value is unset,
//! exactly as the shared ladder treats it.
//!
//! The check runs inside this wrapper, before the caller opens any store or
//! connection, and never inside the shared ladder, whose other callers keep
//! their order (V-3).
//!
//! The argv-credential warning goes to stderr here, because these verbs
//! install no console tracing subscriber
//! (`daemon_runtime::command_installs_console_subscriber`), so the ladder's
//! `tracing::warn!` would be dropped (`migrate::resolve_endpoint` precedent).

use anyhow::Result;

use crate::store_url::{
    STORE_URL_ENV, STORE_URL_FILE_ENV, store_url_from_file, url_carries_credentials,
};

/// The flag name the refusal and the warning cite.
pub const STORE_URL_FLAG: &str = "--store-url";

/// stderr warning when `--store-url` carries a credential (#1927 / #4600).
/// Names the flag and the safer channels; never the URL.
pub const ARGV_CREDENTIAL_WARNING: &str = "warning: --store-url carries a password in argv, \
     which is exposed via world-readable /proc/<pid>/cmdline and `ps auxww` to any local UID \
     (#4600). Prefer AI_MEMORY_STORE_URL_FILE (a 0600 file holding the URL) or \
     AI_MEMORY_STORE_URL instead.";

/// One store-URL channel, in ladder order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreUrlChannel {
    /// `AI_MEMORY_STORE_URL_FILE` (a 0600 file holding the URL).
    File,
    /// `AI_MEMORY_STORE_URL`.
    Env,
    /// `--store-url` on argv.
    Flag,
}

impl StoreUrlChannel {
    /// The env-var or flag name of this channel.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::File => STORE_URL_FILE_ENV,
            Self::Env => STORE_URL_ENV,
            Self::Flag => STORE_URL_FLAG,
        }
    }

    /// The env var to unset in the remedy line, when this channel is one.
    const fn env_var(self) -> Option<&'static str> {
        match self {
            Self::File => Some(STORE_URL_FILE_ENV),
            Self::Env => Some(STORE_URL_ENV),
            Self::Flag => None,
        }
    }
}

/// Two set store-URL channels name different stores.
///
/// Carries channel identities only, so its rendering can never echo a URL
/// or a credential (per ERRORS-09: the fields admit no URL text at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreUrlConflict {
    first: StoreUrlChannel,
    second: StoreUrlChannel,
}

impl StoreUrlConflict {
    /// The two disagreeing channels, in ladder order.
    #[must_use]
    pub const fn channels(&self) -> [StoreUrlChannel; 2] {
        [self.first, self.second]
    }

    /// The env var the remedy line names: the later channel when it is an
    /// env var (an exported variable is the usual stray), else the earlier.
    fn unset_hint(&self) -> &'static str {
        self.second
            .env_var()
            .or(self.first.env_var())
            .unwrap_or(STORE_URL_ENV)
    }
}

impl std::fmt::Display for StoreUrlConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to open a store: {} and {} name different stores (#4600); unset the \
             channel you do not mean, for example `env -u {} ...`, and run again",
            self.first.name(),
            self.second.name(),
            self.unset_hint()
        )
    }
}

impl std::error::Error for StoreUrlConflict {}

/// The FILE channel, read with the shared 0600 enforcement. A set path that
/// is unreadable, lax or empty is an error (never a fall-through).
fn file_channel() -> Result<Option<String>> {
    match std::env::var(STORE_URL_FILE_ENV) {
        Ok(path) if !path.trim().is_empty() => Ok(Some(store_url_from_file(
            std::path::Path::new(path.trim()),
        )?)),
        _ => Ok(None),
    }
}

/// The ENV channel, raw; empty or blank counts as unset (ladder parity).
fn env_channel() -> Option<String> {
    std::env::var(STORE_URL_ENV)
        .ok()
        .filter(|u| !u.trim().is_empty())
}

/// The first set channel is the reference; the first later one whose bytes
/// differ from it is the conflict.
fn check_agreement(set: &[(StoreUrlChannel, &str)]) -> Result<(), StoreUrlConflict> {
    let Some((&(first, reference), rest)) = set.split_first() else {
        return Ok(());
    };
    match rest.iter().find(|(_, value)| *value != reference) {
        Some(&(second, _)) => Err(StoreUrlConflict { first, second }),
        None => Ok(()),
    }
}

/// Resolve the store URL for a one-shot writer verb.
///
/// # Errors
///
/// [`StoreUrlConflict`] when any two set channels differ; every error of
/// [`store_url_from_file`] (unreadable, lax or empty URL file) unchanged.
pub fn resolve(flag: Option<&str>) -> Result<Option<String>> {
    let file = file_channel()?;
    let env = env_channel();
    let set: Vec<(StoreUrlChannel, &str)> = [
        (StoreUrlChannel::File, file.as_deref()),
        (StoreUrlChannel::Env, env.as_deref()),
        (StoreUrlChannel::Flag, flag),
    ]
    .into_iter()
    .filter_map(|(channel, value)| value.map(|v| (channel, v)))
    .collect();
    check_agreement(&set)?;
    if flag.is_some_and(url_carries_credentials) {
        eprintln!("{ARGV_CREDENTIAL_WARNING}");
    }
    Ok(set.first().map(|&(channel, value)| match channel {
        // The ladder hands the trimmed env value to every other caller.
        StoreUrlChannel::Env => value.trim().to_string(),
        StoreUrlChannel::File | StoreUrlChannel::Flag => value.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use StoreUrlChannel::{Env, File, Flag};

    /// V-4: the exact text for every channel pair, pinned.
    #[test]
    fn conflict_message_exact_text_per_pair_4600() {
        let rows = [
            (
                File,
                Env,
                "refusing to open a store: AI_MEMORY_STORE_URL_FILE and AI_MEMORY_STORE_URL \
                 name different stores (#4600); unset the channel you do not mean, for example \
                 `env -u AI_MEMORY_STORE_URL ...`, and run again",
            ),
            (
                File,
                Flag,
                "refusing to open a store: AI_MEMORY_STORE_URL_FILE and --store-url name \
                 different stores (#4600); unset the channel you do not mean, for example \
                 `env -u AI_MEMORY_STORE_URL_FILE ...`, and run again",
            ),
            (
                Env,
                Flag,
                "refusing to open a store: AI_MEMORY_STORE_URL and --store-url name different \
                 stores (#4600); unset the channel you do not mean, for example `env -u \
                 AI_MEMORY_STORE_URL ...`, and run again",
            ),
        ];
        for (first, second, text) in rows {
            let c = StoreUrlConflict { first, second };
            assert_eq!(c.to_string(), text);
            assert_eq!(c.channels(), [first, second]);
            assert!(!c.to_string().contains('\n'), "one line");
        }
    }

    /// V-1 / V-4: byte-unequal values that name "the same" store under a
    /// normaliser all conflict, and the refusal carries no URL part.
    #[test]
    fn agreement_is_exact_bytes_and_names_no_url_part_4600() {
        let parts = [
            "postgres", "://", "h-4600", "u_4600", "pw_4600", "db_4600", "6543",
        ];
        let base = "postgres://u_4600@h-4600:6543/db_4600";
        let others = [
            "postgres://u_4600:pw_4600@h-4600:6543/db_4600",
            "postgres://u_4600@h-4600:6543/db_4600/",
            "postgres://u_4600@h-4600:5432/db_4600",
            "postgres://u_4600@h-4600:6543/db_4600_b",
            "postgres://u_4600_b@h-4600:6543/db_4600",
            "postgres://u_4600@h-4600:6543/db_4600 ",
        ];
        for other in others {
            for (a, b) in [(File, Env), (File, Flag), (Env, Flag)] {
                let err = check_agreement(&[(a, base), (b, other)]).unwrap_err();
                assert_eq!(err.channels(), [a, b], "{other:?}");
                let text = err.to_string();
                for part in parts {
                    assert!(!text.contains(part), "{part:?} leaked: {text}");
                }
            }
        }
        assert_eq!(
            check_agreement(&[(File, base), (Env, base), (Flag, base)]),
            Ok(())
        );
        assert_eq!(check_agreement(&[(Flag, base)]), Ok(()));
        assert_eq!(check_agreement(&[]), Ok(()));
    }

    /// Class gap: FILE vs ENV is compared even when the flag agrees with one.
    #[test]
    fn file_and_env_conflict_whatever_the_flag_4600() {
        let rows = [
            (vec![(File, "a"), (Env, "b")], [File, Env]),
            (vec![(File, "a"), (Env, "b"), (Flag, "a")], [File, Env]),
            (vec![(File, "a"), (Env, "b"), (Flag, "b")], [File, Env]),
            (vec![(File, "a"), (Env, "a"), (Flag, "b")], [File, Flag]),
            (vec![(Env, "a"), (Flag, "b")], [Env, Flag]),
        ];
        for (set, want) in rows {
            assert_eq!(
                check_agreement(&set).unwrap_err().channels(),
                want,
                "{set:?}"
            );
        }
    }

    #[test]
    fn warning_names_no_url_4600() {
        assert!(!ARGV_CREDENTIAL_WARNING.contains("://"));
        assert!(ARGV_CREDENTIAL_WARNING.contains(STORE_URL_FILE_ENV));
    }
}
