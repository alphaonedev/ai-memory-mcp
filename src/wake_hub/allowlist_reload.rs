// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The live hub's store-free allowlist resolver, and the snapshot-freshness
//! posture that goes with it (issue
//! [#3504](https://github.com/alphaonedev/ai-memory-mcp/issues/3504), follow-up
//! to [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! # What changed, and what deliberately did not
//!
//! [`ReloadingAllowlist`] used to re-open, re-read and re-parse the derived
//! snapshot on EVERY hello and on every one-second per-session
//! [`revalidate`](super::conn) — O(connections) JSON parses per second, 256/s at
//! the connection ceiling. It now reuses the PARSED
//! [`AllowlistCache`](super::delegation_verifier::AllowlistCache) while the
//! file's identity (device, inode, mtime, size) is unchanged and the parse is
//! younger than [`ALLOWLIST_CACHE_TTL`].
//!
//! Nothing about what is ADMITTED moved. Three properties are load-bearing and
//! each is exercised by a test:
//!
//! 1. **The permission gate runs on every call.** Every resolution opens the
//!    file with `O_NOFOLLOW` and re-proves owner + exact `0600` + regular-file
//!    through that descriptor. A snapshot whose mode is widened, whose owner
//!    changes, or which is replaced by a symlink is refused IMMEDIATELY, even
//!    when the cached parse is seconds old.
//! 2. **The `refreshed_at` age gate runs on every call.** A cache hit re-runs
//!    [`AllowlistCache::check_snapshot_age`], so reuse can never extend the
//!    life of a snapshot past
//!    [`MAX_CACHE_AGE_SECS`](crate::identity::hub_cache::MAX_CACHE_AGE_SECS).
//!    An expired file stays refused exactly as it was before this cache landed.
//! 3. **A replaced snapshot takes effect immediately.** A new inode, a new
//!    mtime or a new size misses the key and forces a re-read on the very next
//!    call, so a refresh (or a revocation) still lands within the same
//!    one-second revalidation window it always did.
//!
//! # Why the permission check and the read share one descriptor
//!
//! [`AllowlistCache::open_checked`] returns the [`std::fs::Metadata`] it read
//! from the descriptor it opened, and the bytes are then read from that SAME
//! descriptor. The identity reuse is keyed on, the permissions that were
//! checked, and the content that is parsed therefore all describe one inode.
//! A path-based `stat`-then-`open` would leave a window for an attacker with
//! write access to the directory to swap the file between the two; there is no
//! such window here.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Instant;

use chrono::{DateTime, FixedOffset, Utc};

use crate::identity::hub_cache::MAX_CACHE_AGE_SECS;

use super::delegation_verifier::{AllowlistCache, EnrolledRoot, RootKeyResolver};
use super::identity::DenyReason;
use super::limits::ALLOWLIST_CACHE_TTL;

/// The filesystem identity a reused parse is keyed on.
///
/// Device and inode together name the file; mtime and size detect a rewrite
/// that landed on the same inode. Any difference in any field is a miss, so
/// reuse is only ever the answer for a file that has not observably moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotIdentity {
    dev: u64,
    ino: u64,
    mtime_secs: i64,
    mtime_nanos: i64,
    size: u64,
}

impl SnapshotIdentity {
    /// Read the identity from metadata taken through an open descriptor.
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime_secs: meta.mtime(),
            mtime_nanos: meta.mtime_nsec(),
            size: meta.size(),
        }
    }
}

/// One parsed snapshot, with everything needed to decide whether it may be
/// served again without re-reading the file.
#[derive(Debug)]
struct CachedSnapshot {
    identity: SnapshotIdentity,
    /// When the descriptor this parse came from was opened. Monotonic, so a
    /// wall-clock adjustment cannot extend the TTL.
    observed_at: Instant,
    /// The snapshot's own `refreshed_at`, re-checked against the wall clock on
    /// every hit — this is what keeps an expired snapshot refused.
    refreshed_at: DateTime<FixedOffset>,
    cache: Arc<AllowlistCache>,
}

/// Store-free resolver over the derived snapshot on disk.
///
/// A removed, unreadable, mode-widened, stale or invalid file fails closed on
/// the spot. The hub never opens the database; this file is the whole of what
/// it knows about identity, and it holds only public material.
#[derive(Debug)]
pub struct ReloadingAllowlist {
    path: PathBuf,
    /// The last accepted parse. `RwLock` (never held across an `.await` — every
    /// method here is synchronous) because the hot path is read-mostly: at the
    /// connection ceiling this is read hundreds of times per second and written
    /// at most once every [`ALLOWLIST_CACHE_TTL`].
    cached: RwLock<Option<CachedSnapshot>>,
    opens: AtomicU64,
    parses: AtomicU64,
}

impl ReloadingAllowlist {
    /// Validate the initial snapshot before arming the runtime verifier.
    ///
    /// # Errors
    /// Refuses an unreadable or invalid snapshot.
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        AllowlistCache::load_from_file(&path)?;
        Ok(Self {
            path,
            cached: RwLock::new(None),
            opens: AtomicU64::new(0),
            parses: AtomicU64::new(0),
        })
    }

    /// How many times the snapshot has been opened and re-checked.
    ///
    /// Observability and test surface. This counts EVERY identity check, so
    /// `open_count` far exceeding [`Self::parse_count`] is the fix in #3504
    /// working; the two being equal is the defect it removed.
    #[must_use]
    pub fn open_count(&self) -> u64 {
        self.opens.load(Ordering::Relaxed)
    }

    /// How many times the snapshot has actually been read and PARSED.
    #[must_use]
    pub fn parse_count(&self) -> u64 {
        self.parses.load(Ordering::Relaxed)
    }

    /// The parsed snapshot to answer this identity check from.
    ///
    /// Opens and re-checks the file every time; re-parses only when the file's
    /// identity moved or the TTL expired.
    fn snapshot(&self) -> Result<Arc<AllowlistCache>, DenyReason> {
        // (1) The permission gate, on EVERY call, before any reuse: a
        // downgraded, replaced-by-symlink or foreign-owned file dies here.
        self.opens.fetch_add(1, Ordering::Relaxed);
        let (file, meta) =
            AllowlistCache::open_checked(&self.path).map_err(|_| DenyReason::DelegationInvalid)?;
        let identity = SnapshotIdentity::from_metadata(&meta);
        // Taken BEFORE the read, so the TTL is measured from when this
        // descriptor was observed and can only ever expire EARLIER than the
        // parse it protects.
        let observed_at = Instant::now();

        // (2) Reuse, but never the age decision: an expired snapshot stays
        // refused whether or not its parse is still warm.
        if let Some((cache, refreshed_at)) = self.hit(identity) {
            drop(file);
            AllowlistCache::check_snapshot_age(refreshed_at, Utc::now())
                .map_err(|_| DenyReason::DelegationInvalid)?;
            return Ok(cache);
        }

        // (3) Miss: read the bytes from the same descriptor that was checked.
        self.parses.fetch_add(1, Ordering::Relaxed);
        let parsed = AllowlistCache::read_checked(file, &self.path)
            .map_err(|_| DenyReason::DelegationInvalid)?;
        let (cache, refreshed_at) =
            AllowlistCache::from_file_parts(parsed).map_err(|_| DenyReason::DelegationInvalid)?;
        let cache = Arc::new(cache);
        {
            let mut guard = self.cached.write().unwrap_or_else(PoisonError::into_inner);
            *guard = Some(CachedSnapshot {
                identity,
                observed_at,
                refreshed_at,
                cache: Arc::clone(&cache),
            });
        }
        Ok(cache)
    }

    /// The still-valid parse for `identity`, if there is one.
    ///
    /// Returns owned values so the read guard is released before the caller
    /// does anything else — the lock never spans a decision, let alone an
    /// `.await`.
    fn hit(
        &self,
        identity: SnapshotIdentity,
    ) -> Option<(Arc<AllowlistCache>, DateTime<FixedOffset>)> {
        // A poisoned lock means some other thread panicked while replacing a
        // cache entry. The protected value is a DISPOSABLE parse of a file
        // that is re-read on the next miss, never durable truth, so recovering
        // it degrades nothing (rust-1.98 CONCURRENCY-18).
        let guard = self.cached.read().unwrap_or_else(PoisonError::into_inner);
        let cached = guard.as_ref()?;
        if cached.identity != identity || cached.observed_at.elapsed() >= ALLOWLIST_CACHE_TTL {
            return None;
        }
        Some((Arc::clone(&cached.cache), cached.refreshed_at))
    }
}

impl RootKeyResolver for ReloadingAllowlist {
    fn resolve(&self, agent_id: &str) -> Result<EnrolledRoot, DenyReason> {
        self.snapshot()?.resolve(agent_id)
    }

    fn resolve_delegate(
        &self,
        agent_id: &str,
        key: &[u8; 32],
        issued: &str,
    ) -> Result<EnrolledRoot, DenyReason> {
        self.snapshot()?.resolve_delegate(agent_id, key, issued)
    }

    fn check_delegate(
        &self,
        agent_id: &str,
        key: &[u8; 32],
        issued: &str,
    ) -> Result<(), DenyReason> {
        self.snapshot()?.check_delegate(agent_id, key, issued)
    }

    fn readable_prefixes(&self, agent_id: &str) -> Result<Vec<String>, DenyReason> {
        // #3505 — served from the SAME snapshot every other identity answer
        // comes from, so the permission gate and the age gate run on this call
        // too. A widened, replaced, expired or removed snapshot narrows the
        // proven prefixes on the very next revalidation, exactly as it narrows
        // the enrolled root.
        self.snapshot()?.readable_prefixes(agent_id)
    }
}

/// How old the configured snapshot is, for `wake-hub --posture` (#3504).
///
/// The hub refuses every hello once the snapshot passes
/// [`MAX_CACHE_AGE_SECS`], so an operator whose refresher has stopped needs to
/// be able to SEE that before the agents do. This is a read-only observation:
/// it binds nothing, admits nobody, and reports rather than decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotFreshness {
    /// Age in seconds, or `None` when no allowlist is configured or the file
    /// cannot be read as a valid snapshot at all. A negative age means the
    /// snapshot is future-dated, which is refused just like an expired one.
    pub age_secs: Option<i64>,
    /// Whether the hub will currently accept the snapshot's age. `false`
    /// whenever `age_secs` is `None` — an unreadable snapshot is not a fresh
    /// one (fail closed).
    pub within_max_age: bool,
}

impl SnapshotFreshness {
    /// Observe the snapshot at `path`, if one is configured.
    #[must_use]
    pub fn observe(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self {
                age_secs: None,
                within_max_age: false,
            };
        };
        let refreshed = AllowlistCache::read_file(path)
            .ok()
            .and_then(|file| file.refreshed_at)
            .and_then(|stamp| DateTime::parse_from_rfc3339(&stamp).ok());
        let Some(refreshed) = refreshed else {
            return Self {
                age_secs: None,
                within_max_age: false,
            };
        };
        // ONE clock read for both fields: an age the operator is shown and a
        // verdict that disagreed with it would be worse than no posture.
        let now = Utc::now();
        Self {
            age_secs: Some(now.signed_duration_since(refreshed).num_seconds()),
            within_max_age: AllowlistCache::check_snapshot_age(refreshed, now).is_ok(),
        }
    }

    /// The one machine-readable field the posture JSON carries.
    #[must_use]
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "age_secs": self.age_secs,
            "max_age_secs": MAX_CACHE_AGE_SECS,
            "within_max_age": self.within_max_age,
        })
    }

    /// The one line the human posture prints.
    #[must_use]
    pub fn summary(self) -> String {
        match (self.age_secs, self.within_max_age) {
            (Some(age), true) => format!("{age} s old (ceiling {MAX_CACHE_AGE_SECS} s)"),
            (Some(age), false) => format!(
                "{age} s old — OUTSIDE the {MAX_CACHE_AGE_SECS} s ceiling; every hello is \
                 REFUSED until it is refreshed"
            ),
            (None, _) => format!(
                "no readable snapshot; every hello is REFUSED (refresh it at least every \
                 {MAX_CACHE_AGE_SECS} s)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION;
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    const AGENT: &str = "agent-cache-3504";

    /// A 0600 snapshot naming one agent, stamped `age_secs` in the past.
    fn write_snapshot(path: &Path, age_secs: i64, key_byte: u8) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[key_byte; 32]);
        let body = serde_json::json!({
            "version": ALLOWLIST_FILE_VERSION,
            "refreshed_at": (Utc::now() - chrono::Duration::seconds(age_secs)).to_rfc3339(),
            "agents": [{
                "agent_id": AGENT,
                "pubkey_b64": crate::identity::keypair::encode_public_base64(&key.verifying_key()),
                "bind_authority": "possession_proof",
                "bound_at": "2026-09-01T00:00:00Z",
            }],
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .expect("create snapshot");
        file.write_all(serde_json::to_vec(&body).expect("encode").as_slice())
            .expect("write snapshot");
        drop(file);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    fn owner_only_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        dir
    }

    /// The defect #3504 fixes: repeated identity checks against an unchanged
    /// file re-parsed the JSON every time. They must now open (and re-check)
    /// every time and parse ONCE.
    #[test]
    fn repeated_checks_against_an_unchanged_snapshot_parse_once_3504() {
        let dir = owner_only_dir();
        let path = dir.path().join("allow.json");
        write_snapshot(&path, 1, 31);
        let resolver = ReloadingAllowlist::new(path).expect("arm");
        for _ in 0..32 {
            resolver.resolve(AGENT).expect("the agent stays admitted");
        }
        assert_eq!(
            resolver.open_count(),
            32,
            "the permission gate must run on EVERY check, never be skipped"
        );
        assert_eq!(
            resolver.parse_count(),
            1,
            "an unchanged snapshot must be parsed once, not once per check"
        );
    }

    /// A replaced snapshot must be picked up on the very next check, inside
    /// the TTL — this is what keeps a revocation effective within the hub's
    /// one-second revalidation.
    #[test]
    fn a_replaced_snapshot_is_re_read_inside_the_ttl_3504() {
        let dir = owner_only_dir();
        let path = dir.path().join("allow.json");
        write_snapshot(&path, 1, 41);
        let resolver = ReloadingAllowlist::new(path.clone()).expect("arm");
        let first = resolver.resolve(AGENT).expect("admitted").pubkey;
        assert_eq!(resolver.parse_count(), 1);

        // Publish a DIFFERENT key the way the refresher does: a new inode
        // moved into place. The TTL has not elapsed, so only the identity key
        // can catch this.
        let replacement = dir.path().join("next.json");
        write_snapshot(&replacement, 1, 42);
        std::fs::rename(&replacement, &path).expect("atomic replace");

        let second = resolver.resolve(AGENT).expect("admitted").pubkey;
        assert_eq!(
            resolver.parse_count(),
            2,
            "a replaced file must force a re-read even inside the TTL"
        );
        assert_ne!(
            first, second,
            "the hub must serve the key the CURRENT snapshot names"
        );
    }

    /// The regression the issue asks for by name: a stale file stays refused
    /// after the cache lands. The parse is warm and the file has not moved —
    /// the only thing that can refuse it is the age re-check on the hit path.
    #[test]
    fn a_snapshot_that_expires_while_cached_is_refused_3504() {
        let dir = owner_only_dir();
        let path = dir.path().join("allow.json");
        // One second inside the ceiling: valid now, expired a moment later.
        write_snapshot(&path, MAX_CACHE_AGE_SECS - 1, 51);
        let resolver = ReloadingAllowlist::new(path.clone()).expect("arm");
        resolver.resolve(AGENT).expect("still inside the ceiling");
        assert_eq!(resolver.parse_count(), 1);

        // Age the WARM PARSE past the ceiling without touching the file, so the
        // reuse key still hits and the age gate is the only thing that can
        // refuse. White-box on purpose (rust-1.98 `TEST-01`): the wall clock
        // cannot be advanced, and this is precisely the path — a hit — that a
        // black-box test cannot reach deterministically.
        {
            let mut guard = resolver.cached.write().expect("write");
            let entry = guard.as_mut().expect("a parse was cached");
            entry.refreshed_at =
                (Utc::now() - chrono::Duration::seconds(MAX_CACHE_AGE_SECS + 1)).fixed_offset();
        }
        assert!(
            resolver.resolve(AGENT).is_err(),
            "a snapshot older than the ceiling must stay REFUSED even when its parse is warm"
        );
        assert_eq!(
            resolver.parse_count(),
            1,
            "the refusal must come from the age gate on the hit path, not from a re-parse"
        );
    }

    /// A snapshot whose mode is widened is refused IMMEDIATELY, even though
    /// the parse is fresh and the content did not change.
    #[test]
    fn a_downgraded_mode_is_refused_immediately_even_with_a_warm_parse_3504() {
        let dir = owner_only_dir();
        let path = dir.path().join("allow.json");
        write_snapshot(&path, 1, 61);
        let resolver = ReloadingAllowlist::new(path.clone()).expect("arm");
        resolver.resolve(AGENT).expect("admitted");
        assert_eq!(resolver.parse_count(), 1);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("widen");
        assert!(
            resolver.resolve(AGENT).is_err(),
            "a group- or world-readable snapshot must be refused on the spot"
        );
        assert_eq!(
            resolver.parse_count(),
            1,
            "the refusal must precede any read of the widened file"
        );

        // And restoring the mode restores service, so the refusal is about the
        // mode and not a latched failure.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
        resolver.resolve(AGENT).expect("admitted again");
    }

    /// A removed snapshot fails closed rather than serving the last parse.
    #[test]
    fn a_removed_snapshot_fails_closed_rather_than_serving_the_cache_3504() {
        let dir = owner_only_dir();
        let path = dir.path().join("allow.json");
        write_snapshot(&path, 1, 71);
        let resolver = ReloadingAllowlist::new(path.clone()).expect("arm");
        resolver.resolve(AGENT).expect("admitted");
        std::fs::remove_file(&path).expect("remove");
        assert!(
            resolver.resolve(AGENT).is_err(),
            "no file, no authority — the cache must not outlive the snapshot"
        );
    }

    /// The posture reports the age it observes, and calls an expired or
    /// missing snapshot what it is.
    #[test]
    fn the_posture_reports_snapshot_age_and_fails_closed_when_unreadable_3504() {
        let dir = owner_only_dir();
        let path = dir.path().join("allow.json");
        write_snapshot(&path, 5, 81);
        let fresh = SnapshotFreshness::observe(Some(&path));
        assert!(
            matches!(fresh.age_secs, Some(age) if (4..=7).contains(&age)),
            "expected an age near 5 s, got {:?}",
            fresh.age_secs
        );
        assert!(fresh.within_max_age);
        assert!(fresh.summary().contains("ceiling"));
        assert_eq!(fresh.to_json()["max_age_secs"], MAX_CACHE_AGE_SECS);
        assert_eq!(fresh.to_json()["within_max_age"], true);

        write_snapshot(&path, MAX_CACHE_AGE_SECS + 5, 81);
        let stale = SnapshotFreshness::observe(Some(&path));
        assert!(!stale.within_max_age);
        assert!(stale.summary().contains("REFUSED"));

        let absent = SnapshotFreshness::observe(None);
        assert_eq!(absent.age_secs, None);
        assert!(
            !absent.within_max_age,
            "no snapshot is not a fresh snapshot"
        );
        let unreadable = SnapshotFreshness::observe(Some(&dir.path().join("nope.json")));
        assert_eq!(unreadable.age_secs, None);
        assert!(!unreadable.within_max_age);
    }
}
