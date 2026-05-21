// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #983 — process-wide cache for [`crate::governance::Rule`]
//! lists keyed by [`crate::governance::AgentAction::kind`].
//!
//! ## Why this exists
//!
//! Pre-#983 every governance check (`check_agent_action*`) called
//! [`crate::governance::RuleEngine::load_for_action`] which in turn
//! called [`crate::governance::rules_store::list_enabled_by_kind`].
//! That helper prepares a SQL statement, executes it, deserializes
//! each row, AND runs Ed25519 signature verification on every signed
//! row (the L1-6 bypass-impossibility invariant). The substrate
//! issues a governance check on every memory write (store / link /
//! delete / archive / forget) — so the helper fires once per write
//! plus once per dispatched MCP / HTTP call that doesn't fast-path
//! out, totalling 0.5-3 ms of avoidable work per write under the
//! v0.7.0 typed-refusal envelope (#963) wire-up that landed in the
//! 259-commit ship-hardening bundle.
//!
//! ## Cache shape
//!
//! - `by_kind: RwLock<HashMap<&'static str, Arc<Vec<Rule>>>>` keyed
//!   on the canonical kind strings emitted by `AgentAction::kind()`
//!   (`"bash"`, `"filesystem_write"`, `"network_request"`,
//!   `"process_spawn"`, `"custom:<discriminator>"`).
//! - `get_or_load(conn, kind)` returns an `Arc<Vec<Rule>>` so callers
//!   share the snapshot without cloning the row data. The
//!   [`crate::governance::RuleEngine`] holds the `Arc` for the
//!   lifetime of a single check, then drops it.
//! - The Ed25519 signature verify happens INSIDE
//!   [`list_enabled_by_kind`] on the load path; the cache hit avoids
//!   it entirely until invalidation forces a reload.
//!
//! ## Invalidation
//!
//! Conservative: every write to `governance_rules`
//! ([`crate::governance::rules_store::insert`] /
//! [`crate::governance::rules_store::remove`] /
//! [`crate::governance::rules_store::update_signature`]) calls
//! [`RuleEngineCache::invalidate_all`]. The over-invalidation cost is
//! one cache miss per writer per kind ≈ the original behaviour;
//! readers between writes hit the cache.
//!
//! Per-kind invalidation could narrow the rebuild to just the kind
//! that changed, but the rules table is operator-edited at low
//! volume (rule installs are deliberate ops actions, not hot-path
//! writes) so the conservative full-clear stays correct + simple.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use anyhow::Result;
use rusqlite::Connection;

use crate::governance::rules_store::Rule;

/// Process-wide cache of `Vec<Rule>` keyed by `AgentAction::kind()`.
///
/// Cheap to clone (the cache itself is behind an `Arc` in the global
/// singleton). Construct with [`Self::new`] for tests; production
/// callers go through [`global`].
pub struct RuleEngineCache {
    by_kind: RwLock<HashMap<String, Arc<Vec<Rule>>>>,
}

impl RuleEngineCache {
    /// Construct an empty cache. Used by [`global`] (once) and by
    /// tests that need an isolated cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_kind: RwLock::new(HashMap::new()),
        }
    }

    /// Return the cached rule list for `kind`, loading via
    /// [`crate::governance::rules_store::list_enabled_by_kind`] on
    /// cache miss. The Ed25519 signature verify side-effect on the
    /// loader path runs on miss; cache hits skip it.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite error from `list_enabled_by_kind` on
    /// cache miss.
    pub fn get_or_load(&self, conn: &Connection, kind: &str) -> Result<Arc<Vec<Rule>>> {
        // Fast path: hold the read lock for the lookup + clone of
        // the Arc; drop the guard before any further work.
        if let Some(rules) = self
            .by_kind
            .read()
            .ok()
            .and_then(|guard| guard.get(kind).cloned())
        {
            return Ok(rules);
        }
        // Slow path: load + insert under the write lock. The Arc<Vec>
        // we return is cloned from the inserted entry so a concurrent
        // invalidate after this insert doesn't strand our caller with
        // a dropped snapshot.
        let rules = crate::governance::rules_store::list_enabled_by_kind(conn, kind)?;
        let arc = Arc::new(rules);
        if let Ok(mut guard) = self.by_kind.write() {
            // Re-check under the write lock — another thread may have
            // raced us to load. First-writer-wins; the loser's load
            // is discarded.
            let entry = guard
                .entry(kind.to_string())
                .or_insert_with(|| Arc::clone(&arc));
            return Ok(Arc::clone(entry));
        }
        // RwLock poison fallback — return the freshly-loaded snapshot
        // so the caller proceeds with correct data even when the
        // cache is unusable.
        Ok(arc)
    }

    /// Drop the cached entry for `kind`. Used when only one kind's
    /// rule list changes — currently no caller takes this path because
    /// the rules_store writers don't know the affected kind without
    /// inspecting the row, and [`Self::invalidate_all`] is simpler.
    pub fn invalidate(&self, kind: &str) {
        if let Ok(mut guard) = self.by_kind.write() {
            guard.remove(kind);
        }
    }

    /// Drop every cached entry. Used by the rules_store write paths
    /// (insert / remove / update_signature) so the next reader
    /// rebuilds against the post-write state.
    pub fn invalidate_all(&self) {
        if let Ok(mut guard) = self.by_kind.write() {
            guard.clear();
        }
    }

    /// Number of currently-cached entries — for test inspection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_kind
            .read()
            .map(|guard| guard.len())
            .unwrap_or_default()
    }

    /// Whether the cache is empty — for test inspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RuleEngineCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide singleton accessor.
///
/// Lazily initialised on first use. Always returns the same instance
/// so all governance checks across the daemon share one cache.
#[must_use]
pub fn global() -> &'static RuleEngineCache {
    static CACHE: OnceLock<RuleEngineCache> = OnceLock::new();
    CACHE.get_or_init(RuleEngineCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::rules_store::Rule;

    fn sample_rule(id: &str, kind: &str) -> Rule {
        Rule {
            id: id.to_string(),
            kind: kind.to_string(),
            matcher: "{}".to_string(),
            severity: "log".to_string(),
            reason: "test".to_string(),
            namespace: String::new(),
            created_by: "test".to_string(),
            created_at: 0,
            enabled: true,
            signature: None,
            attest_level: "unsigned".to_string(),
        }
    }

    #[test]
    fn invalidate_all_clears_every_entry_983() {
        let cache = RuleEngineCache::new();
        // Manually seed two kinds — `get_or_load` requires a DB connection,
        // so we go through the write lock directly for this test.
        {
            let mut g = cache.by_kind.write().unwrap();
            g.insert(
                "bash".to_string(),
                Arc::new(vec![sample_rule("r1", "bash")]),
            );
            g.insert(
                "filesystem_write".to_string(),
                Arc::new(vec![sample_rule("r2", "filesystem_write")]),
            );
        }
        assert_eq!(cache.len(), 2);
        cache.invalidate_all();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn invalidate_specific_kind_keeps_others_983() {
        let cache = RuleEngineCache::new();
        {
            let mut g = cache.by_kind.write().unwrap();
            g.insert(
                "bash".to_string(),
                Arc::new(vec![sample_rule("r1", "bash")]),
            );
            g.insert(
                "filesystem_write".to_string(),
                Arc::new(vec![sample_rule("r2", "filesystem_write")]),
            );
        }
        cache.invalidate("bash");
        assert_eq!(cache.len(), 1);
        let remaining = cache.by_kind.read().unwrap();
        assert!(remaining.contains_key("filesystem_write"));
        assert!(!remaining.contains_key("bash"));
    }

    #[test]
    fn global_singleton_is_stable_983() {
        let a = global() as *const RuleEngineCache;
        let b = global() as *const RuleEngineCache;
        assert_eq!(a, b, "global() must return the same singleton instance");
    }
}
