// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #991 — per-instance cache for [`crate::governance::Rule`]
//! lists keyed by [`crate::governance::AgentAction::kind`].
//!
//! ## Why this exists
//!
//! Pre-#991 every governance check (`check_agent_action*`) called
//! [`crate::governance::RuleEngine::load_for_action`] which in turn
//! called [`crate::governance::rules_store::list_enabled_by_kind`].
//! That helper prepares a SQL statement, executes it, deserializes
//! each row, AND runs Ed25519 signature verification on every signed
//! row (the L1-6 bypass-impossibility invariant). The substrate
//! issues a governance check on every memory write (store / link /
//! delete / archive / forget) — so the helper fires once per write
//! plus once per dispatched MCP / HTTP call that doesn't fast-path
//! out, totalling 0.5-3 ms of avoidable work per write under the
//! v0.7.0 typed-refusal envelope (#963) wire-up.
//!
//! ## Why this is per-instance, not process-wide (the #990 lesson)
//!
//! #983 shipped a process-wide singleton keyed on
//! [`crate::governance::AgentAction::kind`] alone. The cache was
//! reverted via #990 because multi-connection integration tests
//! (`tests/governance_a2a_rules.rs::disabled_rule_at_peer_b_does_not_enforce_even_if_enabled_at_a`)
//! exposed cross-connection key collisions: peer_b's load polluted
//! peer_a's subsequent lookup. In production this was invisible
//! (single daemon connection) but reverting was necessary to restore
//! test correctness on the v0.7.0 ship-readiness gate.
//!
//! #991 takes the per-instance approach: the cache is *owned* by the
//! Connection-bearing context (HTTP `AppState`, MCP main loop, the
//! storage / wire-check hook installers). Multiple Connections in the
//! same process get multiple independent caches by construction —
//! cross-conn poisoning is structurally impossible. The `Arc<RuleCache>`
//! is shared by reference, not via a global, so the cache lifetime
//! tracks the daemon (or test fixture) that owns it. When the owner
//! drops, the cache drops with it.
//!
//! ## Cache shape
//!
//! - `by_kind: RwLock<HashMap<String, Arc<Vec<Rule>>>>` keyed on the
//!   canonical kind strings emitted by `AgentAction::kind()`
//!   (`"bash"`, `"filesystem_write"`, `"network_request"`,
//!   `"process_spawn"`, `"custom:<discriminator>"`).
//! - `get_or_load(conn, kind)` returns an `Arc<Vec<Rule>>` so callers
//!   share the snapshot without cloning the row data. The
//!   [`crate::governance::RuleEngine`] holds the `Arc` for the
//!   lifetime of a single check, then drops it.
//! - The Ed25519 signature verify happens INSIDE
//!   [`crate::governance::rules_store::list_enabled_by_kind`] on the
//!   load path; the cache hit avoids it entirely until invalidation
//!   forces a reload.
//!
//! ## Invalidation — honest contract (post-#1015 doc-drift fix)
//!
//! **No automatic invalidation on rule writes.** The cache is
//! **invalidate-on-restart-only** at v0.7.0:
//!
//! - The substrate-internal rule-write surface
//!   ([`crate::governance::rules_store::insert`] /
//!   [`crate::governance::rules_store::remove`] /
//!   [`crate::governance::rules_store::set_enabled`] /
//!   [`crate::governance::rules_store::update_signature`]) does NOT
//!   hold an `Arc<RuleCache>` reference and does NOT call
//!   [`RuleCache::invalidate_all`] after a write.
//! - Rule writes happen exclusively via the CLI (`ai-memory rules
//!   …`), which runs as a separate process from any live daemon. The
//!   daemon's cache cannot observe a sibling-process rule write at
//!   all, regardless of whether `invalidate_all` is wired in
//!   intra-process — same effective contract.
//! - The daemon does NOT expose an HTTP / MCP rule-write surface at
//!   v0.7.0. If a future release adds one, the wire should call
//!   [`RuleCache::invalidate_all`] explicitly before returning to the
//!   caller (or thread an `Arc<RuleCache>` through the rules_store
//!   mutators — #1015 tracks the option).
//!
//! **What this means in practice:** after `ai-memory rules add` /
//! `enable` / `disable` / `remove` from the CLI, the operator must
//! restart any running `ai-memory serve` (or MCP daemon) for the
//! change to take effect on the daemon's cached rule set. This
//! matches the pre-#990 #983 contract (rule changes via a separate
//! process require daemon restart). The operator-edited rule volume
//! is low enough that this is acceptable; the operator UI
//! (`ai-memory rules list`) reads directly from SQLite so the
//! source-of-truth is always current.
//!
//! [`RuleCache::invalidate`] and [`RuleCache::invalidate_all`] remain
//! exposed for tests (which want a fresh cache per fixture) and for
//! a future `--reload-rules` SIGHUP / admin endpoint that would call
//! them explicitly. They are NOT load-bearing on the v0.7.0 hot
//! write path.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rusqlite::Connection;

use crate::governance::rules_store::Rule;

/// v0.7.0 #1020 (Agent-1 #6) — typed error for the substrate-public
/// [`RuleCache::get_or_load`] surface. Per CLAUDE.md #964
/// audit-closure rule, substrate-public APIs MUST use typed errors;
/// pre-#1020 `get_or_load` returned `anyhow::Result<Arc<Vec<Rule>>>`,
/// leaking the untyped error type across the substrate boundary at a
/// brand-new (#991) API.
///
/// Variants:
///
/// - [`RuleCacheError::Load`] wraps a downstream load failure from
///   [`crate::governance::rules_store::list_enabled_by_kind`]. The
///   inner `anyhow::Error` preserves the rusqlite + context chain
///   for diagnostics; downstream code paths that need the chain
///   call `.0` directly or `From::<RuleCacheError>::from` into
///   their own anyhow surface.
/// - [`RuleCacheError::Poisoned`] surfaces an `RwLock` poison —
///   previously swallowed with a silent fallback to the
///   freshly-loaded snapshot. Surfacing it lets callers decide
///   whether to refuse, retry, or rebuild the cache.
#[derive(Debug)]
pub enum RuleCacheError {
    /// `list_enabled_by_kind` failed (rusqlite error or downstream
    /// signature-verification panic).
    Load(anyhow::Error),
    /// The inner `RwLock` is poisoned (another thread panicked
    /// while holding it). The legacy fallback returned the freshly-
    /// loaded snapshot; callers can still do so via
    /// [`RuleCacheError::is_poisoned`] but the typed signal lets
    /// observability paths surface the panic.
    Poisoned,
}

impl std::fmt::Display for RuleCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(e) => write!(f, "rule_cache load failed: {e:#}"),
            Self::Poisoned => write!(f, "rule_cache: RwLock poisoned"),
        }
    }
}

impl std::error::Error for RuleCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Load(e) => Some(e.as_ref()),
            Self::Poisoned => None,
        }
    }
}

impl From<anyhow::Error> for RuleCacheError {
    fn from(e: anyhow::Error) -> Self {
        Self::Load(e)
    }
}

// Note: `From<RuleCacheError> for anyhow::Error` is provided by
// anyhow's blanket `impl<E: StdError + Send + Sync + 'static>
// From<E> for anyhow::Error`, since `RuleCacheError: std::error::Error`.
// Callers using `?` against an `anyhow::Result` automatically
// upcast — no manual conversion needed.

impl RuleCacheError {
    /// Returns true for the [`RuleCacheError::Poisoned`] variant.
    /// Callers that want the legacy "silent fallback" posture can
    /// branch on this to recover the freshly-loaded snapshot from
    /// a parallel `list_enabled_by_kind` call.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned)
    }
}

/// Per-instance cache of `Vec<Rule>` keyed by `AgentAction::kind()`.
///
/// The cache is owned by a Connection-bearing context (HTTP
/// `AppState`, MCP main loop, or the substrate `GOVERNANCE_PRE_WRITE`
/// / `GOVERNANCE_PRE_ACTION` hook installer that captures a
/// long-lived Connection). Pass `&RuleCache` (or wrap in `Arc` for
/// shared ownership) to the cached entry points
/// (`check_agent_action_cached`, etc.). Cache hits return an
/// `Arc<Vec<Rule>>` clone — no row data is cloned on the fast path.
#[derive(Debug, Default)]
pub struct RuleCache {
    by_kind: RwLock<HashMap<String, Arc<Vec<Rule>>>>,
}

impl RuleCache {
    /// Construct an empty cache. Cheap; safe to call per-test.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached rule list for `kind`, loading via
    /// [`crate::governance::rules_store::list_enabled_by_kind`] on
    /// cache miss. The Ed25519 signature verify side-effect on the
    /// loader path runs on miss; cache hits skip it.
    ///
    /// v0.7.0 #1020 (Agent-1 #6) — returns the typed
    /// [`RuleCacheError`] enum at the substrate-public boundary
    /// (was bare `anyhow::Result` pre-#1020).
    /// `RuleCacheError: Into<anyhow::Error>` is implemented so
    /// existing anyhow-chained callers can keep their `?` operator
    /// with no signature changes.
    ///
    /// # Errors
    ///
    /// - [`RuleCacheError::Load`] wraps any error from
    ///   `list_enabled_by_kind` (rusqlite errors, signature-verify
    ///   panics).
    /// - [`RuleCacheError::Poisoned`] indicates the inner `RwLock`
    ///   is poisoned by a prior thread panic. The legacy fallback
    ///   returned a fresh snapshot anyway; callers wanting that
    ///   posture can branch via [`RuleCacheError::is_poisoned`] and
    ///   re-call `list_enabled_by_kind` directly.
    #[inline]
    pub fn get_or_load(
        &self,
        conn: &Connection,
        kind: &str,
    ) -> std::result::Result<Arc<Vec<Rule>>, RuleCacheError> {
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
        let rules =
            crate::governance::rules_store::list_enabled_by_kind(conn, kind).map_err(RuleCacheError::Load)?;
        let arc = Arc::new(rules);
        if let Ok(mut guard) = self.by_kind.write() {
            // #1019 — check for an existing entry first (e.g., the
            // loser of a race) BEFORE allocating a fresh String via
            // `kind.to_string()`. Pre-#1019 the `entry(kind.to_string())`
            // call allocated on every slow-path invocation, including
            // the race-loser case where the allocated String was
            // immediately dropped. The contains_key probe avoids the
            // allocation entirely on the common race-loser path.
            if let Some(existing) = guard.get(kind) {
                return Ok(Arc::clone(existing));
            }
            // No race — we're the first to insert.
            let entry = guard
                .entry(kind.to_string())
                .or_insert_with(|| Arc::clone(&arc));
            return Ok(Arc::clone(entry));
        }
        // v0.7.0 #1020 — RwLock poison surfaces as a typed
        // `RuleCacheError::Poisoned`. The legacy fallback returned
        // the freshly-loaded snapshot silently; callers wanting that
        // posture can recover via `err.is_poisoned()` and re-call
        // `list_enabled_by_kind` directly. Surfacing the poison lets
        // observability paths (metrics counter, tracing::error) see
        // the prior thread panic.
        Err(RuleCacheError::Poisoned)
    }

    /// Drop the cached entry for `kind`. Currently no caller takes
    /// this path because the rules_store writers don't know the
    /// affected kind without inspecting the row;
    /// [`Self::invalidate_all`] is simpler.
    #[inline]
    pub fn invalidate(&self, kind: &str) {
        if let Ok(mut guard) = self.by_kind.write() {
            guard.remove(kind);
        }
    }

    /// Drop every cached entry. Used by the rules_store write paths
    /// (insert / remove / set_enabled / update_signature) so the next
    /// reader rebuilds against the post-write state.
    #[inline]
    pub fn invalidate_all(&self) {
        if let Ok(mut guard) = self.by_kind.write() {
            guard.clear();
        }
    }

    /// Number of currently-cached entries — for test inspection.
    ///
    /// **#1018 (2026-05-21):** poison semantics changed from "lie as
    /// empty" to "return None via [`Self::len_checked`]". The legacy
    /// `len()` returns `0` on poison (matches the pre-#1018 contract
    /// some tests still depend on); call sites that need to
    /// distinguish "empty" from "poisoned" use `len_checked`.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.by_kind
            .read()
            .map(|guard| guard.len())
            .unwrap_or_default()
    }

    /// **#1018 (2026-05-21):** poison-aware variant of [`Self::len`].
    /// Returns `Some(len)` on a healthy lock, `None` if the `RwLock`
    /// is poisoned. Pre-#1018 a poisoned cache reported `len() == 0`
    /// and `is_empty() == true` — invisible to callers and test
    /// assertions. Operator inspection paths + future health-probe
    /// surfaces should consume this variant; legacy paths keep `len()`.
    #[must_use]
    pub fn len_checked(&self) -> Option<usize> {
        self.by_kind.read().ok().map(|guard| guard.len())
    }

    /// Whether the cache is empty — for test inspection.
    ///
    /// **#1018:** the legacy contract treats poison as "empty" (returns
    /// `true`). Use [`Self::is_empty_checked`] when the distinction
    /// matters.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// **#1018 (2026-05-21):** poison-aware variant of [`Self::is_empty`].
    /// Returns `Some(true)` when the cache is healthy AND empty,
    /// `Some(false)` when healthy AND populated, `None` when the
    /// `RwLock` is poisoned. Operator inspection paths use this.
    #[must_use]
    pub fn is_empty_checked(&self) -> Option<bool> {
        self.by_kind.read().ok().map(|guard| guard.is_empty())
    }
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
    fn invalidate_all_clears_every_entry_991() {
        let cache = RuleCache::new();
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
    fn invalidate_specific_kind_keeps_others_991() {
        let cache = RuleCache::new();
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
    fn cross_instance_isolation_no_poisoning_991() {
        // The #990 revert reason: a process-wide cache keyed only on
        // `kind` poisoned multi-connection tests. Two `RuleCache`
        // instances must not share entries — pinned here so any
        // future refactor that re-introduces global state surfaces
        // immediately.
        let cache_a = RuleCache::new();
        let cache_b = RuleCache::new();
        {
            let mut g = cache_a.by_kind.write().unwrap();
            g.insert(
                "filesystem_write".to_string(),
                Arc::new(vec![sample_rule("peer-a-r", "filesystem_write")]),
            );
        }
        assert_eq!(cache_a.len(), 1);
        // cache_b never saw the insert — strict isolation.
        assert_eq!(cache_b.len(), 0);
    }

    #[test]
    fn rule_cache_error_implements_std_error_1020() {
        // v0.7.0 #1020 — pin the typed-error contract: RuleCacheError
        // implements std::error::Error, displays the inner anyhow
        // chain on Load, and is auto-upcastable into anyhow::Error
        // via the std::error::Error blanket impl.
        let load_err: RuleCacheError =
            anyhow::anyhow!("synthetic rusqlite failure").into();
        assert!(matches!(load_err, RuleCacheError::Load(_)));
        assert!(!load_err.is_poisoned());
        // Display surfaces the inner chain.
        let display = format!("{load_err}");
        assert!(
            display.contains("rule_cache load failed") && display.contains("synthetic rusqlite failure"),
            "#1020: Load Display MUST surface the wrapped anyhow chain; got {display}"
        );

        let poison_err = RuleCacheError::Poisoned;
        assert!(poison_err.is_poisoned());
        assert!(format!("{poison_err}").contains("RwLock poisoned"));

        // Auto-upcast into anyhow::Error via the blanket impl on
        // std::error::Error — confirms `?` against an anyhow::Result
        // still works for callers post-#1020.
        let upcast: anyhow::Error = poison_err.into();
        assert!(format!("{upcast:#}").contains("RwLock poisoned"));
    }

    #[test]
    fn dropped_instance_drops_entries_991() {
        // The original #983 design had a process-wide singleton that
        // never freed entries until process exit. The per-instance
        // design must let entries drop when the owner drops.
        let weak;
        {
            let cache = RuleCache::new();
            let entry = Arc::new(vec![sample_rule("r1", "bash")]);
            weak = Arc::downgrade(&entry);
            cache
                .by_kind
                .write()
                .unwrap()
                .insert("bash".to_string(), entry);
            assert!(weak.upgrade().is_some(), "entry alive while cache alive");
        }
        // `cache` dropped → its `HashMap` dropped → the inner
        // `Arc<Vec<Rule>>` ref count drops to zero → `Weak::upgrade`
        // returns None.
        assert!(
            weak.upgrade().is_none(),
            "cache drop must release Arc<Vec<Rule>> entries"
        );
    }
}
