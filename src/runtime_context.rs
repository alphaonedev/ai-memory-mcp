// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.x (issue #1174 follow-up #1192 / #1196) — cross-surface
//! `RuntimeContext` for substrate state that spans the HTTP daemon,
//! the MCP stdio binary, and the CLI.
//!
//! ## Why this module exists
//!
//! Pre-#1192 / #1196 the substrate carried a handful of process-wide
//! `static` slots — webhook HMAC override, transcript decompression
//! cap, audit sink + sequence counter, session-recall tracker, X25519
//! keypair cache — that none of `AppState` (HTTP), the MCP
//! `Connection`, or the per-command CLI handlers could own jointly.
//! PR7 (#1192) and PR8 (#1196) on `release/v0.7.0` identified that the
//! correct refactor is a single `Arc<RuntimeContext>` that all three
//! surfaces can hold and that internally backs every former static.
//!
//! This module is that struct. The design preserves the existing
//! public surface (e.g. `crate::config::active_hooks_hmac_secret`,
//! `crate::audit::emit`, `crate::reranker::global_session_recall_tracker`)
//! — those accessors now delegate to the process-wide
//! [`RuntimeContext`] singleton. The wire / chain / cache semantics are
//! byte-for-byte unchanged; the storage merely moved from
//! `static FOO: ... = ...` to a field on [`RuntimeContext`].
//!
//! ## Singleton vs. injected instance
//!
//! [`RuntimeContext`] is a struct, not a global. Tests construct fresh
//! instances via [`RuntimeContext::default`] and exercise the typed
//! accessors directly; production code wires a single instance through
//! [`RuntimeContext::install_global`] at boot so the legacy free
//! functions (`crate::config::set_active_hooks_hmac_secret`,
//! `crate::audit::emit`, etc.) keep working without churning ~60
//! callsites across the codebase.
//!
//! The `global()` accessor returns `&'static RuntimeContext` (via a
//! `LazyLock`-style `OnceLock` seeded on first read). Install order
//! matters only at the very first read; once a context is installed it
//! sticks for the lifetime of the process, matching the prior
//! `OnceLock` / `RwLock<Option<...>>` semantics of every individual
//! extracted static.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// Cross-surface substrate state.
///
/// Held as `Arc<RuntimeContext>` by every long-lived runtime: HTTP
/// daemon `AppState`, MCP stdio dispatch, CLI command handlers. Fields
/// are read-mostly; mutable-config fields use `RwLock` for the rare
/// reload path, and the audit chain uses interior `Mutex` to keep emit
/// ordering atomic across producers (matching the pre-#1192
/// `audit::SINK` lock posture).
#[derive(Debug, Default)]
pub struct RuntimeContext {
    /// v0.7.0 K7 — resolved webhook HMAC override. `None` when the
    /// operator has not configured `[hooks.subscription] hmac_secret`,
    /// in which case per-subscription secrets carry the signing key.
    /// Mutable so the K7 integration tests can flip mid-process; in
    /// production this is set once at boot from
    /// `AppConfig::effective_hooks_hmac_secret`.
    pub hooks_hmac_secret: RwLock<Option<String>>,

    /// I1 cap (#628 agent-3 follow-up) — per-call transcript
    /// decompression cap. `None` means "use the compiled default"
    /// (`crate::transcripts::MAX_DECOMPRESSED_BYTES`). Operators raise
    /// the cap via `[transcripts] max_decompressed_bytes = ...` and
    /// boot writes the resolved value here.
    pub max_decompressed_bytes: RwLock<Option<usize>>,

    /// V-4 audit chain state — the load-bearing tamper-evidence
    /// substrate. See [`AuditState`] for the chain invariants the
    /// `crate::audit::*` public surface preserves.
    pub audit: Arc<AuditState>,

    /// Per-session recall tracker (Form 2 #518 / #1091). Tracks the
    /// last N memory ids returned to each `session_id` so the recall
    /// hot path can apply a +0.05 boost to repeat candidates. Process-
    /// global by design — operator restart clears every session's
    /// recent set.
    pub recall_tracker: Arc<crate::reranker::SessionRecallTracker>,

    /// Per-agent X25519 keypair cache. Populated lazily by
    /// `crate::encryption::get_or_create_keypair` on first encrypt /
    /// decrypt for an `agent_id`; persists for the lifetime of the
    /// process. A future issue will swap this for an on-disk store;
    /// the in-memory shape lets the encryption substrate land without
    /// forcing a key-rotation tool design decision in the same patch.
    pub keypair_cache: Arc<Mutex<HashMap<String, crate::encryption::Keypair>>>,
}

/// V-4 audit chain state. Owns the same `(sink, sequence)` pair the
/// pre-#1192 `src/audit.rs` module-level statics owned; the public
/// `crate::audit::*` functions delegate here.
///
/// The chain invariants this struct preserves byte-for-byte:
///
/// 1. `sink` is wrapped in `RwLock<Option<Arc<AuditSink>>>` so the
///    `init` path can swap the sink atomically and `emit` can clone the
///    `Arc` without holding the lock for the file write.
/// 2. `sequence` is an `AtomicU64` so concurrent emit threads agree on
///    a monotonic counter; it is seeded from the trailing record's
///    sequence on `init` (F2 fix — sequence survives daemon restart).
/// 3. The `AuditSink::inner` mutex serialises the hash-chain head
///    update + line write, so the chain is consistent across producer
///    threads.
#[derive(Debug, Default)]
pub struct AuditState {
    /// Process-wide audit sink. `None` when audit is disabled. Wrapped
    /// in `RwLock` (rather than `OnceLock`) so tests can swap in an
    /// in-memory sink between cases without leaking state across runs.
    pub sink: RwLock<Option<Arc<crate::audit::AuditSink>>>,
    /// Per-process monotonic sequence counter. Starts at 0; first emit
    /// produces sequence 1. `init` reseeds from the trailing record's
    /// sequence so `audit verify` doesn't trip on a restart-induced
    /// reset (F2 round-2 fix).
    pub sequence: AtomicU64,
}

// ---------------------------------------------------------------------------
// Process-wide singleton
// ---------------------------------------------------------------------------

/// Process-wide [`RuntimeContext`] handle. Seeded on first
/// [`global()`] call (lazy-init via [`RuntimeContext::default`]) or
/// explicitly installed at boot via [`install_global`].
///
/// Stored as `Arc<RuntimeContext>` so callers can either borrow the
/// singleton via [`RuntimeContext::global`] (free) or clone the `Arc`
/// via [`RuntimeContext::global_arc`] when they need to keep a typed
/// handle on a struct field (e.g. `AppState::runtime`). Arc clones are
/// cheap (refcount increment) so neither posture pays an allocation.
static GLOBAL: OnceLock<Arc<RuntimeContext>> = OnceLock::new();

impl RuntimeContext {
    /// Install a custom [`RuntimeContext`] as the process-wide singleton.
    /// Idempotent in the same sense as `OnceLock::set` — the first
    /// install wins; subsequent calls are silently ignored (the
    /// returned `Result` is suppressed to keep the boot path
    /// infallible against an accidental double-install).
    ///
    /// Boot code typically does NOT call this — the lazy-init in
    /// [`global()`] is sufficient, and the legacy `set_*` accessors
    /// (`crate::config::set_active_hooks_hmac_secret` etc.) populate
    /// the inner fields via interior mutability. The hook exists for
    /// the rare test that wants to pin a non-default starting state.
    pub fn install_global(ctx: RuntimeContext) {
        // Drop the Result — last-writer-loses matches the prior
        // `OnceLock::set` posture used by the per-static
        // `OnceLock::get_or_init` calls this struct replaced.
        let _ = GLOBAL.set(Arc::new(ctx));
    }

    /// Return a borrowed reference to the process-wide
    /// [`RuntimeContext`]. Seeds the singleton with
    /// [`RuntimeContext::default`] on first call so callers never see
    /// `None` — same `get_or_init` semantics as the per-static
    /// `OnceLock`s this struct replaced.
    ///
    /// The returned reference is `&'static` because the singleton
    /// `Arc<RuntimeContext>` lives inside a process-wide `OnceLock`
    /// that itself never drops — once seeded, the `Arc` (and the
    /// `RuntimeContext` it owns) outlives the entire process.
    #[must_use]
    pub fn global() -> &'static RuntimeContext {
        Self::global_arc_ref()
    }

    /// Internal — return a reference to the `Arc<RuntimeContext>`
    /// stored in the singleton slot. Auto-derefed by [`global()`].
    fn global_arc_ref() -> &'static Arc<RuntimeContext> {
        GLOBAL.get_or_init(|| Arc::new(RuntimeContext::default()))
    }

    /// Return a cloned `Arc<RuntimeContext>` to the process-wide
    /// singleton. Cheap (refcount increment, no allocation). Used by
    /// long-lived runtime structs (notably `AppState::runtime`) that
    /// want to keep a typed handle on a field rather than re-grabbing
    /// the global via [`RuntimeContext::global`] on every access.
    #[must_use]
    pub fn global_arc() -> Arc<RuntimeContext> {
        Arc::clone(Self::global_arc_ref())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_context_default_is_constructible() {
        // Pin: every field has a sensible default that lets unit
        // tests exercise the struct without booting the daemon.
        let ctx = RuntimeContext::default();
        assert!(ctx.hooks_hmac_secret.read().unwrap().is_none());
        assert!(ctx.max_decompressed_bytes.read().unwrap().is_none());
        assert!(ctx.audit.sink.read().unwrap().is_none());
        assert_eq!(
            ctx.audit.sequence.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(ctx.recall_tracker.session_count(), 0);
        assert_eq!(ctx.keypair_cache.lock().unwrap().len(), 0);
    }

    #[test]
    fn runtime_context_global_returns_stable_handle() {
        // Pin: two reads of `global()` from the same process MUST
        // return the same backing struct so the legacy free-fn
        // surface keeps observing the same mutations.
        let a = RuntimeContext::global() as *const RuntimeContext;
        let b = RuntimeContext::global() as *const RuntimeContext;
        assert_eq!(a, b, "global() must return a stable reference");
    }

    #[test]
    fn runtime_context_audit_state_default() {
        // Pin: AuditState defaults match the prior module-level
        // `static SINK: RwLock::new(None)` + `static SEQUENCE:
        // AtomicU64::new(0)` shape.
        let audit = AuditState::default();
        assert!(audit.sink.read().unwrap().is_none());
        assert_eq!(audit.sequence.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
