// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Store-path agent attestation glue (#626 Layer-3, Task 1.3 / C4).
//!
//! Ties the C1-C4 primitives into a single surface the write paths call:
//!
//! - C1 [`crate::identity::sign::SignableWrite`] — the signed surface.
//! - C3 [`crate::db::agent_pubkey`] / [`crate::store::MemoryStore::agent_pubkey`]
//!   — the bound key the signature is checked against.
//! - C4 [`crate::identity::verify::attest_write`] — the decision gate.
//!
//! The two public wrappers ([`stamp_attestation_sync`] for the CLI's
//! direct `rusqlite::Connection` path and [`stamp_attestation_async`] for
//! the MCP/HTTP `MemoryStore` path) resolve the bound key, run the gate,
//! and stamp `metadata.attest_level` on the `Memory` before it is
//! persisted. Both delegate to the I/O-free [`stamp_attestation`] core so
//! the decision logic is unit-tested without a database.
//!
//! # Surface-scoped default (v1.0, #1985)
//!
//! The STORE-path default for `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is
//! *surface-scoped*. With the env unset, an unsigned write is REJECTED only
//! on the HTTP direct-write surface ([`WriteSurface::HttpDirect`] —
//! `POST /api/v1/memories` + `/memories/bulk`); on the MCP and CLI surfaces
//! ([`WriteSurface::Mcp`] / [`WriteSurface::Cli`]) an unsigned write is the
//! permissive operator-as-actor path (#1621/#1675) and lands unstamped (a
//! bare `claimed`-level write). The compiled default is resolved by
//! [`require_agent_attestation_for`].
//!
//! This corrects the v0.9.0 #1751 default, which required attestation on
//! *every* surface — an unsatisfiable posture on MCP hosts (no MCP client
//! can construct/sign the canonical [`SignableWrite`] envelope), the #1981
//! break. Env still wins over the compiled default: `=1`/`=true` forces
//! strict on every surface (the v0.9.0 posture) and `=0`/`=false` forces
//! permissive on every surface (the v0.8 posture). A *presented* signature
//! that fails to verify is ALWAYS rejected (see
//! [`crate::identity::verify::attest_write`]) on every surface regardless of
//! the flag.
//!
//! SCOPE: this gate covers the direct CLI/MCP/HTTP store surfaces only.
//! The federation receive path attests via the per-peer authorship
//! allowlist (`resolve_inbound_attribution`, #1464), NOT this flag — the
//! flip does not change the network boundary. Curator/autonomy self-writes
//! go through the SAL `store()` surface (`CallerContext::for_admin`) and
//! never traverse this gate.

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::identity::sign::SignableWrite;
use crate::identity::verify::AttestLevel;
use crate::models::Memory;

/// Bounded freshness window (seconds) for a remote-caller-supplied
/// `created_at` on a *signed* store (#626 Layer-3, C7).
///
/// The signed [`SignableWrite`] envelope commits to `created_at`, which the
/// server normally stamps with `now()`. A remote signer therefore cannot
/// predict it and must supply the timestamp it actually signed. The server
/// adopts that value verbatim only when it falls within ±this many seconds
/// of `now()` — bounding both replay (a stale timestamp) and post-dating (a
/// future timestamp) while leaving room for ordinary clock skew + transit.
pub const ATTEST_CREATED_AT_SKEW_SECS: i64 = 300;

/// #3422 (data-integrity, cross-backend signature stability) — canonicalize a
/// `created_at` into the ONE byte-form BOTH storage backends persist and return
/// verbatim.
///
/// The divergence this closes: [`SignableWrite`] commits to `created_at` as
/// TEXT, and every re-verification (the store gate itself, and
/// `federation_receive::apply_inbound_write_attestation` on a relayed row)
/// re-derives the envelope from the PERSISTED row. SQLite stores `created_at`
/// in a `TEXT` column and returns the attested string byte-for-byte; postgres
/// stores it in `TIMESTAMPTZ` (microsecond int8) and re-renders the readback
/// through `chrono::DateTime::<Utc>::to_rfc3339()`. So a write attested with
/// `"2026-09-01T12:00:00Z"` (or with chrono's 9-digit nanosecond rendering)
/// comes back out of postgres as `"2026-09-01T12:00:00+00:00"` — different
/// bytes, a different canonical CBOR pre-image, and an Ed25519 signature that
/// can never be re-derived from the row again. The receive path then reads the
/// author's genuine signature as FORGED and SKIPS the row: silent, unrecoverable
/// data loss on a value the peer sent correctly.
///
/// The canonical form is `parse-as-RFC3339 → UTC → truncate to microseconds →
/// to_rfc3339()`, i.e. chrono's `SecondsFormat::AutoSi` fractional digits with
/// the `+00:00` offset. That is *exactly* what the postgres readback emits
/// (`store/postgres.rs` maps every `created_at` column through `to_rfc3339()`),
/// so a string equal to its own canonical form survives BOTH backends
/// unchanged: sqlite stores the bytes verbatim, and postgres truncates nothing
/// it has not already truncated and re-renders identically.
///
/// This deliberately differs from #3281's `storage::canonicalize_valid_until_stamp`,
/// which renders the `Z` (zulu) suffix: `valid_until`'s audit-leaf pre-image is
/// derived from the canonical STRING on both backends (never from a DB
/// readback), so #3281 was free to pick the wire-friendlier `Z`. `created_at`
/// has no such freedom — the postgres readback IS the pre-image, and it emits
/// `+00:00`. Rendering `Z` here would re-introduce the very divergence this
/// closes.
///
/// Returns `None` for an unparseable timestamp (the caller refuses; a value
/// postgres would reject at its `::TIMESTAMPTZ` bind must never enter a signed
/// envelope).
#[must_use]
pub fn canonicalize_attested_created_at(raw: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| canonical_created_at_stamp(dt.with_timezone(&chrono::Utc)))
}

/// #3422 — the ONE rendering of an instant, shared by
/// [`canonicalize_attested_created_at`], [`now_attestable_rfc3339`] and the
/// signed-write funnels, so no caller can drift from the storage-stable form.
///
/// Microsecond truncation matches what `TIMESTAMPTZ` durably keeps; `to_rfc3339`
/// (`SecondsFormat::AutoSi`, `+00:00`) matches what the postgres readback
/// re-renders.
#[must_use]
pub(crate) fn canonical_created_at_stamp(instant: chrono::DateTime<chrono::Utc>) -> String {
    crate::storage::truncate_to_microseconds(instant).to_rfc3339()
}

/// #3422 — is `raw` byte-identical to its own canonical form, i.e. will BOTH
/// backends return exactly these bytes after a store/read round-trip?
///
/// This is the fail-closed predicate the signing and signature-adoption funnels
/// gate on: a `created_at` that fails it CANNOT carry a re-derivable signature
/// on postgres, so no signature is ever minted over it and no presented
/// signature is ever accepted for it.
#[must_use]
pub fn created_at_is_storage_stable(raw: &str) -> bool {
    canonicalize_attested_created_at(raw).is_some_and(|canonical| canonical == raw)
}

/// #3422 — `now` in the one storage-stable `created_at` form, for every write
/// funnel that mints a row which may later be signed (directly, or by the
/// federated-consolidate self-attestation on the read-back row).
///
/// `chrono::Utc::now().to_rfc3339()` renders nanoseconds on Linux; postgres
/// `TIMESTAMPTZ` cannot store them, so a row stamped that way is unsignable on
/// a postgres deployment (and a sqlite-authored one becomes unverifiable the
/// moment it federates to a postgres peer).
#[must_use]
pub fn now_attestable_rfc3339() -> String {
    canonical_created_at_stamp(chrono::Utc::now())
}

/// The API surface a store-path write arrived on (#1985).
///
/// The compiled default for `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is
/// *surface-scoped*: with the env unset, only [`Self::HttpDirect`] requires
/// attestation. [`Self::Mcp`] and [`Self::Cli`] are the operator-as-actor
/// path (#1621/#1675) — the MCP host / shell user IS the operator and has no
/// way to construct and sign the canonical [`SignableWrite`] envelope — so
/// their compiled default is permissive. Scope is chosen by the *API
/// surface* the write entered on, NEVER by transport or bind address: a
/// postgres deployment that proxies MCP through the HTTP daemon still
/// classifies those writes as [`Self::Mcp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSurface {
    /// HTTP direct-write handlers: `POST /api/v1/memories` and
    /// `POST /api/v1/memories/bulk`. Attestation is REQUIRED by default
    /// (fail-closed) — an unauthenticated network client is not the
    /// operator, so an unsigned direct write is rejected unless the operator
    /// opts out with `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`.
    HttpDirect,
    /// MCP `memory_store` dispatch. Permissive by default (operator-as-actor,
    /// #1621/#1675): an MCP host cannot sign the canonical envelope, so an
    /// unsigned write lands as a bare `claimed`-level write.
    Mcp,
    /// CLI `ai-memory store`. Permissive by default (operator-as-actor): the
    /// human at the shell is the operator. `store --sign` still upgrades a
    /// write to `agent_attested` when a bound keypair is present.
    Cli,
}

/// Resolve whether a store-path write on `surface` must be attested (#1985).
///
/// Tri-state read of `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`:
///
/// | env value            | `HttpDirect` | `Mcp` / `Cli` |
/// |----------------------|--------------|---------------|
/// | `1` / `true`         | required     | required      |
/// | `0` / `false`        | permissive   | permissive    |
/// | unset / unrecognized | required     | permissive    |
///
/// Env still wins over the compiled default — the standard
/// `CLI flag > env > config > compiled default` ladder. Forged-signature
/// rejection is unconditional on every surface regardless of this value (see
/// [`crate::identity::verify::attest_write`]).
///
/// SCOPE: direct CLI/MCP/HTTP store writes only; the federation receive
/// boundary attests via the peer-authorship allowlist
/// (`resolve_inbound_attribution`, #1464), not this flag.
#[must_use]
pub fn require_agent_attestation_for(surface: WriteSurface) -> bool {
    resolve_require_agent_attestation(
        std::env::var(ENV_REQUIRE_AGENT_ATTESTATION).ok().as_deref(),
        surface,
    )
}

/// Single SSOT literal for the tri-state store-path attestation knob so the
/// env name is not scattered across sites (pm-v3.1 no-hardcoded-literal).
pub const ENV_REQUIRE_AGENT_ATTESTATION: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";

/// True iff `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is set to an explicit
/// truthy value (`1`/`true`), i.e. attestation is mandated on EVERY write
/// surface (global-strict), as opposed to the surface-scoped compiled
/// default (HTTP-direct strict, MCP/CLI permissive).
///
/// This distinguishes the global-strict posture from the surface default so
/// (a) the [`crate::identity::verify::AttestError::AttestationRequired`]
/// refusal message can name the accurate posture (#3024), and (b) the
/// memory-creating surfaces that present NO caller signature
/// (`entity_register` / `reflect` / `consolidate`) can refuse only when the
/// operator has GLOBALLY mandated attestation (#3014). Those surfaces have
/// no signature channel, so applying the HTTP-direct surface default would
/// permanently brick them; they refuse only under this explicit global
/// mandate and otherwise land `attest_level="claimed"`, exactly like an
/// unsigned MCP/CLI store.
#[must_use]
pub fn global_strict_attestation_enabled() -> bool {
    matches!(
        std::env::var(ENV_REQUIRE_AGENT_ATTESTATION).ok().as_deref(),
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true")
    )
}

/// Stable refusal string for a memory-creating surface that presents no
/// caller signature (`entity_register` / `reflect` / `consolidate`) when
/// global-strict attestation is engaged. Carries the `ATTESTATION_FAILED`
/// slug so HTTP handlers can map it to `403` (mirroring the store path).
pub const ATTESTATION_REFUSED_UNSIGNED_SURFACE: &str = "ATTESTATION_FAILED: agent attestation is required \
     (AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1) but this surface presents no caller \
     signature and cannot attest — the write is refused. Set \
     AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 (or unset) to restore the permissive \
     posture, under which the write lands attest_level=\"claimed\".";

/// Cross the attestation posture on a memory-creating surface that presents
/// NO caller Ed25519 signature (`entity_register` / `reflect` / `consolidate`).
///
/// Under global-strict attestation ([`global_strict_attestation_enabled`])
/// the surface cannot attest, so the write is REFUSED (fail-closed) — closing
/// the #3014 bypass where these funnels wrote provenance-less durable rows
/// under a posture that promised attestation. Otherwise `attest_level="claimed"`
/// is stamped into `metadata` so an attestation census is truthful (#3018),
/// exactly like an unsigned MCP/CLI store.
///
/// `metadata` MUST be the created memory's metadata object; only the
/// permissive path mutates it. Curator / substrate self-writes never reach
/// this gate (they go through the SAL `store()` / `for_admin` surface, per
/// env #48) — callers gate ONLY the tenant-facing surface.
///
/// # Errors
///
/// Returns [`ATTESTATION_REFUSED_UNSIGNED_SURFACE`] when global-strict
/// attestation is engaged.
pub fn gate_unsigned_surface_attestation(
    metadata: &mut serde_json::Value,
) -> Result<crate::identity::verify::AttestLevel> {
    if global_strict_attestation_enabled() {
        return Err(anyhow::anyhow!("{ATTESTATION_REFUSED_UNSIGNED_SURFACE}"));
    }
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            crate::models::field_names::ATTEST_LEVEL.to_string(),
            serde_json::Value::String(AttestLevel::Claimed.as_str().to_string()),
        );
    }
    Ok(AttestLevel::Claimed)
}

/// Stamp `metadata.attest_level = "claimed"` INSERT-IF-ABSENT — set it ONLY
/// when the key is UNSET, NEVER overwrite an existing value.
///
/// The durable-write funnel for a memory-creating surface that presents no
/// caller signature (`db::reflect_with_hooks`, #3018 census) uses this so a
/// reflection created directly AND one created via approve→execute both land
/// an explicit `attest_level` on the durable row. Insert-if-absent (never
/// overwrite) is the fail-safe direction: a value already present (e.g. the
/// SAL reflect gate stamped `claimed` on its clone before the funnel, or a
/// verified signed write stamped `agent_attested` upstream) is preserved, so
/// this stamp can never DOWNGRADE `agent_attested`→`claimed` (#3018/#3014).
///
/// Because it is insert-if-absent, callers MUST ensure a caller-FORGED
/// `attest_level` never reaches this funnel (the tenant reflect surfaces do:
/// `mcp::handle_reflect` scrubs any caller-supplied `attest_level`, and the
/// SAL `SqliteStore`/`PostgresStore::reflect` gate OVERWRITES it via
/// [`gate_unsigned_surface_attestation`] before this runs) — reflections are
/// never cryptographically signed, so their only legitimate level is
/// `claimed`. A non-object `metadata` is left untouched (write paths always
/// build an object metadata).
pub fn stamp_claimed_if_absent(metadata: &mut serde_json::Value) {
    if let Some(obj) = metadata.as_object_mut() {
        obj.entry(crate::models::field_names::ATTEST_LEVEL)
            .or_insert_with(|| {
                serde_json::Value::String(AttestLevel::Claimed.as_str().to_string())
            });
    }
}

/// I/O-free parse core for [`require_agent_attestation_for`] (#1985).
///
/// Explicit falsy (`0`/`false`, case-insensitive) → permissive on every
/// surface; explicit truthy (`1`/`true`, case-insensitive) → required on
/// every surface; unset or any unrecognized value → the surface-scoped
/// compiled default (HTTP-direct fails CLOSED, MCP/CLI operator-as-actor stay
/// permissive) so a typo fails closed on the network surface.
fn resolve_require_agent_attestation(value: Option<&str>, surface: WriteSurface) -> bool {
    match value {
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
        _ => matches!(surface, WriteSurface::HttpDirect),
    }
}

/// #1751/#1985 — pin the parallel lib-test binary to the explicit
/// permissive opt-out (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`), exactly
/// once per process.
///
/// The #1985 surface-scoped default is REQUIRED on
/// [`WriteSurface::HttpDirect`], so every lib unit test that incidentally
/// stores unsigned through the HTTP create handlers would otherwise be
/// rejected (MCP/CLI unit tests would pass under the unset default, but
/// the pin keeps ALL lib tests deterministic against ambient operator
/// env). The strict-posture rejection paths are covered by the dedicated
/// env-serialised integration binaries
/// (`tests/agent_attestation_integrity.rs`, `tests/config_precedence.rs`,
/// `tests/agent_attestation_postgres.rs`) which own their child-process /
/// guarded env.
///
/// Monotonic set-once discipline (the #1609 rule, updated for the flip):
/// the lib-test binary never sets the flag to a STRICT value and never
/// clears it — every concurrent reader observes either "unset" (before
/// the first gated fixture runs, at which point no gated store has been
/// issued yet) or the stable `"0"`, so no set/restore window can leak a
/// strict posture into a sibling test.
#[cfg(test)]
pub(crate) fn permissive_attestation_for_lib_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: single-shot, before the calling test issues any gated
        // store; the value is never mutated again for the process
        // lifetime, matching the crate's accepted env-in-tests discipline
        // (see `src/cli/store.rs` env-test notes).
        unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") };
    });
}

/// Validate the transport fields of a *signed* remote store (#626
/// Layer-3, C7) — shared by every write surface that accepts a
/// caller-presented signature (MCP `memory_store`, HTTP
/// `POST /api/v1/memories`, …).
///
/// Decodes the standard-base64 `signature_b64` and checks the paired
/// `created_at` (the signer cannot predict the server clock, so it must
/// supply the timestamp it signed) against the [`ATTEST_CREATED_AT_SKEW_SECS`]
/// freshness window — bounding both replay (a stale timestamp) and
/// post-dating (a future one). On success returns the decoded signature
/// bytes plus the verbatim `created_at` the caller must adopt so the
/// verifier re-derives the identical [`SignableWrite`] envelope.
///
/// #3422 — the accepted set is narrowed to timestamps that are byte-identical
/// to their own [`canonicalize_attested_created_at`] form, i.e. the ONE
/// rendering BOTH backends return unchanged. A `…Z`-suffixed or
/// nanosecond-precision `created_at` is REFUSED with the canonical string to
/// sign instead: postgres stores `created_at` as `TIMESTAMPTZ` and re-renders
/// the readback, so adopting such a value persists a row whose genuine
/// signature can never be re-derived — a silently unverifiable write that the
/// federation receive path drops as forged.
///
/// # Errors
///
/// Returns a human-readable string (suitable for a 4xx wire envelope)
/// when the signature is not valid base64, `created_at` is absent /
/// not RFC3339, the timestamp falls outside the freshness window, or (#3422)
/// it is not the canonical storage-stable rendering of its instant.
pub fn prepare_signed_store<'a>(
    signature_b64: &str,
    created_at: Option<&'a str>,
) -> std::result::Result<(Vec<u8>, &'a str), String> {
    use base64::Engine as _;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| format!("invalid `signature` (expected standard base64): {e}"))?;
    let created_at = created_at
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "`signature` requires the matching `created_at` (RFC3339) the caller signed".to_string()
        })?;
    let parsed = chrono::DateTime::parse_from_rfc3339(created_at)
        .map_err(|e| format!("invalid `created_at` (expected RFC3339): {e}"))?;
    let skew = (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs();
    if skew > ATTEST_CREATED_AT_SKEW_SECS {
        return Err(format!(
            "`created_at` is outside the ±{ATTEST_CREATED_AT_SKEW_SECS}s attestation freshness \
             window (skew {skew}s); refusing to attest a stale or post-dated write"
        ));
    }
    // #3422 — FAIL CLOSED on a `created_at` the storage layer cannot return
    // byte-for-byte. The signed envelope commits to this string as TEXT and
    // every later re-derivation (this gate, and the federation receive path)
    // rebuilds it from the PERSISTED row: sqlite returns the TEXT verbatim,
    // postgres round-trips it through `TIMESTAMPTZ` (microseconds) and
    // re-renders `to_rfc3339()`. Adopting a non-round-trippable string would
    // persist a row whose genuine signature can never be re-derived again —
    // which the receive path reads as FORGED and SKIPS, losing the row. Refuse
    // at the door instead, naming the exact string to sign. Only the CANONICAL
    // form is echoed back (never the caller's raw bytes) so the 4xx envelope
    // cannot be used to reflect arbitrary attacker-chosen text.
    let canonical = canonical_created_at_stamp(parsed.with_timezone(&chrono::Utc));
    if canonical != created_at {
        return Err(format!(
            "`created_at` must be the canonical UTC form both storage backends round-trip \
             byte-for-byte (`{canonical}`): the signed envelope commits to it as TEXT and \
             postgres `TIMESTAMPTZ` cannot return any other rendering of the same instant. \
             Sign and send `{canonical}`"
        ));
    }
    Ok((sig_bytes, created_at))
}

/// SHA-256 over the UTF-8 bytes of `content` — the bounded body commitment
/// that enters the signed [`SignableWrite`] envelope.
#[must_use]
pub fn content_sha256(content: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher.finalize().into()
}

/// Sign the attestable surface of `mem` with `keypair`, producing the
/// detached Ed25519 signature the write path presents to the gate (#626
/// Layer-3, Task 1.3 / C5).
///
/// Builds the *same* [`SignableWrite`] envelope that [`stamp_attestation`]
/// re-derives — `agent_id + namespace + title + kind + created_at +
/// sha256(content)` — so the signer and the verifier never drift. The
/// caller passes the resolved `agent_id` explicitly (it already has it)
/// rather than re-reading it from metadata.
///
/// #3422 — FAIL CLOSED: refuses to mint a signature over a `created_at` the
/// storage layer cannot return byte-for-byte
/// ([`created_at_is_storage_stable`]). A signature whose pre-image cannot be
/// re-derived from the persisted row is strictly WORSE than no signature: every
/// receiver re-derives from its own row and reads the author's genuine
/// signature as FORGED, which drops the row. Callers that mint a row
/// themselves must stamp [`now_attestable_rfc3339`] (see `cli::store`,
/// `storage::consolidate`); a caller signing a row read back from storage
/// (`handlers::consolidate_federation`) degrades to an UNSIGNED `claimed` row
/// for a legacy non-canonical timestamp — reduced attestation, never a
/// forged-looking one.
///
/// # Errors
///
/// Surfaces a signing failure (e.g. the keypair is public-only) from
/// [`crate::identity::sign::sign_write`], or (#3422) a `created_at` that is not
/// the canonical storage-stable rendering of its instant.
pub fn sign_memory_write(
    keypair: &crate::identity::keypair::AgentKeypair,
    mem: &Memory,
    agent_id: &str,
) -> Result<Vec<u8>> {
    if !created_at_is_storage_stable(&mem.created_at) {
        anyhow::bail!(
            "refusing to sign a write whose `created_at` is not the canonical \
             storage-stable RFC3339 UTC form (#3422): the signature could never be \
             re-derived from the persisted row on a postgres backend"
        );
    }
    let content_hash = content_sha256(&mem.content);
    let write = SignableWrite {
        agent_id,
        namespace: &mem.namespace,
        title: &mem.title,
        kind: mem.memory_kind.as_str(),
        created_at: &mem.created_at,
        content_sha256: &content_hash,
    };
    crate::identity::sign::sign_write(keypair, &write)
}

/// Persist the author's detached Ed25519 write-signature into
/// `metadata.write_signature` (standard base64) at STORE time so it
/// propagates verbatim across every federation relay hop and re-verifies at
/// [`crate::handlers::federation_receive::apply_inbound_write_attestation`].
///
/// This is the sender-EMIT half of #1801→#1954 (ratified MINIMAL scope,
/// 5-agent vote `w9mr01vi8`): the signature MUST be minted+persisted at the
/// AUTHORING node, never re-minted on a relay hop (a relayer signing over a
/// third-party attribution yields a signature that fails verification against
/// the author's enrolled key — Forged, strictly worse than absent). The
/// standard-base64 encoding byte-matches the receiver's decode
/// (`general_purpose::STANDARD` in `apply_inbound_write_attestation`).
///
/// Idempotent and non-clobbering: an EXISTING `metadata.write_signature`
/// (a relayed third-party row carrying the origin author's signature) is left
/// UNTOUCHED, so an intermediate relay never overwrites a propagated origin
/// signature (item 3). Only self-authored rows that do not already carry a
/// signature get stamped.
//
// M-STRONG-TYPES-GUARD: the field-name is the single `field_names` SSOT const,
// never a scattered literal (pm-v3.1 no-hardcoded-literals). num-* n/a — no
// lossy casts. err-* n/a — infallible (a non-object metadata simply no-ops;
// every write path builds `metadata` as a JSON object).
pub fn persist_write_signature(mem: &mut Memory, signature: &[u8]) {
    use base64::Engine as _;
    let Some(obj) = mem.metadata.as_object_mut() else {
        return;
    };
    // Never clobber a propagated origin signature (item 3).
    if obj.contains_key(crate::models::field_names::WRITE_SIGNATURE) {
        return;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    obj.insert(
        crate::models::field_names::WRITE_SIGNATURE.to_string(),
        serde_json::Value::String(b64),
    );
}

/// Fold the storage-funnel credential redaction into `mem` BEFORE the write is
/// signed, so the signed [`SignableWrite`] envelope commits to the SAME
/// `title`/`content` bytes the storage layer will persist.
///
/// Item 4 of the #1801→#1954 corrected design (5-agent vote `w9mr01vi8`): the
/// secret-screen redact (`db::insert` → [`crate::secret_screen::redact_memory_for_storage`])
/// mutates `content` (and `title`/`tags`) AFTER a naive sign, so the signature
/// (over `sha256(content)`) would become UNCONDITIONALLY Forged at every
/// receiver once the stored bytes diverge from the signed bytes. Redacting
/// FIRST guarantees `signed bytes == persisted bytes`; the storage funnel then
/// re-redacts idempotently (a no-op on already-clean bytes).
///
/// Zero-copy on the overwhelmingly common clean path:
/// [`crate::secret_screen::redact_memory_for_storage`] returns `None` (no
/// credential detected, or screening `Off`) and `mem` is left untouched.
pub fn redact_before_sign(mem: &mut Memory) {
    if let Some(redacted) = crate::secret_screen::redact_memory_for_storage(mem) {
        *mem = redacted;
    }
}

/// I/O-free core: resolve the [`AttestLevel`] for `mem` written by
/// `agent_id`, given the agent's bound key + an optional presented signature.
/// Does NOT mutate `mem` (the sibling [`stamp_attestation`] writes the level).
///
/// The signed surface is built from the memory itself —
/// `agent_id + namespace + title + kind + created_at + sha256(content)` —
/// recomputing `sha256(content)` over the PERSISTED bytes (never a presented
/// digest) so the signature commits to the row's identity-bearing fields. The
/// caller supplies `agent_id` explicitly (every write surface already resolved
/// it) rather than re-deriving it from metadata.
///
/// #2863 — factored out of [`stamp_attestation`] so the federation receive path
/// can reuse the EXACT same verification to decide whether to HONOR a
/// cryptographically-attested third-party claim; sharing this one function
/// guarantees the honor decision and the stamped `attest_level` cannot disagree.
///
/// # Errors
///
/// Surfaces [`crate::identity::verify::AttestError`] (forged signature,
/// attestation required but absent, malformed signature, corrupt bound
/// key) as an `anyhow::Error` so the write path rejects the store.
pub fn resolve_write_attest_level(
    mem: &Memory,
    agent_id: &str,
    bound_pubkey_b64: Option<&str>,
    signature: Option<&[u8]>,
    require: bool,
) -> Result<AttestLevel> {
    let content_hash = content_sha256(&mem.content);
    let write = SignableWrite {
        agent_id,
        namespace: &mem.namespace,
        title: &mem.title,
        kind: mem.memory_kind.as_str(),
        created_at: &mem.created_at,
        content_sha256: &content_hash,
    };
    crate::identity::verify::attest_write(&write, bound_pubkey_b64, signature, require)
        .map_err(|e| anyhow::anyhow!("agent attestation failed: {e}"))
}

/// Resolve the [`AttestLevel`] for `mem` written by `agent_id` (via
/// [`resolve_write_attest_level`]) and, on success, stamp
/// `metadata.attest_level`.
///
/// # Errors
///
/// Surfaces [`crate::identity::verify::AttestError`] (forged signature,
/// attestation required but absent, malformed signature, corrupt bound
/// key) as an `anyhow::Error` so the write path rejects the store.
pub fn stamp_attestation(
    mem: &mut Memory,
    agent_id: &str,
    bound_pubkey_b64: Option<&str>,
    signature: Option<&[u8]>,
    require: bool,
) -> Result<AttestLevel> {
    let level = resolve_write_attest_level(mem, agent_id, bound_pubkey_b64, signature, require)?;

    if let Some(obj) = mem.metadata.as_object_mut() {
        obj.insert(
            "attest_level".to_string(),
            serde_json::Value::String(level.as_str().to_string()),
        );
    }
    Ok(level)
}

/// CLI / direct-connection wrapper: resolve the bound key via
/// [`crate::db::agent_pubkey`] and stamp the attestation on `mem`.
///
/// # Errors
///
/// Propagates a key-lookup failure or a gate rejection.
pub fn stamp_attestation_sync(
    conn: &rusqlite::Connection,
    mem: &mut Memory,
    agent_id: &str,
    signature: Option<&[u8]>,
    surface: WriteSurface,
) -> Result<AttestLevel> {
    let bound = crate::db::agent_pubkey(conn, agent_id)?;
    let require = require_agent_attestation_for(surface);
    stamp_attestation(mem, agent_id, bound.as_deref(), signature, require)
}

/// MCP / HTTP wrapper: resolve the bound key via
/// [`crate::store::MemoryStore::agent_pubkey`] and stamp the attestation
/// on `mem`.
///
/// Gated on the `sal` feature because the `MemoryStore` trait lives
/// under the SAL boundary (`#[cfg(feature = "sal")] pub mod store`).
///
/// # Errors
///
/// Propagates a key-lookup failure or a gate rejection.
#[cfg(feature = "sal")]
pub async fn stamp_attestation_async(
    store: &dyn crate::store::MemoryStore,
    mem: &mut Memory,
    agent_id: &str,
    signature: Option<&[u8]>,
    surface: WriteSurface,
) -> Result<AttestLevel> {
    let bound = store
        .agent_pubkey(agent_id)
        .await
        .map_err(|e| anyhow::anyhow!("resolve bound agent pubkey: {e}"))?;
    let require = require_agent_attestation_for(surface);
    stamp_attestation(mem, agent_id, bound.as_deref(), signature, require)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair;
    use crate::identity::sign;
    use crate::models::{MemoryKind, Tier};

    /// #3018 (4) — the durable reflect-funnel stamp fills an UNSET
    /// `attest_level` with `claimed`, but NEVER overwrites an existing value
    /// (insert-if-absent). This is the structural downgrade guard: a stamp
    /// that runs after an upstream `agent_attested` cannot demote it, and the
    /// fail-closed reject a verified signed write produced is never masked.
    #[test]
    fn stamp_claimed_if_absent_fills_only_when_unset_3018() {
        // Unset → filled with claimed.
        let mut empty = serde_json::json!({});
        stamp_claimed_if_absent(&mut empty);
        assert_eq!(empty["attest_level"].as_str(), Some("claimed"));

        // Already claimed → left claimed (idempotent, no double work).
        let mut claimed = serde_json::json!({ "attest_level": "claimed" });
        stamp_claimed_if_absent(&mut claimed);
        assert_eq!(claimed["attest_level"].as_str(), Some("claimed"));

        // Already agent_attested → NEVER downgraded to claimed.
        let mut attested = serde_json::json!({ "attest_level": "agent_attested" });
        stamp_claimed_if_absent(&mut attested);
        assert_eq!(
            attested["attest_level"].as_str(),
            Some("agent_attested"),
            "insert-if-absent must never downgrade agent_attested -> claimed"
        );

        // Non-object metadata is left untouched (never panics).
        let mut arr = serde_json::json!([1, 2, 3]);
        stamp_claimed_if_absent(&mut arr);
        assert!(arr.is_array());
    }

    // ---- #3422: cross-backend `created_at` byte-stability -------------------

    /// #3422 — the canonical form is EXACTLY what the postgres readback emits:
    /// `+00:00` offset, `AutoSi` fractional digits, microsecond precision.
    /// Every non-canonical rendering of the same instant maps onto it.
    #[test]
    fn canonicalize_attested_created_at_maps_every_rendering_onto_one_form_3422() {
        for raw in [
            // `Z` (zulu) suffix — the shape the HTTP sweep caught.
            "2026-09-01T12:00:00Z",
            // Non-UTC offset: the same instant, a different local rendering.
            "2026-09-01T14:00:00+02:00",
            // Already canonical.
            "2026-09-01T12:00:00+00:00",
        ] {
            assert_eq!(
                canonicalize_attested_created_at(raw).as_deref(),
                Some("2026-09-01T12:00:00+00:00"),
                "{raw} must canonicalize onto the postgres readback form"
            );
        }
        // Sub-microsecond digits cannot survive `TIMESTAMPTZ`; they truncate.
        assert_eq!(
            canonicalize_attested_created_at("2026-09-01T12:00:00.123456789Z").as_deref(),
            Some("2026-09-01T12:00:00.123456+00:00")
        );
        // `AutoSi` renders the shortest exact width (0/3/6 digits).
        assert_eq!(
            canonicalize_attested_created_at("2026-09-01T12:00:00.000Z").as_deref(),
            Some("2026-09-01T12:00:00+00:00")
        );
        assert_eq!(
            canonicalize_attested_created_at("2026-09-01T12:00:00.100000Z").as_deref(),
            Some("2026-09-01T12:00:00.100+00:00")
        );
        // Unparseable → None (postgres would reject it at the bind anyway).
        assert!(canonicalize_attested_created_at("2026-09-01 noon").is_none());
        assert!(canonicalize_attested_created_at("").is_none());
    }

    /// #3422 — canonicalization is IDEMPOTENT, which is what makes
    /// `created_at_is_storage_stable` a fixpoint test rather than a
    /// hand-enumerated pattern list.
    #[test]
    fn canonicalize_attested_created_at_is_idempotent_3422() {
        for raw in [
            "2026-09-01T12:00:00Z",
            "2026-09-01T14:00:00+02:00",
            "2026-09-01T12:00:00.123456789Z",
            "2026-09-01T12:00:00.000Z",
            "1999-12-31T23:59:59.999999Z",
        ] {
            let once = canonicalize_attested_created_at(raw).expect("parses");
            let twice = canonicalize_attested_created_at(&once).expect("re-parses");
            assert_eq!(once, twice, "canonicalization must be a fixpoint for {raw}");
            assert!(
                created_at_is_storage_stable(&once),
                "the canonical form must itself be storage-stable"
            );
        }
    }

    /// #3422 — `now_attestable_rfc3339` is storage-stable by construction, so
    /// every row minted with it is signable on BOTH backends. (The bare
    /// `chrono::Utc::now().to_rfc3339()` it replaces is NOT: on Linux it
    /// renders nanoseconds, which postgres `TIMESTAMPTZ` silently drops.)
    #[test]
    fn now_attestable_rfc3339_is_storage_stable_3422() {
        let now = now_attestable_rfc3339();
        assert!(
            created_at_is_storage_stable(&now),
            "minted `now` must round-trip both backends: {now}"
        );
        assert!(now.ends_with("+00:00"), "canonical offset rendering: {now}");
    }

    /// #3422 DENIED path — a caller-signed `created_at` that postgres cannot
    /// return byte-for-byte is refused at the funnel, and the refusal names the
    /// canonical string to sign (never echoing the caller's raw bytes back).
    #[test]
    fn prepare_signed_store_refuses_non_storage_stable_created_at_3422() {
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 64]);
        // A `Z`-suffixed stamp inside the freshness window.
        let z_form = crate::identity::attest::now_attestable_rfc3339().replace("+00:00", "Z");
        let err = prepare_signed_store(&sig_b64, Some(&z_form))
            .expect_err("a non-round-trippable created_at must be refused");
        assert!(
            err.contains("canonical UTC form"),
            "the refusal must state the contract; got: {err}"
        );
        assert!(
            err.contains("+00:00") && !err.contains(&z_form),
            "the refusal must name the canonical form and NOT reflect the raw input; got: {err}"
        );
        // Nanosecond precision is equally refused (chrono's own default
        // `Utc::now().to_rfc3339()` rendering).
        let nanos = "2026-09-01T12:00:00.123456789+00:00";
        let err = prepare_signed_store(&sig_b64, Some(nanos));
        assert!(
            err.is_err(),
            "nanosecond precision cannot survive TIMESTAMPTZ and must be refused"
        );
    }

    /// #3422 ALLOWED path — the canonical form is accepted verbatim and adopted
    /// unchanged, so the persisted row and the signed envelope stay byte-equal.
    #[test]
    fn prepare_signed_store_accepts_the_canonical_created_at_3422() {
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 64]);
        let canonical = now_attestable_rfc3339();
        let (_sig, adopted) =
            prepare_signed_store(&sig_b64, Some(&canonical)).expect("canonical form is accepted");
        assert_eq!(
            adopted, canonical,
            "the canonical timestamp must be adopted verbatim"
        );
    }

    /// #3422 DENIED path (signer half) — the daemon REFUSES to mint a signature
    /// over a `created_at` it could not re-derive from a postgres row. A
    /// signature that reads FORGED at every receiver is strictly worse than no
    /// signature: the receive path drops the row instead of landing it
    /// `claimed`.
    #[test]
    fn sign_memory_write_refuses_non_storage_stable_created_at_3422() {
        let kp = keypair::generate("ai:carol").expect("generate");
        let mut mem = make_memory("scale the deployment to three replicas");
        mem.created_at = "2026-09-01T12:00:00.123456789+00:00".to_string();
        let err = sign_memory_write(&kp, &mem, "ai:carol")
            .expect_err("a nanosecond created_at must not be signed");
        assert!(
            format!("{err:#}").contains("#3422"),
            "the refusal must cite the control; got: {err:#}"
        );
        // ALLOWED: the canonical rendering of the same instant signs, and the
        // signature re-derives from the (unchanged) row.
        mem.created_at = "2026-09-01T12:00:00.123456+00:00".to_string();
        let sig = sign_memory_write(&kp, &mem, "ai:carol").expect("canonical created_at signs");
        let level = resolve_write_attest_level(
            &mem,
            "ai:carol",
            Some(&kp.public_base64()),
            Some(&sig),
            true,
        )
        .expect("the minted signature must re-derive from the row");
        assert_eq!(level, crate::identity::verify::AttestLevel::AgentAttested);
    }

    /// #3422 — THE BUG, reproduced at the unit level without a database: the
    /// postgres readback of `created_at` is `TIMESTAMPTZ → to_rfc3339()`. Feed a
    /// `Z`-attested row through that transformation and the signature no longer
    /// re-derives; feed the canonical form through it and the row is unchanged,
    /// so the signature still verifies. This is exactly what
    /// `federation_receive::apply_inbound_write_attestation` does to a relayed
    /// row on a postgres node.
    #[test]
    fn postgres_readback_breaks_a_z_attested_row_but_not_a_canonical_one_3422() {
        /// The postgres readback, verbatim: `TIMESTAMPTZ` keeps microseconds
        /// and `store/postgres.rs` renders `DateTime<Utc>::to_rfc3339()`.
        fn postgres_round_trip(created_at: &str) -> String {
            let dt = chrono::DateTime::parse_from_rfc3339(created_at).expect("pg parses");
            crate::storage::truncate_to_microseconds(dt.with_timezone(&chrono::Utc)).to_rfc3339()
        }

        let kp = keypair::generate("ai:carol").expect("generate");
        let mut mem = make_memory("scale the deployment to three replicas");

        // (a) The `Z` form the HTTP sweep attested with. Signing it directly
        //     bypasses the new guard the way pre-#3422 code did.
        mem.created_at = "2026-09-01T12:00:00Z".to_string();
        let content_hash = content_sha256(&mem.content);
        let legacy_sig = sign::sign_write(
            &kp,
            &SignableWrite {
                agent_id: "ai:carol",
                namespace: &mem.namespace,
                title: &mem.title,
                kind: mem.memory_kind.as_str(),
                created_at: &mem.created_at,
                content_sha256: &content_hash,
            },
        )
        .expect("sign");
        // Verifies against the row as authored…
        assert!(
            resolve_write_attest_level(
                &mem,
                "ai:carol",
                Some(&kp.public_base64()),
                Some(&legacy_sig),
                true
            )
            .is_ok(),
            "the signature verifies before the storage hop"
        );
        // …and is unverifiable the moment postgres has returned the row.
        let mut from_pg = mem.clone();
        from_pg.created_at = postgres_round_trip(&mem.created_at);
        assert_ne!(from_pg.created_at, mem.created_at, "pg re-renders `…Z`");
        assert!(
            resolve_write_attest_level(
                &from_pg,
                "ai:carol",
                Some(&kp.public_base64()),
                Some(&legacy_sig),
                true
            )
            .is_err(),
            "#3422: the pg readback must break re-derivation of a `…Z` attested row"
        );

        // (b) The canonical form the funnel now enforces survives the hop.
        mem.created_at = "2026-09-01T12:00:00+00:00".to_string();
        let sig = sign_memory_write(&kp, &mem, "ai:carol").expect("canonical signs");
        let mut from_pg = mem.clone();
        from_pg.created_at = postgres_round_trip(&mem.created_at);
        assert_eq!(
            from_pg.created_at, mem.created_at,
            "the canonical form is a postgres fixpoint"
        );
        assert!(
            resolve_write_attest_level(
                &from_pg,
                "ai:carol",
                Some(&kp.public_base64()),
                Some(&sig),
                true
            )
            .is_ok(),
            "#3422: the canonical form must re-derive after the storage hop"
        );
    }

    fn make_memory(content: &str) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "team/alpha".to_string(),
            title: "kubernetes deployment guide".to_string(),
            content: content.to_string(),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "cli".to_string(),
            access_count: 0,
            created_at: "2026-06-01T12:00:00+00:00".to_string(),
            updated_at: "2026-06-01T12:00:00+00:00".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    /// Build a SignableWrite matching `make_memory`'s fields so a test can
    /// produce a valid signature over the exact bytes the gate re-derives.
    fn sign_for(kp: &keypair::AgentKeypair, mem: &Memory, agent_id: &str) -> Vec<u8> {
        let hash = content_sha256(&mem.content);
        let write = SignableWrite {
            agent_id,
            namespace: &mem.namespace,
            title: &mem.title,
            kind: mem.memory_kind.as_str(),
            created_at: &mem.created_at,
            content_sha256: &hash,
        };
        sign::sign_write(kp, &write).unwrap()
    }

    #[test]
    fn content_sha256_is_deterministic_and_bound() {
        let a = content_sha256("hello");
        let b = content_sha256("hello");
        let c = content_sha256("world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn unsigned_write_permissive_stamps_claimed() {
        let mut mem = make_memory("first content");
        let level = stamp_attestation(&mut mem, "ai:curator", None, None, false).unwrap();
        assert_eq!(level, AttestLevel::Claimed);
        assert_eq!(
            mem.metadata.get("attest_level").and_then(|v| v.as_str()),
            Some("claimed")
        );
    }

    #[test]
    fn unsigned_write_required_is_rejected_and_not_stamped() {
        let mut mem = make_memory("first content");
        let kp = keypair::generate("ai:curator").unwrap();
        let pk = kp.public_base64();
        let err = stamp_attestation(&mut mem, "ai:curator", Some(&pk), None, true).unwrap_err();
        assert!(err.to_string().contains("attestation"), "got: {err}");
        // Rejected writes must NOT carry a stamp.
        assert!(mem.metadata.get("attest_level").is_none());
    }

    #[test]
    fn signed_write_with_bound_key_stamps_agent_attested() {
        let kp = keypair::generate("ai:curator").unwrap();
        let mem_for_sig = make_memory("first content");
        let sig = sign_for(&kp, &mem_for_sig, "ai:curator");
        let pk = kp.public_base64();

        let mut mem = make_memory("first content");
        let level =
            stamp_attestation(&mut mem, "ai:curator", Some(&pk), Some(&sig), false).unwrap();
        assert_eq!(level, AttestLevel::AgentAttested);
        assert_eq!(
            mem.metadata.get("attest_level").and_then(|v| v.as_str()),
            Some("agent_attested")
        );
    }

    #[test]
    fn forged_signature_is_rejected_even_when_permissive() {
        let kp = keypair::generate("ai:curator").unwrap();
        let other = keypair::generate("ai:other").unwrap();
        let mem_for_sig = make_memory("first content");
        // Sign with `other`, present `kp`'s key as bound → forged.
        let sig = sign_for(&other, &mem_for_sig, "ai:curator");
        let pk = kp.public_base64();

        let mut mem = make_memory("first content");
        let err =
            stamp_attestation(&mut mem, "ai:curator", Some(&pk), Some(&sig), false).unwrap_err();
        assert!(err.to_string().contains("attestation failed"), "got: {err}");
        assert!(mem.metadata.get("attest_level").is_none());
    }

    #[test]
    fn tampered_content_breaks_attestation() {
        let kp = keypair::generate("ai:curator").unwrap();
        // Sign over "first content"…
        let mem_for_sig = make_memory("first content");
        let sig = sign_for(&kp, &mem_for_sig, "ai:curator");
        let pk = kp.public_base64();
        // …but persist a memory whose content was swapped.
        let mut mem = make_memory("TAMPERED content");
        let err =
            stamp_attestation(&mut mem, "ai:curator", Some(&pk), Some(&sig), false).unwrap_err();
        assert!(err.to_string().contains("attestation failed"), "got: {err}");
    }

    /// #1985 — the I/O-free parse core behind
    /// `require_agent_attestation_for`, over the tri-state × surface matrix.
    /// No process-env mutation here (the parallel lib-test binary must never
    /// set the require flag — see `src/mcp/tools/store/tests.rs` §#626); the
    /// env-backed reader is covered by the env-serialised
    /// `tests/config_precedence.rs`.
    #[test]
    fn require_flag_parse_core_surface_scoped_default() {
        use WriteSurface::{Cli, HttpDirect, Mcp};

        // ---- Explicit opt-OUT spellings → permissive on EVERY surface. ----
        for v in ["0", "false", "FALSE", "False"] {
            for surface in [HttpDirect, Mcp, Cli] {
                assert!(
                    !resolve_require_agent_attestation(Some(v), surface),
                    "{v} must read as the global permissive opt-out on {surface:?}"
                );
            }
        }

        // ---- Explicit opt-IN spellings → required on EVERY surface. ----
        for v in ["1", "true", "TRUE", "True"] {
            for surface in [HttpDirect, Mcp, Cli] {
                assert!(
                    resolve_require_agent_attestation(Some(v), surface),
                    "{v} must read as global strict on {surface:?}"
                );
            }
        }

        // ---- Unset / unrecognized → surface-scoped compiled default:
        // HttpDirect fails CLOSED, MCP/CLI operator-as-actor stay permissive.
        for value in [None, Some("no"), Some(""), Some("yes-please"), Some("2")] {
            assert!(
                resolve_require_agent_attestation(value, HttpDirect),
                "{value:?} must require attestation on the HTTP-direct surface (fail-closed)"
            );
            assert!(
                !resolve_require_agent_attestation(value, Mcp),
                "{value:?} must stay permissive on the MCP surface (operator-as-actor)"
            );
            assert!(
                !resolve_require_agent_attestation(value, Cli),
                "{value:?} must stay permissive on the CLI surface (operator-as-actor)"
            );
        }
    }

    #[test]
    fn prepare_signed_store_accepts_fresh_envelope() {
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 64]);
        // #3422 — the freshness window accepts only the canonical
        // storage-stable rendering; `Utc::now().to_rfc3339()` renders
        // nanoseconds, which no postgres `TIMESTAMPTZ` round-trip preserves.
        let created_at = now_attestable_rfc3339();
        let (bytes, ts) =
            prepare_signed_store(&sig_b64, Some(&created_at)).expect("fresh envelope ok");
        assert_eq!(bytes, vec![7u8; 64]);
        assert_eq!(ts, created_at.trim());
    }

    #[test]
    fn prepare_signed_store_rejects_bad_base64() {
        let err = prepare_signed_store("not base64!!!", Some("2026-06-01T12:00:00+00:00"))
            .expect_err("malformed base64 must error");
        assert!(err.contains("base64"), "got: {err}");
    }

    #[test]
    fn prepare_signed_store_requires_created_at() {
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let err = prepare_signed_store(&sig_b64, None).expect_err("missing created_at must error");
        assert!(err.contains("created_at"), "got: {err}");
    }

    #[test]
    fn prepare_signed_store_rejects_non_rfc3339_created_at() {
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let err = prepare_signed_store(&sig_b64, Some("2026-06-01 noon"))
            .expect_err("non-RFC3339 created_at must error");
        assert!(err.contains("RFC3339"), "got: {err}");
    }

    #[test]
    fn prepare_signed_store_rejects_stale_and_postdated_created_at() {
        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let stale = (chrono::Utc::now()
            - chrono::Duration::seconds(ATTEST_CREATED_AT_SKEW_SECS + 60))
        .to_rfc3339();
        let future = (chrono::Utc::now()
            + chrono::Duration::seconds(ATTEST_CREATED_AT_SKEW_SECS + 60))
        .to_rfc3339();
        for ts in [stale, future] {
            let err = prepare_signed_store(&sig_b64, Some(&ts))
                .expect_err("out-of-window created_at must error");
            assert!(err.contains("freshness window"), "got: {err}");
        }
    }

    // ── #1801→#1954 sender-EMIT helper unit tests ────────────────────────────

    /// The store-time EMIT persists the detached signature under the canonical
    /// `write_signature` key as STANDARD base64 — the exact encoding the
    /// receiver decodes — and it round-trips back to the signed bytes.
    #[test]
    fn persist_write_signature_encodes_standard_base64_1801() {
        use base64::Engine as _;
        let kp = keypair::generate("ai:curator").unwrap();
        let mem = make_memory("scale the deployment");
        let sig = sign_memory_write(&kp, &mem, "ai:curator").unwrap();
        let mut m = mem.clone();
        persist_write_signature(&mut m, &sig);
        let stored = m.metadata[crate::models::field_names::WRITE_SIGNATURE]
            .as_str()
            .expect("write_signature is a string leaf");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(stored)
            .expect("standard base64");
        assert_eq!(decoded, sig, "persisted signature must round-trip");
    }

    /// EMIT is non-clobbering: an already-present signature (a propagated
    /// origin signature on a relayed row) is never overwritten (item 3).
    #[test]
    fn persist_write_signature_never_clobbers_existing_1801() {
        let kp = keypair::generate("ai:curator").unwrap();
        let mem = make_memory("scale the deployment");
        let origin = sign_memory_write(&kp, &mem, "ai:curator").unwrap();
        let mut m = mem.clone();
        persist_write_signature(&mut m, &origin);
        let first = m.metadata[crate::models::field_names::WRITE_SIGNATURE].clone();
        persist_write_signature(&mut m, b"different-bytes-must-be-ignored");
        assert_eq!(
            m.metadata[crate::models::field_names::WRITE_SIGNATURE],
            first,
            "existing signature must be preserved verbatim"
        );
    }

    /// `redact_before_sign` is a no-op (zero-copy) on clean content, so the
    /// signature commits to the unchanged bytes in the common case.
    #[test]
    fn redact_before_sign_is_noop_on_clean_content_1801() {
        let mem = make_memory("perfectly clean content, no secrets here");
        let mut m = mem.clone();
        redact_before_sign(&mut m);
        assert_eq!(m.content, mem.content, "clean content is left untouched");
        assert_eq!(m.title, mem.title);
    }
}
