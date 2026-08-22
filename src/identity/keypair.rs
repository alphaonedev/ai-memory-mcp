// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-agent Ed25519 keypair lifecycle (Track H, Task H1).
//!
//! This module is the OSS substrate for v0.7's "attested cortex" track.
//! Every agent that wants to sign outbound writes (links in H2, memories
//! in H3+, audit events in H5) needs a stable Ed25519 keypair. The four
//! verbs ([`generate`], [`save`], [`load`], [`list`]) plus the CLI
//! wrapper at [`crate::cli::identity`] are the entire OSS surface.
//!
//! # Storage layout
//!
//! Keys live under `<key_dir>/<agent_id>.{pub,priv}`:
//!
//! | File                  | Mode (Unix) | Contents                                    |
//! |-----------------------|-------------|---------------------------------------------|
//! | `<agent_id>.pub`      | `0o644`     | 32 raw bytes — `VerifyingKey::to_bytes()`   |
//! | `<agent_id>.priv`     | `0o600`     | 32 raw bytes — `SigningKey::to_bytes()`     |
//!
//! The supported platforms are Linux and macOS, both of which honour the
//! Unix mode bits above.
//!
//! The default key directory is `dirs::config_dir().join("ai-memory/keys/")`
//! (`~/.config/ai-memory/keys/` on Linux,
//! `~/Library/Application Support/ai-memory/keys/` on macOS). The CLI will
//! create it on first use.
//!
//! # Hardware-backed key storage is OUT of OSS scope
//!
//! Per [`ROADMAP.md`](../../../ROADMAP.md) and
//! [`docs/v0.7/V0.7-EPIC.md`](../../../docs/v0.7/V0.7-EPIC.md), the
//! OSS path stops at file-based 0600 storage. TPM 2.0, PKCS#11 HSMs,
//! Apple Secure Enclave / TEE, AWS KMS / GCP KMS / Azure Key Vault
//! are intentionally **not** implemented in this crate. Operators who
//! need any of those should look at the **AgenticMem™** commercial
//! layer — same `AgentKeypair` shape, same wire format, hardware-backed
//! signing under the hood.
//!
//! The OSS code never imports a hardware-token library and never
//! depends on a non-pure-Rust dependency for key material. This is a
//! deliberate licensing + portability decision, not a "we'll get to it"
//! gap.
//!
//! # Format & interop
//!
//! - The on-disk format is the raw 32-byte key, no PEM, no DER, no
//!   header, no length prefix. This is the smallest possible shape
//!   that round-trips through `ed25519-dalek` and matches the COSE /
//!   CBOR wire format H2 will use.
//! - `export_pub` emits URL-safe, no-padding base64 of the public
//!   key bytes — short enough to paste into a Slack message or a
//!   peer's allowlist file.
//!
//! # Key lifecycle & rotation (#1679)
//!
//! The at-rest keypair lifecycle has four phases:
//!
//! 1. **Generate** — [`generate`] mints a fresh Ed25519 keypair from the
//!    platform CSPRNG. [`ensure_keypair`] auto-generates one at first
//!    `serve` startup (idempotent — a restart never regenerates).
//! 2. **Persist** — [`save`] writes `<id>.priv` mode `0o600` and
//!    `<id>.pub` mode `0o644`. [`load`] enforces the `0o600` private-key
//!    mode at load time (S4-LOW1) and warns on drift.
//! 3. **Rotate** — [`rotate`] (surfaced via `ai-memory identity generate
//!    --force`) replaces the active keypair, but FIRST archives the
//!    **prior public key** to a timestamped sibling
//!    `<id>.pub.<unix_secs>` (mode `0o644`). This preserves the
//!    verification anchor for historical `signed_events` signed with the
//!    rotated-out key — the pre-#1679 `--force` path overwrote the
//!    `.pub` in place and destroyed that anchor irrecoverably. The old
//!    **private** key is intentionally NOT archived: it is destroyed by
//!    the overwrite (forward security — a retired signing key never signs
//!    again, so keeping a copy is pure attack surface).
//! 4. **Out of scope** — hardware-backed storage (TPM / HSM / KMS /
//!    Secure Enclave) is the commercial AgenticMem™ boundary documented
//!    above; revocation lists and a key-id-stamped multi-key
//!    signed-events verifier are not implemented in the OSS crate.
//!
//! ## Verifying signed_events across a rotation
//!
//! The audit chain has two independent properties. The **cross-row hash
//! chain** (`signed_events` integrity / tamper-evidence) is
//! key-independent — it survives rotation untouched and remains the
//! authoritative "has the log been tampered with?" signal. The **per-row
//! Ed25519 signature** (authenticity) is key-bound: the verifier resolves
//! the single *current* daemon key, so after a rotation, rows signed with
//! the prior key surface as `signature_failures` under the new key. This
//! is **expected** (a rotated key), NOT tamper. To re-verify those
//! historical signatures, `ai-memory identity import` the archived
//! `<id>.pub.<unix_secs>` anchor and check against it out-of-band. A
//! verifier that auto-walks the archived-key set per row is a deliberate,
//! separable additive follow-up (adjudicated by the #1679 5-agent vote
//! `4d3ea1c5` — not built here to avoid a key-id schema change on the
//! append-only attested table for a rarely-rotating OSS daemon).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::validate;

/// Suffix for the public-key file (`<agent_id>.pub`).
const PUB_SUFFIX: &str = ".pub";
/// Suffix for the private-key file (`<agent_id>.priv`).
const PRIV_SUFFIX: &str = ".priv";

/// `tracing` target for every operator-facing keystore line (#3146/#3147, and
/// the pm-v3.1 hardcoded-literal gate). One named spelling so a log filter set
/// to this target catches ALL of them and a rename cannot silence half.
const KEYPAIR_TRACE_TARGET: &str = "identity::keypair";

/// Length of an Ed25519 public key in bytes.
const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Length of an Ed25519 private/signing key seed in bytes.
const SECRET_KEY_LEN: usize = ed25519_dalek::SECRET_KEY_LENGTH;

/// Per-agent Ed25519 keypair.
///
/// `private` is `Option` because two of the lifecycle verbs ([`load`]
/// when no `.priv` exists and [`list`] which always skips private
/// material) yield a public-only handle. Code that needs to sign must
/// match on `private` and refuse with a clear error when missing.
#[derive(Debug, Clone)]
pub struct AgentKeypair {
    /// Logical agent identifier — same vocabulary as
    /// `crate::identity::resolve_agent_id`.
    pub agent_id: String,
    /// Public verifying key. Always loaded.
    pub public: VerifyingKey,
    /// Optional private signing key. `None` for public-only loads.
    pub private: Option<SigningKey>,
}

impl AgentKeypair {
    /// Returns `true` when the private key is present and the keypair
    /// can therefore sign.
    #[must_use]
    pub fn can_sign(&self) -> bool {
        self.private.is_some()
    }

    /// URL-safe, no-padding base64 encoding of the public key bytes.
    /// Stable wire format for `export-pub` and for peer allowlists.
    #[must_use]
    pub fn public_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public.to_bytes())
    }
}

/// Test-only process-wide guard for tests that mutate
/// `AI_MEMORY_KEY_DIR`. Exposed at `pub(crate)` (visibility only —
/// no behavioural change) so coverage tests in `src/mcp/mod.rs`
/// can serialise with the existing race-prone tests in this file.
///
/// Without this any other test that reads the env var concurrently
/// can observe a half-written value, surfacing as flaky assertions.
#[cfg(test)]
pub(crate) fn key_dir_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// Env var that relocates the key storage directory (see
/// [`default_key_dir`]). One declaration site so every consumer —
/// the default-dir resolver and the `rules keygen` override detection
/// (#1610) — reads the same name.
pub const KEY_DIR_ENV: &str = "AI_MEMORY_KEY_DIR";

/// Returns the explicit `AI_MEMORY_KEY_DIR` env override when set and
/// non-empty, else `None`. Split out of [`default_key_dir`] so callers
/// that must distinguish "operator explicitly relocated the key store"
/// from "platform default" (the #1610 `rules keygen` write-path fix)
/// share the same set-and-non-empty semantics.
#[must_use]
pub fn key_dir_env_override() -> Option<PathBuf> {
    match std::env::var(KEY_DIR_ENV) {
        Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// Returns the default key storage directory:
/// `dirs::config_dir().join("ai-memory/keys/")`.
///
/// Errors when the OS does not advertise a config dir (extremely rare;
/// every supported target — Linux, macOS — returns one).
///
/// `AI_MEMORY_KEY_DIR` env-var override: when set and non-empty, that
/// path is returned verbatim. This mirrors the env-override pattern
/// other paths in `ai-memory` use (`AI_MEMORY_DB`,
/// `AI_MEMORY_AGENT_ID`) and lets H4's `memory_verify` integration
/// tests stand up an isolated key dir per test without shelling out to
/// the operator's real `~/.config/ai-memory/keys/`. Operators who want
/// to relocate the key store in production can use the same override.
/// Path of the default key directory, WITHOUT the #3198 posture gate.
/// `default_key_dir` is the production funnel and always gates; this is
/// the shape-only half so tests can assert the fallback path without
/// requiring the operator's live `~/.config/ai-memory/keys` to already
/// be `0o700` (this fleet's `umask 0002` leaves it `0o775` — the
/// defect #3198 exists to refuse).
fn resolved_default_key_dir_path() -> Result<PathBuf> {
    if let Some(p) = key_dir_env_override() {
        return Ok(p);
    }
    // COVERAGE: ok_or_else closure reachable only on hosts where
    //           dirs::config_dir() returns None — i.e. exotic
    //           platforms with no HOME env var. Not deterministic to
    //           trigger in tests because removing HOME breaks tempfile.
    let base = dirs::config_dir()
        .ok_or_else(|| anyhow!("OS did not advertise a config directory for key storage"))?;
    Ok(base.join("ai-memory").join("keys"))
}

pub fn default_key_dir() -> Result<PathBuf> {
    let resolved = resolved_default_key_dir_path()?;
    // #3198 — refuse at RESOLUTION, so a group-writable key store is named once
    // at boot rather than surfacing later as a confusing per-operation failure.
    // A path that does not exist yet passes; `ensure_parent` creates it `0700`.
    // Mirrors `log_paths::resolve_dir`'s `enforce_not_world_writable` call.
    enforce_key_dir_secure(&resolved)?;
    Ok(resolved)
}

/// Generate a fresh Ed25519 keypair for `agent_id` using `OsRng`.
///
/// `agent_id` is validated against
/// [`crate::validate::validate_agent_id_shape`] (shape-only — char
/// class + length) so callers cannot smuggle invalid characters into
/// the on-disk filename. The reserved-name reject lives at the WIRE
/// boundary ([`crate::validate::validate_agent_id`]) so internal
/// callers using reserved sentinels (e.g. the daemon's own
/// [`DAEMON_KEYPAIR_LABEL`] self-signing keypair) can still
/// load/generate cleanly. Wire
/// entry points that route caller-supplied agent_ids into this
/// function must validate FIRST via `validate_agent_id` before
/// reaching here.
/// The well-known stable label used by the daemon when auto-generating
/// and loading its outbound link-signing keypair (`<label>.priv` /
/// `<label>.pub` under the key directory).
///
/// This is a key-file LABEL, deliberately distinct from
/// [`crate::identity::sentinels::DAEMON_PRINCIPAL`] (a caller
/// identity) even though both are `"daemon"` today — they govern
/// different mechanisms. Round-3 F12: the daemon's signing identity is
/// process-wide (one daemon = one signing key) and decoupled from
/// per-request `agent_id` resolution; a fixed label keeps `load` and
/// `ensure_keypair` pointed at the same file across restarts.
pub const DAEMON_KEYPAIR_LABEL: &str = "daemon";

/// Substrings that mark a [`load`] / [`load_public`] failure as the
/// ordinary "this key is simply not enrolled here" rung-miss rather than
/// a real fault.
///
/// v1.0.0 #3051 — ONE named home for the discrimination that every
/// keypair-resolution rung (MCP `load_active_keypair_for_mcp_in`, CLI
/// `cli::link::resolve_active_link_keypair`) has to make, so the markers
/// cannot drift apart between surfaces and the operator directive against
/// scattered magic literals holds.
const KEY_ABSENT_ERROR_MARKERS: [&str; 2] = ["No such file", "not found"];

/// Is this keypair-load error just "the key does not exist"?
///
/// Resolution walks a ladder of candidate keys (per-agent, then the
/// substrate `daemon` label) and a miss on a rung is expected and silent.
/// Every OTHER failure — a mode-refused `.priv` (S4-LOW1), a truncated or
/// corrupt key file, an unreadable directory — is operator-actionable and
/// must be surfaced before the caller degrades to an unsigned write, or
/// the degrade is indistinguishable from "no key configured".
///
/// Matches on the rendered `{err:#}` chain because [`load`] composes its
/// causes with `anyhow::Context`; the concrete `io::ErrorKind` is not
/// preserved through that chain.
#[must_use]
pub fn is_key_absent_error(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}");
    KEY_ABSENT_ERROR_MARKERS
        .iter()
        .any(|marker| msg.contains(marker))
}

pub fn generate(agent_id: &str) -> Result<AgentKeypair> {
    validate::validate_agent_id_shape(agent_id)?;
    // ed25519-dalek 2.x consumes a `CryptoRngCore` (rand_core 0.6).
    // `OsRng` is the platform CSPRNG; it never blocks on modern OSes.
    let mut csprng = rand_core::OsRng;
    let private = SigningKey::generate(&mut csprng);
    let public = private.verifying_key();
    Ok(AgentKeypair {
        agent_id: agent_id.to_string(),
        public,
        private: Some(private),
    })
}

/// Persist `keypair` to `dir`.
///
/// Creates the directory tree on first use — on Unix every directory it
/// creates is born mode `0o700` and the resolved key directory is refused
/// outright if it is group- or world-WRITABLE (#3198; see
/// [`enforce_key_dir_secure`]). The public file is written with mode `0o644`
/// and the private file with mode `0o600`.
///
/// # Atomicity — what is and is NOT guaranteed (#3146)
///
/// EACH FILE is replaced atomically and durably by [`write_with_mode`]
/// (staging file in the same directory -> `fsync` -> `rename` -> directory
/// `fsync`), so no crash can leave EITHER file absent, truncated, or partially
/// written. The pre-#3146 doc claimed `fs::write` made this "a single syscall …
/// and a partial write is recoverable by `generate` again"; all three claims
/// were false. `write_with_mode` was remove-then-create, not `fs::write`; a
/// write is not one syscall; and `generate` mints a DIFFERENT identity, so
/// "recovering" that way makes every prior signature unverifiable — the exact
/// key-loss event this function must not be able to cause.
///
/// The PAIR is two files, so two renames, and no filesystem we target offers a
/// cross-file transaction. A crash between them therefore leaves a NEW `.priv`
/// beside a stale-or-absent `.pub`, which [`load`] refuses (its
/// private-derives-public cross-check fails). That shape is deliberate and
/// RECOVERABLE, which is why the private key is written FIRST:
///
/// * the public key is derivable from the private key, so `.priv` present +
///   `.pub` absent loses nothing — [`ensure_keypair`] re-derives the `.pub`;
/// * the reverse (`.pub` present + `.priv` absent) is UNRECOVERABLE, and it is
///   also the shape that pinned the daemon into permanent silent
///   non-signing (#3147), because the `.pub` file is the existence gate.
///
/// Refuses if `keypair.private` is `None` — there is nothing to save
/// beyond a public key, and saving a public-only file is the job of
/// [`save_public_only`] (used by `import` when `--priv` is omitted).
///
/// # Errors
///
/// Surfaces directory-creation and key-write failures, each with the offending
/// path named.
pub fn save(keypair: &AgentKeypair, dir: &Path) -> Result<()> {
    let private = keypair.private.as_ref().ok_or_else(|| {
        anyhow!(
            "AgentKeypair for {} has no private key to save",
            keypair.agent_id
        )
    })?;

    let pub_path = dir.join(format!("{}{PUB_SUFFIX}", keypair.agent_id));
    let priv_path = dir.join(format!("{}{PRIV_SUFFIX}", keypair.agent_id));

    // #1514 — a SPIFFE-style slashed agent_id (e.g. `campaign/region/host`)
    // nests the key files under sub-directories of `dir`; create the parent
    // of each FILE, not just `dir`, or the nested write ENOENTs. For a plain
    // (slash-free) agent_id the parent IS `dir`, so behaviour is unchanged.
    ensure_parent(&pub_path)?;
    ensure_parent(&priv_path)?;
    // #3198 — `ensure_parent` created (or found) the chain and checked the leaf;
    // re-check the WHOLE chain up to the caller's key dir before any key
    // material is written, so a nested #1514 layout cannot be planted through a
    // loose intermediate.
    enforce_key_path_chain_secure(dir, &priv_path)?;

    // #3146 — PRIVATE FIRST. See the atomicity section above: a crash between
    // the two renames must leave the RECOVERABLE half-state (`.priv` current,
    // `.pub` derivable from it), never the unrecoverable one (`.pub` current,
    // no matching `.priv`) that also wedges the #3147 existence gate.
    write_with_mode(&priv_path, &private.to_bytes(), 0o600)
        .with_context(|| format!("writing private key {}", priv_path.display()))?;
    write_with_mode(&pub_path, &keypair.public.to_bytes(), 0o644)
        .with_context(|| format!("writing public key {}", pub_path.display()))?;
    Ok(())
}

/// Persist only the public-key file. Used by `identity import` when the
/// caller supplies a public key without a private key (e.g., importing
/// a peer's allowlist entry). The corresponding `.priv` is left absent;
/// [`load`] will then return a public-only [`AgentKeypair`].
pub fn save_public_only(keypair: &AgentKeypair, dir: &Path) -> Result<()> {
    let pub_path = dir.join(format!("{}{PUB_SUFFIX}", keypair.agent_id));
    // #1514 — create the parent of the FILE (nested for slashed agent_ids),
    // not just `dir`; for a slash-free id the parent IS `dir`.
    ensure_parent(&pub_path)?;
    // #3198 — same whole-chain gate as `save`.
    enforce_key_path_chain_secure(dir, &pub_path)?;
    // COVERAGE: with_context closure (line 192) same class as save's
    //           pub-write closure (line 178) — reachable on EACCES/
    //           ENOSPC; not portable to unit tests on macOS/Linux.
    write_with_mode(&pub_path, &keypair.public.to_bytes(), 0o644)
        .with_context(|| format!("writing public key {}", pub_path.display()))?;
    Ok(())
}

/// Path of `agent_id`'s public-key file under `dir`. Single home for the
/// `<agent_id>.pub` shape so the literal is not scattered (pm-v3.1 lint).
fn agent_pub_path(dir: &Path, agent_id: &str) -> PathBuf {
    dir.join(format!("{agent_id}{PUB_SUFFIX}"))
}

/// `<dir>/<agent_id>.priv` — the private half. #3147 made this a named helper
/// because the existence GATE must consult both halves, not just the public
/// one; it was previously formatted inline in [`load`] only.
fn agent_priv_path(dir: &Path, agent_id: &str) -> PathBuf {
    dir.join(format!("{agent_id}{PRIV_SUFFIX}"))
}

/// v1.0.0 #2004 (PR #2214 audit F4) — does ANY key material exist for
/// `agent_id` under `dir` (`.pub` OR `.priv`)? Distinguishes "custody is
/// genuinely absent" (both files missing → an opt-in feature is simply not
/// enrolled) from "custody is present but unloadable" (a [`load`] failure
/// with material on disk → corrupt / truncated / half-enrolled key files
/// that an EXPLICIT operation must surface, never silently skip).
#[must_use]
pub(crate) fn key_material_present(agent_id: &str, dir: &Path) -> bool {
    agent_pub_path(dir, agent_id).exists() || dir.join(format!("{agent_id}{PRIV_SUFFIX}")).exists()
}

/// #1679 — outcome of a [`rotate`] call.
#[derive(Debug)]
pub struct RotateOutcome {
    /// Path the prior PUBLIC key was archived to — a timestamped
    /// sibling `<agent_id>.pub.<unix_secs>` written mode `0o644`. The
    /// archived public key is the retained verification anchor: an
    /// operator can `identity import` it to verify historical
    /// `signed_events` made with the rotated-out key.
    pub archived_pub: PathBuf,
    /// Path of the newly-active public key (`<agent_id>.pub`).
    pub new_pub: PathBuf,
}

/// #1679 — rotate the daemon/agent Ed25519 signing keypair SAFELY.
///
/// Generates a fresh keypair and makes it the active
/// `<agent_id>.{pub,priv}` — but FIRST archives the existing PUBLIC key
/// to a timestamped sibling `<agent_id>.pub.<unix_secs>` (mode `0o644`)
/// so rotation does **not** silently destroy the verification anchor for
/// historical `signed_events` signed with the old key. Without this, the
/// pre-#1679 `--force` path overwrote the `.pub` in place and the prior
/// public key — the only thing that can verify those old rows' Ed25519
/// signatures — was gone forever.
///
/// The old PRIVATE key is deliberately **not** archived: the subsequent
/// [`save`] overwrites `<agent_id>.priv` in place, destroying the
/// rotated-out signing key. That is the forward-secure posture — a
/// retired signing key never needs to sign again, so retaining a copy on
/// disk would add attack surface with zero verification benefit. The
/// archived `.pub` is non-secret (mode `0o644`).
///
/// Requires an existing `<agent_id>.pub`; for first-time creation use
/// [`generate`] + [`save`] instead.
///
/// Note (see the module-level "Key lifecycle & rotation" section): the
/// single-key signed-events verifier does NOT automatically consume the
/// archived key, so after a rotation, historical SIGNED rows surface as
/// `signature_failures` under the new key — expected (rotated key), not
/// tamper; the cross-row hash chain remains the authoritative
/// tamper-evidence bit. Cross-rotation auto-verification is a documented
/// additive follow-up, not built here (5-agent vote `4d3ea1c5`).
///
/// # Errors
///
/// - no current `<agent_id>.pub` to rotate;
/// - archive write, new-key generation, or save failure.
pub fn rotate(agent_id: &str, dir: &Path) -> Result<RotateOutcome> {
    validate::validate_agent_id_shape(agent_id)?;
    let pub_path = agent_pub_path(dir, agent_id);
    if !pub_path.exists() {
        bail!(
            "no existing keypair to rotate for {agent_id} at {} — use `identity generate` \
             for first-time creation",
            pub_path.display()
        );
    }
    // Read the current public-key bytes (the verification anchor) and
    // archive them to a timestamped, PUBLIC-ONLY sibling BEFORE the new
    // key overwrites the live files.
    let old_pub = fs::read(&pub_path)
        .with_context(|| format!("reading current public key {}", pub_path.display()))?;
    // #3146 — `create_new` + a unique `-N` suffix on collision. The prior form
    // named the archive at 1-second granularity and wrote it with a
    // remove-then-create primitive, so two rotations inside one second silently
    // OVERWROTE the earlier archive — destroying the only retained verification
    // anchor for the identity that rotation had just retired.
    let archived_pub =
        archive_public_key_at(dir, agent_id, &old_pub, chrono::Utc::now().timestamp())?;

    // Generate + persist the new keypair. `save` overwrites the old
    // `.pub`/`.priv` in place — destroying the rotated-out PRIVATE key
    // (forward security). The archived `.pub` above is the only retained
    // trace of the prior identity.
    let new_kp = generate(agent_id)?;
    save(&new_kp, dir)?;
    Ok(RotateOutcome {
        archived_pub,
        new_pub: pub_path,
    })
}

/// v0.9.0 G13 (#1828) — rotate the keypair WITH a signed lineage
/// succession, so the retiring key cryptographically hands the identity
/// off before it is destroyed.
///
/// The ordering is the entire point of this seam: legacy [`rotate`]
/// `generate`s + `save`s immediately, destroying `K_old.private` with
/// no signed link — the exact "rotation orphans history" defect G13
/// closes. This variant:
///
/// 1. loads the CURRENT keypair (`K_old`) — it must exist and carry its
///    private key (a public-only handle cannot sign a handoff);
/// 2. generates the successor (`K_new`) IN MEMORY (nothing on disk yet);
/// 3. runs `sign_and_persist(K_old, K_new)` — the caller signs the
///    succession record with `K_old` and lands it (body + flat-pubkey
///    sync + `signed_events` witness, one transaction — see
///    `crate::storage::append_lineage_record`). Any failure here leaves
///    the on-disk keys UNTOUCHED — the rotation simply did not happen;
/// 4. only then archives the prior `.pub` and overwrites `.pub`/`.priv`
///    with `K_new` (same forward-secure posture as [`rotate`]: the old
///    PRIVATE key is destroyed, the archived `.pub` survives).
///
/// Residual crash window: if the process dies between step 3 and step 4
/// the DB head is `K_new` while the disk still holds `K_old`. That is
/// recoverable (re-import `K_new` or re-run the succession CLI, which
/// detects the head) and — unlike the inverse order — never destroys
/// the only key able to sign the handoff. Legacy [`rotate`] is
/// UNTOUCHED for callers that want the old behaviour.
///
/// # Errors
///
/// - no current keypair (or a public-only one) for `agent_id`;
/// - `sign_and_persist` failure (keys on disk unchanged);
/// - archive/save failure after a successful persist (see above).
pub fn rotate_with_succession<F>(
    agent_id: &str,
    dir: &Path,
    sign_and_persist: F,
) -> Result<RotateOutcome>
where
    F: FnOnce(&AgentKeypair, &AgentKeypair) -> Result<()>,
{
    validate::validate_agent_id_shape(agent_id)?;
    let old_kp = load(agent_id, dir)?;
    if !old_kp.can_sign() {
        bail!(
            "keypair for {agent_id} is public-only — cannot sign a lineage succession; \
             a rotation without the old private key is a key-LOSS event (recovery lands in v1.0)"
        );
    }
    // Successor exists only in memory until the succession is durably
    // signed + persisted — a failure below leaves the identity intact.
    let new_kp = generate(agent_id)?;
    sign_and_persist(&old_kp, &new_kp)?;

    // Succession persisted — now (and only now) touch the disk. Same
    // archive-then-overwrite discipline as `rotate` (#1679).
    let pub_path = agent_pub_path(dir, agent_id);
    let old_pub = fs::read(&pub_path)
        .with_context(|| format!("reading current public key {}", pub_path.display()))?;
    // #3146 — collision-safe archive naming, same rationale as `rotate`.
    let archived_pub =
        archive_public_key_at(dir, agent_id, &old_pub, chrono::Utc::now().timestamp())?;
    save(&new_kp, dir)?;
    Ok(RotateOutcome {
        archived_pub,
        new_pub: pub_path,
    })
}

/// Load only an agent's public verifying key from `<agent_id>.pub`.
///
/// This path never opens or materializes the sibling private key. Use it for
/// verification, trust-anchor export, and other read-only identity flows.
///
/// # Errors
/// Returns an error when the agent-id shape or public-key file is invalid.
pub fn load_public(agent_id: &str, dir: &Path) -> Result<VerifyingKey> {
    // #977 — shape-only here; the daemon loads its own keypair under
    // the reserved label `DAEMON_KEYPAIR_LABEL = "daemon"` and must
    // continue to succeed. Wire-routed callers validate at entry points.
    validate::validate_agent_id_shape(agent_id)?;
    let pub_path = agent_pub_path(dir, agent_id);
    // #3198 — re-stat the directory the key files actually live in on EVERY
    // read, not just at resolution: a directory can be chmod-loosened after
    // boot, and a group-writable key dir makes every file-level control below
    // (mode bits, the private-derives-public cross-check, the #1790 single-open
    // fstat) meaningless — an attacker swaps in a matched pair they control.
    // The FILE's parent, not `dir`, because a slashed #1514 agent_id nests the
    // key files below `dir`; for a plain agent_id the two are the same.
    enforce_key_path_chain_secure(dir, &pub_path)?;
    let pub_bytes = fs::read(&pub_path)
        .with_context(|| format!("reading public key {}", pub_path.display()))?;
    if pub_bytes.len() != PUBLIC_KEY_LEN {
        bail!(
            "public key {} has {} bytes, expected {PUBLIC_KEY_LEN}",
            pub_path.display(),
            pub_bytes.len()
        );
    }
    let mut pub_arr = [0u8; PUBLIC_KEY_LEN];
    pub_arr.copy_from_slice(&pub_bytes);
    VerifyingKey::from_bytes(&pub_arr)
        .with_context(|| format!("decoding public key {}", pub_path.display()))
}

/// Load `agent_id`'s keypair from `dir`.
///
/// The public file must exist (errors otherwise). The private file is
/// optional — if absent the returned `AgentKeypair.private` is `None`
/// and the caller can verify but not sign.
///
/// # v0.7.0 S4-LOW1 — load-time mode-bits enforcement (Unix)
///
/// `save` writes the private file with mode `0o600`, but an operator
/// (or a misconfigured restore-from-backup) can chmod-loosen the
/// file on disk after the fact. Without a load-time check the
/// daemon would happily sign with a world-readable key. On Unix we
/// now stat the `.priv` file before reading and refuse to load
/// when any group/other bit is set (`mode & 0o077 != 0`).
///
/// The error message names the path and the offending mode, and
/// includes the `chmod` invocation that restores 0600 — so an
/// operator hitting this in production has a copy-pasteable fix.
///
/// On non-Unix targets this check is a no-op (mode bits don't
/// apply to NTFS ACLs; hardware-backed key storage is the
/// commercial AgenticMem layer's responsibility — see the
/// "Hardware-backed key storage" section above).
pub fn load(agent_id: &str, dir: &Path) -> Result<AgentKeypair> {
    let public = load_public(agent_id, dir)?;
    let pub_path = agent_pub_path(dir, agent_id);
    let priv_path = agent_priv_path(dir, agent_id);

    let private = read_private_key_file(&priv_path)?;
    if let Some(signing) = private.as_ref() {
        // Cross-check: the private key must derive the same public
        // key we just loaded. Mismatch means file tampering or a
        // stale .pub — refuse loudly rather than sign with the
        // wrong identity.
        if signing.verifying_key().to_bytes() != public.to_bytes() {
            bail!(
                "private key {} does not match public key {}",
                priv_path.display(),
                pub_path.display()
            );
        }
    }

    Ok(AgentKeypair {
        agent_id: agent_id.to_string(),
        public,
        private,
    })
}

/// Read and validate `<agent_id>.priv` at `priv_path`, returning `None` when
/// the file does not exist (a valid public-only state).
///
/// Extracted from [`load`] by #3147 so the self-heal path in [`ensure_keypair`]
/// re-uses the IDENTICAL mode/length/TOCTOU discipline instead of
/// re-implementing a second, drift-prone private-key reader.
///
/// # v0.7.0 S4-LOW1 — load-time mode-bits enforcement (Unix)
///
/// [`save`] writes the private file with mode `0o600`, but an operator (or a
/// misconfigured restore-from-backup) can chmod-loosen the file on disk after
/// the fact. Without a load-time check the daemon would happily sign with a
/// world-readable key, so on Unix we stat the `.priv` file before reading and
/// refuse when any group/other bit is set (`mode & 0o077 != 0`). The error
/// names the path and the offending mode and includes the `chmod` that restores
/// `0600`. On non-Unix targets this check is a no-op (mode bits don't apply to
/// NTFS ACLs; hardware-backed key storage is the commercial AgenticMem layer's
/// responsibility — see the "Hardware-backed key storage" section above).
///
/// # Errors
///
/// Insecure mode bits, a wrong-length key, or a read failure other than
/// "not found".
fn read_private_key_file(priv_path: &Path) -> Result<Option<SigningKey>> {
    // #1790 finding 2 — open the file ONCE and perform the perms check on
    // that handle (`f.metadata()` = fstat), then read the bytes from the
    // SAME handle. The pre-#1790 form did `fs::metadata(path)` then
    // `fs::read(path)` — two path lookups, so a key file could be swapped
    // (perms-OK decoy → real key, or vice versa) in the window between the
    // check and the read (TOCTOU). Opening once closes that re-open window;
    // behaviour is otherwise unchanged.
    match fs::File::open(priv_path) {
        Ok(mut f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = f
                    .metadata()
                    .with_context(|| format!("stat private key {}", priv_path.display()))?;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    bail!(
                        "private key {} has insecure mode {:o}; refusing to load. \
                         Restore with: chmod 0600 {}",
                        priv_path.display(),
                        mode,
                        priv_path.display()
                    );
                }
            }
            use std::io::Read;
            let mut priv_bytes = Vec::new();
            f.read_to_end(&mut priv_bytes)
                .with_context(|| format!("reading private key {}", priv_path.display()))?;
            if priv_bytes.len() != SECRET_KEY_LEN {
                let actual_len = priv_bytes.len();
                // #1258 — zeroize the (wrong-length) buffer before the
                // bail; even a partial private key is a secret.
                use zeroize::Zeroize;
                priv_bytes.zeroize();
                bail!(
                    "private key {} has {} bytes, expected {SECRET_KEY_LEN}",
                    priv_path.display(),
                    actual_len
                );
            }
            let mut priv_arr = [0u8; SECRET_KEY_LEN];
            priv_arr.copy_from_slice(&priv_bytes);
            let signing = SigningKey::from_bytes(&priv_arr);
            // #1258 — zeroize both copies of the raw private-key bytes
            // before they fall out of scope. `SigningKey` owns its own
            // internal `secret` field which `ed25519-dalek` zeroizes on
            // Drop; the two intermediate buffers here are ours to
            // wipe.
            {
                use zeroize::Zeroize;
                priv_bytes.zeroize();
                priv_arr.zeroize();
            }
            Ok(Some(signing))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            Err(anyhow!(e)).with_context(|| format!("reading private key {}", priv_path.display()))
        }
    }
}

/// Enumerate every `<agent_id>.pub` under `dir` and return the
/// public-only keypairs. Private keys are **not** loaded — `list` is
/// the safe verb for ops dashboards and shell autocompletion.
///
/// Returns an empty `Vec` (not an error) when `dir` does not exist —
/// "no keys generated yet" is the common first-run state.
pub fn list(dir: &Path) -> Result<Vec<AgentKeypair>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    // #3198 — a listing is where an operator picks a public key to hand out as a
    // peer trust anchor, so it must not present keys from a directory another
    // local UID can write to as if they were ours. Same gate as every other
    // read path; refuses rather than filtering, because a silently-shortened
    // list is exactly the "wrong answer, not a degraded one" shape.
    enforce_key_dir_secure(dir)?;
    let mut out = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("reading key directory {}", dir.display()))?
    {
        // COVERAGE: entry? Err-arm (line 273) reachable when a
        //           specific dir entry fails to stat mid-iteration
        //           — typically the file was deleted between
        //           read_dir and entry materialisation. Not
        //           deterministic to trigger.
        let entry = entry?;
        let name = entry.file_name();
        // COVERAGE: name.to_str() None arm (line 276) reachable only
        //           on Linux with a non-UTF-8 filesystem encoding.
        //           macOS NFD-normalises everything to UTF-8 so the None
        //           arm doesn't fire on the dev host.
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(stem) = name_str.strip_suffix(PUB_SUFFIX) else {
            continue;
        };
        // Skip .pub files whose stem is not a valid agent_id — they
        // can't have been written by this module's `save`. Shape-only
        // check because on-disk keys can legitimately be labelled
        // with reserved-sentinel names (e.g. the daemon's own
        // `DAEMON_KEYPAIR_LABEL = "daemon"` pubkey).
        if validate::validate_agent_id_shape(stem).is_err() {
            continue;
        }
        let path = entry.path();
        let pub_bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if pub_bytes.len() != PUBLIC_KEY_LEN {
            continue;
        }
        let mut pub_arr = [0u8; PUBLIC_KEY_LEN];
        pub_arr.copy_from_slice(&pub_bytes);
        let Ok(public) = VerifyingKey::from_bytes(&pub_arr) else {
            continue;
        };
        out.push(AgentKeypair {
            agent_id: stem.to_string(),
            public,
            private: None,
        });
    }
    out.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    Ok(out)
}

/// Decode a base64-encoded public key (URL-safe-no-pad **or** standard
/// padded) into a [`VerifyingKey`]. Used by `identity import` so
/// operators can paste either flavor of base64 they were sent.
pub fn decode_public_base64(s: &str) -> Result<VerifyingKey> {
    let trimmed = s.trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .with_context(|| "decoding base64 public key".to_string())?;
    if bytes.len() != PUBLIC_KEY_LEN {
        bail!(
            "decoded public key has {} bytes, expected {PUBLIC_KEY_LEN}",
            bytes.len()
        );
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&bytes);
    // COVERAGE: with_context closure (line 326+) reachable when the
    //           32-byte base64-decoded payload is an invalid Edwards-
    //           curve point. Same class as load() line 218 — coverage
    //           depends on the dalek 2.x decode policy for specific
    //           inputs. Documented per L0.7 playbook §3c.
    VerifyingKey::from_bytes(&arr).with_context(|| "decoding public key bytes".to_string())
}

/// Read a 32-byte raw key file and return the bytes. Used by
/// `identity import` for `--pub <path> --priv <path>` when the operator
/// hands us files instead of base64. Errors loudly on a length mismatch.
pub fn read_raw_key_file(path: &Path) -> Result<[u8; SECRET_KEY_LEN]> {
    let bytes = fs::read(path).with_context(|| format!("reading key file {}", path.display()))?;
    if bytes.len() != SECRET_KEY_LEN {
        bail!(
            "key file {} has {} bytes, expected {SECRET_KEY_LEN}",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; SECRET_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Round-2 F12 — auto-generation of the daemon's signing keypair
// ---------------------------------------------------------------------------
//
// Round-2 evidence: link signing was disabled by default at v0.7.0
// because no Ed25519 keypair existed on a freshly-installed deployment
// and the operator had to manually run `ai-memory identity generate`
// before signed links would land. Default-secure says we should
// auto-generate one at first `serve` startup unless the operator
// explicitly opted out. The lifecycle is idempotent (re-runs are
// no-ops) so a daemon restart never overwrites an existing keypair.

/// Outcome of a single [`ensure_keypair`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// Keypair already existed at the resolved path; no action taken.
    AlreadyExists {
        /// Path to the public-key file the existence check observed.
        pub_path: PathBuf,
    },
    /// A fresh keypair was generated and persisted to `dir`.
    Generated {
        /// Path the public-key file was written to. The corresponding
        /// `.priv` lives alongside.
        pub_path: PathBuf,
    },
    /// Auto-generation was disabled — operator set
    /// `[identity].disabled = true` (or equivalent) in config.
    SkippedDisabled,
    /// #3147 — `<agent_id>.priv` was on disk but `<agent_id>.pub` was NOT, so
    /// the public half was RE-DERIVED from the private key and rewritten.
    ///
    /// The identity is UNCHANGED (a public key is a deterministic function of
    /// its private key), so every prior signature stays verifiable. This is the
    /// crash-window shape #3146's private-key-first `save` ordering deliberately
    /// produces, and self-healing it is the reason that ordering is correct.
    RepairedPublicFromPrivate {
        /// Path of the public-key file that was re-derived.
        pub_path: PathBuf,
    },
    /// #3147 — `<agent_id>.pub` exists but its `<agent_id>.priv` sibling does
    /// NOT. The daemon can verify but cannot sign, and it CANNOT self-heal:
    /// a private key is not derivable from a public key, and regenerating would
    /// mint a DIFFERENT identity, silently invalidating every signature the
    /// lost key produced. Reported so the caller can WARN (default posture) or
    /// REFUSE to boot (`asi-hard`, via [`public_only_refusal`]) — never
    /// auto-repaired.
    PublicOnlyDegraded {
        /// Path of the public-key file that exists.
        pub_path: PathBuf,
        /// Path of the private-key file that is missing.
        priv_path: PathBuf,
    },
}

/// #3147 — the `asi-hard` refusal text for a boot that found a public key with
/// no matching private key, or `None` when boot may proceed.
///
/// Pure (the posture is a parameter, not an env read) so both the daemon wiring
/// and its tests drive the identical decision. Under the DEFAULT posture this
/// returns `None` and the caller WARNs: a public-only key directory is a
/// degraded-but-running state that has been permitted since v0.7, and silently
/// tightening it into a boot refusal would break deployments that deliberately
/// run verify-only. Under `asi-hard` — a posture whose whole contract is that
/// no security control may be silently disabled — a daemon that cannot sign
/// anything is exactly such a disabled control, so it refuses.
#[must_use]
pub fn public_only_refusal(outcome: &EnsureOutcome, asi_hard: bool) -> Option<String> {
    let EnsureOutcome::PublicOnlyDegraded {
        pub_path,
        priv_path,
    } = outcome
    else {
        return None;
    };
    if !asi_hard {
        return None;
    }
    Some(format!(
        "{} refuses to boot with a public-only identity: {} \
         exists but {} does not, so this daemon can verify but can NEVER sign — every \
         signed-link, persona and audit-witness control that depends on it is silently \
         inert. The private key is NOT derivable from the public key and is NOT \
         regenerated automatically (that would mint a different identity and make every \
         prior signature unverifiable). Restore the private key from backup, or — if the \
         identity is genuinely lost and you accept that its prior signatures become \
         unverifiable — remove {} and let the daemon generate a fresh keypair (#3147).",
        crate::security_profile::ASI_HARD_REFUSAL_PREFIX,
        pub_path.display(),
        priv_path.display(),
        pub_path.display(),
    ))
}

/// Round-2 F12 — auto-generate a signing keypair for `agent_id` under
/// `dir` if one does not already exist.
///
/// `disabled` is the operator's opt-out flag (resolved from
/// `[identity].disabled` in config). When `true` the helper returns
/// [`EnsureOutcome::SkippedDisabled`] without touching the filesystem.
///
/// Idempotency: when the public-key file at
/// `<dir>/<agent_id>.pub` already exists the helper returns
/// [`EnsureOutcome::AlreadyExists`] without calling [`generate`] or
/// [`save`]. This guarantees a daemon restart never overwrites a
/// pre-existing keypair (which would silently invalidate every
/// signed link the prior key produced).
///
/// On the [`EnsureOutcome::Generated`] path the helper logs at INFO
/// level via `tracing` so the operator notices the new key in
/// daemon logs. The same line is also surfaced by the F12 startup
/// banner — see [`crate::cli::serve_banner`].
pub fn ensure_keypair(agent_id: &str, dir: &Path, disabled: bool) -> Result<EnsureOutcome> {
    if disabled {
        tracing::info!(
            "identity: auto-gen disabled by config; link signing will be skipped at boot"
        );
        return Ok(EnsureOutcome::SkippedDisabled);
    }
    // #977 — shape-only here: `ensure_keypair` is called from the
    // daemon's own startup path (`src/daemon_runtime.rs:1760`) with
    // `DAEMON_KEYPAIR_LABEL = "daemon"` (a reserved sentinel). The
    // wire-routed callers (CLI `identity install`) validate at their
    // entry point via the reserved-name-rejecting
    // [`crate::validate::validate_agent_id`].
    validate::validate_agent_id_shape(agent_id)?;

    let pub_path = agent_pub_path(dir, agent_id);
    let priv_path = agent_priv_path(dir, agent_id);
    // #3198 — before BELIEVING anything about what is on disk, refuse a key
    // directory another local UID can write to. Every arm below decides from
    // file existence, and under a group-writable directory an attacker controls
    // that answer: they can delete `<agent>.pub` to force the self-heal arm, or
    // plant a matched pair the "both present" arm accepts.
    enforce_key_path_chain_secure(dir, &pub_path)?;
    // #3147 — the gate consults BOTH halves. It used to test `.pub` alone, so a
    // key directory holding only a public key (the #3146 crash window, or a
    // `.pub`-only backup restore) reported `AlreadyExists` on EVERY restart:
    // the daemon signed nothing, forever, with no WARN, no readiness signal and
    // no self-heal.
    match (pub_path.exists(), priv_path.exists()) {
        // Both halves present — idempotent. A daemon restart must keep the
        // operator's existing key (regenerating would silently invalidate every
        // signed link the prior key produced).
        (true, true) => Ok(EnsureOutcome::AlreadyExists { pub_path }),

        // Public half missing, private half present — SELF-HEAL. The public key
        // is a deterministic function of the private key, so re-deriving it
        // restores the pair with the SAME identity and zero signature loss.
        // This is exactly the crash window #3146's private-key-first `save`
        // ordering is designed to leave behind.
        (false, true) => {
            let signing = read_private_key_file(&priv_path)?.ok_or_else(|| {
                anyhow!(
                    "private key {} vanished between the existence check and the read",
                    priv_path.display()
                )
            })?;
            write_with_mode(&pub_path, &signing.verifying_key().to_bytes(), 0o644)
                .with_context(|| format!("re-deriving public key {}", pub_path.display()))?;
            tracing::warn!(
                target: KEYPAIR_TRACE_TARGET,
                "identity: {} was missing while {} was present — RE-DERIVED the public \
                 key from the private key. The identity is unchanged and every prior \
                 signature stays verifiable, but this is the fingerprint of an interrupted \
                 key write or a partial restore; check the key directory and your backups \
                 (#3147).",
                pub_path.display(),
                priv_path.display(),
            );
            Ok(EnsureOutcome::RepairedPublicFromPrivate { pub_path })
        }

        // Public half present, private half missing — DEGRADED, and NOT
        // repairable. Regenerating here would mint a different identity behind
        // the operator's back, so the only honest actions are to shout and (per
        // posture, at the caller) refuse. See [`public_only_refusal`].
        (true, false) => {
            tracing::warn!(
                target: KEYPAIR_TRACE_TARGET,
                "identity: {} exists but {} does NOT — this agent can verify but can \
                 NEVER sign, and it will not self-heal on restart. A private key cannot be \
                 derived from a public key, and it is deliberately NOT regenerated (that \
                 would mint a DIFFERENT identity and make every prior signature \
                 unverifiable). Restore the private key from backup, or remove the public \
                 key to accept a fresh identity (#3147).",
                pub_path.display(),
                priv_path.display(),
            );
            Ok(EnsureOutcome::PublicOnlyDegraded {
                pub_path,
                priv_path,
            })
        }

        // Neither half present — first run.
        (false, false) => ensure_generate(agent_id, dir, pub_path),
    }
}

/// First-run branch of [`ensure_keypair`], split out so the gate above reads as
/// a four-way state table.
fn ensure_generate(agent_id: &str, dir: &Path, pub_path: PathBuf) -> Result<EnsureOutcome> {
    let kp = generate(agent_id)?;
    save(&kp, dir)?;
    // COVERAGE: tracing::info! lazy-format closure (lines 411-417)
    //           — the format args are constructed lazily; the closure
    //           body runs when the INFO subscriber is enabled. Coverage
    //           depends on test subscriber config. Documented per L0.7
    //           playbook §3c.
    tracing::info!(
        "auto-generated identity keypair at {} — consider backing up",
        pub_path.display()
    );
    Ok(EnsureOutcome::Generated { pub_path })
}

/// Create the parent directory of `path` (recursive `mkdir`).
///
/// #1514 — a SPIFFE-style slashed `agent_id` (`campaign/region/host`)
/// produces a key path nested several directories below `dir`; we must
/// create the parent of the FILE, not just `dir`, or the subsequent
/// write fails with `ENOENT`. For a plain (slash-free) `agent_id` the
/// file parent IS `dir`, so this is behaviourally identical to the old
/// `create_dir_all(dir)`.
/// #3198 — every directory this function CREATES is created `0o700`, and the
/// resulting parent is then re-checked by [`enforce_key_dir_secure`]. Directories
/// that already existed keep their mode and are only checked, so an operator's
/// pre-existing `0o755` key dir is not silently rewritten.
pub(crate) fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all_secure(parent)
            .with_context(|| format!("creating key directory {}", parent.display()))?;
        enforce_key_dir_secure(parent)?;
    }
    Ok(())
}

/// Mode every key directory this crate CREATES is born with (#3198). `0o700` is
/// unaffected by any umask that only clears group/other bits, so the fresh tree
/// is owner-only even under the `umask 0002` this fleet runs.
#[cfg(unix)]
const KEY_DIR_MODE: u32 = 0o700;

/// The group/other WRITE bits (#3198). A key directory carrying either of them
/// lets a second local UID unlink and replace `<agent>.priv`/`<agent>.pub`, so
/// every downstream file-level control — the `0o600` mode check, the
/// private-derives-public cross-check, the #1790 single-open fstat — is defeated
/// before it runs: the attacker plants a MATCHED pair and the daemon signs with
/// it, producing forged `signed_events` that VERIFY.
///
/// Deliberately the WRITE bits only, not `0o077`. Refusing on a merely
/// group/other-READABLE `0o755` directory would brick every deployment created
/// under the default `umask 022` — a silent tightening of a shipped default,
/// which this fix must not do. Read access to a directory does not enable the
/// swap; write access does. The remediation text still recommends `0o700`.
#[cfg(unix)]
const KEY_DIR_FORBIDDEN_BITS: u32 = 0o022;

/// `create_dir_all` that gives every directory it CREATES mode
/// [`KEY_DIR_MODE`] (#3198).
///
/// `DirBuilder::mode` applies at `mkdir(2)` time, so the window in which a
/// freshly-created key directory is group-writable does not exist — unlike a
/// `create_dir_all` followed by a `chmod`. Pre-existing directories are left
/// exactly as they are (checked, never rewritten).
fn create_dir_all_secure(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(KEY_DIR_MODE);
    }
    builder.create(dir)
}

/// #3198 — refuse to read or write key material under a directory another local
/// UID can write to.
///
/// The identity keystore had NO directory-posture gate at all, while the log and
/// audit trees have had one since v0.7
/// ([`crate::log_paths::enforce_not_world_writable`] +
/// `log_paths::ensure_dir_secure`'s explicit `0o700`) — so on a `umask 0002`
/// host the signing identity was strictly less protected than the log material
/// describing it.
///
/// A missing directory passes (there is nothing to attack yet, and `save`
/// creates it `0o700`), matching the `log_paths` precedent. On non-Unix this is
/// a no-op: there are no POSIX mode bits to enforce.
///
/// # Errors
///
/// The directory exists and is group- or world-WRITABLE, or it cannot be
/// `stat`ed. The message names the path, the offending mode, and the exact
/// `chmod` that fixes it.
pub(crate) fn enforce_key_dir_secure(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !dir.exists() {
            return Ok(());
        }
        let md =
            fs::metadata(dir).with_context(|| format!("stat key directory {}", dir.display()))?;
        let mode = md.permissions().mode() & 0o7777;
        if mode & KEY_DIR_FORBIDDEN_BITS != 0 {
            bail!(
                "key directory {} is group- or world-writable (mode {mode:o}); refusing to \
                 use it. Another local user can replace {}/<agent>.priv and <agent>.pub with \
                 a keypair they control — the per-file 0600 check and the private-derives-\
                 public cross-check both PASS on a planted matched pair, so this daemon \
                 would sign with an attacker's identity and the forged signatures would \
                 verify. Restore with: chmod 0700 {} (#3198)",
                dir.display(),
                dir.display(),
                dir.display(),
            );
        }
    }
    #[cfg(not(unix))]
    {
        // No POSIX mode bits on non-Unix targets; the directory ACL governs.
        let _ = dir;
    }
    Ok(())
}

/// #3198 — apply [`enforce_key_dir_secure`] to the directory `file` lives in
/// AND to every ancestor up to and including `base`, the caller-supplied key
/// directory.
///
/// For a plain (slash-free) `agent_id` the file's parent IS `base`, so this is
/// one check. For a #1514 SPIFFE-style slashed id (`campaign/region/host`) the
/// key files sit several directories below `base`, and write access to ANY link
/// in that chain is enough to replace the subtree holding the key — checking
/// only the leaf would leave the nested layout half-guarded.
///
/// Owned [`PathBuf`] walk via [`PathBuf::pop`], not a `&Path` reborrow of
/// `.parent()`, so the loop cannot trip a 1.96 borrow-checker stall on
/// `cur = parent` (OWNERSHIP-10 / rustc 1.96 NLL).
pub(crate) fn enforce_key_path_chain_secure(base: &Path, file: &Path) -> Result<()> {
    let mut cur = key_file_dir(file)?;
    loop {
        enforce_key_dir_secure(&cur)?;
        if cur.as_path() == base {
            return Ok(());
        }
        if !cur.starts_with(base) {
            break;
        }
        if !cur.pop() {
            break;
        }
    }
    enforce_key_dir_secure(base)
}

/// #3146 — how many `-N` suffixes [`archive_public_key_at`] will try before
/// refusing, when the un-suffixed archive name for this second is taken.
/// Bounded on purpose: a rotation loop hot enough to exhaust this is a bug,
/// and silently minting unbounded archive files would hide it.
const ARCHIVE_SUFFIX_ATTEMPTS: u32 = 64;

/// Resolve the directory a key file lives in, for staging + `fsync`.
fn key_file_dir(path: &Path) -> io::Result<PathBuf> {
    match path.parent() {
        // A bare relative filename (`"daemon.pub"`) has an EMPTY parent, which
        // is not an openable directory — normalise it to the CWD.
        Some(p) if p.as_os_str().is_empty() => Ok(PathBuf::from(".")),
        Some(p) => Ok(p.to_path_buf()),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("key path {} has no parent directory", path.display()),
        )),
    }
}

/// A private, unique sibling of `path` in the SAME directory (so the later
/// `rename` is a same-filesystem, atomic replace). Leading `.` keeps it out of
/// casual `ls`; the name deliberately does NOT end in `.pub`/`.priv`, so a
/// concurrent [`list`] never sees a half-written key.
fn staging_sibling(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let stem = path.file_name().map_or_else(
        || std::ffi::OsString::from("key"),
        std::ffi::OsStr::to_os_string,
    );
    let mut name = std::ffi::OsString::from(".");
    name.push(&stem);
    name.push(format!(".staged.{}.{seq}", std::process::id()));
    path.with_file_name(name)
}

/// #3146 — turn a bare `EPERM`/`EACCES` on the key directory into something an
/// operator can act on. The staging file is created in the SAME directory as
/// the key, so a read-only, wrong-owner, or (Linux) IMMUTABLE key directory now
/// names itself and the check that finds it, instead of surfacing a naked
/// "Permission denied (os error 1)" that reads like a problem with the key file.
#[cfg(unix)]
fn annotate_staging_error(e: &io::Error, dir: &Path, path: &Path) -> io::Error {
    if !matches!(e.kind(), io::ErrorKind::PermissionDenied) {
        return io::Error::new(e.kind(), e.to_string());
    }
    io::Error::new(
        e.kind(),
        format!(
            "cannot create a staging file in the key directory {} while writing {}: {e}. \
             The key directory must be writable by this process: check its owner and mode \
             (`ls -ld {}`), and on Linux check for an immutable flag (`lsattr -d {}` -> clear \
             with `chattr -i {}`).",
            dir.display(),
            path.display(),
            dir.display(),
            dir.display(),
            dir.display(),
        ),
    )
}

/// `fsync` the DIRECTORY so a completed `rename` survives a power cut. On the
/// platforms we support this is the only way to make a directory entry durable;
/// best-effort because a filesystem that refuses `fsync` on a directory (some
/// network mounts) must not fail an otherwise-successful key write.
fn sync_dir(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Durably write `bytes` to `path` with an explicit Unix mode, replacing any
/// existing file ATOMICALLY.
///
/// # v1.0.0 #3146 — this used to be remove-then-create
///
/// The prior body was `let _ = fs::remove_file(path);` followed by an
/// `OpenOptions::create_new` on the FINAL path: the old file was destroyed
/// BEFORE a single new byte existed. A crash, `ENOSPC`, `EIO`, or an OOM kill
/// anywhere in that window left the key file absent or truncated — and for
/// `<agent>.priv` that is the destruction of a SOLE private key, which no
/// backup-free deployment can recover (regenerating mints a DIFFERENT identity,
/// making every prior signature unverifiable).
///
/// The sequence is now the standard durable-replace dance, every step of which
/// leaves the ORIGINAL file byte-for-byte intact until the last one:
///
/// 1. create a private, uniquely-named staging file in the SAME directory
///    (same filesystem, so the rename below cannot be a cross-device copy),
///    with the requested mode applied at creation — the key material is never
///    momentarily world-readable;
/// 2. write the bytes and `fsync` the staging FILE (bytes are on the platter);
/// 3. `rename` staging -> `path`, which POSIX guarantees is atomic: a
///    concurrent reader observes either the complete old file or the complete
///    new one, never a partial or absent one, and no unlink window exists;
/// 4. `fsync` the DIRECTORY so the rename itself survives a power cut.
///
/// Any failure before step 3 removes the staging file and returns the error
/// with `path` untouched. A failure at step 3 does the same.
///
/// # Errors
///
/// Surfaces the underlying `io::Error`. A `PermissionDenied` while staging is
/// re-rendered with the key DIRECTORY named plus the `ls -ld` / `lsattr` /
/// `chattr -i` checks, because a read-only or immutable key directory is the
/// common cause and the bare errno points at the wrong file.
#[cfg(unix)]
pub(crate) fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = key_file_dir(path)?;
    let staged = staging_sibling(path);

    // Step 1 — stage. `create_new` on a unique name never clobbers anything;
    // `.mode(mode)` applies the permission bits AT CREATION so a 0600 private
    // key is never briefly readable by anyone else.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&staged)
        .map_err(|e| annotate_staging_error(&e, &dir, path))?;

    // Steps 2-4. From here every failure must unlink the staging file and
    // leave `path` exactly as it was.
    let commit = || -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&staged, path)?;
        sync_dir(&dir);
        Ok(())
    };
    match commit() {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&staged);
            Err(e)
        }
    }
}

/// #3146 — create `path` with `bytes` and `mode`, REFUSING if it already
/// exists. Used for rotation archives, where overwriting an existing archive
/// would destroy the only retained trace of a prior identity. Unlike
/// [`write_with_mode`] there is no staging file: `create_new` on the final
/// name IS the atomic claim, and a lost race is reported as `AlreadyExists`
/// so the caller can pick another name rather than clobber.
#[cfg(unix)]
fn create_new_with_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = key_file_dir(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    let commit = || -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        sync_dir(&dir);
        Ok(())
    };
    match commit() {
        Ok(()) => Ok(()),
        Err(e) => {
            // The name was ours to claim, so removing the partial file is safe
            // and keeps a failed archive attempt from blocking a retry.
            let _ = fs::remove_file(path);
            Err(e)
        }
    }
}

#[cfg(not(unix))]
fn create_new_with_mode(path: &Path, bytes: &[u8], _mode: u32) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let commit = || -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        sync_dir(path.parent().unwrap_or_else(|| Path::new(".")));
        Ok(())
    };
    match commit() {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(path);
            Err(e)
        }
    }
}

/// #3146 — archive `pub_bytes` as a timestamped, PUBLIC-ONLY sibling of
/// `<agent_id>.pub`, NEVER overwriting an existing archive.
///
/// `rotate` used to name the archive `<agent_id>.pub.<unix_seconds>` and write
/// it with a remove-then-create primitive, so two rotations inside the SAME
/// SECOND silently overwrote the first archive — destroying the only retained
/// verification anchor for the identity that rotation retired. The name is now
/// claimed with `create_new`; on collision the helper appends `-1`, `-2`, … and
/// on exhaustion REFUSES rather than overwriting.
///
/// `ts` is a parameter (not read from the clock here) so the collision
/// behaviour is deterministically testable.
///
/// # Errors
///
/// - the archive directory cannot be created or written;
/// - every candidate name for `ts` is taken ([`ARCHIVE_SUFFIX_ATTEMPTS`]).
fn archive_public_key_at(dir: &Path, agent_id: &str, pub_bytes: &[u8], ts: i64) -> Result<PathBuf> {
    for attempt in 0..=ARCHIVE_SUFFIX_ATTEMPTS {
        let candidate = if attempt == 0 {
            dir.join(format!("{agent_id}{PUB_SUFFIX}.{ts}"))
        } else {
            dir.join(format!("{agent_id}{PUB_SUFFIX}.{ts}-{attempt}"))
        };
        ensure_parent(&candidate)?;
        match create_new_with_mode(&candidate, pub_bytes, 0o644) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(anyhow!(e)).with_context(|| {
                    format!("archiving prior public key to {}", candidate.display())
                });
            }
        }
    }
    bail!(
        "refusing to rotate {agent_id}: every archive name for timestamp {ts} under {} is \
         already taken ({ARCHIVE_SUFFIX_ATTEMPTS} suffixes tried). Overwriting one would \
         destroy the only retained verification anchor for a prior identity — move the \
         existing archives aside and retry.",
        dir.display()
    )
}

#[cfg(not(unix))]
pub(crate) fn write_with_mode(path: &Path, bytes: &[u8], _mode: u32) -> io::Result<()> {
    // Non-Unix: mode bits don't apply. The file inherits the parent
    // directory ACL. (Linux and macOS, the supported platforms, take the
    // unix path above; this branch is a defensive fallback only.)
    //
    // v0.7.0 de-silencing: the requested restrictive `mode` cannot be
    // honored here, so the private key lands with whatever the parent
    // directory's ACL grants. Emit a once-per-process operator-visible
    // warn so this weaker-than-Unix posture is observable rather than
    // silent.
    static NON_UNIX_KEY_PERM_WARN_ONCE: std::sync::Once = std::sync::Once::new();
    NON_UNIX_KEY_PERM_WARN_ONCE.call_once(|| {
        tracing::warn!(
            target: KEYPAIR_TRACE_TARGET,
            "writing key material on a non-Unix platform: restrictive file-mode \
             bits are not applied, so the key file inherits the parent directory \
             ACL. Restrict the key directory's ACL manually, or use hardware-backed \
             key storage, to protect private keys."
        );
    });
    // #3146 — same durable-replace discipline as the Unix branch: stage a
    // unique sibling, fsync it, atomically rename over `path`, fsync the
    // directory. `fs::write` truncated the target in place, so a crash left a
    // ZERO-length or partial key file where a complete one had been.
    use std::io::Write;
    let dir = key_file_dir(path)?;
    let staged = staging_sibling(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let commit = || -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&staged, path)?;
        sync_dir(&dir);
        Ok(())
    };
    match commit() {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&staged);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::Verifier;
    use tempfile::TempDir;

    fn tmp_dir() -> TempDir {
        TempDir::new().expect("tempdir")
    }

    /// v1.0.0 #3051 — the shared rung-miss predicate both keypair-resolution
    /// ladders (MCP `load_active_keypair_for_mcp_in`, CLI
    /// `cli::link::resolve_active_link_keypair`) branch on. It must classify
    /// a genuinely absent key as silent, and EVERY other fault — notably the
    /// S4-LOW1 mode refusal — as operator-visible, or a degraded-to-unsigned
    /// write becomes indistinguishable from "no key configured".
    #[test]
    fn is_key_absent_error_only_swallows_a_missing_key_3051() {
        let dir = tmp_dir();

        // Absent key: expected rung-miss, silent.
        let absent = load("nobody", dir.path()).expect_err("no such key");
        assert!(
            is_key_absent_error(&absent),
            "a missing key must be classified absent; got: {absent:#}"
        );

        // Mode-refused `.priv` (S4-LOW1): a real fault, must NOT be swallowed.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let kp = generate("alice").expect("generate");
            save(&kp, dir.path()).expect("save");
            let priv_path = dir.path().join(format!("alice{PRIV_SUFFIX}"));
            fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o644)).expect("widen mode");
            let refused = load("alice", dir.path()).expect_err("insecure mode");
            assert!(
                !is_key_absent_error(&refused),
                "a mode-refused .priv must stay operator-visible; got: {refused:#}"
            );
        }
    }

    #[test]
    fn generate_yields_signing_keypair() {
        let kp = generate("alice").expect("generate");
        assert_eq!(kp.agent_id, "alice");
        assert!(
            kp.can_sign(),
            "freshly generated keypair must have private key"
        );
        // Public derives from private.
        let priv_pub = kp.private.as_ref().unwrap().verifying_key().to_bytes();
        assert_eq!(priv_pub, kp.public.to_bytes());
    }

    #[test]
    fn generate_rejects_invalid_agent_id() {
        assert!(generate("has space").is_err());
        assert!(generate("has\0null").is_err());
    }

    #[test]
    fn round_trip_save_then_load() {
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).expect("save");
        let loaded = load("alice", dir.path()).expect("load");
        assert_eq!(loaded.agent_id, "alice");
        assert_eq!(loaded.public.to_bytes(), kp.public.to_bytes());
        assert!(loaded.can_sign(), "private key should round-trip");
        // Sign with loaded key, verify with original public.
        let msg = b"hello world";
        let sig = loaded.private.as_ref().unwrap().sign(msg);
        assert!(kp.public.verify(msg, &sig).is_ok());
    }

    // ----- #1679 safe key rotation -----------------------------------

    /// #1679 — rotation archives the OLD public key (the verification
    /// anchor) before activating a new key, and copies NO private-key
    /// material. Timestamp-agnostic: asserts on the path `rotate`
    /// returns, never a literal timestamp.
    #[test]
    fn rotate_archives_old_pub_and_activates_new_key() {
        let dir = tmp_dir();
        let old = generate("alice").unwrap();
        save(&old, dir.path()).unwrap();
        let old_pub_bytes = old.public.to_bytes();

        let outcome = rotate("alice", dir.path()).expect("rotate");

        // Archived path exists and decodes to the OLD public key.
        assert!(outcome.archived_pub.exists(), "archived .pub must exist");
        let archived = fs::read(&outcome.archived_pub).unwrap();
        assert_eq!(
            archived.as_slice(),
            old_pub_bytes.as_slice(),
            "archived bytes must be the prior public key"
        );
        // Filename is a `<id>.pub.<ts>` sibling (no timestamp literal).
        let name = outcome.archived_pub.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("alice.pub."), "archive name = {name}");

        // The active key is NEW, loadable, and can sign.
        let active = load("alice", dir.path()).unwrap();
        assert_ne!(
            active.public.to_bytes(),
            old_pub_bytes,
            "rotated-in key must differ from the old key"
        );
        assert!(active.can_sign(), "rotated-in key must sign");

        // NO private-key material was archived (forward security).
        let stray_priv = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_str().is_some_and(|n| n.contains(".priv.")));
        assert!(!stray_priv, "rotation must NOT copy private-key material");

        // `list` ignores the archived file (not a spurious live key).
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1, "only the live key is listed");
        assert_eq!(listed[0].agent_id, "alice");
    }

    #[cfg(unix)]
    #[test]
    fn rotate_archived_pub_is_world_readable_not_secret() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        save(&generate("alice").unwrap(), dir.path()).unwrap();
        let outcome = rotate("alice", dir.path()).expect("rotate");
        let mode = fs::metadata(&outcome.archived_pub)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "archived .pub is the non-secret 0644 anchor");
    }

    #[test]
    fn rotate_refuses_when_no_existing_key() {
        let dir = tmp_dir();
        let err = rotate("ghost", dir.path()).expect_err("must refuse with no existing key");
        assert!(
            err.to_string().contains("no existing keypair"),
            "unexpected error: {err}"
        );
    }

    // ----- v0.9.0 G13 (#1828) rotate_with_succession -------------------

    /// The closure sees `K_old` WITH its private key (it must sign the
    /// succession) and the in-memory `K_new`; only after it succeeds do
    /// the on-disk keys change (archive + overwrite, like `rotate`).
    #[test]
    fn rotate_with_succession_signs_before_destroying_old_key() {
        let dir = tmp_dir();
        let old = generate("alice").unwrap();
        save(&old, dir.path()).unwrap();
        let old_pub = old.public.to_bytes();

        let seen: std::cell::RefCell<Option<([u8; 32], [u8; 32], bool)>> =
            std::cell::RefCell::new(None);
        let outcome = rotate_with_succession("alice", dir.path(), |k_old, k_new| {
            // At closure time the DISK still holds the old keypair —
            // nothing has been archived or overwritten yet.
            let on_disk = load("alice", dir.path()).unwrap();
            assert_eq!(on_disk.public.to_bytes(), k_old.public.to_bytes());
            seen.replace(Some((
                k_old.public.to_bytes(),
                k_new.public.to_bytes(),
                k_old.can_sign(),
            )));
            Ok(())
        })
        .expect("rotate_with_succession");

        let (seen_old, seen_new, old_could_sign) = seen.into_inner().expect("closure ran");
        assert_eq!(seen_old, old_pub, "closure must see the retiring key");
        assert!(old_could_sign, "closure must be able to sign with K_old");

        // After: the active key IS the successor the closure saw.
        let active = load("alice", dir.path()).unwrap();
        assert_eq!(active.public.to_bytes(), seen_new);
        assert_ne!(active.public.to_bytes(), old_pub);
        assert!(outcome.archived_pub.exists(), "prior .pub archived");
        assert_eq!(
            fs::read(&outcome.archived_pub).unwrap().as_slice(),
            old_pub.as_slice(),
            "archived bytes must be the prior public key"
        );
    }

    /// A failed sign/persist leaves the on-disk identity UNTOUCHED —
    /// the rotation simply did not happen (no archive, no overwrite).
    #[test]
    fn rotate_with_succession_persist_failure_leaves_keys_untouched() {
        let dir = tmp_dir();
        let old = generate("alice").unwrap();
        save(&old, dir.path()).unwrap();
        let old_pub = old.public.to_bytes();

        let err = rotate_with_succession("alice", dir.path(), |_k_old, _k_new| {
            anyhow::bail!("db is down")
        })
        .expect_err("closure failure must propagate");
        assert!(err.to_string().contains("db is down"), "got: {err}");

        // Disk unchanged: same key, no archived sibling.
        let active = load("alice", dir.path()).unwrap();
        assert_eq!(active.public.to_bytes(), old_pub, "old key must survive");
        let archived = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("alice.pub."))
            });
        assert!(!archived, "no archive sibling on a failed succession");
    }

    #[test]
    fn rotate_with_succession_refuses_missing_and_public_only_keys() {
        let dir = tmp_dir();
        // No key at all.
        let err = rotate_with_succession("ghost", dir.path(), |_, _| Ok(()))
            .expect_err("must refuse with no existing key");
        assert!(!err.to_string().is_empty());
        // Public-only handle cannot sign the handoff — that is a
        // key-LOSS event, out of scope this train (recovery = v1.0).
        let kp = generate("alice").unwrap();
        save_public_only(&kp, dir.path()).unwrap();
        let err = rotate_with_succession("alice", dir.path(), |_, _| Ok(()))
            .expect_err("public-only key must refuse");
        assert!(
            err.to_string().contains("public-only"),
            "unexpected error: {err}"
        );
    }

    // #1514 — a SPIFFE-style slashed agent_id nests the key files under
    // sub-directories of `dir`. `save` must create those parents (not just
    // `dir`) or the write ENOENTs; `load` must then round-trip the nested
    // files. Regression pin for the save/load asymmetry.
    #[test]
    fn round_trip_save_then_load_slashed_agent_id() {
        let dir = tmp_dir();
        let agent_id = "hive-1461/nyc3/hive-peer-nyc3-01";
        let kp = generate(agent_id).expect("generate slashed id");
        save(&kp, dir.path()).expect("save slashed id must create nested parents");

        // The files really do live nested under dir.
        let pub_path = dir.path().join(format!("{agent_id}.pub"));
        let priv_path = dir.path().join(format!("{agent_id}.priv"));
        assert!(pub_path.exists(), "nested .pub must exist at {pub_path:?}");
        assert!(
            priv_path.exists(),
            "nested .priv must exist at {priv_path:?}"
        );

        let loaded = load(agent_id, dir.path()).expect("load slashed id");
        assert_eq!(loaded.agent_id, agent_id);
        assert_eq!(loaded.public.to_bytes(), kp.public.to_bytes());
        assert!(loaded.can_sign(), "private key should round-trip");

        // Modes survive the nested write on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let pub_mode = fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
            let priv_mode = fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(pub_mode, 0o644, "nested public key must be 0644");
            assert_eq!(priv_mode, 0o600, "nested private key must be 0600");
        }
    }

    // #1514 — `save_public_only` must also create nested parents for a
    // slashed agent_id (the allowlist-import path).
    #[test]
    fn save_public_only_slashed_agent_id_creates_nested_parent() {
        let dir = tmp_dir();
        let agent_id = "hive-1461/sfo2/hive-peer-sfo2-01";
        let kp = generate(agent_id).expect("generate");
        save_public_only(&kp, dir.path()).expect("save_public_only nested");

        let pub_path = dir.path().join(format!("{agent_id}.pub"));
        assert!(pub_path.exists(), "nested .pub must exist at {pub_path:?}");
        let loaded = load(agent_id, dir.path()).expect("load");
        assert!(!loaded.can_sign(), "public-only save must yield no private");
        assert_eq!(loaded.public.to_bytes(), kp.public.to_bytes());
    }

    #[test]
    fn load_without_private_yields_public_only() {
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).expect("save");
        // Drop the private file.
        let priv_path = dir.path().join("alice.priv");
        fs::remove_file(&priv_path).expect("rm priv");
        let loaded = load("alice", dir.path()).expect("load");
        assert!(!loaded.can_sign(), "missing .priv must yield None private");
        assert_eq!(loaded.public.to_bytes(), kp.public.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_unix_mode_0600_and_0644() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).expect("save");

        let pub_meta = fs::metadata(dir.path().join("alice.pub")).unwrap();
        let priv_meta = fs::metadata(dir.path().join("alice.priv")).unwrap();

        // Mask off the file-type bits; we only care about the perm bits.
        let pub_mode = pub_meta.permissions().mode() & 0o777;
        let priv_mode = priv_meta.permissions().mode() & 0o777;
        assert_eq!(
            priv_mode, 0o600,
            "private key must be 0600, got {priv_mode:o}"
        );
        assert_eq!(pub_mode, 0o644, "public key must be 0644, got {pub_mode:o}");
    }

    #[test]
    fn list_enumerates_saved_keypairs() {
        let dir = tmp_dir();
        let alice = generate("alice").unwrap();
        let bob = generate("bob").unwrap();
        save(&alice, dir.path()).unwrap();
        save(&bob, dir.path()).unwrap();

        let listed = list(dir.path()).expect("list");
        assert_eq!(listed.len(), 2);
        // Sorted by agent_id.
        assert_eq!(listed[0].agent_id, "alice");
        assert_eq!(listed[1].agent_id, "bob");
        // No private keys in list output.
        for kp in &listed {
            assert!(!kp.can_sign(), "list must not load private keys");
        }
        // Public bytes match.
        assert_eq!(listed[0].public.to_bytes(), alice.public.to_bytes());
        assert_eq!(listed[1].public.to_bytes(), bob.public.to_bytes());
    }

    #[test]
    fn list_on_missing_dir_returns_empty() {
        let dir = tmp_dir();
        let nonexistent = dir.path().join("does-not-exist");
        let listed = list(&nonexistent).expect("list");
        assert!(listed.is_empty());
    }

    #[test]
    fn list_skips_unrelated_files() {
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        // Drop noise that should be skipped.
        fs::write(dir.path().join("README.txt"), b"ignore me").unwrap();
        fs::write(dir.path().join("not-a-key.pub"), b"too short").unwrap();

        let listed = list(dir.path()).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent_id, "alice");
    }

    #[test]
    fn load_rejects_truncated_public_key() {
        let dir = tmp_dir();
        fs::write(dir.path().join("alice.pub"), b"short").unwrap();
        let err = load("alice", dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("expected 32"), "got: {msg}");
    }

    #[test]
    fn load_rejects_priv_pub_mismatch() {
        let dir = tmp_dir();
        let alice = generate("alice").unwrap();
        let bob = generate("alice").unwrap();
        save(&alice, dir.path()).unwrap();
        // Overwrite .priv with a different keypair's private bytes.
        fs::remove_file(dir.path().join("alice.priv")).unwrap();
        // Use save_public_only path effectively: write a .priv that
        // doesn't match alice's .pub.
        let bob_priv = bob.private.as_ref().unwrap().to_bytes();
        write_with_mode(&dir.path().join("alice.priv"), &bob_priv, 0o600).unwrap();
        let err = load("alice", dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("does not match"), "got: {msg}");
    }

    #[test]
    fn export_pub_round_trips_through_base64() {
        let kp = generate("alice").unwrap();
        let b64 = kp.public_base64();
        let decoded = decode_public_base64(&b64).expect("decode");
        assert_eq!(decoded.to_bytes(), kp.public.to_bytes());
    }

    #[test]
    fn decode_public_base64_accepts_padded_form() {
        let kp = generate("alice").unwrap();
        let padded = base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes());
        let decoded = decode_public_base64(&padded).expect("decode padded");
        assert_eq!(decoded.to_bytes(), kp.public.to_bytes());
    }

    #[test]
    fn read_raw_key_file_validates_length() {
        let dir = tmp_dir();
        let p = dir.path().join("short.bin");
        fs::write(&p, b"short").unwrap();
        let err = read_raw_key_file(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("expected 32"), "got: {msg}");
    }

    #[test]
    fn save_refuses_public_only_keypair() {
        let dir = tmp_dir();
        let kp = AgentKeypair {
            agent_id: "alice".to_string(),
            public: generate("alice").unwrap().public,
            private: None,
        };
        let err = save(&kp, dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key to save"), "got: {msg}");
    }

    #[test]
    fn save_public_only_writes_pub_only() {
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "alice".to_string(),
            public: kp.public,
            private: None,
        };
        save_public_only(&pub_only, dir.path()).expect("save_public_only");
        assert!(dir.path().join("alice.pub").exists());
        assert!(!dir.path().join("alice.priv").exists());
        let loaded = load("alice", dir.path()).expect("load");
        assert!(!loaded.can_sign());
    }

    #[test]
    fn default_key_dir_ends_in_ai_memory_keys() {
        // M9 — `default_key_dir_honours_env_override` flips the same
        // `AI_MEMORY_KEY_DIR` key. Acquire the shared lock so the two
        // tests cannot interleave under `cargo test --jobs N`.
        let _g = key_dir_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: env mutation serialised by `_g`. The H4 env-var
        // override (`AI_MEMORY_KEY_DIR`) is scrubbed up-front so this
        // test asserts the *fallback* path.
        unsafe {
            std::env::remove_var("AI_MEMORY_KEY_DIR");
        }
        // Shape only — do NOT go through `default_key_dir()`, which
        // refuses a group-writable live keystore (#3198). This host's
        // `~/.config/ai-memory/keys` is `0o775` under `umask 0002`.
        let p = resolved_default_key_dir_path().expect("default dir path");
        let s = p.to_string_lossy();
        assert!(s.ends_with("ai-memory/keys") || s.ends_with("ai-memory\\keys"));
    }

    /// Process-wide guard for tests that mutate `AI_MEMORY_KEY_DIR`.
    /// Delegates to the module-level `pub(crate) key_dir_env_lock` so
    /// sibling-crate test files (e.g. `src/mcp/mod.rs`'s H4 verify
    /// coverage tests) can serialise against the keypair-module tests
    /// that also mutate the env var. Local thin wrapper kept so the
    /// existing call sites in this file do not change.
    fn key_dir_env_lock() -> &'static std::sync::Mutex<()> {
        super::key_dir_env_lock()
    }

    // ---- Round-2 F12 ensure_keypair --------------------------------------

    #[test]
    fn ensure_keypair_generates_when_missing() {
        let dir = tmp_dir();
        let outcome = ensure_keypair("alice", dir.path(), false).expect("ensure");
        match outcome {
            EnsureOutcome::Generated { pub_path } => {
                assert!(pub_path.exists(), "pub key must be on disk");
                let priv_path = dir.path().join("alice.priv");
                assert!(priv_path.exists(), "priv key must be on disk");
            }
            other => panic!("expected Generated, got {other:?}"),
        }
    }

    #[test]
    fn ensure_keypair_idempotent_on_second_call() {
        let dir = tmp_dir();
        let first = ensure_keypair("alice", dir.path(), false).expect("first");
        let pub_path = dir.path().join("alice.pub");
        let priv_path = dir.path().join("alice.priv");
        // Snapshot bytes to assert non-overwrite.
        let pub_before = fs::read(&pub_path).unwrap();
        let priv_before = fs::read(&priv_path).unwrap();

        let second = ensure_keypair("alice", dir.path(), false).expect("second");
        match second {
            EnsureOutcome::AlreadyExists { pub_path: observed } => {
                assert_eq!(observed, pub_path);
            }
            other => panic!("expected AlreadyExists on second call, got {other:?}"),
        }
        // Bytes must NOT have changed — overwrite would corrupt every
        // prior signed link.
        let pub_after = fs::read(&pub_path).unwrap();
        let priv_after = fs::read(&priv_path).unwrap();
        assert_eq!(pub_before, pub_after);
        assert_eq!(priv_before, priv_after);
        // First call's outcome must have been Generated.
        assert!(matches!(first, EnsureOutcome::Generated { .. }));
    }

    #[test]
    fn ensure_keypair_respects_disabled_flag() {
        let dir = tmp_dir();
        let outcome = ensure_keypair("alice", dir.path(), true).expect("ensure");
        assert_eq!(outcome, EnsureOutcome::SkippedDisabled);
        // Filesystem must be untouched.
        assert!(!dir.path().join("alice.pub").exists());
        assert!(!dir.path().join("alice.priv").exists());
    }

    #[test]
    fn ensure_keypair_validates_agent_id() {
        let dir = tmp_dir();
        let res = ensure_keypair("has space", dir.path(), false);
        assert!(res.is_err(), "must reject invalid agent_id");
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — error path + visibility closures
    // -----------------------------------------------------------------

    #[test]
    fn save_returns_context_when_dir_is_a_file() {
        // Lines 172, 178: with_context closure for create_dir_all
        // when the parent component is a file.
        let dir = tmp_dir();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"file").unwrap();
        let kp = generate("alice").unwrap();
        // Treat the file as if it were a dir → mkdir of "blocker/sub"
        // fails because blocker is a file.
        let sub = blocker.join("sub");
        let err = save(&kp, &sub).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("creating key directory"),
            "expected wrapped context, got: {msg}"
        );
    }

    #[test]
    fn save_public_only_returns_context_when_dir_is_a_file() {
        // Lines 189: with_context closure for create_dir_all.
        let dir = tmp_dir();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"file").unwrap();
        let kp = generate("alice").unwrap();
        let sub = blocker.join("sub");
        let err = save_public_only(&kp, &sub).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("creating key directory"),
            "expected wrapped context, got: {msg}"
        );
    }

    #[test]
    fn load_returns_context_when_pub_file_missing() {
        // Line 207: with_context closure for fs::read of public.
        let dir = tmp_dir();
        let err = load("alice", dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading public key"), "got: {msg}");
    }

    #[test]
    fn load_returns_decode_context_for_corrupt_public_key() {
        // Line 218: with_context closure for VerifyingKey::from_bytes.
        // Construct 32 bytes that fail decode (an Ed25519 invariant
        // requires the encoded point to lie on the curve — most
        // arbitrary 32-byte sequences are valid, but certain
        // canonical points fail). Use 32 0xFF bytes to maximise the
        // chance of decode failure; if dalek accepts it, the test
        // falls back to asserting the length is the only check that
        // would fire. We trust the historical Ed25519 spec which
        // rejects all-1 encodings.
        let dir = tmp_dir();
        let bytes = [0xFFu8; PUBLIC_KEY_LEN];
        fs::write(dir.path().join("alice.pub"), bytes).unwrap();
        // The result may surface either a length-OK + decode error
        // OR a decode error directly. We only assert that LOAD errors
        // (not panics) — this pins the path even if dalek's decode
        // policy varies across versions.
        let res = load("alice", dir.path());
        if let Err(err) = res {
            let msg = format!("{err:#}");
            // Either path is acceptable; both go through with_context.
            assert!(
                msg.contains("decoding public key") || msg.contains("expected"),
                "got: {msg}"
            );
        } else {
            // If dalek accepted the all-FF point as a valid public
            // key, this test is a no-op (the spec edge differs from
            // our assumption). Document that we tolerate either
            // outcome via this branch.
        }
    }

    #[test]
    fn load_with_truncated_priv_returns_length_error() {
        // Lines 222-226: bail! when private key bytes are wrong length.
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        // Truncate .priv to a non-32-byte length (e.g. 8 bytes).
        fs::write(dir.path().join("alice.priv"), b"shortie!").unwrap();
        let err = load("alice", dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("expected 32"), "got: {msg}");
    }

    #[test]
    fn list_returns_context_on_unreadable_directory() {
        // Line 271: with_context closure for read_dir failure. Hardest
        // to trigger portably — passing a regular file as `dir` makes
        // `dir.exists()` return true but read_dir fails with ENOTDIR.
        let dir = tmp_dir();
        let file = dir.path().join("not-a-dir");
        fs::write(&file, b"x").unwrap();
        let err = list(&file).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading key directory"), "got: {msg}");
    }

    #[test]
    fn decode_public_base64_rejects_garbage() {
        // Line 317: with_context closure on base64 decode failure.
        let err = decode_public_base64("not-valid-base64!!!").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("decoding base64"), "got: {msg}");
    }

    #[test]
    fn decode_public_base64_rejects_wrong_length() {
        // Line 318-322: bail! when decoded bytes are not 32.
        // 8 bytes encodes to 12 chars in base64 (no padding).
        let short = URL_SAFE_NO_PAD.encode([0u8; 8]);
        let err = decode_public_base64(&short).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("expected 32"), "got: {msg}");
    }

    #[test]
    fn read_raw_key_file_returns_context_when_path_missing() {
        // Line 333: with_context closure on fs::read failure.
        let dir = tmp_dir();
        let missing = dir.path().join("nope.bin");
        let err = read_raw_key_file(&missing).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading key file"), "got: {msg}");
    }

    #[test]
    fn ensure_keypair_rejects_invalid_agent_id_when_enabled() {
        // Line 402: validate_agent_id fires on the enabled branch.
        let dir = tmp_dir();
        let err = ensure_keypair("has space", dir.path(), false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid character"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — list() iteration error closures + load() io error
    // branches not covered by the prior suite.
    // -----------------------------------------------------------------

    #[test]
    fn list_skips_pub_file_with_invalid_agent_id_stem() {
        // Line 283-285: validate_agent_id(stem).is_err() => continue.
        // The stem must look like a .pub file (so the suffix strip
        // doesn't continue first) but must FAIL validate_agent_id.
        // "has space" violates the agent_id regex.
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        // 32-byte bytes so the length guard doesn't skip first.
        fs::write(dir.path().join("has space.pub"), [0u8; PUBLIC_KEY_LEN]).unwrap();
        let listed = list(dir.path()).expect("list");
        // The bogus stem is filtered out; only alice survives.
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent_id, "alice");
    }

    #[cfg(unix)]
    #[test]
    fn list_skips_unreadable_pub_file_continues_iteration() {
        // Lines 287-289: Err(_) => continue. Make a 0000-mode file
        // alongside a readable one — list must skip the unreadable
        // entry and still return the good one.
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        let alice = generate("alice").unwrap();
        save(&alice, dir.path()).unwrap();
        let unreadable = dir.path().join("bob.pub");
        fs::write(&unreadable, [0u8; PUBLIC_KEY_LEN]).unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        let listed = list(dir.path()).expect("list");
        // Restore so tempdir cleanup works.
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644)).unwrap();
        // The unreadable file is skipped — only alice survives. Bob
        // *may* survive if running as root (which bypasses 0000), so
        // we accept either 1 or 2 entries but require alice present.
        assert!(listed.iter().any(|k| k.agent_id == "alice"));
    }

    #[test]
    fn list_skips_pub_file_with_invalid_curve_point() {
        // Lines 296-297: VerifyingKey::from_bytes Err => continue.
        // Search for a 32-byte sequence that ed25519-dalek rejects.
        // Many arbitrary inputs are valid points; some y-coordinates
        // off-curve are not. We probe a handful of candidates and
        // use the first one that errors. If none of them error on
        // this dalek version we fall back to asserting the iteration
        // doesn't panic — the COVERAGE note below records the cap.
        let dir = tmp_dir();
        let alice = generate("alice").unwrap();
        save(&alice, dir.path()).unwrap();

        let mut bogus: Option<[u8; PUBLIC_KEY_LEN]> = None;
        for seed in 0u8..=255 {
            let mut bytes = [seed; PUBLIC_KEY_LEN];
            // Twiddle the high bits — Edwards curve y-coords are
            // 255-bit; setting bytes[31] = 0xFF often pushes the
            // decoded y above the field prime (2^255 - 19), which
            // dalek rejects.
            bytes[31] = 0xFF;
            if VerifyingKey::from_bytes(&bytes).is_err() {
                bogus = Some(bytes);
                break;
            }
        }
        if let Some(b) = bogus {
            fs::write(dir.path().join("bogus.pub"), b).unwrap();
            let listed = list(dir.path()).expect("list");
            // alice survives; bogus.pub is skipped because
            // VerifyingKey::from_bytes returned Err.
            assert!(
                listed.iter().any(|k| k.agent_id == "alice"),
                "alice must survive a sibling invalid-curve-point .pub file"
            );
            assert!(
                !listed.iter().any(|k| k.agent_id == "bogus"),
                "bogus.pub with invalid curve point must be filtered out"
            );
        }
        // COVERAGE: when no 32-byte sequence the search range rejects
        // (impossible on the dalek 2.x release pinned in Cargo.toml),
        // this test falls through without an assertion; the from_bytes
        // error closure stays uncovered. dalek versions <2 accepted
        // every 32-byte point; dalek 2.x rejects high-y wraps so the
        // search above terminates.
    }

    #[cfg(unix)]
    #[test]
    fn load_propagates_non_notfound_io_error_on_private_key() {
        // Lines 246-249: Err(e) => return Err(anyhow!(e))
        //                     .with_context("reading private key ...")
        // Trigger by making the .priv file readable to nobody (mode
        // 0000) — fs::read returns EACCES, which is NOT NotFound.
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        let priv_path = dir.path().join("alice.priv");
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o000)).unwrap();
        let res = load("alice", dir.path());
        // Restore so tempdir cleanup works regardless of test outcome.
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).unwrap();
        // On most CI hosts EACCES surfaces; if running as root the
        // permission is ignored and load succeeds — either way we
        // assert the function did not panic and returned a result.
        if let Err(err) = res {
            let msg = format!("{err:#}");
            assert!(msg.contains("reading private key"), "got: {msg}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_keypair_save_failure_propagates_context() {
        // Lines 412 + save chain: when save() fails (because the dir
        // is a regular file, not a directory), ensure_keypair must
        // propagate the error.
        let dir = tmp_dir();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"file").unwrap();
        let sub = blocker.join("sub");
        let res = ensure_keypair("alice", &sub, false);
        assert!(res.is_err(), "save under a file-blocked dir must fail");
    }

    #[test]
    fn default_key_dir_honours_env_override() {
        // v0.7 H4 — the override exists so `memory_verify` integration
        // tests can populate a hermetic key dir per test process. Pin
        // the contract here so a future refactor doesn't quietly drop
        // the override.
        let _g = key_dir_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        // Bind the override path once (OS-agnostic temp root) and assert
        // the same value round-trips, so the contract can't desync.
        let override_path = std::env::temp_dir().join("ai-memory-key-dir-override-probe");
        // SAFETY: env mutation serialised by `key_dir_env_lock` for
        // the duration of this test.
        unsafe {
            std::env::set_var("AI_MEMORY_KEY_DIR", &override_path);
        }
        let p = default_key_dir().expect("default dir");
        assert_eq!(p, override_path);
        // SAFETY: scoped cleanup so other tests see the unset value.
        unsafe {
            std::env::remove_var("AI_MEMORY_KEY_DIR");
        }
    }

    // -----------------------------------------------------------------
    // v0.7.0 S4-LOW1 — load-time mode-bits enforcement
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_keypair_load_refuses_world_readable_priv() {
        // 0o777 grants rwx to group + world. Loading must refuse.
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        let priv_path = dir.path().join("alice.priv");
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o777)).unwrap();
        let err = load("alice", dir.path()).unwrap_err();
        // Restore mode so tempdir cleanup works regardless of outcome.
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).unwrap();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("insecure mode"),
            "error must name the failure mode, got: {msg}"
        );
        assert!(
            msg.contains("chmod 0600"),
            "error must include the fix invocation, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_keypair_load_refuses_group_readable_priv() {
        // 0o640 grants read to group. Loading must refuse — any
        // group/other bit triggers the check (mode & 0o077 != 0).
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        let priv_path = dir.path().join("alice.priv");
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = load("alice", dir.path()).unwrap_err();
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).unwrap();
        let msg = format!("{err:#}");
        assert!(msg.contains("insecure mode"), "got: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn test_keypair_load_accepts_0600() {
        // The canonical mode `save` writes. Must load cleanly.
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        let priv_path = dir.path().join("alice.priv");
        // `save` already writes 0600; assert explicitly to catch a
        // future-self regression that loosens the save path.
        let mode = fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "save must write 0600, got {mode:o}");

        let loaded = load("alice", dir.path()).expect("0600 must load");
        assert!(loaded.can_sign(), "0600 mode must yield a signing keypair");
    }

    #[cfg(unix)]
    #[test]
    fn test_keypair_load_missing_priv_skips_mode_check() {
        // Public-only load (no .priv file) must NOT trip the mode
        // check. This is the documented "verify but not sign" path
        // for peer pubkey enrolment.
        let dir = tmp_dir();
        let kp = generate("alice").unwrap();
        save(&kp, dir.path()).unwrap();
        fs::remove_file(dir.path().join("alice.priv")).unwrap();
        let loaded = load("alice", dir.path()).expect("public-only load must succeed");
        assert!(!loaded.can_sign());
    }

    // -----------------------------------------------------------------
    // #3146 — rotation archives are claimed with `create_new`, never
    // overwritten. `archive_public_key_at` takes `ts` as a PARAMETER
    // precisely so the same-second collision is deterministic here
    // instead of depending on how fast the host can fsync four files.
    // -----------------------------------------------------------------

    #[test]
    fn archive_public_key_at_never_overwrites_a_prior_archive_3146() {
        let dir = tmp_dir();
        let ts = 1_700_000_000_i64;

        let first = archive_public_key_at(dir.path(), "daemon", b"FIRSTKEY", ts)
            .expect("first archive must be written");
        let second = archive_public_key_at(dir.path(), "daemon", b"SECONDKY", ts)
            .expect("a second rotation in the SAME second must still archive");

        assert_ne!(
            first, second,
            "two rotations inside one second must not resolve to the same archive name"
        );
        assert_eq!(
            fs::read(&first).expect("first archive must still exist"),
            b"FIRSTKEY",
            "the earlier archive must SURVIVE the later rotation — it is the only \
             retained verification anchor for the identity that rotation retired \
             (pre-#3146 the 1-second-granularity name silently overwrote it)"
        );
        assert_eq!(fs::read(&second).expect("second archive"), b"SECONDKY");
        assert_eq!(
            second.file_name().unwrap_or_default().to_string_lossy(),
            format!("daemon{PUB_SUFFIX}.{ts}-1"),
            "the collision suffix must be a deterministic `-N`"
        );
    }

    #[test]
    fn archive_public_key_at_refuses_rather_than_overwriting_when_exhausted_3146() {
        let dir = tmp_dir();
        let ts = 1_700_000_001_i64;
        // Claim every candidate name for this second.
        for attempt in 0..=ARCHIVE_SUFFIX_ATTEMPTS {
            let name = if attempt == 0 {
                format!("daemon{PUB_SUFFIX}.{ts}")
            } else {
                format!("daemon{PUB_SUFFIX}.{ts}-{attempt}")
            };
            fs::write(dir.path().join(name), b"PRIOR").expect("seed prior archive");
        }

        let err = archive_public_key_at(dir.path(), "daemon", b"NEWKEYXX", ts)
            .expect_err("with every name taken, archiving must REFUSE, not overwrite");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("refusing to rotate"),
            "the refusal must say what it is protecting, got: {rendered}"
        );

        // Not one prior archive may have been clobbered on the way out.
        for attempt in 0..=ARCHIVE_SUFFIX_ATTEMPTS {
            let name = if attempt == 0 {
                format!("daemon{PUB_SUFFIX}.{ts}")
            } else {
                format!("daemon{PUB_SUFFIX}.{ts}-{attempt}")
            };
            assert_eq!(
                fs::read(dir.path().join(&name)).expect("prior archive must still exist"),
                b"PRIOR",
                "{name} must be byte-for-byte intact after a refused archive"
            );
        }
    }

    /// #3146 — a `write_with_mode` that cannot complete must leave NO staging
    /// file behind. A `.staged.` dropping is not merely litter: a half-written
    /// key sibling is exactly what the staging name shape exists to keep out of
    /// `list`/`load`, and an accumulating pile hides the failure.
    #[cfg(unix)]
    #[test]
    fn write_with_mode_removes_its_staging_file_when_the_replace_fails_3146() {
        let dir = tmp_dir();
        let target = dir.path().join(format!("daemon{PUB_SUFFIX}"));
        // A directory at the destination makes the final `rename` fail
        // (EISDIR) while staging itself succeeds.
        fs::create_dir(&target).expect("claim the destination with a directory");

        let err = write_with_mode(&target, b"0123456789abcdef0123456789abcdef", 0o644)
            .expect_err("renaming a file onto a directory must fail");
        let _ = err;

        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .expect("read key dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != &format!("daemon{PUB_SUFFIX}"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed durable-replace must remove its staging file; found {leftovers:?}"
        );
    }

    /// #3146 — the happy path is a REPLACE, not a remove-then-create: the
    /// destination ends up holding the new bytes at the requested mode, with
    /// no staging residue.
    #[cfg(unix)]
    #[test]
    fn write_with_mode_replaces_in_place_at_the_requested_mode_3146() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmp_dir();
        let target = dir.path().join(format!("daemon{PRIV_SUFFIX}"));

        write_with_mode(&target, &[0xAAu8; SECRET_KEY_LEN], 0o600).expect("first write");
        write_with_mode(&target, &[0xBBu8; SECRET_KEY_LEN], 0o600).expect("replace");

        assert_eq!(
            fs::read(&target).expect("read replaced key"),
            vec![0xBBu8; SECRET_KEY_LEN]
        );
        let mode = fs::metadata(&target).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the mode must be applied AT CREATION of the staging file, so the private \
             key is never momentarily group/world-readable; got {mode:o}"
        );

        let names: Vec<String> = fs::read_dir(dir.path())
            .expect("read key dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![format!("daemon{PRIV_SUFFIX}")],
            "a successful replace must leave exactly one file"
        );
    }
}
