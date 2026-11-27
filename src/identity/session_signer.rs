// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9926 — the stdio MCP session signer.
//!
//! A stdio `ai-memory mcp` client (an AI harness) holds no Ed25519 key and
//! has no API for producing a signature over the canonical
//! [`crate::identity::sign::SignableWrite`] envelope, so before this module
//! every stdio write landed `claimed`, and under
//! `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` every one was refused.
//!
//! With `AI_MEMORY_MCP_SIGNING_KEY_FILE` set, the `mcp` boot installs ONE
//! process-global [`SessionSigner`] for the session agent
//! (`AI_MEMORY_AGENT_ID`). Covered write funnels then call [`seal_sync`],
//! which signs the row server-side over the canonical envelope, verifies the
//! signature against the agent's CURRENT bound key and records it in the
//! attested-write replay ledger before the row is persisted.
//!
//! Invariants (3-agent vote (71472661), V2, option A, condition 3):
//! - the key file is opened once with `O_NOFOLLOW`, and every check runs on
//!   that one descriptor (`fstat`): a regular file, owned by the effective
//!   uid, no group or other permission bit, exactly 32 raw bytes;
//! - the key's public half must equal the session agent's bound public key
//!   at boot (drift check), under both REQUIRE settings;
//! - a signing failure refuses the write ([`SealOutcome::Refused`]); there is
//!   no fallback to `claimed`;
//! - with the variable unset nothing is installed and every write path runs
//!   exactly as before;
//! - there is no public constructor from raw key bytes: the only way in is
//!   [`install_from_env`].
//!
//! Key bytes are never logged or put in an error message.

use std::io::Read as _;
use std::sync::OnceLock;

use anyhow::Result;
use zeroize::Zeroize as _;

use crate::identity::keypair::{AgentKeypair, canonical_public_base64, encode_public_base64};
use crate::models::Memory;

/// The environment variable that names the session signing-key file.
pub const MCP_SIGNING_KEY_FILE_ENV: &str = "AI_MEMORY_MCP_SIGNING_KEY_FILE";

/// Length of a raw Ed25519 secret key, the only accepted file content.
const SECRET_KEY_BYTES: usize = 32;

/// The variable is set to the empty string.
pub const REFUSE_EMPTY: &str = "mcp session signer (#9926): AI_MEMORY_MCP_SIGNING_KEY_FILE is set but empty; refusing to start";
/// The variable is not valid Unicode.
pub const REFUSE_NOT_UNICODE: &str = "mcp session signer (#9926): AI_MEMORY_MCP_SIGNING_KEY_FILE is not valid Unicode; refusing to start";
/// The named file does not exist.
pub const REFUSE_MISSING: &str =
    "mcp session signer (#9926): signing key file does not exist; refusing to start";
/// The named path is a symbolic link (`O_NOFOLLOW` reported `ELOOP`).
pub const REFUSE_SYMLINK: &str =
    "mcp session signer (#9926): signing key file is a symbolic link; refusing to start";
/// Any other open failure (permission denied, I/O error).
pub const REFUSE_OPEN: &str =
    "mcp session signer (#9926): signing key file could not be opened; refusing to start";
/// `fstat` or the read on the opened descriptor failed.
pub const REFUSE_READ: &str =
    "mcp session signer (#9926): signing key file could not be read; refusing to start";
/// The path is a directory, fifo, device or anything but a regular file.
pub const REFUSE_NOT_REGULAR: &str =
    "mcp session signer (#9926): signing key file is not a regular file; refusing to start";
/// The file is owned by a user other than the effective uid.
pub const REFUSE_OWNER: &str = "mcp session signer (#9926): signing key file is not owned by the effective user; refusing to start";
/// A group or other permission bit is set.
pub const REFUSE_MODE: &str = "mcp session signer (#9926): signing key file is readable or writable by group or other; refusing to start (chmod 0600)";
/// The file does not hold exactly 32 bytes.
pub const REFUSE_LENGTH: &str = "mcp session signer (#9926): signing key file must hold exactly 32 raw secret-key bytes; refusing to start";
/// No session agent (`AI_MEMORY_AGENT_ID`) is configured.
pub const REFUSE_NO_AGENT: &str = "mcp session signer (#9926): AI_MEMORY_MCP_SIGNING_KEY_FILE requires AI_MEMORY_AGENT_ID; refusing to start";
/// The session agent has no bound public key.
pub const REFUSE_UNBOUND: &str = "mcp session signer (#9926): the session agent has no bound public key; refusing to start (bind it with `ai-memory agents bind-key`)";
/// The bound key could not be read or decoded.
pub const REFUSE_BOUND_UNREADABLE: &str = "mcp session signer (#9926): the session agent's bound public key could not be read; refusing to start";
/// The key's public half is not the bound key (drift).
pub const REFUSE_MISMATCH: &str = "mcp session signer (#9926): signing key does not match the public key bound to the session agent; refusing to start";
/// The session forwards tool calls to a federation peer, so no local write
/// would ever be sealed.
pub const REFUSE_FORWARD: &str = "mcp session signer (#9926): AI_MEMORY_MCP_SIGNING_KEY_FILE cannot be combined with an MCP federation forward URL; refusing to start";
/// A second install in one process.
pub const REFUSE_ALREADY_INSTALLED: &str =
    "mcp session signer (#9926): a session signer is already installed; refusing to start";

/// Prefix of every per-write refusal [`seal_sync`] returns.
pub const SEAL_REFUSAL_PREFIX: &str =
    "ATTESTATION_FAILED: mcp session signer (#9926) refused to sign this write";

/// The one spelling of a per-write refusal: [`SEAL_REFUSAL_PREFIX`], then the reason.
fn seal_refusal(reason: impl std::fmt::Display) -> String {
    format!("{SEAL_REFUSAL_PREFIX}: {reason}")
}

/// The process-global signer. Set at most once, by [`install_from_env`].
static SESSION_SIGNER: OnceLock<SessionSigner> = OnceLock::new();

/// The installed session signer: the session agent and its keypair.
///
/// Fields are private and there is no constructor from raw bytes; the one
/// way to obtain a `SessionSigner` is [`install_from_env`] followed by
/// [`session_signer`] (CBC-03).
pub struct SessionSigner {
    agent_id: String,
    keypair: AgentKeypair,
}

impl std::fmt::Debug for SessionSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material: only the agent and the public half.
        f.debug_struct("SessionSigner")
            .field("agent_id", &self.agent_id)
            .field("public", &encode_public_base64(&self.keypair.public))
            .finish_non_exhaustive()
    }
}

impl SessionSigner {
    /// The session agent this signer signs for.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Whether a write attributed to `agent_id` is sealed by this signer.
    #[must_use]
    pub fn covers(&self, agent_id: &str) -> bool {
        self.agent_id == agent_id
    }
}

/// The installed signer, or `None` when the variable was unset at boot or
/// this process is not a stdio `mcp` session.
#[must_use]
pub fn session_signer() -> Option<&'static SessionSigner> {
    SESSION_SIGNER.get()
}

/// Lib-test-only: install `keypair` as the session signer of `agent_id`
/// without the key-file checks of [`install_from_env`] (which reads an env
/// var lib tests must not set). It covers ONLY `agent_id`, so every other
/// lib test keeps the unkeyed path. Returns the installed signer's agent:
/// a second call is a no-op that reports the first agent.
#[cfg(test)]
pub(crate) fn install_for_lib_test(agent_id: &str, keypair: AgentKeypair) -> &'static str {
    SESSION_SIGNER
        .get_or_init(|| SessionSigner {
            agent_id: agent_id.to_string(),
            keypair,
        })
        .agent_id
        .as_str()
}

/// #10012 — the session signer's keypair, for the signed-row surfaces that
/// carry their own signature column (links, signals, checkpoints, routines,
/// skills): with a session signer installed they sign with the session key,
/// never with a key-directory key that may belong to another agent.
#[must_use]
pub fn session_keypair() -> Option<AgentKeypair> {
    session_signer().map(|signer| signer.keypair.clone())
}

/// Refusal for a strict-mode write to a signed side row (offload blob, link)
/// attributed to an agent the session signer does not cover (#10012).
pub const SIDE_ROW_STRICT_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a signed row attributed to an agent other than the session agent cannot be signed; refused";

/// Which key signs a side row (offload blob, link) attributed to an agent
/// (#10012, CBC-02/05).
#[must_use]
#[derive(Debug, Clone)]
pub enum SideRowSigner {
    /// No session signer is installed: the caller keeps its own key choice.
    NoSession,
    /// The session signer covers the agent: sign with this key.
    Session(AgentKeypair),
    /// A session signer is installed but does not cover the agent and strict
    /// mode is off: the row is written unsigned (a session never signs for
    /// another agent).
    NotCoveredPermissive,
}

/// Resolve the signer of a side row attributed to `agent_id` (#10012).
///
/// # Errors
///
/// [`SIDE_ROW_STRICT_REFUSAL`] when a session signer is installed, does not
/// cover `agent_id`, and strict MCP attestation is on.
pub fn side_row_signer(agent_id: &str) -> std::result::Result<SideRowSigner, String> {
    use crate::identity::attest;
    side_row_decision(
        session_signer(),
        agent_id,
        attest::require_agent_attestation_for(attest::WriteSurface::Mcp),
    )
}

/// The pure decision behind [`side_row_signer`]: the installed signer (if
/// any), the agent the side row is attributed to, and whether strict MCP
/// attestation is on (#10012).
fn side_row_decision(
    signer: Option<&SessionSigner>,
    agent_id: &str,
    strict: bool,
) -> std::result::Result<SideRowSigner, String> {
    let Some(signer) = signer else {
        return Ok(SideRowSigner::NoSession);
    };
    if signer.covers(agent_id) {
        return Ok(SideRowSigner::Session(signer.keypair.clone()));
    }
    if strict {
        Err(SIDE_ROW_STRICT_REFUSAL.to_string())
    } else {
        Ok(SideRowSigner::NotCoveredPermissive)
    }
}

/// Refusal for an invalidation of a link whose stored signature does not
/// verify against the session key over its stored fields (#10012): the
/// session never re-signs over bytes it did not seal.
pub const EDGE_TAMPERED_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): stored link signature does not verify; refusing to re-sign";

/// Refusal for an invalidation of a link signed by, or attributed to,
/// another agent (#10012): `valid_until` is a signed field, so the write
/// would change bytes the session did not seal.
pub const EDGE_FOREIGN_SEAL_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): the invalidation changes a link signed by another agent; refused";

/// Strict-mode refusal for an invalidation of a link with no `observed_by`
/// (#10012): no observer; the session does not re-sign.
pub const EDGE_NO_OBSERVER_STRICT_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a link with no observer cannot be sealed: no observer; the session does not re-sign; refused";

/// Strict-mode refusal for an invalidation of the session agent's own link
/// that carries no signature (#10012): the session did not seal its bytes.
pub const EDGE_UNSIGNED_STRICT_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 an unsigned link the session did not seal cannot be sealed; refused";

/// What an invalidation does with the signature of the superseded link
/// under a session signer (#10012, CBC-02/05).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeReseal {
    /// No session signer: the H5 semantics are unchanged.
    NoSession,
    /// The prior signature is the session's own and verifies: re-sign.
    Reseal,
    /// The link carries no signature and strict mode is off: it stays
    /// unsigned (a session never signs bytes it did not seal).
    LeaveUnsigned,
}

/// The decision behind a link invalidation under a session signer
/// (#10012). `prior` is the link as stored before the invalidation (its
/// `valid_until` the stored one), `signature` its stored signature.
///
/// # Errors
///
/// [`EDGE_TAMPERED_REFUSAL`] for the session agent's link whose signature
/// does not verify under the session key; [`EDGE_FOREIGN_SEAL_REFUSAL`] for
/// a signed link of another agent or of no agent (both postures). Under
/// strict mode, for an unsigned link: [`EDGE_NO_OBSERVER_STRICT_REFUSAL`]
/// (no observer), [`EDGE_UNSIGNED_STRICT_REFUSAL`] (the session agent's) or
/// [`SIDE_ROW_STRICT_REFUSAL`] (another agent's).
pub fn edge_invalidation_decision(
    session: Option<&AgentKeypair>,
    prior: &crate::identity::sign::SignableLink<'_>,
    signature: Option<&[u8]>,
    strict: bool,
) -> std::result::Result<EdgeReseal, String> {
    let Some(session) = session else {
        return Ok(EdgeReseal::NoSession);
    };
    let owned = prior.observed_by == Some(session.agent_id.as_str());
    match (signature, prior.observed_by) {
        (Some(sig), _) if owned => crate::identity::verify::verify(&session.public, prior, sig)
            .map(|()| EdgeReseal::Reseal)
            .map_err(|_| EDGE_TAMPERED_REFUSAL.to_string()),
        (Some(_), _) => Err(EDGE_FOREIGN_SEAL_REFUSAL.to_string()),
        (None, _) if !strict => Ok(EdgeReseal::LeaveUnsigned),
        (None, None) => Err(EDGE_NO_OBSERVER_STRICT_REFUSAL.to_string()),
        (None, Some(_)) if owned => Err(EDGE_UNSIGNED_STRICT_REFUSAL.to_string()),
        (None, Some(_)) => Err(SIDE_ROW_STRICT_REFUSAL.to_string()),
    }
}

/// Whether the installed signer covers writes attributed to `agent_id`.
#[must_use]
pub fn covers(agent_id: &str) -> bool {
    session_signer().is_some_and(|signer| signer.covers(agent_id))
}

/// The result of [`seal_sync`] (CBC-05: a decision result is never dropped).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealOutcome {
    /// The row was signed, verified against the bound key, stamped
    /// `agent_attested` and admitted to the replay ledger.
    Signed,
    /// No signer is installed, or it signs for a different agent: the caller
    /// runs its unchanged unsigned path.
    UnsignedOtherAgent,
    /// The signer covers this agent but sealing failed: the caller MUST
    /// refuse the write with this reason.
    Refused(String),
}

/// Read the session-key file at boot and install the process-global signer.
///
/// `session_agent` is the resolved `AI_MEMORY_AGENT_ID`;
/// `forward_configured` is whether the session forwards tool calls to a
/// federation peer.
///
/// With the variable unset this is a no-op and returns `Ok(())`.
///
/// # Errors
///
/// One of the `REFUSE_*` reasons, verbatim, as a refusal; the `mcp` boot
/// aborts before the stdio loop opens.
pub fn install_from_env(
    conn: &rusqlite::Connection,
    session_agent: Option<&str>,
    forward_configured: bool,
) -> Result<()> {
    let raw = match std::env::var(MCP_SIGNING_KEY_FILE_ENV) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(crate::errors::refusal(REFUSE_NOT_UNICODE));
        }
    };
    if raw.is_empty() {
        return Err(crate::errors::refusal(REFUSE_EMPTY));
    }
    if forward_configured {
        return Err(crate::errors::refusal(REFUSE_FORWARD));
    }
    let Some(agent_id) = session_agent else {
        return Err(crate::errors::refusal(REFUSE_NO_AGENT));
    };
    let signing = read_session_key(std::path::Path::new(&raw))
        .map_err(|reason| crate::errors::refusal(reason))?;
    let public = signing.verifying_key();

    let bound = crate::db::agent_pubkey(conn, agent_id)
        .map_err(|_| crate::errors::refusal(REFUSE_BOUND_UNREADABLE))?;
    let Some(bound) = bound else {
        return Err(crate::errors::refusal(REFUSE_UNBOUND));
    };
    let bound_canonical = canonical_public_base64(&bound)
        .map_err(|_| crate::errors::refusal(REFUSE_BOUND_UNREADABLE))?;
    if encode_public_base64(&public) != bound_canonical {
        return Err(crate::errors::refusal(REFUSE_MISMATCH));
    }

    let signer = SessionSigner {
        agent_id: agent_id.to_string(),
        keypair: AgentKeypair {
            agent_id: agent_id.to_string(),
            public,
            private: Some(signing),
        },
    };
    SESSION_SIGNER
        .set(signer)
        .map_err(|_| crate::errors::refusal(REFUSE_ALREADY_INSTALLED))?;
    tracing::info!(
        agent_id,
        "mcp session signer (#9926): installed; covered stdio writes are signed server-side"
    );
    // #10040 — the boot connection gets the row-attestation funnel (every
    // later `db::open` arms it too); boot refuses when it cannot arm. It is
    // installed before the seal triggers so the seal check fires first
    // (SQLite fires the most recently created trigger first).
    match crate::storage::row_attest::sqlite::install(conn)
        .map_err(|e| crate::errors::refusal(format!("{REFUSE_ROW_ATTEST_NOT_INSTALLED}: {e:#}")))?
    {
        crate::storage::row_attest::sqlite::ArmState::Armed => {}
        crate::storage::row_attest::sqlite::ArmState::NoSigner
        | crate::storage::row_attest::sqlite::ArmState::Refusing => {
            return Err(crate::errors::refusal(REFUSE_ROW_ATTEST_NOT_INSTALLED));
        }
    }
    // #10012 — the boot connection opened before the signer existed, so it
    // gets the write-seal funnel here; every later `db::open` installs it.
    match install_write_seal_funnel(conn)? {
        FunnelState::Installed => Ok(()),
        FunnelState::NoSigner => Err(crate::errors::refusal(REFUSE_FUNNEL_NOT_INSTALLED)),
    }
}

/// The row-attestation funnel could not be armed on the boot connection
/// right after the signer was installed (#10040); boot refuses.
pub const REFUSE_ROW_ATTEST_NOT_INSTALLED: &str = "row attestation (#10040): the funnel did not install on the boot connection; refusing to start";

/// The write-seal funnel could not be installed on the boot connection right
/// after the signer was (#10012); boot refuses rather than run unsealed.
pub const REFUSE_FUNNEL_NOT_INSTALLED: &str =
    "mcp session signer (#10012): the write-seal funnel did not install; refusing to start";

/// A refusal of the #10012 write-seal funnel that names the memory row it
/// refused (CBC-02: one variant per reason, the text is a `match`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowRefusal {
    /// Strict mode, a row the session agent does not own: a session never
    /// signs for another agent.
    Foreign,
    /// Strict mode, a row of the session agent whose stored content the
    /// session did not seal (an unsigned row written outside this session,
    /// a restored unsigned row, a copy of unverified bytes).
    Unsealed,
    /// Both modes: the stored seal of the row does not verify against its
    /// current bytes; re-signing would erase the tamper evidence.
    Tampered,
    /// Both modes: the row carries another agent's verifying seal and the
    /// write changes the bytes that seal covers.
    ForeignSeal,
}

impl RowRefusal {
    /// Every variant, for exhaustive tables.
    pub const ALL: [Self; 4] = [
        Self::Foreign,
        Self::Unsealed,
        Self::Tampered,
        Self::ForeignSeal,
    ];

    /// The text before the row tag.
    #[must_use]
    pub const fn head(self) -> &'static str {
        match self {
            Self::Foreign => {
                "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a write to a memory row the session agent does not own cannot be sealed"
            }
            Self::Unsealed => {
                "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a write over memory content the session did not seal cannot be sealed"
            }
            Self::Tampered => {
                "ATTESTATION_FAILED: mcp session signer (#10012): stored seal does not verify; refusing to re-sign"
            }
            Self::ForeignSeal => {
                "ATTESTATION_FAILED: mcp session signer (#10012): the write changes bytes sealed by another agent"
            }
        }
    }

    /// The text after the row tag.
    #[must_use]
    pub const fn tail(self) -> &'static str {
        match self {
            Self::Foreign | Self::Unsealed | Self::ForeignSeal => "; refused",
            Self::Tampered => "",
        }
    }

    /// The exact refusal for row `id`: `<head> (row <tag>)<tail>`.
    #[must_use]
    pub fn text(self, id: &str) -> String {
        format!("{} (row {}){}", self.head(), row_tag(id), self.tail())
    }

    /// The row tag `text` carries when it is exactly this refusal.
    fn parse(self, text: &str) -> Option<&str> {
        let tag = text
            .strip_prefix(self.head())?
            .strip_prefix(" (row ")?
            .strip_suffix(self.tail())?
            .strip_suffix(')')?;
        (tag == INVALID_ROW_TAG || is_row_tag(tag)).then_some(tag)
    }
}

/// The tag a refusal carries for a row id outside the tag alphabet.
pub const INVALID_ROW_TAG: &str = "<invalid id>";

/// Longest row id a refusal echoes.
const ROW_TAG_MAX: usize = 64;

fn is_row_tag(id: &str) -> bool {
    (1..=ROW_TAG_MAX).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A row id as a refusal echoes it: ids are minted UUIDs, so anything outside
/// `[A-Za-z0-9_-]{1,64}` is replaced, never echoed (no injection into the
/// refusal text).
fn row_tag(id: &str) -> &str {
    if is_row_tag(id) { id } else { INVALID_ROW_TAG }
}

/// The closed-vocabulary refusal behind the text SQLite carries back from a
/// funnel trigger (#10012).
///
/// The seal function fails the statement with its refusal reason, which
/// reaches the caller as a driver error. This maps that text back to OUR
/// refusal so the caller sees the exact refusal instead of the storage
/// class: a [`RowRefusal`] text or [`SIDE_ROW_STRICT_REFUSAL`] returns
/// itself, and any other per-write seal failure returns
/// [`SEAL_REFUSAL_PREFIX`] alone (its tail may carry driver text, which never
/// reaches a caller). Every other text is `None`.
#[must_use]
pub fn funnel_refusal(text: &str) -> Option<String> {
    if text == SIDE_ROW_STRICT_REFUSAL {
        return Some(SIDE_ROW_STRICT_REFUSAL.to_string());
    }
    if RowRefusal::ALL
        .into_iter()
        .any(|refusal| refusal.parse(text).is_some())
    {
        return Some(text.to_string());
    }
    // #10040 — a row-attestation refusal keeps its exact reason (C-4).
    if text.starts_with(crate::storage::row_attest::sqlite::ROW_ATTEST_REFUSAL_PREFIX) {
        return Some(text.to_string());
    }
    text.starts_with(SEAL_REFUSAL_PREFIX)
        .then(|| SEAL_REFUSAL_PREFIX.to_string())
}

/// The SQL function the TEMP AFTER triggers call (#10012).
const SEAL_FN: &str = "ai_memory_session_seal_10012";

/// The SQL function the TEMP BEFORE UPDATE trigger calls: it records whether
/// the row's seal is intact BEFORE the statement changes it (#10012).
const PRIOR_FN: &str = "ai_memory_session_prior_10012";

/// TEMP triggers of the write-seal funnel (#10012). TEMP: they live only in
/// this connection, so nothing is added to the stored schema, and they exist
/// only on connections of a process that installed a session signer.
///
/// - BEFORE UPDATE records the seal state of the row as it was.
/// - AFTER INSERT seals a new memory row the session authored.
/// - AFTER UPDATE seals a change to a signed-envelope column (namespace,
///   title, content, kind, `created_at`) or to `metadata` (owner and seal)
///   only when the row's prior seal was the session's own and intact.
///
/// The function aborts the triggering statement on a refusal, so a refused
/// write is rolled back with it: nothing is stored or changed.
const SEAL_TRIGGERS_SQL: &str = "\
CREATE TEMP TRIGGER IF NOT EXISTS ai_memory_session_seal_insert_10012 \
AFTER INSERT ON main.memories BEGIN \
SELECT ai_memory_session_seal_10012(NEW.id, 1); END;\
CREATE TEMP TRIGGER IF NOT EXISTS ai_memory_session_prior_update_10012 \
BEFORE UPDATE OF namespace, title, content, memory_kind, created_at, metadata \
ON main.memories BEGIN \
SELECT ai_memory_session_prior_10012(OLD.id); END;\
CREATE TEMP TRIGGER IF NOT EXISTS ai_memory_session_seal_update_10012 \
AFTER UPDATE OF namespace, title, content, memory_kind, created_at, metadata \
ON main.memories BEGIN \
SELECT ai_memory_session_seal_10012(NEW.id, 0); END;";

/// The seal state of a row before a covered UPDATE changed it (#10012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriorSeal {
    /// The row is being minted by this session's own insert (the
    /// `created_at` restamp of a fresh row).
    Fresh,
    /// The row is the session agent's and its stored seal verifies.
    Intact,
    /// The row's stored seal verifies under another agent's key.
    VerifiesForeign,
    /// The row carries a seal (`write_signature` or `agent_attested`) that
    /// does not verify against its bytes.
    SignatureBroken,
    /// The row carries no seal at all.
    Unsigned,
}

/// Per-connection state shared by the funnel's SQL functions (#10012).
#[derive(Debug, Default)]
struct FunnelLedger {
    /// Prior seal state per row id, pushed by BEFORE UPDATE and popped by
    /// the matching AFTER UPDATE (a stack: a nested write of the same row
    /// pushes and pops inside its parent's AFTER).
    prior: std::collections::HashMap<String, Vec<PriorSeal>>,
    /// Rows this session's own AFTER INSERT is restamping right now.
    fresh: std::collections::HashSet<String>,
}

type SharedLedger = std::sync::Arc<std::sync::Mutex<FunnelLedger>>;

/// Run `f` on the ledger; the guard never outlives `f`, so no nested
/// statement runs while it is held (CONCURRENCY-03).
fn with_ledger<T>(
    ledger: &SharedLedger,
    f: impl FnOnce(&mut FunnelLedger) -> T,
) -> std::result::Result<T, String> {
    let mut guard = ledger
        .lock()
        .map_err(|_| seal_refusal("the funnel ledger is poisoned"))?;
    Ok(f(&mut guard))
}

/// Proof that the bytes about to be signed by [`reseal_with`] were supplied
/// by this session in this call (#10012). Private, no public constructor:
/// only the funnel classifications ([`decide_update`], [`decide_insert`])
/// build one, and only for a fresh insert, a consolidated summary, a copy of
/// a source that carries the session's own verifying seal, or a change to a
/// row whose prior seal was the session's own and intact.
#[must_use]
struct SessionAuthored(());

/// Whether [`install_write_seal_funnel`] armed the connection (CBC-02/05).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunnelState {
    /// A session signer is installed and this connection now seals every
    /// memory-row write through the TEMP triggers.
    Installed,
    /// No session signer: the connection is unchanged.
    NoSigner,
}

/// Arm `conn` with the #10012 write-seal funnel when a session signer is
/// installed.
///
/// Every memory row any MCP tool inserts or changes on this connection then
/// passes [`seal_stored_row`] inside the same statement. The session signs
/// only bytes it authored in this call (a fresh row, a consolidated summary,
/// a copy of its own verifying row, a change to its own intact row); a row
/// whose prior seal is absent, foreign or broken is never given a session
/// seal: the write is left as written or refused, and a failure aborts the
/// statement.
///
/// # Errors
///
/// Registering the SQL functions or creating the TEMP triggers failed.
pub fn install_write_seal_funnel(conn: &rusqlite::Connection) -> Result<FunnelState> {
    use rusqlite::functions::FunctionFlags;
    if session_signer().is_none() {
        return Ok(FunnelState::NoSigner);
    }
    let ledger = SharedLedger::default();
    let prior_ledger = std::sync::Arc::clone(&ledger);
    conn.create_scalar_function(PRIOR_FN, 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        let id: String = ctx.get(0)?;
        // SAFETY: the connection reference is used only for the duration of
        // this call, on the thread that runs the statement, and is never
        // closed or stored (rusqlite `Context::get_connection` contract).
        let conn = unsafe { ctx.get_connection() }?;
        record_prior_seal(&conn, &prior_ledger, &id)
            .map(|_recorded| 0_i64)
            .map_err(|reason| rusqlite::Error::UserFunctionError(reason.into()))
    })?;
    let peek_ledger = std::sync::Arc::clone(&ledger);
    conn.create_scalar_function(PEEK_FN, 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        let id: String = ctx.get(0)?;
        // SAFETY: as above (rusqlite `Context::get_connection` contract).
        let conn = unsafe { ctx.get_connection() }?;
        pending_seal_refusal(&conn, &peek_ledger, &id)
            .map_err(|reason| rusqlite::Error::UserFunctionError(reason.into()))
    })?;
    conn.create_scalar_function(SEAL_FN, 2, FunctionFlags::SQLITE_UTF8, move |ctx| {
        let id: String = ctx.get(0)?;
        let inserted: i64 = ctx.get(1)?;
        // SAFETY: as above (rusqlite `Context::get_connection` contract).
        let conn = unsafe { ctx.get_connection() }?;
        let phase = if inserted == 1 {
            RowWrite::Inserted
        } else {
            RowWrite::Updated
        };
        match seal_stored_row(&conn, &ledger, &id, phase) {
            Ok(StoredSeal::AlreadySealed | StoredSeal::LeftAsWritten) => Ok(0_i64),
            Ok(StoredSeal::Sealed(Resealed)) => Ok(1_i64),
            Err(reason) => Err(rusqlite::Error::UserFunctionError(reason.into())),
        }
    })?;
    conn.execute_batch(SEAL_TRIGGERS_SQL)?;
    Ok(FunnelState::Installed)
}

/// Which write fired the funnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowWrite {
    Inserted,
    Updated,
}

/// What [`seal_stored_row`] did with one row.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredSeal {
    /// The stored seal already verifies against the owner's anchored key.
    AlreadySealed,
    /// The session signer sealed bytes the session authored.
    Sealed(Resealed),
    /// Strict mode is off and the session did not author the row's signed
    /// bytes: left exactly as written, never given a session seal.
    LeftAsWritten,
}

/// What the funnel does with one written row (#10012), before any signing.
#[must_use]
enum SealDecision {
    /// The stored seal already verifies.
    AlreadySealed,
    /// The session authored the signed bytes: seal them.
    Seal(SessionAuthored),
    /// Leave the row as written (permissive) or refuse with this reason
    /// (strict); [`Self::resolve`] picks by the posture.
    NotSessionBytes(RowRefusal),
    /// Refuse in both postures.
    Refuse(RowRefusal),
}

/// The owner (`metadata.agent_id`) of `row`.
fn row_owner(row: &Memory) -> Option<&str> {
    row.metadata
        .get(crate::mcp::param_names::AGENT_ID)
        .and_then(serde_json::Value::as_str)
}

/// Whether `row` carries any seal material (an `agent_attested` level or a
/// `write_signature`).
fn carries_seal(row: &Memory) -> bool {
    use crate::identity::verify::AttestLevel;
    let level = row
        .metadata
        .get(crate::models::field_names::ATTEST_LEVEL)
        .and_then(serde_json::Value::as_str);
    level == Some(AttestLevel::AgentAttested.as_str())
        || row
            .metadata
            .get(crate::models::field_names::WRITE_SIGNATURE)
            .is_some_and(|value| !value.is_null())
}

fn read_row(conn: &rusqlite::Connection, id: &str) -> std::result::Result<Memory, String> {
    crate::db::get_any(conn, id)
        .map_err(|e| format!("{SEAL_REFUSAL_PREFIX}: written row read failed: {e}"))?
        .ok_or_else(|| format!("{SEAL_REFUSAL_PREFIX}: the written row is gone"))
}

/// Classify the seal of `row` as it is now.
fn classify_seal(signer: &SessionSigner, row: &Memory) -> PriorSeal {
    let owner = row_owner(row);
    if stored_seal_verifies(row, owner) {
        return if owner.is_some_and(|agent| signer.covers(agent)) {
            PriorSeal::Intact
        } else {
            PriorSeal::VerifiesForeign
        };
    }
    if carries_seal(row) {
        PriorSeal::SignatureBroken
    } else {
        PriorSeal::Unsigned
    }
}

/// BEFORE UPDATE body: record the seal state of row `id` as it is now.
/// Returns the state recorded, or `None` when no session signer is
/// installed (nothing is recorded).
fn record_prior_seal(
    conn: &rusqlite::Connection,
    ledger: &SharedLedger,
    id: &str,
) -> std::result::Result<Option<PriorSeal>, String> {
    let Some(signer) = session_signer() else {
        return Ok(None);
    };
    let fresh = with_ledger(ledger, |state| state.fresh.contains(id))?;
    let prior = if fresh {
        PriorSeal::Fresh
    } else {
        classify_seal(signer, &read_row(conn, id)?)
    };
    with_ledger(ledger, |state| {
        state.prior.entry(id.to_string()).or_default().push(prior);
    })?;
    Ok(Some(prior))
}

/// The SQL function the #10040 row-attestation funnel calls when a memory
/// row it is about to attest changed outside the funnel: it returns the
/// refusal the pending AFTER UPDATE seal check of row `id` will return, or
/// NULL. SQLite does not fix the order TEMP triggers of one table fire in,
/// so this makes the refusal of a tampered row the same whichever fires
/// first.
pub const PEEK_FN: &str = "ai_memory_session_seal_peek_10012";

/// [`PEEK_FN`] body: the refusal [`seal_stored_row`] would return for the
/// update of row `id` now in flight (its prior state is peeked, not popped),
/// or `None` when it would not refuse or no update of `id` is in flight.
fn pending_seal_refusal(
    conn: &rusqlite::Connection,
    ledger: &SharedLedger,
    id: &str,
) -> std::result::Result<Option<String>, String> {
    use crate::identity::attest;
    let Some(signer) = session_signer() else {
        return Ok(None);
    };
    let Some(prior) = with_ledger(ledger, |state| {
        state.prior.get(id).and_then(|stack| stack.last().copied())
    })?
    else {
        return Ok(None);
    };
    let row = read_row(conn, id)?;
    let strict = attest::require_agent_attestation_for(attest::WriteSurface::Mcp);
    Ok(match decide_update(signer, &row, prior) {
        SealDecision::Refuse(refusal) => Some(refusal.text(id)),
        SealDecision::NotSessionBytes(refusal) if strict => Some(refusal.text(id)),
        SealDecision::AlreadySealed | SealDecision::Seal(_) | SealDecision::NotSessionBytes(_) => {
            None
        }
    })
}

/// The #10012 funnel body: seal row `id` when the session authored its
/// signed bytes, else leave it or refuse.
fn seal_stored_row(
    conn: &rusqlite::Connection,
    ledger: &SharedLedger,
    id: &str,
    phase: RowWrite,
) -> std::result::Result<StoredSeal, String> {
    use crate::identity::attest;
    let Some(signer) = session_signer() else {
        return Ok(StoredSeal::LeftAsWritten);
    };
    let prior = match phase {
        RowWrite::Updated => Some(
            with_ledger(ledger, |state| {
                let popped = state.prior.get_mut(id).and_then(Vec::pop);
                if state.prior.get(id).is_some_and(Vec::is_empty) {
                    state.prior.remove(id);
                }
                popped
            })?
            .ok_or_else(|| seal_refusal("no prior seal state was recorded for the row"))?,
        ),
        RowWrite::Inserted => None,
    };
    let row = read_row(conn, id)?;
    let strict = attest::require_agent_attestation_for(attest::WriteSurface::Mcp);
    let decision = match prior {
        Some(prior) => decide_update(signer, &row, prior),
        None => decide_insert(conn, signer, &row)?,
    };
    let proof = match decision {
        SealDecision::AlreadySealed => return Ok(StoredSeal::AlreadySealed),
        SealDecision::Refuse(refusal) => return Err(refusal.text(id)),
        SealDecision::NotSessionBytes(refusal) => {
            return if strict {
                Err(refusal.text(id))
            } else {
                Ok(StoredSeal::LeftAsWritten)
            };
        }
        SealDecision::Seal(proof) => proof,
    };
    // A row minted now with a sub-microsecond `created_at` is restamped, the
    // same as `seal_with` does before an insert; a changed row keeps its
    // `created_at` (its identity) and `reseal_with` refuses an unstable one.
    if phase == RowWrite::Inserted && !attest::created_at_is_storage_stable(&row.created_at) {
        with_ledger(ledger, |state| state.fresh.insert(id.to_string()))?;
        let restamp = conn.execute(
            "UPDATE memories SET created_at = ?1 WHERE id = ?2",
            rusqlite::params![attest::now_attestable_rfc3339(), id],
        );
        with_ledger(ledger, |state| state.fresh.remove(id))?;
        restamp.map_err(|e| format!("{SEAL_REFUSAL_PREFIX}: restamping created_at failed: {e}"))?;
        // The restamp is itself a covered write: its own trigger has sealed
        // the row already (classified fresh), so only re-check it.
        let restamped = read_row(conn, id)?;
        if stored_seal_verifies(&restamped, row_owner(&restamped)) {
            return Ok(StoredSeal::Sealed(Resealed));
        }
    }
    reseal_with(conn, id, signer, proof)
        .map(StoredSeal::Sealed)
        .map_err(seal_refusal)
}

/// The refusal for a write over bytes the session did not seal: `Unsealed`
/// for the session agent's row, `Foreign` for any other owner.
fn not_session_bytes(signer: &SessionSigner, row: &Memory) -> SealDecision {
    if row_owner(row).is_some_and(|agent| signer.covers(agent)) {
        SealDecision::NotSessionBytes(RowRefusal::Unsealed)
    } else {
        SealDecision::NotSessionBytes(RowRefusal::Foreign)
    }
}

/// AFTER UPDATE: seal only a change to a row whose prior seal was the
/// session's own and intact (or a fresh row's restamp).
fn decide_update(signer: &SessionSigner, row: &Memory, prior: PriorSeal) -> SealDecision {
    if stored_seal_verifies(row, row_owner(row)) {
        return SealDecision::AlreadySealed;
    }
    let owned = row_owner(row).is_some_and(|agent| signer.covers(agent));
    match prior {
        PriorSeal::Fresh | PriorSeal::Intact if owned => SealDecision::Seal(SessionAuthored(())),
        PriorSeal::Fresh | PriorSeal::Intact => SealDecision::NotSessionBytes(RowRefusal::Foreign),
        PriorSeal::SignatureBroken => SealDecision::Refuse(RowRefusal::Tampered),
        PriorSeal::VerifiesForeign => SealDecision::Refuse(RowRefusal::ForeignSeal),
        PriorSeal::Unsigned => not_session_bytes(signer, row),
    }
}

/// AFTER INSERT: seal a row the session authored in this call; a restored
/// row or a copy of bytes the session did not seal is never sealed.
fn decide_insert(
    conn: &rusqlite::Connection,
    signer: &SessionSigner,
    row: &Memory,
) -> std::result::Result<SealDecision, String> {
    use crate::identity::attest::ReownKind;
    if stored_seal_verifies(row, row_owner(row)) {
        return Ok(SealDecision::AlreadySealed);
    }
    if !row_owner(row).is_some_and(|agent| signer.covers(agent)) {
        return Ok(SealDecision::NotSessionBytes(RowRefusal::Foreign));
    }
    // A restore re-inserts archived bytes while the archive row still exists.
    let restored = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM archived_memories WHERE id = ?1)",
            rusqlite::params![row.id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|e| seal_refusal(format!("archive lookup failed: {e}")))?;
    if restored {
        return Ok(if carries_seal(row) {
            SealDecision::Refuse(RowRefusal::Tampered)
        } else {
            SealDecision::NotSessionBytes(RowRefusal::Unsealed)
        });
    }
    let reason = row
        .metadata
        .get(crate::models::field_names::ATTEST_RESET_REASON)
        .and_then(serde_json::Value::as_str);
    let Some(reason) = reason else {
        return Ok(SealDecision::Seal(SessionAuthored(())));
    };
    let source_key = match ReownKind::from_reason(reason) {
        // The summary is the text this call supplied (caller or LLM tier).
        Some(ReownKind::Consolidate) => return Ok(SealDecision::Seal(SessionAuthored(()))),
        Some(kind) => kind.provenance_key(),
        // An unknown reset reason names no clone path: not provably authored.
        None => return Ok(SealDecision::NotSessionBytes(RowRefusal::Unsealed)),
    };
    let source = source_key
        .and_then(|key| row.metadata.get(key))
        .and_then(serde_json::Value::as_str)
        .map(|source_id| crate::db::get_any(conn, source_id))
        .transpose()
        .map_err(|e| seal_refusal(format!("clone source read failed: {e}")))?
        .flatten();
    let source_intact = source
        .as_ref()
        .is_some_and(|source| classify_seal(signer, source) == PriorSeal::Intact);
    Ok(if source_intact {
        SealDecision::Seal(SessionAuthored(()))
    } else {
        SealDecision::NotSessionBytes(RowRefusal::Unsealed)
    })
}

/// Exact reason a persisted row's in-row `write_signature` failed verification
/// against the out-of-database [`crate::storage::row_attest::anchor::TrustAnchor`]
/// (#10111). Never falls back to the current key or any database-stored key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealDefect {
    /// No usable out-of-database trust anchor was loaded.
    Unanchored(crate::storage::row_attest::anchor::Unanchored),
    /// The row claims `agent_attested` but its `write_signature` is missing,
    /// not valid standard base64, or not 64 bytes.
    MalformedSignature,
    /// The trust anchor holds no key at all for the row's owner.
    UnknownAgent {
        /// Row owner (`metadata.agent_id`).
        agent_id: String,
    },
    /// The trust anchor holds keys for `agent_id`, but none verified the
    /// signature (retired key missing from anchor, unanchored key, or forged).
    UnknownKey {
        /// Row owner (`metadata.agent_id`).
        agent_id: String,
    },
    /// The signature verified under an anchored key belonging to another agent.
    OtherAgent {
        /// Matching key id.
        key_id: String,
        /// Row owner (`metadata.agent_id`).
        agent_id: String,
        /// Agent the key is anchored to.
        anchored_agent: String,
    },
    /// The row's write timestamp is not a valid RFC 3339 timestamp.
    BadTime {
        /// Matching key id.
        key_id: String,
        /// The malformed timestamp string.
        timestamp: String,
    },
    /// The signing key is anchored to the owner, but the row's write time is
    /// outside that key's anchored validity window.
    OutOfRange {
        /// Matching key id.
        key_id: String,
        /// Window start, unix seconds (`None` for the first key).
        valid_from: Option<i64>,
        /// Window end, unix seconds (`None` for the current key).
        valid_to: Option<i64>,
    },
}

impl std::fmt::Display for SealDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unanchored(why) => write!(f, "write seal unanchored: {why}"),
            Self::MalformedSignature => f.write_str("write seal signature is missing or malformed"),
            Self::UnknownAgent { agent_id } => write!(
                f,
                "write seal names agent {agent_id} with no key in the trust anchor"
            ),
            Self::UnknownKey { agent_id } => write!(
                f,
                "write seal for agent {agent_id} does not match any key in the trust anchor"
            ),
            Self::OtherAgent {
                key_id,
                agent_id,
                anchored_agent,
            } => write!(
                f,
                "write seal key_id {key_id} is anchored to agent {anchored_agent}, not {agent_id}"
            ),
            Self::BadTime { key_id, timestamp } => write!(
                f,
                "write seal key_id {key_id} has invalid write timestamp {timestamp:?}"
            ),
            Self::OutOfRange {
                key_id,
                valid_from,
                valid_to,
            } => write!(
                f,
                "write seal key_id {key_id} used outside its anchored validity (from {valid_from:?} to {valid_to:?})"
            ),
        }
    }
}

/// Verdict of verifying a persisted memory row's in-row `write_signature`
/// against the out-of-database trust anchor (#10111).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredSealCheck {
    /// The row carries `agent_attested` and a `write_signature` that verified
    /// under `key_id` within its anchored validity window.
    Verified {
        /// Anchored key id (`row_attest::key_id_of`) that verified the seal.
        key_id: String,
    },
    /// The row carries no `agent_attested` seal (no owner or `attest_level != agent_attested`).
    Unsealed,
    /// The row carries a seal that failed verification against the anchor,
    /// with the exact defect reason.
    Defect(SealDefect),
}

impl StoredSealCheck {
    /// True iff the seal verified under an anchored key inside its validity window.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// Verify the in-row write seal of `row` against an explicit out-of-database
/// trust anchor (#10111). Takes no database handle: no verifying key can ever
/// be read from the store (#10086).
pub fn verify_row_seal_with(
    row: &Memory,
    anchor: &crate::storage::row_attest::anchor::AnchorLoad,
) -> StoredSealCheck {
    verify_stored_seal_with(row, row_owner(row), anchor)
}

/// Verify the in-row write seal of `row` against the process key directory's
/// trust anchor ([`crate::storage::row_attest::anchor::TrustAnchor::from_key_dir`], #10111).
pub fn verify_row_seal(row: &Memory) -> StoredSealCheck {
    let anchor = crate::storage::row_attest::anchor::TrustAnchor::from_key_dir();
    verify_row_seal_with(row, &anchor)
}

/// Whether the in-row seal of `row` verifies against its owner's anchored key
/// (current or retired within its validity window, NOTICE 4c / E-3 / #10111).
#[cfg(feature = "sal")]
#[must_use]
pub(crate) fn row_seal_verifies(row: &Memory) -> bool {
    verify_row_seal(row).is_verified()
}

/// Whether `row` carries `agent_attested` and a `write_signature` that
/// verifies over its stored envelope against the owner's anchored key within
/// its validity window (#10111).
fn stored_seal_verifies(row: &Memory, owner: Option<&str>) -> bool {
    let anchor = crate::storage::row_attest::anchor::TrustAnchor::from_key_dir();
    verify_stored_seal_with(row, owner, &anchor).is_verified()
}

fn verify_stored_seal_with(
    row: &Memory,
    owner: Option<&str>,
    anchor: &crate::storage::row_attest::anchor::AnchorLoad,
) -> StoredSealCheck {
    use crate::identity::attest::content_sha256;
    use crate::identity::sign::SignableWrite;
    use crate::identity::verify::{AttestLevel, SIGNATURE_LEN, verify_write};
    use crate::storage::row_attest::anchor::{AnchorLoad, KeyRefusal};
    use base64::Engine as _;

    let Some(owner) = owner else {
        return StoredSealCheck::Unsealed;
    };
    let level = row
        .metadata
        .get(crate::models::field_names::ATTEST_LEVEL)
        .and_then(serde_json::Value::as_str);
    if level != Some(AttestLevel::AgentAttested.as_str()) {
        return StoredSealCheck::Unsealed;
    }
    let Some(signature) = row
        .metadata
        .get(crate::models::field_names::WRITE_SIGNATURE)
        .and_then(serde_json::Value::as_str)
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .filter(|bytes| bytes.len() == SIGNATURE_LEN)
    else {
        return StoredSealCheck::Defect(SealDefect::MalformedSignature);
    };
    let anchor = match anchor {
        AnchorLoad::Anchored(anchor) => anchor,
        AnchorLoad::Unanchored(why) => {
            return StoredSealCheck::Defect(SealDefect::Unanchored(why.clone()));
        }
    };
    let content_hash = content_sha256(&row.content);
    let write = SignableWrite {
        agent_id: owner,
        namespace: &row.namespace,
        title: &row.title,
        kind: row.memory_kind.as_str(),
        created_at: &row.created_at,
        content_sha256: &content_hash,
    };
    match anchor.verify_key_for_span(
        owner,
        &row.created_at,
        Some(row.updated_at.as_str()),
        |public| verify_write(public, &write, &signature).is_ok(),
    ) {
        Ok(key_id) => StoredSealCheck::Verified { key_id },
        Err(refusal) => StoredSealCheck::Defect(match refusal.refusal {
            KeyRefusal::UnknownAgent => SealDefect::UnknownAgent {
                agent_id: owner.to_string(),
            },
            KeyRefusal::UnknownKey => SealDefect::UnknownKey {
                agent_id: owner.to_string(),
            },
            KeyRefusal::OtherAgent(anchored_agent) => SealDefect::OtherAgent {
                key_id: refusal.key_id.unwrap_or_default(),
                agent_id: owner.to_string(),
                anchored_agent,
            },
            KeyRefusal::BadTime => {
                let bad_ts = if chrono::DateTime::parse_from_rfc3339(&row.created_at).is_err() {
                    row.created_at.clone()
                } else {
                    row.updated_at.clone()
                };
                SealDefect::BadTime {
                    key_id: refusal.key_id.unwrap_or_default(),
                    timestamp: bad_ts,
                }
            }
            KeyRefusal::OutOfRange {
                valid_from,
                valid_to,
            } => SealDefect::OutOfRange {
                key_id: refusal.key_id.unwrap_or_default(),
                valid_from,
                valid_to,
            },
        }),
    }
}

/// Open `path` once with `O_NOFOLLOW`, check the descriptor with `fstat` and
/// read exactly [`SECRET_KEY_BYTES`] from it. Every intermediate buffer is
/// zeroized. The error is one `REFUSE_*` reason; it never carries key bytes.
fn read_session_key(
    path: &std::path::Path,
) -> std::result::Result<ed25519_dalek::SigningKey, &'static str> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK: a fifo planted at the path cannot park the boot.
        options
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path).map_err(|error| open_refusal(&error))?;
    let meta = file.metadata().map_err(|_| REFUSE_READ)?;
    if !meta.is_file() {
        return Err(REFUSE_NOT_REGULAR);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid is always defined on unix and has no preconditions (UNSAFE-01).
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(REFUSE_OWNER);
        }
        if meta.mode() & 0o077 != 0 {
            return Err(REFUSE_MODE);
        }
    }
    // Bounded read: one byte over the key length proves an over-long file
    // without reading it whole; the buffer is sized up front so it never
    // reallocates (a reallocation would leave an unwiped copy).
    let mut raw = zeroize::Zeroizing::new(Vec::with_capacity(SECRET_KEY_BYTES + 1));
    let cap = u64::try_from(SECRET_KEY_BYTES + 1).map_err(|_| REFUSE_READ)?;
    file.take(cap)
        .read_to_end(&mut raw)
        .map_err(|_| REFUSE_READ)?;
    let mut key = [0u8; SECRET_KEY_BYTES];
    if raw.len() != SECRET_KEY_BYTES {
        return Err(REFUSE_LENGTH);
    }
    key.copy_from_slice(&raw);
    let signing = ed25519_dalek::SigningKey::from_bytes(&key);
    key.zeroize();
    Ok(signing)
}

/// Map an open failure to its exact refusal.
fn open_refusal(error: &std::io::Error) -> &'static str {
    #[cfg(unix)]
    {
        if error.raw_os_error() == Some(libc::ELOOP) {
            return REFUSE_SYMLINK;
        }
    }
    if error.kind() == std::io::ErrorKind::NotFound {
        REFUSE_MISSING
    } else {
        REFUSE_OPEN
    }
}

/// Seal one about-to-be-persisted row with the session signer.
///
/// When the signer covers `agent_id`:
/// 1. a `created_at` that is not storage-stable is restamped with
///    [`crate::identity::attest::now_attestable_rfc3339`] (the row is being
///    minted now);
/// 2. [`crate::identity::attest::redact_before_sign`] runs, so the signed
///    bytes are the persisted bytes;
/// 3. the row is signed over the canonical envelope;
/// 4. the signature is verified against the agent's CURRENT bound key (a key
///    rebound after boot refuses) and `attest_level` is stamped;
/// 5. the envelope is admitted to the attested-write replay ledger;
/// 6. the signature is persisted into the row metadata.
///
/// Any failure returns [`SealOutcome::Refused`]; nothing falls back to
/// `claimed`. The reason never carries key material.
pub fn seal_sync(conn: &rusqlite::Connection, mem: &mut Memory, agent_id: &str) -> SealOutcome {
    let Some(signer) = session_signer().filter(|signer| signer.covers(agent_id)) else {
        return SealOutcome::UnsignedOtherAgent;
    };
    match seal_with(conn, mem, signer) {
        Ok(Sealed) => SealOutcome::Signed,
        Err(reason) => SealOutcome::Refused(seal_refusal(reason)),
    }
}

/// Proof that [`seal_with`] signed, verified, admitted and persisted the row
/// (a typed success instead of a unit `Ok`, per CBC-05).
#[must_use]
struct Sealed;

fn seal_with(
    conn: &rusqlite::Connection,
    mem: &mut Memory,
    signer: &SessionSigner,
) -> std::result::Result<Sealed, String> {
    use crate::identity::attest;
    use crate::identity::verify::AttestLevel;

    if !attest::created_at_is_storage_stable(&mem.created_at) {
        mem.created_at = attest::now_attestable_rfc3339();
    }
    attest::redact_before_sign(mem);
    let signature = attest::sign_memory_write(&signer.keypair, mem, &signer.agent_id)
        .map_err(|e| format!("signing failed: {e}"))?;
    let bound = crate::db::agent_pubkey(conn, &signer.agent_id)
        .map_err(|e| format!("bound key lookup failed: {e}"))?;
    let level = attest::stamp_attestation(
        mem,
        &signer.agent_id,
        bound.as_deref(),
        Some(&signature),
        true,
    )
    .map_err(|e| e.to_string())?;
    match level {
        AttestLevel::AgentAttested => {}
        AttestLevel::Claimed => {
            return Err("the signed write did not verify as agent_attested".to_string());
        }
    }
    match attest::admit_attested_write_sync(conn, &signer.agent_id, &mem.created_at, &signature)? {
        attest::AttestedWriteAdmission::Fresh => {}
        attest::AttestedWriteAdmission::Replay => {
            return Err(attest::ATTESTED_WRITE_REPLAY_REFUSAL.to_string());
        }
    }
    // This row is authored here and now, so a `write_signature` key that
    // arrived in caller metadata is not an origin signature to preserve: drop
    // it so the persisted signature is the one just verified.
    if let Some(obj) = mem.metadata.as_object_mut() {
        obj.remove(crate::models::field_names::WRITE_SIGNATURE);
    }
    attest::persist_write_signature(mem, &signature);
    Ok(Sealed)
}

/// Refusal for a signed `memory_store` whose merge detour cannot be
/// re-sealed: no session signer covers the agent (#10011).
pub const MERGE_RESEAL_REFUSAL: &str = "ATTESTATION_FAILED: a signed memory_store that merges into an existing row needs the session signer of its agent to re-sign the merged row (#10011); retry with on_conflict \"version\" or a new title";

/// Refusal for a signed `memory_store` whose merge target did not carry the
/// session's own intact seal before the merge, so the merged row mixes bytes
/// the session never sealed (#10012): it is never re-signed.
pub const MERGE_UNSEALED_PRIOR_REFUSAL: &str = "ATTESTATION_FAILED: a signed memory_store that merges into an existing row needs that row to carry the session's own intact seal (#10012); retry with on_conflict \"version\" or a new title";

/// Proof that the stored row carries a session seal that verifies as
/// `agent_attested` against the bound key (CBC-05).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resealed;

/// Check that row `id` is sealed by the session after a merge rewrote its
/// content (#10011, #10012).
///
/// The merge runs on a connection armed with the write-seal funnel
/// ([`install_write_seal_funnel`]), whose AFTER UPDATE trigger already
/// re-sealed the merged row when, and only when, its prior seal was the
/// session's own and intact. This never signs: it proves the stored row now
/// verifies under the session key. A merge into a row whose prior seal was
/// absent, foreign or broken is refused here (or by the trigger, under strict
/// mode), never re-signed.
///
/// The caller runs this inside the write transaction that wrote the content,
/// so an `Err` rolls the merge back: a merged row is never committed as
/// claimed when its write was signed.
///
/// # Errors
///
/// [`MERGE_RESEAL_REFUSAL`] when no session signer covers `agent_id`;
/// [`MERGE_UNSEALED_PRIOR_REFUSAL`] when the stored row does not verify under
/// the session key; a reason starting with [`SEAL_REFUSAL_PREFIX`] when the
/// row or the bound key cannot be read.
pub fn reseal_row_sync(
    conn: &rusqlite::Connection,
    id: &str,
    agent_id: &str,
) -> std::result::Result<Resealed, String> {
    let Some(signer) = session_signer().filter(|signer| signer.covers(agent_id)) else {
        return Err(MERGE_RESEAL_REFUSAL.to_string());
    };
    let row = read_row(conn, id)?;
    if row_owner(&row).is_some_and(|agent| signer.covers(agent))
        && stored_seal_verifies(&row, row_owner(&row))
    {
        Ok(Resealed)
    } else {
        Err(MERGE_UNSEALED_PRIOR_REFUSAL.to_string())
    }
}

/// Sign row `id` as stored with the session key. Only the funnel calls it,
/// and only with a [`SessionAuthored`] proof that the bytes are this call's.
fn reseal_with(
    conn: &rusqlite::Connection,
    id: &str,
    signer: &SessionSigner,
    _authored: SessionAuthored,
) -> std::result::Result<Resealed, String> {
    use crate::identity::attest;
    use crate::identity::verify::AttestLevel;
    use base64::Engine as _;

    // `get_any`: a quarantined or tombstoned row still has an owner and a
    // stored envelope to seal (#10012); `get` would hide it.
    let mut row = crate::db::get_any(conn, id)
        .map_err(|e| format!("merged row read failed: {e}"))?
        .ok_or_else(|| "the merged row is gone".to_string())?;
    let owner = row
        .metadata
        .get(crate::mcp::param_names::AGENT_ID)
        .and_then(serde_json::Value::as_str);
    if owner != Some(signer.agent_id.as_str()) {
        return Err("the merged row is not owned by the session agent".to_string());
    }
    // The row keeps its original `created_at`; restamping it here would
    // rewrite the row's identity, so an unstable value refuses instead.
    if !attest::created_at_is_storage_stable(&row.created_at) {
        return Err("the merged row created_at is not storage-stable".to_string());
    }
    let stored = (row.title.clone(), row.content.clone(), row.tags.clone());
    attest::redact_before_sign(&mut row);
    if (&row.title, &row.content, &row.tags) != (&stored.0, &stored.1, &stored.2) {
        return Err("the merged row bytes differ from their redacted form".to_string());
    }
    let signature = attest::sign_memory_write(&signer.keypair, &row, &signer.agent_id)
        .map_err(|e| format!("signing failed: {e}"))?;
    let bound = crate::db::agent_pubkey(conn, &signer.agent_id)
        .map_err(|e| format!("bound key lookup failed: {e}"))?;
    let level = attest::stamp_attestation(
        &mut row,
        &signer.agent_id,
        bound.as_deref(),
        Some(&signature),
        true,
    )
    .map_err(|e| e.to_string())?;
    match level {
        AttestLevel::AgentAttested => {}
        AttestLevel::Claimed => {
            return Err("the re-signed row did not verify as agent_attested".to_string());
        }
    }
    match attest::admit_attested_write_sync(conn, &signer.agent_id, &row.created_at, &signature)? {
        attest::AttestedWriteAdmission::Fresh | attest::AttestedWriteAdmission::Replay => {}
    }
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    crate::storage::row_attestation::set_row_attestation(
        conn,
        id,
        AttestLevel::AgentAttested.as_str(),
        &signature_b64,
    )
    .map_err(|e| format!("persisting the seal failed: {e}"))?;
    Ok(Resealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-session key isolation: the signer covers exactly its own agent.
    /// No stdio funnel reaches `covers` with a foreign agent (the identity
    /// layer refuses the mismatch first), so this guard is pinned here.
    #[test]
    fn signer_covers_only_its_session_agent_9926() {
        let signer = SessionSigner {
            agent_id: "agent-a-9926".to_string(),
            keypair: crate::identity::keypair::generate("agent-a-9926").expect("keypair"),
        };
        assert!(signer.covers("agent-a-9926"));
        for other in [
            "agent-b-9926",
            "agent-a-9926x",
            "agent-a-992",
            "",
            "AGENT-A-9926",
        ] {
            assert!(!signer.covers(other), "signer must not cover {other:?}");
        }
    }

    #[test]
    fn open_refusal_maps_each_kind_9926() {
        let rows: [(std::io::Error, &str); 3] = [
            (
                std::io::Error::from(std::io::ErrorKind::NotFound),
                REFUSE_MISSING,
            ),
            (
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                REFUSE_OPEN,
            ),
            (
                std::io::Error::from_raw_os_error(libc::ELOOP),
                REFUSE_SYMLINK,
            ),
        ];
        for (error, expected) in rows {
            assert_eq!(open_refusal(&error), expected);
        }
    }

    #[test]
    fn read_session_key_refuses_wrong_lengths_9926() {
        let dir = tempfile::tempdir_in(
            std::env::var_os("TMPDIR")
                .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from),
        )
        .expect("tempdir");
        for len in [0usize, 1, 31, 33, 64, 4096] {
            let path = dir.path().join(format!("k{len}"));
            std::fs::write(&path, vec![7u8; len]).expect("write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
            assert_eq!(
                read_session_key(&path).err(),
                Some(REFUSE_LENGTH),
                "len {len}"
            );
        }
        let ok = dir.path().join("k32");
        std::fs::write(&ok, [7u8; 32]).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert!(read_session_key(&ok).is_ok());
        assert_eq!(read_session_key(dir.path()).err(), Some(REFUSE_NOT_REGULAR));
    }

    const SIDE_SESSION_AGENT_10012: &str = "agent-side-session-10012";
    const SIDE_OTHER_AGENT_10012: &str = "agent-side-other-10012";

    /// The decision a side-row signer test row expects (#10012).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SideExpect {
        NoSession,
        SessionKey,
        NotCoveredPermissive,
        Refused,
    }

    /// #10012: the full truth table of the side-row signer decision over
    /// (signer installed?, side row's agent, strict mode). The expected column
    /// is written by hand; the refusal is the exact text.
    #[test]
    fn side_row_decision_truth_table_10012() {
        const ROWS: [(bool, &str, bool, SideExpect); 8] = [
            (
                false,
                SIDE_SESSION_AGENT_10012,
                false,
                SideExpect::NoSession,
            ),
            (false, SIDE_SESSION_AGENT_10012, true, SideExpect::NoSession),
            (false, SIDE_OTHER_AGENT_10012, false, SideExpect::NoSession),
            (false, SIDE_OTHER_AGENT_10012, true, SideExpect::NoSession),
            (
                true,
                SIDE_SESSION_AGENT_10012,
                false,
                SideExpect::SessionKey,
            ),
            (true, SIDE_SESSION_AGENT_10012, true, SideExpect::SessionKey),
            (
                true,
                SIDE_OTHER_AGENT_10012,
                false,
                SideExpect::NotCoveredPermissive,
            ),
            (true, SIDE_OTHER_AGENT_10012, true, SideExpect::Refused),
        ];
        let kp = crate::identity::keypair::generate(SIDE_SESSION_AGENT_10012).expect("keypair");
        let signer = SessionSigner {
            agent_id: SIDE_SESSION_AGENT_10012.to_string(),
            keypair: kp.clone(),
        };
        let session_public = encode_public_base64(&kp.public);
        for (installed, agent, strict, expected) in ROWS {
            let what = format!("installed={installed} agent={agent} strict={strict}");
            let got = side_row_decision(installed.then_some(&signer), agent, strict);
            let observed = match got {
                Ok(SideRowSigner::NoSession) => SideExpect::NoSession,
                Ok(SideRowSigner::Session(used)) => {
                    assert_eq!(
                        encode_public_base64(&used.public),
                        session_public,
                        "{what}: signs with the session key"
                    );
                    SideExpect::SessionKey
                }
                Ok(SideRowSigner::NotCoveredPermissive) => SideExpect::NotCoveredPermissive,
                Err(text) => {
                    assert_eq!(text, SIDE_ROW_STRICT_REFUSAL, "{what}: exact refusal");
                    SideExpect::Refused
                }
            };
            assert_eq!(observed, expected, "{what}");
        }
    }

    const OPEN_ARM_AGENT_10012: &str = "agent-open-arm-10012";

    /// #10012: a connection opened AFTER the signer is installed (the
    /// governance and backfill connections of the stdio server, any later
    /// `db::open`) is armed by `storage::connection::open` itself, so a
    /// session-agent row written through it is stored sealed. Runs alone in a
    /// child process because the signer is process-wide.
    #[test]
    fn every_later_db_open_seals_session_rows_10012() {
        use base64::Engine as _;
        if crate::test_support::run_env_isolated_child_or_spawn_home(
            "identity::session_signer::tests::every_later_db_open_seals_session_rows_10012",
        ) {
            return;
        }
        // Security LOW-1: the child never sees the operator's home.
        let home = std::path::PathBuf::from(std::env::var_os("HOME").expect("child HOME"));
        let config =
            std::path::PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").expect("child XDG"));
        assert!(
            home.starts_with(std::env::temp_dir()) && config == home.join(".config"),
            "child HOME {home:?} / XDG_CONFIG_HOME {config:?} are not the isolated per-run dir"
        );
        crate::identity::attest::permissive_attestation_for_lib_tests();
        let kp = crate::identity::keypair::generate(OPEN_ARM_AGENT_10012).expect("keypair");
        // Registered and bound before the signer exists, as the stdio boot
        // requires (REFUSE_UNBOUND); the write goes through a LATER open.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("open-arm-10012.db");
        {
            let boot = crate::db::open(&path).expect("boot open");
            crate::db::register_agent(&boot, OPEN_ARM_AGENT_10012, "nhi", &[]).expect("register");
            crate::db::bind_agent_pubkey_with_keypair(&boot, OPEN_ARM_AGENT_10012, &kp)
                .expect("bind");
        }
        assert_eq!(
            install_for_lib_test(OPEN_ARM_AGENT_10012, kp.clone()),
            OPEN_ARM_AGENT_10012
        );
        let conn = crate::db::open(&path).expect("open after install");
        let now = crate::identity::attest::now_attestable_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: "open-arm-10012".to_string(),
            title: "open arm 10012".to_string(),
            content: "written through a later connection".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({ crate::META_KEY_AGENT_ID: OPEN_ARM_AGENT_10012 }),
            ..Memory::default()
        };
        let id = crate::db::insert(&conn, &mem).expect("insert");
        let row = crate::db::get(&conn, &id).expect("read").expect("row");
        assert_eq!(
            row.metadata[crate::models::field_names::ATTEST_LEVEL].as_str(),
            Some("agent_attested"),
            "attest_level of a row written through a later db::open"
        );
        let stored = row.metadata[crate::models::field_names::WRITE_SIGNATURE]
            .as_str()
            .expect("write_signature");
        let stored = base64::engine::general_purpose::STANDARD
            .decode(stored)
            .expect("base64 signature");
        let expected = crate::identity::attest::sign_memory_write(&kp, &row, OPEN_ARM_AGENT_10012)
            .expect("re-sign stored row");
        assert_eq!(stored, expected, "signature over the stored row");
    }

    const SEAL_ROT_AGENT_10111: &str = "ai:seal-rot-10111";
    const SEAL_OTHER_AGENT_10111: &str = "ai:seal-other-10111";
    const SEAL_UNKNOWN_AGENT_10111: &str = "ai:seal-unknown-10111";

    fn sealed_memory_10111(
        owner: &str,
        signer: &AgentKeypair,
        created_at: &str,
        updated_at: &str,
    ) -> Memory {
        let mut mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: "seal-rot-10111".to_string(),
            title: "seal rotation 10111".to_string(),
            content: "body for write-seal verification under retired key".to_string(),
            created_at: created_at.to_string(),
            updated_at: updated_at.to_string(),
            metadata: serde_json::json!({
                crate::META_KEY_AGENT_ID: owner,
                crate::models::field_names::ATTEST_LEVEL:
                    crate::identity::verify::AttestLevel::AgentAttested.as_str(),
            }),
            ..Memory::default()
        };
        let sig = crate::identity::attest::sign_memory_write(signer, &mem, owner)
            .expect("sign test memory");
        crate::identity::attest::persist_write_signature(&mut mem, &sig);
        mem
    }

    /// #10111: `verify_row_seal_with` verifies seals made under a retired key
    /// within its anchored validity window after rotation, accepts lawful
    /// post-rotation re-seals under the new key (where `created_at` stays old
    /// and `updated_at` is in the new key's window), and reports the exact
    /// named [`SealDefect`] for out-of-range retired/pre-activation keys,
    /// missing/unanchored keys, cross-agent keys, bad timestamps, malformed
    /// signatures, and unanchored trust anchors — never falling back to the
    /// current key or any database key.
    #[test]
    fn stored_seal_verifies_retired_key_and_rejects_out_of_range_and_unanchored_10111() {
        use crate::storage::row_attest::anchor::{AnchorLoad, TrustAnchor, Unanchored};
        use crate::storage::row_attest::key_id_of;

        const T_ROT: i64 = 1_750_000_000;
        let ts_before = crate::identity::attest::canonical_created_at_stamp(
            chrono::DateTime::from_timestamp(T_ROT - 60, 0).expect("ts_before"),
        );
        let ts_exact = crate::identity::attest::canonical_created_at_stamp(
            chrono::DateTime::from_timestamp(T_ROT, 0).expect("ts_exact"),
        );
        let ts_after = crate::identity::attest::canonical_created_at_stamp(
            chrono::DateTime::from_timestamp(T_ROT + 60, 0).expect("ts_after"),
        );
        let ts_before = ts_before.as_str();
        let ts_exact = ts_exact.as_str();
        let ts_after = ts_after.as_str();

        let k_old = crate::identity::keypair::generate(SEAL_ROT_AGENT_10111).expect("k_old");
        let k_new = crate::identity::keypair::generate(SEAL_ROT_AGENT_10111).expect("k_new");
        let k_other = crate::identity::keypair::generate(SEAL_OTHER_AGENT_10111).expect("k_other");
        let k_unanchored =
            crate::identity::keypair::generate(SEAL_ROT_AGENT_10111).expect("k_unanchored");

        let id_old = key_id_of(&k_old.public);
        let id_new = key_id_of(&k_new.public);
        let id_other = key_id_of(&k_other.public);

        let anchor = AnchorLoad::Anchored(TrustAnchor::for_test(
            "test-anchor-10111",
            &[
                (SEAL_ROT_AGENT_10111, k_old.public, None, Some(T_ROT)),
                (SEAL_ROT_AGENT_10111, k_new.public, Some(T_ROT), None),
                (SEAL_OTHER_AGENT_10111, k_other.public, None, None),
            ],
        ));

        // 1. Pre-rotation seal under retired K_old verifies after rotation.
        let pre = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_old, ts_before, ts_before);
        assert_eq!(
            verify_row_seal_with(&pre, &anchor),
            StoredSealCheck::Verified {
                key_id: id_old.clone(),
            },
            "retired K_old inside [None, T_ROT] must verify"
        );

        // 2. Exact retirement boundary timestamp is inclusive (matches anchor::key_for).
        let boundary = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_old, ts_exact, ts_exact);
        assert_eq!(
            verify_row_seal_with(&boundary, &anchor),
            StoredSealCheck::Verified {
                key_id: id_old.clone(),
            },
            "retired K_old at exact retirement second must verify"
        );

        // 3. Retired K_old dated AFTER retirement is named OutOfRange defect.
        let post_retired = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_old, ts_after, ts_after);
        let expected_oor = SealDefect::OutOfRange {
            key_id: id_old.clone(),
            valid_from: None,
            valid_to: Some(T_ROT),
        };
        assert_eq!(
            verify_row_seal_with(&post_retired, &anchor),
            StoredSealCheck::Defect(expected_oor.clone()),
            "K_old seal dated after retirement must be exact OutOfRange defect"
        );
        assert_eq!(
            expected_oor.to_string(),
            format!(
                "write seal key_id {id_old} used outside its anchored validity (from None to Some({T_ROT}))"
            )
        );

        // 4. Tampering updated_at backward never lets a post-retirement K_old seal pass.
        let backdated_upd = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_old, ts_after, ts_before);
        assert_eq!(
            verify_row_seal_with(&backdated_upd, &anchor),
            StoredSealCheck::Defect(expected_oor),
            "tampered updated_at < created_at must never bypass retirement bound"
        );

        // 5. Post-rotation non-signed-column update (updated_at > T_ROT, seal still K_old).
        let non_signed_upd = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_old, ts_before, ts_after);
        assert_eq!(
            verify_row_seal_with(&non_signed_upd, &anchor),
            StoredSealCheck::Verified {
                key_id: id_old.clone(),
            },
            "non-signed update after rotation preserves K_old seal validity"
        );

        // 6. Post-rotation new row under K_new verifies.
        let fresh_new = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_new, ts_after, ts_after);
        assert_eq!(
            verify_row_seal_with(&fresh_new, &anchor),
            StoredSealCheck::Verified {
                key_id: id_new.clone(),
            },
            "current K_new inside [T_ROT, None] must verify"
        );

        // 7. Lawful post-rotation re-seal of a pre-rotation row (created_at < T_ROT <= updated_at).
        let resealed_new = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_new, ts_before, ts_after);
        assert_eq!(
            verify_row_seal_with(&resealed_new, &anchor),
            StoredSealCheck::Verified {
                key_id: id_new.clone(),
            },
            "post-rotation K_new re-seal preserving created_at must verify"
        );

        // 8. Pre-activation un-updated row signed by K_new before valid_from is OutOfRange.
        let early_new = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_new, ts_before, ts_before);
        assert_eq!(
            verify_row_seal_with(&early_new, &anchor),
            StoredSealCheck::Defect(SealDefect::OutOfRange {
                key_id: id_new,
                valid_from: Some(T_ROT),
                valid_to: None,
            }),
            "K_new seal with created_at == updated_at < valid_from must be OutOfRange"
        );

        // 9. Retired key removed from anchor (only K_new present): named UnknownKey, no fallback.
        let current_only = AnchorLoad::Anchored(TrustAnchor::for_test(
            "current-only-10111",
            &[(SEAL_ROT_AGENT_10111, k_new.public, Some(T_ROT), None)],
        ));
        assert_eq!(
            verify_row_seal_with(&pre, &current_only),
            StoredSealCheck::Defect(SealDefect::UnknownKey {
                agent_id: SEAL_ROT_AGENT_10111.to_string(),
            }),
            "missing retired key in anchor must be UnknownKey, never fallback to K_new"
        );

        // 10. Key not in anchor at all -> UnknownKey.
        let rogue = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_unanchored, ts_before, ts_before);
        assert_eq!(
            verify_row_seal_with(&rogue, &anchor),
            StoredSealCheck::Defect(SealDefect::UnknownKey {
                agent_id: SEAL_ROT_AGENT_10111.to_string(),
            }),
            "unanchored signing key must be UnknownKey"
        );

        // 11. Owner with no keys in anchor -> UnknownAgent.
        let unknown_owner = sealed_memory_10111(
            SEAL_UNKNOWN_AGENT_10111,
            &k_unanchored,
            ts_before,
            ts_before,
        );
        assert_eq!(
            verify_row_seal_with(&unknown_owner, &anchor),
            StoredSealCheck::Defect(SealDefect::UnknownAgent {
                agent_id: SEAL_UNKNOWN_AGENT_10111.to_string(),
            }),
            "agent with no keys in anchor must be UnknownAgent"
        );

        // 12. Row claiming SEAL_ROT_AGENT_10111 but signed by SEAL_OTHER_AGENT_10111 -> OtherAgent.
        let cross_agent = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_other, ts_before, ts_before);
        assert_eq!(
            verify_row_seal_with(&cross_agent, &anchor),
            StoredSealCheck::Defect(SealDefect::OtherAgent {
                key_id: id_other,
                agent_id: SEAL_ROT_AGENT_10111.to_string(),
                anchored_agent: SEAL_OTHER_AGENT_10111.to_string(),
            }),
            "signature from another anchored agent's key must be OtherAgent"
        );

        // 13. Malformed write timestamp -> BadTime.
        // Build `bad_created` directly with `sign_write` because `sign_memory_write`
        // refuses non-canonical timestamps at signing time (#3422).
        let mut bad_created = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: "seal-rot-10111".to_string(),
            title: "seal rotation 10111".to_string(),
            content: "body for write-seal verification under retired key".to_string(),
            created_at: "not-a-ts".to_string(),
            updated_at: ts_before.to_string(),
            metadata: serde_json::json!({
                crate::META_KEY_AGENT_ID: SEAL_ROT_AGENT_10111,
                crate::models::field_names::ATTEST_LEVEL:
                    crate::identity::verify::AttestLevel::AgentAttested.as_str(),
            }),
            ..Memory::default()
        };
        let bad_hash = crate::identity::attest::content_sha256(&bad_created.content);
        let bad_write = crate::identity::sign::SignableWrite {
            agent_id: SEAL_ROT_AGENT_10111,
            namespace: &bad_created.namespace,
            title: &bad_created.title,
            kind: bad_created.memory_kind.as_str(),
            created_at: &bad_created.created_at,
            content_sha256: &bad_hash,
        };
        let bad_sig =
            crate::identity::sign::sign_write(&k_old, &bad_write).expect("raw sign_write");
        crate::identity::attest::persist_write_signature(&mut bad_created, &bad_sig);
        assert_eq!(
            verify_row_seal_with(&bad_created, &anchor),
            StoredSealCheck::Defect(SealDefect::BadTime {
                key_id: id_old.clone(),
                timestamp: "not-a-ts".to_string(),
            }),
            "malformed created_at must be BadTime"
        );
        let bad_updated = sealed_memory_10111(SEAL_ROT_AGENT_10111, &k_old, ts_before, "bad-upd");
        assert_eq!(
            verify_row_seal_with(&bad_updated, &anchor),
            StoredSealCheck::Defect(SealDefect::BadTime {
                key_id: id_old,
                timestamp: "bad-upd".to_string(),
            }),
            "malformed updated_at must be BadTime"
        );

        // 14. Unanchored trust anchor -> Unanchored defect (never falls back to DB).
        let unanchored_why = Unanchored::Missing {
            path: std::path::PathBuf::from("/nonexistent-anchor-10111"),
        };
        assert_eq!(
            verify_row_seal_with(&pre, &AnchorLoad::Unanchored(unanchored_why.clone())),
            StoredSealCheck::Defect(SealDefect::Unanchored(unanchored_why)),
            "unanchored load must be Unanchored defect"
        );

        // 15. Malformed / truncated / missing write_signature under agent_attested -> MalformedSignature.
        let mut bad_sig = pre.clone();
        bad_sig.metadata["write_signature"] = serde_json::json!("not-64-bytes");
        assert_eq!(
            verify_row_seal_with(&bad_sig, &anchor),
            StoredSealCheck::Defect(SealDefect::MalformedSignature)
        );
        let mut missing_sig = pre.clone();
        missing_sig
            .metadata
            .as_object_mut()
            .expect("obj")
            .remove("write_signature");
        assert_eq!(
            verify_row_seal_with(&missing_sig, &anchor),
            StoredSealCheck::Defect(SealDefect::MalformedSignature)
        );

        // 16. Claimed / ownerless rows -> Unsealed, and all SealDefect Display arms are pinned.
        let mut claimed = pre.clone();
        claimed.metadata["attest_level"] = serde_json::json!("claimed");
        assert_eq!(
            verify_row_seal_with(&claimed, &anchor),
            StoredSealCheck::Unsealed
        );
        let mut ownerless = pre;
        ownerless
            .metadata
            .as_object_mut()
            .expect("obj")
            .remove(crate::META_KEY_AGENT_ID);
        assert_eq!(
            verify_row_seal_with(&ownerless, &anchor),
            StoredSealCheck::Unsealed
        );
        assert!(
            SealDefect::Unanchored(Unanchored::Missing {
                path: std::path::PathBuf::from("/missing-10111"),
            })
            .to_string()
            .starts_with("write seal unanchored:")
        );
        assert_eq!(
            SealDefect::MalformedSignature.to_string(),
            "write seal signature is missing or malformed"
        );
        assert_eq!(
            SealDefect::UnknownAgent {
                agent_id: SEAL_UNKNOWN_AGENT_10111.to_string(),
            }
            .to_string(),
            format!(
                "write seal names agent {SEAL_UNKNOWN_AGENT_10111} with no key in the trust anchor"
            )
        );
        assert_eq!(
            SealDefect::UnknownKey {
                agent_id: SEAL_ROT_AGENT_10111.to_string(),
            }
            .to_string(),
            format!(
                "write seal for agent {SEAL_ROT_AGENT_10111} does not match any key in the trust anchor"
            )
        );
        assert_eq!(
            SealDefect::OtherAgent {
                key_id: "kid".to_string(),
                agent_id: SEAL_ROT_AGENT_10111.to_string(),
                anchored_agent: SEAL_OTHER_AGENT_10111.to_string(),
            }
            .to_string(),
            format!(
                "write seal key_id kid is anchored to agent {SEAL_OTHER_AGENT_10111}, not {SEAL_ROT_AGENT_10111}"
            )
        );
        assert_eq!(
            SealDefect::BadTime {
                key_id: "kid".to_string(),
                timestamp: "not-a-ts".to_string(),
            }
            .to_string(),
            "write seal key_id kid has invalid write timestamp \"not-a-ts\""
        );
    }
}
