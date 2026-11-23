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
    // #10012 — the boot connection opened before the signer existed, so it
    // gets the write-seal funnel here; every later `db::open` installs it.
    match install_write_seal_funnel(conn)? {
        FunnelState::Installed => Ok(()),
        FunnelState::NoSigner => Err(crate::errors::refusal(REFUSE_FUNNEL_NOT_INSTALLED)),
    }
}

/// The write-seal funnel could not be installed on the boot connection right
/// after the signer was (#10012); boot refuses rather than run unsealed.
pub const REFUSE_FUNNEL_NOT_INSTALLED: &str =
    "mcp session signer (#10012): the write-seal funnel did not install; refusing to start";

/// Refusal for a strict-mode write to a memory row the session cannot seal
/// because the row is not owned by the session agent (#10012). A session
/// never signs for another agent, so under strict mode the write is refused.
pub const FOREIGN_ROW_STRICT_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a write to a memory row the session agent does not own cannot be sealed; refused";

/// The closed-vocabulary refusal behind the text SQLite carries back from a
/// funnel trigger (#10012).
///
/// The seal function fails the statement with its refusal reason, which
/// reaches the caller as a driver error. This maps that text back to OUR
/// constant so the caller sees the exact refusal instead of the storage
/// class: a strict-mode refusal returns itself, and any other per-write
/// seal failure returns [`SEAL_REFUSAL_PREFIX`] alone (its tail may carry
/// driver text, which never reaches a caller). Every other text is `None`.
#[must_use]
pub fn funnel_refusal(text: &str) -> Option<&'static str> {
    [FOREIGN_ROW_STRICT_REFUSAL, SIDE_ROW_STRICT_REFUSAL]
        .into_iter()
        .find(|refusal| text == *refusal)
        .or_else(|| {
            text.starts_with(SEAL_REFUSAL_PREFIX)
                .then_some(SEAL_REFUSAL_PREFIX)
        })
}

/// The SQL function the TEMP seal triggers call (#10012).
const SEAL_FN: &str = "ai_memory_session_seal_10012";

/// TEMP triggers of the write-seal funnel (#10012). TEMP: they live only in
/// this connection, so nothing is added to the stored schema, and they exist
/// only on connections of a process that installed a session signer.
///
/// - AFTER INSERT seals every new memory row.
/// - AFTER UPDATE seals every change to a signed-envelope column (namespace,
///   title, content, kind, `created_at`) or to `metadata` (owner and seal).
///
/// The function aborts the triggering statement on a refusal, so a refused
/// write is rolled back with it: nothing is stored or changed.
const SEAL_TRIGGERS_SQL: &str = "\
CREATE TEMP TRIGGER IF NOT EXISTS ai_memory_session_seal_insert_10012 \
AFTER INSERT ON main.memories BEGIN \
SELECT ai_memory_session_seal_10012(NEW.id, 1); END;\
CREATE TEMP TRIGGER IF NOT EXISTS ai_memory_session_seal_update_10012 \
AFTER UPDATE OF namespace, title, content, memory_kind, created_at, metadata \
ON main.memories BEGIN \
SELECT ai_memory_session_seal_10012(NEW.id, 0); END;";

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
/// passes [`seal_stored_row`] inside the same statement: rows of the session
/// agent are signed, verified against the bound key, admitted to the replay
/// ledger and persisted `agent_attested`; a failure aborts the statement.
///
/// # Errors
///
/// Registering the SQL function or creating the TEMP triggers failed.
pub fn install_write_seal_funnel(conn: &rusqlite::Connection) -> Result<FunnelState> {
    use rusqlite::functions::FunctionFlags;
    if session_signer().is_none() {
        return Ok(FunnelState::NoSigner);
    }
    conn.create_scalar_function(SEAL_FN, 2, FunctionFlags::SQLITE_UTF8, |ctx| {
        let id: String = ctx.get(0)?;
        let inserted: i64 = ctx.get(1)?;
        // SAFETY: the connection reference is used only for the duration of
        // this call, on the thread that runs the statement, and is never
        // closed or stored (rusqlite `Context::get_connection` contract).
        let conn = unsafe { ctx.get_connection() }?;
        let phase = if inserted == 1 {
            RowWrite::Inserted
        } else {
            RowWrite::Updated
        };
        match seal_stored_row(&conn, &id, phase) {
            Ok(StoredSeal::AlreadySealed | StoredSeal::NotOwnedPermissive) => Ok(0_i64),
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
    /// The stored seal already verifies against the owner's bound key.
    AlreadySealed,
    /// The session signer sealed the row.
    Sealed(Resealed),
    /// The row is not the session agent's and strict mode is off: left as
    /// written (a session never signs for another agent; #9926 contract).
    NotOwnedPermissive,
}

/// The #10012 funnel body: make the stored row `id` sealed by the session
/// signer, or refuse.
fn seal_stored_row(
    conn: &rusqlite::Connection,
    id: &str,
    phase: RowWrite,
) -> std::result::Result<StoredSeal, String> {
    use crate::identity::attest;
    let Some(signer) = session_signer() else {
        return Ok(StoredSeal::NotOwnedPermissive);
    };
    let row = crate::db::get_any(conn, id)
        .map_err(|e| format!("{SEAL_REFUSAL_PREFIX}: written row read failed: {e}"))?
        .ok_or_else(|| format!("{SEAL_REFUSAL_PREFIX}: the written row is gone"))?;
    let owner = row
        .metadata
        .get(crate::mcp::param_names::AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    if stored_seal_verifies(conn, &row, owner.as_deref())? {
        return Ok(StoredSeal::AlreadySealed);
    }
    match owner.as_deref() {
        Some(agent) if signer.covers(agent) => {}
        _ => {
            return if attest::require_agent_attestation_for(attest::WriteSurface::Mcp) {
                Err(FOREIGN_ROW_STRICT_REFUSAL.to_string())
            } else {
                Ok(StoredSeal::NotOwnedPermissive)
            };
        }
    }
    // A row minted now with a sub-microsecond `created_at` is restamped, the
    // same as `seal_with` does before an insert; a changed row keeps its
    // `created_at` (its identity) and `reseal_with` refuses an unstable one.
    if phase == RowWrite::Inserted && !attest::created_at_is_storage_stable(&row.created_at) {
        conn.execute(
            "UPDATE memories SET created_at = ?1 WHERE id = ?2",
            rusqlite::params![attest::now_attestable_rfc3339(), id],
        )
        .map_err(|e| format!("{SEAL_REFUSAL_PREFIX}: restamping created_at failed: {e}"))?;
        // The restamp is itself a covered write: its own trigger has sealed
        // the row already, so only re-check it.
        let restamped = crate::db::get_any(conn, id)
            .map_err(|e| format!("{SEAL_REFUSAL_PREFIX}: written row read failed: {e}"))?
            .ok_or_else(|| format!("{SEAL_REFUSAL_PREFIX}: the written row is gone"))?;
        if stored_seal_verifies(conn, &restamped, owner.as_deref())? {
            return Ok(StoredSeal::Sealed(Resealed));
        }
    }
    reseal_with(conn, id, signer)
        .map(StoredSeal::Sealed)
        .map_err(seal_refusal)
}

/// Whether `row` carries `agent_attested` and a `write_signature` that
/// verifies over its stored envelope against the owner's CURRENT bound key.
fn stored_seal_verifies(
    conn: &rusqlite::Connection,
    row: &Memory,
    owner: Option<&str>,
) -> std::result::Result<bool, String> {
    use crate::identity::verify::AttestLevel;
    use base64::Engine as _;
    let Some(owner) = owner else {
        return Ok(false);
    };
    let level = row
        .metadata
        .get(crate::models::field_names::ATTEST_LEVEL)
        .and_then(serde_json::Value::as_str);
    if level != Some(AttestLevel::AgentAttested.as_str()) {
        return Ok(false);
    }
    let Some(signature) = row
        .metadata
        .get(crate::models::field_names::WRITE_SIGNATURE)
        .and_then(serde_json::Value::as_str)
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
    else {
        return Ok(false);
    };
    let bound = crate::db::agent_pubkey(conn, owner)
        .map_err(|e| format!("{SEAL_REFUSAL_PREFIX}: bound key lookup failed: {e}"))?;
    // A forged or stale signature is an Err here: it does not verify, so the
    // funnel re-seals (own row) or refuses / leaves it (foreign row).
    Ok(matches!(
        crate::identity::attest::resolve_write_attest_level(
            row,
            owner,
            bound.as_deref(),
            Some(&signature),
            true,
        ),
        Ok(AttestLevel::AgentAttested)
    ))
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

/// Proof that [`reseal_row_sync`] signed the stored row, verified it as
/// `agent_attested` against the bound key and persisted the seal (CBC-05).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resealed;

/// Re-seal row `id` after a merge rewrote its content (#10011).
///
/// `db::update` never mints an attestation (#3420), so the merge detour of a
/// signed `memory_store` lands the merged row `claimed`. This signs the row
/// AS STORED (its id, namespace, title, kind and `created_at`, plus the
/// merged content) with the session signer of `agent_id`, verifies the
/// signature against the agent's CURRENT bound key, records it in the replay
/// ledger and persists `attest_level` + `write_signature` through
/// [`crate::storage::row_attestation::set_row_attestation`].
///
/// The caller runs this inside the write transaction that wrote the content,
/// so an `Err` rolls the merge back: a merged row is never committed as
/// claimed when its write was signed.
///
/// A ledger `Replay` is admitted here. decision: admit over refuse because
/// the signature is minted by the session key over this row's own envelope
/// (no presented envelope is being replayed), and Ed25519 is deterministic,
/// so a merge back to an earlier body re-derives an already-spent
/// fingerprint; refusing it would lose a legitimate write.
///
/// # Errors
///
/// [`MERGE_RESEAL_REFUSAL`] when no session signer covers `agent_id`; a
/// reason starting with [`SEAL_REFUSAL_PREFIX`] for every other failure
/// (row missing, owner mismatch, unstable `created_at`, stored bytes that
/// redaction would change, signing, a key rebound after boot, ledger
/// unavailable, persistence).
pub fn reseal_row_sync(
    conn: &rusqlite::Connection,
    id: &str,
    agent_id: &str,
) -> std::result::Result<Resealed, String> {
    let Some(signer) = session_signer().filter(|signer| signer.covers(agent_id)) else {
        return Err(MERGE_RESEAL_REFUSAL.to_string());
    };
    reseal_with(conn, id, signer).map_err(seal_refusal)
}

fn reseal_with(
    conn: &rusqlite::Connection,
    id: &str,
    signer: &SessionSigner,
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
        if crate::config::run_env_isolated_child_or_spawn(
            "identity::session_signer::tests::every_later_db_open_seals_session_rows_10012",
        ) {
            return;
        }
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
}
