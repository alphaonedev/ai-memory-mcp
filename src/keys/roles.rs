// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The key-role table (#3717): every role, its files, its typed state, and
//! the ONE plan that decides what `keys init` does about it.
//!
//! Roles, in plan order (the recovery anchor first because the at-rest
//! escrow is wrapped under it):
//!
//! | Role               | Files                                             | Mint                        |
//! |--------------------|---------------------------------------------------|-----------------------------|
//! | `recovery-anchor`  | `recovery.x25519.pub`                             | `--recovery-key-out <file>` |
//! | `identity`         | `<agent>.priv` / `.pub`                           | `ensure_keypair`            |
//! | `daemon-signer`    | `daemon.priv` / `.pub`                            | `ensure_keypair`            |
//! | `at-rest-wrap`     | `<agent>.x25519.priv` / `.escrow` / `.pub`        | mint + escrow, atomically   |
//! | `tls`              | `tls/local-ca.{key,pem}` + `tls/server.{key,pem}` | `ensure_local_tls`          |
//! | `capability-owner` | `owner.priv` / `owner.caproot` / `owner.pub`      | `init_owner`                |
//!
//! [`observe`] reads NO key material (existence, kind and mode; the TLS
//! leaf's expiry from the public certificate). [`plan`] is pure. Only
//! [`execute`] writes, and only what the plan says.

use crate::config::AppConfig;
use crate::config::shape::{AtRestPolicy, DeploymentShape};
use crate::encryption::escrow;
use anyhow::{Context as _, Result, bail};
use std::path::{Path, PathBuf};

/// Who may hold a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Custody {
    /// Secret material: mode `0o600`, back up, never distribute.
    Private,
    /// Public material: mode `0o644`, safe to distribute.
    Public,
    /// The at-rest key wrapped under the recovery key: mode `0o600`, back
    /// up together with the private material (it is useless without the
    /// off-node recovery key and harmless to lose while the `.priv` lives).
    Escrow,
}

impl Custody {
    /// Whether this custody class belongs on the BACK UP list.
    #[must_use]
    pub fn is_backed_up(self) -> bool {
        matches!(self, Self::Private | Self::Escrow)
    }

    /// The mode a file of this custody must carry.
    #[must_use]
    pub fn expected_mode(self) -> u32 {
        match self {
            Self::Private | Self::Escrow => 0o600,
            Self::Public => 0o644,
        }
    }
}

/// One file of a role, as observed (never read).
#[derive(Clone, Debug, serde::Serialize)]
pub struct KeyFile {
    pub path: PathBuf,
    pub custody: Custody,
    pub present: bool,
    /// `mode & 0o777` on unix when present.
    pub mode: Option<u32>,
    /// Present AND a regular file (not a symlink, not a directory).
    pub regular: bool,
    /// Present AND the size a raw key of this kind must have, when the
    /// kind has a fixed size (`None` = no size rule for this file).
    pub size_ok: Option<bool>,
}

impl KeyFile {
    fn observe(path: PathBuf, custody: Custody, expected_len: Option<u64>) -> Self {
        let meta = std::fs::symlink_metadata(&path).ok();
        let present = meta.is_some();
        let regular = meta.as_ref().is_some_and(std::fs::Metadata::is_file);
        #[cfg(unix)]
        let mode = meta.as_ref().map(|m| {
            use std::os::unix::fs::PermissionsExt as _;
            m.permissions().mode() & 0o777
        });
        #[cfg(not(unix))]
        let mode = None;
        let size_ok = match (expected_len, meta.as_ref()) {
            (Some(n), Some(m)) => Some(m.len() == n),
            _ => None,
        };
        Self {
            path,
            custody,
            present,
            mode,
            regular,
            size_ok,
        }
    }

    /// A present PRIVATE / ESCROW file readable by group or others, or a
    /// present file of any custody writable by them.
    #[must_use]
    pub fn mode_is_loose(&self) -> bool {
        let Some(mode) = self.mode else {
            return false;
        };
        match self.custody {
            Custody::Private | Custody::Escrow => mode & 0o077 != 0,
            Custody::Public => mode & 0o022 != 0,
        }
    }

    /// Present but not usable as a key file: not a regular file, a wrong
    /// size, or (private) a loose mode.
    #[must_use]
    pub fn unreadable(&self) -> bool {
        self.present && (!self.regular || self.size_ok == Some(false) || self.mode_is_loose())
    }

    /// `chmod` line for a loose file.
    #[must_use]
    pub fn chmod_fix(&self) -> String {
        format!(
            "chmod {:04o} {}",
            self.custody.expected_mode(),
            self.path.display()
        )
    }
}

/// Whether a role is needed under the observed configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Need {
    /// Every installation needs it.
    Always,
    /// Needed under this configuration / shape.
    Required,
    /// Not needed under this configuration.
    NotRequired,
}

/// The roles, in plan order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleId {
    RecoveryAnchor,
    Identity,
    DaemonSigner,
    AtRestWrap,
    Tls,
    CapabilityOwner,
}

impl RoleId {
    /// Every role, in plan order.
    pub const ALL: [Self; 6] = [
        Self::RecoveryAnchor,
        Self::Identity,
        Self::DaemonSigner,
        Self::AtRestWrap,
        Self::Tls,
        Self::CapabilityOwner,
    ];

    /// Stable kebab-case label (output, JSON, doctor facts).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::RecoveryAnchor => "recovery-anchor",
            Self::Identity => "identity",
            Self::DaemonSigner => "daemon-signer",
            Self::AtRestWrap => "at-rest-wrap",
            Self::Tls => "tls",
            Self::CapabilityOwner => "capability-owner",
        }
    }
}

/// Why a role is only partly on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Partial {
    /// The private half survives; everything missing derives from it.
    /// Repaired in place, never re-minted.
    Recoverable,
    /// The private half is gone. Nothing here can regenerate it without
    /// minting a DIFFERENT key; refused until the operator restores it (or,
    /// for the at-rest key, recovers it from its escrow).
    LostPrivate,
    /// A file is present but unusable (wrong size, not a regular file, a
    /// loose mode). Refused with the fix named.
    Unreadable,
}

/// The typed state of a role on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "partial")]
pub enum RoleState {
    /// No file of the role exists.
    Absent,
    /// Every file of the role exists and is usable.
    Complete,
    /// Some files exist.
    Partial(Partial),
    /// Material this installation must never touch (a fleet shape's TLS).
    OperatorSupplied,
}

/// One role as observed.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Role {
    pub id: RoleId,
    pub purpose: &'static str,
    pub need: Need,
    /// Why the role has this `need` under this configuration.
    pub why: String,
    pub files: Vec<KeyFile>,
    pub state: RoleState,
    /// What is missing / wrong, and the remedy, in plain language.
    pub detail: String,
    /// The TLS leaf's days to expiry (negative = expired).
    pub expires_in_days: Option<i64>,
    /// The command that mints this role, when this installation can.
    pub mint_command: Option<String>,
}

/// The observed posture of a key directory for one agent.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Posture {
    pub key_dir: PathBuf,
    /// `mode & 0o777` of the key directory on unix.
    pub key_dir_mode: Option<u32>,
    pub agent_id: String,
    pub shape: String,
    /// A deployment recovery key is enrolled (escrows can be written).
    pub recovery_enrolled: bool,
    pub roles: Vec<Role>,
}

impl Posture {
    /// Every present file on the BACK UP list (private + escrow), by path.
    #[must_use]
    pub fn back_up(&self) -> Vec<&Path> {
        self.files_where(|f| f.custody.is_backed_up())
    }

    /// Every present PUBLIC file, by path.
    #[must_use]
    pub fn distribute(&self) -> Vec<&Path> {
        self.files_where(|f| f.custody == Custody::Public)
    }

    fn files_where(&self, pred: impl Fn(&KeyFile) -> bool) -> Vec<&Path> {
        self.roles
            .iter()
            .flat_map(|r| r.files.iter())
            .filter(|f| f.present && pred(f))
            .map(|f| f.path.as_path())
            .collect()
    }

    /// The role by id (every role is always listed).
    #[must_use]
    pub fn role(&self, id: RoleId) -> &Role {
        self.roles
            .iter()
            .find(|r| r.id == id)
            .expect("every RoleId is observed")
    }

    /// Required roles that are not complete.
    #[must_use]
    pub fn missing_required(&self) -> Vec<&Role> {
        self.roles
            .iter()
            .filter(|r| {
                r.need != Need::NotRequired
                    && !matches!(r.state, RoleState::Complete | RoleState::OperatorSupplied)
            })
            .collect()
    }

    /// Every present file whose mode is loose.
    #[must_use]
    pub fn loose_files(&self) -> Vec<&KeyFile> {
        self.roles
            .iter()
            .flat_map(|r| r.files.iter())
            .filter(|f| f.mode_is_loose())
            .collect()
    }

    /// `true` when the key directory itself admits group or others.
    #[must_use]
    pub fn key_dir_is_loose(&self) -> bool {
        self.key_dir_mode.is_some_and(|m| m & 0o077 != 0)
    }
}

const RAW_KEY_LEN: u64 = 32;

/// The at-rest need under `shape` + config + env — the same predicate the
/// seal path uses (`encryption_enabled`) plus the shape's floor.
fn at_rest_needed(config: &AppConfig, shape: DeploymentShape) -> (Need, String) {
    let policy = shape.derive().at_rest.value();
    if policy != AtRestPolicy::Off {
        return (
            Need::Required,
            format!(
                "{} derives at-rest policy `{}`",
                shape.config_line(),
                policy.as_str()
            ),
        );
    }
    let flag = config.encryption.as_ref().and_then(|e| e.at_rest);
    if crate::encryption::encryption_enabled(flag) {
        return (
            Need::Required,
            format!(
                "at-rest encryption is enabled ([encryption].at_rest or {})",
                crate::encryption::ENV_ENCRYPT_AT_REST
            ),
        );
    }
    (
        Need::NotRequired,
        format!(
            "{} derives at-rest policy `off` and at-rest encryption is not enabled",
            shape.config_line()
        ),
    )
}

fn capabilities_needed(config: &AppConfig) -> (Need, String) {
    let enabled = crate::governance::capability::capabilities_env_override().unwrap_or_else(|| {
        config
            .capabilities
            .as_ref()
            .and_then(|c| c.enabled)
            .unwrap_or(crate::governance::capability::DEFAULT_CAPABILITIES_ENABLED)
    });
    if enabled {
        (
            Need::Required,
            format!(
                "capability tokens are enabled ([capabilities].enabled / {})",
                crate::governance::capability::ENV_CAPABILITIES
            ),
        )
    } else {
        (
            Need::NotRequired,
            "capability tokens are disabled".to_string(),
        )
    }
}

/// State of a private/public pair (`priv`, then the derivable files).
/// `derivable` are the files a surviving private half regenerates.
fn pair_state(private: &KeyFile, derivable: &[&KeyFile]) -> (RoleState, String) {
    let all = std::iter::once(private).chain(derivable.iter().copied());
    if let Some(bad) = all.clone().find(|f| f.unreadable()) {
        return (
            RoleState::Partial(Partial::Unreadable),
            unreadable_detail(bad),
        );
    }
    let derivable_missing: Vec<&KeyFile> =
        derivable.iter().copied().filter(|f| !f.present).collect();
    let any_present = all.clone().any(|f| f.present);
    if !any_present {
        return (RoleState::Absent, "absent".to_string());
    }
    if private.present {
        if derivable_missing.is_empty() {
            return (RoleState::Complete, "present".to_string());
        }
        let names: Vec<String> = derivable_missing
            .iter()
            .map(|f| f.path.display().to_string())
            .collect();
        return (
            RoleState::Partial(Partial::Recoverable),
            format!(
                "{} present, {} missing — repaired from the private half by `keys init`",
                private.path.display(),
                names.join(", ")
            ),
        );
    }
    (
        RoleState::Partial(Partial::LostPrivate),
        format!(
            "{} is MISSING while {} exists — the private half cannot be derived and is \
             deliberately NOT regenerated (that would mint a different key); restore it from \
             backup, or remove the surviving files to accept a fresh key",
            private.path.display(),
            all.filter(|f| f.present)
                .map(|f| f.path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
}

fn unreadable_detail(f: &KeyFile) -> String {
    if !f.regular {
        format!(
            "{} is not a regular file (a symlink or directory) — remove it or restore the real file",
            f.path.display()
        )
    } else if f.size_ok == Some(false) {
        format!(
            "{} has the wrong size for a raw key — restore it from backup",
            f.path.display()
        )
    } else {
        format!(
            "{} is mode {:04o}; fix: {}",
            f.path.display(),
            f.mode.unwrap_or_default(),
            f.chmod_fix()
        )
    }
}

/// Observe the posture of `dir` for `agent_id` under the declared `shape`.
/// Read-only. Reads no key material.
///
/// # Errors
/// The TLS leaf exists but cannot be parsed (a corrupt artefact is an
/// error, never "absent").
pub fn observe(
    dir: &Path,
    agent_id: &str,
    shape: DeploymentShape,
    config: &AppConfig,
) -> Result<Posture> {
    use crate::identity::keypair::{DAEMON_KEYPAIR_LABEL, agent_priv_path, agent_pub_path};
    let mut roles = Vec::with_capacity(RoleId::ALL.len());
    let (at_rest_need, at_rest_why) = at_rest_needed(config, shape);

    // recovery-anchor
    let recovery_file = KeyFile::observe(
        escrow::recovery_pub_path(dir),
        Custody::Public,
        Some(RAW_KEY_LEN),
    );
    let recovery_enrolled = recovery_file.present && !recovery_file.unreadable();
    let (state, detail) = if recovery_file.unreadable() {
        (
            RoleState::Partial(Partial::Unreadable),
            unreadable_detail(&recovery_file),
        )
    } else if recovery_file.present {
        (RoleState::Complete, "present".to_string())
    } else {
        (
            RoleState::Absent,
            format!(
                "no deployment recovery key is enrolled, so no at-rest escrow can be written; \
                 mint one: {}",
                escrow::REMEDY_ENROLL_RECOVERY_KEY
            ),
        )
    };
    roles.push(Role {
        id: RoleId::RecoveryAnchor,
        purpose: "the deployment recovery public key every at-rest escrow is wrapped under \
                  (its private half lives OFF-NODE with the operator)",
        need: at_rest_need,
        why: at_rest_why.clone(),
        files: vec![recovery_file],
        state,
        detail,
        expires_in_days: None,
        mint_command: Some(escrow::REMEDY_ENROLL_RECOVERY_KEY.to_string()),
    });

    // identity + daemon-signer
    for (id, label, purpose, why, mint) in [
        (
            RoleId::Identity,
            agent_id,
            "signs this node's links, attestations and audit rows as the resolved agent id",
            format!("every installation signs as `{agent_id}`"),
            format!("ai-memory identity generate --agent-id {agent_id}"),
        ),
        (
            RoleId::DaemonSigner,
            DAEMON_KEYPAIR_LABEL,
            "signs the daemon's own ledger rows (the reserved `daemon` label)",
            "every daemon writes a signed ledger".to_string(),
            KEYS_INIT.to_string(),
        ),
    ] {
        let private = KeyFile::observe(
            agent_priv_path(dir, label),
            Custody::Private,
            Some(RAW_KEY_LEN),
        );
        let public = KeyFile::observe(
            agent_pub_path(dir, label),
            Custody::Public,
            Some(RAW_KEY_LEN),
        );
        let (state, detail) = pair_state(&private, &[&public]);
        roles.push(Role {
            id,
            purpose,
            need: Need::Always,
            why,
            files: vec![private, public],
            state,
            detail,
            expires_in_days: None,
            mint_command: Some(mint),
        });
    }

    // at-rest-wrap
    let (x_pub, x_priv) = crate::encryption::x25519_key_paths(agent_id, dir);
    let private = KeyFile::observe(x_priv, Custody::Private, Some(RAW_KEY_LEN));
    let escrow_file = KeyFile::observe(escrow::escrow_path(agent_id, dir), Custody::Escrow, None);
    let public = KeyFile::observe(x_pub, Custody::Public, Some(RAW_KEY_LEN));
    let (state, mut detail) = pair_state(&private, &[&escrow_file, &public]);
    if state == RoleState::Partial(Partial::LostPrivate) {
        detail = if escrow_file.present {
            format!(
                "{} is MISSING but its escrow {} exists — restore it: {}",
                private.path.display(),
                escrow_file.path.display(),
                escrow::REMEDY_RECOVER
            )
        } else {
            format!(
                "{} is MISSING and no escrow exists — every row sealed under it is unreadable \
                 until it is restored from backup; nothing here can regenerate it",
                private.path.display()
            )
        };
    } else if state == RoleState::Partial(Partial::Recoverable)
        && !escrow_file.present
        && !recovery_enrolled
    {
        detail = format!(
            "{} present, {} missing and no recovery key is enrolled to wrap it under — enroll \
             one first: {}",
            private.path.display(),
            escrow_file.path.display(),
            escrow::REMEDY_ENROLL_RECOVERY_KEY
        );
    }
    roles.push(Role {
        id: RoleId::AtRestWrap,
        purpose: "wraps the per-record data keys that seal memory content at rest (X25519), \
                  escrowed under the recovery key",
        need: at_rest_need,
        why: at_rest_why,
        files: vec![private, escrow_file, public],
        state,
        detail,
        expires_in_days: None,
        mint_command: Some(KEYS_INIT.to_string()),
    });

    // tls
    let tls_dir = dir.join(crate::tls_bootstrap::TLS_SUBDIR);
    let leaf = crate::tls_bootstrap::leaf_status(dir)?;
    let fleet = shape != DeploymentShape::Singleton;
    let ca_key = KeyFile::observe(
        tls_dir.join(crate::tls_bootstrap::LOCAL_CA_KEY_FILE),
        Custody::Private,
        None,
    );
    let ca_cert = KeyFile::observe(
        tls_dir.join(crate::tls_bootstrap::LOCAL_CA_CERT_FILE),
        Custody::Public,
        None,
    );
    let leaf_key = KeyFile::observe(
        tls_dir.join(crate::tls_bootstrap::SERVER_KEY_FILE),
        Custody::Private,
        None,
    );
    let leaf_cert = KeyFile::observe(
        tls_dir.join(crate::tls_bootstrap::SERVER_CERT_FILE),
        Custody::Public,
        None,
    );
    let files = [&ca_key, &ca_cert, &leaf_key, &leaf_cert];
    let any_present = files.iter().any(|f| f.present);
    let (state, detail, why, mint) = if fleet {
        let why = format!(
            "{} takes enterprise PKI: {}",
            shape.config_line(),
            crate::transit_encryption::REMEDY_ENTERPRISE_PKI
        );
        if any_present {
            (
                RoleState::OperatorSupplied,
                "present; operator material under a fleet shape is never touched here".to_string(),
                why,
                None,
            )
        } else {
            (RoleState::Absent, "absent".to_string(), why, None)
        }
    } else if let Some(bad) = files.iter().find(|f| f.unreadable()) {
        (
            RoleState::Partial(Partial::Unreadable),
            unreadable_detail(bad),
            SINGLETON_TLS_WHY.to_string(),
            Some(KEYS_INIT.to_string()),
        )
    } else if !any_present {
        (
            RoleState::Absent,
            "absent".to_string(),
            SINGLETON_TLS_WHY.to_string(),
            Some(KEYS_INIT.to_string()),
        )
    } else if ca_key.present && ca_cert.present {
        if leaf_key.present && leaf_cert.present {
            (
                RoleState::Complete,
                "present".to_string(),
                SINGLETON_TLS_WHY.to_string(),
                Some(KEYS_INIT.to_string()),
            )
        } else {
            (
                RoleState::Partial(Partial::Recoverable),
                format!(
                    "the local CA is present and the server certificate is not — re-issued \
                     from the CA by `keys init` (the CA is never rewritten)"
                ),
                SINGLETON_TLS_WHY.to_string(),
                Some(KEYS_INIT.to_string()),
            )
        }
    } else if ca_cert.present {
        (
            RoleState::Partial(Partial::LostPrivate),
            format!(
                "{} is MISSING while {} exists — the CA every bundled client trusts cannot be \
                 re-issued without its key and is deliberately NOT regenerated; restore the key \
                 from backup, or remove the whole {} directory to accept a fresh CA",
                ca_key.path.display(),
                ca_cert.path.display(),
                tls_dir.display()
            ),
            SINGLETON_TLS_WHY.to_string(),
            Some(KEYS_INIT.to_string()),
        )
    } else {
        (
            RoleState::Partial(Partial::Unreadable),
            format!(
                "{} exists without {} — the CA certificate cannot be re-issued here; restore it \
                 from backup, or remove the whole {} directory to accept a fresh CA",
                ca_key.path.display(),
                ca_cert.path.display(),
                tls_dir.display()
            ),
            SINGLETON_TLS_WHY.to_string(),
            Some(KEYS_INIT.to_string()),
        )
    };
    roles.push(Role {
        id: RoleId::Tls,
        purpose: "the listener's certificate and key (#3705: every hop is TLS)",
        need: Need::Always,
        why,
        files: vec![ca_key, ca_cert, leaf_key, leaf_cert],
        state,
        detail,
        expires_in_days: leaf.days_remaining,
        mint_command: mint,
    });

    // capability-owner
    let (need, why) = capabilities_needed(config);
    let owner = crate::governance::capability::OWNER_ISSUER;
    let private = KeyFile::observe(
        agent_priv_path(dir, owner),
        Custody::Private,
        Some(RAW_KEY_LEN),
    );
    let caproot = KeyFile::observe(
        crate::governance::capability::caproot_path(dir, owner)?,
        Custody::Private,
        Some(crate::governance::capability::ROOT_SECRET_LEN as u64),
    );
    let public = KeyFile::observe(
        agent_pub_path(dir, owner),
        Custody::Public,
        Some(RAW_KEY_LEN),
    );
    let (state, mut detail) = pair_state(&private, &[&caproot, &public]);
    if state == RoleState::Partial(Partial::Recoverable) && !caproot.present {
        detail.push_str(
            " (a fresh owner.caproot invalidates every outstanding owner-issued token — the \
             documented rotation)",
        );
    }
    roles.push(Role {
        id: RoleId::CapabilityOwner,
        purpose: "mints and attributes capability tokens (the reserved `owner` issuer)",
        need,
        why,
        files: vec![private, caproot, public],
        state,
        detail,
        expires_in_days: None,
        mint_command: Some("ai-memory capability init".to_string()),
    });

    #[cfg(unix)]
    let key_dir_mode = {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(dir)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let key_dir_mode = None;

    Ok(Posture {
        key_dir: dir.to_path_buf(),
        key_dir_mode,
        agent_id: agent_id.to_string(),
        shape: shape.as_str().to_string(),
        recovery_enrolled,
        roles,
    })
}

const KEYS_INIT: &str = "ai-memory keys init";
/// JSON / doctor fact key: whether a recovery key is enrolled.
pub const FIELD_RECOVERY_ENROLLED: &str = "recovery_enrolled";
/// JSON / doctor fact key: the key directory's mode.
pub const FIELD_KEY_DIR_MODE: &str = "key_dir_mode";
/// The output word for operator-supplied material.
pub const WORD_OPERATOR_SUPPLIED: &str = "operator-supplied";
const SINGLETON_TLS_WHY: &str = "the singleton shape mints a local CA and server certificate";

/// What the plan says to do about one role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Absent and mintable here: mint.
    Mint,
    /// Recoverable partial: repair from the surviving private half.
    Repair,
    /// Complete: nothing to do.
    Present,
    /// Not needed under this configuration: nothing to do.
    NotRequired,
    /// Needed but this installation cannot mint it (fleet TLS, no recovery
    /// key): nothing is written; the reason names the remedy.
    CannotMint,
    /// A lost-private or unreadable partial: the whole run refuses BEFORE
    /// any write.
    Refuse,
    /// Operator material: never touched.
    OperatorSupplied,
}

/// One planned step.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Step {
    pub role: RoleId,
    pub action: Action,
    pub reason: String,
}

/// The plan for a posture: one step per role, in role order.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Plan {
    pub steps: Vec<Step>,
}

impl Plan {
    /// The steps that refuse the run.
    #[must_use]
    pub fn refusals(&self) -> Vec<&Step> {
        self.steps
            .iter()
            .filter(|s| s.action == Action::Refuse)
            .collect()
    }

    /// Whether any step refuses (then [`execute`] writes nothing).
    #[must_use]
    pub fn is_refused(&self) -> bool {
        !self.refusals().is_empty()
    }

    /// The step for `role`.
    #[must_use]
    pub fn step(&self, role: RoleId) -> &Step {
        self.steps
            .iter()
            .find(|s| s.role == role)
            .expect("every role is planned")
    }
}

/// Inputs the plan needs beyond the posture.
#[derive(Clone, Debug, Default)]
pub struct PlanOptions {
    /// Mint a deployment recovery keypair, writing its PRIVATE half here.
    pub recovery_key_out: Option<PathBuf>,
    /// The bind host the local TLS leaf must cover.
    pub host: Option<String>,
}

/// Decide, purely, what `keys init` does about each role of `posture`.
/// Consumed unchanged by the dry run, the real run and `keys status`.
#[must_use]
pub fn plan(posture: &Posture, opts: &PlanOptions) -> Plan {
    let recovery_available = posture.recovery_enrolled || opts.recovery_key_out.is_some();
    let steps = posture
        .roles
        .iter()
        .map(|r| {
            let (action, reason) = match r.state {
                _ if r.need == Need::NotRequired => (Action::NotRequired, r.why.clone()),
                RoleState::Complete => (Action::Present, "present".to_string()),
                RoleState::OperatorSupplied => (Action::OperatorSupplied, r.detail.clone()),
                RoleState::Partial(Partial::LostPrivate | Partial::Unreadable) => {
                    (Action::Refuse, r.detail.clone())
                }
                RoleState::Partial(Partial::Recoverable) => match r.id {
                    RoleId::AtRestWrap if !recovery_available && !r.files[1].present => {
                        (Action::CannotMint, r.detail.clone())
                    }
                    _ => (Action::Repair, r.detail.clone()),
                },
                RoleState::Absent => match r.id {
                    RoleId::RecoveryAnchor if opts.recovery_key_out.is_none() => {
                        (Action::CannotMint, r.detail.clone())
                    }
                    RoleId::AtRestWrap if !recovery_available => (
                        Action::CannotMint,
                        format!(
                            "no recovery key is enrolled — the at-rest key is minted only with \
                             its escrow; enroll one first: {}",
                            escrow::REMEDY_ENROLL_RECOVERY_KEY
                        ),
                    ),
                    _ if r.mint_command.is_none() => (Action::CannotMint, r.why.clone()),
                    _ => (Action::Mint, format!("absent; {}", r.why)),
                },
            };
            Step {
                role: r.id,
                action,
                reason,
            }
        })
        .collect();
    Plan { steps }
}

/// What [`execute`] did for one role. Never `Minted` unless a generator
/// reported a fresh mint; never `Repaired` unless the role is complete
/// afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintOutcome {
    Present,
    Minted,
    Repaired,
    NotRequired,
    CannotMint,
    OperatorSupplied,
}

/// One role's outcome.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Outcome {
    pub role: RoleId,
    pub outcome: MintOutcome,
    pub reason: String,
}

/// The refusal text for a plan that refuses (one line per refusing role).
#[must_use]
pub fn refusal_text(plan: &Plan) -> String {
    let lines: Vec<String> = plan
        .refusals()
        .iter()
        .map(|s| format!("  {:<17} {}", s.role.label(), s.reason))
        .collect();
    format!(
        "keys init: refusing before any write — a key role is partly on disk and cannot be \
         completed without minting a different key (#3717):\n{}",
        lines.join("\n")
    )
}

/// The refusal text for a leaky directory or file.
#[must_use]
pub fn loose_text(posture: &Posture) -> Option<String> {
    let mut lines = Vec::new();
    if let Some(mode) = posture.key_dir_mode.filter(|_| posture.key_dir_is_loose()) {
        lines.push(format!(
            "  {} is mode {mode:04o}; fix: chmod 0700 {}",
            posture.key_dir.display(),
            posture.key_dir.display()
        ));
    }
    for f in posture.loose_files() {
        lines.push(format!(
            "  {} is mode {:04o}; fix: {}",
            f.path.display(),
            f.mode.unwrap_or_default(),
            f.chmod_fix()
        ));
    }
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "keys init: refusing to mint into a key directory that leaks — private material must be \
         0600 and the directory 0700 (#3717):\n{}",
        lines.join("\n")
    ))
}

/// Carry out `plan` for `posture`. Refuses BEFORE ANY WRITE when the plan
/// refuses or the directory leaks; otherwise each `Mint` / `Repair` step
/// runs through the role's own generator and reports a typed outcome.
///
/// # Errors
/// The plan refuses, the directory leaks, or a generator fails (every
/// generator refuses on its own partial states as well — belt and braces).
pub fn execute(posture: &Posture, plan: &Plan, opts: &PlanOptions) -> Result<Vec<Outcome>> {
    if let Some(text) = loose_text(posture) {
        bail!(text);
    }
    if plan.is_refused() {
        bail!(refusal_text(plan));
    }
    let dir = posture.key_dir.as_path();
    let host = opts.host.as_deref().unwrap_or(DEFAULT_TLS_HOST);
    let mut out = Vec::with_capacity(plan.steps.len());
    for step in &plan.steps {
        let outcome = match step.action {
            Action::Present => MintOutcome::Present,
            Action::NotRequired => MintOutcome::NotRequired,
            Action::CannotMint => MintOutcome::CannotMint,
            Action::OperatorSupplied => MintOutcome::OperatorSupplied,
            Action::Refuse => unreachable!("refusals bail above"),
            Action::Mint | Action::Repair => {
                run_step(posture, step, dir, host, opts.recovery_key_out.as_deref())?
            }
        };
        out.push(Outcome {
            role: step.role,
            outcome,
            reason: step.reason.clone(),
        });
    }
    Ok(out)
}

/// The bind host `keys init` covers for the local TLS leaf when none is
/// given (the loopback set plus the machine hostname are always covered).
pub const DEFAULT_TLS_HOST: &str = "127.0.0.1";

fn run_step(
    posture: &Posture,
    step: &Step,
    dir: &Path,
    host: &str,
    recovery_key_out: Option<&Path>,
) -> Result<MintOutcome> {
    use crate::identity::keypair::{DAEMON_KEYPAIR_LABEL, EnsureOutcome, ensure_keypair};
    let repairing = step.action == Action::Repair;
    let agent_id = posture.agent_id.as_str();
    match step.role {
        RoleId::RecoveryAnchor => {
            let out = recovery_key_out
                .context("the recovery-anchor step needs --recovery-key-out (planned as Mint)")?;
            escrow::mint_recovery_keypair(dir, out).context("minting the recovery keypair")?;
            Ok(MintOutcome::Minted)
        }
        RoleId::Identity | RoleId::DaemonSigner => {
            let label = if step.role == RoleId::Identity {
                agent_id
            } else {
                DAEMON_KEYPAIR_LABEL
            };
            match ensure_keypair(label, dir, false)
                .with_context(|| format!("ensuring the {} keypair", step.role.label()))?
            {
                EnsureOutcome::Generated { .. } => Ok(MintOutcome::Minted),
                EnsureOutcome::RepairedPublicFromPrivate { .. } => Ok(MintOutcome::Repaired),
                EnsureOutcome::AlreadyExists { .. } => Ok(if repairing {
                    MintOutcome::Repaired
                } else {
                    MintOutcome::Present
                }),
                EnsureOutcome::PublicOnlyDegraded { pub_path, .. } => bail!(
                    "{} refused: {} exists without its private half (planned as {:?})",
                    step.role.label(),
                    pub_path.display(),
                    step.action
                ),
                EnsureOutcome::SkippedDisabled => bail!("keypair auto-generation is disabled"),
            }
        }
        RoleId::AtRestWrap => {
            if repairing {
                escrow::repair_public_half(agent_id, dir)?;
                match escrow::ensure_escrow(agent_id, dir)? {
                    escrow::EscrowOutcome::Present | escrow::EscrowOutcome::Written => {
                        Ok(MintOutcome::Repaired)
                    }
                    escrow::EscrowOutcome::NoRecoveryKey => Ok(MintOutcome::CannotMint),
                }
            } else {
                crate::encryption::get_or_create_keypair_in(agent_id, dir)
                    .with_context(|| format!("minting the at-rest wrap keypair for {agent_id}"))?;
                if !escrow::escrow_present(agent_id, dir) {
                    bail!(
                        "the at-rest key for {agent_id} was minted but no escrow was written — \
                         no recovery key is enrolled at {}",
                        escrow::recovery_pub_path(dir).display()
                    );
                }
                Ok(MintOutcome::Minted)
            }
        }
        RoleId::Tls => {
            let tls = crate::tls_bootstrap::ensure_local_tls(dir, host)
                .context("minting the local TLS certificate")?;
            Ok(match tls.outcome {
                crate::tls_bootstrap::Outcome::Generated => MintOutcome::Minted,
                crate::tls_bootstrap::Outcome::Renewed { .. }
                | crate::tls_bootstrap::Outcome::Reused => MintOutcome::Repaired,
            })
        }
        RoleId::CapabilityOwner => {
            let outcome = crate::cli::capability::init_owner(dir)
                .context("minting the capability owner custody")?;
            Ok(if outcome.already_initialized() {
                if repairing {
                    MintOutcome::Repaired
                } else {
                    MintOutcome::Present
                }
            } else if repairing {
                MintOutcome::Repaired
            } else {
                MintOutcome::Minted
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::shape::DeploymentSection;
    use std::collections::BTreeMap;

    /// A per-test agent id: the at-rest keypair cache is process-wide and
    /// keyed by agent id, so two tests sharing one id would see each
    /// other's cached key instead of their own sandbox's disk.
    fn agent(tag: &str) -> String {
        format!("ai:posture-3717-{tag}-{}", uuid::Uuid::new_v4().simple())
    }

    fn sandbox() -> tempfile::TempDir {
        let t = tempfile::tempdir().expect("tempdir under TMPDIR");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::create_dir_all(t.path().join("off-node")).unwrap();
        t
    }

    fn config_for(shape: DeploymentShape, at_rest: bool) -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.deployment = Some(DeploymentSection { shape: Some(shape) });
        cfg.encryption = Some(crate::config::EncryptionSection {
            at_rest: Some(at_rest),
        });
        cfg
    }

    /// Every regular file under `dir` with its bytes.
    fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = format!("{prefix}{}", e.file_name().to_string_lossy());
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), &format!("{name}/"), out);
                } else {
                    out.insert(name, std::fs::read(e.path()).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, "", &mut out);
        out
    }

    fn opts(dir: &Path) -> PlanOptions {
        PlanOptions {
            recovery_key_out: Some(dir.join("off-node").join("recovery.key")),
            host: Some("10.1.2.3".into()),
        }
    }

    fn singleton(dir: &Path, agent: &str, cfg: &AppConfig) -> Posture {
        observe(dir, agent, DeploymentShape::Singleton, cfg).unwrap()
    }

    /// Mint a complete singleton posture (every role incl. at-rest + owner).
    /// The caller holds the crate env lock.
    fn mint_complete(dir: &Path, agent: &str) -> (AppConfig, Posture) {
        let cfg = config_for(DeploymentShape::Singleton, true);
        let before = singleton(dir, agent, &cfg);
        let p = plan(&before, &opts(dir));
        assert!(!p.is_refused(), "{p:?}");
        let outcomes = execute(&before, &p, &opts(dir)).unwrap();
        for o in &outcomes {
            assert!(
                matches!(o.outcome, MintOutcome::Minted | MintOutcome::NotRequired),
                "{o:?}"
            );
        }
        crate::encryption::evict_cached_keypair(agent);
        let after = singleton(dir, agent, &cfg);
        assert!(
            after.missing_required().is_empty(),
            "{:?}",
            after.missing_required()
        );
        (cfg, after)
    }

    #[test]
    fn empty_singleton_dir_mints_every_role_once_and_partitions_by_custody_3717() {
        let tmp = sandbox();
        let agent = agent("mint");
        let _env = crate::test_support::env_lock();
        let (cfg, after) = mint_complete(tmp.path(), &agent);
        let files = snapshot(tmp.path());
        let mut expected: Vec<String> = [
            format!("{agent}.priv"),
            format!("{agent}.pub"),
            format!("{agent}.x25519.escrow"),
            format!("{agent}.x25519.priv"),
            format!("{agent}.x25519.pub"),
        ]
        .into_iter()
        .chain(
            [
                "daemon.priv",
                "daemon.pub",
                "off-node/recovery.key",
                "owner.caproot",
                "owner.priv",
                "owner.pub",
                "recovery.x25519.pub",
                "tls/local-ca.key",
                "tls/local-ca.pem",
                "tls/server.key",
                "tls/server.pem",
            ]
            .map(String::from),
        )
        .collect();
        expected.sort();
        assert_eq!(files.keys().cloned().collect::<Vec<_>>(), expected);
        assert!(after.loose_files().is_empty(), "{:?}", after.loose_files());
        let rel = |paths: Vec<&Path>| {
            let mut v: Vec<String> = paths
                .iter()
                .map(|p| p.strip_prefix(tmp.path()).unwrap().display().to_string())
                .collect();
            v.sort();
            v
        };
        let back_up = rel(after.back_up());
        let distribute = rel(after.distribute());
        assert!(
            back_up.iter().all(|f| f.ends_with(".priv")
                || f.ends_with(".key")
                || f.ends_with(".caproot")
                || f.ends_with(".escrow")),
            "{back_up:?}"
        );
        assert!(
            distribute
                .iter()
                .all(|f| f.ends_with(".pub") || f.ends_with(".pem")),
            "{distribute:?}"
        );
        let mut union = back_up.clone();
        union.extend(distribute.iter().cloned());
        union.sort();
        let mut on_disk: Vec<String> = files.keys().cloned().collect();
        on_disk.retain(|f| f != "off-node/recovery.key");
        assert_eq!(union, on_disk, "every key-dir file is in exactly one list");
        // Second run: same plan shape, nothing written, bytes untouched.
        let p = plan(&after, &PlanOptions::default());
        assert!(
            p.steps
                .iter()
                .all(|s| matches!(s.action, Action::Present | Action::NotRequired)),
            "{p:?}"
        );
        let again = execute(&after, &p, &PlanOptions::default()).unwrap();
        assert!(
            again
                .iter()
                .all(|o| matches!(o.outcome, MintOutcome::Present | MintOutcome::NotRequired)),
            "{again:?}"
        );
        assert_eq!(snapshot(tmp.path()), files, "idempotent: byte-identical");
        assert!(
            singleton(tmp.path(), &agent, &cfg)
                .missing_required()
                .is_empty()
        );
    }

    /// The dry run and the real run consume the SAME plan: the plan is a
    /// pure function of the posture, and planning writes nothing. Without
    /// `--recovery-key-out` the anchor and the at-rest key CANNOT be minted
    /// (the escrow is mandatory) and the plan says so instead of minting.
    #[test]
    fn dry_run_and_real_run_share_one_plan_3717() {
        let tmp = sandbox();
        let agent = agent("plan");
        let _env = crate::test_support::env_lock();
        let cfg = config_for(DeploymentShape::Singleton, true);
        let before = singleton(tmp.path(), &agent, &cfg);
        let p1 = plan(&before, &opts(tmp.path()));
        let p2 = plan(&before, &opts(tmp.path()));
        assert_eq!(p1, p2);
        assert!(
            p1.steps.iter().all(|s| s.action == Action::Mint),
            "everything absent mints: {p1:?}"
        );
        assert_eq!(snapshot(tmp.path()).len(), 0, "planning writes nothing");
        let p3 = plan(&before, &PlanOptions::default());
        assert_eq!(p3.step(RoleId::RecoveryAnchor).action, Action::CannotMint);
        assert_eq!(p3.step(RoleId::AtRestWrap).action, Action::CannotMint);
        assert!(
            p3.step(RoleId::AtRestWrap)
                .reason
                .contains("--recovery-key-out")
        );
        let outcomes = execute(&before, &p3, &PlanOptions::default()).unwrap();
        assert!(
            outcomes
                .iter()
                .filter(|o| matches!(o.role, RoleId::RecoveryAnchor | RoleId::AtRestWrap))
                .all(|o| o.outcome == MintOutcome::CannotMint)
        );
        assert!(
            !tmp.path().join(format!("{agent}.x25519.priv")).exists(),
            "no at-rest key without an escrow"
        );
        assert!(
            tmp.path().join("daemon.priv").exists(),
            "the mintable roles minted"
        );
    }

    /// The loss-property table: for every role, losing a DERIVABLE file is
    /// repaired from the surviving private half (private bytes untouched),
    /// and losing the PRIVATE half refuses the whole run before any write.
    #[test]
    fn loss_property_table_over_every_role_3717() {
        let _env = crate::test_support::env_lock();
        let agent = agent("table");
        let a = agent.as_str();
        // (role, derivable file(s) to delete, private file(s) to delete)
        let table: [(RoleId, Vec<String>, Vec<String>); 5] = [
            (
                RoleId::Identity,
                vec![format!("{a}.pub")],
                vec![format!("{a}.priv")],
            ),
            (
                RoleId::DaemonSigner,
                vec!["daemon.pub".into()],
                vec!["daemon.priv".into()],
            ),
            (
                RoleId::AtRestWrap,
                vec![format!("{a}.x25519.pub"), format!("{a}.x25519.escrow")],
                vec![format!("{a}.x25519.priv")],
            ),
            (
                RoleId::Tls,
                vec!["tls/server.key".into(), "tls/server.pem".into()],
                vec!["tls/local-ca.key".into()],
            ),
            (
                RoleId::CapabilityOwner,
                vec!["owner.pub".into(), "owner.caproot".into()],
                vec!["owner.priv".into()],
            ),
        ];
        for (role, derivable, private) in &table {
            // Recoverable: delete the derivable files.
            let tmp = sandbox();
            let (cfg, _) = mint_complete(tmp.path(), a);
            let complete = snapshot(tmp.path());
            for f in derivable {
                std::fs::remove_file(tmp.path().join(f)).unwrap();
            }
            let p = singleton(tmp.path(), a, &cfg);
            assert_eq!(
                p.role(*role).state,
                RoleState::Partial(Partial::Recoverable),
                "{role:?}: {}",
                p.role(*role).detail
            );
            let plan_r = plan(&p, &PlanOptions::default());
            assert_eq!(plan_r.step(*role).action, Action::Repair, "{role:?}");
            assert!(
                plan_r
                    .steps
                    .iter()
                    .filter(|s| s.role != *role)
                    .all(|s| matches!(s.action, Action::Present | Action::NotRequired)),
                "{role:?}: only the damaged role acts: {plan_r:?}"
            );
            let outcomes = execute(&p, &plan_r, &PlanOptions::default()).unwrap();
            let o = outcomes.iter().find(|o| o.role == *role).unwrap();
            assert_eq!(o.outcome, MintOutcome::Repaired, "{role:?}: {o:?}");
            let repaired = snapshot(tmp.path());
            for f in private {
                assert_eq!(
                    repaired[f], complete[f],
                    "{role:?}: {f} untouched by the repair"
                );
            }
            crate::encryption::evict_cached_keypair(a);
            let after = singleton(tmp.path(), a, &cfg);
            assert_eq!(after.role(*role).state, RoleState::Complete, "{role:?}");
            // A re-derived public key is byte-identical (a function of its
            // private half); a re-issued leaf, a fresh caproot and a
            // re-wrapped escrow are legitimately new bytes.
            for f in derivable.iter().filter(|f| f.ends_with(".pub")) {
                assert_eq!(repaired[f], complete[f], "{role:?}: {f} re-derived");
            }

            // LostPrivate: delete the private file(s) from a complete set.
            let tmp = sandbox();
            let (cfg, _) = mint_complete(tmp.path(), a);
            for f in private {
                std::fs::remove_file(tmp.path().join(f)).unwrap();
            }
            let before = snapshot(tmp.path());
            let p = singleton(tmp.path(), a, &cfg);
            assert_eq!(
                p.role(*role).state,
                RoleState::Partial(Partial::LostPrivate),
                "{role:?}: {}",
                p.role(*role).detail
            );
            let plan_l = plan(&p, &opts(tmp.path()));
            assert_eq!(plan_l.step(*role).action, Action::Refuse, "{role:?}");
            assert!(plan_l.is_refused());
            let err = execute(&p, &plan_l, &opts(tmp.path())).unwrap_err();
            let text = format!("{err:#}");
            assert!(
                text.contains("refusing before any write"),
                "{role:?}: {text}"
            );
            assert!(text.contains(role.label()), "{role:?}: {text}");
            assert_eq!(
                snapshot(tmp.path()),
                before,
                "{role:?}: nothing written on refusal"
            );
            crate::encryption::evict_cached_keypair(a);
        }
    }

    /// F1 — `owner.priv` present, `owner.pub` absent (the half-state the
    /// rejected cut's `init_owner … unwrap_or(false)` minted OVER): the
    /// private half is never overwritten; the public half is re-derived.
    /// The mirror half-state (`owner.pub` without `owner.priv`) is refused,
    /// not re-minted, by the primitive itself.
    #[test]
    fn f1_owner_priv_half_state_is_never_overwritten_3717() {
        let tmp = sandbox();
        let agent = agent("f1");
        let _env = crate::test_support::env_lock();
        let (cfg, _) = mint_complete(tmp.path(), &agent);
        let owner_priv = std::fs::read(tmp.path().join("owner.priv")).unwrap();
        let owner_pub = std::fs::read(tmp.path().join("owner.pub")).unwrap();
        std::fs::remove_file(tmp.path().join("owner.pub")).unwrap();
        let p = singleton(tmp.path(), &agent, &cfg);
        assert_eq!(
            p.role(RoleId::CapabilityOwner).state,
            RoleState::Partial(Partial::Recoverable)
        );
        let pl = plan(&p, &PlanOptions::default());
        assert_eq!(pl.step(RoleId::CapabilityOwner).action, Action::Repair);
        execute(&p, &pl, &PlanOptions::default()).unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("owner.priv")).unwrap(),
            owner_priv,
            "F1: owner.priv untouched"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("owner.pub")).unwrap(),
            owner_pub,
            "F1: owner.pub re-derived from the surviving private half"
        );
        std::fs::remove_file(tmp.path().join("owner.pub")).unwrap();
        crate::cli::capability::init_owner(tmp.path()).unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("owner.priv")).unwrap(),
            owner_priv
        );
        assert_eq!(
            std::fs::read(tmp.path().join("owner.pub")).unwrap(),
            owner_pub
        );
        std::fs::remove_file(tmp.path().join("owner.priv")).unwrap();
        let err = crate::cli::capability::init_owner(tmp.path())
            .err()
            .expect("public-only owner refused");
        assert!(
            format!("{err:#}").contains("without its private half"),
            "{err:#}"
        );
        assert!(!tmp.path().join("owner.priv").exists(), "nothing minted");
    }

    /// F2 — `<agent>.x25519.priv` lost, `.pub` (and the escrow) present:
    /// refused before any write; the `.pub` is untouched; the remedy names
    /// `keys recover`.
    #[test]
    fn f2_lost_x25519_priv_refuses_and_leaves_pub_untouched_3717() {
        let tmp = sandbox();
        let agent = agent("f2");
        let _env = crate::test_support::env_lock();
        let (cfg, _) = mint_complete(tmp.path(), &agent);
        std::fs::remove_file(tmp.path().join(format!("{agent}.x25519.priv"))).unwrap();
        let before = snapshot(tmp.path());
        let p = singleton(tmp.path(), &agent, &cfg);
        let pl = plan(&p, &PlanOptions::default());
        // The DISK evidence first (the defect was an overwrite), the typing after.
        let res = execute(&p, &pl, &PlanOptions::default());
        assert_eq!(
            snapshot(tmp.path()),
            before,
            "F2: nothing written, .pub untouched"
        );
        let err = res.err().expect("F2: a lost private half refuses");
        assert!(format!("{err:#}").contains("at-rest-wrap"), "{err:#}");
        let role = p.role(RoleId::AtRestWrap);
        assert_eq!(role.state, RoleState::Partial(Partial::LostPrivate));
        assert!(
            role.detail.contains(escrow::REMEDY_RECOVER),
            "{}",
            role.detail
        );
        assert_eq!(pl.step(RoleId::AtRestWrap).action, Action::Refuse);
    }

    /// F4 — singleton TLS with `local-ca.key` offline (cert present): the
    /// CA is never rewritten and nothing is written at all; with only the
    /// LEAF missing the CA files are byte-identical after the repair.
    #[test]
    fn f4_existing_local_tls_ca_is_never_rewritten_when_its_key_is_offline_3717() {
        let tmp = sandbox();
        let agent = agent("f4");
        let _env = crate::test_support::env_lock();
        let (cfg, _) = mint_complete(tmp.path(), &agent);
        let ca_pem = std::fs::read(tmp.path().join("tls/local-ca.pem")).unwrap();
        std::fs::remove_file(tmp.path().join("tls/local-ca.key")).unwrap();
        let before = snapshot(tmp.path());
        let p = singleton(tmp.path(), &agent, &cfg);
        let pl = plan(&p, &opts(tmp.path()));
        // The DISK evidence first (the defect was a rewritten CA), the typing after.
        let res = execute(&p, &pl, &opts(tmp.path()));
        assert_eq!(
            std::fs::read(tmp.path().join("tls/local-ca.pem")).unwrap(),
            ca_pem,
            "F4: the CA certificate every client trusts is never rewritten"
        );
        assert_eq!(snapshot(tmp.path()), before, "F4: nothing written");
        let err = res.err().expect("F4: an offline CA key refuses");
        assert!(format!("{err:#}").contains("local-ca.key"), "{err:#}");
        assert_eq!(
            p.role(RoleId::Tls).state,
            RoleState::Partial(Partial::LostPrivate)
        );
        assert_eq!(pl.step(RoleId::Tls).action, Action::Refuse);
        // Leaf-only loss: the CA survives the re-issue byte for byte.
        let tmp = sandbox();
        let agent = self::agent("f4-leaf");
        let (cfg, _) = mint_complete(tmp.path(), &agent);
        let ca_key = std::fs::read(tmp.path().join("tls/local-ca.key")).unwrap();
        let ca_pem = std::fs::read(tmp.path().join("tls/local-ca.pem")).unwrap();
        std::fs::remove_file(tmp.path().join("tls/server.pem")).unwrap();
        let p = singleton(tmp.path(), &agent, &cfg);
        assert_eq!(
            p.role(RoleId::Tls).state,
            RoleState::Partial(Partial::Recoverable)
        );
        let pl = plan(&p, &PlanOptions::default());
        assert_eq!(pl.step(RoleId::Tls).action, Action::Repair);
        let outcomes = execute(&p, &pl, &PlanOptions::default()).unwrap();
        assert_eq!(
            outcomes
                .iter()
                .find(|o| o.role == RoleId::Tls)
                .unwrap()
                .outcome,
            MintOutcome::Repaired
        );
        assert_eq!(
            std::fs::read(tmp.path().join("tls/local-ca.key")).unwrap(),
            ca_key
        );
        assert_eq!(
            std::fs::read(tmp.path().join("tls/local-ca.pem")).unwrap(),
            ca_pem
        );
        assert!(tmp.path().join("tls/server.pem").exists());
    }

    /// A fleet shape: the at-rest key IS required, TLS cannot be minted here
    /// (enterprise PKI) and present TLS material is operator-supplied and
    /// never touched; a loose private file is reported with its chmod fix
    /// and refuses the run.
    #[test]
    fn production_requires_at_rest_never_touches_tls_and_refuses_loose_modes_3717() {
        let tmp = sandbox();
        let agent = agent("prod");
        let _env = crate::test_support::env_lock();
        let cfg = config_for(DeploymentShape::Production, true);
        let before = observe(tmp.path(), &agent, DeploymentShape::Production, &cfg).unwrap();
        let at_rest = before.role(RoleId::AtRestWrap);
        assert_eq!(at_rest.need, Need::Required, "{}", at_rest.why);
        assert!(
            at_rest.why.contains("pending recovery escrow"),
            "{}",
            at_rest.why
        );
        let tls = before.role(RoleId::Tls);
        assert!(tls.mint_command.is_none());
        assert!(
            tls.why
                .contains(crate::transit_encryption::REMEDY_ENTERPRISE_PKI),
            "{}",
            tls.why
        );
        let pl = plan(&before, &opts(tmp.path()));
        assert_eq!(pl.step(RoleId::Tls).action, Action::CannotMint);
        assert_eq!(pl.step(RoleId::AtRestWrap).action, Action::Mint);
        let outcomes = execute(&before, &pl, &opts(tmp.path())).unwrap();
        let of = |id: RoleId| outcomes.iter().find(|o| o.role == id).unwrap().outcome;
        assert_eq!(of(RoleId::AtRestWrap), MintOutcome::Minted);
        assert_eq!(of(RoleId::Tls), MintOutcome::CannotMint);
        assert!(tmp.path().join(format!("{agent}.x25519.escrow")).exists());
        assert!(
            !tmp.path().join("tls").exists(),
            "nothing minted for tls on a fleet shape"
        );
        crate::encryption::evict_cached_keypair(&agent);
        // Operator material under a fleet shape is never touched (a real
        // leaf, minted elsewhere, stands in for the operator's PKI cert).
        let elsewhere = sandbox();
        crate::tls_bootstrap::ensure_local_tls(elsewhere.path(), "127.0.0.1").unwrap();
        std::fs::create_dir_all(tmp.path().join("tls")).unwrap();
        std::fs::copy(
            elsewhere.path().join("tls/server.pem"),
            tmp.path().join("tls/server.pem"),
        )
        .unwrap();
        let p = observe(tmp.path(), &agent, DeploymentShape::Production, &cfg).unwrap();
        assert_eq!(p.role(RoleId::Tls).state, RoleState::OperatorSupplied);
        let pl = plan(&p, &PlanOptions::default());
        assert_eq!(pl.step(RoleId::Tls).action, Action::OperatorSupplied);
        let snap = snapshot(tmp.path());
        execute(&p, &pl, &PlanOptions::default()).unwrap();
        assert_eq!(snapshot(tmp.path()), snap);
        std::fs::remove_dir_all(tmp.path().join("tls")).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let priv_path = tmp.path().join(format!("{agent}.priv"));
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let p = observe(tmp.path(), &agent, DeploymentShape::Production, &cfg).unwrap();
            assert_eq!(
                p.role(RoleId::Identity).state,
                RoleState::Partial(Partial::Unreadable)
            );
            assert!(p.role(RoleId::Identity).detail.contains("chmod 0600"));
            let loose: Vec<&Path> = p.loose_files().iter().map(|f| f.path.as_path()).collect();
            assert_eq!(loose, vec![priv_path.as_path()]);
            let pl = plan(&p, &PlanOptions::default());
            assert_eq!(pl.step(RoleId::Identity).action, Action::Refuse);
            let err = execute(&p, &pl, &PlanOptions::default()).unwrap_err();
            assert!(format!("{err:#}").contains("chmod 0600"), "{err:#}");
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                observe(tmp.path(), &agent, DeploymentShape::Production, &cfg)
                    .unwrap()
                    .loose_files()
                    .is_empty()
            );
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
            let p = observe(tmp.path(), &agent, DeploymentShape::Production, &cfg).unwrap();
            assert!(p.key_dir_is_loose());
            assert!(loose_text(&p).unwrap().contains("chmod 0700"));
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// A key minted on the seal path BEFORE any recovery key was enrolled
    /// is reported as recoverable-partial with the enrolment remedy, and
    /// its escrow is backfilled once one is (the private bytes untouched).
    #[test]
    fn escrow_backfill_after_late_recovery_enrolment_3717() {
        let tmp = sandbox();
        let agent = agent("late");
        let _env = crate::test_support::env_lock();
        let cfg = config_for(DeploymentShape::Singleton, true);
        crate::encryption::get_or_create_keypair_in(&agent, tmp.path()).unwrap();
        crate::encryption::evict_cached_keypair(&agent);
        let p = singleton(tmp.path(), &agent, &cfg);
        let r = p.role(RoleId::AtRestWrap);
        assert_eq!(r.state, RoleState::Partial(Partial::Recoverable));
        assert!(r.detail.contains("--recovery-key-out"), "{}", r.detail);
        let pl = plan(&p, &PlanOptions::default());
        assert_eq!(pl.step(RoleId::AtRestWrap).action, Action::CannotMint);
        let pl = plan(&p, &opts(tmp.path()));
        assert_eq!(pl.step(RoleId::RecoveryAnchor).action, Action::Mint);
        assert_eq!(pl.step(RoleId::AtRestWrap).action, Action::Repair);
        let priv_path = tmp.path().join(format!("{agent}.x25519.priv"));
        let priv_bytes = std::fs::read(&priv_path).unwrap();
        execute(&p, &pl, &opts(tmp.path())).unwrap();
        assert!(escrow::escrow_present(&agent, tmp.path()));
        assert_eq!(std::fs::read(&priv_path).unwrap(), priv_bytes);
        crate::encryption::evict_cached_keypair(&agent);
        let after = singleton(tmp.path(), &agent, &cfg);
        assert_eq!(after.role(RoleId::AtRestWrap).state, RoleState::Complete);
    }
}
