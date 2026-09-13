// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3714 — the deployment shape: the ONE primary input from which the
//! posture, transit, at-rest and storage requirements of a node are
//! derived.
//!
//! This module is the single definition. `#3700` (posture) and `#3709`
//! (transit) consume [`ShapeDerived`]; nothing consumes the shape through
//! the environment, and no other module re-derives a requirement from a
//! proxy (`AI_MEMORY_SECURITY_PROFILE`, a loopback bind, a peer list, a
//! store URL) that this module already answers.
//!
//! ## Floor vs Default
//!
//! Every derived value carries a marker:
//!
//! - [`Requirement::Floor`] — the shape REQUIRES it. An operator override
//!   below the floor refuses boot (the `security_profile::KNOBS`
//!   contract, generalised). An override ABOVE it (hardening a
//!   `singleton` to `asi-hard`) is always accepted.
//! - [`Requirement::Default`] — the shape SUGGESTS it. Any explicit
//!   operator value wins.
//!
//! `ai-memory config show` renders the table with the marker on every
//! row so an operator can see which values they may override and which
//! will refuse — that distinction is the whole safety property of
//! shape-derived configuration.
//!
//! ## What v1.0.0 enforces from this table (the #3308 freeze-zone slice)
//!
//! - `security_posture` — pinned at boot through the existing
//!   `AI_MEMORY_SECURITY_PROFILE` spelling by [`enforce_at_boot_pre_runtime`]
//!   (unset → pinned; set below a floor → refused).
//! - `at_rest` — [`enforce_at_boot_pre_runtime`] refuses an explicit
//!   `[encryption].at_rest = false` under a shape whose floor requires it
//!   and WARNs while the requirement is pending escrow (see
//!   [`AtRestPolicy::RequiredPendingEscrow`]).
//!
//! Every other row is DECLARED here and enforced by its named consumer
//! (`#3705`/`#3709` for transit, `#3700` for the governance rows). The
//! `init` / `plan` / `apply` verbs, the migrator ladder, provenance on
//! every resolver and the key-set collapse are v1.0.1 (Conductor ruling on
//! #3714, 2026-09-13).
//!
//! ## The 2→3 rule
//!
//! A config with no `[deployment]` block is a `singleton`. An upgrade
//! never silently promotes a running node to a stricter shape it did
//! not ask for — promotion is an operator act (Conductor ruling (b)).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_profile::SecurityPosture;

/// #3700 — the deployment-shape DETECTOR: observed signals held against the
/// declared shape (WARN and record, never re-posture; a hardened declared
/// shape with knobs below the floor refuses naming every knob).
pub mod detector;

/// `[deployment]` block of `config.toml` — the only top-level setting
/// the #3714 programme adds.
///
/// ```toml
/// [deployment]
/// shape = "production"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct DeploymentSection {
    /// The deployment shape. Absent = [`DeploymentShape::Singleton`].
    #[serde(default)]
    pub shape: Option<DeploymentShape>,
}

/// The five deployment shapes (#3714). Ordered from least to most
/// demanding; the order is informational only — every requirement is
/// stated explicitly in [`DeploymentShape::derive`], never inferred
/// from position.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentShape {
    /// One operator, one host, MCP stdio and a loopback daemon, sqlite.
    /// Trust-all reads; no federation; recoverability over
    /// confidentiality.
    #[default]
    Singleton,
    /// Several agents on one host or LAN behind the HTTP daemon; per-agent
    /// identity and api keys; sqlite or postgres.
    Team,
    /// A single-tenant hardened node: the `asi-hard` pin set, custody
    /// keys, at-rest encryption, backup signing, postgres.
    Production,
    /// `production` plus peers: every federation gate at its floor, a
    /// peer attestation map, fingerprints, a trust domain, mTLS binding.
    Federated,
    /// `federated` for N nodes provisioned from ONE artifact: identity is
    /// generated per node at first boot and enrolled through a join
    /// token (#3709); a copied key directory is refused.
    Hive,
}

impl DeploymentShape {
    /// Every shape, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Singleton,
        Self::Team,
        Self::Production,
        Self::Federated,
        Self::Hive,
    ];

    /// The canonical config token (`[deployment] shape = "<token>"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Singleton => "singleton",
            Self::Team => "team",
            Self::Production => "production",
            Self::Federated => "federated",
            Self::Hive => "hive",
        }
    }

    /// Parse a shape token (trimmed, case-insensitive). Unknown tokens are
    /// an error so a typo in the primary input fails LOUDLY rather than
    /// silently booting `singleton`.
    ///
    /// # Errors
    /// Returns an error naming the accepted tokens for anything else.
    pub fn parse(token: &str) -> anyhow::Result<Self> {
        let t = token.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|s| s.as_str() == t)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unrecognised [deployment] shape {token:?} (expected one of {})",
                    Self::ALL
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// Whether this shape carries the hardened (`asi-hard`) posture floor.
    #[must_use]
    pub fn is_hardened(self) -> bool {
        matches!(self, Self::Production | Self::Federated | Self::Hive)
    }

    /// Derive every shape-dependent requirement. This is the ONE table;
    /// there is no second derivation anywhere in the crate.
    #[must_use]
    pub fn derive(self) -> ShapeDerived {
        use Requirement::{Default as D, Floor as F};
        let hardened = self.is_hardened();
        let posture = if hardened {
            F(SecurityPosture::AsiHard)
        } else {
            D(SecurityPosture::Standard)
        };
        ShapeDerived {
            shape: self,
            security_posture: posture,
            // #3705 scope ruling (2026-09-13): every hop encrypted, no
            // loopback exemption, in EVERY shape including a singleton's
            // 127.0.0.1 listener. Enforced by the transit gate (#3705/#3709).
            tls_required: F(true),
            plaintext_peers_allowed: F(false),
            api_key_required: if self == Self::Singleton {
                D(false)
            } else {
                F(true)
            },
            http_identity: match self {
                Self::Singleton => D(super::HttpIdentityMode::Advisory),
                Self::Team => D(super::HttpIdentityMode::Enforce),
                _ => F(super::HttpIdentityMode::Enforce),
            },
            permissions_mode: if hardened {
                F(super::PermissionsMode::Enforce)
            } else {
                D(super::PermissionsMode::Enforce)
            },
            governed_namespace_required: match self {
                Self::Singleton | Self::Team => D(false),
                Self::Production => D(true),
                Self::Federated | Self::Hive => F(true),
            },
            at_rest: if hardened {
                F(AtRestPolicy::RequiredPendingEscrow)
            } else {
                D(AtRestPolicy::Off)
            },
            // Declared as a Default at v1.0.0: the turnkey pg+AGE+pgvector
            // provisioning (`init`, v1.0.1) is what makes a postgres FLOOR
            // honest. A floor with no provisioning path is hostile.
            storage_backend: if hardened {
                D(StorageBackend::Postgres)
            } else {
                D(StorageBackend::Sqlite)
            },
        }
    }
}

impl DeploymentShape {
    /// The config-file spelling of this shape, `[deployment] shape = "<token>"`
    /// — the ONE rendering every message and table header uses.
    #[must_use]
    pub fn config_line(self) -> String {
        format!("[deployment] shape = \"{self}\"")
    }
}

impl fmt::Display for DeploymentShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A shape-derived value with its marker. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement<T> {
    /// The shape requires this value; an override below it refuses boot.
    Floor(T),
    /// The shape suggests this value; an explicit operator value wins.
    Default(T),
}

impl<T: Copy> Requirement<T> {
    /// The derived value, marker stripped.
    #[must_use]
    pub fn value(self) -> T {
        match self {
            Self::Floor(v) | Self::Default(v) => v,
        }
    }

    /// Whether this is a floor.
    #[must_use]
    pub fn is_floor(self) -> bool {
        matches!(self, Self::Floor(_))
    }

    /// The marker as rendered by `config show`.
    #[must_use]
    pub fn marker(self) -> &'static str {
        match self {
            Self::Floor(_) => "FLOOR",
            Self::Default(_) => "default",
        }
    }
}

/// At-rest content-encryption policy derived from the shape.
///
/// The per-row envelope (`[encryption].at_rest`, `AI_MEMORY_ENCRYPT_AT_REST`)
/// is the mechanism the shape derives; SQLCipher is never derived because
/// it has no rekey path (`PRAGMA rekey` appears nowhere in `src/`) and so
/// cannot meet the recoverability bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtRestPolicy {
    /// Not required. The operator may still enable it explicitly.
    Off,
    /// The shape REQUIRES at-rest encryption, and the requirement is
    /// engaged the moment a recovery escrow for the at-rest key is
    /// provisioned (#3717). Until then the node boots with the gap
    /// DECLARED (boot WARN, `doctor` posture, #3557), because the
    /// standing rule is recoverability > confidentiality: a lost key must
    /// never mean lost memory, and today a lost per-agent X25519 key loses
    /// `content` with no escrow to recover it from.
    ///
    /// An explicit `[encryption].at_rest = false` under this policy is an
    /// override below the floor and refuses boot.
    RequiredPendingEscrow,
    /// Required and engaged (escrow provisioned). Not reachable at v1.0.0;
    /// declared so the v1.0.1 keys work has its target state named.
    Required,
}

impl AtRestPolicy {
    /// Config-facing token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::RequiredPendingEscrow => "required (pending recovery escrow, #3717)",
            Self::Required => "required",
        }
    }
}

/// Storage backend the shape derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    /// The local sqlite file.
    Sqlite,
    /// `postgres://` with AGE + pgvector.
    Postgres,
}

impl StorageBackend {
    /// Config-facing token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Everything a shape derives. Consumers read fields; nothing here is
/// read from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapeDerived {
    /// The shape this table was derived from.
    pub shape: DeploymentShape,
    /// The `asi-hard` / `standard` posture (the 28-knob pin set).
    /// Enforced at boot by [`enforce_at_boot_pre_runtime`] through the
    /// `AI_MEMORY_SECURITY_PROFILE` spelling so every existing
    /// `is_asi_hard()` read site honours it without change.
    pub security_posture: Requirement<SecurityPosture>,
    /// TLS on every listener, every bind (#3705). Enforced by the transit
    /// gate (#3705/#3709).
    pub tls_required: Requirement<bool>,
    /// Whether an `http://` federation peer may ever be accepted (#3705:
    /// never). Enforced by `tls::validate_peer_url_scheme` (#3705).
    pub plaintext_peers_allowed: Requirement<bool>,
    /// Whether the HTTP daemon refuses a keyless bind on every host
    /// (`AI_MEMORY_REQUIRE_API_KEY`). Enforced by `daemon_runtime` (#3709).
    pub api_key_required: Requirement<bool>,
    /// `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY` posture. Consumed by #3700.
    pub http_identity: Requirement<super::HttpIdentityMode>,
    /// `[permissions].mode`. Consumed by #3700.
    pub permissions_mode: Requirement<super::PermissionsMode>,
    /// `AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE`. Consumed by #3700.
    pub governed_namespace_required: Requirement<bool>,
    /// At-rest content-encryption policy. Enforced at boot by
    /// [`enforce_at_boot_pre_runtime`].
    pub at_rest: Requirement<AtRestPolicy>,
    /// Storage backend. Declared only at v1.0.0 (see [`DeploymentShape::derive`]).
    pub storage_backend: Requirement<StorageBackend>,
}

/// The `enforced by` cell shared by the three governance rows.
const ENFORCED_BY_GOVERNANCE: &str = "governance posture (#3700)";

impl ShapeDerived {
    /// The rows of the derivation table as `(setting, marker, value,
    /// enforced-by)` — the shape of `ai-memory config show` and of the
    /// `doctor` posture readout. One rendering site, so the two cannot
    /// disagree.
    #[must_use]
    pub fn rows(&self) -> Vec<[String; 4]> {
        fn row<T: Copy>(
            name: &str,
            r: Requirement<T>,
            render: impl Fn(T) -> String,
            enforced_by: &str,
        ) -> [String; 4] {
            [
                name.to_string(),
                r.marker().to_string(),
                render(r.value()),
                enforced_by.to_string(),
            ]
        }
        vec![
            row(
                "security_posture",
                self.security_posture,
                |v| v.as_str().to_string(),
                "boot (this module, via AI_MEMORY_SECURITY_PROFILE)",
            ),
            row(
                "tls_required",
                self.tls_required,
                |v| v.to_string(),
                "transit gate (#3705/#3709)",
            ),
            row(
                "plaintext_peers_allowed",
                self.plaintext_peers_allowed,
                |v| v.to_string(),
                "transit gate (#3705)",
            ),
            row(
                "api_key_required",
                self.api_key_required,
                |v| v.to_string(),
                "daemon bind guard (#3709)",
            ),
            row(
                "http_identity",
                self.http_identity,
                |v| format!("{v:?}").to_ascii_lowercase(),
                ENFORCED_BY_GOVERNANCE,
            ),
            row(
                "permissions_mode",
                self.permissions_mode,
                |v| format!("{v:?}").to_ascii_lowercase(),
                ENFORCED_BY_GOVERNANCE,
            ),
            row(
                "governed_namespace_required",
                self.governed_namespace_required,
                |v| v.to_string(),
                ENFORCED_BY_GOVERNANCE,
            ),
            row(
                "at_rest",
                self.at_rest,
                |v| v.as_str().to_string(),
                "boot (this module)",
            ),
            row(
                "storage_backend",
                self.storage_backend,
                |v| v.as_str().to_string(),
                "declared only (turnkey provisioning is v1.0.1)",
            ),
        ]
    }

    /// Render the derivation table as fixed-width text for `config show`.
    #[must_use]
    pub fn render_table(&self) -> String {
        let rows = self.rows();
        let w: [usize; 4] = std::array::from_fn(|i| {
            rows.iter()
                .map(|r| r[i].len())
                .max()
                .unwrap_or(0)
                .max(["setting", "marker", "value", "enforced by"][i].len())
        });
        let mut out = format!(
            "{}\n{:<w0$}  {:<w1$}  {:<w2$}  {}\n",
            self.shape.config_line(),
            "setting",
            "marker",
            "value",
            "enforced by",
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
        );
        for r in &rows {
            out.push_str(&format!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {}\n",
                r[0],
                r[1],
                r[2],
                r[3],
                w0 = w[0],
                w1 = w[1],
                w2 = w[2],
            ));
        }
        out.push_str(
            "FLOOR = the shape requires it; an override below it refuses boot. \
             default = the shape suggests it; an explicit value wins.\n",
        );
        out
    }
}

/// What the boot-time enforcement decided, for the boot banner and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeBootReport {
    /// The resolved shape.
    pub shape: DeploymentShape,
    /// `AI_MEMORY_SECURITY_PROFILE` was unset and has been pinned to the
    /// shape's posture floor.
    pub posture_pinned: bool,
    /// At-rest is required by the shape but no recovery escrow exists
    /// yet, so the gap is declared rather than closed.
    pub at_rest_pending_escrow: bool,
    /// The operator explicitly enabled at-rest with no escrow provisioned.
    pub at_rest_on_without_escrow: bool,
}

/// Whether a recovery escrow for the at-rest key is provisioned. There
/// is none at v1.0.0 — the escrow is the #3717 deliverable (v1.0.1) —
/// so this is `false` for every node, and it is a function rather than a
/// constant so the ONE call site that decides "pending" versus "engaged"
/// is already in place for it.
#[must_use]
pub fn at_rest_escrow_provisioned() -> bool {
    false
}

/// Evaluate the shape's boot-time floors against the loaded config and
/// the environment. Pure: reads `env` through the supplied accessor and
/// returns the pin to apply (if any) instead of applying it, so the
/// decision is testable without touching the process environment.
///
/// # Errors
/// - `AI_MEMORY_SECURITY_PROFILE` is set to a posture below the shape's
///   floor (`standard` under `production` / `federated` / `hive`).
/// - `[encryption].at_rest = false` is set under a shape whose at-rest
///   policy is a floor.
pub fn evaluate_boot(
    cfg: &super::AppConfig,
    security_profile_env: Option<&str>,
) -> anyhow::Result<(ShapeBootReport, Option<&'static str>)> {
    let shape = cfg.effective_shape();
    let line = shape.config_line();
    let derived = shape.derive();
    let mut pin: Option<&'static str> = None;
    let mut posture_pinned = false;

    match (derived.security_posture, security_profile_env) {
        (Requirement::Floor(floor), Some(raw)) => {
            let set = SecurityPosture::parse(raw)?;
            if set != floor {
                anyhow::bail!(
                    "{line} requires security posture \
                     \"{floor}\" (a FLOOR), but {env} is set to {raw:?}. Remove the \
                     override (the shape pins it) or choose a shape whose posture \
                     is a default (`singleton`, `team`). Promotion and demotion are \
                     both operator acts: nothing here changes the shape for you.",
                    env = crate::security_profile::ENV_SECURITY_PROFILE,
                );
            }
        }
        (Requirement::Floor(floor), None) => {
            pin = Some(floor.as_str());
            posture_pinned = true;
        }
        (Requirement::Default(_), _) => {}
    }

    let explicit_at_rest = cfg.encryption.as_ref().and_then(|e| e.at_rest);
    let mut at_rest_pending_escrow = false;
    let mut at_rest_on_without_escrow = false;
    match derived.at_rest {
        Requirement::Floor(AtRestPolicy::RequiredPendingEscrow | AtRestPolicy::Required) => {
            match explicit_at_rest {
                Some(false) => anyhow::bail!(
                    "{line} requires at-rest encryption (a \
                     FLOOR), but [encryption].at_rest = false is set. Remove the \
                     override or choose `singleton` / `team`, where at-rest is a default."
                ),
                Some(true) => {
                    at_rest_on_without_escrow = !at_rest_escrow_provisioned();
                }
                None => {
                    at_rest_pending_escrow = !at_rest_escrow_provisioned();
                }
            }
        }
        Requirement::Floor(AtRestPolicy::Off) | Requirement::Default(_) => {}
    }

    Ok((
        ShapeBootReport {
            shape,
            posture_pinned,
            at_rest_pending_escrow,
            at_rest_on_without_escrow,
        },
        pin,
    ))
}

/// The declared-gap WARN text for a shape whose at-rest floor is pending
/// escrow. One site, shared by boot and `doctor`.
#[must_use]
pub fn at_rest_pending_escrow_warning(shape: DeploymentShape) -> String {
    let line = shape.config_line();
    format!(
        "ai-memory: WARN {line} requires at-rest \
         encryption, but no recovery escrow for the at-rest key exists in this \
         release, so it is NOT enabled: a lost key must never mean lost memory \
         (recoverability > confidentiality — the gap is declared in #3557, the \
         escrow is #3717). Set [encryption].at_rest = true to enable it anyway, \
         accepting that a lost `<key-dir>/<agent>.x25519.priv` loses `content`."
    )
}

/// Pre-runtime shape enforcement (#3714). MUST run in the synchronous,
/// single-threaded phase of `fn main()` BEFORE
/// `security_profile::enforce_at_boot_pre_runtime`, because the posture
/// pin it applies is a `std::env::set_var` (the same #1889 / #2386
/// contract as the `KNOBS` pins) and because the posture enforcement
/// must observe the pinned value.
///
/// # Errors
/// Propagates every [`evaluate_boot`] refusal.
pub fn enforce_at_boot_pre_runtime(cfg: &super::AppConfig) -> anyhow::Result<ShapeBootReport> {
    let env = std::env::var(crate::security_profile::ENV_SECURITY_PROFILE).ok();
    let (report, pin) = evaluate_boot(cfg, env.as_deref())?;
    if let Some(value) = pin {
        // SAFETY: called ONLY from the synchronous single-threaded
        // pre-runtime phase of `fn main()` — before the tracing appender
        // worker or any tokio runtime worker exists — so no other thread
        // can be reading the environment concurrently (#1889 / #2386).
        unsafe {
            std::env::set_var(crate::security_profile::ENV_SECURITY_PROFILE, value);
        }
    }
    if report.at_rest_pending_escrow {
        eprintln!("{}", at_rest_pending_escrow_warning(report.shape));
    }
    if report.at_rest_on_without_escrow {
        eprintln!(
            "ai-memory: WARN [encryption].at_rest = true under [deployment] shape = \
             \"{}\" with no recovery escrow: a lost `<key-dir>/<agent>.x25519.priv` \
             loses `content` (#3717).",
            report.shape
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, EncryptionSection};

    fn cfg_with(shape: Option<DeploymentShape>, at_rest: Option<bool>) -> AppConfig {
        AppConfig {
            deployment: shape.map(|s| DeploymentSection { shape: Some(s) }),
            encryption: at_rest.map(|v| EncryptionSection { at_rest: Some(v) }),
            ..AppConfig::default()
        }
    }

    #[test]
    fn absent_deployment_block_is_singleton_never_a_promotion() {
        assert_eq!(
            AppConfig::default().effective_shape(),
            DeploymentShape::Singleton
        );
        let cfg = cfg_with(None, None);
        let (report, pin) = evaluate_boot(&cfg, None).unwrap();
        assert_eq!(report.shape, DeploymentShape::Singleton);
        assert!(pin.is_none(), "singleton must not pin a posture");
        assert!(!report.at_rest_pending_escrow);
    }

    #[test]
    fn every_token_round_trips_and_typos_fail_loud() {
        for s in DeploymentShape::ALL {
            assert_eq!(DeploymentShape::parse(s.as_str()).unwrap(), s);
            assert_eq!(
                DeploymentShape::parse(&s.as_str().to_ascii_uppercase()).unwrap(),
                s
            );
            let toml_src = format!("[deployment]\nshape = \"{s}\"\n");
            let cfg: AppConfig = toml::from_str(&toml_src).unwrap();
            assert_eq!(cfg.effective_shape(), s);
        }
        let err = DeploymentShape::parse("prod").unwrap_err().to_string();
        assert!(err.contains("production"), "{err}");
        assert!(toml::from_str::<AppConfig>("[deployment]\nshape = \"prod\"\n").is_err());
    }

    #[test]
    fn hardened_shapes_carry_floors_and_the_others_carry_defaults() {
        for s in DeploymentShape::ALL {
            let d = s.derive();
            assert_eq!(d.shape, s);
            assert_eq!(d.security_posture.is_floor(), s.is_hardened(), "{s}");
            assert_eq!(
                d.security_posture.value(),
                if s.is_hardened() {
                    SecurityPosture::AsiHard
                } else {
                    SecurityPosture::Standard
                },
                "{s}"
            );
            // #3705: TLS is a floor in EVERY shape, loopback included.
            assert_eq!(d.tls_required, Requirement::Floor(true), "{s}");
            assert_eq!(d.plaintext_peers_allowed, Requirement::Floor(false), "{s}");
            assert_eq!(d.at_rest.is_floor(), s.is_hardened(), "{s}");
            // Storage is DECLARED, never a floor, until provisioning exists.
            assert!(!d.storage_backend.is_floor(), "{s}");
        }
        assert_eq!(
            DeploymentShape::Singleton.derive().api_key_required,
            Requirement::Default(false)
        );
        assert_eq!(
            DeploymentShape::Team.derive().api_key_required,
            Requirement::Floor(true)
        );
    }

    #[test]
    fn production_pins_asi_hard_when_unset_and_refuses_standard() {
        let cfg = cfg_with(Some(DeploymentShape::Production), None);
        let (report, pin) = evaluate_boot(&cfg, None).unwrap();
        assert_eq!(pin, Some("asi-hard"));
        assert!(report.posture_pinned);
        assert!(
            report.at_rest_pending_escrow,
            "at-rest floor pending escrow is declared"
        );

        let (report, pin) = evaluate_boot(&cfg, Some("asi-hard")).unwrap();
        assert_eq!(pin, None);
        assert!(!report.posture_pinned);

        let err = evaluate_boot(&cfg, Some("standard"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("FLOOR"), "{err}");
        assert!(err.contains("production"), "{err}");

        // A garbage posture token still fails loud through the shape path.
        assert!(evaluate_boot(&cfg, Some("medium")).is_err());
    }

    #[test]
    fn singleton_accepts_hardening_above_its_default() {
        let cfg = cfg_with(Some(DeploymentShape::Singleton), None);
        let (report, pin) = evaluate_boot(&cfg, Some("asi-hard")).unwrap();
        assert_eq!(pin, None);
        assert!(!report.posture_pinned);
    }

    #[test]
    fn at_rest_floor_refuses_explicit_off_and_warns_on_explicit_on() {
        let off = cfg_with(Some(DeploymentShape::Federated), Some(false));
        let err = evaluate_boot(&off, Some("asi-hard"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("at_rest = false"), "{err}");

        let on = cfg_with(Some(DeploymentShape::Hive), Some(true));
        let (report, _) = evaluate_boot(&on, Some("asi-hard")).unwrap();
        assert!(report.at_rest_on_without_escrow);
        assert!(!report.at_rest_pending_escrow);

        // Below the hardened tier an explicit `false` is an ordinary default.
        let team_off = cfg_with(Some(DeploymentShape::Team), Some(false));
        let (report, _) = evaluate_boot(&team_off, None).unwrap();
        assert!(!report.at_rest_pending_escrow && !report.at_rest_on_without_escrow);
    }

    #[test]
    fn escrow_is_not_provisioned_at_v1_0_0() {
        assert!(!at_rest_escrow_provisioned());
    }

    #[test]
    fn render_table_marks_every_row_and_names_the_shape() {
        for s in DeploymentShape::ALL {
            let text = s.derive().render_table();
            assert!(text.starts_with(&s.config_line()), "{text}");
            for r in s.derive().rows() {
                assert!(text.contains(&r[0]), "{text} lacks {}", r[0]);
                assert!(r[1] == "FLOOR" || r[1] == "default");
            }
            assert!(text.contains("FLOOR = the shape requires it"));
        }
    }
}
