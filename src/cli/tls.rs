// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3709 item 2 — the `ai-memory tls` verb family: `init`, `import`,
//! `status`.
//!
//! Operator directive (2026-09-13): *"make the data encryption in transit
//! configuration and setup end user and admin easy."* Item 1 made the
//! encrypted path free on first boot; this module makes it OPERABLE without
//! reading source: mint the local material on purpose (`init`), install an
//! enterprise pair with every check the listener will make (`import`), and
//! read what is installed and what the next boot will do with it (`status`).
//!
//! Every verb reads and writes ONLY `<key_dir>/tls/` through
//! [`crate::tls_bootstrap`] — the same functions the daemon's listener
//! resolution uses — so the verdict `status` prints is the verdict `serve`
//! reaches. There is no second resolver and no second parser.
//!
//! The declared deployment shape rule (#3709 3x7 ruling) is honoured here
//! exactly as at boot: `init` mints the local CA for the SINGLETON shape only;
//! every other shape is told to `import` enterprise PKI. `import` is accepted
//! on every shape.
//!
//! Not in this cut (v1.0.0 GA scope ruling, Conductor 2026-09-16): `tls acme`,
//! `tls renew` for imported material (re-run `import`), `db check-tls`.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};

use crate::config::AppConfig;
use crate::config::shape::DeploymentShape;
use crate::tls_bootstrap::{self, LeafStatus, Outcome};
use crate::transit_encryption::{ISSUE_TAG, REMEDY_ENTERPRISE_PKI};

/// The bind host `init` covers when none is given: the loopback set plus
/// the machine hostname (see [`tls_bootstrap::leaf_subject_alt_names`]).
const DEFAULT_INIT_HOST: &str = "127.0.0.1";

#[derive(Args)]
pub struct TlsArgs {
    /// Key directory holding `tls/` (defaults to AI_MEMORY_KEY_DIR / the
    /// platform key directory; the same resolution the daemon uses).
    #[arg(long, global = true)]
    pub key_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub action: TlsAction,
}

#[derive(Subcommand)]
pub enum TlsAction {
    /// Mint the local CA and server certificate now (singleton shape only;
    /// idempotent — existing valid material is reused, never overwritten).
    Init {
        /// Bind host the certificate must cover (an IP literal or DNS name).
        #[arg(long)]
        host: Option<String>,
    },
    /// Verify an operator certificate + key pair the way the listener will,
    /// then install it under <key_dir>/tls/ (any shape). Nothing is written
    /// unless every check passes.
    Import {
        /// PEM certificate (a fullchain file is accepted; leaf first).
        #[arg(long, value_name = "FULLCHAIN.PEM")]
        cert: PathBuf,
        /// PEM private key (PKCS#8, RSA or SEC1).
        #[arg(long, value_name = "KEY.PEM")]
        key: PathBuf,
        /// PEM CA bundle the bundled clients (doctor --remote, the MCP forward)
        /// should trust; must be the certificate's issuer.
        #[arg(long, value_name = "CA.PEM")]
        ca: Option<PathBuf>,
        /// Bind host the certificate must cover; refused when no subject
        /// alternative name matches.
        #[arg(long)]
        host: Option<String>,
    },
    /// Report the installed material and what the next boot will do with it
    /// under the declared deployment shape.
    Status,
}

/// What `tls status` decided about the next boot, under the declared shape
/// — a rendering of the ONE listener verdict (F2, rule (s)).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct StatusVerdict {
    /// `absent`, `local-ca` or `operator-supplied`.
    pub source: &'static str,
    /// The declared shape the verdict was computed for.
    pub shape: String,
    /// `true` when `serve` (without --tls-cert/--tls-key) would refuse.
    pub boot_would_refuse: bool,
    /// The one-line verdict, with the fix when refusing.
    pub verdict: String,
    /// The typed verdict the daemon decides by.
    pub decision: tls_bootstrap::ListenerVerdict,
}

/// `tls status`'s view of [`tls_bootstrap::listener_verdict`] — the SAME
/// predicate [`crate::daemon_runtime::resolve_tls_material`] refuses or
/// serves by and `doctor` renders; this function only wraps it.
#[must_use]
pub fn status_verdict(status: &LeafStatus, shape: DeploymentShape) -> StatusVerdict {
    let decision = tls_bootstrap::listener_verdict(status, shape);
    StatusVerdict {
        source: decision.source(),
        shape: shape.to_string(),
        boot_would_refuse: decision.refuses(),
        verdict: decision.render(shape),
        decision,
    }
}

fn resolve_key_dir(args: &TlsArgs) -> Result<PathBuf> {
    match &args.key_dir {
        Some(dir) => Ok(dir.clone()),
        None => crate::identity::keypair::default_key_dir(),
    }
}

fn read_pem(path: &Path, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("{ISSUE_TAG}: reading {what} {}", path.display()))
}

/// `ai-memory tls …` dispatch entry.
///
/// # Errors
/// - The key directory cannot be resolved or fails its posture check.
/// - `init` on a non-singleton shape, or over operator-supplied material.
/// - `import` fails any listener check (nothing is written).
/// - The installed leaf cannot be parsed (`status` reports a corrupt
///   artefact, never "absent").
pub fn run(
    args: TlsArgs,
    json: bool,
    app_config: &AppConfig,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    let key_dir = resolve_key_dir(&args)?;
    let shape = app_config.effective_shape();
    match args.action {
        TlsAction::Init { host } => run_init(&key_dir, host.as_deref(), shape, json, out),
        TlsAction::Import {
            cert,
            key,
            ca,
            host,
        } => run_import(
            &key_dir,
            &cert,
            &key,
            ca.as_deref(),
            host.as_deref(),
            json,
            out,
        ),
        TlsAction::Status => run_status(&key_dir, shape, json, out),
    }
}

fn run_init(
    key_dir: &Path,
    host: Option<&str>,
    shape: DeploymentShape,
    json: bool,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    if tls_bootstrap::operator_material_present(key_dir)? {
        bail!(
            "{ISSUE_TAG}: operator-supplied material is installed under {} — `tls init` mints \
             nothing over it (it IS the certificate); `ai-memory tls status` shows it, and \
             `ai-memory tls import` replaces it",
            key_dir.join(tls_bootstrap::TLS_SUBDIR).display()
        );
    }
    if shape != DeploymentShape::Singleton {
        bail!(
            "{ISSUE_TAG}: this deployment declares `{}` (a FLEET-shaped estate); the zero-config \
             local CA is minted for a SINGLETON install only — a locally minted CA would be an \
             audit finding. Fix: {REMEDY_ENTERPRISE_PKI}",
            shape.config_line()
        );
    }
    let host = host.unwrap_or(DEFAULT_INIT_HOST);
    let local = tls_bootstrap::ensure_local_tls(key_dir, host)?;
    let outcome = match &local.outcome {
        Outcome::Generated => "generated".to_string(),
        Outcome::Renewed { reason } => format!("renewed ({reason})"),
        Outcome::Reused => "reused".to_string(),
        // Excluded above; a race with a concurrent import is still reported
        // truthfully rather than as a mint.
        Outcome::OperatorSupplied => tls_bootstrap::SOURCE_OPERATOR_SUPPLIED.to_string(),
    };
    let status = tls_bootstrap::leaf_status(key_dir)?;
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "outcome": outcome,
                "cert_path": local.cert_path,
                "key_path": local.key_path,
                "ca_cert_path": local.ca_cert_path,
                "days_remaining": local.leaf_days_remaining,
                "subject_alt_names": status.subject_alt_names,
                "not_after": status.not_after,
            })
        )?;
    } else {
        writeln!(out.stdout, "tls init: {outcome}")?;
        writeln!(out.stdout, "  certificate: {}", local.cert_path.display())?;
        writeln!(out.stdout, "  key:         {}", local.key_path.display())?;
        writeln!(
            out.stdout,
            "  local CA:    {}",
            local.ca_cert_path.display()
        )?;
        writeln!(
            out.stdout,
            "  expires:     {} ({} day(s))",
            status.not_after.as_deref().unwrap_or("?"),
            local.leaf_days_remaining
        )?;
        writeln!(
            out.stdout,
            "  covers:      {}",
            tls_bootstrap::render_sans(&status.subject_alt_names)
        )?;
    }
    Ok(())
}

fn run_import(
    key_dir: &Path,
    cert: &Path,
    key: &Path,
    ca: Option<&Path>,
    host: Option<&str>,
    json: bool,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    let cert_pem = read_pem(cert, "--cert")?;
    let key_pem = read_pem(key, "--key")?;
    let ca_pem = match ca {
        Some(p) => Some(read_pem(p, "--ca")?),
        None => None,
    };
    let report = tls_bootstrap::import_operator_material(
        key_dir,
        &cert_pem,
        &key_pem,
        ca_pem.as_deref(),
        host,
    )?;
    if json {
        writeln!(out.stdout, "{}", serde_json::to_string(&report)?)?;
    } else {
        writeln!(out.stdout, "tls import: installed")?;
        writeln!(out.stdout, "  certificate: {}", report.cert_path.display())?;
        writeln!(out.stdout, "  key:         {}", report.key_path.display())?;
        match &report.ca_cert_path {
            Some(p) => writeln!(out.stdout, "  CA bundle:   {}", p.display())?,
            None => writeln!(
                out.stdout,
                "  CA bundle:   not installed (pass --ca <ca.pem> so doctor --remote and the \
                 MCP forward trust this issuer)"
            )?,
        }
        writeln!(
            out.stdout,
            "  issuer:      {:?}  subject: {:?}  chain: {} certificate(s)",
            report.issuer, report.subject, report.chain_len
        )?;
        writeln!(
            out.stdout,
            "  expires:     {} ({} day(s))",
            report.not_after, report.days_remaining
        )?;
        writeln!(
            out.stdout,
            "  covers:      {}{}",
            tls_bootstrap::render_sans(&report.subject_alt_names),
            match &report.host_checked {
                Some(h) => format!(" (verified for --host {h})"),
                None => " (no --host given; coverage of the bind host not checked)".to_string(),
            }
        )?;
    }
    Ok(())
}

fn run_status(
    key_dir: &Path,
    shape: DeploymentShape,
    json: bool,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    let status = tls_bootstrap::leaf_status(key_dir)?;
    let verdict = status_verdict(&status, shape);
    let tls_dir = key_dir.join(tls_bootstrap::TLS_SUBDIR);
    let operator_ca = tls_dir.join(tls_bootstrap::OPERATOR_CA_CERT_FILE);
    let local_ca = tls_dir.join(tls_bootstrap::LOCAL_CA_CERT_FILE);
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "tls_dir": tls_dir,
                "present": status.present,
                "source": verdict.source,
                "issuer": status.issuer,
                "subject_alt_names": status.subject_alt_names,
                "not_after": status.not_after,
                "days_remaining": status.days_remaining,
                "within_renewal_window": status.within_renewal_window,
                "operator_ca_installed": operator_ca.exists(),
                "local_ca_present": local_ca.exists(),
                "shape": verdict.shape,
                "boot_would_refuse": verdict.boot_would_refuse,
                "verdict": verdict.verdict,
            })
        )?;
        return Ok(());
    }
    writeln!(out.stdout, "tls status: {}", tls_dir.display())?;
    writeln!(out.stdout, "  source:      {}", verdict.source)?;
    if status.present {
        writeln!(out.stdout, "  issuer:      {:?}", status.issuer)?;
        writeln!(
            out.stdout,
            "  expires:     {} ({} day(s){})",
            status.not_after.as_deref().unwrap_or("?"),
            status.days_remaining.unwrap_or_default(),
            if status.within_renewal_window {
                ", inside the renewal window"
            } else {
                ""
            }
        )?;
        writeln!(
            out.stdout,
            "  covers:      {}",
            tls_bootstrap::render_sans(&status.subject_alt_names)
        )?;
    }
    writeln!(
        out.stdout,
        "  client root: {}",
        if operator_ca.exists() {
            format!("operator CA {}", operator_ca.display())
        } else if local_ca.exists() {
            format!("local CA {}", local_ca.display())
        } else {
            "none installed".to_string()
        }
    )?;
    writeln!(out.stdout, "  shape:       {}", verdict.shape)?;
    writeln!(
        out.stdout,
        "  next boot:   {}{}",
        if verdict.boot_would_refuse {
            "REFUSES — "
        } else {
            ""
        },
        verdict.verdict
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;
    use crate::config::shape::DeploymentSection;

    fn key_dir(env: &TestEnv) -> PathBuf {
        let dir = env
            .db_path
            .parent()
            .expect("db path has a parent")
            .join("tls-keys");
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn config_for(shape: DeploymentShape) -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.deployment = Some(DeploymentSection { shape: Some(shape) });
        cfg
    }

    fn status_of(present: bool, operator: bool, days: i64) -> LeafStatus {
        LeafStatus {
            present,
            // #3709 F7 — this matrix models complete pairs (cert ⟺ key); the
            // broken-pair refusals have their own dedicated cells.
            key_present: present,
            days_remaining: present.then_some(days),
            subject_alt_names: vec!["localhost".into()],
            within_renewal_window: present && days <= tls_bootstrap::RENEWAL_WINDOW_DAYS,
            issuer: if operator {
                "Example Corp".into()
            } else {
                "ai-memory local CA".into()
            },
            operator_supplied: operator,
            not_after: present.then(|| "2030-01-01T00:00:00Z".to_string()),
        }
    }

    /// The verdict matrix: every cell that REFUSES names its fix, every cell
    /// that serves says "encrypted as required", and the two populations
    /// never overlap on one sink.
    #[test]
    fn issue_3709_status_verdict_matrix_names_the_shape_and_the_fix() {
        use DeploymentShape::{Singleton, Team};
        // (status, shape, refuses, needle, the fix a refusing cell must name)
        let cells: [(LeafStatus, DeploymentShape, bool, &str, &str); 10] = [
            (
                status_of(false, false, 0),
                Singleton,
                false,
                "mints a local CA",
                "",
            ),
            (
                status_of(false, false, 0),
                Team,
                true,
                "no operator certificate is installed",
                "ai-memory tls import",
            ),
            (
                status_of(true, false, 60),
                Singleton,
                false,
                "encrypted as required for shape singleton; 60 day(s) to expiry",
                "",
            ),
            (
                status_of(true, false, 60),
                Team,
                true,
                "minted by the local CA",
                "ai-memory tls import",
            ),
            // F2 (#3709 review): {fleet, local, EXPIRED} — the fleet rule
            // decides, so the fix is enterprise PKI, never "renew locally"
            // (which would not make the next boot succeed).
            (
                status_of(true, false, -3),
                Team,
                true,
                "minted by the local CA",
                "ai-memory tls import",
            ),
            // {singleton, local, expired}: the daemon re-issues from the local
            // CA — a renewal, not a refusal.
            (
                status_of(true, false, -3),
                Singleton,
                false,
                "re-issued from the local CA",
                "",
            ),
            (
                status_of(true, true, 60),
                Team,
                false,
                "encrypted as required for shape team; operator-supplied",
                "",
            ),
            (
                status_of(true, true, -2),
                Team,
                true,
                "operator-supplied certificate EXPIRED 2 day(s) ago",
                "ai-memory tls import",
            ),
            (
                status_of(true, true, -2),
                Singleton,
                true,
                "operator-supplied certificate EXPIRED 2 day(s) ago",
                "ai-memory tls import",
            ),
            (
                status_of(true, true, 5),
                Team,
                false,
                "operator-supplied certificate, 5 day(s) to expiry",
                "",
            ),
        ];
        for (status, shape, refuses, needle, fix) in &cells {
            let v = status_verdict(status, *shape);
            assert_eq!(v.boot_would_refuse, *refuses, "{v:?}");
            assert!(v.verdict.contains(needle), "{needle:?} not in {v:?}");
            assert_eq!(v.shape, shape.to_string());
            assert_eq!(v.decision.refuses(), *refuses);
            if *refuses {
                assert!(v.verdict.contains("REFUSES"), "{v:?}");
                assert!(
                    v.verdict.contains(fix),
                    "a refusing verdict names its fix: {v:?}"
                );
                assert!(!v.verdict.contains("encrypted as required"), "{v:?}");
            } else {
                assert!(!v.verdict.contains("REFUSES"), "{v:?}");
            }
        }
        assert_eq!(
            status_verdict(&status_of(true, true, 60), Team).source,
            "operator-supplied"
        );
        assert_eq!(
            status_verdict(&status_of(true, false, 60), Singleton).source,
            "local-ca"
        );
        assert_eq!(
            status_verdict(&status_of(false, false, 0), Singleton).source,
            "absent"
        );
        // The CLI verdict IS the daemon's predicate: byte-identical decision
        // for every cell (rule (s)).
        for (status, shape, ..) in &cells {
            assert_eq!(
                status_verdict(status, *shape).decision,
                tls_bootstrap::listener_verdict(status, *shape)
            );
        }
    }

    /// `init` on the singleton shape mints (presence) and is idempotent; on
    /// a fleet shape it REFUSES naming `tls import` and writes nothing
    /// (absence + control).
    #[test]
    fn issue_3709_init_mints_for_singleton_and_refuses_for_a_fleet_shape() {
        let mut env = TestEnv::fresh();
        let dir = key_dir(&env);
        let refused = {
            let mut out = env.output();
            run(
                TlsArgs {
                    key_dir: Some(dir.clone()),
                    action: TlsAction::Init { host: None },
                },
                false,
                &config_for(DeploymentShape::Team),
                &mut out,
            )
        };
        let err = refused.expect_err("team shape refuses init").to_string();
        assert!(err.contains("FLEET-shaped"), "{err}");
        assert!(err.contains("`ai-memory tls import"), "{err}");
        assert!(
            !dir.join(tls_bootstrap::TLS_SUBDIR).exists(),
            "nothing written"
        );

        {
            let mut out = env.output();
            run(
                TlsArgs {
                    key_dir: Some(dir.clone()),
                    action: TlsAction::Init {
                        host: Some("10.1.2.3".into()),
                    },
                },
                false,
                &config_for(DeploymentShape::Singleton),
                &mut out,
            )
            .expect("singleton init mints");
        }
        let text = env.stdout_str().to_string();
        assert!(text.contains("tls init: generated"), "{text}");
        assert!(text.contains("10.1.2.3"), "{text}");
        assert!(
            dir.join(tls_bootstrap::TLS_SUBDIR)
                .join(tls_bootstrap::SERVER_KEY_FILE)
                .exists()
        );
        env.stdout.clear();
        {
            let mut out = env.output();
            run(
                TlsArgs {
                    key_dir: Some(dir.clone()),
                    action: TlsAction::Init {
                        host: Some("10.1.2.3".into()),
                    },
                },
                true,
                &config_for(DeploymentShape::Singleton),
                &mut out,
            )
            .expect("second init reuses");
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["outcome"], "reused");

        // `status` reads the same directory and gives the singleton verdict.
        env.stdout.clear();
        {
            let mut out = env.output();
            run(
                TlsArgs {
                    key_dir: Some(dir.clone()),
                    action: TlsAction::Status,
                },
                true,
                &config_for(DeploymentShape::Singleton),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["source"], "local-ca");
        assert_eq!(v["boot_would_refuse"], false);
        assert!(
            v["verdict"]
                .as_str()
                .unwrap()
                .contains("encrypted as required for shape singleton")
        );
        // The same material under a declared TEAM shape is the refusing verdict.
        env.stdout.clear();
        {
            let mut out = env.output();
            run(
                TlsArgs {
                    key_dir: Some(dir),
                    action: TlsAction::Status,
                },
                true,
                &config_for(DeploymentShape::Team),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["boot_would_refuse"], true);
        assert!(
            v["verdict"]
                .as_str()
                .unwrap()
                .contains("ai-memory tls import")
        );
    }
}
