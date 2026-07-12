// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory capability` subcommand — macaroon capability-token
//! lifecycle (v0.9.0 G10.1, #1827; R9 zero-config owner mint, #1960).
//!
//! Six verbs over the stateless primitive in
//! [`crate::governance::capability`]:
//!
//! - `init`      — R9 (#1960) zero-config OWNER mint: idempotently create the
//!   reserved `owner` keypair (`owner.priv`/`owner.pub`) + `owner.caproot`
//!   mint secret, so the owner can mint attenuated tokens with NO
//!   `[capabilities.issuers]` config. Custody follows the key-dir discipline
//!   (0o600 private material). Re-running is a no-op.
//! - `keygen`    — generate the issuer's 32-byte HMAC mint secret
//!   (`<key_dir>/<issuer>.caproot`, mode `0o600`). Refuses to overwrite:
//!   rotation is an explicit delete-then-keygen (which consciously
//!   invalidates every outstanding token minted under the old secret).
//! - `mint`      — mint a root token. Requires BOTH the issuer's Ed25519
//!   private key (`<issuer>.priv`, attribution) and the `.caproot`
//!   secret (the SOLE mint gate). Enforces the mandatory-expiry lint:
//!   an unbounded token (no `--expires-at` / `--expires-in-secs`) is
//!   refused.
//! - `attenuate` — append caveats to an existing token, keyless
//!   (needs only the token itself; the result is strictly narrower).
//! - `inspect`   — decode and print a token's structure (no
//!   verification, no secrets).
//! - `verify`    — run the full fail-closed verify against the loaded
//!   `[capabilities]` config and a request tuple.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};

use crate::cli::CliOutput;
use crate::governance::capability::{
    CapRequest, CapabilityToken, Caveat, OWNER_ISSUER, OpLevel, attenuate, caveats_have_expiry,
    mint_with_secret, read_root_secret, verify, write_root_secret,
};
use crate::identity::keypair;

/// Shared caveat flags for `mint` / `attenuate`. Every provided flag
/// becomes one first-party [`Caveat`]; each further NARROWS the grant
/// (AND semantics).
#[derive(Args, Debug, Clone, Default)]
pub struct CaveatFlags {
    /// Restrict to this namespace or its `/`-descendants.
    #[arg(long)]
    pub namespace_prefix: Option<String>,
    /// Op-level ceiling: none / read / write / admin.
    #[arg(long)]
    pub op_ceiling: Option<String>,
    /// Restrict to exactly this governed action (Store/Delete/Promote/Reflect).
    #[arg(long)]
    pub action: Option<String>,
    /// Bind the token to this presenting agent id.
    #[arg(long)]
    pub agent: Option<String>,
    /// Unix-seconds instant the token stops being valid.
    #[arg(long)]
    pub expires_at: Option<i64>,
    /// Relative expiry in seconds from now (alternative to --expires-at).
    #[arg(long)]
    pub expires_in_secs: Option<i64>,
    /// Unix-seconds instant the token starts being valid.
    #[arg(long)]
    pub not_before: Option<i64>,
}

impl CaveatFlags {
    /// Materialise the provided flags into caveats, in a stable order.
    ///
    /// # Errors
    /// Rejects an unparseable `--op-ceiling` and a
    /// `--expires-at`/`--expires-in-secs` double-specification.
    fn to_caveats(&self, now: i64) -> Result<Vec<Caveat>> {
        let mut out = Vec::new();
        if let Some(p) = &self.namespace_prefix {
            out.push(Caveat::NamespacePrefix(p.clone()));
        }
        if let Some(raw) = &self.op_ceiling {
            let Some(level) = OpLevel::parse(raw) else {
                bail!("invalid --op-ceiling {raw:?} (expected none/read/write/admin)");
            };
            out.push(Caveat::OpCeiling(level));
        }
        if let Some(a) = &self.action {
            out.push(Caveat::Action(a.clone()));
        }
        if let Some(a) = &self.agent {
            out.push(Caveat::Agent(a.clone()));
        }
        if let Some(nb) = self.not_before {
            out.push(Caveat::NotBefore(nb));
        }
        match (self.expires_at, self.expires_in_secs) {
            (Some(_), Some(_)) => {
                bail!("pass either --expires-at or --expires-in-secs, not both");
            }
            (Some(t), None) => out.push(Caveat::ExpiresAt(t)),
            (None, Some(secs)) => out.push(Caveat::ExpiresAt(now.saturating_add(secs))),
            (None, None) => {}
        }
        Ok(out)
    }
}

#[derive(Args)]
pub struct CapabilityArgs {
    /// Override the default key storage directory (honors
    /// `AI_MEMORY_KEY_DIR` when omitted). Used by keygen / mint /
    /// attenuate; `verify` resolves issuers via the loaded
    /// `[capabilities]` config (which itself honors `AI_MEMORY_KEY_DIR`).
    #[arg(long, value_name = "PATH", global = true)]
    pub key_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub action: CapabilityAction,
}

#[derive(Subcommand)]
pub enum CapabilityAction {
    /// Zero-config owner mint (R9, #1960): idempotently create the reserved
    /// `owner` capability keypair + `.caproot` mint secret in the key dir,
    /// so the owner can immediately mint attenuated tokens WITHOUT editing
    /// `config.toml`. Re-running is a no-op (custody already present).
    Init,
    /// Generate the issuer's `.caproot` mint secret (mode 0o600).
    Keygen {
        /// Issuer id (must also be listed under `[capabilities.issuers]`).
        issuer: String,
    },
    /// Mint a root capability token (needs `<issuer>.priv` + `.caproot`).
    Mint {
        /// Issuer id.
        issuer: String,
        #[command(flatten)]
        caveats: CaveatFlags,
    },
    /// Append caveats to an existing token (keyless; strictly narrows).
    Attenuate {
        /// The `cap1:...` wire token to narrow.
        #[arg(long)]
        token: String,
        #[command(flatten)]
        caveats: CaveatFlags,
    },
    /// Decode and print a token's structure (no verification).
    Inspect {
        /// The `cap1:...` wire token.
        #[arg(long)]
        token: String,
    },
    /// Verify a token against the `[capabilities]` config + request tuple.
    Verify {
        /// The `cap1:...` wire token.
        #[arg(long)]
        token: String,
        /// Governed action name (Store/Delete/Promote/Reflect).
        #[arg(long)]
        action: String,
        /// Target namespace.
        #[arg(long)]
        namespace: String,
        /// The presenting agent id.
        #[arg(long)]
        agent: String,
        /// Verification instant (unix seconds); defaults to now.
        #[arg(long)]
        now: Option<i64>,
    },
}

/// Resolve the effective key directory: `--key-dir` > `AI_MEMORY_KEY_DIR`
/// > the platform default.
fn resolve_key_dir(flag: Option<PathBuf>) -> Result<PathBuf> {
    match flag {
        Some(d) => Ok(d),
        None => keypair::default_key_dir(),
    }
}

/// What an idempotent `capability init` (R9, #1960) actually did.
struct OwnerInitOutcome {
    /// A fresh `owner.priv`/`owner.pub` keypair was generated this call.
    created_keypair: bool,
    /// A fresh `owner.caproot` mint secret was written this call.
    created_root_secret: bool,
}

impl OwnerInitOutcome {
    /// True when both halves already existed (the call was a pure no-op).
    fn already_initialized(&self) -> bool {
        !self.created_keypair && !self.created_root_secret
    }
}

/// Idempotently establish the zero-config OWNER capability custody in `dir`
/// (R9, #1960): the `owner.priv`/`owner.pub` keypair (attribution) + the
/// `owner.caproot` mint secret (mode `0o600`). Re-running when both halves
/// already exist is a no-op; a partial state (one half missing) is repaired.
/// Custody follows the existing key-dir discipline (0o600 private material).
fn init_owner(dir: &std::path::Path) -> Result<OwnerInitOutcome> {
    // Keypair — considered present iff a loadable PRIVATE key exists (a
    // public-only file cannot mint).
    let has_keypair = keypair::load(OWNER_ISSUER, dir)
        .map(|kp| kp.private.is_some())
        .unwrap_or(false);
    let created_keypair = if has_keypair {
        false
    } else {
        let kp = keypair::generate(OWNER_ISSUER).context("generating owner capability keypair")?;
        keypair::save(&kp, dir).context("saving owner capability keypair")?;
        true
    };

    // Caproot mint secret — present iff it loads cleanly (right length +
    // secure mode).
    let has_caproot = read_root_secret(dir, OWNER_ISSUER).is_ok();
    let created_root_secret = if has_caproot {
        false
    } else {
        write_root_secret(dir, OWNER_ISSUER).context("writing owner root secret")?;
        true
    };

    Ok(OwnerInitOutcome {
        created_keypair,
        created_root_secret,
    })
}

/// Render a token summary for `inspect` / post-mint output.
fn token_summary(tok: &CapabilityToken) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "v": tok.v,
        "issuer": tok.issuer,
        "root_id": tok.root_id,
        "root_caveats": serde_json::to_value(&tok.root_caveats)?,
        "ext_caveats": serde_json::to_value(&tok.ext_caveats)?,
        "has_expiry": caveats_have_expiry(&tok.root_caveats)
            || caveats_have_expiry(&tok.ext_caveats),
    }))
}

/// Parse a wire token or fail with the reject code.
fn parse_wire(token: &str) -> Result<CapabilityToken> {
    CapabilityToken::from_wire(token.trim())
        .map_err(|rej| anyhow::anyhow!("invalid capability token: {rej}"))
}

/// Dispatch an `ai-memory capability <verb>` invocation.
///
/// # Errors
/// Any verb-specific failure (missing keys, mandatory-expiry lint,
/// malformed token, verify reject) surfaces as an `Err` so the caller
/// exits non-zero.
pub fn run(
    args: CapabilityArgs,
    json_out: bool,
    app_config: &crate::config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    match args.action {
        CapabilityAction::Init => {
            let dir = resolve_key_dir(args.key_dir)?;
            let outcome = init_owner(&dir)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "issuer": OWNER_ISSUER,
                        "key_dir": dir.display().to_string(),
                        "created_keypair": outcome.created_keypair,
                        "created_root_secret": outcome.created_root_secret,
                        "already_initialized": outcome.already_initialized(),
                    })
                )?;
            } else if outcome.already_initialized() {
                writeln!(
                    out.stdout,
                    "owner capability key already initialized in {} (no-op)",
                    dir.display()
                )?;
            } else {
                writeln!(
                    out.stdout,
                    "owner capability key initialized in {}",
                    dir.display()
                )?;
                writeln!(
                    out.stdout,
                    "mint attenuated tokens with: ai-memory capability mint {OWNER_ISSUER} \
                     --op-ceiling read --expires-in-secs 3600 [--namespace-prefix <ns>]"
                )?;
            }
            Ok(())
        }
        CapabilityAction::Keygen { issuer } => {
            let dir = resolve_key_dir(args.key_dir)?;
            let path = write_root_secret(&dir, &issuer)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "issuer": issuer,
                        "root_secret_path": path.display().to_string(),
                    })
                )?;
            } else {
                writeln!(out.stdout, "root secret written: {}", path.display())?;
                writeln!(
                    out.stdout,
                    "list the issuer under [capabilities.issuers.\"{issuer}\"] with a max_op \
                     ceiling to activate it"
                )?;
            }
            Ok(())
        }
        CapabilityAction::Mint { issuer, caveats } => {
            let dir = resolve_key_dir(args.key_dir)?;
            let now = chrono::Utc::now().timestamp();
            let root_caveats = caveats.to_caveats(now)?;
            // Mandatory-expiry lint (T9): refuse an unbounded token —
            // stateless revocation relies on short ExpiresAt bounds.
            if !caveats_have_expiry(&root_caveats) {
                bail!(
                    "refusing to mint an unbounded token: pass --expires-at or \
                     --expires-in-secs (revocation in G10.1 is expiry + root-secret rotation)"
                );
            }
            let kp = keypair::load(&issuer, &dir)
                .with_context(|| format!("loading issuer keypair for '{issuer}'"))?;
            let Some(private) = kp.private else {
                bail!(
                    "issuer '{issuer}' has no private key in {} — minting needs \
                     <issuer>.priv (attribution) plus <issuer>.caproot (mint gate)",
                    dir.display()
                );
            };
            let secret = read_root_secret(&dir, &issuer)?;
            let root_id = uuid::Uuid::new_v4().to_string();
            let tok = mint_with_secret(&private, &secret, &issuer, &root_id, root_caveats)?;
            let wire = tok.to_wire()?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({ "token": wire, "summary": token_summary(&tok)? })
                )?;
            } else {
                writeln!(out.stdout, "{wire}")?;
            }
            Ok(())
        }
        CapabilityAction::Attenuate { token, caveats } => {
            let now = chrono::Utc::now().timestamp();
            let to_add = caveats.to_caveats(now)?;
            if to_add.is_empty() {
                bail!("attenuate needs at least one caveat flag (nothing to narrow)");
            }
            let mut tok = parse_wire(&token)?;
            for c in to_add {
                tok = attenuate(&tok, c)?;
            }
            let wire = tok.to_wire()?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({ "token": wire, "summary": token_summary(&tok)? })
                )?;
            } else {
                writeln!(out.stdout, "{wire}")?;
            }
            Ok(())
        }
        CapabilityAction::Inspect { token } => {
            let tok = parse_wire(&token)?;
            let summary = token_summary(&tok)?;
            if json_out {
                writeln!(out.stdout, "{summary}")?;
            } else {
                writeln!(out.stdout, "{}", serde_json::to_string_pretty(&summary)?)?;
            }
            Ok(())
        }
        CapabilityAction::Verify {
            token,
            action,
            namespace,
            agent,
            now,
        } => {
            let tok = parse_wire(&token)?;
            let cfg = app_config.load_capability_config();
            let req = CapRequest {
                action,
                namespace,
                agent_id: agent,
                now: now.unwrap_or_else(|| chrono::Utc::now().timestamp()),
            };
            match verify(&tok, &cfg, &req) {
                Ok(grant) => {
                    if json_out {
                        writeln!(
                            out.stdout,
                            "{}",
                            serde_json::json!({
                                "verified": true,
                                "issuer": grant.issuer,
                                "root_id": grant.root_id,
                                "op_level": grant.op_level.as_str(),
                                "namespace_prefix": grant.namespace_prefix,
                            })
                        )?;
                    } else {
                        writeln!(
                            out.stdout,
                            "verified: issuer={} op_level={} namespace_prefix={:?}",
                            grant.issuer,
                            grant.op_level.as_str(),
                            grant.namespace_prefix,
                        )?;
                    }
                    Ok(())
                }
                Err(rej) => {
                    if json_out {
                        writeln!(
                            out.stdout,
                            "{}",
                            serde_json::json!({ "verified": false, "code": rej.code() })
                        )?;
                    } else {
                        writeln!(out.stderr, "reject: {rej}")?;
                    }
                    bail!("capability token rejected: {rej}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;
    use crate::config::AppConfig;

    fn key_dir(env: &TestEnv) -> PathBuf {
        env.db_path
            .parent()
            .expect("db path has a parent")
            .join("caps-keys")
    }

    fn args(key_dir: PathBuf, action: CapabilityAction) -> CapabilityArgs {
        CapabilityArgs {
            key_dir: Some(key_dir),
            action,
        }
    }

    fn seed_issuer(dir: &PathBuf, issuer: &str) {
        let kp = keypair::generate(issuer).expect("generate issuer keypair");
        keypair::save(&kp, dir).expect("save issuer keypair");
    }

    fn mint_flags(expires_at: Option<i64>) -> CaveatFlags {
        CaveatFlags {
            namespace_prefix: Some("team".to_string()),
            op_ceiling: Some("write".to_string()),
            expires_at,
            ..CaveatFlags::default()
        }
    }

    fn run_expect_token(env: &mut TestEnv, a: CapabilityArgs) -> String {
        let outcome = {
            let mut out = env.output();
            run(a, false, &AppConfig::default(), &mut out)
        };
        outcome.expect("command runs");
        let token = env.stdout_str().trim().to_string();
        assert!(token.starts_with("cap1:"), "got: {token}");
        token
    }

    #[test]
    fn init_creates_owner_custody_is_idempotent_and_owner_can_mint() {
        // R9 (#1960) zero-config owner mint: init establishes the owner
        // keypair + caproot, is idempotent, and the owner can immediately
        // mint an attenuated token with NO [capabilities.issuers] config.
        let mut env = TestEnv::fresh();
        let dir = key_dir(&env);
        {
            let mut out = env.output();
            run(
                args(dir.clone(), CapabilityAction::Init),
                true,
                &AppConfig::default(),
                &mut out,
            )
            .expect("init ok");
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["issuer"].as_str(), Some(OWNER_ISSUER));
        assert_eq!(v["created_keypair"].as_bool(), Some(true));
        assert_eq!(v["created_root_secret"].as_bool(), Some(true));
        assert_eq!(v["already_initialized"].as_bool(), Some(false));
        assert!(dir.join("owner.priv").exists(), "owner.priv written");
        assert!(dir.join("owner.pub").exists(), "owner.pub written");
        assert!(dir.join("owner.caproot").exists(), "owner.caproot written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.join("owner.caproot"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(m, 0o600, "caproot must be 0600");
        }

        // Second init is a pure no-op (idempotent).
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run(
                args(dir.clone(), CapabilityAction::Init),
                true,
                &AppConfig::default(),
                &mut out,
            )
            .expect("re-init ok");
        }
        let v2: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v2["created_keypair"].as_bool(), Some(false));
        assert_eq!(v2["created_root_secret"].as_bool(), Some(false));
        assert_eq!(v2["already_initialized"].as_bool(), Some(true));

        // The owner can mint an attenuated token straight away (zero config).
        env.stdout.clear();
        env.stderr.clear();
        let token = run_expect_token(
            &mut env,
            args(
                dir,
                CapabilityAction::Mint {
                    issuer: OWNER_ISSUER.to_string(),
                    caveats: CaveatFlags {
                        op_ceiling: Some("read".to_string()),
                        expires_at: Some(9_999_999_999),
                        ..CaveatFlags::default()
                    },
                },
            ),
        );
        assert!(token.starts_with("cap1:"));
    }

    #[test]
    fn keygen_writes_0600_and_refuses_overwrite() {
        let mut env = TestEnv::fresh();
        let dir = key_dir(&env);
        {
            let mut out = env.output();
            run(
                args(
                    dir.clone(),
                    CapabilityAction::Keygen {
                        issuer: "ai:iss".into(),
                    },
                ),
                false,
                &AppConfig::default(),
                &mut out,
            )
            .expect("keygen ok");
        }
        let path = dir.join("ai:iss.caproot");
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "caproot must be 0600");
        }
        // second keygen refuses (rotation = delete then keygen)
        let mut out = env.output();
        let err = run(
            args(
                dir,
                CapabilityAction::Keygen {
                    issuer: "ai:iss".into(),
                },
            ),
            false,
            &AppConfig::default(),
            &mut out,
        )
        .unwrap_err();
        assert!(err.to_string().contains("root secret"), "got: {err:#}");
    }

    #[test]
    fn mint_rejects_unbounded_expiry() {
        let mut env = TestEnv::fresh();
        let dir = key_dir(&env);
        seed_issuer(&dir, "ai:iss");
        {
            let mut out = env.output();
            run(
                args(
                    dir.clone(),
                    CapabilityAction::Keygen {
                        issuer: "ai:iss".into(),
                    },
                ),
                false,
                &AppConfig::default(),
                &mut out,
            )
            .unwrap();
        }
        let mut out = env.output();
        let err = run(
            args(
                dir,
                CapabilityAction::Mint {
                    issuer: "ai:iss".into(),
                    caveats: mint_flags(None), // no expiry ⇒ lint fires
                },
            ),
            false,
            &AppConfig::default(),
            &mut out,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unbounded"),
            "mandatory-expiry lint must fire: {err:#}"
        );
    }

    #[test]
    fn mint_attenuate_inspect_round_trip() {
        let mut env = TestEnv::fresh();
        let dir = key_dir(&env);
        seed_issuer(&dir, "ai:iss");
        {
            let mut out = env.output();
            run(
                args(
                    dir.clone(),
                    CapabilityAction::Keygen {
                        issuer: "ai:iss".into(),
                    },
                ),
                false,
                &AppConfig::default(),
                &mut out,
            )
            .unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let token = run_expect_token(
            &mut env,
            args(
                dir.clone(),
                CapabilityAction::Mint {
                    issuer: "ai:iss".into(),
                    caveats: mint_flags(Some(9_999_999_999)),
                },
            ),
        );
        // attenuate: narrow to read
        env.stdout.clear();
        env.stderr.clear();
        let narrowed = run_expect_token(
            &mut env,
            args(
                dir.clone(),
                CapabilityAction::Attenuate {
                    token: token.clone(),
                    caveats: CaveatFlags {
                        op_ceiling: Some("read".to_string()),
                        ..CaveatFlags::default()
                    },
                },
            ),
        );
        assert_ne!(token, narrowed, "attenuation must change the wire form");
        // inspect
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run(
                args(dir, CapabilityAction::Inspect { token: narrowed }),
                true,
                &AppConfig::default(),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["issuer"].as_str().unwrap(), "ai:iss");
        assert_eq!(v["ext_caveats"].as_array().unwrap().len(), 1);
        assert!(v["has_expiry"].as_bool().unwrap());
    }

    #[test]
    fn attenuate_requires_a_caveat_and_valid_op_ceiling() {
        let mut env = TestEnv::fresh();
        let mut out = env.output();
        let err = run(
            args(
                PathBuf::from("/nonexistent"),
                CapabilityAction::Attenuate {
                    token: "cap1:zzz".into(),
                    caveats: CaveatFlags::default(),
                },
            ),
            false,
            &AppConfig::default(),
            &mut out,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one caveat"), "{err:#}");

        let flags = CaveatFlags {
            op_ceiling: Some("supreme".to_string()),
            ..CaveatFlags::default()
        };
        let err2 = flags.to_caveats(0).unwrap_err();
        assert!(err2.to_string().contains("op-ceiling"), "{err2:#}");
        let both = CaveatFlags {
            expires_at: Some(1),
            expires_in_secs: Some(1),
            ..CaveatFlags::default()
        };
        let err3 = both.to_caveats(0).unwrap_err();
        assert!(err3.to_string().contains("not both"), "{err3:#}");
    }

    #[test]
    fn inspect_rejects_garbage_token() {
        let mut env = TestEnv::fresh();
        let mut out = env.output();
        let err = run(
            args(
                PathBuf::from("/nonexistent"),
                CapabilityAction::Inspect {
                    token: "not-a-token".into(),
                },
            ),
            false,
            &AppConfig::default(),
            &mut out,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid capability token"),
            "{err:#}"
        );
    }

    #[test]
    fn verify_rejects_unknown_issuer_and_json_reports_code() {
        // Default AppConfig ⇒ empty issuer allowlist ⇒ UnknownIssuer.
        let mut env = TestEnv::fresh();
        let dir = key_dir(&env);
        seed_issuer(&dir, "ai:iss");
        {
            let mut out = env.output();
            run(
                args(
                    dir.clone(),
                    CapabilityAction::Keygen {
                        issuer: "ai:iss".into(),
                    },
                ),
                false,
                &AppConfig::default(),
                &mut out,
            )
            .unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let token = run_expect_token(
            &mut env,
            args(
                dir,
                CapabilityAction::Mint {
                    issuer: "ai:iss".into(),
                    caveats: mint_flags(Some(9_999_999_999)),
                },
            ),
        );
        env.stdout.clear();
        env.stderr.clear();
        let outcome = {
            let mut out = env.output();
            run(
                CapabilityArgs {
                    key_dir: None,
                    action: CapabilityAction::Verify {
                        token,
                        action: "Store".into(),
                        namespace: "team/x".into(),
                        agent: "ai:someone".into(),
                        now: Some(1),
                    },
                },
                true,
                &AppConfig::default(),
                &mut out,
            )
        };
        assert!(outcome.is_err(), "unlisted issuer must reject");
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["verified"].as_bool(), Some(false));
        assert_eq!(v["code"].as_str(), Some("unknown_issuer"));
    }
}
