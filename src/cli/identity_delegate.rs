// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory identity delegate --scope a2a-hub` — mint a scoped
//! `a2a-hub/join/v1` delegation (issue
//! [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! # What this hands out, and what it deliberately does not
//!
//! It mints a FRESH delegated keypair and signs a short-lived certificate for
//! it with the agent's ENROLLED key. The bundle it writes therefore contains a
//! private key — the delegated one — and never the enrolled `.priv`. That is
//! the whole point: a wake-listener holding this bundle can join the hub as the
//! agent and can do NOTHING else. If the listener is compromised, the blast
//! radius is "someone can be woken as me until this expires", not "someone can
//! write my history".
//!
//! The bundle is written 0600 into a directory the caller already trusts with
//! key material, and the window is bounded by
//! [`MAX_DELEGATION_TTL_SECS`] — refused, never clamped, because the hub does
//! no live revocation lookup and expiry IS the revocation mechanism.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::cli::CliOutput;
use crate::identity::hub_delegation::{
    A2A_HUB_SCOPE, DelegationWire, MAX_DELEGATION_TTL_SECS, check_ttl, sign_hub_delegation,
};
use crate::identity::keypair;

/// Format version of the bundle this writes.
pub const DELEGATION_BUNDLE_VERSION: u32 = 1;

/// Default delegation lifetime when `--ttl-secs` is omitted (1 hour).
pub const DEFAULT_DELEGATION_TTL_SECS: i64 = 3_600;

/// The on-disk bundle a wake-listener consumes.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationBundle {
    /// Bundle format version.
    pub version: u32,
    /// The enrolled agent this delegation speaks for.
    pub agent_id: String,
    /// The hub it is valid at.
    pub hub_id: String,
    /// The delegation certificate, wire-encoded, URL-safe base64.
    pub delegation_b64: String,
    /// The DELEGATED private key seed, URL-safe base64. Never the enrolled key.
    pub delegate_private_b64: String,
    /// RFC3339 window start, inclusive.
    pub not_before: String,
    /// RFC3339 window end, exclusive.
    pub not_after: String,
}

/// Mint a delegation and write the bundle.
///
/// # Errors
///
/// Refuses when the scope is not `a2a-hub`, when the enrolled key cannot sign
/// (a public-only handle cannot delegate), when the TTL is outside
/// `1..=MAX_DELEGATION_TTL_SECS`, or on any write failure.
#[allow(clippy::too_many_arguments)]
pub fn run(
    key_dir: &Path,
    agent_id: &str,
    scope: &str,
    hub_id: &str,
    ttl_secs: i64,
    out_path: Option<&Path>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if scope != A2A_HUB_SCOPE {
        bail!(
            "unknown delegation scope {scope:?}; this build mints only {A2A_HUB_SCOPE:?}. \
             A scope is an authority boundary, so an unrecognised one is refused rather \
             than minted with a name nothing checks."
        );
    }
    if ttl_secs <= 0 || ttl_secs > MAX_DELEGATION_TTL_SECS {
        bail!(
            "--ttl-secs {ttl_secs} is outside 1..={MAX_DELEGATION_TTL_SECS}. The hub performs \
             no live revocation lookup, so a delegation's expiry IS its revocation; a window \
             longer than the maximum would be an un-revocable credential."
        );
    }

    // The ENROLLED key. A public-only handle must not be able to delegate.
    let enrolled = keypair::load(agent_id, key_dir)
        .with_context(|| format!("cannot load the enrolled keypair for {agent_id}"))?;
    let Some(root) = enrolled.private.as_ref() else {
        bail!(
            "the keypair for {agent_id} is PUBLIC-ONLY, so it cannot mint a delegation. \
             Minting requires the enrolled private key on this host."
        );
    };

    // A FRESH delegated key: the hub session key is never the enrolled key.
    let delegate =
        keypair::generate(agent_id).context("could not generate the delegated hub key")?;
    let Some(delegate_private) = delegate.private.as_ref() else {
        bail!("generated delegated keypair is unexpectedly public-only");
    };

    let now = chrono::Utc::now();
    let not_before = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let not_after = (now + chrono::Duration::seconds(ttl_secs))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut wire = DelegationWire {
        principal: agent_id.to_owned(),
        scope: A2A_HUB_SCOPE.to_owned(),
        delegate_key_id: delegate.public.to_bytes(),
        hub_id: hub_id.to_owned(),
        not_before: not_before.clone(),
        not_after: not_after.clone(),
        signature: [0u8; 64],
    };
    wire.signature = sign_hub_delegation(root, &wire.as_delegation())
        .map_err(|e| anyhow::anyhow!("could not mint the delegation: {e}"))?;
    // Verify the bound we just claimed to honour, rather than trusting the
    // arithmetic above.
    check_ttl(&wire.as_delegation())
        .map_err(|e| anyhow::anyhow!("minted delegation failed its own window check: {e}"))?;

    let encoded = wire
        .encode()
        .map_err(|e| anyhow::anyhow!("could not encode the delegation: {e}"))?;
    let bundle = DelegationBundle {
        version: DELEGATION_BUNDLE_VERSION,
        agent_id: agent_id.to_owned(),
        hub_id: hub_id.to_owned(),
        delegation_b64: URL_SAFE_NO_PAD.encode(&encoded),
        delegate_private_b64: URL_SAFE_NO_PAD.encode(delegate_private.to_bytes()),
        not_before: not_before.clone(),
        not_after: not_after.clone(),
    };

    let target = out_path.map_or_else(|| default_bundle_path(key_dir, agent_id), Path::to_path_buf);
    write_bundle_0600(&target, &bundle)?;

    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "agent_id": agent_id,
                "hub_id": hub_id,
                "scope": A2A_HUB_SCOPE,
                "not_before": not_before,
                "not_after": not_after,
                "ttl_secs": ttl_secs,
                "bundle": target.display().to_string(),
                "delegated_pubkey_b64": delegate.public_base64(),
            }))?
        )?;
    } else {
        writeln!(out.stdout, "minted a2a-hub delegation")?;
        writeln!(out.stdout, "  agent:      {agent_id}")?;
        writeln!(out.stdout, "  hub:        {hub_id}")?;
        writeln!(out.stdout, "  scope:      {A2A_HUB_SCOPE}")?;
        writeln!(out.stdout, "  valid:      {not_before} .. {not_after}")?;
        writeln!(out.stdout, "  bundle:     {} (0600)", target.display())?;
        writeln!(
            out.stdout,
            "  the bundle holds a DELEGATED key, never the enrolled private key"
        )?;
    }
    Ok(())
}

/// Where a bundle lands when `--out` is omitted.
#[must_use]
pub fn default_bundle_path(key_dir: &Path, agent_id: &str) -> PathBuf {
    key_dir.join(format!("{agent_id}.a2a-hub.json"))
}

/// Write the bundle with owner-only permissions, creating it fresh.
///
/// The mode is set BEFORE the secret is written and verified after, so the
/// delegated private key is never briefly readable by another user.
fn write_bundle_0600(path: &Path, bundle: &DelegationBundle) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(bundle).context("cannot serialise the bundle")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.write_all(&json)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot flush {}", path.display()))?;
    drop(file);

    // `mode()` on OpenOptions only applies at CREATION, so an existing file
    // keeps whatever mode it had. Set and VERIFY rather than assume.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set 0600 on {}", path.display()))?;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("cannot re-stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        bail!(
            "{} is mode {mode:04o} after chmod, not 0600. It holds a private key, so this \
             filesystem cannot store it safely; refusing.",
            path.display()
        );
    }
    Ok(())
}
