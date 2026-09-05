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
//! no direct store lookup; cache refresh and certificate expiry bound revocation.

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
#[derive(serde::Serialize, serde::Deserialize)]
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
    db_path: &Path,
    store_url: Option<&str>,
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
             no direct store lookup; a certificate must retain a bounded expiry even \
             when its public revocation cache is refreshed."
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

    // WHOLE SECONDS, deliberately (v1.0.0 #3511). The hub verifier compares
    // against its own clock rendered at `SecondsFormat::Secs`
    // (`ScopedDelegationVerifier::now`), i.e. TRUNCATED DOWN to the second. A
    // `not_before` carrying sub-second precision is therefore in the FUTURE
    // for that clock for up to a second, so a bundle minted and presented
    // inside one wall-clock second was refused as not-yet-valid — a fresh
    // wake-listener delegation turned into a refused hello. Stamping at the
    // granularity the verifier reads at removes the race WITHOUT widening the
    // window: the start moves EARLIER by at most 999 ms, never later, and the
    // end moves with it so the TTL stays exactly `ttl_secs`. Same remedy, and
    // for the same reason, as `wake_sink::producer_identity::mint` (#3469).
    let now = chrono::Utc::now();
    let not_before = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let not_after = (now + chrono::Duration::seconds(ttl_secs))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // The local key file proves possession, not enrollment. Resolve the v97
    // ledger before signing; a legacy or retired root cannot delegate.
    let snapshot =
        crate::cli::identity_hub_cache::derive(db_path, store_url, &[agent_id.to_owned()], None)?;
    let entry = snapshot
        .agents
        .first()
        .context("agent has no proven current enrolled delegation issuer")?;
    let issuer = keypair::decode_public_base64(&entry.pubkey_b64)?;
    if issuer != root.verifying_key() {
        bail!("local key does not match the current enrolled delegation issuer");
    }

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
                crate::models::field_names::NOT_BEFORE: not_before,
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
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    let mode = file.metadata()?.permissions().mode() & 0o7777;
    if mode != 0o600 {
        bail!("delegation bundle must be mode 0600 before writing its private key");
    }
    file.write_all(&json)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot flush {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn bundle() -> DelegationBundle {
        DelegationBundle {
            version: DELEGATION_BUNDLE_VERSION,
            agent_id: "agent-3468".to_owned(),
            hub_id: "hub".to_owned(),
            delegation_b64: "certificate".to_owned(),
            delegate_private_b64: "secret".to_owned(),
            not_before: "2026-09-04T12:00:00Z".to_owned(),
            not_after: "2026-09-04T13:00:00Z".to_owned(),
        }
    }

    /// REGRESSION (v1.0.0 #3511): a delegation this command mints must be
    /// usable the INSTANT it is minted.
    ///
    /// `ScopedDelegationVerifier::now` renders `Utc::now()` at
    /// `SecondsFormat::Secs`, i.e. truncated DOWN. A `not_before` carrying
    /// sub-second precision therefore sits in that clock's FUTURE for up to a
    /// second, so a bundle minted and presented inside one wall-clock second
    /// was judged not-yet-valid and a fresh wake-listener delegation became a
    /// refused hello. Mirrors
    /// `wake_sink::producer_identity::tests::a_freshly_minted_delegation_is_valid_against_a_second_truncated_clock_3469`
    /// for the CLI-minted bundle, and additionally pins that truncating the
    /// stamp did not shorten the window the operator asked for.
    #[test]
    fn a_freshly_minted_bundle_is_valid_against_a_second_truncated_clock_3511() {
        use crate::identity::hub_delegation::{DelegationWire, check_validity};

        const TTL_SECS: i64 = 60;
        const AGENT: &str = "ai:delegate-stamp-3511";

        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("identity.db");
        let keys = dir.path().join("keys");
        let conn = crate::db::open(&db).expect("open db");
        crate::db::register_agent(&conn, AGENT, "nhi", &[]).expect("register");
        let key = keypair::generate(AGENT).expect("generate");
        keypair::save(&key, &keys).expect("save");
        crate::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &key).expect("bind");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let bundle_path = dir.path().join("bundle.json");
        run(
            &db,
            None,
            &keys,
            AGENT,
            A2A_HUB_SCOPE,
            "hub",
            TTL_SECS,
            Some(&bundle_path),
            true,
            &mut out,
        )
        .expect("mint");

        let bundle: DelegationBundle =
            serde_json::from_slice(&std::fs::read(&bundle_path).expect("read bundle"))
                .expect("parse bundle");
        let encoded = URL_SAFE_NO_PAD
            .decode(&bundle.delegation_b64)
            .expect("decode delegation");
        let wire = DelegationWire::decode(&encoded).expect("decode wire");

        let truncated_now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        check_validity(&wire.as_delegation(), &truncated_now)
            .expect("a delegation the hub cannot use the instant it is minted is useless");

        // No sub-second component anywhere — on the wire and in the bundle the
        // listener reads — so the property does not depend on where in the
        // wall-clock second the mint happened to land.
        for stamp in [
            wire.not_before.as_str(),
            wire.not_after.as_str(),
            bundle.not_before.as_str(),
            bundle.not_after.as_str(),
        ] {
            assert!(!stamp.contains('.'), "sub-second stamp: {stamp}");
        }

        // Truncation moves the START earlier by at most 999 ms, never later,
        // and the end moves with it: the operator's TTL is exact.
        let start = chrono::DateTime::parse_from_rfc3339(&wire.not_before).expect("parse start");
        let end = chrono::DateTime::parse_from_rfc3339(&wire.not_after).expect("parse end");
        assert_eq!(
            (end - start).num_seconds(),
            TTL_SECS,
            "{} .. {}",
            wire.not_before,
            wire.not_after
        );
        assert_eq!(bundle.not_before, wire.not_before);
        assert_eq!(bundle.not_after, wire.not_after);
    }

    #[test]
    fn bundle_is_private_and_never_overwrites_an_existing_file_or_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        write_bundle_0600(&path, &bundle()).expect("fresh bundle");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let original = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(write_bundle_0600(&path, &bundle()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let link = dir.path().join("link.json");
        symlink(&path, &link).unwrap();
        assert!(write_bundle_0600(&link, &bundle()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}
