// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `fed_issue` — first-party zero-touch federation issuer CLI (operator tool).
//!
//! This is the operator-invokable wrapper around the federation-identity
//! issuance primitives that already ship in the library
//! ([`ai_memory::federation::identity::issuer::FederationIssuer`],
//! [`ai_memory::federation::identity::trust_bundle`],
//! [`ai_memory::federation::identity::credential::SignedCredential`]). The
//! library implements the mint/verify core; the shipped `ai-memory identity`
//! subcommand only generates *node* keypairs, so before this tool there was
//! no command-line path to mint a root CA, publish a trust bundle, or issue a
//! short-lived leaf credential. This closes that gap WITHOUT touching the
//! shipped `ai-memory` binary: it is a standalone `cargo` example, compiled on
//! demand, never linked into the daemon, so the published golden-binary
//! `sha256` is unchanged.
//!
//! The four verbs mirror the enterprise lifecycle (see
//! `docs/zero-touch-trust.html`):
//!
//! | Verb           | Effect                                                         |
//! |----------------|----------------------------------------------------------------|
//! | `mint-ca`      | generate (or reuse) the root issuer keypair in a key dir       |
//! | `gen-node`     | generate (or reuse) a node keypair (slashed SPIFFE-style id)   |
//! | `export-bundle`| publish the issuer verifying key as `<bundle>/<issuer>.pub`    |
//! | `issue`        | mint a short-lived leaf credential bound to a node's pubkey    |
//!
//! On-disk formats are exactly what the daemon reads at boot:
//! - keypair: `<key_dir>/<id>.pub` / `.priv` — raw 32-byte Ed25519 encodings.
//! - trust bundle: `<bundle_dir>/<issuer_id>.pub` — raw 32 bytes
//!   (`AI_MEMORY_FED_TRUST_BUNDLE_DIR`).
//! - leaf credential: a text file holding the `v1=<base64(CBOR)>`
//!   `X-Memory-Cred` header value (`AI_MEMORY_FED_CRED_PATH`).
//!
//! The issuer id MUST be slash-free (trust bundles are non-recursive — the
//! published `<issuer-id>.pub` must be a direct child of the bundle dir); node
//! `subject-agent-id`s SHOULD be slashed SPIFFE-style `campaign/region/host`.
//!
//! ```text
//! # mint the campaign root CA, generate a node key, publish the bundle, issue a leaf
//! cargo run --example fed_issue -- mint-ca       --key-dir KEYS --issuer-id hive-1461-ca
//! cargo run --example fed_issue -- gen-node      --key-dir NODEKEYS --agent-id hive-1461/nyc3/hive-peer-nyc3-01
//! cargo run --example fed_issue -- export-bundle --key-dir KEYS --issuer-id hive-1461-ca --bundle-dir BUNDLE
//! cargo run --example fed_issue -- issue         --key-dir KEYS --issuer-id hive-1461-ca \
//!     --trust-domain hive.fleet --subject-agent-id hive-1461/nyc3/hive-peer-nyc3-01 \
//!     --subject-pub-file NODEKEYS/hive-1461/nyc3/hive-peer-nyc3-01.pub --out peer-1.cred
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};

use ai_memory::federation::identity::issuer::{
    DEFAULT_CREDENTIAL_TTL_SECS, FederationIssuer, IssuerConfig,
};
use ai_memory::identity::keypair;

/// Raw Ed25519 verifying-key length on disk — the single source for the
/// length check when ingesting a subject `.pub`. Mirrors the substrate's
/// `<id>.pub` 32-byte convention.
const VERIFYING_KEY_LEN: usize = PUBLIC_KEY_LENGTH;

/// Suffix of a public-key file (issuer bundle entry + node `.pub`). Mirrors
/// `crate::identity::keypair`'s and `trust_bundle`'s `.pub` convention.
const PUB_SUFFIX: &str = ".pub";

/// Restrictive mode for the private-issuer key dir and the minted leaf
/// credential file — secrets are operator-only.
#[cfg(unix)]
const SECRET_DIR_MODE: u32 = 0o700;
/// A leaf credential is bearer-presentable but still mode-restricted on the
/// issuer host; the fan-out step lands it 0400 on the node.
#[cfg(unix)]
const CRED_FILE_MODE: u32 = 0o600;
/// A published issuer verifying key is world-readable (it is public).
#[cfg(unix)]
const PUB_FILE_MODE: u32 = 0o644;

#[derive(Parser)]
#[command(
    name = "fed_issue",
    about = "First-party zero-touch federation issuer (mint-ca / export-bundle / issue)",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate (or reuse) the root issuer keypair under `--key-dir`.
    MintCa {
        /// Directory holding issuer keypairs (`<issuer-id>.pub` / `.priv`).
        #[arg(long)]
        key_dir: PathBuf,
        /// Logical issuer identity stamped into every minted credential and
        /// keyed in receivers' trust bundles.
        #[arg(long)]
        issuer_id: String,
    },
    /// Generate (or reuse) a node keypair under `--key-dir` (raw `.pub`/`.priv`).
    ///
    /// The node's federation identity is normally a slashed SPIFFE-style id
    /// (`campaign/region/host`); the keypair files nest under sub-directories
    /// of `--key-dir` accordingly. Idempotent: an existing keypair is reused so
    /// re-runs keep a stable node identity. Prints the node verifying key.
    GenNode {
        /// Directory holding node keypairs (`<agent-id>.pub` / `.priv`).
        #[arg(long)]
        key_dir: PathBuf,
        /// The node's federation identity (== the `--federation-identity` the
        /// daemon resolves; e.g. `hive-1461/nyc3/hive-peer-nyc3-01`).
        #[arg(long)]
        agent_id: String,
    },
    /// Publish the issuer verifying key as `<bundle-dir>/<issuer-id>.pub`.
    ExportBundle {
        /// Directory holding the issuer keypair.
        #[arg(long)]
        key_dir: PathBuf,
        /// Issuer identity to publish.
        #[arg(long)]
        issuer_id: String,
        /// Trust-bundle directory (the receiver's
        /// `AI_MEMORY_FED_TRUST_BUNDLE_DIR`).
        #[arg(long)]
        bundle_dir: PathBuf,
    },
    /// Mint a short-lived leaf credential bound to a node's pubkey.
    Issue {
        /// Directory holding the issuer keypair (must contain the `.priv`).
        #[arg(long)]
        key_dir: PathBuf,
        /// Issuer identity that signs the credential.
        #[arg(long)]
        issuer_id: String,
        /// Trust domain stamped into the credential; receivers scoped to a
        /// different domain reject it.
        #[arg(long)]
        trust_domain: String,
        /// The node's federation identity (== its keypair `agent_id`).
        #[arg(long)]
        subject_agent_id: String,
        /// File holding the node's raw 32-byte verifying key (`<id>.pub`).
        #[arg(long)]
        subject_pub_file: PathBuf,
        /// Output path for the credential header value (`v1=<base64>`).
        #[arg(long)]
        out: PathBuf,
        /// Credential lifetime in seconds. Defaults to the library's
        /// compiled leaf TTL.
        #[arg(long, default_value_t = DEFAULT_CREDENTIAL_TTL_SECS)]
        ttl_secs: i64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fed_issue: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::MintCa { key_dir, issuer_id } => {
            let pub_b64 = mint_ca(&key_dir, &issuer_id)?;
            println!("issuer {issuer_id} ready (pub {pub_b64})");
            Ok(())
        }
        Command::GenNode { key_dir, agent_id } => {
            let pub_b64 = gen_node(&key_dir, &agent_id)?;
            println!("node {agent_id} ready (pub {pub_b64})");
            Ok(())
        }
        Command::ExportBundle {
            key_dir,
            issuer_id,
            bundle_dir,
        } => {
            let path = export_bundle(&key_dir, &issuer_id, &bundle_dir)?;
            println!("bundle entry written: {}", path.display());
            Ok(())
        }
        Command::Issue {
            key_dir,
            issuer_id,
            trust_domain,
            subject_agent_id,
            subject_pub_file,
            out,
            ttl_secs,
        } => {
            issue_credential(
                &key_dir,
                &issuer_id,
                &trust_domain,
                ttl_secs,
                &subject_agent_id,
                &subject_pub_file,
                &out,
            )?;
            println!(
                "credential for {subject_agent_id} (ttl {ttl_secs}s) written: {}",
                out.display()
            );
            Ok(())
        }
    }
}

/// Reject an `issuer_id` that cannot round-trip through a trust bundle.
///
/// `TrustBundle::from_dir` is **non-recursive**: it reads
/// `<bundle_dir>/<issuer_id>.pub` as a direct child only. A `/` (or any
/// platform path separator) in the issuer id would nest the published key in a
/// sub-directory the loader skips, silently yielding an empty bundle and an
/// `UnknownIssuer` verify failure downstream. Node `subject_agent_id`s MAY be
/// slashed (SPIFFE-style `campaign/region/host`); the ISSUER id may not. Empty
/// ids are rejected too. This is a boundary check on operator CLI input.
fn validate_issuer_id(issuer_id: &str) -> Result<()> {
    if issuer_id.is_empty() {
        return Err(anyhow!("issuer-id must not be empty"));
    }
    if issuer_id.contains('/') || issuer_id.contains('\\') {
        return Err(anyhow!(
            "issuer-id {issuer_id:?} must not contain a path separator — trust \
             bundles are non-recursive (the published <issuer-id>.pub must be a \
             direct child of the bundle dir, or it is never loaded). Use a \
             slash-free id like 'hive-1461-ca'; node subject-agent-ids may still \
             be slashed."
        ));
    }
    Ok(())
}

/// Current wall-clock UNIX seconds — the issuance `now` reference.
fn now_unix() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?
        .as_secs();
    i64::try_from(secs).map_err(|_| anyhow!("UNIX time overflows i64"))
}

/// Generate (or reuse) the issuer root keypair under `key_dir`. Idempotent:
/// an existing `<issuer_id>.priv` is loaded and returned untouched so re-runs
/// keep a stable CA. Returns the issuer's public key (URL-safe base64).
fn mint_ca(key_dir: &Path, issuer_id: &str) -> Result<String> {
    validate_issuer_id(issuer_id)?;
    ensure_secret_dir(key_dir)?;
    let priv_path = key_dir.join(format!("{issuer_id}{}", ".priv"));
    let keypair = if priv_path.exists() {
        keypair::load(issuer_id, key_dir)
            .with_context(|| format!("reuse existing issuer key for {issuer_id}"))?
    } else {
        let kp =
            keypair::generate(issuer_id).with_context(|| format!("generate issuer {issuer_id}"))?;
        keypair::save(&kp, key_dir).with_context(|| format!("persist issuer {issuer_id}"))?;
        kp
    };
    Ok(keypair.public_base64())
}

/// Generate (or reuse) a node keypair under `key_dir`, persisting both halves
/// (`<agent_id>.pub` 0644 / `.priv` 0600 via the substrate's `keypair::save`).
/// Idempotent: an existing `<agent_id>.priv` is loaded and returned untouched.
/// Returns the node's public key (URL-safe base64).
fn gen_node(key_dir: &Path, agent_id: &str) -> Result<String> {
    ensure_secret_dir(key_dir)?;
    let priv_path = key_dir.join(format!("{agent_id}{}", ".priv"));
    let keypair = if priv_path.exists() {
        keypair::load(agent_id, key_dir)
            .with_context(|| format!("reuse existing node key for {agent_id}"))?
    } else {
        let kp =
            keypair::generate(agent_id).with_context(|| format!("generate node {agent_id}"))?;
        keypair::save(&kp, key_dir).with_context(|| format!("persist node {agent_id}"))?;
        kp
    };
    Ok(keypair.public_base64())
}

/// Publish the issuer verifying key into a trust-bundle directory as
/// `<bundle_dir>/<issuer_id>.pub` (raw 32 bytes) — the O(1) enrollment
/// surface a receiver loads via `AI_MEMORY_FED_TRUST_BUNDLE_DIR`. Returns the
/// written path.
fn export_bundle(key_dir: &Path, issuer_id: &str, bundle_dir: &Path) -> Result<PathBuf> {
    validate_issuer_id(issuer_id)?;
    let keypair = keypair::load(issuer_id, key_dir)
        .with_context(|| format!("load issuer {issuer_id} for bundle export"))?;
    ensure_dir(bundle_dir)?;
    let dest = bundle_dir.join(format!("{issuer_id}{PUB_SUFFIX}"));
    if let Some(parent) = dest.parent() {
        ensure_dir(parent)?;
    }
    write_with_mode(&dest, &keypair.public.to_bytes(), PUB_FILE_MODE)
        .with_context(|| format!("write bundle entry {}", dest.display()))?;
    Ok(dest)
}

/// Mint a leaf credential for `subject_agent_id` bound to the verifying key in
/// `subject_pub_file`, signed by the issuer loaded from `key_dir`, and write
/// the `X-Memory-Cred` header value to `out`.
fn issue_credential(
    key_dir: &Path,
    issuer_id: &str,
    trust_domain: &str,
    ttl_secs: i64,
    subject_agent_id: &str,
    subject_pub_file: &Path,
    out: &Path,
) -> Result<()> {
    validate_issuer_id(issuer_id)?;
    let config = IssuerConfig::new(issuer_id, trust_domain).with_ttl_secs(ttl_secs);
    let issuer = FederationIssuer::load(config, key_dir)
        .map_err(|e| anyhow!("load issuer {issuer_id}: {e}"))?;
    let subject_pub = read_verifying_key(subject_pub_file)?;
    let signed = issuer
        .issue(subject_agent_id, &subject_pub, now_unix()?)
        .map_err(|e| anyhow!("mint credential for {subject_agent_id}: {e}"))?;
    let header = signed
        .to_header_value()
        .map_err(|e| anyhow!("encode credential: {e}"))?;
    if let Some(parent) = out.parent() {
        ensure_dir(parent)?;
    }
    write_with_mode(out, header.as_bytes(), CRED_FILE_MODE)
        .with_context(|| format!("write credential {}", out.display()))?;
    Ok(())
}

/// Read a raw 32-byte Ed25519 verifying key from a `.pub` file, validating the
/// length against [`VERIFYING_KEY_LEN`] and the bytes as a canonical point.
fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let bytes =
        fs::read(path).with_context(|| format!("read subject pubkey {}", path.display()))?;
    let arr: [u8; VERIFYING_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "subject pubkey {} is {} bytes, expected {VERIFYING_KEY_LEN}",
            path.display(),
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| {
        anyhow!(
            "subject pubkey {} is not a valid Ed25519 point: {e}",
            path.display()
        )
    })
}

/// Create a directory tree if absent.
fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))
}

/// Create a secrets directory tree and tighten its mode (Unix only).
fn ensure_secret_dir(dir: &Path) -> Result<()> {
    ensure_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(SECRET_DIR_MODE))
            .with_context(|| format!("chmod {SECRET_DIR_MODE:o} {}", dir.display()))?;
    }
    Ok(())
}

/// Write `bytes` to `path`, then set its Unix mode (no-op on non-Unix).
fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

/// Persist a freshly generated node keypair (test helper analogue of the
/// node-side `ai-memory identity generate`), returning its public key.
#[cfg(test)]
fn generate_node_pub(key_dir: &Path, agent_id: &str) -> Result<VerifyingKey> {
    let kp = keypair::generate(agent_id)?;
    keypair::save(&kp, key_dir)?;
    Ok(kp.public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_memory::federation::identity::credential::SignedCredential;
    use ai_memory::federation::identity::trust_bundle::TrustBundle;

    // The issuer id MUST be slash-free (trust bundles are non-recursive); the
    // node subject id is deliberately slashed (SPIFFE-style) to exercise the
    // #1514 nested-keypair-save path end-to-end.
    const ISSUER_ID: &str = "hive-1461-ca";
    const TRUST_DOMAIN: &str = "hive.fleet";
    const NODE_ID: &str = "hive-1461/nyc3/hive-peer-nyc3-01";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn mint_ca_is_idempotent() {
        let dir = tmp();
        let first = mint_ca(dir.path(), ISSUER_ID).expect("first mint");
        let second = mint_ca(dir.path(), ISSUER_ID).expect("re-mint reuses");
        assert_eq!(first, second, "re-running mint-ca must keep a stable CA");
        assert!(dir.path().join(format!("{ISSUER_ID}.priv")).exists());
        assert!(dir.path().join(format!("{ISSUER_ID}.pub")).exists());
    }

    #[test]
    fn export_bundle_writes_raw_issuer_key() {
        let keys = tmp();
        let bundle = tmp();
        mint_ca(keys.path(), ISSUER_ID).expect("mint");
        let dest = export_bundle(keys.path(), ISSUER_ID, bundle.path()).expect("export");
        let bytes = fs::read(&dest).expect("read bundle entry");
        assert_eq!(bytes.len(), VERIFYING_KEY_LEN);
        // The published bytes load back as a real bundle the daemon trusts.
        let loaded = TrustBundle::from_dir(bundle.path()).expect("load bundle");
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn issued_credential_verifies_against_the_published_bundle() {
        let keys = tmp();
        let bundle = tmp();
        let nodekeys = tmp();
        let out = tmp();
        mint_ca(keys.path(), ISSUER_ID).expect("mint");
        export_bundle(keys.path(), ISSUER_ID, bundle.path()).expect("export");

        // A node generates its own keypair; only its .pub crosses to the issuer.
        let node_pub = generate_node_pub(nodekeys.path(), NODE_ID).expect("node key");
        let subject_pub_file = nodekeys.path().join(format!("{NODE_ID}.pub"));
        let cred_path = out.path().join("peer-1.cred");

        issue_credential(
            keys.path(),
            ISSUER_ID,
            TRUST_DOMAIN,
            DEFAULT_CREDENTIAL_TTL_SECS,
            NODE_ID,
            &subject_pub_file,
            &cred_path,
        )
        .expect("issue");

        // The on-disk credential is exactly what the daemon loads + presents.
        let loaded = SignedCredential::load_from_path(&cred_path)
            .expect("read cred")
            .expect("cred present");
        let domain_bundle = TrustBundle::from_dir(bundle.path())
            .expect("bundle")
            .with_trust_domain(TRUST_DOMAIN);
        let verified = domain_bundle
            .verify(&loaded, now_unix().unwrap())
            .expect("trust-bundle verifies the issued credential");
        assert_eq!(verified.subject_agent_id, NODE_ID);
        assert_eq!(verified.issuer_id, ISSUER_ID);
        assert_eq!(verified.trust_domain, TRUST_DOMAIN);
        assert_eq!(verified.subject_pubkey, node_pub.to_bytes());
    }

    #[test]
    fn gen_node_is_idempotent_and_persists_slashed_keypair() {
        let dir = tmp();
        let first = gen_node(dir.path(), NODE_ID).expect("first gen");
        let second = gen_node(dir.path(), NODE_ID).expect("re-gen reuses");
        assert_eq!(
            first, second,
            "re-running gen-node must keep a stable node key"
        );
        // Slashed id → nested files really exist (the #1514 save path).
        assert!(dir.path().join(format!("{NODE_ID}.priv")).exists());
        assert!(dir.path().join(format!("{NODE_ID}.pub")).exists());
        // The published pub matches what `load` round-trips.
        let loaded = keypair::load(NODE_ID, dir.path()).expect("load node");
        assert_eq!(loaded.public_base64(), first);
        assert!(
            loaded.can_sign(),
            "node keypair must carry its private half"
        );
    }

    #[test]
    fn mint_ca_rejects_slashed_issuer_id() {
        let dir = tmp();
        let err = mint_ca(dir.path(), "hive/ca").expect_err("slashed issuer must be refused");
        assert!(
            err.to_string().contains("path separator"),
            "expected the non-recursive-bundle explanation, got: {err}"
        );
        // Empty is also rejected.
        assert!(
            mint_ca(dir.path(), "").is_err(),
            "empty issuer must be refused"
        );
    }

    #[test]
    fn issue_rejects_wrong_length_subject_pub() {
        let keys = tmp();
        let bad = tmp();
        let out = tmp();
        mint_ca(keys.path(), ISSUER_ID).expect("mint");
        let bad_pub = bad.path().join("short.pub");
        fs::write(&bad_pub, [0u8; 8]).expect("write short");
        let err = issue_credential(
            keys.path(),
            ISSUER_ID,
            TRUST_DOMAIN,
            DEFAULT_CREDENTIAL_TTL_SECS,
            NODE_ID,
            &bad_pub,
            &out.path().join("x.cred"),
        )
        .expect_err("short pubkey must fail");
        assert!(err.to_string().contains("expected"), "got: {err}");
    }

    #[test]
    fn issue_without_issuer_key_fails() {
        let keys = tmp();
        let nodekeys = tmp();
        let out = tmp();
        // No mint-ca → no issuer .priv present.
        generate_node_pub(nodekeys.path(), NODE_ID).expect("node key");
        let subject_pub_file = nodekeys.path().join(format!("{NODE_ID}.pub"));
        let err = issue_credential(
            keys.path(),
            ISSUER_ID,
            TRUST_DOMAIN,
            DEFAULT_CREDENTIAL_TTL_SECS,
            NODE_ID,
            &subject_pub_file,
            &out.path().join("x.cred"),
        )
        .expect_err("missing issuer must fail");
        assert!(err.to_string().contains("load issuer"), "got: {err}");
    }

    #[test]
    fn cross_domain_credential_is_rejected_by_scoped_bundle() {
        let keys = tmp();
        let bundle = tmp();
        let nodekeys = tmp();
        let out = tmp();
        mint_ca(keys.path(), ISSUER_ID).expect("mint");
        export_bundle(keys.path(), ISSUER_ID, bundle.path()).expect("export");
        generate_node_pub(nodekeys.path(), NODE_ID).expect("node key");
        let subject_pub_file = nodekeys.path().join(format!("{NODE_ID}.pub"));
        let cred_path = out.path().join("peer.cred");
        issue_credential(
            keys.path(),
            ISSUER_ID,
            TRUST_DOMAIN,
            DEFAULT_CREDENTIAL_TTL_SECS,
            NODE_ID,
            &subject_pub_file,
            &cred_path,
        )
        .expect("issue");
        let loaded = SignedCredential::load_from_path(&cred_path)
            .expect("read")
            .expect("present");
        let other_domain = TrustBundle::from_dir(bundle.path())
            .expect("bundle")
            .with_trust_domain("other.fleet");
        assert!(
            other_domain.verify(&loaded, now_unix().unwrap()).is_err(),
            "a bundle scoped to a different domain must reject the credential"
        );
    }
}
