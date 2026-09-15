// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3709 item 1 — **zero-config TLS on first boot.**
//!
//! Operator directive (2026-09-13): *"make the data encryption in transit
//! configuration and setup end user and admin easy."* #3705 makes plaintext
//! impossible; this module makes the encrypted path free: a fresh install
//! with no flags and no environment generates a local certificate authority
//! and a server certificate, writes them with correct permissions into the
//! key directory, and serves TLS. The bundled clients (`doctor --remote`,
//! the MCP → daemon forward) trust that CA because the same installation
//! wrote it. A developer on a laptop never types a TLS flag and never sees
//! plaintext.
//!
//! ## Two constraints that are not tradeable (#3709)
//!
//! - **Automatic generation is not automatic trust.** The local CA is right
//!   where the same installation is both issuer and truster. It is NEVER a
//!   licence to trust an unknown federation peer's certificate — peer trust
//!   stays an explicit act (`--quorum-ca-cert`, fingerprint pins, the
//!   allowlist). Nothing here touches the federation client's roots
//!   (#2448's accept-any closure stands).
//! - **No silent downgrade, ever.** If generation, renewal or loading
//!   fails, boot REFUSES (with the command that resolves it, #3709 item 5);
//!   it never falls back to plaintext to stay available.
//!
//! ## Material and lifetimes
//!
//! `<key_dir>/tls/` (0700): `local-ca.pem` + `local-ca.key` (0600) and
//! `server.pem` + `server.key` (0600). The CA lives
//! [`CA_LIFETIME_DAYS`]; the leaf lives [`LEAF_LIFETIME_DAYS`] and is
//! re-issued from the CA automatically whenever boot (or the daily renewal
//! tick) finds it inside [`RENEWAL_WINDOW_DAYS`] of expiry, or its subject
//! alternative names no longer cover the bind host. Under fail-closed an
//! expired certificate is an outage, so the renewal path ships with the
//! refusal, not after it. Expiry is read from the certificate itself, never
//! from a sidecar (derive state from the artefact).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

/// Sub-directory of the key directory holding the local TLS material.
pub const TLS_SUBDIR: &str = "tls";
pub const LOCAL_CA_CERT_FILE: &str = "local-ca.pem";
pub const LOCAL_CA_KEY_FILE: &str = "local-ca.key";
pub const SERVER_CERT_FILE: &str = "server.pem";
pub const SERVER_KEY_FILE: &str = "server.key";

/// The local CA's lifetime. Long: clients pin it by reading the file the
/// same installation wrote, and a rotated CA is a client-visible event.
pub const CA_LIFETIME_DAYS: i64 = 3650;
/// The server leaf's lifetime. Short: it is re-issued automatically.
pub const LEAF_LIFETIME_DAYS: i64 = 90;
/// The leaf is re-issued when this many days (or fewer) remain.
pub const RENEWAL_WINDOW_DAYS: i64 = 30;
/// How often the running daemon re-checks the leaf (seconds).
pub const RENEWAL_CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;

const CA_COMMON_NAME: &str = "ai-memory local CA";
const LEAF_COMMON_NAME: &str = "ai-memory local server";
const ORGANIZATION: &str = "ai-memory";
/// Backdate `not_before` so a host whose clock lags the generator by a few
/// minutes still validates the fresh certificate.
const NOT_BEFORE_SKEW_SECS: i64 = 5 * 60;
const MODE_PRIVATE: u32 = 0o600;
const MODE_PUBLIC: u32 = 0o644;
const MODE_DIR: u32 = 0o700;

/// What `ensure_local_tls` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// CA and leaf generated (first boot).
    Generated,
    /// The leaf was re-issued from the existing CA (renewal window, or the
    /// bind host was not covered).
    Renewed { reason: String },
    /// Existing material is valid and covers the host.
    Reused,
}

/// The resolved local TLS material.
#[derive(Clone, Debug)]
pub struct LocalTls {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub outcome: Outcome,
    /// Days until the leaf expires, read from the certificate.
    pub leaf_days_remaining: i64,
}

/// Observed state of the leaf on disk (for doctor / status; read-only).
#[derive(Clone, Debug)]
pub struct LeafStatus {
    pub present: bool,
    pub days_remaining: Option<i64>,
    pub subject_alt_names: Vec<String>,
    pub within_renewal_window: bool,
}

/// The local TLS directory under the resolved key directory.
///
/// # Errors
/// The key directory cannot be resolved or fails its posture check (#3198).
/// The one context line for a local-TLS artefact that could not be read.
fn read_context(path: &Path) -> String {
    format!("reading {} (#3709)", path.display())
}

pub fn local_tls_dir() -> Result<PathBuf> {
    Ok(crate::identity::keypair::default_key_dir()?.join(TLS_SUBDIR))
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, ORGANIZATION);
    dn
}

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// The subject alternative names a leaf must carry: the loopback forms, the
/// machine hostname and the bind host (an IP literal or a DNS name).
#[must_use]
pub fn leaf_subject_alt_names(bind_host: &str) -> Vec<String> {
    let mut sans: Vec<String> = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(name) = gethostname::gethostname().to_str()
        && !name.is_empty()
    {
        sans.push(name.to_string());
    }
    let host = bind_host.trim().trim_matches(|c| c == '[' || c == ']');
    // A wildcard bind is reachable on every interface; the leaf cannot
    // enumerate them, so it covers the loopback + hostname set and the
    // operator supplies a proper certificate for a public endpoint.
    if !host.is_empty() && host != "0.0.0.0" && host != "::" {
        sans.push(host.to_string());
    }
    sans.sort();
    sans.dedup();
    sans
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    write_mode(path, bytes, MODE_PRIVATE)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    write_mode(path, bytes, MODE_PUBLIC)
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("replacing {} (#3709)", path.display()))?;
    }
    #[cfg(unix)]
    {
        crate::identity::keypair::write_with_mode(path, bytes, mode)
            .with_context(|| format!("writing {} with mode {mode:o} (#3709)", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, bytes).with_context(|| format!("writing {} (#3709)", path.display()))
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating the local TLS directory {} (#3709)", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(MODE_DIR))
            .with_context(|| format!("chmod {MODE_DIR:o} {} (#3709)", dir.display()))?;
    }
    Ok(())
}

/// Parse one PEM certificate's validity end and its subject alternative
/// names, from the artefact itself.
fn parse_leaf(pem_bytes: &[u8]) -> Result<(time::OffsetDateTime, Vec<String>)> {
    let der = pem::parse(pem_bytes).context("parsing the certificate PEM (#3709)")?;
    let (_, cert) = x509_parser::parse_x509_certificate(der.contents())
        .map_err(|e| anyhow::anyhow!("parsing the certificate DER: {e} (#3709)"))?;
    let not_after = cert.validity().not_after.to_datetime();
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(d) => sans.push((*d).to_string()),
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    let ip = match bytes.len() {
                        4 => {
                            IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap_or([0; 4])).to_string()
                        }
                        16 => IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap_or([0; 16]))
                            .to_string(),
                        _ => continue,
                    };
                    sans.push(ip);
                }
                _ => {}
            }
        }
    }
    Ok((not_after, sans))
}

fn days_until(when: time::OffsetDateTime) -> i64 {
    (when - now()).whole_days()
}

/// Read-only status of the leaf under `key_dir` (for doctor / `tls status`).
///
/// # Errors
/// The leaf exists but cannot be parsed (a corrupt artefact is reported,
/// never treated as absent).
pub fn leaf_status(key_dir: &Path) -> Result<LeafStatus> {
    let cert_path = key_dir.join(TLS_SUBDIR).join(SERVER_CERT_FILE);
    if !cert_path.exists() {
        return Ok(LeafStatus {
            present: false,
            days_remaining: None,
            subject_alt_names: Vec::new(),
            within_renewal_window: false,
        });
    }
    let pem_bytes = std::fs::read(&cert_path).with_context(|| read_context(&cert_path))?;
    let (not_after, sans) = parse_leaf(&pem_bytes)?;
    let days = days_until(not_after);
    Ok(LeafStatus {
        present: true,
        days_remaining: Some(days),
        subject_alt_names: sans,
        within_renewal_window: days <= RENEWAL_WINDOW_DAYS,
    })
}

fn generate_ca(dir: &Path) -> Result<(String, KeyPair)> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("building the local CA parameters (#3709)")?;
    params.distinguished_name = dn(CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = now() - time::Duration::seconds(NOT_BEFORE_SKEW_SECS);
    params.not_after = now() + time::Duration::days(CA_LIFETIME_DAYS);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("generating the local CA key (#3709)")?;
    let cert = params
        .self_signed(&key)
        .context("self-signing the local CA (#3709)")?;
    let ca_pem = cert.pem();
    write_private(&dir.join(LOCAL_CA_KEY_FILE), key.serialize_pem().as_bytes())?;
    write_public(&dir.join(LOCAL_CA_CERT_FILE), ca_pem.as_bytes())?;
    Ok((ca_pem, key))
}

fn issue_leaf(dir: &Path, ca_pem: &str, ca_key: KeyPair, sans: &[String]) -> Result<()> {
    let issuer = Issuer::from_ca_cert_pem(ca_pem, ca_key)
        .context("re-reading the local CA as an issuer (#3709)")?;
    let mut params = CertificateParams::new(sans.to_vec())
        .context("building the server certificate parameters (#3709)")?;
    params.distinguished_name = dn(LEAF_COMMON_NAME);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now() - time::Duration::seconds(NOT_BEFORE_SKEW_SECS);
    params.not_after = now() + time::Duration::days(LEAF_LIFETIME_DAYS);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("generating the server key (#3709)")?;
    let cert = params
        .signed_by(&key, &issuer)
        .context("signing the server certificate with the local CA (#3709)")?;
    write_private(&dir.join(SERVER_KEY_FILE), key.serialize_pem().as_bytes())?;
    write_public(&dir.join(SERVER_CERT_FILE), cert.pem().as_bytes())?;
    Ok(())
}

fn load_ca(dir: &Path) -> Result<Option<(String, KeyPair)>> {
    let cert_path = dir.join(LOCAL_CA_CERT_FILE);
    let key_path = dir.join(LOCAL_CA_KEY_FILE);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }
    let ca_pem = std::fs::read_to_string(&cert_path).with_context(|| read_context(&cert_path))?;
    let key_pem = std::fs::read_to_string(&key_path).with_context(|| read_context(&key_path))?;
    let key = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parsing the local CA key {} (#3709)", key_path.display()))?;
    // The CA must itself be inside its validity; an expired CA is
    // regenerated (clients re-read the CA file the same installation wrote).
    let (ca_not_after, _) = parse_leaf(ca_pem.as_bytes())?;
    if days_until(ca_not_after) <= RENEWAL_WINDOW_DAYS {
        return Ok(None);
    }
    Ok(Some((ca_pem, key)))
}

/// Ensure valid local TLS material exists for a listener on `bind_host`,
/// generating or renewing as needed. Every failure is an error — never a
/// plaintext fallback (#3705 / #3709).
///
/// # Errors
/// The key directory is unusable, or generation / renewal / parsing fails.
pub fn ensure_local_tls(key_dir: &Path, bind_host: &str) -> Result<LocalTls> {
    let dir = key_dir.join(TLS_SUBDIR);
    ensure_dir(&dir)?;
    let cert_path = dir.join(SERVER_CERT_FILE);
    let key_path = dir.join(SERVER_KEY_FILE);
    let ca_cert_path = dir.join(LOCAL_CA_CERT_FILE);
    let wanted = leaf_subject_alt_names(bind_host);

    let (ca_pem, ca_key, fresh_ca) = match load_ca(&dir)? {
        Some((pem, key)) => (pem, key, false),
        None => {
            let (pem, key) = generate_ca(&dir)?;
            (pem, key, true)
        }
    };

    let renew_reason: Option<String> = if fresh_ca {
        Some("first boot (no local CA)".to_string())
    } else if !cert_path.exists() || !key_path.exists() {
        Some("no server certificate".to_string())
    } else {
        let status = leaf_status(key_dir)?;
        let missing: Vec<&String> = wanted
            .iter()
            .filter(|w| !status.subject_alt_names.contains(w))
            .collect();
        if status.within_renewal_window {
            Some(format!(
                "{} day(s) to expiry (renewal window {RENEWAL_WINDOW_DAYS})",
                status.days_remaining.unwrap_or_default()
            ))
        } else if !missing.is_empty() {
            Some(format!(
                "certificate does not cover {}",
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        } else {
            None
        }
    };

    let outcome = match renew_reason {
        Some(reason) => {
            issue_leaf(&dir, &ca_pem, ca_key, &wanted)?;
            if fresh_ca {
                Outcome::Generated
            } else {
                Outcome::Renewed { reason }
            }
        }
        None => Outcome::Reused,
    };
    let status = leaf_status(key_dir)?;
    Ok(LocalTls {
        cert_path,
        key_path,
        ca_cert_path,
        outcome,
        leaf_days_remaining: status.days_remaining.unwrap_or_default(),
    })
}

/// The local CA certificate this installation wrote, as PEM — for the
/// BUNDLED clients only (`doctor --remote`, the MCP → daemon forward).
/// `Ok(None)` when no local CA exists (the operator supplied their own
/// material). Never used for federation peers: peer trust is explicit.
///
/// # Errors
/// The key directory cannot be resolved, or the CA file cannot be read.
pub fn local_ca_pem() -> Result<Option<Vec<u8>>> {
    let path = local_tls_dir()?.join(LOCAL_CA_CERT_FILE);
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read(&path)
        .map(Some)
        .with_context(|| format!("reading the local CA {} (#3709)", path.display()))
}

/// [`local_ca_pem`] as a `reqwest` root certificate for the bundled clients.
///
/// # Errors
/// See [`local_ca_pem`]; a CA file that does not parse is an error, never
/// silently ignored.
pub fn local_ca_certificate() -> Result<Option<reqwest::Certificate>> {
    match local_ca_pem()? {
        None => Ok(None),
        Some(pem_bytes) => reqwest::Certificate::from_pem(&pem_bytes)
            .map(Some)
            .context("parsing the local CA certificate (#3709)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir under TMPDIR")
    }

    #[test]
    fn first_boot_generates_ca_and_leaf_with_private_modes_3709() {
        let tmp = sandbox();
        let tls = ensure_local_tls(tmp.path(), "127.0.0.1").expect("generate");
        assert_eq!(tls.outcome, Outcome::Generated);
        assert!(tls.cert_path.exists() && tls.key_path.exists() && tls.ca_cert_path.exists());
        assert!(tls.leaf_days_remaining > RENEWAL_WINDOW_DAYS);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&tls.key_path), MODE_PRIVATE);
            assert_eq!(
                mode(&tmp.path().join(TLS_SUBDIR).join(LOCAL_CA_KEY_FILE)),
                MODE_PRIVATE
            );
            assert_eq!(mode(&tmp.path().join(TLS_SUBDIR)), MODE_DIR);
        }
        let status = leaf_status(tmp.path()).unwrap();
        assert!(status.present && !status.within_renewal_window);
        for san in ["localhost", "127.0.0.1", "::1"] {
            assert!(status.subject_alt_names.iter().any(|s| s == san), "{san}");
        }
    }

    #[test]
    fn second_boot_reuses_and_a_new_host_renews_3709() {
        let tmp = sandbox();
        let first = ensure_local_tls(tmp.path(), "127.0.0.1").unwrap();
        let again = ensure_local_tls(tmp.path(), "127.0.0.1").unwrap();
        assert_eq!(again.outcome, Outcome::Reused);
        assert_eq!(
            std::fs::read(&first.cert_path).unwrap(),
            std::fs::read(&again.cert_path).unwrap()
        );
        let renewed = ensure_local_tls(tmp.path(), "10.1.2.3").unwrap();
        assert!(
            matches!(renewed.outcome, Outcome::Renewed { .. }),
            "{:?}",
            renewed.outcome
        );
        let status = leaf_status(tmp.path()).unwrap();
        assert!(status.subject_alt_names.iter().any(|s| s == "10.1.2.3"));
        // The CA is unchanged across a leaf renewal.
        assert_eq!(
            std::fs::read(&first.ca_cert_path).unwrap(),
            std::fs::read(&renewed.ca_cert_path).unwrap()
        );
    }

    #[test]
    fn generated_material_loads_as_a_rustls_server_config_3709() {
        let tmp = sandbox();
        let tls = ensure_local_tls(tmp.path(), "localhost").unwrap();
        let cert = std::fs::read(&tls.cert_path).unwrap();
        let key = std::fs::read(&tls.key_path).unwrap();
        let certs = crate::tls::rustls_pki_pem_iter_certs(&cert).unwrap();
        assert_eq!(certs.len(), 1);
        crate::tls::rustls_pki_pem_parse_private_key(&key).unwrap();
        // The CA is a valid reqwest root for the bundled clients.
        let ca = std::fs::read(&tls.ca_cert_path).unwrap();
        reqwest::Certificate::from_pem(&ca).unwrap();
    }

    #[test]
    fn wildcard_bind_is_not_a_san_3709() {
        let sans = leaf_subject_alt_names("0.0.0.0");
        assert!(!sans.iter().any(|s| s == "0.0.0.0"));
        assert!(sans.iter().any(|s| s == "localhost"));
        let sans = leaf_subject_alt_names("[::1]");
        assert!(sans.iter().any(|s| s == "::1"));
    }
}
