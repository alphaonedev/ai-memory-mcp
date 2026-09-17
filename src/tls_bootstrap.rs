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
/// #3709 item 2 — the CA bundle an operator installs with `tls import --ca`
/// so the BUNDLED clients (`doctor --remote`, the MCP → daemon forward) can
/// verify an operator-supplied leaf. Public material (0644). Preferred over
/// [`LOCAL_CA_CERT_FILE`] by [`local_ca_pem`] when present.
pub const OPERATOR_CA_CERT_FILE: &str = "operator-ca.pem";
/// The one word for material `ai-memory tls import` (or an operator's hand)
/// installed — `tls status`, `tls init` and `doctor` all say it this way.
pub const SOURCE_OPERATOR_SUPPLIED: &str = "operator-supplied";
/// The one word for material the local CA issued.
pub const SOURCE_LOCAL_CA: &str = "local-ca";

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
    /// #3709 item 2 — `<key_dir>/tls/server.pem` was installed by the
    /// operator (`ai-memory tls import`): its issuer is not the local CA.
    /// Nothing is minted or renewed over it; an expired one REFUSES.
    OperatorSupplied,
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
    /// #3709 F7 — `true` when `<key_dir>/tls/server.key` exists on disk. The
    /// verdict predicate must see the KEY as well as the certificate: a
    /// `present` cert without its key would fall through to the local
    /// bootstrap (mint-over) while the verdict falsely attests it is served.
    pub key_present: bool,
    pub days_remaining: Option<i64>,
    pub subject_alt_names: Vec<String>,
    pub within_renewal_window: bool,
    /// The issuer's common name, read from the certificate (#3709 item 2).
    pub issuer: String,
    /// `true` when the leaf was not issued by the local CA — installed by
    /// `ai-memory tls import`, or copied in by hand. The bootstrap never
    /// mints over it and the fleet-shape rule accepts it as enterprise PKI.
    pub operator_supplied: bool,
    /// `not_after` as RFC 3339, read from the certificate.
    pub not_after: Option<String>,
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

/// What [`parse_leaf`] reads from one certificate, from the artefact itself.
#[derive(Clone, Debug)]
struct ParsedCert {
    not_after: time::OffsetDateTime,
    sans: Vec<String>,
    issuer_cn: String,
    subject_cn: String,
    /// The certificate's DER, kept so [`issued_by`] can verify its
    /// signature against a CA we hold (F3: identity, never a CN string).
    der: Vec<u8>,
}

/// F3 (#3709 review) — `true` when `leaf` was ISSUED BY `ca`: the issuer
/// name equals the CA's subject name AND the leaf's signature verifies
/// under the CA's public key (every verification algorithm the listener's
/// crypto provider supports is tried; a wrong algorithm simply fails). This
/// is how the bootstrap tells material it minted from material an operator
/// installed — by the CA it holds, never by a common-name string an
/// enterprise CA could also carry.
fn issued_by(leaf_der: &[u8], ca_der: &[u8]) -> bool {
    let Ok((_, leaf)) = x509_parser::parse_x509_certificate(leaf_der) else {
        return false;
    };
    let Ok((_, ca)) = x509_parser::parse_x509_certificate(ca_der) else {
        return false;
    };
    if leaf.issuer().as_raw() != ca.subject().as_raw() {
        return false;
    }
    let ca_key: &[u8] = &ca.public_key().subject_public_key.data;
    let tbs: &[u8] = leaf.tbs_certificate.as_ref();
    let signature: &[u8] = &leaf.signature_value.data;
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
        .iter()
        .any(|alg| alg.verify_signature(ca_key, tbs, signature).is_ok())
}

/// F4 (#3709 review) — SANs are foreign text from the artefact; render each
/// escaped (the way issuer / subject already are) so a `tls status` pasted
/// into a ticket cannot carry a control character through.
#[must_use]
pub fn render_sans(sans: &[String]) -> String {
    if sans.is_empty() {
        "none".to_string()
    } else {
        sans.iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn common_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map_or_else(|| name.to_string(), str::to_string)
}

/// Parse the FIRST PEM certificate's validity end, subject alternative
/// names and issuer / subject common names, from the artefact itself. A
/// fullchain file parses as its leaf (the leaf comes first).
fn parse_leaf(pem_bytes: &[u8]) -> Result<ParsedCert> {
    let der = pem::parse(pem_bytes).context("parsing the certificate PEM (#3709)")?;
    let (_, cert) = x509_parser::parse_x509_certificate(der.contents())
        .map_err(|e| anyhow::anyhow!("parsing the certificate DER: {e} (#3709)"))?;
    let not_after = cert.validity().not_after.to_datetime();
    let issuer_cn = common_name(cert.issuer());
    let subject_cn = common_name(cert.subject());
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
    Ok(ParsedCert {
        not_after,
        sans,
        issuer_cn,
        subject_cn,
        der: der.contents().to_vec(),
    })
}

fn rfc3339(when: time::OffsetDateTime) -> String {
    when.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| when.to_string())
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
    // #3709 F7 — the private key's presence is part of the material's state:
    // the verdict predicate refuses a broken pair rather than serving a cert
    // whose key is missing (which would mint a local certificate over it).
    let key_present = key_dir.join(TLS_SUBDIR).join(SERVER_KEY_FILE).exists();
    if !cert_path.exists() {
        return Ok(LeafStatus {
            present: false,
            key_present,
            days_remaining: None,
            subject_alt_names: Vec::new(),
            within_renewal_window: false,
            issuer: String::new(),
            operator_supplied: false,
            not_after: None,
        });
    }
    let pem_bytes = std::fs::read(&cert_path).with_context(|| read_context(&cert_path))?;
    let parsed = parse_leaf(&pem_bytes)?;
    let days = days_until(parsed.not_after);
    // F3 — minted by US only if it verifies under the local CA THIS key
    // directory holds; no local CA, no signature match, or an unreadable CA
    // file all mean "not ours" (operator-supplied). A common name proves
    // nothing: an enterprise CA may carry the same string.
    let ca_path = key_dir.join(TLS_SUBDIR).join(LOCAL_CA_CERT_FILE);
    let minted_locally = std::fs::read(&ca_path)
        .ok()
        .and_then(|ca_pem| parse_leaf(&ca_pem).ok())
        .is_some_and(|ca| issued_by(&parsed.der, &ca.der));
    Ok(LeafStatus {
        present: true,
        key_present,
        days_remaining: Some(days),
        subject_alt_names: parsed.sans,
        within_renewal_window: days <= RENEWAL_WINDOW_DAYS,
        operator_supplied: !minted_locally,
        issuer: parsed.issuer_cn,
        not_after: Some(rfc3339(parsed.not_after)),
    })
}

/// #3709 item 2 — `true` when `<key_dir>/tls/server.pem` exists and was
/// not issued by the local CA this key directory holds (the artefact
/// decides; no sidecar). A missing leaf is `false`; an unreadable one is
/// an error.
///
/// # Errors
/// The leaf exists but cannot be parsed.
pub fn operator_material_present(key_dir: &Path) -> Result<bool> {
    Ok(leaf_status(key_dir)?.operator_supplied)
}

/// F2 (#3709 review, rule (s)) — the ONE decision about the listener's
/// material under the declared shape. The daemon refuses or serves by it
/// ([`crate::daemon_runtime::resolve_tls_material`]); `tls status` and
/// `doctor` RENDER it. There is no second ordering anywhere: operator
/// material (any shape) is judged on its expiry alone; a fleet shape
/// without operator material refuses whatever local material is present;
/// a singleton mints, renews or serves its local leaf.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum ListenerVerdict {
    /// Singleton, nothing installed: the next boot mints the local CA + leaf.
    MintsLocal,
    /// A locally minted leaf serves; `days` to expiry.
    ServesLocal { days: i64 },
    /// A locally minted leaf inside its renewal window or already expired:
    /// the next boot (or the daily task) re-issues it from the local CA.
    RenewsLocal { days: i64 },
    /// Operator-supplied material serves; renewal is the operator's.
    ServesOperator { days: i64 },
    /// Refuses: a fleet shape with no operator material — nothing
    /// installed, or a locally minted leaf (an unmanaged CA on an estate).
    RefusesFleetNeedsPki { local_present: bool },
    /// Refuses: operator-supplied material has expired; the daemon never
    /// re-issues what it did not mint.
    RefusesOperatorExpired { days_ago: i64 },
    /// Refuses (#3709 F7): `server.pem` is installed under `<key_dir>/tls/`
    /// but its private key `server.key` is MISSING — a broken pair. On EVERY
    /// shape: serving would fall through to the local bootstrap, which mints a
    /// local CA + leaf OVER the installed certificate and serves that
    /// `managed`, while the verdict would falsely attest the installed
    /// certificate is served.
    RefusesCertWithoutKey,
    /// Refuses (#3709 F7): `server.key` is installed under `<key_dir>/tls/`
    /// but its certificate `server.pem` is MISSING — the other half of the
    /// broken pair. Typed refusal on EVERY shape.
    RefusesKeyWithoutCert,
}

impl ListenerVerdict {
    /// `true` when `serve` (without --tls-cert/--tls-key) refuses to bind.
    #[must_use]
    pub const fn refuses(&self) -> bool {
        matches!(
            self,
            Self::RefusesFleetNeedsPki { .. }
                | Self::RefusesOperatorExpired { .. }
                | Self::RefusesCertWithoutKey
                | Self::RefusesKeyWithoutCert
        )
    }

    /// The material's source word: `absent`, `local-ca` or `operator-supplied`.
    #[must_use]
    pub const fn source(&self) -> &'static str {
        match self {
            Self::MintsLocal => "absent",
            Self::ServesLocal { .. } | Self::RenewsLocal { .. } => SOURCE_LOCAL_CA,
            Self::ServesOperator { .. } | Self::RefusesOperatorExpired { .. } => {
                SOURCE_OPERATOR_SUPPLIED
            }
            Self::RefusesFleetNeedsPki { local_present } => {
                if *local_present {
                    SOURCE_LOCAL_CA
                } else {
                    "absent"
                }
            }
            // #3709 F7 — a cert without its key is the operator-import-
            // missing-key shape (a local mint always writes both); a key
            // without its cert has no certificate to attribute a source to.
            Self::RefusesCertWithoutKey => SOURCE_OPERATOR_SUPPLIED,
            Self::RefusesKeyWithoutCert => "absent",
        }
    }

    /// The one-line operator rendering, with the fix when refusing.
    #[must_use]
    pub fn render(&self, shape: crate::config::shape::DeploymentShape) -> String {
        match self {
            Self::MintsLocal => "no certificate installed: the next boot mints a local CA and \
                                 server certificate under <key_dir>/tls/ (or run `ai-memory tls \
                                 init` now)"
                .to_string(),
            Self::ServesLocal { days } => {
                format!("encrypted as required for shape {shape}; {days} day(s) to expiry")
            }
            Self::RenewsLocal { days } => format!(
                "encrypted as required for shape {shape}; the local leaf has {days} day(s) to \
                 expiry (renewal window {RENEWAL_WINDOW_DAYS} days) and is re-issued from the \
                 local CA at the next boot or by the daily task"
            ),
            Self::ServesOperator { days } => format!(
                "encrypted as required for shape {shape}; operator-supplied certificate, {days} \
                 day(s) to expiry (not renewed by the daemon: {})",
                crate::transit_encryption::REMEDY_TLS_RENEW
            ),
            Self::RefusesFleetNeedsPki { local_present } => format!(
                "{} `{}` declares a fleet shape: the next boot REFUSES. Fix: {}",
                if *local_present {
                    "the installed certificate was minted by the local CA but"
                } else {
                    "no operator certificate is installed and"
                },
                shape.config_line(),
                crate::transit_encryption::REMEDY_ENTERPRISE_PKI
            ),
            Self::RefusesOperatorExpired { days_ago } => format!(
                "operator-supplied certificate EXPIRED {days_ago} day(s) ago: the next boot \
                 REFUSES. Fix: {}",
                crate::transit_encryption::REMEDY_TLS_RENEW
            ),
            Self::RefusesCertWithoutKey => format!(
                "the certificate `{SERVER_CERT_FILE}` is installed under <key_dir>/tls/ but its \
                 private key `{SERVER_KEY_FILE}` is MISSING: the next boot REFUSES rather than \
                 mint a local certificate OVER it (which would falsely attest the installed \
                 certificate is being served). Fix: {}",
                crate::transit_encryption::REMEDY_SUPPLY_TLS
            ),
            Self::RefusesKeyWithoutCert => format!(
                "the private key `{SERVER_KEY_FILE}` is installed under <key_dir>/tls/ but its \
                 certificate `{SERVER_CERT_FILE}` is MISSING: the next boot REFUSES. Fix: {}",
                crate::transit_encryption::REMEDY_SUPPLY_TLS
            ),
        }
    }
}

/// The ONE predicate behind [`ListenerVerdict`] (see there for the order).
#[must_use]
pub fn listener_verdict(
    status: &LeafStatus,
    shape: crate::config::shape::DeploymentShape,
) -> ListenerVerdict {
    // #3709 F7 — the verdict sees the KEY as well as the certificate. A broken
    // pair is a typed refusal on EVERY shape, BEFORE any serve / mint / shape
    // decision: a lone `server.pem` would otherwise fall through to the local
    // bootstrap (`resolve_local_material` -> `ensure_local_tls`), which mints a
    // local CA + leaf OVER it and serves that `managed`, while this verdict
    // falsely attests the installed certificate is served.
    if status.present && !status.key_present {
        return ListenerVerdict::RefusesCertWithoutKey;
    }
    if status.key_present && !status.present {
        return ListenerVerdict::RefusesKeyWithoutCert;
    }
    let days = status.days_remaining.unwrap_or_default();
    if status.present && status.operator_supplied {
        return if days < 0 {
            ListenerVerdict::RefusesOperatorExpired { days_ago: -days }
        } else {
            ListenerVerdict::ServesOperator { days }
        };
    }
    if shape != crate::config::shape::DeploymentShape::Singleton {
        return ListenerVerdict::RefusesFleetNeedsPki {
            local_present: status.present,
        };
    }
    if !status.present {
        return ListenerVerdict::MintsLocal;
    }
    if status.within_renewal_window {
        ListenerVerdict::RenewsLocal { days }
    } else {
        ListenerVerdict::ServesLocal { days }
    }
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
    let ca = parse_leaf(ca_pem.as_bytes())?;
    if days_until(ca.not_after) <= RENEWAL_WINDOW_DAYS {
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

    // #3709 item 2 — operator-supplied material (`tls import`) is never
    // minted over, renewed or shadowed: it IS the certificate. Expired
    // operator material is a refusal naming its fix, never a re-issue and
    // never plaintext.
    if cert_path.exists() && key_path.exists() {
        let status = leaf_status(key_dir)?;
        if status.operator_supplied {
            let days = status.days_remaining.unwrap_or_default();
            if days < 0 {
                anyhow::bail!(
                    "{}: the operator-supplied certificate {} (issuer {:?}) EXPIRED {} day(s) \
                     ago — refusing to serve it. Fix: {}",
                    crate::transit_encryption::ISSUE_TAG,
                    cert_path.display(),
                    status.issuer,
                    -days,
                    crate::transit_encryption::REMEDY_TLS_RENEW
                );
            }
            return Ok(LocalTls {
                cert_path,
                key_path,
                ca_cert_path: dir.join(OPERATOR_CA_CERT_FILE),
                outcome: Outcome::OperatorSupplied,
                leaf_days_remaining: days,
            });
        }
    }

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
    let dir = local_tls_dir()?;
    // #3709 item 2 — an operator CA installed by `tls import --ca` is the
    // bundled clients' root when present; the local CA otherwise.
    let operator = dir.join(OPERATOR_CA_CERT_FILE);
    let path = if operator.exists() {
        operator
    } else {
        dir.join(LOCAL_CA_CERT_FILE)
    };
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

/// #3709 item 2 — what `ai-memory tls import` verified and installed.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ImportReport {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Set when `--ca` was given: the bundle the bundled clients now trust.
    pub ca_cert_path: Option<PathBuf>,
    pub issuer: String,
    pub subject: String,
    pub subject_alt_names: Vec<String>,
    pub not_after: String,
    pub days_remaining: i64,
    /// Certificates in the supplied file (a fullchain carries more than one).
    pub chain_len: usize,
    /// The host whose SAN coverage was verified, when `--host` was given.
    pub host_checked: Option<String>,
}

/// Normalise a bind host the way [`leaf_subject_alt_names`] does.
fn host_for_san(host: &str) -> String {
    host.trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_string()
}

/// #3709 item 2 — verify an operator's certificate + key pair and install
/// it under `<key_dir>/tls/` as the listener's material. Every check runs
/// BEFORE anything is written, so a refused import leaves the directory
/// exactly as it was: the PEM pair parses the way the listener parses it,
/// the private key matches the leaf (`SubjectPublicKeyInfo` comparison, the
/// listener's own loader), the leaf is not expired, `host` (when given) is
/// covered by a subject alternative name, and `ca_pem` (when given) is the
/// leaf's issuer by name. A fullchain file is accepted (leaf first).
///
/// # Errors
/// Any check above fails — the message names the property, never the key
/// bytes — or the directory cannot be written.
pub fn import_operator_material(
    key_dir: &Path,
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: Option<&[u8]>,
    host: Option<&str>,
) -> Result<ImportReport> {
    let tag = crate::transit_encryption::ISSUE_TAG;
    let chain = crate::tls::rustls_pki_pem_iter_certs(cert_pem)
        .with_context(|| format!("{tag}: --cert is not a PEM certificate (nothing installed)"))?;
    let key = crate::tls::rustls_pki_pem_parse_private_key(key_pem)
        .with_context(|| format!("{tag}: --key is not a PEM private key (nothing installed)"))?;
    let chain_len = chain.len();
    // The explicit ring provider: this verb runs before any process-default
    // provider is installed (the listener installs one at bind time).
    rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(crate::tls::SUPPORTED_PROTOCOL_VERSIONS)
    .map_err(|e| anyhow::anyhow!("{tag}: building the listener configuration: {e}"))?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(|e| {
        anyhow::anyhow!(
            "{tag}: the private key does not match the certificate, or the listener cannot \
                 load the pair ({e}); nothing installed"
        )
    })?;
    let leaf = parse_leaf(cert_pem)?;
    let days = days_until(leaf.not_after);
    if days < 0 {
        anyhow::bail!(
            "{tag}: the certificate EXPIRED {} day(s) ago ({}); nothing installed. Fix: {}",
            -days,
            rfc3339(leaf.not_after),
            crate::transit_encryption::REMEDY_TLS_RENEW
        );
    }
    let host_checked = match host {
        Some(h) => {
            let want = host_for_san(h);
            if !leaf.sans.iter().any(|s| s.eq_ignore_ascii_case(&want)) {
                anyhow::bail!(
                    "{tag}: the certificate does not cover host {want:?} (subject alternative \
                     names: {}); nothing installed",
                    render_sans(&leaf.sans)
                );
            }
            Some(want)
        }
        None => None,
    };
    let dir = key_dir.join(TLS_SUBDIR);
    let operator_ca_path = dir.join(OPERATOR_CA_CERT_FILE);
    match ca_pem {
        Some(ca) => {
            crate::tls::rustls_pki_pem_iter_certs(ca).with_context(|| {
                format!("{tag}: --ca is not a PEM certificate (nothing installed)")
            })?;
            let ca_cert = parse_leaf(ca)?;
            // F3 — the bundle must have ISSUED the leaf (name + signature),
            // not merely carry the issuer's name.
            if !issued_by(&leaf.der, &ca_cert.der) {
                anyhow::bail!(
                    "{tag}: --ca (subject {:?}) did not issue this certificate (issuer {:?}): \
                     the name or the signature does not verify; nothing installed",
                    ca_cert.subject_cn,
                    leaf.issuer_cn
                );
            }
        }
        None => {
            // F5 (#3709 review) — a bundle retained from an earlier import
            // is the bundled clients' trust root; installing a leaf it did
            // not issue would leave them verifying against the wrong root
            // and failing without naming the cause. Refuse, naming the fix.
            if operator_ca_path.exists() {
                let retained = std::fs::read(&operator_ca_path)
                    .with_context(|| read_context(&operator_ca_path))?;
                let retained_ca = parse_leaf(&retained)?;
                if !issued_by(&leaf.der, &retained_ca.der) {
                    anyhow::bail!(
                        "{tag}: the retained CA bundle {} (subject {:?}) did not issue this \
                         certificate (issuer {:?}), so the bundled clients would trust the wrong \
                         root; pass --ca <the issuing bundle> or remove that file first; nothing \
                         installed",
                        operator_ca_path.display(),
                        retained_ca.subject_cn,
                        leaf.issuer_cn
                    );
                }
            }
        }
    }

    ensure_dir(&dir)?;
    let cert_path = dir.join(SERVER_CERT_FILE);
    let key_path = dir.join(SERVER_KEY_FILE);
    write_private(&key_path, key_pem)?;
    write_public(&cert_path, cert_pem)?;
    let ca_cert_path = match ca_pem {
        Some(ca) => {
            write_public(&operator_ca_path, ca)?;
            Some(operator_ca_path)
        }
        // A retained bundle that verified the new leaf stays the trust root.
        None => operator_ca_path.exists().then_some(operator_ca_path),
    };
    Ok(ImportReport {
        cert_path,
        key_path,
        ca_cert_path,
        issuer: leaf.issuer_cn,
        subject: leaf.subject_cn,
        subject_alt_names: leaf.sans,
        not_after: rfc3339(leaf.not_after),
        days_remaining: days,
        chain_len,
        host_checked,
    })
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

    // ---- #3709 item 2: operator material -------------------------------------

    /// An operator PKI: a CA that is NOT the local CA, and a leaf it issued.
    struct OperatorPki {
        ca_pem: String,
        ca_key: KeyPair,
    }

    impl OperatorPki {
        fn new() -> Self {
            Self::named("Example Corp Issuing CA")
        }

        /// A CA with an arbitrary common name — including OUR local CA's
        /// name, which must not fool the discriminator (F3).
        fn named(common_name: &str) -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name = dn(common_name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.not_before = now() - time::Duration::days(1);
            params.not_after = now() + time::Duration::days(3650);
            let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let ca_pem = params.self_signed(&ca_key).unwrap().pem();
            Self { ca_pem, ca_key }
        }

        /// A leaf for `sans`, valid until `not_after`; returns (cert PEM, key PEM).
        fn leaf(&self, sans: &[&str], not_after: time::OffsetDateTime) -> (String, String) {
            let issuer = Issuer::from_ca_cert_pem(
                &self.ca_pem,
                KeyPair::from_pem(&self.ca_key.serialize_pem()).unwrap(),
            )
            .unwrap();
            let mut params =
                CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
                    .unwrap();
            params.distinguished_name = dn("memory.example.test");
            params.not_before = now() - time::Duration::days(2);
            params.not_after = not_after;
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            (cert.pem(), key.serialize_pem())
        }
    }

    fn tls_dir_listing(key_dir: &Path) -> Vec<String> {
        let dir = key_dir.join(TLS_SUBDIR);
        if !dir.exists() {
            return Vec::new();
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// P1 (presence): a valid operator pair passes every listener check,
    /// lands with private modes, and reads back as operator-supplied with
    /// the issuer the artefact names.
    #[test]
    fn issue_3709_import_installs_a_valid_operator_pair_with_private_modes() {
        let tmp = sandbox();
        let pki = OperatorPki::new();
        let (cert, key) = pki.leaf(
            &["memory.example.test", "10.9.8.7"],
            now() + time::Duration::days(200),
        );
        let report = import_operator_material(
            tmp.path(),
            cert.as_bytes(),
            key.as_bytes(),
            Some(pki.ca_pem.as_bytes()),
            Some("memory.example.test"),
        )
        .expect("a valid pair installs");
        assert_eq!(report.issuer, "Example Corp Issuing CA");
        assert_eq!(report.subject, "memory.example.test");
        assert_eq!(report.chain_len, 1);
        assert_eq!(report.host_checked.as_deref(), Some("memory.example.test"));
        assert!(report.days_remaining >= 199, "{}", report.days_remaining);
        assert_eq!(
            tls_dir_listing(tmp.path()),
            vec![
                OPERATOR_CA_CERT_FILE.to_string(),
                SERVER_KEY_FILE.to_string(),
                SERVER_CERT_FILE.to_string()
            ]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&report.key_path), MODE_PRIVATE);
            assert_eq!(mode(&report.cert_path), MODE_PUBLIC);
            assert_eq!(mode(&tmp.path().join(TLS_SUBDIR)), MODE_DIR);
        }
        let status = leaf_status(tmp.path()).unwrap();
        assert!(status.present && status.operator_supplied);
        assert_eq!(status.issuer, "Example Corp Issuing CA");
        assert!(status.subject_alt_names.iter().any(|s| s == "10.9.8.7"));
        assert!(operator_material_present(tmp.path()).unwrap());
        // The bundled clients' root is the operator CA now.
        let parsed_ca = parse_leaf(pki.ca_pem.as_bytes()).unwrap();
        assert_eq!(parsed_ca.subject_cn, status.issuer);
    }

    /// P2 (absence + control): a mismatched key, an expired leaf, a leaf that
    /// does not cover `--host`, and a CA that is not the issuer each REFUSE
    /// naming the property, and NOTHING is written; the same leaf without
    /// `--host` (the control) installs.
    #[test]
    fn issue_3709_import_refuses_each_bad_input_and_writes_nothing() {
        let pki = OperatorPki::new();
        let (cert, key) = pki.leaf(&["memory.example.test"], now() + time::Duration::days(200));

        // Mismatched key: a key that never signed anything in this PKI.
        let tmp = sandbox();
        let other_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_pem();
        let err = import_operator_material(
            tmp.path(),
            cert.as_bytes(),
            other_key.as_bytes(),
            None,
            None,
        )
        .expect_err("a mismatched key must be refused")
        .to_string();
        assert!(err.contains("does not match the certificate"), "{err}");
        assert!(err.contains("nothing installed"), "{err}");
        assert!(tls_dir_listing(tmp.path()).is_empty(), "{err}");

        // Expired leaf (signed by the same PKI, valid key).
        let tmp = sandbox();
        let (old_cert, old_key) =
            pki.leaf(&["memory.example.test"], now() - time::Duration::days(3));
        let err = import_operator_material(
            tmp.path(),
            old_cert.as_bytes(),
            old_key.as_bytes(),
            None,
            None,
        )
        .expect_err("an expired leaf must be refused")
        .to_string();
        assert!(
            err.contains("EXPIRED 3 day(s) ago") || err.contains("EXPIRED 2 day(s) ago"),
            "{err}"
        );
        assert!(
            err.contains(crate::transit_encryption::REMEDY_TLS_RENEW),
            "{err}"
        );
        assert!(tls_dir_listing(tmp.path()).is_empty());

        // Host not covered.
        let tmp = sandbox();
        let err = import_operator_material(
            tmp.path(),
            cert.as_bytes(),
            key.as_bytes(),
            None,
            Some("other.example.test"),
        )
        .expect_err("an uncovered host must be refused")
        .to_string();
        assert!(
            err.contains("does not cover host \"other.example.test\""),
            "{err}"
        );
        assert!(
            err.contains("memory.example.test"),
            "the SANs are listed: {err}"
        );
        assert!(tls_dir_listing(tmp.path()).is_empty());

        // A CA that is not the issuer.
        let tmp = sandbox();
        let stranger = OperatorPki::new();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = dn("Some Other CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let stranger_pem = params.self_signed(&stranger.ca_key).unwrap().pem();
        let err = import_operator_material(
            tmp.path(),
            cert.as_bytes(),
            key.as_bytes(),
            Some(stranger_pem.as_bytes()),
            None,
        )
        .expect_err("a CA that did not issue the leaf must be refused")
        .to_string();
        assert!(
            err.contains("--ca (subject \"Some Other CA\") did not issue this certificate"),
            "{err}"
        );
        assert!(
            err.contains("the name or the signature does not verify"),
            "{err}"
        );
        assert!(tls_dir_listing(tmp.path()).is_empty());

        // Control: the same valid pair, no --host, no --ca — installs.
        let report =
            import_operator_material(tmp.path(), cert.as_bytes(), key.as_bytes(), None, None)
                .expect("the control installs");
        assert!(report.host_checked.is_none() && report.ca_cert_path.is_none());
        assert_eq!(
            tls_dir_listing(tmp.path()),
            vec![SERVER_KEY_FILE.to_string(), SERVER_CERT_FILE.to_string()]
        );
    }

    /// P3: the bootstrap never mints over operator material (it is the
    /// certificate, on any host), and an expired operator leaf REFUSES
    /// naming the fix instead of being re-issued or served.
    #[test]
    fn issue_3709_bootstrap_keeps_operator_material_and_refuses_it_expired() {
        let tmp = sandbox();
        let pki = OperatorPki::new();
        let (cert, key) = pki.leaf(&["memory.example.test"], now() + time::Duration::days(200));
        import_operator_material(tmp.path(), cert.as_bytes(), key.as_bytes(), None, None).unwrap();
        let before = std::fs::read(tmp.path().join(TLS_SUBDIR).join(SERVER_CERT_FILE)).unwrap();
        // A bind host the operator leaf does not cover would trigger a
        // renewal for a LOCAL leaf; operator material is left alone.
        let local = ensure_local_tls(tmp.path(), "10.1.2.3").expect("operator material serves");
        assert_eq!(local.outcome, Outcome::OperatorSupplied);
        assert_eq!(
            std::fs::read(&local.cert_path).unwrap(),
            before,
            "the operator leaf is byte-identical after the bootstrap"
        );
        assert!(
            !tmp.path().join(TLS_SUBDIR).join(LOCAL_CA_KEY_FILE).exists(),
            "no local CA was minted alongside operator material"
        );
        assert_eq!(
            tls_dir_listing(tmp.path()),
            vec![SERVER_KEY_FILE.to_string(), SERVER_CERT_FILE.to_string()]
        );

        // Expired operator material, copied in by hand (import refuses it).
        let tmp = sandbox();
        let (old_cert, old_key) =
            pki.leaf(&["memory.example.test"], now() - time::Duration::days(3));
        let dir = tmp.path().join(TLS_SUBDIR);
        ensure_dir(&dir).unwrap();
        write_public(&dir.join(SERVER_CERT_FILE), old_cert.as_bytes()).unwrap();
        write_private(&dir.join(SERVER_KEY_FILE), old_key.as_bytes()).unwrap();
        let err = ensure_local_tls(tmp.path(), "127.0.0.1")
            .expect_err("expired operator material must refuse")
            .to_string();
        assert!(err.contains("operator-supplied certificate"), "{err}");
        assert!(err.contains("EXPIRED"), "{err}");
        assert!(
            err.contains(crate::transit_encryption::REMEDY_TLS_RENEW),
            "{err}"
        );
        assert_eq!(
            std::fs::read(dir.join(SERVER_CERT_FILE)).unwrap(),
            old_cert.as_bytes(),
            "a refusal re-issues nothing"
        );
        // Control: a locally minted leaf on the same sandbox shape IS
        // re-issued (the existing renewal path), never refused.
        let tmp = sandbox();
        let first = ensure_local_tls(tmp.path(), "127.0.0.1").unwrap();
        let status = leaf_status(tmp.path()).unwrap();
        assert!(!status.operator_supplied);
        assert_eq!(status.issuer, CA_COMMON_NAME);
        assert_eq!(first.outcome, Outcome::Generated);
    }

    /// F3 (#3709 review) — "operator-supplied" is decided by the CA this
    /// key directory HOLDS, never by a common-name string: an enterprise CA
    /// named exactly like the local CA still yields operator-supplied
    /// material (the bootstrap must not renew over it), a leaf minted by
    /// ANOTHER installation's local CA is likewise not ours, and only a leaf
    /// that verifies under our own local-ca.pem is locally minted.
    #[test]
    fn issue_3709_f3_operator_supplied_is_decided_by_our_ca_not_by_a_name() {
        // Our own installation: mint, then the leaf verifies under our CA.
        let tmp = sandbox();
        let ours = ensure_local_tls(tmp.path(), "127.0.0.1").unwrap();
        assert_eq!(ours.outcome, Outcome::Generated);
        let status = leaf_status(tmp.path()).unwrap();
        assert!(!status.operator_supplied, "our own leaf is locally minted");
        assert_eq!(status.issuer, CA_COMMON_NAME);

        // A look-alike enterprise CA carrying OUR common name.
        let lookalike = OperatorPki::named(CA_COMMON_NAME);
        let (cert, key) =
            lookalike.leaf(&["memory.example.test"], now() + time::Duration::days(200));
        import_operator_material(tmp.path(), cert.as_bytes(), key.as_bytes(), None, None)
            .expect("an operator pair installs beside the local CA");
        let status = leaf_status(tmp.path()).unwrap();
        assert_eq!(status.issuer, CA_COMMON_NAME, "the NAME is identical");
        assert!(
            status.operator_supplied,
            "F3: a leaf the local CA did not sign is operator-supplied whatever its issuer says"
        );
        // ...and the bootstrap keeps it (never renews over it) on any host.
        let kept = ensure_local_tls(tmp.path(), "10.9.9.9").unwrap();
        assert_eq!(kept.outcome, Outcome::OperatorSupplied);
        assert_eq!(
            std::fs::read(&kept.cert_path).unwrap(),
            cert.as_bytes(),
            "byte-identical after the bootstrap"
        );

        // A leaf minted by ANOTHER installation's local CA, copied in by hand.
        let other = sandbox();
        let theirs = ensure_local_tls(other.path(), "127.0.0.1").unwrap();
        let dir = tmp.path().join(TLS_SUBDIR);
        write_public(
            &dir.join(SERVER_CERT_FILE),
            &std::fs::read(&theirs.cert_path).unwrap(),
        )
        .unwrap();
        write_private(
            &dir.join(SERVER_KEY_FILE),
            &std::fs::read(&theirs.key_path).unwrap(),
        )
        .unwrap();
        let status = leaf_status(tmp.path()).unwrap();
        assert_eq!(status.issuer, CA_COMMON_NAME);
        assert!(
            status.operator_supplied,
            "another installation's leaf does not verify under OUR local CA"
        );
        // No local CA on disk at all: nothing can be ours.
        let bare = sandbox();
        let dir = bare.path().join(TLS_SUBDIR);
        ensure_dir(&dir).unwrap();
        write_public(
            &dir.join(SERVER_CERT_FILE),
            &std::fs::read(&ours.cert_path).unwrap(),
        )
        .unwrap();
        write_private(
            &dir.join(SERVER_KEY_FILE),
            &std::fs::read(&ours.key_path).unwrap(),
        )
        .unwrap();
        assert!(leaf_status(bare.path()).unwrap().operator_supplied);
    }

    /// F5 (#3709 review) — a CA bundle retained from an earlier import is
    /// the bundled clients' trust root: an import WITHOUT `--ca` of a leaf
    /// that bundle did not issue is REFUSED naming the file and the fix,
    /// and nothing is written; a leaf the retained bundle DID issue installs
    /// (the bundle stays the root); `--ca` with the new issuer replaces it.
    /// `--ca` itself must have ISSUED the leaf (name + signature), not
    /// merely carry the issuer's name.
    #[test]
    fn issue_3709_f5_a_stale_retained_ca_bundle_refuses_a_foreign_leaf() {
        let tmp = sandbox();
        let a = OperatorPki::new();
        let (cert_a, key_a) = a.leaf(&["memory.example.test"], now() + time::Duration::days(200));
        import_operator_material(
            tmp.path(),
            cert_a.as_bytes(),
            key_a.as_bytes(),
            Some(a.ca_pem.as_bytes()),
            None,
        )
        .expect("first import with its bundle");
        let bundle_path = tmp.path().join(TLS_SUBDIR).join(OPERATOR_CA_CERT_FILE);
        assert_eq!(std::fs::read(&bundle_path).unwrap(), a.ca_pem.as_bytes());
        let before = tls_dir_listing(tmp.path());
        let installed_a =
            std::fs::read(tmp.path().join(TLS_SUBDIR).join(SERVER_CERT_FILE)).unwrap();

        // A leaf from a DIFFERENT issuer, no --ca: refused, nothing written.
        let b = OperatorPki::named("Other Corp Issuing CA");
        let (cert_b, key_b) = b.leaf(&["memory.example.test"], now() + time::Duration::days(200));
        let err =
            import_operator_material(tmp.path(), cert_b.as_bytes(), key_b.as_bytes(), None, None)
                .expect_err("F5: the retained bundle did not issue this leaf")
                .to_string();
        assert!(err.contains("retained CA bundle"), "{err}");
        assert!(
            err.contains(&bundle_path.display().to_string()),
            "names the file: {err}"
        );
        assert!(
            err.contains("pass --ca <the issuing bundle> or remove that file"),
            "{err}"
        );
        assert!(err.contains("nothing installed"), "{err}");
        assert_eq!(tls_dir_listing(tmp.path()), before);
        assert_eq!(
            std::fs::read(tmp.path().join(TLS_SUBDIR).join(SERVER_CERT_FILE)).unwrap(),
            installed_a,
            "the installed leaf is untouched"
        );

        // A second leaf from the SAME issuer, no --ca: the retained bundle
        // verifies it, so it installs and the bundle stays (control).
        let (cert_a2, key_a2) = a.leaf(&["memory.example.test"], now() + time::Duration::days(300));
        let report = import_operator_material(
            tmp.path(),
            cert_a2.as_bytes(),
            key_a2.as_bytes(),
            None,
            None,
        )
        .expect("the retained bundle issued this leaf");
        assert_eq!(report.ca_cert_path.as_deref(), Some(bundle_path.as_path()));
        assert_eq!(std::fs::read(&bundle_path).unwrap(), a.ca_pem.as_bytes());

        // --ca that merely NAMES the issuer but did not sign the leaf: refused.
        let impostor = OperatorPki::named("Other Corp Issuing CA");
        let err = import_operator_material(
            tmp.path(),
            cert_b.as_bytes(),
            key_b.as_bytes(),
            Some(impostor.ca_pem.as_bytes()),
            None,
        )
        .expect_err("a --ca with the right name but the wrong key did not issue the leaf")
        .to_string();
        assert!(err.contains("did not issue this certificate"), "{err}");
        assert!(
            err.contains("the name or the signature does not verify"),
            "{err}"
        );
        assert_eq!(
            std::fs::read(&bundle_path).unwrap(),
            a.ca_pem.as_bytes(),
            "bundle untouched"
        );

        // --ca with the real new issuer: installs and REPLACES the bundle.
        let report = import_operator_material(
            tmp.path(),
            cert_b.as_bytes(),
            key_b.as_bytes(),
            Some(b.ca_pem.as_bytes()),
            None,
        )
        .expect("the issuing bundle replaces the retained one");
        assert_eq!(report.issuer, "Other Corp Issuing CA");
        assert_eq!(std::fs::read(&bundle_path).unwrap(), b.ca_pem.as_bytes());
    }

    /// F4 (#3709 review) — subject alternative names are foreign text from
    /// the artefact; every rendering escapes them like issuer / subject.
    #[test]
    fn issue_3709_f4_sans_render_escaped() {
        assert_eq!(render_sans(&[]), "none");
        let rendered = render_sans(&["localhost".to_string(), "a\u{7}b".to_string()]);
        assert_eq!(rendered, "\"localhost\", \"a\\u{7}b\"");
        assert!(
            !rendered.contains('\u{7}'),
            "no control byte reaches the terminal"
        );
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
