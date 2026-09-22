// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3709 item 2 (review F1 / F6) — the DAEMON seam: `resolve_tls_material`
//! is the function `serve` refuses or serves by, and it must honour
//! operator material installed with `ai-memory tls import` on a FLEET shape
//! (the presence half of the fleet rule pinned in
//! `tests/transit_encryption_3709_lib.rs`), and must surface a corrupt
//! installed leaf as its own typed refusal, never as "no PKI".
//!
//! Own process: the pins write into the process key-dir sandbox
//! (`key_dir_sandbox::pin()`), which the sibling file also uses for its
//! absence cell, so they cannot share a binary.
//!
//! RED legs: on the fixed tree with `&& !imported` deleted (the reviewer's
//! mutation M3) / the verdict short-circuited, `fleet_shape_serves_imported_
//! operator_material_3709` fails; on `17205b2b9` (the rejected cut)
//! `corrupt_installed_leaf_is_its_own_refusal_3709` fails on the message.

use std::path::Path;
use std::sync::Mutex;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

/// Both cells write into the ONE process sandbox: serialise them and start
/// each from an empty `tls/`.
static SANDBOX_LOCK: Mutex<()> = Mutex::new(());

fn fresh_tls_dir(sandbox: &Path) -> std::path::PathBuf {
    let dir = sandbox.join(ai_memory::tls_bootstrap::TLS_SUBDIR);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for f in [
        ai_memory::tls_bootstrap::SERVER_CERT_FILE,
        ai_memory::tls_bootstrap::SERVER_KEY_FILE,
        ai_memory::tls_bootstrap::OPERATOR_CA_CERT_FILE,
        ai_memory::tls_bootstrap::LOCAL_CA_CERT_FILE,
        ai_memory::tls_bootstrap::LOCAL_CA_KEY_FILE,
    ] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    dir
}

use ai_memory::config::shape::DeploymentShape;

/// An operator PKI: a CA that is NOT the local CA, and a leaf it issued.
fn operator_pair() -> (String, String, String) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example Corp Issuing CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_pem = params.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::from_ca_cert_pem(
        &ca_pem,
        rcgen::KeyPair::from_pem(&ca_key.serialize_pem()).unwrap(),
    )
    .unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec!["memory.example.test".to_string()]).unwrap();
    leaf.distinguished_name
        .push(rcgen::DnType::CommonName, "memory.example.test");
    let now = time::OffsetDateTime::now_utc();
    leaf.not_before = now - time::Duration::days(1);
    leaf.not_after = now + time::Duration::days(200);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = leaf.signed_by(&key, &issuer).unwrap();
    (cert.pem(), key.serialize_pem(), ca_pem)
}

fn tls_dir(sandbox: &Path) -> std::path::PathBuf {
    sandbox.join(ai_memory::tls_bootstrap::TLS_SUBDIR)
}

/// F1 — PRESENCE at the daemon seam: on every fleet shape, imported
/// operator material is accepted (`Ok`), unmanaged (`managed == false`),
/// and IS the imported leaf; the local CA is never minted beside it. The
/// singleton shape serves it too.
#[test]
fn fleet_shape_serves_imported_operator_material_3709() {
    let _serial = SANDBOX_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let sandbox = key_dir_sandbox::pin();
    fresh_tls_dir(sandbox);
    let (cert, key, ca) = operator_pair();
    let report = ai_memory::tls_bootstrap::import_operator_material(
        sandbox,
        cert.as_bytes(),
        key.as_bytes(),
        Some(ca.as_bytes()),
        Some("memory.example.test"),
    )
    .expect("import into the sandbox");
    assert_eq!(report.issuer, "Example Corp Issuing CA");

    for declared in DeploymentShape::ALL {
        let material = ai_memory::daemon_runtime::resolve_tls_material(
            None,
            None,
            "127.0.0.1",
            9077,
            declared,
        )
        .unwrap_or_else(|e| {
            panic!("#3709 F1: imported operator material must serve under {declared:?}: {e:#}")
        });
        assert!(
            !material.managed,
            "operator material is never managed (renewed) by the daemon ({declared:?})"
        );
        assert_eq!(
            material.cert_path,
            tls_dir(sandbox).join(ai_memory::tls_bootstrap::SERVER_CERT_FILE),
            "the listener serves the IMPORTED leaf ({declared:?})"
        );
        assert_eq!(
            std::fs::read(&material.cert_path).unwrap(),
            cert.as_bytes(),
            "byte-identical to what was imported ({declared:?})"
        );
        assert_eq!(
            material.ca_cert_path.as_deref(),
            Some(
                tls_dir(sandbox)
                    .join(ai_memory::tls_bootstrap::OPERATOR_CA_CERT_FILE)
                    .as_path()
            ),
            "the bundled clients' root is the imported bundle ({declared:?})"
        );
        assert!(
            !tls_dir(sandbox)
                .join(ai_memory::tls_bootstrap::LOCAL_CA_KEY_FILE)
                .exists(),
            "no local CA is minted beside operator material ({declared:?})"
        );
    }
}

/// F6 — a corrupt installed leaf is its OWN typed refusal on every shape:
/// the error names the tls directory and the re-install fix, never the
/// fleet "enterprise PKI missing" text, and never mints over the file.
#[test]
fn corrupt_installed_leaf_is_its_own_refusal_3709() {
    let _serial = SANDBOX_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let sandbox = key_dir_sandbox::pin();
    let dir = fresh_tls_dir(sandbox);
    let leaf = dir.join(ai_memory::tls_bootstrap::SERVER_CERT_FILE);
    std::fs::write(
        &leaf,
        b"-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(ai_memory::tls_bootstrap::SERVER_KEY_FILE),
        b"garbage",
    )
    .unwrap();
    let before = std::fs::read(&leaf).unwrap();
    for declared in [DeploymentShape::Team, DeploymentShape::Singleton] {
        let err = ai_memory::daemon_runtime::resolve_tls_material(
            None,
            None,
            "127.0.0.1",
            9077,
            declared,
        )
        .err()
        .map(|e| format!("{e:#}"))
        .expect("a corrupt leaf refuses");
        assert!(err.contains("#3705"), "{err}");
        assert!(err.contains("cannot be read"), "{err}");
        assert!(
            err.contains(&dir.display().to_string()),
            "names the directory: {err}"
        );
        assert!(
            err.contains("`ai-memory tls import"),
            "names the re-install fix: {err}"
        );
        assert!(
            !err.contains("enterprise PKI") && !err.contains("FLEET-shaped"),
            "F6: a parse failure is not a missing-PKI verdict ({declared:?}): {err}"
        );
        assert_eq!(std::fs::read(&leaf).unwrap(), before, "never minted over");
    }
}
