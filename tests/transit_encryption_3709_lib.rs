// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3705 / #3709 — the library halves of the transit-encryption floor that
//! need NEW crate API (`transit_encryption`, `tls_bootstrap`,
//! `daemon_runtime::resolve_tls_material`). Kept apart from
//! `tests/transit_encryption_3705.rs`, which is copied verbatim onto the
//! release head for the fails-on-head proof and must compile there; this
//! file does not compile on that head at all (the API does not exist), which
//! is its own negative proof.

use std::path::Path;
use std::sync::Mutex;

mod common;
use common::tls::TestTls;
#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

/// The DECLARED singleton shape (`[deployment] shape` absent or
/// `"singleton"`): the only shape that mints the local CA (#3709 ruling).
fn singleton_shape() -> ai_memory::config::shape::DeploymentShape {
    ai_memory::config::shape::DeploymentShape::Singleton
}

/// A DECLARED fleet shape (`[deployment] shape = "federated"`): enterprise
/// PKI first-class, nothing minted. The declaration is the operator's act —
/// an observed signal never promotes a node into this branch (#3700 ruling).
fn fleet_shape() -> ai_memory::config::shape::DeploymentShape {
    ai_memory::config::shape::DeploymentShape::Federated
}

/// Process-wide lock for the env-reading token matrix.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn key_dir(root: &Path) -> std::path::PathBuf {
    let dir = root.join("keys");
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// Item 2 — ONE truthy grammar through the resolver: every canonical truthy
/// token affirms the floor, unset is the floor, a falsy token is a refused
/// downgrade request, an unrecognised token refuses; both refusals name
/// the fix (`unset AI_MEMORY_REQUIRE_TLS`).
#[test]
fn require_tls_token_grammar_3705() {
    use ai_memory::transit_encryption::{RequireTls, enforce_require_tls_token, require_tls_token};
    let _g = ENV_LOCK.lock().unwrap();
    for token in ["1", "true", "yes", "on", "TRUE", " on "] {
        // SAFETY: serialised by ENV_LOCK; no child inherits this env.
        unsafe { std::env::set_var("AI_MEMORY_REQUIRE_TLS", token) };
        assert_eq!(require_tls_token(), RequireTls::Affirmed, "{token:?}");
        assert!(enforce_require_tls_token().is_ok(), "{token:?}");
    }
    for token in ["0", "false", "no", "off"] {
        // SAFETY: as above.
        unsafe { std::env::set_var("AI_MEMORY_REQUIRE_TLS", token) };
        assert!(
            matches!(require_tls_token(), RequireTls::DowngradeRequested(_)),
            "{token:?}"
        );
        let err = enforce_require_tls_token()
            .expect_err("falsy is a refused downgrade")
            .to_string();
        assert!(
            err.contains("#3705") && err.contains("impossible to select"),
            "{err}"
        );
        assert!(err.contains("unset AI_MEMORY_REQUIRE_TLS"), "{err}");
        assert!(
            err.contains("--tls-cert <fullchain.pem> --tls-key <key.pem>"),
            "{err}"
        );
    }
    // SAFETY: as above.
    unsafe { std::env::set_var("AI_MEMORY_REQUIRE_TLS", "maybe") };
    assert!(matches!(
        require_tls_token(),
        RequireTls::Unrecognised(ref v) if v == "maybe"
    ));
    let err = enforce_require_tls_token()
        .expect_err("unrecognised refuses")
        .to_string();
    assert!(err.contains("not a recognised token"), "{err}");
    assert!(err.contains("unset AI_MEMORY_REQUIRE_TLS"), "{err}");
    // SAFETY: as above.
    unsafe { std::env::remove_var("AI_MEMORY_REQUIRE_TLS") };
    assert_eq!(require_tls_token(), RequireTls::Floor);
    assert!(enforce_require_tls_token().is_ok());
}

/// Item 4 — the removed downgrade paths, through the resolver, name the
/// variable and the fix.
#[test]
fn removed_downgrade_paths_named_with_remedy_3705() {
    use ai_memory::transit_encryption::{
        REMOVED_DOWNGRADE_ENVS, armed_downgrade_paths, enforce_no_downgrade_paths,
    };
    let _g = ENV_LOCK.lock().unwrap();
    for env in REMOVED_DOWNGRADE_ENVS {
        // SAFETY: serialised by ENV_LOCK.
        unsafe { std::env::remove_var(env) };
    }
    assert!(armed_downgrade_paths().is_empty());
    assert!(enforce_no_downgrade_paths().is_ok());
    for env in REMOVED_DOWNGRADE_ENVS {
        // SAFETY: as above.
        unsafe { std::env::set_var(env, "yes") };
        assert_eq!(armed_downgrade_paths(), vec![*env]);
        let err = enforce_no_downgrade_paths()
            .expect_err("an armed downgrade path refuses")
            .to_string();
        assert!(err.contains("#3705") && err.contains(env), "{err}");
        assert!(err.contains("downgrade path"), "{err}");
        assert!(err.contains(&format!("unset {env}")), "{err}");
        // A falsy / unrecognised token does not arm it (FBL-14 both ways).
        for tok in ["0", "off", "maybe", ""] {
            // SAFETY: as above.
            unsafe { std::env::set_var(env, tok) };
            assert!(armed_downgrade_paths().is_empty(), "{env}={tok:?}");
        }
        // SAFETY: as above.
        unsafe { std::env::remove_var(env) };
    }
}

/// #3709 item 5 — a HALF-configured pair is refused by the resolver every
/// listener takes, with the remedy; never a plaintext fallback.
#[test]
fn half_configured_tls_pair_refuses_with_remedy_3709() {
    let root = tempfile::tempdir().unwrap();
    let tls = TestTls::generate(&root.path().join("tls-3705"));
    for (cert, key) in [
        (Some(tls.cert_path.as_path()), None),
        (None, Some(tls.key_path.as_path())),
    ] {
        let err = ai_memory::daemon_runtime::resolve_tls_material(
            cert,
            key,
            "127.0.0.1",
            9077,
            singleton_shape(),
        )
        .err()
        .map(|e| format!("{e:#}"))
        .expect("#3709: a half-configured TLS pair must be refused");
        assert!(err.contains("#3705"), "{err}");
        assert!(
            err.contains("--tls-cert <fullchain.pem> --tls-key <key.pem>"),
            "{err}"
        );
        assert!(err.contains("--tls-cert/--tls-key"), "{err}");
    }
    // The full pair resolves to exactly the operator's files, unmanaged.
    let material = ai_memory::daemon_runtime::resolve_tls_material(
        Some(tls.cert_path.as_path()),
        Some(tls.key_path.as_path()),
        "127.0.0.1",
        9077,
        fleet_shape(),
    )
    .expect("a full pair resolves on any shape");
    assert_eq!(material.cert_path, tls.cert_path);
    assert_eq!(material.key_path, tls.key_path);
    assert!(!material.managed);
}

/// #3709 item 5 — generation into a read-only key directory refuses (never
/// plaintext) and writes nothing.
#[cfg(unix)]
#[test]
fn unwritable_key_dir_refuses_via_library_3709() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let dir = key_dir(root.path());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let res = ai_memory::tls_bootstrap::ensure_local_tls(&dir, "127.0.0.1");
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    assert!(
        res.is_err(),
        "#3709: a read-only key dir must refuse, never yield plaintext"
    );
    assert!(
        !dir.join(ai_memory::tls_bootstrap::TLS_SUBDIR)
            .join(ai_memory::tls_bootstrap::SERVER_KEY_FILE)
            .exists()
    );
}

/// #3709 — the local leaf is REUSED while valid and covering the host, and
/// RE-ISSUED from the unchanged CA when a new bind host is not covered.
#[test]
fn renewal_reissues_leaf_inside_window_3709() {
    use ai_memory::tls_bootstrap::{
        LOCAL_CA_CERT_FILE, Outcome, TLS_SUBDIR, ensure_local_tls, leaf_status,
    };
    let root = tempfile::tempdir().unwrap();
    let dir = key_dir(root.path());
    let first = ensure_local_tls(&dir, "127.0.0.1").expect("first boot generates");
    assert_eq!(first.outcome, Outcome::Generated);
    assert!(first.leaf_days_remaining > 0);
    let ca_before = std::fs::read(dir.join(TLS_SUBDIR).join(LOCAL_CA_CERT_FILE)).unwrap();

    let second = ensure_local_tls(&dir, "127.0.0.1").expect("second boot reuses");
    assert_eq!(second.outcome, Outcome::Reused);

    let third = ensure_local_tls(&dir, "10.9.8.7").expect("new host re-issues");
    assert!(
        matches!(third.outcome, Outcome::Renewed { .. }),
        "{:?}",
        third.outcome
    );
    let status = leaf_status(&dir).expect("leaf status");
    assert!(status.present);
    assert!(
        status.subject_alt_names.iter().any(|s| s == "10.9.8.7"),
        "{:?}",
        status.subject_alt_names
    );
    let ca_after = std::fs::read(dir.join(TLS_SUBDIR).join(LOCAL_CA_CERT_FILE)).unwrap();
    assert_eq!(
        ca_before, ca_after,
        "renewal re-issues the leaf, never the CA"
    );
    // The re-issued leaf is what the bundled client trusts through the CA.
    let ca = reqwest::Certificate::from_pem(&ca_after).expect("CA parses");
    let _client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .build()
        .expect("CA-trusting client builds");
}

/// #3709 (3x7 audit ruling) — the local CA is minted for the SINGLETON shape
/// only: a DECLARED fleet shape without an operator pair is refused,
/// naming enterprise PKI as the path; a singleton without a pair still mints.
#[test]
fn fleet_shape_without_certs_refuses_naming_enterprise_pki_3709() {
    // In-process minting writes into the process key dir: arm the shared
    // sandbox so nothing touches a real keystore (#3198/#3516).
    let sandbox = key_dir_sandbox::pin();
    // Every declared shape but `singleton` — team included — refuses without
    // an operator pair; the refusal names the declaration itself.
    for declared in ai_memory::config::shape::DeploymentShape::ALL
        .into_iter()
        .filter(|s| *s != singleton_shape())
    {
        let err = ai_memory::daemon_runtime::resolve_tls_material(
            None,
            None,
            "127.0.0.1",
            9077,
            declared,
        )
        .err()
        .map(|e| format!("{e:#}"))
        .expect(
            "#3709: a declared non-singleton shape without --tls-cert/--tls-key must be refused",
        );
        assert!(err.contains("#3705"), "{err}");
        assert!(err.contains("FLEET-shaped"), "{err}");
        assert!(err.contains("enterprise PKI"), "{err}");
        assert!(err.contains("--tls-cert <fullchain.pem>"), "{err}");
        assert!(
            !err.contains("ai-memory tls"),
            "no fictional verb in a remedy: {err}"
        );
        assert!(err.contains("Bring your own certificate"), "{err}");
        assert!(
            err.contains(&declared.config_line()),
            "the refusal names the operator's declaration, not an observed signal: {err}"
        );
        assert!(
            !sandbox.join(ai_memory::tls_bootstrap::TLS_SUBDIR).exists(),
            "a fleet refusal must mint nothing ({declared:?})"
        );
    }

    let minted = ai_memory::daemon_runtime::resolve_tls_material(
        None,
        None,
        "127.0.0.1",
        9077,
        singleton_shape(),
    )
    .expect("a singleton without a pair mints the local certificate");
    assert!(minted.managed);
    assert!(minted.cert_path.starts_with(sandbox));
    assert!(
        sandbox
            .join(ai_memory::tls_bootstrap::TLS_SUBDIR)
            .join(ai_memory::tls_bootstrap::SERVER_CERT_FILE)
            .is_file()
    );
}
