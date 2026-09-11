// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Actual binary boot/doctor checks. Environment is supplied only to child
//! processes; no process-global mutation or shared test lock is required.

use std::path::Path;
use std::process::{Command, Output};

use ai_memory::config::{FeatureTier, ResolvedModels};
use ai_memory::mcp::{
    CapabilitiesAccept, handle_capabilities_with_conn, handle_capabilities_with_conn_v3,
};

const SCOPED: &str = r#"{"peer":{"allowed_namespaces":["team/**"]}}"#;

fn command(root: &Path, posture: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", root.join("keys"))
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_SECURITY_PROFILE", posture);
    cmd
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn quorum_zero_and_sync_daemon_refuse_before_database_open_3582() {
    for args in [
        vec![
            "serve",
            "--quorum-writes",
            "0",
            "--quorum-peers",
            "https://127.0.0.1:1",
        ],
        vec!["sync-daemon", "--peers", "https://127.0.0.1:1"],
    ] {
        for allowlist in [
            None,
            Some(""),
            Some("   "),
            Some("{}"),
            Some("invalid-json"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut cmd = command(root.path(), "asi-hard");
            cmd.args(&args);
            if let Some(value) = allowlist {
                cmd.env("AI_MEMORY_FED_PEER_ATTESTATION", value);
            }
            let out = cmd.output().unwrap();
            assert!(!out.status.success());
            assert!(stderr(&out).contains("#3582"), "{}", stderr(&out));
            assert!(stderr(&out).contains("AI_MEMORY_FED_PEER_ATTESTATION"));
            assert!(!root.path().join("store.db").exists());
        }
    }
}

#[test]
fn inbound_only_public_enrollment_refuses_and_doctor_still_reports_3582() {
    for posture in ["standard", "asi-hard"] {
        let root = tempfile::tempdir().unwrap();
        let key = ai_memory::identity::keypair::generate("region/peer").unwrap();
        ai_memory::identity::keypair::save_public_only(&key, &root.path().join("keys")).unwrap();
        let out = command(root.path(), posture)
            .env("AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE", "1")
            .args(["serve", "--host", "0.0.0.0"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(stderr(&out).contains("#3582"), "{}", stderr(&out));
        if posture == "standard" {
            assert!(stderr(&out).contains("WARN #3582"));
        }
        assert!(!root.path().join("store.db").exists());
        let out = command(root.path(), posture)
            .args(["doctor", "--json"])
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!("doctor must render despite refusal: {e}; {}", stderr(&out))
        });
        let section = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Federation peer authorization")
            .unwrap();
        assert_eq!(
            section["severity"],
            if posture == "asi-hard" {
                "critical"
            } else {
                "warning"
            }
        );
        let facts = section["facts"].to_string();
        assert!(facts.contains("unobservable from this process"));
        assert!(facts.contains("present"));
        assert!(section["note"].as_str().unwrap().contains("#3582"));
    }
}

#[test]
fn scoped_allowlist_clears_peer_gate_but_preserves_other_boot_gates_3582() {
    for posture in ["standard", "asi-hard"] {
        let root = tempfile::tempdir().unwrap();
        let out = command(root.path(), posture)
            .env("AI_MEMORY_FED_PEER_ATTESTATION", SCOPED)
            .env("AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE", "1")
            .args([
                "serve",
                "--host",
                "0.0.0.0",
                "--quorum-writes",
                "0",
                "--quorum-peers",
                "https://127.0.0.1:1",
            ])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "the existing enterprise-federation gate must still refuse"
        );
        assert!(!stderr(&out).contains("#3582"), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("enterprise-federation"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn direct_entry_points_and_shared_capabilities_keep_the_gate_3582() {
    let main = include_str!("../src/main.rs");
    let gate = main.find("peer_posture::enforce_at_boot(").unwrap();
    assert!(gate < main.find("logging::init_file_logging(").unwrap());
    assert!(gate < main.find("tokio::runtime::Builder").unwrap());
    let daemon = include_str!("../src/daemon_runtime.rs");
    for name in [
        "pub async fn bootstrap_serve(",
        "pub async fn run_sync_daemon_with_shutdown_using_client(",
    ] {
        let body = daemon.split_once(name).unwrap().1;
        let body = body.split_once(") -> Result<").unwrap().1;
        let body = body.split_once('{').unwrap().1;
        assert!(
            body.trim_start()
                .starts_with("crate::federation::peer_posture::enforce_at_boot(")
        );
    }
    let caps = include_str!("../src/mcp/tools/capabilities.rs");
    assert!(
        caps.contains("caps.federation_security = crate::federation::peer_posture::boot_report()")
    );
}

#[test]
fn capabilities_preserve_daemon_argv_evaluation_in_v2_and_v3_3582() {
    const CHILD: &str = "PEER_POSTURE_CAPS_CHILD_3582";
    if std::env::var_os(CHILD).is_none() {
        let root = tempfile::tempdir().unwrap();
        let template = command(root.path(), "standard");
        let out = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .envs(template.get_envs().filter_map(|(k, v)| v.map(|v| (k, v))))
            .env(CHILD, "1")
            .args([
                "--exact",
                "capabilities_preserve_daemon_argv_evaluation_in_v2_and_v3_3582",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            stderr(&out),
            String::from_utf8_lossy(&out.stdout)
        );
        return;
    }
    ai_memory::federation::peer_posture::enforce_at_boot(true, None).unwrap();
    let tier = FeatureTier::Keyword.config();
    let models = ResolvedModels::from_tier_preset(&tier);
    let v2 =
        handle_capabilities_with_conn(&tier, &models, None, false, None, CapabilitiesAccept::V2)
            .unwrap();
    let v3 = handle_capabilities_with_conn_v3(
        &tier,
        &models,
        None,
        false,
        None,
        &ai_memory::profile::Profile::core(),
        None,
        None,
        None,
    )
    .unwrap();
    for value in [&v2, &v3] {
        let report = &value["federation_security"];
        assert_eq!(report["outbound_peers"], "present");
        assert_eq!(report["inbound_bindings"], "absent");
        assert_eq!(report["verdict"], "warning");
        assert_eq!(report["key_enrollment_required"], true);
        assert_eq!(report["require_push_namespace_scope"], true);
    }
    assert_eq!(v2["federation_security"], v3["federation_security"]);
    let v1 =
        handle_capabilities_with_conn(&tier, &models, None, false, None, CapabilitiesAccept::V1)
            .unwrap();
    assert!(v1.get("federation_security").is_none(), "v1 remains frozen");
}

#[test]
fn configured_fingerprint_certificate_and_issuer_sources_refuse_3582() {
    let fingerprint = "ab".repeat(32);
    for source in ["fingerprint", "certificate", "issuer", "listener"] {
        let root = tempfile::tempdir().unwrap();
        let mut cmd = command(root.path(), "asi-hard");
        cmd.arg("serve");
        match source {
            "fingerprint" => {
                let path = root.path().join("pins");
                std::fs::write(&path, format!("peer.example {fingerprint}\n")).unwrap();
                cmd.env("AI_MEMORY_FED_PEER_FINGERPRINTS", path);
            }
            "certificate" => {
                let path = root.path().join("bindings");
                std::fs::write(&path, format!("{fingerprint} region/peer\n")).unwrap();
                cmd.env("AI_MEMORY_FED_CERT_PEER_BINDING_MAP", path);
            }
            "issuer" => {
                let dir = root.path().join("issuers");
                std::fs::create_dir(&dir).unwrap();
                let key = ai_memory::identity::keypair::generate("issuer").unwrap();
                std::fs::write(dir.join("issuer.pub"), key.public.to_bytes()).unwrap();
                cmd.env("AI_MEMORY_FED_TRUST_BUNDLE_DIR", dir);
            }
            "listener" => {
                let path = root.path().join("mtls-pins");
                std::fs::write(&path, format!("{fingerprint}\n")).unwrap();
                cmd.args([
                    "--tls-cert",
                    "unused-cert",
                    "--tls-key",
                    "unused-key",
                    "--mtls-allowlist",
                ])
                .arg(path);
            }
            _ => unreachable!(),
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        assert!(stderr(&out).contains("#3582"), "{source}: {}", stderr(&out));
        assert!(!root.path().join("store.db").exists());
    }
}

#[test]
fn no_peers_and_reserved_local_key_do_not_trigger_peer_refusal_3582() {
    for posture in ["standard", "asi-hard"] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        std::fs::create_dir(&dir).unwrap();
        let key = ai_memory::identity::keypair::generate("peer").unwrap();
        std::fs::write(dir.join("daemon.pub"), key.public.to_bytes()).unwrap();
        let out = command(root.path(), posture)
            .env("AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE", "1")
            .arg("serve")
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(!stderr(&out).contains("#3582"), "{}", stderr(&out));
        assert!(stderr(&out).contains("enterprise-federation"));
    }
}

#[test]
fn unreadable_enrollment_is_never_reported_as_safe_absence_3582() {
    for posture in ["standard", "asi-hard"] {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-bindings");
        let mut cmd = command(root.path(), posture);
        cmd.env("AI_MEMORY_FED_CERT_PEER_BINDING_MAP", &missing)
            .env("AI_MEMORY_FED_PEER_ATTESTATION", SCOPED);
        let out = cmd.args(["doctor", "--json"]).output().unwrap();
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let section = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Federation peer authorization")
            .unwrap();
        assert_eq!(
            section["severity"],
            if posture == "asi-hard" {
                "critical"
            } else {
                "warning"
            }
        );
        assert!(section["facts"].to_string().contains("observation_error"));
        let out = command(root.path(), posture)
            .env("AI_MEMORY_FED_CERT_PEER_BINDING_MAP", &missing)
            .env("AI_MEMORY_FED_PEER_ATTESTATION", SCOPED)
            .env("AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE", "1")
            .arg("serve")
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(stderr(&out).contains("#3582"), "{}", stderr(&out));
    }
}
