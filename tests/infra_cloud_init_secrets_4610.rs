// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4610 / #4628 (CWE-214 / CWE-319) — the cloud-init templates keep the
//! Postgres role password OUT of instance user-data, and the AWS agent talks
//! https with its credentials read from root-only files.
//!
//! User-data is served unauthenticated to every local process by the cloud
//! metadata service, so a password rendered into it is readable by any local
//! UID. The role password is therefore generated ON the node (`openssl rand`)
//! and the DSN file and the role SQL are derived from it there. These are source-level pins over the shipped templates; the
//! cloud-init token allowlist gate (`scripts/check-docs-no-argv-secrets.py`)
//! scans the same files for argv/xtrace/mode shapes.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

#[test]
fn infra_4610_do_hive_role_password_is_minted_on_the_node() {
    let tpl = read("infra/do-hive/cloud-init-memory.yaml.tpl");
    let tf = read("infra/do-hive/main.tf");
    assert!(
        !tpl.contains("db_password"),
        "do-hive memory template must not render a db password into user-data"
    );
    assert!(
        !tf.contains("db_password"),
        "main.tf must not declare or pass a db_password variable (it lands in user-data and tfstate)"
    );
    assert_minted_on_node(&tpl, "do-hive");
}

#[test]
fn infra_4610_aws_role_password_is_minted_on_the_node() {
    let tpl = read("infra/aws-gpu-burst/cloud-init-memory.yaml.tpl");
    assert!(
        !tpl.contains("db_password"),
        "AWS memory template must not render a db password into user-data"
    );
    assert_minted_on_node(&tpl, "aws-gpu-burst");
}

/// The shipped DSN carries only the `CHANGEME` placeholder; the provision
/// script replaces it with a random hex secret and refuses to continue if it
/// survives (#4788).
fn assert_minted_on_node(tpl: &str, which: &str) {
    assert!(
        tpl.contains("NEW_SECRET=\"$(openssl rand -hex 24)\""),
        "{which}: the role password must be generated on the node"
    );
    assert!(
        tpl.contains("sed -i \"s/CHANGEME/$NEW_SECRET/\" /etc/ai-memory/store-url"),
        "{which}: the minted secret must replace the placeholder in the store-url file"
    );
    let guard = tpl
        .matches("grep -q CHANGEME /etc/ai-memory/store-url")
        .count();
    assert!(
        guard >= 2,
        "{which}: a mint check and a fail-closed check on a surviving placeholder are both required, found {guard}"
    );
    assert!(
        tpl.contains("placeholder db password still in /etc/ai-memory/store-url"),
        "{which}: a surviving placeholder must stop the script"
    );
}

#[test]
fn infra_4610_spawn_sh_copies_tfstate_owner_only() {
    let sh = read("infra/do-hive/spawn.sh");
    assert!(
        sh.contains("( umask 077; cp terraform.tfstate"),
        "the tfstate copy holds the rendered user-data and must be owner-only"
    );
}

#[test]
fn infra_4628_aws_agent_uses_https_with_root_only_credentials() {
    let tpl = read("infra/aws-gpu-burst/cloud-init-agent.yaml.tpl");
    assert!(
        !tpl.contains("http://${memory_private_ip}"),
        "the memory daemon refuses plaintext binds; the agent must not use http://"
    );
    assert!(tpl.contains("AI_MEMORY_HTTP=https://${memory_private_ip}:9077"));
    assert!(
        tpl.contains("EnvironmentFile=/etc/ironclaw/memory.env"),
        "the API key must come from a root-only file, not a unit line or argv"
    );
    assert!(
        tpl.contains("SSL_CERT_FILE=/etc/ironclaw/memory-ca.crt"),
        "the agent must trust the memory node certificate"
    );
    assert!(
        !tpl.contains("AI_MEMORY_API_KEY=") || tpl.contains("printf 'AI_MEMORY_API_KEY=%s"),
        "no literal API key value may appear in the template"
    );
}
