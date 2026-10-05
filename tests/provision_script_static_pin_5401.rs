// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Static pin for #5401 (PR 4810 round-4 security note): `deploy/hive-1461/provision/20_pg_age.sh`
//! must build the pg-age image from an EMPTY context directory with the Dockerfile passed
//! through `-f`, so the peer-local CA key (`tls-ca/`) and the secret files (`.secrets/`) under
//! `/opt/hive/pg-age` are never sent to the docker daemon.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read provisioning script {}: {e}", path.display()))
}

#[test]
fn hive_pg_age_docker_build_context_is_empty_and_dockerfile_comes_from_f_5401() {
    let script = read("deploy/hive-1461/provision/20_pg_age.sh");
    let builds: Vec<&str> = script
        .lines()
        .filter(|l| l.contains("docker build") && !l.trim_start().starts_with('#'))
        .collect();
    assert_eq!(
        builds.len(),
        1,
        "expected exactly one docker build line: {builds:?}"
    );
    let line = builds[0];
    assert!(
        line.contains("-f /opt/hive/pg-age/Dockerfile"),
        "#5401: the Dockerfile must come in through -f: {line}"
    );
    assert!(
        line.trim_end()
            .ends_with("/opt/hive/pg-age/build-ctx\" >/dev/null"),
        "#5401: the build context must be the empty build-ctx directory: {line}"
    );
    assert!(
        line.contains("mkdir -p /opt/hive/pg-age/build-ctx"),
        "#5401: the empty context directory must be created before the build: {line}"
    );
}
