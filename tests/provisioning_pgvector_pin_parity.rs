// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Cross-lane pgvector pin parity (#2872) — mechanical pin.
//!
//! The two certified provisioning SSOTs — the docker-1461 container lane
//! (`deploy/docker-1461/provision/lib.sh`, Debian 13 / `pgdg13`) and the
//! do-1461 NATIVE lane (`deploy/do-1461/provision/lib.sh`, Ubuntu 24.04 /
//! `pgdg24.04`) — MUST agree on the pgvector PATCH they pin. They deliberately
//! differ only in the pgdg distro suffix baked into the apt version string,
//! because they provision on different distros; the `x.y.z` patch itself is a
//! fleet-wide contract (the canonical v1.0.0 GA stack, pinned to pgvector
//! 0.8.5 in `docs/v1.0.0/release-notes.md`).
//!
//! Before #2872 the two lanes silently disagreed (docker-1461 pinned 0.8.5
//! while do-1461 pinned 0.8.2) — a bet-the-farm consistency defect, and the
//! do-1461 pin was additionally no longer resolvable in the live pgdg repo
//! (the #2658 nonexistent-pin class). This test fails LOUD on any future
//! accidental re-divergence, so the reconciliation cannot silently rot.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_lib_sh(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read provisioning SSOT {}: {e}", path.display()))
}

/// Extract the default from the first live `${var:-<default>}` shell
/// parameter-expansion whose inner variable is `var`.
///
/// Keyed on the INNER `${var:-` token, not the LHS assignment name, because a
/// lane may assign through an override indirection whose LHS differs from the
/// inner default var (docker-1461:
/// `PGVECTOR_APT_VERSION="${DOCKER_1461_PGVECTOR_APT_VERSION:-…}"`). Comment
/// lines are skipped so a `#`-prefixed narrative mention never shadows the
/// live pin.
fn shell_default(source: &str, var: &str) -> String {
    let needle = format!("${{{var}:-");
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.split_once(&needle).map(|(_, r)| r) {
            let value = rest.split_once('}').map_or(rest, |(v, _)| v);
            return value.to_string();
        }
    }
    panic!("no live `{var}` default expansion found in provisioning SSOT");
}

/// Reduce a pgdg apt version string (`0.8.5-1.pgdg24.04+1`) to its bare
/// upstream patch (`0.8.5`). A bare patch (`0.8.5`) is returned unchanged.
fn upstream_patch(apt_version: &str) -> String {
    apt_version
        .split_once('-')
        .map_or(apt_version, |(patch, _)| patch)
        .to_string()
}

/// The canonical v1.0.0 GA pgvector patch both lanes must pin.
const EXPECTED_PGVECTOR_PATCH: &str = "0.8.5";

const DOCKER_LANE: &str = "deploy/docker-1461/provision/lib.sh";
const DO_LANE: &str = "deploy/do-1461/provision/lib.sh";

#[test]
fn docker_and_do_lanes_pin_the_same_pgvector_patch_2872() {
    let docker = read_lib_sh(DOCKER_LANE);
    let dolane = read_lib_sh(DO_LANE);

    let docker_patch = upstream_patch(&shell_default(&docker, "DOCKER_1461_PGVECTOR_APT_VERSION"));
    let do_patch = upstream_patch(&shell_default(&dolane, "PGVECTOR_APT_VERSION"));

    assert_eq!(
        docker_patch, do_patch,
        "cross-lane pgvector patch drift (#2872): docker-1461 pins {docker_patch}, \
         do-1461 pins {do_patch} — both certified SSOTs must pin the same patch"
    );
    assert_eq!(
        docker_patch, EXPECTED_PGVECTOR_PATCH,
        "docker-1461 pgvector patch {docker_patch} != canonical v1.0.0 stack \
         {EXPECTED_PGVECTOR_PATCH}"
    );
}

#[test]
fn do_lane_expected_matches_its_apt_pin_2872() {
    let dolane = read_lib_sh(DO_LANE);
    let apt_patch = upstream_patch(&shell_default(&dolane, "PGVECTOR_APT_VERSION"));
    let expected = shell_default(&dolane, "EXPECTED_PGVECTOR_VERSION");

    assert_eq!(
        apt_patch, expected,
        "do-1461 self-consistency (#2872): the validate harness asserts the \
         installed pgvector equals EXPECTED_PGVECTOR_VERSION ({expected}), but \
         the apt pin installs {apt_patch}"
    );
    assert_eq!(
        expected, EXPECTED_PGVECTOR_PATCH,
        "do-1461 EXPECTED_PGVECTOR_VERSION {expected} != canonical v1.0.0 stack \
         {EXPECTED_PGVECTOR_PATCH}"
    );
}

#[test]
fn each_lane_carries_its_own_pgdg_distro_suffix_2872() {
    // The lanes MUST keep distinct distro suffixes (they provision different
    // distros); unifying the suffix would be a false unification that breaks
    // one lane's apt resolution.
    let docker = shell_default(
        &read_lib_sh(DOCKER_LANE),
        "DOCKER_1461_PGVECTOR_APT_VERSION",
    );
    let dolane = shell_default(&read_lib_sh(DO_LANE), "PGVECTOR_APT_VERSION");

    assert!(
        docker.contains("pgdg13"),
        "docker-1461 (Debian 13) pgvector pin should carry the pgdg13 suffix: {docker}"
    );
    assert!(
        dolane.contains("pgdg24.04"),
        "do-1461 (Ubuntu 24.04) pgvector pin should carry the pgdg24.04 suffix: {dolane}"
    );
}
