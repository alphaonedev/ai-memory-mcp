// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 (GA standard 3) — source ratchet: an agent attest level is named
//! only at allowlisted sites.
//!
//! Invariant I1 says a `signed_events` row carries an agent label
//! (`self_signed`, `signed_by_peer`, `peer_attested`) only with the 64-byte
//! signature of that agent. The one constructor that pairs the two is
//! `src/signed_events/agent_row.rs` (`AgentRowSignature`). Every other
//! place that NAMES an agent level — the enum variant (`SelfSigned`,
//! `SignedByPeer`, `PeerAttested`, through any path or alias) or the quoted
//! wire literal — is a site a reviewer has checked, held here as an
//! ALLOWLIST of exact per-file counts over every tracked and untracked,
//! not-ignored `.rs` file of the repository (`git ls-files`). A new site
//! anywhere (a literal, an `AttestLevel::` path, a `use ... as` alias, another
//! call form such as `from_str("self_signed")`, a file in any directory)
//! raises a count and fails; a removed site lowers one and fails too, so the
//! list stays the exact boundary.
//!
//! Left out, with the reason: every non-`.rs` file (only Rust code writes a
//! `signed_events` row; prose and JSON fixtures write nothing), and this file
//! (it names the forms to forbid them). Comments are counted: a count is a
//! count, and moving prose is cheap to re-pin.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// The tree listing must be at least this large, so an empty or broken git
/// listing cannot pass vacuously.
const MIN_TREE_FILES: usize = 1000;

/// This ratchet names every form to forbid it.
const SELF: &str = "tests/agent_attest_level_ratchet_10108.rs";

/// The variant names of the three agent levels.
const VARIANTS: [&str; 3] = ["SelfSigned", "SignedByPeer", "PeerAttested"];

/// The quoted wire literals of the three agent levels.
const LITERALS: [&str; 3] = ["\"self_signed\"", "\"signed_by_peer\"", "\"peer_attested\""];

/// `(file, count)`: every `.rs` file that names an agent level, with the exact
/// number of forms it holds. Regenerate only after reviewing each new site.
const ALLOWLIST: &[(&str, usize)] = &[
    ("src/cli/commands/export_reflections.rs", 13),
    ("src/cli/link.rs", 1),
    ("src/cli/verify.rs", 7),
    ("src/curator/mod.rs", 4),
    ("src/handlers/capture_turn/attestation.rs", 2),
    ("src/handlers/coordination.rs", 1),
    ("src/handlers/federation_receive.rs", 1),
    ("src/handlers/federation_signing_check.rs", 1),
    ("src/handlers/tests.rs", 1),
    ("src/handlers/transport.rs", 1),
    ("src/identity/verify.rs", 6),
    ("src/mcp/mod.rs", 12),
    ("src/mcp/tools/capture_turn.rs", 10),
    ("src/mcp/tools/checkpoint.rs", 4),
    ("src/mcp/tools/link.rs", 1),
    ("src/mcp/tools/recall.rs", 23),
    ("src/mcp/tools/routine.rs", 1),
    ("src/mcp/tools/signal.rs", 2),
    ("src/mcp/tools/verify.rs", 6),
    ("src/models/link.rs", 26),
    ("src/models/mod.rs", 24),
    ("src/offload/mod.rs", 1),
    ("src/persona/mod.rs", 10),
    ("src/signed_events.rs", 11),
    ("src/signed_events/agent_row.rs", 9),
    ("src/signed_events/agent_row_10108_tests.rs", 10),
    ("src/storage/migrations.rs", 4),
    ("src/storage/mod.rs", 18),
    ("src/store/mod.rs", 5),
    ("src/store/postgres.rs", 4),
    ("src/store/sqlite.rs", 1),
    ("src/trust.rs", 4),
    ("tests/a2a_campaign_round1.rs", 1),
    ("tests/agent_row_pg_10108.rs", 5),
    ("tests/archive_restore_link_cid_3250.rs", 1),
    ("tests/attest_level_stamp_values_3548.rs", 4),
    ("tests/attest_level_string_invariant.rs", 3),
    ("tests/capture_turn_security_integrity.rs", 8),
    ("tests/cov_ga2_pg_federation.rs", 1),
    ("tests/curator_conserves_contradiction_g7.rs", 1),
    ("tests/federation_inbound_verify.rs", 3),
    ("tests/g3_postgres_verify_link_signature_roundtrip.rs", 2),
    ("tests/h2_invalidate_link_signed.rs", 2),
    ("tests/http_capture_attestation_3406.rs", 3),
    ("tests/identity_e2e.rs", 13),
    ("tests/issue_2059_2060_covenant_pg.rs", 1),
    ("tests/issue_2121_2122_2123_covenant_funnels.rs", 1),
    ("tests/link_invalidate_payload_hash_parity_3281.rs", 2),
    ("tests/memory_verify.rs", 12),
    ("tests/persona_signing_pipeline_813.rs", 7),
    ("tests/recall_no_lock_across_hnsw.rs", 4),
    ("tests/recursive_sal_coverage.rs", 2),
    ("tests/reflect_owner_parity_3423.rs", 2),
    ("tests/sal_contract.rs", 2),
    ("tests/sal_parity_link_window_3178.rs", 2),
    ("tests/serve_postgres_smoke.rs", 1),
    ("tests/signed_events_legacy_cutoff_10074.rs", 15),
    ("tests/signed_events_legacy_cutoff_10074_pg.rs", 5),
    ("tests/store_parity_gaps.rs", 1),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every tracked file plus every untracked file git does not ignore. Fails
/// closed when git cannot list the tree.
fn tree_files() -> BTreeSet<String> {
    let sandbox = home_sandbox::install();
    let out = Command::new("git")
        .env("HOME", sandbox.home())
        .env("XDG_CONFIG_HOME", sandbox.home().join(".config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(root())
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .unwrap_or_else(|e| panic!("git ls-files could not run: {e}"));
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let files: BTreeSet<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    assert!(
        files.len() > MIN_TREE_FILES,
        "tree listing too small: {}",
        files.len()
    );
    files
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Occurrences of `word` in `text` as a whole identifier.
fn count_word(text: &str, word: &str) -> usize {
    let bytes = text.as_bytes();
    text.match_indices(word)
        .filter(|(i, _)| {
            let before = i.checked_sub(1).map(|j| bytes[j]);
            let after = bytes.get(i + word.len()).copied();
            !before.is_some_and(is_ident_byte) && !after.is_some_and(is_ident_byte)
        })
        .count()
}

/// The number of agent-level forms `text` holds.
fn count_forms(text: &str) -> usize {
    VARIANTS.iter().map(|v| count_word(text, v)).sum::<usize>()
        + LITERALS
            .iter()
            .map(|l| text.matches(l).count())
            .sum::<usize>()
}

fn observed() -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for f in tree_files() {
        let is_rust = std::path::Path::new(&f)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
        if !is_rust || f == SELF {
            continue;
        }
        let path = root().join(&f);
        let Ok(bytes) = std::fs::read(&path) else {
            // A listed file that is gone from disk (deleted, not yet
            // staged) holds no code.
            continue;
        };
        let text =
            String::from_utf8(bytes).unwrap_or_else(|_| panic!("{f}: .rs file is not UTF-8"));
        let n = count_forms(&text);
        if n > 0 {
            map.insert(f, n);
        }
    }
    map
}

#[test]
fn agent_attest_level_sites_match_the_allowlist_10108() {
    let want: BTreeMap<String, usize> = ALLOWLIST
        .iter()
        .map(|(f, n)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(want.len(), ALLOWLIST.len(), "duplicate allowlist entry");
    let got = observed();
    let mut diffs = Vec::new();
    for (f, n) in &got {
        match want.get(f) {
            None => diffs.push(format!(
                "{f}: {n} agent-level form(s), file not allowlisted"
            )),
            Some(w) if w != n => {
                diffs.push(format!("{f}: {n} agent-level form(s), allowlist says {w}"));
            }
            Some(_) => {}
        }
    }
    for (f, w) in &want {
        if !got.contains_key(f) {
            diffs.push(format!(
                "{f}: allowlisted with {w}, holds none (stale entry)"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "#10108 agent attest level named outside the reviewed sites:\n{}",
        diffs.join("\n")
    );
}

#[test]
fn counter_sees_every_form_10108() {
    // One sample per form the construct can take (written out).
    let samples: [(&str, usize); 7] = [
        ("let l = \"self_signed\";", 1),
        ("AttestLevel::SignedByPeer.as_str()", 1),
        ("use crate::models::AttestLevel::PeerAttested as Pa;", 1),
        ("AttestLevel::from_str(\"peer_attested\")", 1),
        (
            "const L: [AttestLevel; 2] = [AttestLevel::SelfSigned, AttestLevel::PeerAttested];",
            2,
        ),
        ("match x { AgentAttestation::SelfSigned => 1 }", 1),
        // Not a form: a longer identifier or an unquoted word.
        ("SelfSignedLike self_signed_count NotPeerAttested", 0),
    ];
    for (text, n) in samples {
        assert_eq!(count_forms(text), n, "{text}");
    }
}

#[test]
fn test_process_resolves_no_path_under_the_real_home_10108() {
    let _ = home_sandbox::real_home();
    let sandbox = home_sandbox::install();
    home_sandbox::assert_outside_real_home("git child HOME", &sandbox.home());
    home_sandbox::assert_process_isolated();
}
