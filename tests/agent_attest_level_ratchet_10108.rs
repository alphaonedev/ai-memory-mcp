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
//! wire word directly after a double or single quote (a Rust literal, an
//! escaped JSON literal such as `"\"self_signed\""`, a raw string, or an SQL
//! literal inside a Rust string or a `.sql` file) — is a site a reviewer has
//! checked, held here as an ALLOWLIST of exact per-file counts over every
//! tracked and untracked, not-ignored `.rs` and `.sql` file of the repository
//! (`git ls-files`). An escaped underscore (`\x5f`, `\u{5f}`) is decoded
//! before counting, so `"self\x5fsigned"` is the same form. A new site
//! anywhere (a literal, an `AttestLevel::` path, a `use ... as` alias, another
//! call form such as `from_str("self_signed")` or a serde or SQL literal, a
//! table in any container form, a file in any directory) raises a count and
//! fails; a removed site lowers one and fails too, so the list stays the exact
//! boundary.
//!
//! Left out, with the reason: every file that is neither `.rs` nor `.sql`
//! (docs, CSV and JSON evidence, and the tool-schema snapshot JSON are never
//! executed against a database; only Rust code and the SQL migrations it runs
//! write a row), and this file (it names the forms to forbid them). A value
//! assembled at run time (for example `format!` of two halves) is not a source
//! form; the walk refuses an agent-labelled row without its signature above
//! the cutover marker whatever wrote it. Comments are counted: a count is a
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

/// The wire words of the three agent levels. A word counts when it is a whole
/// identifier directly after one of [`QUOTES`].
const WIRE_WORDS: [&str; 3] = ["self_signed", "signed_by_peer", "peer_attested"];

/// The bytes that open a string literal in Rust (`"`, also the `\"` of an
/// escaped JSON literal) or in SQL (`'`).
const QUOTES: [u8; 2] = *b"\"'";

/// Escaped spellings of `_` a Rust literal can hold; each is decoded to `_`
/// before counting.
const ESCAPED_UNDERSCORES: [&str; 6] = [
    "\\x5f",
    "\\x5F",
    "\\u{5f}",
    "\\u{5F}",
    "\\u{005f}",
    "\\u{005F}",
];

/// The file extensions the ratchet reads: Rust code and the SQL it runs.
const SCANNED_EXTENSIONS: [&str; 2] = ["rs", "sql"];

/// `(file, count)`: every `.rs` and `.sql` file that names an agent level, with
/// the exact number of forms it holds. Re-pin a row only after reviewing each
/// new site; a `// reviewed:` line above a row gives the reason its sites are
/// legitimate (reader, label table, CHECK guard, test fixture, comment).
const ALLOWLIST: &[(&str, usize)] = &[
    // reviewed: CHECK constraint that refuses a signed link label without a 64-byte signature, and
    // a backfill that only demotes such a phantom-signed link to unsigned (it never writes an agent
    // label), plus comments.
    (
        "migrations/postgres/0024_v07_persona_signing_atomicity.sql",
        6,
    ),
    // reviewed: comment naming the allowed link label values.
    ("migrations/postgres/0029_v07_links_temporal_columns.sql", 2),
    // reviewed: comments naming the link label values the column holds.
    ("migrations/sqlite/0017_v07_link_attest_level.sql", 2),
    // reviewed: CHECK triggers that refuse an unknown link label (guard, writes no row).
    ("migrations/sqlite/0023_v07_check_constraints.sql", 4),
    // reviewed: CHECK triggers that refuse an unknown link label (guard, writes no row).
    (
        "migrations/sqlite/0027_v07_memory_links_relation_check.sql",
        4,
    ),
    // reviewed: triggers that refuse a signed link label without a 64-byte signature, and a
    // backfill that only demotes such a phantom-signed link to unsigned (it never writes an agent
    // label), plus comments.
    (
        "migrations/sqlite/0037_v07_persona_signing_atomicity.sql",
        10,
    ),
    // reviewed: CHECK triggers re-created by the table rebuild (guard, writes no row).
    (
        "migrations/sqlite/0053_v63_memory_links_typed_cognition_relations.sql",
        4,
    ),
    // reviewed: signature triggers restored after the rebuild (guard, writes no row).
    (
        "migrations/sqlite/0054_v65_restore_memory_links_signature_triggers.sql",
        4,
    ),
    ("src/cli/commands/export_reflections.rs", 13),
    ("src/cli/link.rs", 1),
    // reviewed: test fixtures in the cfg(test) module (seeded rows and expected verify output).
    ("src/cli/verify.rs", 8),
    // reviewed: doc comment of run_consolidation_pass and cfg(test) assertions on the signed
    // persona sweep.
    ("src/curator/mod.rs", 5),
    // reviewed: comment describing the signed reflects_on edges.
    ("src/curator/reflection_pass.rs", 1),
    ("src/handlers/capture_turn/attestation.rs", 2),
    ("src/handlers/coordination.rs", 1),
    ("src/handlers/federation_receive.rs", 1),
    ("src/handlers/federation_signing_check.rs", 1),
    ("src/handlers/tests.rs", 1),
    ("src/handlers/transport.rs", 1),
    ("src/identity/verify.rs", 6),
    // reviewed: cfg(test) handler tests asserting the stored and echoed label, and their comments.
    ("src/mcp/mod.rs", 14),
    ("src/mcp/tools/capture_turn.rs", 10),
    ("src/mcp/tools/checkpoint.rs", 4),
    ("src/mcp/tools/link.rs", 1),
    ("src/mcp/tools/recall.rs", 23),
    ("src/mcp/tools/routine.rs", 1),
    ("src/mcp/tools/signal.rs", 2),
    // reviewed: comments describing the signed edge the store path writes.
    ("src/mcp/tools/store/mod.rs", 2),
    ("src/mcp/tools/verify.rs", 6),
    ("src/models/link.rs", 26),
    // reviewed: the AttestLevel enum, its wire strings and its cfg(test) round-trip and serde
    // tests.
    ("src/models/mod.rs", 26),
    ("src/offload/mod.rs", 1),
    ("src/persona/mod.rs", 10),
    ("src/signed_events.rs", 11),
    // reviewed: is_agent_labelled, a reader that sorts a label into agent or not; writes no row.
    ("src/signed_events/agent_cutover.rs", 3),
    ("src/signed_events/agent_row.rs", 9),
    ("src/signed_events/agent_row_10108_tests.rs", 10),
    // reviewed: read-only count of rows with an unknown link label at CHECK trigger install
    // (reader).
    ("src/storage/connection.rs", 2),
    // reviewed: comment naming the signed link labels the trigger guards.
    ("src/storage/migration_meta.rs", 2),
    // reviewed: CHECK triggers that refuse an unknown link label, comments, and a cfg(test) rebuild
    // fixture.
    ("src/storage/migrations.rs", 10),
    // reviewed: signed link writer and readers counted at the base, plus doc comments and cfg(test)
    // trigger fixtures.
    ("src/storage/mod.rs", 26),
    // reviewed: doc comment naming the signed reflects_on edges.
    ("src/storage/model_attest.rs", 1),
    // reviewed: doc comment naming the signed reflects_on rows.
    ("src/storage/reflect.rs", 1),
    // reviewed: trait doc comments and the signed signal path counted at the base.
    ("src/store/mod.rs", 6),
    // reviewed: doc comments and the signed link, reflect and signal paths counted at the base.
    ("src/store/postgres.rs", 6),
    // reviewed: comment naming the allowed link label values.
    ("src/store/postgres_schema.sql", 2),
    ("src/store/sqlite.rs", 1),
    ("src/trust.rs", 4),
    // reviewed: test fixture and its verify expectation.
    ("tests/a2a_campaign_round1.rs", 2),
    // reviewed: test fixture that inserts an agent-labelled row to test the cutover.
    ("tests/agent_cutover_v103_10108.rs", 1),
    // reviewed: walk test fixtures: hand-made rows through insert_raw into a temporary DB.
    ("tests/agent_era_walk_10108.rs", 7),
    // reviewed: Postgres walk fixture builder for the legacy and pre-cutover specs.
    ("tests/agent_era_walk_pg_10108.rs", 1),
    ("tests/agent_row_pg_10108.rs", 5),
    ("tests/archive_restore_link_cid_3250.rs", 1),
    ("tests/attest_level_stamp_values_3548.rs", 4),
    ("tests/attest_level_string_invariant.rs", 3),
    ("tests/capture_turn_security_integrity.rs", 8),
    // reviewed: test fixture inserting a signed reflects_on edge.
    ("tests/cli_verify_chain.rs", 1),
    ("tests/cov_ga2_pg_federation.rs", 1),
    ("tests/curator_conserves_contradiction_g7.rs", 1),
    ("tests/federation_inbound_verify.rs", 3),
    ("tests/g3_postgres_verify_link_signature_roundtrip.rs", 2),
    // reviewed: test fixture inserting a signed reflects_on edge.
    ("tests/g_phase_e_4_verify_exit_codes.rs", 1),
    ("tests/h2_invalidate_link_signed.rs", 2),
    ("tests/http_capture_attestation_3406.rs", 3),
    ("tests/identity_e2e.rs", 13),
    ("tests/issue_2059_2060_covenant_pg.rs", 1),
    ("tests/issue_2121_2122_2123_covenant_funnels.rs", 1),
    ("tests/link_invalidate_payload_hash_parity_3281.rs", 2),
    ("tests/memory_verify.rs", 12),
    // reviewed: trigger-refusal fixture and assertions on the signed persona pipeline.
    ("tests/persona_signing_pipeline_813.rs", 10),
    // reviewed: Postgres CHECK tests: phantom-signed inserts that must fail and a signed insert
    // that must pass.
    ("tests/postgres_persona_signing_atomicity.rs", 16),
    // reviewed: test fixtures and expected attestation values.
    ("tests/recall_no_lock_across_hnsw.rs", 6),
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

/// Occurrences of `word` in `text` as a whole identifier directly after a
/// byte of [`QUOTES`].
fn count_quoted_word(text: &str, word: &str) -> usize {
    let bytes = text.as_bytes();
    text.match_indices(word)
        .filter(|(i, _)| {
            let before = i.checked_sub(1).map(|j| bytes[j]);
            let after = bytes.get(i + word.len()).copied();
            before.is_some_and(|b| QUOTES.contains(&b)) && !after.is_some_and(is_ident_byte)
        })
        .count()
}

/// The number of agent-level forms `text` holds.
fn count_forms(text: &str) -> usize {
    let decoded = ESCAPED_UNDERSCORES
        .iter()
        .fold(text.to_string(), |acc, esc| acc.replace(esc, "_"));
    VARIANTS
        .iter()
        .map(|v| count_word(&decoded, v))
        .sum::<usize>()
        + WIRE_WORDS
            .iter()
            .map(|w| count_quoted_word(&decoded, w))
            .sum::<usize>()
}

fn observed() -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for f in tree_files() {
        let scanned = std::path::Path::new(&f).extension().is_some_and(|ext| {
            SCANNED_EXTENSIONS
                .iter()
                .any(|want| ext.eq_ignore_ascii_case(want))
        });
        if !scanned || f == SELF {
            continue;
        }
        let path = root().join(&f);
        let Ok(bytes) = std::fs::read(&path) else {
            // A listed file that is gone from disk (deleted, not yet
            // staged) holds no code.
            continue;
        };
        let text =
            String::from_utf8(bytes).unwrap_or_else(|_| panic!("{f}: scanned file is not UTF-8"));
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
    let samples: [(&str, usize); 15] = [
        ("let l = \"self_signed\";", 1),
        ("AttestLevel::SignedByPeer.as_str()", 1),
        ("use crate::models::AttestLevel::PeerAttested as Pa;", 1),
        ("AttestLevel::from_str(\"peer_attested\")", 1),
        (
            "const L: [AttestLevel; 2] = [AttestLevel::SelfSigned, AttestLevel::PeerAttested];",
            2,
        ),
        ("match x { AgentAttestation::SelfSigned => 1 }", 1),
        // An escaped JSON literal handed to serde.
        (
            "serde_json::from_str::<AttestLevel>(\"\\\"self_signed\\\"\")",
            1,
        ),
        // An SQL literal inside a Rust string, and in a `.sql` file.
        ("\"VALUES (?1, 'signed_by_peer')\"", 1),
        ("WHERE attest_level IN ('self_signed', 'peer_attested')", 2),
        // A raw string holding JSON.
        ("r#\"{\"attest_level\":\"peer_attested\"}\"#", 1),
        // An escaped underscore.
        ("\"self\\x5fsigned\" \"peer\\u{5f}attested\"", 2),
        // A static table in slice form.
        (
            "static T: &[&str] = &[\"unsigned\", \"signed_by_peer\"];",
            1,
        ),
        // A quoted list in prose still names the first level.
        ("\"self_signed, or none\"", 1),
        // Not a form: a longer identifier, an unquoted word or a word after
        // a backtick.
        ("SelfSignedLike self_signed_count NotPeerAttested", 0),
        ("`self_signed` 'self_signed_x' \"peer_attested2\"", 0),
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
