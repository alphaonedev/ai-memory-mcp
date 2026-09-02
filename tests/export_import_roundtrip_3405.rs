// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// The module docs narrate the defect in prose and name SQLite as a product
// rather than as a code item, matching the `tests/` precedent for
// prose-heavy regression docs (see `tests/export_import_false_success_2490.rs`).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #3405 — `ai-memory export | ai-memory import` must round-trip its
//! OWN bundle, and a bundle that cannot be round-tripped must say why and
//! offer the operator a disposition.
//!
//! # The defect, reproduced by EXECUTION against the parent commit `1fa0b76c`
//!
//! `memories[]` and `links[]` are two INDEPENDENT reads.
//! `storage::export_all` applies the fail-closed lifecycle allow-list (a
//! `tombstoned` / `quarantined` row never leaves) and
//! `export_taxonomy::screen_memories_for_export_audited` then DROPS
//! forbidden-class rows; `storage::export_links` filtered only on EXPIRY. So
//! the exporter emitted edges naming memories the artifact does not contain.
//!
//! Executed at `1fa0b76c` on a three-row corpus where two rows were
//! consolidated (`AI_MEMORY_LINEAGE_DAG=1` +
//! `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES=1`, which RETAINS the sources as
//! `lifecycle_state='tombstoned'` and writes `derived_from` edges to them):
//!
//! ```text
//! $ ai-memory export > bundle.json          # exit 0
//! count: 2, links: 3   <- all three edges name a tombstoned endpoint
//! $ ai-memory import < bundle.json          # exit 3
//! links_refused: 3 ("target memory not found: …")
//! ```
//!
//! Exit 0 on the producing side, exit 3 on the consuming side, on the FIRST
//! run and on every subsequent one, with no flag an operator could pass —
//! `memory_links` carries `REFERENCES memories(id)` and `db::open` sets
//! `PRAGMA foreign_keys=ON`, so the destination can neither create the edge
//! nor invent the missing row. A backup pipeline whose restore leg is
//! permanently non-zero ends as `|| true`, which then also silences the
//! genuine refusals #2490 exists to surface.
//!
//! # The control these tests pin
//!
//! 1. **Producer** — `export_scope::retain_resolvable_links` is the one
//!    funnel every bundle producer (CLI `export`, `export --full`, the HTTP
//!    admin export on both backends) passes its edges through: an artifact
//!    never claims an edge it cannot carry, and the drop is REPORTED (in-band
//!    `withheld.dangling_links_withheld`, plus the rendered edges on the
//!    operator stderr channel — never in-band, per the #2490 objection-O3
//!    id-confidentiality boundary).
//! 2. **Consumer** — `import` distinguishes an endpoint the BUNDLE never
//!    carried (a dangling artifact: a producer defect) from an endpoint the
//!    bundle carried whose row did not land (a genuine reconstruction
//!    failure). The first is reported under its own counter and gated by an
//!    explicit `--allow-dangling` ratchet; the second still exits 3.
//!
//! # Why these tests drive the BINARY
//!
//! R-203 requires the regression to FAIL at the parent commit and PASS after.
//! Every assertion here is reachable through the shipped CLI, so the
//! identical source compiles and runs against `1fa0b76c` — where the
//! round-trip exits 3, `dangling_links_withheld` is absent, and
//! `--allow-dangling` is not a recognised flag.
//!
//! Spawning a subprocess also keeps every `AI_MEMORY_*` mutation out of the
//! test process, so nothing here races the shared `config::test_env_lock()`
//! discipline (#2127 / #2146).

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// Exit code for "artifact written / rows applied, but INCOMPLETE" —
/// deliberately distinct from 1 so an orchestrator can branch on it.
const EXIT_INCOMPLETE: i32 = 3;

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// Store one memory and return its id.
fn store(db: &Path, title: &str, content: &str) -> String {
    let out = ai_memory(db)
        .args([
            "--json",
            "store",
            "--title",
            title,
            "--content",
            content,
            "--namespace",
            "probe",
            "--tier",
            "long",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_slice(&out).expect("store emits a JSON memory record");
    v["id"]
        .as_str()
        .expect("stored memory carries an id")
        .to_string()
}

/// Seed the exact corpus the issue describes: live rows, edges, and rows
/// RETAINED as `lifecycle_state='tombstoned'` that are still named by edges.
///
/// Consolidation with the lineage-DAG on is the production path that mints
/// this shape (`storage::consolidate` writes a `derived_from` edge to every
/// source and then tombstones it), so the fixture is the real generator, not
/// a hand-poked row.
///
/// Returns `(live_id, consolidated_id, tombstoned_ids)`.
fn seed_tombstoned_corpus(db: &Path) -> (String, String, Vec<String>) {
    let live = store(db, "note-live", "content live");
    let src_a = store(db, "note-src-a", "content source a");
    let src_b = store(db, "note-src-b", "content source b");

    // A plain edge from the live row into a soon-to-be-tombstoned source.
    ai_memory(db)
        .args(["link", &live, &src_a, "--relation", "related_to"])
        .assert()
        .success();

    let out = ai_memory(db)
        .env("AI_MEMORY_LINEAGE_DAG", "1")
        .env("AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES", "1")
        .args([
            "consolidate",
            &format!("{src_a},{src_b}"),
            "-T",
            "note-merged",
            "-s",
            "merged summary",
            "-n",
            "probe",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let consolidate_stdout = String::from_utf8(out).expect("utf-8 consolidate output");
    let consolidated = consolidate_stdout
        .rsplit(':')
        .next()
        .expect("consolidate names the new id")
        .trim()
        .to_string();
    (live, consolidated, vec![src_a, src_b])
}

/// Run `export` and return `(exit_code, parsed_stdout, stderr)`.
fn export(db: &Path, extra: &[&str]) -> (i32, serde_json::Value, String) {
    let assert = ai_memory(db).arg("export").args(extra).assert();
    let out = assert.get_output();
    let code = out.status.code().expect("export exits with a code");
    let stdout: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("export stdout stays valid JSON");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

/// Run `import --json` against `payload` and return `(exit_code, report, stderr)`.
fn import(db: &Path, payload: &str, extra: &[&str]) -> (i32, serde_json::Value, String) {
    let assert = ai_memory(db)
        .arg("--json")
        .arg("import")
        .args(extra)
        .write_stdin(payload.to_string())
        .assert();
    let out = assert.get_output();
    let code = out.status.code().expect("import exits with a code");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("import --json emits a JSON report");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, report, stderr)
}

// ── 1. THE ALLOWED PATH — a bundle round-trips through its own binary ──

/// THE #3405 REGRESSION. A corpus holding tombstoned rows that edges still
/// name must export exit-0 WITHOUT dangling edges, and that artifact must
/// import exit-0 into a fresh store.
///
/// At the parent commit the export carried three edges to tombstoned rows and
/// the import exited 3 with `links_refused: 3`.
#[test]
fn export_import_round_trips_a_store_with_tombstones_and_links_3405() {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("src.db");
    let dst = tmp.path().join("dst.db");
    let (live, consolidated, tombstoned) = seed_tombstoned_corpus(&src);

    let (code, bundle, stderr) = export(&src, &[]);
    assert_eq!(
        code, 0,
        "a corpus whose only omissions are tombstones is not partial; stderr: {stderr}"
    );

    // Producer control: no edge names a memory the artifact does not carry.
    let carried: std::collections::HashSet<&str> = bundle["memories"]
        .as_array()
        .expect("memories array")
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert!(
        carried.contains(live.as_str()) && carried.contains(consolidated.as_str()),
        "both live rows ride the artifact"
    );
    for id in &tombstoned {
        assert!(
            !carried.contains(id.as_str()),
            "the tombstoned source {id} is correctly withheld"
        );
    }
    for link in bundle["links"].as_array().expect("links array") {
        let (s, t) = (
            link["source_id"].as_str().expect("source_id"),
            link["target_id"].as_str().expect("target_id"),
        );
        assert!(
            carried.contains(s) && carried.contains(t),
            "#3405: the artifact emitted an edge {s}->{t} whose endpoint it does not carry"
        );
    }

    // …and the loss is REPORTED, never silent: in-band as a COUNT, on the
    // operator channel with the edges (ids never ride the artifact — #2490 O3).
    assert_eq!(
        bundle["withheld"]["dangling_links_withheld"].as_u64(),
        Some(3),
        "three edges named a tombstoned endpoint and must be counted in-band"
    );
    assert_eq!(
        bundle["withheld"]["tombstoned"].as_u64(),
        Some(2),
        "both consolidated sources are retained as tombstoned rows"
    );
    assert!(
        bundle["withheld"].get("dangling_link_edges").is_none(),
        "the rendered edges name withheld ids and must NEVER ride the portable artifact"
    );
    assert!(
        stderr.contains("dangling_link_edges") && stderr.contains("export_report"),
        "the structured operator line carries the edges; got: {stderr}"
    );

    // Consumer: the artifact its own binary produced restores cleanly.
    let payload = serde_json::to_string(&bundle).expect("re-serialize bundle");
    let (code, report, stderr) = import(&dst, &payload, &[]);
    assert_eq!(
        code, 0,
        "#3405: import must exit 0 on a bundle the same binary exported; \
         report={report}, stderr={stderr}"
    );
    assert_eq!(report["links_refused"].as_u64(), Some(0));
    assert_eq!(report["links_skipped_dangling"].as_u64(), Some(0));
    assert_eq!(report["imported"].as_u64(), Some(2));
}

/// The same round-trip on the Portability-v2 `--full` envelope: it composes
/// `memories[]` and `links[]` from the same two independent reads and carries
/// tombstones AS `forget_tombstones`, never as live rows.
#[test]
fn full_envelope_round_trips_a_store_with_tombstones_and_links_3405() {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("src.db");
    let dst = tmp.path().join("dst.db");
    let (_live, _consolidated, _tombstoned) = seed_tombstoned_corpus(&src);

    let (code, envelope, stderr) = export(&src, &["--full"]);
    assert_eq!(code, 0, "export --full over a tombstoned corpus; {stderr}");

    let carried: std::collections::HashSet<&str> = envelope["memories"]
        .as_array()
        .expect("memories array")
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    for link in envelope["links"].as_array().expect("links array") {
        let (s, t) = (
            link["source_id"].as_str().expect("source_id"),
            link["target_id"].as_str().expect("target_id"),
        );
        assert!(
            carried.contains(s) && carried.contains(t),
            "#3405: the v2 envelope emitted an edge {s}->{t} it cannot carry"
        );
    }

    let payload = serde_json::to_string(&envelope).expect("re-serialize envelope");
    let (code, report, stderr) = import(&dst, &payload, &[]);
    assert_eq!(
        code, 0,
        "#3405: the v2 envelope must round-trip through its own importer; \
         report={report}, stderr={stderr}"
    );
    assert_eq!(
        report["links_skipped_missing_endpoint"].as_u64(),
        Some(0),
        "a producer-side-consistent envelope leaves no unresolvable edge"
    );
}

// ── 2. THE DENIED PATH — a dangling bundle is refused, loudly, with a door ──

/// A hand-built bundle whose edge names a memory the bundle does not carry —
/// exactly what every pre-#3405 exporter produced. It must NOT be applied
/// silently: exit [`EXIT_INCOMPLETE`], the edge counted under its OWN
/// `links_skipped_dangling` disposition (not conflated with a destination
/// refusal), and the message must name the override.
#[test]
fn import_refuses_a_dangling_bundle_and_names_the_override_3405() {
    let tmp = TempDir::new().expect("tempdir");
    let dst = tmp.path().join("dst.db");
    let payload = serde_json::json!({
        "memories": [{
            "id": "11111111-1111-4111-8111-111111111111",
            "tier": "long",
            "namespace": "probe",
            "title": "kept",
            "content": "the endpoint that IS carried",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "import",
            "access_count": 0,
            "created_at": "2026-07-14T00:00:00+00:00",
            "updated_at": "2026-07-14T00:00:00+00:00",
            "metadata": {},
            "version": 1
        }],
        "links": [{
            "source_id": "11111111-1111-4111-8111-111111111111",
            "target_id": "22222222-2222-4222-8222-222222222222",
            "relation": "related_to",
            "created_at": "2026-07-14T00:00:00+00:00"
        }]
    })
    .to_string();

    let (code, report, stderr) = import(&dst, &payload, &[]);
    assert_eq!(
        code, EXIT_INCOMPLETE,
        "a bundle that cannot be faithfully reconstructed stays fail-closed; \
         report={report}"
    );
    assert_eq!(
        report["links_skipped_dangling"].as_u64(),
        Some(1),
        "the edge is attributed to the PRODUCER defect, not to a destination refusal"
    );
    assert_eq!(
        report["links_refused"].as_u64(),
        Some(0),
        "a dangling artifact is not a destination refusal — the counters must not conflate"
    );
    assert_eq!(
        report["imported"].as_u64(),
        Some(1),
        "DEGRADE, never withhold: every applicable row still lands"
    );
    assert!(
        stderr.contains("--allow-dangling"),
        "the refusal must name the operator's disposition; got: {stderr}"
    );
    assert!(
        stderr.contains("DANGLING"),
        "the refusal must say WHICH defect it is; got: {stderr}"
    );
}

/// The ratchet: the same bundle with the explicit acknowledgement exits 0,
/// the edge is STILL skipped and STILL reported (the flag is not a mute), and
/// the acknowledgement is recorded in the machine-readable report.
#[test]
fn allow_dangling_accepts_the_incomplete_graph_without_muting_it_3405() {
    let tmp = TempDir::new().expect("tempdir");
    let dst = tmp.path().join("dst.db");
    let payload = serde_json::json!({
        "memories": [{
            "id": "11111111-1111-4111-8111-111111111111",
            "tier": "long",
            "namespace": "probe",
            "title": "kept",
            "content": "the endpoint that IS carried",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "import",
            "access_count": 0,
            "created_at": "2026-07-14T00:00:00+00:00",
            "updated_at": "2026-07-14T00:00:00+00:00",
            "metadata": {},
            "version": 1
        }],
        "links": [{
            "source_id": "11111111-1111-4111-8111-111111111111",
            "target_id": "22222222-2222-4222-8222-222222222222",
            "relation": "related_to",
            "created_at": "2026-07-14T00:00:00+00:00"
        }]
    })
    .to_string();

    let (code, report, stderr) = import(&dst, &payload, &["--allow-dangling"]);
    assert_eq!(code, 0, "the acknowledged ratchet exits 0; stderr={stderr}");
    assert_eq!(
        report["links_skipped_dangling"].as_u64(),
        Some(1),
        "the flag governs the EXIT CODE only — the edge is still skipped and still counted"
    );
    assert_eq!(
        report["allow_dangling"].as_bool(),
        Some(true),
        "the acknowledgement is recorded in the report, never implicit"
    );
    assert!(
        stderr.contains("--allow-dangling"),
        "the acknowledged skip is still announced; got: {stderr}"
    );
    assert_eq!(report["imported"].as_u64(), Some(1));
}

/// The discrimination that keeps `--allow-dangling` from becoming a blanket
/// mute: an endpoint the bundle DID carry but whose row was refused at the
/// destination is a genuine reconstruction failure, so the edge still counts
/// toward the non-zero exit EVEN WITH the flag set.
#[test]
fn allow_dangling_never_excuses_an_endpoint_the_bundle_carried_3405() {
    let tmp = TempDir::new().expect("tempdir");
    let dst = tmp.path().join("dst.db");
    // The second memory carries an INVALID tier, so `validate_memory` refuses
    // that row; the bundle nonetheless carried its id, so the edge naming it
    // is a reconstruction failure, not a dangling artifact.
    let payload = serde_json::json!({
        "memories": [
            {
                "id": "11111111-1111-4111-8111-111111111111",
                "tier": "long",
                "namespace": "probe",
                "title": "kept",
                "content": "the endpoint that IS carried",
                "tags": [], "priority": 5, "confidence": 1.0, "source": "import",
                "access_count": 0,
                "created_at": "2026-07-14T00:00:00+00:00",
                "updated_at": "2026-07-14T00:00:00+00:00",
                "metadata": {}, "version": 1
            },
            {
                "id": "22222222-2222-4222-8222-222222222222",
                "tier": "long",
                "namespace": "probe",
                "title": "",
                "content": "",
                "tags": [], "priority": 5, "confidence": 1.0, "source": "import",
                "access_count": 0,
                "created_at": "2026-07-14T00:00:00+00:00",
                "updated_at": "2026-07-14T00:00:00+00:00",
                "metadata": {}, "version": 1
            }
        ],
        "links": [{
            "source_id": "11111111-1111-4111-8111-111111111111",
            "target_id": "22222222-2222-4222-8222-222222222222",
            "relation": "related_to",
            "created_at": "2026-07-14T00:00:00+00:00"
        }]
    })
    .to_string();

    let (code, report, stderr) = import(&dst, &payload, &["--allow-dangling"]);
    assert_eq!(
        report["links_skipped_dangling"].as_u64(),
        Some(0),
        "the bundle CARRIED the endpoint, so this is not a dangling artifact; report={report}"
    );
    assert_eq!(
        report["links_refused"].as_u64(),
        Some(1),
        "a bundle-carried endpoint that did not land is a reconstruction FAILURE"
    );
    assert_eq!(
        code, EXIT_INCOMPLETE,
        "--allow-dangling must not launder a genuine refusal; stderr={stderr}"
    );
}
