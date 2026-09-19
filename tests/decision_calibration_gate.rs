// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3806 W5 — the pins that make the decision-provider calibration harness
//! load-bearing.
//!
//! The harness itself is `tests/decision_calibration/` (test-only; nothing in
//! any production path). This binary is its gate:
//!
//! | pin | proves |
//! |---|---|
//! | `preregistration_binds_every_heldout_set` | the held-out sets are exactly what was committed |
//! | `manifest_mismatch_is_refused` | editing a fixture without its manifest goes RED (three arms: changed bytes, missing file, unlisted file) |
//! | `heldout_sets_pass_their_seam_gate` | a calibrated provider is GREEN |
//! | `miscalibrated_control_fails_the_ece_gate` | the gate can go RED, on the ECE arm specifically |
//! | `null_baseline_absent_and_provider_present` | ALWAYS-ABSTAIN yields NO ECE (absence) while the provider on the SAME record yields one (presence) |
//! | `baselines_bracket_every_provider_figure` | oracle <= provider < miscalibrated |
//! | `report_is_byte_identical_across_runs` | determinism under the fixed seed |
//! | `seed_moves_only_the_resample` | the seed is load-bearing, and moves the bootstrap bound only — never the measurement |
//! | `report_vocabulary_is_closed` | no free text reaches a report |
//! | `report_is_bound_to_tree_and_manifest` | every figure names the tree and the held-out set that produced it |
//! | `pinned_figures_are_stable` | the numbers themselves, golden |
//! | `loader_refuses_off_contract_lines` | fail-closed parsing, with a presence control |
//! | `item_ids_are_unique_across_the_whole_corpus` | one item cannot vote twice, and a set cannot be padded from a neighbour |
//! | `every_seam_has_a_gate_row` | no seam is measured without a published threshold |
//! | `report_is_written_for_the_evidence_producer` | the producer's report path round-trips |
//!
//! rust-1.98 ERRORS-24: `unwrap`/`expect` are the correct idiom here.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

mod decision_calibration;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use decision_calibration::report::{CalibrationReport, build, build_repo_default, render};
use decision_calibration::{
    BIN_COUNT, CALIBRATION_SEED, ENV_REPORT_OUT, Expectation, FixtureDirKind, FixtureVariant,
    GateVerdict, MANIFEST_FILE, ProviderSource, Refusal, ReportVerdict, Seam, gate_for,
    load_fixture, parse_fixture_name, sha256_hex, verify_manifest,
};

fn fixture_dir() -> PathBuf {
    decision_calibration::report::repo_fixture_dir()
}

fn report() -> CalibrationReport {
    build_repo_default().expect("the in-repo preregistered sets measure cleanly")
}

/// Copy the preregistered directory somewhere writable so a pin can mutate it
/// WITHOUT touching the committed corpus.
fn scratch_copy() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dst = tmp.path().join("decision-calibration");
    std::fs::create_dir_all(&dst).expect("mkdir");
    for entry in std::fs::read_dir(fixture_dir()).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        std::fs::copy(entry.path(), dst.join(entry.file_name())).expect("copy fixture");
    }
    (tmp, dst)
}

// ---------------------------------------------------------------------------
// Preregistration
// ---------------------------------------------------------------------------

#[test]
fn preregistration_binds_every_heldout_set() {
    let verified = verify_manifest(&fixture_dir()).expect("manifest verifies on a clean tree");
    assert_eq!(
        verified.manifest_sha256.len(),
        64,
        "the manifest digest is what a report names the corpus by"
    );
    assert!(
        verified.files.len() >= 5,
        "expected four held-out sets plus the miscalibrated control, saw {}",
        verified.files.len()
    );

    let mut heldout_seams = BTreeSet::new();
    let mut negative_controls = 0usize;
    for (file, digest) in &verified.files {
        let (seam, variant) =
            parse_fixture_name(file).expect("preregistered name is in-vocabulary");
        assert_eq!(digest.len(), 64, "{file} digest is a sha256");
        match variant {
            FixtureVariant::Heldout => {
                heldout_seams.insert(seam);
            }
            FixtureVariant::Miscalibrated => negative_controls += 1,
        }
    }
    for seam in Seam::ALL {
        assert!(
            heldout_seams.contains(seam),
            "seam {} has no preregistered held-out set",
            seam.as_str()
        );
    }
    assert!(
        negative_controls >= 1,
        "a gate with no negative control gates nothing"
    );
}

#[test]
fn manifest_mismatch_is_refused() {
    // Arm 1 — a fixture's bytes move without its manifest entry.
    let (_tmp, dir) = scratch_copy();
    let victim = dir.join("classify_kind.heldout.jsonl");
    let mut text = std::fs::read_to_string(&victim).expect("read victim");
    text.push_str(
        "{\"item_id\":\"ck-h-999\",\"label\":true,\"predicted\":0.5,\
         \"seam\":\"classify_kind\",\"source\":\"decision_model\"}\n",
    );
    std::fs::write(&victim, &text).expect("write victim");
    assert_eq!(
        verify_manifest(&dir).err(),
        Some(Refusal::ManifestDigestMismatch {
            file: "classify_kind.heldout.jsonl".to_string()
        }),
        "a held-out set that changed without its manifest MUST go red"
    );

    // Arm 2 — a preregistered fixture disappears.
    let (_tmp2, dir2) = scratch_copy();
    std::fs::remove_file(dir2.join("synthesis_verdict.miscalibrated.jsonl")).expect("rm");
    assert_eq!(
        verify_manifest(&dir2).err(),
        Some(Refusal::ManifestFileMissing {
            file: "synthesis_verdict.miscalibrated.jsonl".to_string()
        }),
        "deleting the negative control MUST go red, not silently shrink the corpus"
    );

    // Arm 3 — an extra held-out set appears that nobody preregistered.
    let (_tmp3, dir3) = scratch_copy();
    std::fs::write(
        dir3.join("classify_kind.heldout2.jsonl"),
        "{\"item_id\":\"ck-x-001\",\"label\":true,\"predicted\":0.5,\
         \"seam\":\"classify_kind\",\"source\":\"decision_model\"}\n",
    )
    .expect("plant");
    assert_eq!(
        verify_manifest(&dir3).err(),
        Some(Refusal::FixtureNotInManifest {
            file: "classify_kind.heldout2.jsonl".to_string()
        }),
        "you cannot grow a held-out set after seeing the numbers"
    );

    // PRESENCE CONTROL on the same sink: the untouched copy still verifies, so
    // the three refusals above are the mutation talking, not a broken harness.
    let (_tmp4, dir4) = scratch_copy();
    assert!(
        verify_manifest(&dir4).is_ok(),
        "an unmutated copy of the corpus must verify"
    );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn heldout_sets_pass_their_seam_gate() {
    let report = report();
    let mut checked = 0usize;
    for s in &report.seams {
        if s.variant != FixtureVariant::Heldout {
            continue;
        }
        checked += 1;
        assert_eq!(
            s.gate.verdict,
            GateVerdict::Pass,
            "{} scored ECE {:?} against a ceiling of {}",
            s.fixture_file,
            s.provider.ece,
            s.gate.max_ece
        );
        assert_eq!(s.expectation, Expectation::ExpectPass);
        assert!(s.expectation_met);
    }
    assert_eq!(checked, Seam::ALL.len(), "every seam must be measured");
}

#[test]
fn miscalibrated_control_fails_the_ece_gate() {
    let report = report();
    let s = report
        .seams
        .iter()
        .find(|s| s.variant == FixtureVariant::Miscalibrated)
        .expect("the negative control is preregistered");

    assert_eq!(
        s.gate.verdict,
        GateVerdict::FailEce,
        "the deliberately overconfident set must be caught BY THE ECE ARM \
         (a coverage refusal would not prove the ceiling works)"
    );
    assert!(
        s.coverage >= s.gate.min_coverage,
        "the control must clear the coverage floor ({} >= {}) so the only thing \
         failing it is the ECE ceiling",
        s.coverage,
        s.gate.min_coverage
    );
    let ece = s.provider.ece.expect("the control scored items");
    assert!(
        ece > s.gate.max_ece,
        "control ECE {ece} must exceed the ceiling {}",
        s.gate.max_ece
    );
    assert_eq!(s.expectation, Expectation::ExpectFailEce);
    assert!(
        s.expectation_met,
        "a negative control that stopped failing is a gate that stopped gating"
    );
    assert_eq!(
        report.verdict,
        ReportVerdict::Pass,
        "the report is PASS because every set met its DECLARED expectation"
    );
}

// ---------------------------------------------------------------------------
// Baselines — absence with its presence control on the same sink
// ---------------------------------------------------------------------------

#[test]
fn null_baseline_absent_and_provider_present() {
    let report = report();
    assert!(!report.seams.is_empty());
    for s in &report.seams {
        let null = &s.baseline_null_always_abstain;
        // ABSENCE: always-abstain has no calibration to report.
        assert_eq!(null.metrics.n_scored, 0, "{}", s.fixture_file);
        assert!(
            null.metrics.ece.is_none() && null.metrics.brier.is_none(),
            "{}: the null baseline must report ABSENT figures, never a \
             flattering 0.0 — ECE is trivially gamed by abstaining",
            s.fixture_file
        );
        assert!(null.metrics.ece_bootstrap_p95.is_none());
        assert_eq!(
            null.gate_verdict,
            GateVerdict::RefusedNoCoverage,
            "{}: always-abstain must be REFUSED on coverage, not passed",
            s.fixture_file
        );
        assert_eq!(null.metrics.reliability.len(), BIN_COUNT);
        assert!(null.metrics.reliability.iter().all(|b| b.count == 0));

        // PRESENCE, same record, same sink: the provider does report figures.
        assert!(
            s.provider.ece.is_some() && s.provider.brier.is_some(),
            "{}: the provider must report figures on the very set where the \
             null baseline reports none",
            s.fixture_file
        );
        assert!(s.provider.n_scored > 0);
        assert!(s.provider.ece_bootstrap_p95.is_some());

        // POSITIVE control: the oracle answers the truth and never abstains.
        let oracle = &s.baseline_oracle;
        assert_eq!(oracle.metrics.n_scored, s.n_items, "{}", s.fixture_file);
        assert_eq!(oracle.metrics.brier, Some(0.0), "{}", s.fixture_file);
        assert_eq!(oracle.metrics.ece, Some(0.0), "{}", s.fixture_file);
        assert_eq!(oracle.gate_verdict, GateVerdict::Pass, "{}", s.fixture_file);
    }
}

#[test]
fn baselines_bracket_every_provider_figure() {
    let report = report();
    for s in &report.seams {
        let oracle = s.baseline_oracle.metrics.ece.expect("oracle ECE present");
        let provider = s.provider.ece.expect("provider ECE present");
        assert!(
            oracle <= provider,
            "{}: the oracle must be at least as calibrated as the provider \
             ({oracle} <= {provider})",
            s.fixture_file
        );
    }

    // Same seam, two preregistered sets: the ordering of the well-calibrated
    // set against its deliberately miscalibrated twin is the whole claim.
    let good = report
        .seams
        .iter()
        .find(|s| s.seam == Seam::SynthesisVerdict && s.variant == FixtureVariant::Heldout)
        .expect("synthesis held-out set");
    let bad = report
        .seams
        .iter()
        .find(|s| s.seam == Seam::SynthesisVerdict && s.variant == FixtureVariant::Miscalibrated)
        .expect("synthesis negative control");
    let (g, b) = (
        good.provider.ece.expect("ece"),
        bad.provider.ece.expect("ece"),
    );
    assert!(
        g < b,
        "the calibrated twin must score below the miscalibrated one ({g} < {b})"
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn report_is_byte_identical_across_runs() {
    let first = render(&report());
    let second = render(&report());
    assert_eq!(
        first, second,
        "two runs of the same tree at the same seed must render byte-identically"
    );
    assert!(first.len() > 1_000, "the report is not a stub");
}

#[test]
fn seed_moves_only_the_resample() {
    let pinned = report();
    let other = build(
        &fixture_dir(),
        FixtureDirKind::RepoSyntheticControl,
        CALIBRATION_SEED ^ 0xFFFF_FFFF,
    )
    .expect("an alternate seed still measures");

    assert_eq!(
        pinned.seams.len(),
        other.seams.len(),
        "the corpus does not depend on the seed"
    );
    let mut moved = 0usize;
    for (a, b) in pinned.seams.iter().zip(other.seams.iter()) {
        assert_eq!(a.fixture_file, b.fixture_file);
        // The MEASUREMENT is seed-independent: Brier, ECE and the reliability
        // curve are pure functions of the preregistered bytes.
        assert_eq!(a.provider.ece, b.provider.ece, "{}", a.fixture_file);
        assert_eq!(a.provider.brier, b.provider.brier, "{}", a.fixture_file);
        assert_eq!(a.gate.verdict, b.gate.verdict, "{}", a.fixture_file);
        if a.provider.ece_bootstrap_p95 != b.provider.ece_bootstrap_p95 {
            moved += 1;
        }
    }
    assert!(
        moved > 0,
        "the seed must be LOAD-BEARING: if no bootstrap bound moves when the \
         seed changes, the seed is decorative and the determinism pin proves \
         nothing"
    );
    assert_ne!(pinned.seed, other.seed, "the report names its seed");
}

// ---------------------------------------------------------------------------
// Closed vocabulary + binding
// ---------------------------------------------------------------------------

fn collect_strings(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(s) => {
            out.insert(s.clone());
        }
        serde_json::Value::Array(items) => {
            for v in items {
                collect_strings(v, out);
            }
        }
        // Keys are Rust field names from `#[derive(Serialize)]`; only VALUES
        // could ever carry text from outside the tree, so only values are
        // audited here.
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn report_vocabulary_is_closed() {
    let rendered = render(&report());
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("report is JSON");
    let mut strings = BTreeSet::new();
    collect_strings(&value, &mut strings);
    assert!(!strings.is_empty());

    let mut vocabulary: BTreeSet<String> = BTreeSet::new();
    vocabulary.insert("decision_calibration".to_string());
    vocabulary.insert("decision-calibration".to_string());
    vocabulary.insert("repo_synthetic_control".to_string());
    vocabulary.insert("operator_supplied".to_string());
    vocabulary.insert("PASS".to_string());
    vocabulary.insert("FAIL".to_string());
    for token in [
        "pass",
        "fail_ece",
        "refused_no_coverage",
        "refused_insufficient_items",
        "expect_pass",
        "expect_fail_ece",
        "heldout",
        "miscalibrated",
    ] {
        vocabulary.insert(token.to_string());
    }
    for seam in Seam::ALL {
        vocabulary.insert(seam.as_str().to_string());
        for variant in [FixtureVariant::Heldout, FixtureVariant::Miscalibrated] {
            vocabulary.insert(format!("{}.{}.jsonl", seam.as_str(), variant.as_str()));
        }
    }
    for source in [
        ProviderSource::DecisionModel,
        ProviderSource::GenerativeFallback,
        ProviderSource::Deterministic,
    ] {
        vocabulary.insert(source.as_str().to_string());
    }

    for s in &strings {
        let ok = vocabulary.contains(s)
            || is_hex(s, 40)
            || is_hex(s, 64)
            || (s.starts_with("0x") && is_hex(&s[2..], 16));
        assert!(
            ok,
            "report carries a string outside the closed vocabulary: {s:?}. \
             No free text — from a model or anywhere else — may reach a report."
        );
    }
}

#[test]
fn report_is_bound_to_tree_and_manifest() {
    let report = report();
    assert!(
        is_hex(&report.source_commit, 40),
        "source_commit must name the tree: {}",
        report.source_commit
    );

    let manifest_bytes =
        std::fs::read(fixture_dir().join(MANIFEST_FILE)).expect("read the manifest");
    assert_eq!(
        report.fixture_manifest_sha256,
        sha256_hex(&manifest_bytes),
        "the report must name the preregistered corpus it measured"
    );
    assert_eq!(
        report.fixture_dir_kind,
        FixtureDirKind::RepoSyntheticControl
    );
    assert_eq!(report.bin_count, BIN_COUNT);
    assert_eq!(report.verdict, ReportVerdict::Pass);

    for s in &report.seams {
        let bytes = std::fs::read(fixture_dir().join(&s.fixture_file)).expect("read fixture");
        assert_eq!(
            s.fixture_sha256,
            sha256_hex(&bytes),
            "{} must carry its own digest",
            s.fixture_file
        );
        assert_eq!(s.n_items, s.n_scored + s.n_abstained, "{}", s.fixture_file);
        let counts = &s.by_source;
        assert_eq!(
            counts.decision_model + counts.generative_fallback + counts.deterministic,
            s.n_items,
            "{}: per-source counts must account for every item",
            s.fixture_file
        );
    }
}

// ---------------------------------------------------------------------------
// The numbers themselves
// ---------------------------------------------------------------------------

/// `(fixture, brier, ece)` at six decimals on the preregistered corpus.
/// These are GOLDEN: a change here means the corpus or the metric moved, and
/// either is a deliberate act that belongs in the diff.
const PINNED_FIGURES: &[(&str, f64, f64)] = &[
    ("classify_kind.heldout.jsonl", 0.149_300, 0.043_333),
    ("consolidation_merge.heldout.jsonl", 0.160_300, 0.060_000),
    ("detect_contradiction.heldout.jsonl", 0.147_967, 0.050_000),
    ("synthesis_verdict.heldout.jsonl", 0.153_967, 0.056_667),
    // 0.294667 against a 0.10 ceiling: the negative control fails with ~3x
    // margin, so the gate is not riding a rounding edge.
    (
        "synthesis_verdict.miscalibrated.jsonl",
        0.269_247,
        0.294_667,
    ),
];

#[test]
fn pinned_figures_are_stable() {
    let report = report();
    assert_eq!(report.seams.len(), PINNED_FIGURES.len());
    for (file, brier, ece) in PINNED_FIGURES {
        let s = report
            .seams
            .iter()
            .find(|s| s.fixture_file == *file)
            .unwrap_or_else(|| panic!("{file} is preregistered"));
        assert_eq!(
            s.provider.brier,
            Some(*brier),
            "{file} Brier drifted (actual {:?})",
            s.provider.brier
        );
        assert_eq!(
            s.provider.ece,
            Some(*ece),
            "{file} ECE drifted (actual {:?})",
            s.provider.ece
        );
    }
}

// ---------------------------------------------------------------------------
// Fail-closed loading
// ---------------------------------------------------------------------------

fn load_line(name: &str, body: &str) -> Result<decision_calibration::Fixture, Refusal> {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(tmp.path().join(name), body).expect("plant");
    load_fixture(tmp.path(), name, &"0".repeat(64))
}

const GOOD_LINE: &str = "{\"item_id\":\"ck-h-001\",\"label\":true,\"predicted\":0.5,\
     \"seam\":\"classify_kind\",\"source\":\"decision_model\"}\n";

#[test]
fn loader_refuses_off_contract_lines() {
    let name = "classify_kind.heldout.jsonl";

    // PRESENCE CONTROL first: the on-contract line loads.
    let ok = load_line(name, GOOD_LINE).expect("a well-formed line loads");
    assert_eq!(ok.items.len(), 1);
    assert_eq!(ok.seam, Seam::ClassifyKind);
    assert_eq!(ok.variant, FixtureVariant::Heldout);
    assert_eq!(ok.items[0].predicted, Some(0.5));

    let cases: &[(&str, Refusal)] = &[
        // A free-text field smuggled in alongside the five keys.
        (
            "{\"item_id\":\"ck-h-001\",\"label\":true,\"predicted\":0.5,\
             \"seam\":\"classify_kind\",\"source\":\"decision_model\",\
             \"reason\":\"the model said so\"}",
            Refusal::LineKeySetWrong {
                file: name.to_string(),
                line: 1,
            },
        ),
        // A MISSING key is a refusal too: serde would have read an absent
        // `predicted` as `None`, quietly inventing an abstain.
        (
            "{\"item_id\":\"ck-h-001\",\"label\":true,\
             \"seam\":\"classify_kind\",\"source\":\"decision_model\"}",
            Refusal::LineKeySetWrong {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "{\"item_id\":\"ck-h-001\",\"label\":true,\"predicted\":1.5,\
             \"seam\":\"classify_kind\",\"source\":\"decision_model\"}",
            Refusal::PredictedOutOfRange {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "{\"item_id\":\"ck-h-001\",\"label\":true,\"predicted\":\"abstain\",\
             \"seam\":\"classify_kind\",\"source\":\"decision_model\"}",
            Refusal::PredictedOutOfRange {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "{\"item_id\":\"ck-h-001\",\"label\":\"yes\",\"predicted\":0.5,\
             \"seam\":\"classify_kind\",\"source\":\"decision_model\"}",
            Refusal::LabelNotBool {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "{\"item_id\":\"ck-h-001\",\"label\":true,\"predicted\":0.5,\
             \"seam\":\"synthesis_verdict\",\"source\":\"decision_model\"}",
            Refusal::ItemSeamMismatch {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "{\"item_id\":\"ck-h-001\",\"label\":true,\"predicted\":0.5,\
             \"seam\":\"classify_kind\",\"source\":\"vibes\"}",
            Refusal::UnknownSource {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "{\"item_id\":\"CK\",\"label\":true,\"predicted\":0.5,\
             \"seam\":\"classify_kind\",\"source\":\"decision_model\"}",
            Refusal::ItemIdMalformed {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "not json at all",
            Refusal::LineNotJsonObject {
                file: name.to_string(),
                line: 1,
            },
        ),
        (
            "",
            Refusal::FixtureEmpty {
                file: name.to_string(),
            },
        ),
    ];

    for (body, expected) in cases {
        assert_eq!(
            load_line(name, body).err().as_ref(),
            Some(expected),
            "off-contract line was not refused as expected: {body}"
        );
    }

    // A repeated item_id would let one item vote twice.
    let doubled = format!("{GOOD_LINE}{GOOD_LINE}");
    assert_eq!(
        load_line(name, &doubled).err(),
        Some(Refusal::ItemIdDuplicated {
            file: name.to_string(),
            line: 2
        })
    );

    // The filename is the seam/variant binding; it cannot be off-vocabulary.
    assert_eq!(
        load_line("permissions_evaluate.heldout.jsonl", GOOD_LINE).err(),
        Some(Refusal::UnknownSeam {
            file: "permissions_evaluate.heldout.jsonl".to_string()
        }),
        "the decider is never calibrated on a governance seam"
    );
    assert_eq!(
        load_line("classify_kind.tuned.jsonl", GOOD_LINE).err(),
        Some(Refusal::UnknownVariant {
            file: "classify_kind.tuned.jsonl".to_string()
        })
    );
}

#[test]
fn item_ids_are_unique_across_the_whole_corpus() {
    // An item that appears in two preregistered sets would vote twice, and a
    // set could be silently padded with a neighbour's items.
    let verified = verify_manifest(&fixture_dir()).expect("manifest verifies");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut total = 0usize;
    for (file, digest) in &verified.files {
        let fixture = load_fixture(&fixture_dir(), file, digest).expect("fixture loads");
        for item in &fixture.items {
            total += 1;
            assert!(
                seen.insert(item.item_id.clone()),
                "{}: item_id {} is not unique across the corpus",
                file,
                item.item_id
            );
        }
    }
    assert_eq!(seen.len(), total, "every item is counted exactly once");
    assert!(
        total >= 300,
        "the corpus is too small to calibrate on: {total}"
    );
}

#[test]
fn every_seam_has_a_gate_row() {
    for seam in Seam::ALL {
        let gate = gate_for(*seam);
        assert!(
            gate.max_ece > 0.0 && gate.max_ece <= 0.2,
            "{}: an ECE ceiling above 0.2 would certify a provider whose \
             claimed probabilities are meaningless",
            seam.as_str()
        );
        assert!(gate.min_coverage >= 0.5, "{}", seam.as_str());
        assert!(gate.min_scored_items >= 40, "{}", seam.as_str());
    }
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

#[test]
fn report_is_written_for_the_evidence_producer() {
    // The producer resolves its corpus from the environment (an operator's own
    // preregistered directory, or the in-repo controls); a plain `cargo test`
    // run resolves to the in-repo controls.
    let rendered = render(
        &decision_calibration::report::build_from_env().expect("the resolved corpus measures"),
    );
    let default_out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("decision-calibration.json");
    std::fs::write(&default_out, &rendered).expect("write the report");
    let read_back = std::fs::read_to_string(&default_out).expect("read the report back");
    assert_eq!(read_back, rendered);

    // `scripts/evidence/decision-calibration.sh` asks for it by path.
    if let Ok(path) = std::env::var(ENV_REPORT_OUT)
        && !path.trim().is_empty()
    {
        if let Some(parent) = Path::new(&path).parent() {
            std::fs::create_dir_all(parent).expect("create the report directory");
        }
        std::fs::write(&path, &rendered).expect("write the requested report");
    }
}
