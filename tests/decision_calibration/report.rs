// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3806 W5 — rendering a calibration report from a CLOSED VOCABULARY.
//!
//! Every string in a rendered report is one of:
//!
//! * a token from a Rust enum in the parent module ([`super::Seam`],
//!   [`super::FixtureVariant`], [`super::ProviderSource`],
//!   [`super::GateVerdict`], [`super::Expectation`],
//!   [`super::FixtureDirKind`], [`super::ReportVerdict`]);
//! * a fixed literal owned by this file (`report_kind`, `producer_id`);
//! * a computed digest (sha256 / git sha) or a preregistered filename.
//!
//! There is no field a model — or a fixture author — can put prose into. The
//! loader's exact-key-set check is the other half of that guarantee: a line
//! carrying an extra `"reason"` string is refused, not silently ignored.
//!
//! The report carries `source_commit` and `fixture_manifest_sha256` so any
//! figure traces back to BOTH the tree that computed it and the held-out set
//! it was computed on. A figure that cannot name both is not a result, and
//! [`build`] refuses rather than emitting one.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{
    BOOTSTRAP_DRAWS, BinReport, CALIBRATION_SEED, ENV_SOURCE_COMMIT, Expectation, FIXTURE_DIR_REL,
    FixtureDirKind, GateVerdict, PRODUCER_ID, REPORT_KIND, REPORT_SCHEMA_VERSION, Refusal,
    ReportVerdict, Seam, SourceCounts, brier, ece, ece_bootstrap_p95, evaluate_gate, fixture_seed,
    gate_for, is_git_sha, load_fixture, reliability, round6, verify_manifest,
};

/// The in-repo held-out sets.
pub fn repo_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_DIR_REL)
}

/// Metric block for one producer (the provider, or a baseline).
#[derive(Debug, Clone, Serialize)]
pub struct MetricsReport {
    pub n_scored: usize,
    /// `None` means ABSENT, not zero: nothing was scored, so there is no score.
    pub brier: Option<f64>,
    pub ece: Option<f64>,
    pub ece_bootstrap_p95: Option<f64>,
    pub reliability: Vec<BinReport>,
}

impl MetricsReport {
    fn of(points: &[(f64, bool)], seed: u64) -> Self {
        Self {
            n_scored: points.len(),
            brier: brier(points).map(round6),
            ece: ece(points).map(round6),
            ece_bootstrap_p95: ece_bootstrap_p95(points, seed, BOOTSTRAP_DRAWS).map(round6),
            reliability: reliability(points),
        }
    }
}

/// A baseline computed on the SAME held-out set as the provider.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineReport {
    pub coverage: f64,
    pub gate_verdict: GateVerdict,
    #[serde(flatten)]
    pub metrics: MetricsReport,
}

/// The thresholds this seam was judged against, published next to the verdict
/// so a reader never has to go and find them.
#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    pub max_ece: f64,
    pub min_coverage: f64,
    pub min_scored_items: usize,
    pub verdict: GateVerdict,
}

/// One preregistered set, measured.
#[derive(Debug, Clone, Serialize)]
pub struct SeamReport {
    pub seam: Seam,
    pub variant: super::FixtureVariant,
    pub fixture_file: String,
    pub fixture_sha256: String,
    pub n_items: usize,
    pub n_scored: usize,
    pub n_abstained: usize,
    pub coverage: f64,
    pub by_source: SourceCounts,
    pub provider: MetricsReport,
    /// ALWAYS-ABSTAIN. The null baseline every report is read against.
    pub baseline_null_always_abstain: BaselineReport,
    /// Answers the truth, never abstains. The positive control.
    pub baseline_oracle: BaselineReport,
    pub gate: GateReport,
    pub expectation: Expectation,
    pub expectation_met: bool,
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct CalibrationReport {
    pub schema_version: u32,
    pub report_kind: &'static str,
    pub producer_id: &'static str,
    /// The tree that computed these figures.
    pub source_commit: String,
    /// Whose held-out sets these are.
    pub fixture_dir_kind: FixtureDirKind,
    /// sha256 of `MANIFEST.sha256` — the one value that names the whole
    /// preregistered corpus.
    pub fixture_manifest_sha256: String,
    pub seed: String,
    pub bin_count: usize,
    pub bootstrap_draws: usize,
    pub seams: Vec<SeamReport>,
    /// PASS iff EVERY preregistered set met its declared expectation: each
    /// held-out set passed its gate, and each miscalibrated control was caught
    /// by the ECE arm. A green report therefore proves the gate discriminates,
    /// not merely that today's numbers were flattering.
    pub verdict: ReportVerdict,
}

/// Resolve the tree binding. Env override first (the producer script already
/// knows the commit), then `git rev-parse HEAD`. Both absent is a REFUSAL:
/// an unbound figure is not a result.
pub fn resolve_source_commit() -> Result<String, Refusal> {
    if let Ok(v) = std::env::var(ENV_SOURCE_COMMIT) {
        let v = v.trim().to_string();
        return if is_git_sha(&v) {
            Ok(v)
        } else {
            Err(Refusal::SourceCommitUnbindable(format!(
                "{ENV_SOURCE_COMMIT} is not a 40-char lowercase git sha"
            )))
        };
    }
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| Refusal::SourceCommitUnbindable(format!("git not runnable: {e}")))?;
    if !out.status.success() {
        return Err(Refusal::SourceCommitUnbindable(
            "git rev-parse HEAD failed".to_string(),
        ));
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if is_git_sha(&sha) {
        Ok(sha)
    } else {
        Err(Refusal::SourceCommitUnbindable(
            "git rev-parse HEAD did not print a 40-char sha".to_string(),
        ))
    }
}

/// Measure one preregistered set against its seam gate.
fn seam_report(dir: &Path, file: &str, sha256: &str, seed: u64) -> Result<SeamReport, Refusal> {
    let fixture = load_fixture(dir, file, sha256)?;
    let gate = gate_for(fixture.seam);

    let scored = fixture.scored_points();
    let coverage = round6(fixture.coverage());
    let provider = MetricsReport::of(&scored, fixture_seed(seed, file));
    let verdict = evaluate_gate(gate, coverage, scored.len(), provider.ece);

    let null = MetricsReport::of(&[], fixture_seed(seed, file));
    let null_baseline = BaselineReport {
        coverage: 0.0,
        gate_verdict: evaluate_gate(gate, 0.0, 0, null.ece),
        metrics: null,
    };

    let oracle_points = fixture.oracle_points();
    let oracle = MetricsReport::of(&oracle_points, fixture_seed(seed, file));
    let oracle_baseline = BaselineReport {
        coverage: 1.0,
        gate_verdict: evaluate_gate(gate, 1.0, oracle_points.len(), oracle.ece),
        metrics: oracle,
    };

    let expectation = fixture.variant.expectation();
    let expectation_met = match expectation {
        Expectation::ExpectPass => verdict == GateVerdict::Pass,
        Expectation::ExpectFailEce => verdict == GateVerdict::FailEce,
    };

    Ok(SeamReport {
        seam: fixture.seam,
        variant: fixture.variant,
        fixture_file: fixture.file.clone(),
        fixture_sha256: fixture.sha256.clone(),
        n_items: fixture.items.len(),
        n_scored: scored.len(),
        n_abstained: fixture.n_abstained(),
        coverage,
        by_source: fixture.source_counts(),
        provider,
        baseline_null_always_abstain: null_baseline,
        baseline_oracle: oracle_baseline,
        gate: GateReport {
            max_ece: gate.max_ece,
            min_coverage: gate.min_coverage,
            min_scored_items: gate.min_scored_items,
            verdict,
        },
        expectation,
        expectation_met,
    })
}

/// Verify the preregistration, measure every set it names, and render.
pub fn build(
    dir: &Path,
    dir_kind: FixtureDirKind,
    seed: u64,
) -> Result<CalibrationReport, Refusal> {
    let manifest = verify_manifest(dir)?;
    let source_commit = resolve_source_commit()?;

    let mut seams = Vec::with_capacity(manifest.files.len());
    for (file, sha256) in &manifest.files {
        seams.push(seam_report(dir, file, sha256, seed)?);
    }
    seams.sort_by(|a, b| a.fixture_file.cmp(&b.fixture_file));

    // f1 F4 (#3806) — PASS certifies the CAMPAIGN, not just the rows
    // present: every seam's held-out set AND at least one negative control
    // (a miscalibrated set the gate must fail). A corpus whose rows all met
    // their expectations but that lacks any of these is PARTIAL — reported
    // as such, never as PASS, and the producer exits non-zero on it.
    let complete = super::Seam::ALL.iter().all(|seam| {
        seams
            .iter()
            .any(|s| s.seam == *seam && s.variant == super::FixtureVariant::Heldout)
    }) && seams
        .iter()
        .any(|s| s.variant == super::FixtureVariant::Miscalibrated);
    let verdict = if !seams.iter().all(|s| s.expectation_met) {
        ReportVerdict::Fail
    } else if complete {
        ReportVerdict::Pass
    } else {
        ReportVerdict::Partial
    };

    Ok(CalibrationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        report_kind: REPORT_KIND,
        producer_id: PRODUCER_ID,
        source_commit,
        fixture_dir_kind: dir_kind,
        fixture_manifest_sha256: manifest.manifest_sha256,
        seed: format!("{seed:#018x}"),
        bin_count: super::BIN_COUNT,
        bootstrap_draws: BOOTSTRAP_DRAWS,
        seams,
        verdict,
    })
}

/// The in-repo synthetic controls at the one named seed.
pub fn build_repo_default() -> Result<CalibrationReport, Refusal> {
    build(
        &repo_fixture_dir(),
        FixtureDirKind::RepoSyntheticControl,
        CALIBRATION_SEED,
    )
}

/// Serialize deterministically: two runs of the same tree at the same seed
/// produce byte-identical output.
pub fn render(report: &CalibrationReport) -> String {
    let mut s = serde_json::to_string_pretty(report).expect("report serializes");
    s.push('\n');
    s
}

/// Resolve the corpus the way the evidence producer does: an operator's own
/// preregistered directory when [`super::ENV_FIXTURE_DIR`] names one,
/// otherwise the in-repo synthetic controls. The report says which it was, so
/// a customer's numbers are never mistaken for ours or the reverse.
pub fn resolve_fixture_dir() -> (PathBuf, FixtureDirKind) {
    match std::env::var(super::ENV_FIXTURE_DIR) {
        Ok(dir) if !dir.trim().is_empty() => {
            (PathBuf::from(dir.trim()), FixtureDirKind::OperatorSupplied)
        }
        _ => (repo_fixture_dir(), FixtureDirKind::RepoSyntheticControl),
    }
}

/// What `scripts/evidence/decision-calibration.sh` renders.
pub fn build_from_env() -> Result<CalibrationReport, Refusal> {
    let (dir, kind) = resolve_fixture_dir();
    build(&dir, kind, CALIBRATION_SEED)
}
