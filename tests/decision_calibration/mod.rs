// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3806 W5 — the `[decision]` provider CALIBRATION HARNESS (test-only).
//!
//! Nothing in this module is compiled into any production path: it lives under
//! `tests/`, is reached only from integration-test binaries, and never touches
//! the daemon, a database, or the network. It is the measurement instrument for
//! the decision-provider work, folded into the #3564 / #3570 evidence-harness
//! family (preregistration, frozen held-out sets, null + positive baselines,
//! fixed seeds) rather than standing up a second harness of its own.
//!
//! # What it measures
//!
//! A decision provider answers a seam with either a PROBABILITY or an ABSTAIN.
//! Three figures say whether that probability means anything:
//!
//! * **Brier score** — mean squared error of the probability against the truth.
//!   A sharpness-and-calibration composite; lower is better, 0 is perfect.
//! * **Expected calibration error (ECE)** — the count-weighted mean gap between
//!   what the provider claimed and what actually happened, over
//!   [`BIN_COUNT`] fixed equal-width bins. This is the GATED figure: a provider
//!   that says "0.9" and is right 55 % of the time is the failure mode that
//!   turns an advisory verdict into a destructive one.
//! * **Reliability curve** — the per-bin (claimed, observed) pairs the ECE
//!   summarises, so a report shows WHERE the miscalibration lives.
//!
//! Every figure is reported between two baselines computed on the SAME
//! held-out set, so a number is never read in a vacuum:
//!
//! * the **null baseline** — ALWAYS-ABSTAIN. It has no scored items, so its
//!   ECE is ABSENT (`None`), not a flattering `0.0`, and its coverage is 0.
//!   That is the whole point: ECE alone is trivially gamed by abstaining, so
//!   the gate carries a coverage floor next to the ECE ceiling.
//! * the **oracle baseline** — a positive control that answers 1.0 / 0.0 with
//!   the truth and never abstains. Brier 0, ECE 0, coverage 1.
//!
//! # Preregistration
//!
//! The held-out sets are frozen BEFORE any result: every fixture's sha256 is
//! committed in `MANIFEST.sha256` and [`verify_manifest`] re-hashes the
//! directory on every run. Editing a fixture without updating the manifest is
//! a RED test, and so is adding an unlisted `.jsonl` — you cannot quietly grow
//! or trim a held-out set until the numbers look better.
//!
//! # Input shape (deliberately minimal — W1a-independent)
//!
//! One JSON object per line, EXACTLY these five keys:
//!
//! ```text
//! {"item_id":"sv-h-001","seam":"synthesis_verdict","source":"decision_model",
//!  "predicted":0.82,"label":true}
//! ```
//!
//! * `predicted` — the probability the provider assigned to the event "the
//!   preregistered label is TRUE", or `null` for an ABSTAIN. Explicit `null`
//!   is required; a missing key is a refusal, never an implied abstain.
//! * `label` — the preregistered ground truth (the independent oracle).
//! * `seam` / `source` — closed vocabularies ([`Seam`], [`ProviderSource`]).
//!
//! This shape is deliberately NOT the W1a `DecisionProvider` types: W5 must not
//! depend on a trait that is being built in parallel. When W1c / W2 land, each
//! seam adapts its own result into this shape — a `Judgement` contributes
//! `predicted = confidence of the claimed verdict` (or `null` when the verdict
//! is an abstain or no logprobs were returned), a `Choice` contributes
//! `predicted = probability of the chosen option` with `label = (chosen ==
//! truth)`. No change to this module is needed for either.
//!
//! # Determinism
//!
//! Everything here is a pure function of the fixture bytes and
//! [`CALIBRATION_SEED`]. The seed drives the bootstrap resample that produces
//! the honest upper bound `ece_bootstrap_p95` (an ECE point estimate over ~60
//! items is noisy; reporting only the point estimate would overstate what the
//! set can support). Two runs of the same tree produce byte-identical reports.

#![allow(
    // Every cast below is usize -> f64 for a ratio, or a bounded f64 -> usize
    // bin index that is clamped to 0..BIN_COUNT immediately before the cast.
    // Test-only measurement code; the precision question is the metric's, not
    // the cast's (rust-1.98 PERF-12 lints acknowledged, not silently ignored).
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    // Test-support surface: the module docs above carry the contract; per-fn
    // `# Panics` / `# Errors` sections would be noise in a test harness.
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use std::fmt;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of fixed equal-width reliability bins on `[0, 1]`.
pub const BIN_COUNT: usize = 10;

/// Bootstrap resamples behind `ece_bootstrap_p95`.
pub const BOOTSTRAP_DRAWS: usize = 256;

/// The one fixed seed for this harness. Named, not inline, so the
/// seed-determinism pin can mutate exactly one value and watch the report move.
pub const CALIBRATION_SEED: u64 = 0x3806_CA11_B2A7_0001;

/// Preregistered held-out sets, relative to the crate root.
pub const FIXTURE_DIR_REL: &str = "tests/fixtures/decision-calibration";

/// The committed digest list inside [`FIXTURE_DIR_REL`].
pub const MANIFEST_FILE: &str = "MANIFEST.sha256";

/// Stable token in every refusal this module raises.
pub const REFUSAL_TOKEN: &str = "decision-calibration REFUSED (#3806)";

/// Optional operator override for the fixture directory (their OWN
/// preregistered held-out sets plus their own `MANIFEST.sha256`).
pub const ENV_FIXTURE_DIR: &str = "AI_MEMORY_CALIBRATION_FIXTURE_DIR";

/// Optional override for the tree binding, for a producer that already knows
/// the commit (`scripts/evidence/decision-calibration.sh` passes it).
pub const ENV_SOURCE_COMMIT: &str = "AI_MEMORY_CALIBRATION_SOURCE_COMMIT";

/// Where the producer script asks for the rendered report.
pub const ENV_REPORT_OUT: &str = "AI_MEMORY_CALIBRATION_REPORT_OUT";

/// `producer-map.json` id this report is published under.
pub const PRODUCER_ID: &str = "decision-calibration";

/// `report_kind` discriminator carried by the rendered report.
pub const REPORT_KIND: &str = "decision_calibration";

/// Report schema version. Bump with any field change.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// The seams a decision provider is allowed to be calibrated on. A fixture
/// naming anything else is REFUSED — the report can only ever contain a token
/// from this list, never a string a model produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Seam {
    ClassifyKind,
    DetectContradiction,
    SynthesisVerdict,
    ConsolidationMerge,
}

impl Seam {
    pub const ALL: &'static [Seam] = &[
        Seam::ClassifyKind,
        Seam::DetectContradiction,
        Seam::SynthesisVerdict,
        Seam::ConsolidationMerge,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Seam::ClassifyKind => "classify_kind",
            Seam::DetectContradiction => "detect_contradiction",
            Seam::SynthesisVerdict => "synthesis_verdict",
            Seam::ConsolidationMerge => "consolidation_merge",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == token)
    }
}

/// Which producer answered an item. Mirrors the `DecisionSource` the W1a trait
/// will carry, 1:1, so a seam adapter is a rename and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSource {
    DecisionModel,
    GenerativeFallback,
    Deterministic,
}

impl ProviderSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderSource::DecisionModel => "decision_model",
            ProviderSource::GenerativeFallback => "generative_fallback",
            ProviderSource::Deterministic => "deterministic",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        [
            ProviderSource::DecisionModel,
            ProviderSource::GenerativeFallback,
            ProviderSource::Deterministic,
        ]
        .into_iter()
        .find(|s| s.as_str() == token)
    }
}

/// What a fixture is FOR. Encoded in the filename (`<seam>.<variant>.jsonl`)
/// so the expectation is fixed by the preregistered name, not by a flag a
/// later run can flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureVariant {
    /// A preregistered held-out set. Expected to PASS its seam gate.
    Heldout,
    /// A deliberately overconfident negative control. Expected to FAIL its
    /// seam gate ON THE ECE ARM. A gate that cannot go red gates nothing.
    Miscalibrated,
}

impl FixtureVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            FixtureVariant::Heldout => "heldout",
            FixtureVariant::Miscalibrated => "miscalibrated",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        [FixtureVariant::Heldout, FixtureVariant::Miscalibrated]
            .into_iter()
            .find(|v| v.as_str() == token)
    }

    pub fn expectation(self) -> Expectation {
        match self {
            FixtureVariant::Heldout => Expectation::ExpectPass,
            FixtureVariant::Miscalibrated => Expectation::ExpectFailEce,
        }
    }
}

/// The preregistered expectation for a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    ExpectPass,
    /// Must fail, and must fail because the ECE ceiling caught it — a coverage
    /// refusal does NOT discharge a miscalibrated control.
    ExpectFailEce,
}

/// Gate outcome. Closed set; no prose verdict ever reaches the report
/// (the `scripts/check-evidence-bundle.sh` rule, applied one level down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    FailEce,
    RefusedNoCoverage,
    RefusedInsufficientItems,
}

/// Whose held-out sets produced this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureDirKind {
    /// The in-repo synthetic controls. These calibrate THE GATE, and are not a
    /// claim about any real provider's calibration.
    RepoSyntheticControl,
    /// An operator's own preregistered held-out set.
    OperatorSupplied,
}

/// Top-level report verdict, in the evidence-bundle closed vocabulary so the
/// producer can hand it straight to `scripts/evidence/write-bundle.sh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReportVerdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Every way this harness declines to produce a number. Fail CLOSED: a fixture
/// that is not exactly what was preregistered is never silently skipped,
/// truncated, or coerced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    FixtureDirUnreadable(String),
    ManifestMissing(String),
    ManifestMalformed { line: usize },
    ManifestEmpty,
    ManifestDigestMismatch { file: String },
    ManifestFileMissing { file: String },
    FixtureNotInManifest { file: String },
    FixtureNameMalformed { file: String },
    UnknownSeam { file: String },
    UnknownVariant { file: String },
    FixtureEmpty { file: String },
    LineNotJsonObject { file: String, line: usize },
    LineKeySetWrong { file: String, line: usize },
    ItemIdMalformed { file: String, line: usize },
    ItemIdDuplicated { file: String, line: usize },
    ItemSeamMismatch { file: String, line: usize },
    UnknownSource { file: String, line: usize },
    PredictedOutOfRange { file: String, line: usize },
    LabelNotBool { file: String, line: usize },
    SourceCommitUnbindable(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REFUSAL_TOKEN}: ")?;
        match self {
            Refusal::FixtureDirUnreadable(d) => write!(f, "fixture directory unreadable: {d}"),
            Refusal::ManifestMissing(d) => write!(f, "{MANIFEST_FILE} missing in {d}"),
            Refusal::ManifestMalformed { line } => {
                write!(f, "{MANIFEST_FILE} line {line} is not `<sha256>  <name>`")
            }
            Refusal::ManifestEmpty => write!(f, "{MANIFEST_FILE} lists no fixture"),
            Refusal::ManifestDigestMismatch { file } => write!(
                f,
                "held-out set {file} does not match its preregistered sha256 \
                 (a fixture changed without its manifest)"
            ),
            Refusal::ManifestFileMissing { file } => {
                write!(f, "{MANIFEST_FILE} names {file}, which is not on disk")
            }
            Refusal::FixtureNotInManifest { file } => write!(
                f,
                "{file} is present but not preregistered in {MANIFEST_FILE}"
            ),
            Refusal::FixtureNameMalformed { file } => {
                write!(f, "{file} is not `<seam>.<variant>.jsonl`")
            }
            Refusal::UnknownSeam { file } => {
                write!(f, "{file} names a seam outside the closed set")
            }
            Refusal::UnknownVariant { file } => {
                write!(f, "{file} names a variant outside the closed set")
            }
            Refusal::FixtureEmpty { file } => write!(f, "{file} carries no items"),
            Refusal::LineNotJsonObject { file, line } => {
                write!(f, "{file}:{line} is not a JSON object")
            }
            Refusal::LineKeySetWrong { file, line } => write!(
                f,
                "{file}:{line} key set is not exactly \
                 {{item_id, seam, source, predicted, label}}"
            ),
            Refusal::ItemIdMalformed { file, line } => {
                write!(f, "{file}:{line} item_id is not `[a-z][a-z0-9-]{{2,31}}`")
            }
            Refusal::ItemIdDuplicated { file, line } => {
                write!(f, "{file}:{line} repeats an item_id")
            }
            Refusal::ItemSeamMismatch { file, line } => {
                write!(f, "{file}:{line} seam differs from the filename's seam")
            }
            Refusal::UnknownSource { file, line } => {
                write!(f, "{file}:{line} source is outside the closed set")
            }
            Refusal::PredictedOutOfRange { file, line } => {
                write!(
                    f,
                    "{file}:{line} predicted is not null or a number in [0,1]"
                )
            }
            Refusal::LabelNotBool { file, line } => write!(f, "{file}:{line} label is not a bool"),
            Refusal::SourceCommitUnbindable(why) => write!(
                f,
                "calibration report UNBINDABLE: no source_commit ({why}). A figure \
                 that cannot name the tree that produced it is not a result."
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Items and fixtures
// ---------------------------------------------------------------------------

/// One preregistered calibration item.
#[derive(Debug, Clone, PartialEq)]
pub struct CalibrationItem {
    pub item_id: String,
    pub seam: Seam,
    pub source: ProviderSource,
    /// `None` == the provider ABSTAINED. A first-class value, never a default.
    pub predicted: Option<f64>,
    pub label: bool,
}

/// One loaded held-out set.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub file: String,
    pub seam: Seam,
    pub variant: FixtureVariant,
    pub sha256: String,
    pub items: Vec<CalibrationItem>,
}

impl Fixture {
    /// The `(probability, truth)` pairs the provider actually committed to.
    pub fn scored_points(&self) -> Vec<(f64, bool)> {
        self.items
            .iter()
            .filter_map(|i| i.predicted.map(|p| (p, i.label)))
            .collect()
    }

    /// The positive control: answer the truth, never abstain, on the SAME set.
    pub fn oracle_points(&self) -> Vec<(f64, bool)> {
        self.items
            .iter()
            .map(|i| (if i.label { 1.0 } else { 0.0 }, i.label))
            .collect()
    }

    pub fn n_abstained(&self) -> usize {
        self.items.iter().filter(|i| i.predicted.is_none()).count()
    }

    pub fn coverage(&self) -> f64 {
        if self.items.is_empty() {
            return 0.0;
        }
        (self.items.len() - self.n_abstained()) as f64 / self.items.len() as f64
    }

    pub fn source_counts(&self) -> SourceCounts {
        let count = |want: ProviderSource| self.items.iter().filter(|i| i.source == want).count();
        SourceCounts {
            decision_model: count(ProviderSource::DecisionModel),
            generative_fallback: count(ProviderSource::GenerativeFallback),
            deterministic: count(ProviderSource::Deterministic),
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest (preregistration)
// ---------------------------------------------------------------------------

/// A verified `MANIFEST.sha256`: the held-out sets are exactly what was
/// committed before the first result.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    /// sha256 of the manifest file itself — the single value a report carries
    /// to name the held-out corpus it measured.
    pub manifest_sha256: String,
    /// `(file name, sha256)` in manifest order.
    pub files: Vec<(String, String)>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Re-hash every preregistered fixture and refuse on ANY drift, in either
/// direction: a listed file whose bytes moved, a listed file that vanished, or
/// a `.jsonl` on disk that nobody preregistered.
pub fn verify_manifest(dir: &Path) -> Result<VerifiedManifest, Refusal> {
    let manifest_path = dir.join(MANIFEST_FILE);
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|_| Refusal::ManifestMissing(dir.display().to_string()))?;
    let manifest_text = String::from_utf8_lossy(&manifest_bytes).into_owned();

    let mut files: Vec<(String, String)> = Vec::new();
    for (idx, raw) in manifest_text.lines().enumerate() {
        let line = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let Some((digest, name)) = raw.split_once("  ") else {
            return Err(Refusal::ManifestMalformed { line });
        };
        if !is_sha256_hex(digest) || name.trim().is_empty() || name.contains('/') {
            return Err(Refusal::ManifestMalformed { line });
        }
        files.push((name.to_string(), digest.to_string()));
    }
    if files.is_empty() {
        return Err(Refusal::ManifestEmpty);
    }

    for (name, digest) in &files {
        let bytes = std::fs::read(dir.join(name))
            .map_err(|_| Refusal::ManifestFileMissing { file: name.clone() })?;
        if &sha256_hex(&bytes) != digest {
            return Err(Refusal::ManifestDigestMismatch { file: name.clone() });
        }
    }

    for entry in std::fs::read_dir(dir)
        .map_err(|_| Refusal::FixtureDirUnreadable(dir.display().to_string()))?
    {
        let entry = entry.map_err(|_| Refusal::FixtureDirUnreadable(dir.display().to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if Path::new(&name).extension().is_some_and(|e| e == "jsonl")
            && !files.iter().any(|(f, _)| f == &name)
        {
            return Err(Refusal::FixtureNotInManifest { file: name });
        }
    }

    Ok(VerifiedManifest {
        manifest_sha256: sha256_hex(&manifest_bytes),
        files,
    })
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_git_sha(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_item_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    (3..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

// ---------------------------------------------------------------------------
// Loading (fail closed)
// ---------------------------------------------------------------------------

const ITEM_KEYS: [&str; 5] = ["item_id", "label", "predicted", "seam", "source"];

/// Parse `<seam>.<variant>.jsonl` into the two closed vocabularies. The
/// filename is the binding: a set cannot be re-pointed at another seam, or
/// promoted from a negative control to a held-out set, without a rename that
/// also invalidates the manifest.
pub fn parse_fixture_name(file: &str) -> Result<(Seam, FixtureVariant), Refusal> {
    let stem = file
        .strip_suffix(".jsonl")
        .ok_or_else(|| Refusal::FixtureNameMalformed { file: file.into() })?;
    let (seam_tok, variant_tok) = stem
        .split_once('.')
        .ok_or_else(|| Refusal::FixtureNameMalformed { file: file.into() })?;
    let seam = Seam::parse(seam_tok).ok_or_else(|| Refusal::UnknownSeam { file: file.into() })?;
    let variant = FixtureVariant::parse(variant_tok)
        .ok_or_else(|| Refusal::UnknownVariant { file: file.into() })?;
    Ok((seam, variant))
}

/// Load one preregistered set. Every deviation from the declared shape is a
/// refusal naming the file and line — never a skipped row.
pub fn load_fixture(dir: &Path, file: &str, sha256: &str) -> Result<Fixture, Refusal> {
    let (seam, variant) = parse_fixture_name(file)?;
    let text = std::fs::read_to_string(dir.join(file))
        .map_err(|_| Refusal::ManifestFileMissing { file: file.into() })?;

    let mut items: Vec<CalibrationItem> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|_| Refusal::LineNotJsonObject {
                file: file.into(),
                line,
            })?;
        let obj = value.as_object().ok_or(Refusal::LineNotJsonObject {
            file: file.into(),
            line,
        })?;

        // Exact key set: unknown keys AND missing keys are both refusals. A
        // free-text field smuggled alongside the five would be rejected here,
        // which is what keeps model prose out of the report (SERDE-01, made
        // explicit because serde treats a missing `Option` as `None`).
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        if keys != ITEM_KEYS {
            return Err(Refusal::LineKeySetWrong {
                file: file.into(),
                line,
            });
        }

        let item_id = obj["item_id"].as_str().unwrap_or_default().to_string();
        if !is_item_id(&item_id) {
            return Err(Refusal::ItemIdMalformed {
                file: file.into(),
                line,
            });
        }
        if seen.contains(&item_id) {
            return Err(Refusal::ItemIdDuplicated {
                file: file.into(),
                line,
            });
        }

        let item_seam =
            obj["seam"]
                .as_str()
                .and_then(Seam::parse)
                .ok_or(Refusal::ItemSeamMismatch {
                    file: file.into(),
                    line,
                })?;
        if item_seam != seam {
            return Err(Refusal::ItemSeamMismatch {
                file: file.into(),
                line,
            });
        }

        let source = obj["source"]
            .as_str()
            .and_then(ProviderSource::parse)
            .ok_or(Refusal::UnknownSource {
                file: file.into(),
                line,
            })?;

        let predicted = match &obj["predicted"] {
            serde_json::Value::Null => None,
            other => {
                let p = other.as_f64().ok_or(Refusal::PredictedOutOfRange {
                    file: file.into(),
                    line,
                })?;
                if !p.is_finite() || !(0.0..=1.0).contains(&p) {
                    return Err(Refusal::PredictedOutOfRange {
                        file: file.into(),
                        line,
                    });
                }
                Some(p)
            }
        };

        let label = obj["label"].as_bool().ok_or(Refusal::LabelNotBool {
            file: file.into(),
            line,
        })?;

        seen.push(item_id.clone());
        items.push(CalibrationItem {
            item_id,
            seam,
            source,
            predicted,
            label,
        });
    }

    if items.is_empty() {
        return Err(Refusal::FixtureEmpty { file: file.into() });
    }

    Ok(Fixture {
        file: file.to_string(),
        seam,
        variant,
        sha256: sha256.to_string(),
        items,
    })
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64)
// ---------------------------------------------------------------------------

/// SplitMix64. Chosen because it is ten lines of integer arithmetic with no
/// dependency, no platform-dependent float behaviour, and a fully specified
/// output sequence — so "the same seed gives the same report" is a property of
/// the algorithm, not of a crate version.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// rust-1.98 PERF-04: every `wrapping_*` here is the algorithm's defined
    /// mod-2^64 arithmetic, not an overflow we tolerated.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish index below `n`. The modulo bias over a 64-bit draw for the
    /// n < 1000 this harness uses is below 1e-16 and cannot move a reported
    /// figure at six decimal places.
    pub fn below(&mut self, n: usize) -> usize {
        assert!(n > 0, "below(0) has no value");
        let m = u64::try_from(n).expect("fixture size fits u64");
        usize::try_from(self.next_u64() % m).expect("index fits usize")
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Report floats at six decimals. Rounding is what makes two runs on two hosts
/// byte-identical without pretending the underlying estimate is exact.
pub fn round6(x: f64) -> f64 {
    (x * 1_000_000.0).round() / 1_000_000.0
}

/// Which of the [`BIN_COUNT`] equal-width bins a probability falls in.
/// `p == 1.0` belongs to the top bin, which is closed on the right.
pub fn bin_index(p: f64) -> usize {
    let raw = (p * BIN_COUNT as f64).floor();
    if raw < 0.0 {
        return 0;
    }
    let idx = raw as usize;
    if idx >= BIN_COUNT { BIN_COUNT - 1 } else { idx }
}

#[derive(Debug, Clone, Copy, Default)]
struct BinAccum {
    count: usize,
    predicted_sum: f64,
    positives: usize,
}

fn accumulate(points: &[(f64, bool)]) -> [BinAccum; BIN_COUNT] {
    let mut bins = [BinAccum::default(); BIN_COUNT];
    for &(p, label) in points {
        let b = &mut bins[bin_index(p)];
        b.count += 1;
        b.predicted_sum += p;
        if label {
            b.positives += 1;
        }
    }
    bins
}

/// Brier score: mean squared error of the claimed probability against the
/// truth. `None` when nothing was scored — an always-abstain provider has no
/// Brier score, and reporting `0.0` would read as perfection.
pub fn brier(points: &[(f64, bool)]) -> Option<f64> {
    if points.is_empty() {
        return None;
    }
    let sum: f64 = points
        .iter()
        .map(|&(p, label)| {
            let y = if label { 1.0 } else { 0.0 };
            (p - y) * (p - y)
        })
        .sum();
    Some(sum / points.len() as f64)
}

/// Expected calibration error over [`BIN_COUNT`] fixed equal-width bins:
/// the count-weighted mean of |claimed - observed| per bin. `None` when
/// nothing was scored (see [`brier`]).
pub fn ece(points: &[(f64, bool)]) -> Option<f64> {
    if points.is_empty() {
        return None;
    }
    let bins = accumulate(points);
    let total = points.len() as f64;
    let mut acc = 0.0;
    for b in &bins {
        if b.count == 0 {
            continue;
        }
        let mean_predicted = b.predicted_sum / b.count as f64;
        let rate = b.positives as f64 / b.count as f64;
        acc += (b.count as f64 / total) * (mean_predicted - rate).abs();
    }
    Some(acc)
}

/// The reliability curve the ECE summarises: all [`BIN_COUNT`] bins, empty
/// ones included with absent figures so the curve has a fixed shape.
pub fn reliability(points: &[(f64, bool)]) -> Vec<BinReport> {
    let bins = accumulate(points);
    bins.iter()
        .enumerate()
        .map(|(i, b)| BinReport {
            bin_lower: round6(i as f64 / BIN_COUNT as f64),
            bin_upper: round6((i + 1) as f64 / BIN_COUNT as f64),
            count: b.count,
            mean_predicted: (b.count > 0).then(|| round6(b.predicted_sum / b.count as f64)),
            empirical_rate: (b.count > 0).then(|| round6(b.positives as f64 / b.count as f64)),
        })
        .collect()
}

/// Seeded bootstrap upper bound on the ECE. An ECE point estimate over ~60
/// items is noisy; this is the honest 95th percentile of the resampled
/// estimate, REPORTED but deliberately NOT gated (gating a percentile of a
/// resample would let a wider set buy a looser bound).
pub fn ece_bootstrap_p95(points: &[(f64, bool)], seed: u64, draws: usize) -> Option<f64> {
    if points.is_empty() || draws == 0 {
        return None;
    }
    let mut rng = SplitMix64::new(seed);
    let mut sample: Vec<(f64, bool)> = Vec::with_capacity(points.len());
    let mut estimates: Vec<f64> = Vec::with_capacity(draws);
    for _ in 0..draws {
        sample.clear();
        for _ in 0..points.len() {
            sample.push(points[rng.below(points.len())]);
        }
        if let Some(e) = ece(&sample) {
            estimates.push(e);
        }
    }
    if estimates.is_empty() {
        return None;
    }
    // rust-1.98 PERF-25: total order on f64, never `partial_cmp().unwrap()`.
    estimates.sort_by(f64::total_cmp);
    let rank = (estimates.len() * 95).div_ceil(100).saturating_sub(1);
    Some(estimates[rank])
}

/// Derive a per-fixture bootstrap seed from the one named seed, so two
/// fixtures never share a resample sequence while the whole report still
/// depends on exactly one constant.
pub fn fixture_seed(seed: u64, file: &str) -> u64 {
    let digest = sha256_hex(file.as_bytes());
    let mut acc = seed;
    for byte in digest.as_bytes().iter().take(8) {
        acc = acc.rotate_left(8) ^ u64::from(*byte);
    }
    acc
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Per-seam admission thresholds.
#[derive(Debug, Clone, Copy)]
pub struct SeamGate {
    pub seam: Seam,
    /// ECE ceiling. Exceeding it is [`GateVerdict::FailEce`].
    pub max_ece: f64,
    /// Coverage floor. Without it, ALWAYS-ABSTAIN scores a perfect (vacuous)
    /// calibration and the gate would certify a provider that never answers.
    pub min_coverage: f64,
    /// Below this many scored items the set cannot support a 10-bin ECE at
    /// all, so the harness REFUSES rather than reporting a noisy number.
    pub min_scored_items: usize,
}

/// # Thresholds and why these numbers
///
/// These are ADMISSION thresholds for a decision provider, set conservatively
/// in the only direction that matters for data integrity: loose enough that a
/// genuinely calibrated provider is not failed by sampling noise, tight enough
/// that the overconfident class — the one that turns an advisory verdict into
/// a destructive action — cannot get through.
///
/// * The floor is measurement, not aspiration. A 10-bin ECE over a 60-item set
///   has six items per bin, so the empirical rate can only land on multiples of
///   1/6; a PERFECTLY calibrated provider still scores ECE ~0.043 on a set this
///   size. A ceiling near that floor would fail correct providers.
/// * The ceiling is 0.10 for the three judge-shaped seams: a provider whose
///   claimed probability is off by a tenth on average is still usable as ADVICE
///   behind a deterministic pipeline, and anything worse is not.
/// * `classify_kind` gets 0.12 because it is a 16-way choice whose top-1
///   probability is intrinsically noisier than a binary judgement.
/// * The observed miscalibrated control sits at ECE ~0.295 — 3x the ceiling —
///   so the gate has real margin on the side that matters.
///
/// # The ratchet
///
/// These thresholds TIGHTEN, never loosen (the repo's "thresholds rise, never
/// fall" discipline, pointed the other way because here LOWER is stricter).
/// Raising a ceiling to make a run green is the defect this gate exists to
/// prevent; a provider that cannot meet its seam's ceiling is refused, and the
/// seam keeps its deterministic behaviour.
///
/// The coverage floor is 0.50 everywhere: a provider that abstains on more than
/// half a held-out set has not been measured, whatever its ECE says.
pub const SEAM_GATES: &[SeamGate] = &[
    SeamGate {
        seam: Seam::ClassifyKind,
        max_ece: 0.12,
        min_coverage: 0.50,
        min_scored_items: 40,
    },
    SeamGate {
        seam: Seam::DetectContradiction,
        max_ece: 0.10,
        min_coverage: 0.50,
        min_scored_items: 40,
    },
    SeamGate {
        seam: Seam::SynthesisVerdict,
        max_ece: 0.10,
        min_coverage: 0.50,
        min_scored_items: 40,
    },
    SeamGate {
        seam: Seam::ConsolidationMerge,
        max_ece: 0.10,
        min_coverage: 0.50,
        min_scored_items: 40,
    },
];

pub fn gate_for(seam: Seam) -> &'static SeamGate {
    SEAM_GATES
        .iter()
        .find(|g| g.seam == seam)
        .expect("every Seam variant has a gate row")
}

/// Order matters and is deliberate: coverage and item-count REFUSALS are
/// checked before the ECE ceiling, so "we never measured this" can never be
/// reported as "this passed".
pub fn evaluate_gate(
    gate: &SeamGate,
    coverage: f64,
    n_scored: usize,
    ece: Option<f64>,
) -> GateVerdict {
    if coverage < gate.min_coverage {
        return GateVerdict::RefusedNoCoverage;
    }
    if n_scored < gate.min_scored_items {
        return GateVerdict::RefusedInsufficientItems;
    }
    match ece {
        None => GateVerdict::RefusedNoCoverage,
        Some(e) if e > gate.max_ece => GateVerdict::FailEce,
        Some(_) => GateVerdict::Pass,
    }
}

/// Report rendering lives next door so this file stays the measurement and
/// that one stays the presentation.
pub mod report;

/// One bin of the reliability curve. `mean_predicted` / `empirical_rate` are
/// ABSENT for an empty bin rather than a misleading zero.
#[derive(Debug, Clone, Serialize)]
pub struct BinReport {
    pub bin_lower: f64,
    pub bin_upper: f64,
    pub count: usize,
    pub mean_predicted: Option<f64>,
    pub empirical_rate: Option<f64>,
}

/// How many items each producer contributed. Published so a report cannot
/// quietly be mostly generative fallback while being read as a measurement of
/// the decision model.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SourceCounts {
    pub decision_model: usize,
    pub generative_fallback: usize,
    pub deterministic: usize,
}
