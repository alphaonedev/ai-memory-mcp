// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1c — the calibration-row adapter.
//!
//! W5 (`tests/decision_calibration/`) owns the preregistered held-out
//! sets, the Brier / ECE / reliability metrics and the gate. Its input
//! is one JSON object per item with EXACTLY five keys:
//!
//! ```json
//! {"item_id":"sv-001","seam":"synthesis_verdict","source":"decision_model",
//!  "predicted":0.82,"label":true}
//! ```
//!
//! This module is the one place that turns a [`Decision`] into that
//! object, so W2's seams can emit calibration rows without touching W5
//! and without re-deriving the mapping at four call sites.
//!
//! ## The mapping, and the one place it is easy to get wrong
//!
//! `predicted` is **the probability the provider assigned to the
//! preregistered label being TRUE**, as W5's loader defines it — not
//! "the confidence of whatever the model said". Those two differ exactly
//! when the model says NO: a judgement of `false` at confidence `0.9`
//! assigns probability `0.1` to the label being true, and recording
//! `0.9` there would make a well-calibrated model look badly calibrated
//! (and, worse, make a badly calibrated one look fine). So:
//!
//! - [`CalibrationRow::from_judgement`] — `predicted = c` when the
//!   verdict is `true`, `1.0 - c` when it is `false`, and `null` when
//!   the provider abstained OR reported no confidence.
//! - [`CalibrationRow::from_choice`] — `predicted` is the confidence of
//!   the chosen option and `label = (chosen == truth)`, so the pair
//!   answers "how often is the model right when it says it is this
//!   sure". An abstain is `predicted = null`.
//!
//! **`null` is never a stand-in for a number.** An abstain and a
//! missing-logprobs decision both produce `null`, because in both cases
//! no probability exists; W5 counts those against its coverage floor
//! rather than scoring them, which is precisely why the floor sits
//! beside the ECE ceiling.
//!
//! There is deliberately NO adapter from a `Scored`: a score is a
//! quantity, not a probability that a label holds, and forcing one into
//! the `predicted` column would publish a calibration figure for
//! something that was never a probability.

use serde_json::{Value, json};

use crate::decision::{Choice, DecisionSource, Judgement};

/// Which seam produced a calibration row. The tokens are W5's
/// preregistered vocabulary; a fifth seam needs a fixture set and a gate
/// row there before it can appear here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalibrationSeam {
    /// `classify_kind` — the 16-way closed choice.
    ClassifyKind,
    /// `memory_detect_contradiction` — the yes/no judgement.
    DetectContradiction,
    /// The synthesis verb, whose `Delete` arm is destructive.
    SynthesisVerdict,
    /// The curator merge judge, gating `db::consolidate`.
    ConsolidationMerge,
}

impl CalibrationSeam {
    /// The preregistered wire token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClassifyKind => "classify_kind",
            Self::DetectContradiction => "detect_contradiction",
            Self::SynthesisVerdict => "synthesis_verdict",
            Self::ConsolidationMerge => "consolidation_merge",
        }
    }
}

impl std::fmt::Display for CalibrationSeam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of the calibration harness's input.
#[derive(Debug, Clone, PartialEq)]
pub struct CalibrationRow {
    item_id: String,
    seam: CalibrationSeam,
    source: DecisionSource,
    predicted: Option<f64>,
    label: bool,
}

impl CalibrationRow {
    /// Build a row directly.
    ///
    /// `predicted` is degraded to `None` unless it is a finite
    /// probability in `0.0..=1.0` — the same fail-closed rule
    /// `Decision::decided` applies, repeated here because a row can also
    /// be built by a caller with its own mapping.
    #[must_use]
    pub fn new(
        item_id: impl Into<String>,
        seam: CalibrationSeam,
        source: DecisionSource,
        predicted: Option<f64>,
        label: bool,
    ) -> Self {
        Self {
            item_id: item_id.into(),
            seam,
            source,
            predicted: predicted.filter(|p| p.is_finite() && (0.0..=1.0).contains(p)),
            label,
        }
    }

    /// Render a yes/no judgement against a preregistered `label`.
    ///
    /// `predicted` is the probability assigned to `label` being TRUE:
    /// the confidence when the verdict is `true`, its complement when
    /// the verdict is `false`, and `None` on an abstain or when the
    /// endpoint reported no confidence.
    #[must_use]
    pub fn from_judgement(
        item_id: impl Into<String>,
        seam: CalibrationSeam,
        judgement: &Judgement,
        label: bool,
    ) -> Self {
        let predicted = match (judgement.verdict(), judgement.confidence()) {
            (Some(true), Some(confidence)) => Some(confidence),
            (Some(false), Some(confidence)) => Some(1.0 - confidence),
            _ => None,
        };
        Self::new(item_id, seam, judgement.source(), predicted, label)
    }

    /// Render a closed-set choice against the preregistered `truth`.
    ///
    /// `predicted` is the confidence of the chosen option; `label` is
    /// whether that option was the right one. An abstain contributes
    /// `predicted = null` and `label = false` — nothing was chosen, so
    /// nothing was chosen correctly.
    #[must_use]
    pub fn from_choice(
        item_id: impl Into<String>,
        seam: CalibrationSeam,
        choice: &Choice,
        truth: &str,
    ) -> Self {
        let label = choice.chosen() == Some(truth);
        let predicted = choice.chosen().and(choice.confidence());
        Self::new(item_id, seam, choice.source(), predicted, label)
    }

    /// The preregistered item identifier.
    #[must_use]
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    /// The seam this row came from.
    #[must_use]
    pub fn seam(&self) -> CalibrationSeam {
        self.seam
    }

    /// Which class of provider answered.
    #[must_use]
    pub fn source(&self) -> DecisionSource {
        self.source
    }

    /// The probability assigned to the label being true, or `None` for
    /// an abstain / an absent confidence.
    #[must_use]
    pub fn predicted(&self) -> Option<f64> {
        self.predicted
    }

    /// The preregistered ground truth.
    #[must_use]
    pub fn label(&self) -> bool {
        self.label
    }

    /// The row as JSON. EXACTLY five keys, with `predicted` always
    /// present and explicitly `null` on an abstain: W5's loader refuses
    /// both an extra key and a missing one, because serde would
    /// otherwise read an absent `predicted` as an invented abstain.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "seam": self.seam.as_str(),
            "source": self.source.as_str(),
            "predicted": self.predicted,
            "label": self.label,
        })
    }

    /// One JSONL line, ready for a preregistered held-out set.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        self.to_value().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::AbstainReason;

    #[test]
    fn a_row_has_exactly_the_five_preregistered_keys() {
        let row = CalibrationRow::new(
            "sv-001",
            CalibrationSeam::SynthesisVerdict,
            DecisionSource::DecisionModel,
            Some(0.82),
            true,
        );
        let value = row.to_value();
        let object = value.as_object().expect("a row is a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["item_id", "label", "predicted", "seam", "source"],
            "W5's loader refuses an extra key AND a missing one"
        );
        assert_eq!(object["seam"], json!("synthesis_verdict"));
        assert_eq!(object["source"], json!("decision_model"));
        assert_eq!(object["predicted"], json!(0.82));
        assert!(row.to_json_line().contains("\"predicted\":0.82"));
    }

    #[test]
    fn a_no_verdict_records_the_complement_not_the_confidence() {
        // The mapping that is easy to get wrong: a CONFIDENT NO assigns
        // a LOW probability to the label being true.
        let confident_no = Judgement::decided(false, Some(0.9), DecisionSource::DecisionModel);
        let row = CalibrationRow::from_judgement(
            "dc-001",
            CalibrationSeam::DetectContradiction,
            &confident_no,
            false,
        );
        // PERF-25: never `==` on floats — `1.0 - 0.9` is not `0.1`.
        let predicted = row.predicted().expect("a confident `no` is still scored");
        assert!(
            (predicted - 0.1).abs() < 1e-12,
            "predicted is P(label is TRUE), so a confident `no` is 1 - c, got {predicted}"
        );
        // PRESENCE control on the same sink: a confident YES records the
        // confidence itself.
        let confident_yes = Judgement::decided(true, Some(0.9), DecisionSource::DecisionModel);
        let row = CalibrationRow::from_judgement(
            "dc-002",
            CalibrationSeam::DetectContradiction,
            &confident_yes,
            true,
        );
        let predicted = row.predicted().expect("a confident `yes` is scored");
        assert!((predicted - 0.9).abs() < 1e-12, "got {predicted}");
    }

    #[test]
    fn an_abstain_or_an_absent_confidence_is_an_explicit_null() {
        let abstained = Judgement::abstain(AbstainReason::Timeout, DecisionSource::DecisionModel);
        let row = CalibrationRow::from_judgement(
            "dc-003",
            CalibrationSeam::DetectContradiction,
            &abstained,
            true,
        );
        assert_eq!(row.predicted(), None);
        assert_eq!(
            row.to_value()["predicted"],
            Value::Null,
            "the key must be PRESENT and null, never omitted"
        );
        // A decision with no logprobs is also a null, not a 1.0.
        let no_logprobs = Judgement::decided(true, None, DecisionSource::DecisionModel);
        let row = CalibrationRow::from_judgement(
            "dc-004",
            CalibrationSeam::DetectContradiction,
            &no_logprobs,
            true,
        );
        assert_eq!(row.predicted(), None);
        assert_eq!(row.to_value()["predicted"], Value::Null);
    }

    #[test]
    fn a_choice_row_labels_itself_against_the_preregistered_truth() {
        let chosen = Choice::decided("Fact".to_string(), Some(0.7), DecisionSource::DecisionModel);
        let right =
            CalibrationRow::from_choice("ck-001", CalibrationSeam::ClassifyKind, &chosen, "Fact");
        assert_eq!(right.predicted(), Some(0.7));
        assert!(right.label(), "the chosen option was the truth");
        let wrong = CalibrationRow::from_choice(
            "ck-002",
            CalibrationSeam::ClassifyKind,
            &chosen,
            "Decision",
        );
        assert_eq!(wrong.predicted(), Some(0.7));
        assert!(!wrong.label(), "same confidence, wrong option");
        // An abstain chooses nothing, so it is neither scored nor right.
        let abstained = Choice::abstain(AbstainReason::Unusable, DecisionSource::DecisionModel);
        let none = CalibrationRow::from_choice(
            "ck-003",
            CalibrationSeam::ClassifyKind,
            &abstained,
            "Fact",
        );
        assert_eq!(none.predicted(), None);
        assert!(!none.label());
    }

    #[test]
    fn a_generative_row_reports_its_own_provenance() {
        let judgement = Judgement::decided(true, None, DecisionSource::GenerativeFallback);
        let row = CalibrationRow::from_judgement(
            "sv-002",
            CalibrationSeam::SynthesisVerdict,
            &judgement,
            true,
        );
        assert_eq!(row.source(), DecisionSource::GenerativeFallback);
        assert_eq!(row.to_value()["source"], json!("generative_fallback"));
    }

    #[test]
    fn an_impossible_predicted_value_degrades_to_null() {
        for bad in [f64::NAN, f64::INFINITY, -0.5, 1.5] {
            let row = CalibrationRow::new(
                "x",
                CalibrationSeam::ConsolidationMerge,
                DecisionSource::DecisionModel,
                Some(bad),
                true,
            );
            assert_eq!(row.predicted(), None, "{bad} is not a probability");
        }
        // PRESENCE control: a real probability survives.
        let row = CalibrationRow::new(
            "x",
            CalibrationSeam::ConsolidationMerge,
            DecisionSource::DecisionModel,
            Some(0.0),
            true,
        );
        assert_eq!(row.predicted(), Some(0.0));
    }
}
