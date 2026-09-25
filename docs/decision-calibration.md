---
layout: doc
---
# Decision-provider calibration (`[decision]`)

A decision provider does not answer a seam with prose; it answers with a
typed decision and, where the endpoint returns logprobs or calibration
evidence, a PROBABILITY. This page is about that number: how ai-memory
measures whether it means anything, and how you preregister your own
held-out set so the measurement is about *your* traffic.

This is the `[decision]` half of calibration. The substrate-side
`memories.confidence` pipeline is a different mechanism, documented in
[confidence-calibration.md](confidence-calibration.md).

> **What the in-repo numbers are.** The fixtures shipped in
> `tests/fixtures/decision-calibration/` are SYNTHETIC CONTROLS. They
> calibrate the GATE — they prove it passes a well-calibrated set and fails an
> overconfident one. They are not a claim about any vendor's model. A report
> built from them records `fixture_dir_kind: repo_synthetic_control`; a report
> built from your corpus records `operator_supplied`.

## What is measured

| Figure | Meaning | Gated |
|---|---|---|
| `brier` | mean squared error of the claimed probability against the truth; 0 is perfect | no |
| `ece` | count-weighted mean gap between claimed and observed, over ten fixed equal-width bins | **yes** |
| `ece_bootstrap_p95` | seeded-bootstrap 95th percentile of the ECE estimate — how much of the ECE is just sample size | no (see *What a corpus can support*) |
| `reliability` | the per-bin (claimed, observed) pairs the ECE summarises | no |
| `coverage` | fraction of items the provider actually answered (the rest ABSTAINED) | **yes** |

Every seam is reported between two baselines computed on the SAME held-out set:

* the **null baseline**, ALWAYS-ABSTAIN. It has no scored items, so its ECE and
  Brier are ABSENT — not `0.0`. That is deliberate: ECE alone is trivially
  gamed by abstaining, which is why the gate carries a coverage floor beside
  its ECE ceiling, and why the null baseline's gate verdict is
  `refused_no_coverage` rather than a pass.
* the **oracle baseline**, which answers the truth and never abstains
  (Brier 0, ECE 0, coverage 1). The positive control.

## The gate

Per seam, in `tests/decision_calibration/mod.rs::SEAM_GATES`:

| Seam | ECE ceiling | Coverage floor | Minimum scored items |
|---|---|---|---|
| `classify_kind` | 0.12 | 0.50 | 40 |
| `detect_contradiction` | 0.10 | 0.50 | 40 |
| `synthesis_verdict` | 0.10 | 0.50 | 40 |
| `consolidation_merge` | 0.10 | 0.50 | 40 |

The ceilings are ADMISSION thresholds, conservative in the direction that
matters: loose enough that a genuinely calibrated provider is not failed by
sampling noise, tight enough that the overconfident class cannot get through.
`classify_kind` is looser because it is a 16-way choice whose top-1 probability
is intrinsically noisier than a binary judgement. **Thresholds tighten, never
loosen** — raising a ceiling to make a run green is exactly the defect this
gate exists to prevent. A provider that cannot meet its seam's ceiling is
refused, and the seam keeps its deterministic behaviour.

Coverage and item-count refusals are evaluated BEFORE the ECE ceiling, so
"we never measured this" can never be reported as "this passed".

## Preregistering your own held-out set

1. Build one file per seam, named `<seam>.heldout.jsonl`, where `<seam>` is one
   of `classify_kind`, `detect_contradiction`, `synthesis_verdict`,
   `consolidation_merge`. One JSON object per line, EXACTLY five keys:

   ```json
   {"item_id":"sv-001","seam":"synthesis_verdict","source":"decision_model","predicted":0.82,"label":true}
   ```

   * `predicted` — the probability the provider assigned to the event "the
     preregistered label is TRUE", or `null` for an ABSTAIN. Explicit `null` is
     required; a missing key is refused, never read as an implied abstain.
   * `label` — your ground truth. This is the independent oracle; it must be
     fixed before you look at any provider output.
   * `source` — `decision_model`, `generative_fallback`, or `deterministic`.
   * `item_id` — `[a-z][a-z0-9-]{2,31}`, unique across your whole corpus.

   Anything else on a line — including a free-text `reason` field — is a
   refusal naming the file and line. That is what keeps model prose out of a
   report.

2. Freeze it. From your corpus directory:

   ```
   sha256sum *.jsonl > MANIFEST.sha256     # or: shasum -a 256 *.jsonl
   ```

   Commit that file **before** you run anything. From then on, editing a
   fixture, deleting one, or adding an unlisted one is a hard refusal in both
   readers. You cannot grow, trim, or re-point a held-out set after seeing the
   numbers.

3. Measure:

   ```
   scripts/evidence/decision-calibration.sh --fixture-dir /path/to/your/corpus
   ```

   The producer verifies your manifest with the system sha256 tool, runs the
   harness (which verifies it again, independently), writes the report and a
   bound evidence bundle under `.local-runs/decision-calibration/`, and
   validates that bundle with `scripts/check-evidence-bundle.sh`.

## Reading the report

```json
{
  "report_kind": "decision_calibration",
  "source_commit": "<40-hex>",
  "fixture_manifest_sha256": "<64-hex>",
  "seed": "0x3806ca11b2a70001",
  "seams": [ { "seam": "synthesis_verdict", "variant": "heldout", ... } ],
  "verdict": "PASS"
}
```

* `source_commit` + `fixture_manifest_sha256` are the binding: every figure
  names both the tree that computed it and the held-out corpus it was computed
  on. A figure that cannot name both is refused, not emitted.
* `seed` names the one constant behind the bootstrap. Two runs of the same tree
  on the same corpus render byte-identically.
* Every string in the report comes from a closed vocabulary — a Rust enum, a
  fixed literal, a digest, or a preregistered filename. Nothing a model wrote
  can reach it.
* `verdict` is `PASS` only when EVERY preregistered set met its declared
  expectation: each `heldout` set passed its gate, and each `miscalibrated`
  control was caught by the ECE arm specifically. A green report therefore
  proves the gate discriminates, not merely that today's numbers were
  flattering.
* `verdict` is `PARTIAL` (never `PASS`) when every set present met its
  expectation but the corpus does not cover the campaign — every seam's
  `heldout` set AND at least one `miscalibrated` negative control (#3806, f1
  F4). A one-seam operator corpus reports `PARTIAL`: its numbers are real, but
  it cannot certify the contract. The bundle binds it as
  `BLOCKED{partial_campaign}`.
* `scripts/evidence/decision-calibration.sh` exits `0` ONLY on `PASS`. On
  `FAIL` or `PARTIAL` it still writes the report and the bundle — failing
  evidence is evidence — and then exits `1`, so a CI consumer that reads only
  the exit code can never mistake a failing calibration for success (#3806,
  f1 F3).

## What a corpus of this size can and cannot support

The in-repo controls carry ~60 scored items per seam. At ten bins that is six
items per bin, so the empirical rate can only land on multiples of 1/6: a
PERFECTLY calibrated provider still scores ECE ≈ 0.043 on a set this size, and
the reported `ece_bootstrap_p95` sits near 0.18 — above the 0.10 ceiling.

Read honestly, that means: at n ≈ 60 the gate is a REGRESSION DETECTOR — it
separates a calibrated set from a 3×-overconfident one with wide margin — and
NOT a certification that a provider's true ECE is below its ceiling with
confidence. The bound is published in every report precisely so that limitation
is visible rather than assumed away.

If you intend to certify a provider rather than watch it for regressions,
preregister a larger corpus and read `ece_bootstrap_p95` off YOUR report: the
bound shrinks roughly as 1/√n, so several times more items per seam are needed
before the bound itself sits under the ceiling. Do not assume a number here —
this harness measures it for your corpus, which is the point.

## Where a verdict may and may not go

Calibration is evidence for ADVICE. The decider only ever NARROWS a destructive
path; it never sits in `Permissions::evaluate` or the federation LWW merge, and
the deterministic pipeline stays authoritative. A seam name outside the four
above is refused by the harness for that reason — you cannot calibrate your way
into a governance decision.
