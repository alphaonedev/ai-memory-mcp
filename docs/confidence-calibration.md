---
layout: doc
---
# Confidence Calibration (v0.7.0 Form 5)

This document explains the substrate-side confidence pipeline: how
ai-memory derives, decays, observes, and calibrates the
`memories.confidence` value at v0.7.0 and later.

Before v0.7.0 Form 5 (issue #758) the `confidence` REAL column had
existed since schema v2 and recall ranking consumed it
(`+ confidence * 2.0` in the FTS5 score expression at
`src/storage/mod.rs`). The audit (PR #753) found the surrounding
pipeline incomplete: every caller value was taken at face, there was no
freshness signal, no telemetry capturing whether the caller's value
agreed with what the substrate would have computed, and no calibration
mechanism. Form 5 closes those four gaps; the legacy contract is
preserved unchanged when no opt-in flag is set.

## Model

A memory's confidence is one of four typed provenance buckets, named on
the `memories.confidence_source TEXT NOT NULL DEFAULT 'caller_provided'`
column (schema v39 sqlite / v38 postgres):

* `caller_provided` — the legacy default. Recall ranking and forensic
  bundles trust the caller's value verbatim.
* `auto_derived` — the deterministic engine in
  `src/confidence/mod.rs::derive` computed the value at write time from
  observable row signals (see *Signals* below). Opt-in via
  `AI_MEMORY_AUTO_CONFIDENCE=1`.
* `calibrated` — the operator-driven sweep
  (`ai-memory calibrate confidence --from-shadow` /
  `memory_calibrate_confidence` MCP tool) replaced the live value with
  a per-(namespace, source) baseline computed from shadow-mode samples.
* `decayed` — the freshness-decay updater applied
  `exp(-age * ln(2) / half_life)` when the periodic fold job applies the
  recall-access ladders from the `recall_observations` ledger (recall
  itself is a pure read; #1953). Opt-in via
  `AI_MEMORY_CONFIDENCE_DECAY=1` or per-namespace
  `confidence_decay_half_life_days` policy.

The discriminator lets recall ranking, forensic bundle export, and the
calibration sweep reason about the trust path of a score without
re-running the derivation. The companion column
`memories.confidence_signals TEXT NULL` stores a JSON snapshot of the
signals that produced a derived or calibrated value (NULL for legacy
and caller-provided rows). `memories.confidence_decayed_at TEXT NULL`
records the RFC3339 stamp of the last decay update.

## Signals

`ConfidenceSignals` carries five fields, all preserved alongside the
row so the derivation is reproducible after the fact:

| Field | Source | Effect |
|---|---|---|
| `source_age_days` | `metadata.observed_at` (Form 4) or `created_at` | drives the freshness factor |
| `atom_derivation` | `atom_of IS NOT NULL` (WT-1-A) | +0.1 base bump |
| `prior_corroboration_count` | `COUNT(*)` over outbound `memory_links` | `+0.05 * log10(1 + n)` |
| `freshness_factor` | `2^(-age / half_life)` clamped to `[0,1]` | blends with baseline |
| `baseline_per_source` | calibration table for `(namespace, source)` | drift floor when fresh content is stale |

The deterministic auto-derive formula is:

```text
base = 0.5
     + 0.1 * is_atom
     + 0.05 * log10(1 + corroboration)
     - 0.02 * age * (ln(2) / half_life)
value = clamp(base, 0, 1) * freshness_factor
      + (1 - freshness_factor) * baseline_per_source
```

`derive` is pure and audit-honest — it does **not** touch the substrate,
fire a hook, or read environment variables. Callers gate on
`auto_confidence_enabled()` and persist the returned value only when
the operator has opted in. Tests pass handcrafted `DeriveContext` values
and get bit-identical outputs across runs.

## Shadow-mode usage

Shadow mode captures both the caller-supplied value and the value the
auto-derive engine would have computed, alongside the signal envelope
that produced the derivation. Per-recall rows land in the
`confidence_shadow_observations` table when
`AI_MEMORY_CONFIDENCE_SHADOW=1`, sampled at
`AI_MEMORY_CONFIDENCE_SHADOW_SAMPLE_RATE` (0.0..=1.0; default 1.0).

The critical audit-honest property: shadow mode **never silently
overrides** the caller's confidence. The recall ranker still uses the
caller value downstream; the derived value is stored only for later
calibration review. This is the load-bearing property that lets
operators safely turn the engine on in production before any actual
recall-side behaviour changes.

Each observation row carries:

* `memory_id`, `namespace`, `observed_at` (the join key + window)
* `caller_confidence`, `derived_confidence` (the side-by-side comparison)
* `signals` (the JSON envelope that produced `derived_confidence`)
* `recall_outcome` (`consumed` | `unconsumed` | NULL) — the
  pre-provisioned slot for the v0.9.0 §11.5 (#1706) recall-usage
  feedback loop, described below. NULL until the offline sweep
  backfills it.

## Recall-usage feedback loop (v0.9.0 §11.5, #1706 — SHADOW MODE)

Closes the loop between "what did recall rank" and "what did the
caller actually use", **without changing recall ranking**. Every
`calibrate_from_shadow` sweep run
(`ai-memory calibrate confidence --from-shadow` /
`memory_calibrate_confidence`) now does two things before it computes
baselines:

1. **Backfill `recall_outcome`.** For every shadow row still `NULL`,
   `crate::confidence::shadow::backfill_recall_outcomes` joins the
   `recall_observations` consumption ledger (schema v47, #886;
   dual-backend + authenticated per #1705) on `memory_id`: `consumed`
   when a ledger row for that memory has `consumed = 1`, `unconsumed`
   when a ledger row exists but none is consumed, left `NULL` when no
   ledger row correlates at all. If the `recall_observations` table is
   absent (pre-#886 schema, or a bare fixture) this logs a WARN —
   `"recall_observations ledger absent, skipping consumption utility
   backfill"` — and returns cleanly; the sweep never fails just because
   the ledger isn't there.
2. **Emit `consumption_utility`.** Each `PerSourceBaseline` now carries
   `consumption_utility: Option<f64>` —
   `COUNT(recall_outcome = 'consumed') / COUNT(recall_outcome IS NOT
   NULL)` for that `(namespace, source)` group. `None` (never a
   misleading `0.0`) when no row in the group has ledger evidence yet.

**This is logged only.** `consumption_utility` is surfaced in the
`CalibrationReport` JSON, the `UTIL` column of the ASCII table, and a
`tracing::info!` line per group — `crate::storage::recall` never reads
it and its score formula is untouched. The metric exists to give the
future live-wire decision (issue #1707, conditional) real evidence
before any ranking change is considered.

Today the confidence-shadow write path (`shadow::observe`) has no live
caller — `AI_MEMORY_CONFIDENCE_SHADOW=1` provisions the table and the
sweep/backfill/GC machinery, but nothing on the recall or store hot
path calls `observe` yet, so `confidence_shadow_observations` stays
empty in a stock deployment until that separate wiring lands. The
sweep and metric described here are correct against whatever shadow
rows exist (proven by fixture-driven tests) and degrade to `None` /
empty reports otherwise — they do not depend on that wiring landing
first.

## Decay function

Freshness decay applies the standard half-life model:

```text
decayed(base, age_days, half_life_days)
    = base * 2^(-age / half_life)
    = base * exp(-age * ln(2) / half_life)
```

clamped to `[0.0, 1.0]`. At `age == half_life`, the value collapses to
`0.5 * base`. The default half-life is 30 days
(`DEFAULT_HALF_LIFE_DAYS`); each namespace can override via the
`confidence_decay_half_life_days` policy field.

`decay::decayed` is pure (no I/O). The recall path is the caller — when
`AI_MEMORY_CONFIDENCE_DECAY=1` or the namespace policy is set, recall
computes the decayed value, UPDATEs `memories.confidence`, sets
`confidence_source = 'decayed'`, and stamps `confidence_decayed_at`.

## Who the report covers — caller-scoped aggregate (v1.0.0, #3507)

The report NAMES namespaces and reports per-namespace statistics, so it is
gated like any other read: **the sweep aggregates only rows the calling
principal can read**, on BOTH backends.

* The predicate is the store's own, not a second copy — the
  `crate::storage::visibility_clause` fragment (the #1921 team/unit/org
  subtree arms plus the #1720 owner-keyed `scope=private` arm), the #3348
  substrate exclusion, and the fail-closed lifecycle allow-list. SQLite and
  PostgreSQL render it from the SAME generator; only the bound-parameter
  dialect differs.
* **ADMIN keeps the global sweep.** On HTTP that is the existing admin
  allow-list gate (`is_admin_caller_trusted`: an allow-listed id, request
  authentication, and per-agent-key attestation where enrolled); at the SAL
  boundary it is a `CallerContext` with `bypass_visibility`. The MCP and CLI
  surfaces have no authenticated admin gate, so they have no admin arm.
* **No resolvable caller is a REFUSAL, never "everything."** `POST
  /api/v1/memory_calibrate_confidence` answers `403` when `X-Agent-Id` is
  absent; the SAL method refuses an empty, shape-invalid or synthetic
  `anonymous:` principal. MCP and the CLI bind to the process-derived
  identity the write path stamps when `AI_MEMORY_AGENT_ID` is unset, so a
  single-operator install keeps working.
* **Two documented consequences of the scoped sweep, both fail-closed.** An
  ORPHAN observation (its source memory was CASCADE-deleted) has no row whose
  visibility can be evaluated, so it is dropped — the orphan tolerance
  described above survives only for the admin sweep. And a scoped sweep is
  strictly READ-ONLY: the `recall_outcome` backfill below runs for the admin
  sweep only, so `consumption_utility` / `consume_access_divergence` may stay
  `null` for rows nothing has backfilled — the honest "no evidence yet",
  never a wrong number.

## Calibration workflow

1. Operator turns on shadow mode for a window:
   `AI_MEMORY_CONFIDENCE_SHADOW=1`. Optionally caps the sample rate via
   `AI_MEMORY_CONFIDENCE_SHADOW_SAMPLE_RATE=0.1` (10% of recall touches
   record a row).
2. Daemon runs normal traffic. Per-recall samples accumulate.
3. Operator (or the daemon) drains the report:
   `ai-memory calibrate confidence --from-shadow --days 30`. Equivalent
   MCP tool: `memory_calibrate_confidence` (Family::Power).
4. Output is a `CalibrationReport` envelope: `window_days`,
   `total_observations`, and a list of `PerSourceBaseline` rows with
   median, mean, count, and a 10-bucket histogram per
   `(namespace, source)` pair.
5. Operator reviews the report. If the sample is well-distributed and
   the medians look sensible, the baselines become the
   `baseline_per_source` signal `derive` consumes on the next write
   wave. Persistence into a calibration store is operator-driven in a
   follow-up; v0.7.0 ships the observation pipeline and the read-side
   report only. A poorly-sampled window can't silently re-pin a
   namespace's confidence ceiling.

The audit-honest contract: every step is opt-in and reviewable. No
substrate write changes the canonical confidence value until the
operator authorises it.

## See also

* `src/confidence/mod.rs` — `derive`, `DeriveContext`,
  `auto_confidence_enabled`.
* `src/confidence/decay.rs` — `decayed`, `decay_enabled`.
* `src/confidence/shadow.rs` — `observe`, `observations_since`,
  `should_sample`, `backfill_recall_outcomes` (#1706).
* `src/confidence/calibrate.rs` — `calibrate_from_shadow`,
  `CalibrationReport`, `PerSourceBaseline`.
* `migrations/sqlite/0033_v07_form5_confidence_calibration.sql` —
  schema half (mirror at `migrations/postgres/0020_…`).
* `tests/form_5_confidence_calibration.rs` — acceptance suite.
