// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory doctor --remote` — the daemon-served sections (v1.0.0
//! [#3656](https://github.com/alphaonedev/ai-memory-mcp/issues/3656), audit
//! #3645 finding F10).
//!
//! Lives in its own module rather than inside `cli::doctor`, per the #3471
//! precedent: a new section is a new file, not another 200 lines on the pile.
//!
//! # What the remote doctor consumes, and what each surface proves
//!
//! | Surface | Sections | What it proves |
//! |---|---|---|
//! | `GET /api/v1/health` | Health, Sync | liveness (connection + FTS reachability), the CACHED FTS integrity verdict with its age, embedder wiring, whether federation is configured |
//! | `GET /api/v1/stats` | Storage, Index | corpus counts, `dim_violations`, process-local HNSW evictions |
//! | `GET /api/v1/metrics` | Index, Sync, Webhook | the daemon's live Prometheus registry |
//!
//! # The three rules every section here holds to (the #3646 standard)
//!
//! 1. **Never emit a number you did not measure.** A series absent from the
//!    scrape renders `not_in_response`, never `0`; a fetch that failed renders
//!    the error and the section is `N/A`, never `Info`.
//! 2. **Never report a quiet node as healthy.** `pending` / `stale` /
//!    `disabled` integrity verdicts are "no assertion" and the report says so.
//!    A verdict the daemon calls `ok` is re-aged by THIS clock against the
//!    daemon's own ceiling ([`STALE_INTERVAL_MULTIPLIER`] × `interval_secs`),
//!    so a checker that died after the daemon last evaluated its verdict
//!    cannot re-present its last pass through the doctor.
//! 3. **Preserve the unavailable / disabled / failed distinctions.** Each is a
//!    different operator action, so each is a different fact value and note.
//!
//! # What this module deliberately does NOT assert
//!
//! - Fleet convergence: peer push freshness has no remote surface (#3654), so
//!   `Sync` states `convergence = not_asserted` rather than inferring it from
//!   an empty DLQ.
//! - Wake-plane readiness (#3657).
//! - Governance queue age: `GET /api/v1/pending` is caller-scoped, so a count
//!   read through one credential is not the node's queue. `Governance` stays
//!   `N/A` in remote mode and says why.

use std::collections::HashMap;

use serde_json::Value;

use super::doctor::{
    FACT_DISPATCHED_TOTAL, FACT_FAILED_TOTAL, FACT_HTTP_STATUS, FACT_INDEX_EVICTIONS_TOTAL,
    FACT_MAX_SKEW_SECS, FACT_SUCCESS_RATE_PCT, HttpStatusError, MSG_NO_DELIVERIES_YET,
    NOT_IN_RESPONSE, RemoteAuth, ReportSection, Severity, WEBHOOK_SUCCESS_WARN_PCT, append_note,
    http_get_raw, http_success, severity_max, stats_forbidden_note,
};
use crate::background::fts_integrity::{
    STALE_INTERVAL_MULTIPLIER, VERDICT_DISABLED, VERDICT_FAILED, VERDICT_OK, VERDICT_PENDING,
    VERDICT_STALE,
};
use crate::handlers::transport::{
    HEALTH_KEY_CHECKED_AT, HEALTH_KEY_CHECKS, HEALTH_KEY_CONNECTION, HEALTH_KEY_EMBEDDER_READY,
    HEALTH_KEY_FEDERATION_ENABLED, HEALTH_KEY_FTS_INDEX, HEALTH_KEY_FTS_INTEGRITY,
    HEALTH_KEY_INTERVAL_SECS, HEALTH_KEY_STATUS, HEALTH_KEY_VERSION, PROBE_ERROR, PROBE_OK,
};
use crate::metrics::names as metric;

/// Section name for the daemon liveness probe. One definition, referenced by
/// the renderer and by the tests that assert the section is present.
pub const SECTION_HEALTH: &str = "Health";

/// Fact: the daemon's own `status` verdict from `/health`.
const FACT_DAEMON_STATUS: &str = "daemon_status";
/// Fact: the daemon binary version reported by `/health`.
const FACT_DAEMON_VERSION: &str = "daemon_version";
/// Fact: `checks.connection` — the connection answered SQL.
const FACT_CHECK_CONNECTION: &str = "check_connection";
/// Fact: `checks.fts_index` — the FTS5 index is reachable (not verified).
const FACT_CHECK_FTS_INDEX: &str = "check_fts_index";
/// Fact: the cached deep-integrity verdict tag.
const FACT_FTS_INTEGRITY_STATUS: &str = "fts_integrity_status";
/// Fact: RFC3339 of the last completed integrity check, or `never`.
const FACT_FTS_INTEGRITY_CHECKED_AT: &str = "fts_integrity_checked_at";
/// Fact: seconds between the last completed check and THIS probe's clock.
const FACT_FTS_INTEGRITY_AGE_SECS: &str = "fts_integrity_age_secs";
/// Fact: the configured checker cadence (`0` = disabled).
const FACT_FTS_INTEGRITY_INTERVAL_SECS: &str = "fts_integrity_interval_secs";
/// Fact: what the Health section asserts — and what it does not.
const FACT_PROVES: &str = "proves";
/// Value of [`FACT_PROVES`]. Spelled once; the doc page quotes it.
const MSG_HEALTH_PROVES: &str = "liveness + cached FTS integrity verdict only — not wake-plane \
                                 (#3657) or replication (#3654) readiness";
/// Fact value when the daemon never completed an integrity check.
const CHECKED_AT_NEVER: &str = "never";
/// Fact: live HNSW population from the daemon's registry.
const FACT_HNSW_SIZE: &str = "hnsw_size";
/// Fact: pending federation push DLQ rows.
const FACT_PUSH_DLQ_DEPTH: &str = "push_dlq_depth";
/// Fact: quorum writes that met W with at least one peer past the deadline.
const FACT_PARTIAL_QUORUM_TOTAL: &str = "partial_quorum_total";
/// Fact: post-quorum fanout tasks whose outcome was never observed.
const FACT_FANOUT_DROPPED_TOTAL: &str = "fanout_dropped_total";
/// Fact: age of the last successful push per peer — no remote surface yet.
const FACT_LAST_PUSH_AGE_SECS: &str = "last_successful_push_age_secs";
/// Fact: whether this report asserts the mesh has converged.
const FACT_CONVERGENCE: &str = "convergence";
/// Fact: active webhook subscriptions.
const FACT_SUBSCRIPTIONS_ACTIVE: &str = "subscriptions_active";
/// Fact: DLQ inserts refused at the per-subscription depth cap.
const FACT_SUBSCRIPTION_DLQ_OVERFLOW_TOTAL: &str = "subscription_dlq_overflow_total";
/// Fact: the stats document could not be read.
const FACT_STATS_ERROR: &str = "stats_error";
/// Fact: the fetch error, when a surface could not be read.
const FACT_ERROR: &str = "error";
/// Value for a fact whose signal has no remote surface at all (distinct from
/// [`NOT_IN_RESPONSE`], which means the daemon answered without the field).
const UNAVAILABLE_NO_REMOTE_SURFACE: &str =
    "unavailable (no remote surface — run doctor with --db on the node)";
/// Value for [`FACT_LAST_PUSH_AGE_SECS`] until #3654 lands the observation.
const UNAVAILABLE_PENDING_3654: &str = "unavailable (peer push freshness lands with #3654)";
/// Value for [`FACT_CONVERGENCE`]: measured counters are not a convergence proof.
const CONVERGENCE_NOT_ASSERTED: &str = "not_asserted (peer freshness has no remote surface, #3654)";
/// Note stem for every metrics-derived section — counters are process-local.
const NOTE_PROCESS_LIFETIME: &str =
    "counters are process-lifetime since daemon start; a restart resets them";
/// Note when the scrape could not be read: nothing metrics-derived is asserted.
const NOTE_METRICS_UNREADABLE: &str =
    "metrics endpoint unreadable — nothing in this section is asserted";

// ---------------------------------------------------------------------------
// Health — `GET /api/v1/health`
// ---------------------------------------------------------------------------

/// The result of probing `/health`: the rendered section plus the one field
/// another section (Sync) needs.
pub(super) struct HealthProbe {
    pub(super) section: ReportSection,
    /// `federation_enabled` as the daemon reported it; `None` when the probe
    /// failed or the field was absent.
    pub(super) federation_enabled: Option<bool>,
}

/// `v.get(key)` as a string, or [`NOT_IN_RESPONSE`].
fn str_or_absent<'a>(v: Option<&'a Value>) -> &'a str {
    v.and_then(Value::as_str).unwrap_or(NOT_IN_RESPONSE)
}

/// Render a boolean top-level field as a fact and hand the value back.
fn push_bool_fact(v: &Value, key: &str, facts: &mut Vec<(String, String)>) -> Option<bool> {
    let b = v.get(key).and_then(Value::as_bool);
    facts.push((
        key.into(),
        b.map_or_else(|| NOT_IN_RESPONSE.to_string(), |b| b.to_string()),
    ));
    b
}

/// Probe the daemon's liveness endpoint and render it as the `Health` section.
///
/// The body is read at EVERY status: a `503` is the daemon's fail-closed
/// answer and its body names which check failed, so bailing on the status
/// (as the JSON helper does for the other surfaces) would throw away exactly
/// the finding this section exists to surface.
pub(super) fn section_health_remote(url: &str, auth: &RemoteAuth, now_unix: i64) -> HealthProbe {
    let mut facts: Vec<(String, String)> = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;
    let mut federation_enabled = None;

    match http_get_raw(url, auth) {
        Err(e) => {
            severity = Severity::Critical;
            facts.push((FACT_ERROR.into(), e.to_string()));
            note = Some(format!("could not reach {url}"));
        }
        Ok((status, body)) => {
            facts.push((FACT_HTTP_STATUS.into(), status.to_string()));
            match serde_json::from_str::<Value>(&body) {
                Err(e) => {
                    severity = Severity::Critical;
                    facts.push((FACT_ERROR.into(), format!("non-JSON body: {e}")));
                    note = Some(format!(
                        "{url} answered HTTP {status} without a health document"
                    ));
                }
                Ok(v) => {
                    federation_enabled = render_health_document(
                        &v,
                        status,
                        now_unix,
                        &mut facts,
                        &mut severity,
                        &mut note,
                    );
                }
            }
        }
    }
    facts.push((FACT_PROVES.into(), MSG_HEALTH_PROVES.into()));
    HealthProbe {
        section: ReportSection {
            name: SECTION_HEALTH.into(),
            severity,
            facts,
            note,
        },
        federation_enabled,
    }
}

/// Render a parsed `/health` document. Returns the daemon's
/// `federation_enabled` for the Sync section.
fn render_health_document(
    v: &Value,
    http_status: u16,
    now_unix: i64,
    facts: &mut Vec<(String, String)>,
    severity: &mut Severity,
    note: &mut Option<String>,
) -> Option<bool> {
    let daemon_status = str_or_absent(v.get(HEALTH_KEY_STATUS));
    facts.push((FACT_DAEMON_STATUS.into(), daemon_status.to_string()));
    facts.push((
        FACT_DAEMON_VERSION.into(),
        str_or_absent(v.get(HEALTH_KEY_VERSION)).to_string(),
    ));
    if !http_success(http_status) || daemon_status != PROBE_OK {
        *severity = Severity::Critical;
        append_note(
            note,
            &format!(
                "daemon reports HTTP {http_status} / status={daemon_status} — it is not serving"
            ),
        );
    }

    let checks = v.get(HEALTH_KEY_CHECKS);
    for (fact, key) in [
        (FACT_CHECK_CONNECTION, HEALTH_KEY_CONNECTION),
        (FACT_CHECK_FTS_INDEX, HEALTH_KEY_FTS_INDEX),
    ] {
        let val = str_or_absent(checks.and_then(|c| c.get(key)));
        facts.push((fact.into(), val.to_string()));
        if val == PROBE_ERROR {
            *severity = Severity::Critical;
            append_note(note, &format!("the daemon's {key} probe failed"));
        }
    }

    match v.get(HEALTH_KEY_FTS_INTEGRITY) {
        Some(integrity) => render_integrity_verdict(integrity, now_unix, facts, severity, note),
        None => {
            facts.push((FACT_FTS_INTEGRITY_STATUS.into(), NOT_IN_RESPONSE.into()));
            append_note(
                note,
                "daemon predates the cached integrity verdict (#2579) — index integrity is \
                 not asserted",
            );
        }
    }

    push_bool_fact(v, HEALTH_KEY_EMBEDDER_READY, facts);
    push_bool_fact(v, HEALTH_KEY_FEDERATION_ENABLED, facts)
}

/// Render the cached deep-integrity verdict with the daemon's distinctions
/// intact, and re-age an `ok` verdict by this clock.
fn render_integrity_verdict(
    integrity: &Value,
    now_unix: i64,
    facts: &mut Vec<(String, String)>,
    severity: &mut Severity,
    note: &mut Option<String>,
) {
    let tag = str_or_absent(integrity.get(HEALTH_KEY_STATUS));
    facts.push((FACT_FTS_INTEGRITY_STATUS.into(), tag.to_string()));
    let checked_at = integrity.get(HEALTH_KEY_CHECKED_AT).and_then(Value::as_str);
    facts.push((
        FACT_FTS_INTEGRITY_CHECKED_AT.into(),
        checked_at.unwrap_or(CHECKED_AT_NEVER).to_string(),
    ));
    let interval = integrity
        .get(HEALTH_KEY_INTERVAL_SECS)
        .and_then(Value::as_u64);
    facts.push((
        FACT_FTS_INTEGRITY_INTERVAL_SECS.into(),
        interval.map_or_else(|| NOT_IN_RESPONSE.to_string(), |i| i.to_string()),
    ));
    // Age by THIS clock: a measurement this probe made, not a relay of the
    // daemon's opinion about itself. Negative means the daemon's clock is
    // ahead of ours; it is rendered as measured.
    let age = checked_at
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| now_unix.saturating_sub(t.timestamp()));
    if let Some(age) = age {
        facts.push((FACT_FTS_INTEGRITY_AGE_SECS.into(), age.to_string()));
    }

    match tag {
        VERDICT_FAILED => {
            *severity = Severity::Critical;
            append_note(
                note,
                "the daemon's FTS5 index disagrees with its memories table — keyword recall \
                 on this node silently returns FEWER rows than it should; rebuild the index \
                 on the node",
            );
        }
        VERDICT_STALE => {
            *severity = severity_max(*severity, Severity::Warning);
            append_note(
                note,
                "the daemon's integrity checker is not running — its last pass has aged out \
                 and index integrity is NOT asserted",
            );
        }
        VERDICT_DISABLED => {
            *severity = severity_max(*severity, Severity::Warning);
            append_note(
                note,
                "the integrity checker is disabled on this node — an absent control is not \
                 a passing one",
            );
        }
        VERDICT_PENDING => {
            append_note(
                note,
                "no integrity check has completed on this node yet — integrity is not \
                 asserted (not a failure)",
            );
        }
        VERDICT_OK => {
            if let (Some(age), Some(interval)) = (age, interval)
                && interval > 0
            {
                let ceiling = i64::try_from(interval)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(STALE_INTERVAL_MULTIPLIER);
                if age > ceiling {
                    *severity = severity_max(*severity, Severity::Warning);
                    append_note(
                        note,
                        &format!(
                            "daemon reports ok but the verdict is {age}s old by this clock \
                             (ceiling {ceiling}s = {STALE_INTERVAL_MULTIPLIER}×interval) — \
                             the checker stopped or the clocks disagree"
                        ),
                    );
                }
            }
        }
        other => {
            *severity = severity_max(*severity, Severity::Warning);
            append_note(
                note,
                &format!("unrecognised integrity verdict tag {other:?}"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics scrape — `GET /api/v1/metrics`
// ---------------------------------------------------------------------------

/// One parsed Prometheus text scrape: series name → summed sample value.
///
/// A labelled family (`name{reason="a"} 1` / `name{reason="b"} 2`) sums to one
/// value per name, which is what every doctor fact here wants ("how many
/// fanout outcomes were dropped", not per reason). Absent is `None`, never
/// `0`.
#[derive(Debug, Default)]
pub(super) struct MetricsSample {
    series: HashMap<String, f64>,
}

impl MetricsSample {
    /// Parse the text exposition format. Comment / blank lines are skipped;
    /// a line that does not parse is skipped rather than failing the whole
    /// scrape — a value we cannot read is a value we do not report.
    pub(super) fn parse(text: &str) -> Self {
        let mut series: HashMap<String, f64> = HashMap::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((name, rest)) = split_series_name(line) else {
                continue;
            };
            let Some(value) = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
            else {
                continue;
            };
            if !value.is_finite() {
                continue;
            }
            *series.entry(name.to_string()).or_insert(0.0) += value;
        }
        Self { series }
    }

    /// The summed sample for `name`, or `None` when the scrape had no such
    /// series.
    pub(super) fn get(&self, name: &str) -> Option<f64> {
        self.series.get(name).copied()
    }
}

/// Split `name{labels} value …` / `name value …` into `(name, " value …")`,
/// skipping a quoted label block whose values may themselves contain `}`.
fn split_series_name(line: &str) -> Option<(&str, &str)> {
    let name_end = line
        .find(|c: char| c == '{' || c.is_whitespace())
        .unwrap_or(line.len());
    let name = &line[..name_end];
    if name.is_empty() {
        return None;
    }
    let rest = &line[name_end..];
    let Some(labels) = rest.strip_prefix('{') else {
        return Some((name, rest));
    };
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in labels.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '}' if !in_quotes => return Some((name, &labels[i + 1..])),
            _ => {}
        }
    }
    None
}

/// Fetch and parse the scrape. A non-2xx answer is an error — an empty
/// document would otherwise render every series as absent, and "absent" and
/// "unreadable" are different findings.
pub(super) fn fetch_metrics(url: &str, auth: &RemoteAuth) -> anyhow::Result<MetricsSample> {
    let (status, body) = http_get_raw(url, auth)?;
    if !http_success(status) {
        return Err(HttpStatusError::new(status, url).into());
    }
    Ok(MetricsSample::parse(&body))
}

/// Render a sample the way the exposition wrote it: integral counters and
/// gauges without a fractional tail.
fn fmt_sample(v: f64) -> String {
    if v.fract().abs() < f64::EPSILON {
        format!("{v:.0}")
    } else {
        format!("{v}")
    }
}

/// Push `fact` from the scrape and hand the value back. Absent renders
/// [`NOT_IN_RESPONSE`] — never a zero the daemon did not report.
fn push_series(
    sample: &MetricsSample,
    name: &str,
    fact: &str,
    facts: &mut Vec<(String, String)>,
) -> Option<f64> {
    let v = sample.get(name);
    facts.push((
        fact.into(),
        v.map_or_else(|| NOT_IN_RESPONSE.to_string(), fmt_sample),
    ));
    v
}

// ---------------------------------------------------------------------------
// Index — `/stats.index_evictions_total` + `/metrics` HNSW gauge
// ---------------------------------------------------------------------------

/// The remote Index section. Evictions come from `/stats` (the P3 counter the
/// local section still renders as `not_observed` because it is process-local
/// to the daemon), the live population from the scrape. Same rule as the
/// module doc for local mode: **Critical** when evictions > 0.
pub(super) fn section_index_remote(
    stats: &anyhow::Result<Value>,
    metrics: &anyhow::Result<MetricsSample>,
) -> ReportSection {
    let mut facts: Vec<(String, String)> = Vec::new();
    let mut severity = Severity::NotAvailable;
    let mut note: Option<String> = None;

    match metrics {
        Ok(m) => {
            severity = Severity::Info;
            push_series(m, metric::HNSW_SIZE, FACT_HNSW_SIZE, &mut facts);
        }
        Err(e) => facts.push((FACT_ERROR.into(), e.to_string())),
    }
    match stats {
        Ok(v) => {
            severity = severity_max(severity, Severity::Info);
            match v.get(FACT_INDEX_EVICTIONS_TOTAL).and_then(Value::as_u64) {
                Some(0) => facts.push((FACT_INDEX_EVICTIONS_TOTAL.into(), "0".into())),
                Some(n) => {
                    facts.push((FACT_INDEX_EVICTIONS_TOTAL.into(), n.to_string()));
                    severity = Severity::Critical;
                    append_note(
                        &mut note,
                        &format!(
                            "{n} HNSW evictions since daemon start — the in-memory index hit \
                             its cap and recall quality has degraded for evicted ids"
                        ),
                    );
                }
                None => facts.push((FACT_INDEX_EVICTIONS_TOTAL.into(), NOT_IN_RESPONSE.into())),
            }
        }
        Err(e) => {
            facts.push((FACT_STATS_ERROR.into(), e.to_string()));
            if let Some(msg) = stats_forbidden_note(e) {
                append_note(&mut note, msg);
            }
        }
    }
    if severity == Severity::NotAvailable {
        append_note(&mut note, NOTE_METRICS_UNREADABLE);
    }

    ReportSection {
        name: "Index".into(),
        severity,
        facts,
        note,
    }
}

// ---------------------------------------------------------------------------
// Sync — `/health.federation_enabled` + `/metrics` federation counters
// ---------------------------------------------------------------------------

/// The remote Sync section. Measures what the daemon exposes (DLQ depth,
/// partial-quorum and dropped-fanout totals) and states, by name, the two
/// signals it cannot measure. It never infers convergence from quiet
/// counters.
pub(super) fn section_sync_remote(
    federation_enabled: Option<bool>,
    metrics: &anyhow::Result<MetricsSample>,
) -> ReportSection {
    let mut facts: Vec<(String, String)> = vec![(
        HEALTH_KEY_FEDERATION_ENABLED.into(),
        federation_enabled.map_or_else(|| NOT_IN_RESPONSE.to_string(), |b| b.to_string()),
    )];
    if federation_enabled == Some(false) {
        return ReportSection {
            name: "Sync".into(),
            severity: Severity::NotAvailable,
            facts,
            note: Some(
                "federation is not configured on this node — there is no mesh to converge".into(),
            ),
        };
    }
    let mut severity = Severity::NotAvailable;
    let mut note: Option<String> = None;

    match metrics {
        Ok(m) => {
            severity = Severity::Info;
            let dlq = push_series(
                m,
                metric::FEDERATION_PUSH_DLQ_DEPTH,
                FACT_PUSH_DLQ_DEPTH,
                &mut facts,
            );
            if dlq.is_some_and(|d| d > 0.0) {
                severity = severity_max(severity, Severity::Warning);
                append_note(
                    &mut note,
                    &format!(
                        "{} federation pushes are quarantined in the DLQ — one or more peers \
                         are persistently unreachable; replay after peer recovery",
                        fmt_sample(dlq.unwrap_or_default())
                    ),
                );
            }
            push_series(
                m,
                metric::FEDERATION_PARTIAL_QUORUM_TOTAL,
                FACT_PARTIAL_QUORUM_TOTAL,
                &mut facts,
            );
            let dropped = push_series(
                m,
                metric::FEDERATION_FANOUT_DROPPED_TOTAL,
                FACT_FANOUT_DROPPED_TOTAL,
                &mut facts,
            );
            if dropped.is_some_and(|d| d > 0.0) {
                severity = severity_max(severity, Severity::Warning);
                append_note(
                    &mut note,
                    &format!(
                        "{} post-quorum fanout outcomes were never observed — mesh \
                         divergence risk",
                        fmt_sample(dropped.unwrap_or_default())
                    ),
                );
            }
            append_note(&mut note, NOTE_PROCESS_LIFETIME);
        }
        Err(e) => {
            facts.push((FACT_ERROR.into(), e.to_string()));
            append_note(&mut note, NOTE_METRICS_UNREADABLE);
        }
    }
    facts.push((
        FACT_MAX_SKEW_SECS.into(),
        UNAVAILABLE_NO_REMOTE_SURFACE.into(),
    ));
    facts.push((
        FACT_LAST_PUSH_AGE_SECS.into(),
        UNAVAILABLE_PENDING_3654.into(),
    ));
    facts.push((FACT_CONVERGENCE.into(), CONVERGENCE_NOT_ASSERTED.into()));

    ReportSection {
        name: "Sync".into(),
        severity,
        facts,
        note,
    }
}

// ---------------------------------------------------------------------------
// Webhook — `/metrics` delivery counters
// ---------------------------------------------------------------------------

/// The remote Webhook section. Same success-rate rule as local mode
/// ([`WEBHOOK_SUCCESS_WARN_PCT`]), over the daemon's process-lifetime
/// counters rather than the table's lifetime columns.
pub(super) fn section_webhook_remote(metrics: &anyhow::Result<MetricsSample>) -> ReportSection {
    let mut facts: Vec<(String, String)> = Vec::new();
    let mut severity = Severity::NotAvailable;
    let mut note: Option<String> = None;

    match metrics {
        Ok(m) => {
            severity = Severity::Info;
            push_series(
                m,
                metric::SUBSCRIPTIONS_ACTIVE,
                FACT_SUBSCRIPTIONS_ACTIVE,
                &mut facts,
            );
            let dispatched = push_series(
                m,
                metric::WEBHOOK_DISPATCHED_TOTAL,
                FACT_DISPATCHED_TOTAL,
                &mut facts,
            );
            let failed = push_series(
                m,
                metric::WEBHOOK_FAILED_TOTAL,
                FACT_FAILED_TOTAL,
                &mut facts,
            );
            match (dispatched, failed) {
                (Some(d), Some(f)) if d > 0.0 => {
                    // A counter reset between the two samples can put failed
                    // above dispatched; clamp rather than report a negative rate.
                    let success_rate = ((d - f).max(0.0) / d) * 100.0;
                    facts.push((FACT_SUCCESS_RATE_PCT.into(), format!("{success_rate:.2}")));
                    if success_rate < WEBHOOK_SUCCESS_WARN_PCT {
                        severity = severity_max(severity, Severity::Warning);
                        append_note(
                            &mut note,
                            &format!(
                                "delivery success {success_rate:.2}% since daemon start < \
                                 {WEBHOOK_SUCCESS_WARN_PCT}% threshold"
                            ),
                        );
                    }
                }
                (Some(_), Some(_)) => {
                    facts.push((FACT_SUCCESS_RATE_PCT.into(), MSG_NO_DELIVERIES_YET.into()));
                }
                _ => facts.push((FACT_SUCCESS_RATE_PCT.into(), NOT_IN_RESPONSE.into())),
            }
            let overflow = push_series(
                m,
                metric::SUBSCRIPTION_DLQ_OVERFLOW_TOTAL,
                FACT_SUBSCRIPTION_DLQ_OVERFLOW_TOTAL,
                &mut facts,
            );
            if overflow.is_some_and(|o| o > 0.0) {
                severity = severity_max(severity, Severity::Warning);
                append_note(
                    &mut note,
                    &format!(
                        "{} subscription DLQ inserts were refused at the depth cap — a \
                         persistently failing webhook target; drain it with `ai-memory \
                         subscription dlq drain <subscription_id>`",
                        fmt_sample(overflow.unwrap_or_default())
                    ),
                );
            }
            append_note(&mut note, NOTE_PROCESS_LIFETIME);
        }
        Err(e) => {
            facts.push((FACT_ERROR.into(), e.to_string()));
            append_note(&mut note, NOTE_METRICS_UNREADABLE);
        }
    }

    ReportSection {
        name: "Webhook".into(),
        severity,
        facts,
        note,
    }
}

// ---------------------------------------------------------------------------
// Tests — the live HTTP fixtures the issue asks for (wiremock), plus the
// parser. Full-report composition is pinned in `cli::doctor`'s tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::routes;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fact<'a>(section: &'a ReportSection, key: &str) -> &'a str {
        section
            .facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("fact {key} missing in {section:?}"))
    }

    fn note(section: &ReportSection) -> &str {
        section.note.as_deref().unwrap_or_default()
    }

    /// A `/health` document the way the daemon writes it (#2579 shape).
    fn health_doc(
        status: &str,
        connection: &str,
        fts_index: &str,
        verdict: &str,
        checked_at: Option<String>,
        interval_secs: u64,
    ) -> Value {
        serde_json::json!({
            HEALTH_KEY_STATUS: status,
            "service": "ai-memory",
            HEALTH_KEY_VERSION: "test",
            HEALTH_KEY_EMBEDDER_READY: false,
            HEALTH_KEY_FEDERATION_ENABLED: true,
            HEALTH_KEY_CHECKS: {
                HEALTH_KEY_CONNECTION: connection,
                HEALTH_KEY_FTS_INDEX: fts_index,
            },
            HEALTH_KEY_FTS_INTEGRITY: {
                HEALTH_KEY_STATUS: verdict,
                HEALTH_KEY_CHECKED_AT: checked_at,
                HEALTH_KEY_INTERVAL_SECS: interval_secs,
            },
        })
    }

    fn rfc3339_secs_ago(now_unix: i64, secs: i64) -> String {
        chrono::DateTime::from_timestamp(now_unix - secs, 0)
            .expect("test timestamp")
            .to_rfc3339()
    }

    async fn probe(
        server: &MockServer,
        http_status: u16,
        body: Value,
        now_unix: i64,
    ) -> HealthProbe {
        Mock::given(method("GET"))
            .and(path(routes::HEALTH))
            .respond_with(ResponseTemplate::new(http_status).set_body_json(body))
            .mount(server)
            .await;
        let url = format!("{}{}", server.uri(), routes::HEALTH);
        tokio::task::spawn_blocking(move || {
            section_health_remote(&url, &RemoteAuth::default(), now_unix)
        })
        .await
        .expect("join")
    }

    const NOW: i64 = 1_800_000_000;
    const INTERVAL: u64 = 900;

    #[tokio::test(flavor = "multi_thread")]
    async fn health_failed_integrity_is_critical_and_reads_the_503_body_3656() {
        let server = MockServer::start().await;
        let body = health_doc(
            PROBE_ERROR,
            PROBE_OK,
            "reachable",
            VERDICT_FAILED,
            Some(rfc3339_secs_ago(NOW, 10)),
            INTERVAL,
        );
        let probe = probe(&server, 503, body, NOW).await;
        let s = &probe.section;
        assert_eq!(s.name, SECTION_HEALTH);
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(fact(s, FACT_HTTP_STATUS), "503");
        assert_eq!(fact(s, FACT_DAEMON_STATUS), PROBE_ERROR);
        // The 503 body was READ, not discarded on status: the verdict is named.
        assert_eq!(fact(s, FACT_FTS_INTEGRITY_STATUS), VERDICT_FAILED);
        assert_eq!(fact(s, FACT_FTS_INTEGRITY_AGE_SECS), "10");
        assert!(note(s).contains("disagrees"), "{s:?}");
        assert_eq!(probe.federation_enabled, Some(true));
        assert_eq!(fact(s, FACT_PROVES), MSG_HEALTH_PROVES);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_stale_verdict_is_warning_never_healthy_3656() {
        let server = MockServer::start().await;
        let body = health_doc(
            PROBE_OK,
            PROBE_OK,
            "reachable",
            VERDICT_STALE,
            Some(rfc3339_secs_ago(NOW, 5_000)),
            INTERVAL,
        );
        let s = probe(&server, 200, body, NOW).await.section;
        assert_eq!(s.severity, Severity::Warning);
        assert_eq!(fact(&s, FACT_FTS_INTEGRITY_STATUS), VERDICT_STALE);
        assert!(note(&s).contains("not running"), "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_ok_verdict_aged_past_ceiling_by_this_clock_warns_3656() {
        let server = MockServer::start().await;
        let ceiling = i64::try_from(INTERVAL).expect("fits") * STALE_INTERVAL_MULTIPLIER;
        let body = health_doc(
            PROBE_OK,
            PROBE_OK,
            "reachable",
            VERDICT_OK,
            Some(rfc3339_secs_ago(NOW, ceiling + 60)),
            INTERVAL,
        );
        let s = probe(&server, 200, body, NOW).await.section;
        // The daemon SAYS ok; the doctor measured otherwise and says so.
        assert_eq!(fact(&s, FACT_FTS_INTEGRITY_STATUS), VERDICT_OK);
        assert_eq!(
            fact(&s, FACT_FTS_INTEGRITY_AGE_SECS),
            (ceiling + 60).to_string()
        );
        assert_eq!(s.severity, Severity::Warning);
        assert!(note(&s).contains("clocks disagree"), "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_fresh_ok_verdict_is_info_with_measured_age_3656() {
        let server = MockServer::start().await;
        let body = health_doc(
            PROBE_OK,
            PROBE_OK,
            "reachable",
            VERDICT_OK,
            Some(rfc3339_secs_ago(NOW, 30)),
            INTERVAL,
        );
        let s = probe(&server, 200, body, NOW).await.section;
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(fact(&s, FACT_FTS_INTEGRITY_AGE_SECS), "30");
        assert_eq!(fact(&s, FACT_FTS_INTEGRITY_INTERVAL_SECS), "900");
        assert!(s.note.is_none(), "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_pending_and_disabled_are_distinct_and_not_healthy_3656() {
        for (verdict, interval, expect) in [
            (VERDICT_PENDING, INTERVAL, Severity::Info),
            (VERDICT_DISABLED, 0, Severity::Warning),
        ] {
            let server = MockServer::start().await;
            let body = health_doc(PROBE_OK, PROBE_OK, "reachable", verdict, None, interval);
            let s = probe(&server, 200, body, NOW).await.section;
            assert_eq!(s.severity, expect, "{verdict}: {s:?}");
            assert_eq!(fact(&s, FACT_FTS_INTEGRITY_STATUS), verdict);
            assert_eq!(fact(&s, FACT_FTS_INTEGRITY_CHECKED_AT), CHECKED_AT_NEVER);
            assert!(
                s.facts
                    .iter()
                    .all(|(k, _)| k != FACT_FTS_INTEGRITY_AGE_SECS),
                "no age may be invented when nothing was checked: {s:?}"
            );
            assert!(note(&s).contains("not asserted") || note(&s).contains("absent control"));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_connection_probe_error_is_critical_3656() {
        let server = MockServer::start().await;
        let body = health_doc(
            PROBE_ERROR,
            PROBE_ERROR,
            PROBE_ERROR,
            VERDICT_PENDING,
            None,
            INTERVAL,
        );
        let s = probe(&server, 503, body, NOW).await.section;
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(fact(&s, FACT_CHECK_CONNECTION), PROBE_ERROR);
        assert_eq!(fact(&s, FACT_CHECK_FTS_INDEX), PROBE_ERROR);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_unreachable_or_non_json_is_critical_3656() {
        // No mock: wiremock answers 404 with an empty body.
        let server = MockServer::start().await;
        let url = format!("{}{}", server.uri(), routes::HEALTH);
        let probe = tokio::task::spawn_blocking(move || {
            section_health_remote(&url, &RemoteAuth::default(), NOW)
        })
        .await
        .expect("join");
        assert_eq!(probe.section.severity, Severity::Critical);
        assert_eq!(fact(&probe.section, FACT_HTTP_STATUS), "404");
        assert_eq!(probe.federation_enabled, None);

        // Transport failure: bind an ephemeral port, release it, probe it.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("ephemeral port")
            .port();
        drop(server);
        let url = format!("http://127.0.0.1:{port}{}", routes::HEALTH);
        let probe = tokio::task::spawn_blocking(move || {
            section_health_remote(&url, &RemoteAuth::default(), NOW)
        })
        .await
        .expect("join");
        assert_eq!(probe.section.severity, Severity::Critical);
        assert!(note(&probe.section).contains("could not reach"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_missing_integrity_object_renders_not_in_response_3656() {
        let server = MockServer::start().await;
        let body = serde_json::json!({ HEALTH_KEY_STATUS: PROBE_OK });
        let s = probe(&server, 200, body, NOW).await.section;
        assert_eq!(fact(&s, FACT_FTS_INTEGRITY_STATUS), NOT_IN_RESPONSE);
        assert_eq!(fact(&s, FACT_CHECK_CONNECTION), NOT_IN_RESPONSE);
        assert_eq!(fact(&s, HEALTH_KEY_EMBEDDER_READY), NOT_IN_RESPONSE);
        assert!(note(&s).contains("not asserted"), "{s:?}");
    }

    #[test]
    fn metrics_sample_sums_labelled_series_and_skips_comments_3656() {
        let text = "# HELP ai_memory_x help\n\
                    # TYPE ai_memory_x counter\n\
                    ai_memory_x{reason=\"a}b\"} 2\n\
                    ai_memory_x{reason=\"c\\\"d\"} 3 1700000000\n\
                    ai_memory_y 4.5\n\
                    ai_memory_z NaN\n\
                    garbage line without value\n";
        let s = MetricsSample::parse(text);
        assert_eq!(s.get("ai_memory_x"), Some(5.0));
        assert_eq!(s.get("ai_memory_y"), Some(4.5));
        assert_eq!(s.get("ai_memory_z"), None, "NaN is not a measurement");
        assert_eq!(s.get("garbage"), None);
        assert_eq!(s.get("absent"), None);
        assert_eq!(fmt_sample(5.0), "5");
        assert_eq!(fmt_sample(4.5), "4.5");
    }

    #[test]
    fn metrics_names_the_doctor_parses_are_the_names_the_registry_renders_3656() {
        let rendered = crate::metrics::render();
        for name in [
            metric::HNSW_SIZE,
            metric::HNSW_EVICTIONS_TOTAL,
            metric::WEBHOOK_DISPATCHED_TOTAL,
            metric::WEBHOOK_FAILED_TOTAL,
            metric::SUBSCRIPTIONS_ACTIVE,
            metric::SUBSCRIPTION_DLQ_OVERFLOW_TOTAL,
            metric::FEDERATION_PUSH_DLQ_DEPTH,
            metric::FEDERATION_PARTIAL_QUORUM_TOTAL,
        ] {
            assert!(
                MetricsSample::parse(&rendered).get(name).is_some(),
                "{name} is not in the live scrape"
            );
        }
        // A labelled family renders nothing until it has a child. Touch one
        // (no increment — the same shape `fanout_dropped_counter_increments`
        // uses) so the registered name is provably the constant parsed here.
        crate::metrics::registry()
            .federation_fanout_dropped_total
            .with_label_values(&["shutdown"]);
        let rendered = crate::metrics::render();
        assert!(
            MetricsSample::parse(&rendered)
                .get(metric::FEDERATION_FANOUT_DROPPED_TOTAL)
                .is_some(),
            "{} is not in the live scrape",
            metric::FEDERATION_FANOUT_DROPPED_TOTAL
        );
    }

    fn scrape(pairs: &[(&str, &str)]) -> anyhow::Result<MetricsSample> {
        let text: String = pairs.iter().map(|(k, v)| format!("{k} {v}\n")).collect();
        Ok(MetricsSample::parse(&text))
    }

    #[test]
    fn index_evictions_from_stats_is_critical_and_hnsw_size_from_metrics_3656() {
        let stats = Ok(serde_json::json!({ FACT_INDEX_EVICTIONS_TOTAL: 3 }));
        let metrics = scrape(&[(metric::HNSW_SIZE, "1234")]);
        let s = section_index_remote(&stats, &metrics);
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(fact(&s, FACT_INDEX_EVICTIONS_TOTAL), "3");
        assert_eq!(fact(&s, FACT_HNSW_SIZE), "1234");
        assert!(note(&s).contains("evictions"));

        let stats = Ok(serde_json::json!({ FACT_INDEX_EVICTIONS_TOTAL: 0 }));
        let s = section_index_remote(&stats, &metrics);
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(fact(&s, FACT_INDEX_EVICTIONS_TOTAL), "0");
    }

    #[test]
    fn index_missing_series_never_renders_zero_3656() {
        let stats = Ok(serde_json::json!({}));
        let metrics = scrape(&[]);
        let s = section_index_remote(&stats, &metrics);
        assert_eq!(fact(&s, FACT_INDEX_EVICTIONS_TOTAL), NOT_IN_RESPONSE);
        assert_eq!(fact(&s, FACT_HNSW_SIZE), NOT_IN_RESPONSE);
        assert_eq!(s.severity, Severity::Info);

        let stats: anyhow::Result<Value> = Err(anyhow::anyhow!("HTTP 500 from stats"));
        let metrics: anyhow::Result<MetricsSample> = Err(anyhow::anyhow!("HTTP 500 from metrics"));
        let s = section_index_remote(&stats, &metrics);
        assert_eq!(s.severity, Severity::NotAvailable);
        assert!(fact(&s, FACT_STATS_ERROR).contains("500"));
        assert!(fact(&s, FACT_ERROR).contains("500"));
        assert!(s.facts.iter().all(|(_, v)| v != "0"), "{s:?}");
    }

    #[test]
    fn sync_dlq_depth_warns_and_unmeasured_signals_stay_unavailable_3656() {
        let metrics = scrape(&[
            (metric::FEDERATION_PUSH_DLQ_DEPTH, "2"),
            (metric::FEDERATION_PARTIAL_QUORUM_TOTAL, "0"),
        ]);
        let s = section_sync_remote(Some(true), &metrics);
        assert_eq!(s.severity, Severity::Warning);
        assert_eq!(fact(&s, FACT_PUSH_DLQ_DEPTH), "2");
        assert_eq!(fact(&s, FACT_PARTIAL_QUORUM_TOTAL), "0");
        assert_eq!(fact(&s, FACT_FANOUT_DROPPED_TOTAL), NOT_IN_RESPONSE);
        assert_eq!(fact(&s, FACT_MAX_SKEW_SECS), UNAVAILABLE_NO_REMOTE_SURFACE);
        assert_eq!(fact(&s, FACT_LAST_PUSH_AGE_SECS), UNAVAILABLE_PENDING_3654);
        assert_eq!(fact(&s, FACT_CONVERGENCE), CONVERGENCE_NOT_ASSERTED);
        assert!(note(&s).contains("quarantined"));

        // Quiet counters are Info WITH the not-asserted facts — never a
        // healthy claim.
        let metrics = scrape(&[
            (metric::FEDERATION_PUSH_DLQ_DEPTH, "0"),
            (metric::FEDERATION_FANOUT_DROPPED_TOTAL, "0"),
        ]);
        let s = section_sync_remote(Some(true), &metrics);
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(fact(&s, FACT_CONVERGENCE), CONVERGENCE_NOT_ASSERTED);

        let metrics = scrape(&[(metric::FEDERATION_FANOUT_DROPPED_TOTAL, "1")]);
        let s = section_sync_remote(None, &metrics);
        assert_eq!(s.severity, Severity::Warning);
        assert_eq!(fact(&s, HEALTH_KEY_FEDERATION_ENABLED), NOT_IN_RESPONSE);
        assert!(note(&s).contains("divergence"));
    }

    #[test]
    fn sync_federation_disabled_is_not_available_and_unreadable_metrics_assert_nothing_3656() {
        let metrics = scrape(&[(metric::FEDERATION_PUSH_DLQ_DEPTH, "9")]);
        let s = section_sync_remote(Some(false), &metrics);
        assert_eq!(s.severity, Severity::NotAvailable);
        assert!(
            s.facts.iter().all(|(k, _)| k != FACT_PUSH_DLQ_DEPTH),
            "{s:?}"
        );

        let metrics: anyhow::Result<MetricsSample> = Err(anyhow::anyhow!("HTTP 401"));
        let s = section_sync_remote(Some(true), &metrics);
        assert_eq!(s.severity, Severity::NotAvailable);
        assert!(fact(&s, FACT_ERROR).contains("401"));
        assert_eq!(fact(&s, FACT_CONVERGENCE), CONVERGENCE_NOT_ASSERTED);
    }

    #[test]
    fn webhook_success_rate_and_overflow_from_metrics_3656() {
        let metrics = scrape(&[
            (metric::SUBSCRIPTIONS_ACTIVE, "2"),
            (metric::WEBHOOK_DISPATCHED_TOTAL, "100"),
            (metric::WEBHOOK_FAILED_TOTAL, "10"),
            (metric::SUBSCRIPTION_DLQ_OVERFLOW_TOTAL, "0"),
        ]);
        let s = section_webhook_remote(&metrics);
        assert_eq!(s.severity, Severity::Warning);
        assert_eq!(fact(&s, FACT_SUBSCRIPTIONS_ACTIVE), "2");
        assert_eq!(fact(&s, FACT_DISPATCHED_TOTAL), "100");
        assert_eq!(fact(&s, FACT_FAILED_TOTAL), "10");
        assert_eq!(fact(&s, FACT_SUCCESS_RATE_PCT), "90.00");
        assert!(note(&s).contains("95%"), "{s:?}");

        let metrics = scrape(&[
            (metric::WEBHOOK_DISPATCHED_TOTAL, "100"),
            (metric::WEBHOOK_FAILED_TOTAL, "3"),
            (metric::SUBSCRIPTION_DLQ_OVERFLOW_TOTAL, "1"),
        ]);
        let s = section_webhook_remote(&metrics);
        assert_eq!(fact(&s, FACT_SUCCESS_RATE_PCT), "97.00");
        assert_eq!(s.severity, Severity::Warning, "overflow alone warns: {s:?}");
        assert!(note(&s).contains("depth cap"));

        let metrics = scrape(&[
            (metric::WEBHOOK_DISPATCHED_TOTAL, "0"),
            (metric::WEBHOOK_FAILED_TOTAL, "0"),
        ]);
        let s = section_webhook_remote(&metrics);
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(fact(&s, FACT_SUCCESS_RATE_PCT), MSG_NO_DELIVERIES_YET);
        assert_eq!(fact(&s, FACT_SUBSCRIPTIONS_ACTIVE), NOT_IN_RESPONSE);
    }

    #[test]
    fn webhook_unreadable_metrics_is_not_available_3656() {
        let metrics: anyhow::Result<MetricsSample> = Err(anyhow::anyhow!("connection refused"));
        let s = section_webhook_remote(&metrics);
        assert_eq!(s.severity, Severity::NotAvailable);
        assert!(fact(&s, FACT_ERROR).contains("refused"));
        assert!(
            s.facts.iter().all(|(k, _)| k != FACT_SUCCESS_RATE_PCT),
            "{s:?}"
        );
        assert!(note(&s).contains("unreadable"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_metrics_non_2xx_is_an_error_not_an_empty_scrape_3656() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(routes::METRICS))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let url = format!("{}{}", server.uri(), routes::METRICS);
        let r = tokio::task::spawn_blocking(move || fetch_metrics(&url, &RemoteAuth::default()))
            .await
            .expect("join");
        assert!(r.is_err(), "a 500 must not parse as an empty scrape");
    }
}
