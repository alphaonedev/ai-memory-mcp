// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `RecallRequest` — canonical Data Transfer Object for the recall pipeline.
//!
//! Wave-2 Tier-C2 (issue #967): the three recall surfaces (HTTP, MCP, CLI)
//! historically extracted ~17 scalars from their wire shapes and threaded
//! them as positional arguments through `recall_response` (HTTP) /
//! `handle_recall` (MCP) / `run_with_embedder` (CLI). Adding a new field
//! (Form 6 `kinds`, Form 4 `has_citations`, `session_id`, etc.) meant
//! editing four signatures.
//!
//! This module promotes the schemars-derived [`RecallRequest`] (originally
//! defined under `mcp::tools::recall` for D1.3 #984 schema generation)
//! into a canonical DTO every surface marshals into ONCE. Constructors
//! land per surface:
//!
//! * [`RecallRequest::from_mcp_params`] — accepts a `&serde_json::Value`
//!   params bag (the MCP `arguments` shape).
//! * [`RecallRequest::from_http_query`] — accepts a `&RecallQuery`
//!   (HTTP GET).
//! * [`RecallRequest::from_http_body`] — accepts a `&RecallBody`
//!   (HTTP POST).
//! * [`RecallRequest::from_cli_args`] — accepts a `&crate::cli::recall::RecallArgs`.
//!
//! The schemars derivation is preserved verbatim so D1.4 (#985) parity
//! tests in `mcp::tools::recall::d1_3_984_tests` keep matching the
//! legacy hand-coded schema byte-for-byte. The schema struct AND the
//! runtime DTO are now the same type — option (a) in the issue rubric.

use crate::models::MemoryKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// v0.7.0 #972 D1.3 (#984) — `kinds` filter shape for `memory_recall`.
///
/// The legacy hand-coded schema declares this field as a `oneOf` union
/// (array-of-strings OR a single CSV string); modelling it as an
/// `#[serde(untagged)]` enum replicates the wire shape exactly without
/// forcing callers to wrap their CSV in an array.
///
/// Originally lived under `mcp::tools::recall::KindsFilter`; promoted
/// here for the #967 canonical-DTO refactor. Re-exported from the
/// original location for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[allow(dead_code)]
#[serde(untagged)]
pub enum KindsFilter {
    /// Array of kind tokens, e.g. `["concept", "claim"]`.
    Array(Vec<String>),
    /// Comma-separated kinds string, e.g. `"concept,claim"`.
    Csv(String),
}

impl KindsFilter {
    /// Parse the filter into a vector of [`MemoryKind`] tokens. Returns
    /// `None` when the filter resolves to "no filter declared" — empty
    /// string, empty array, or the literal `"all"`.
    ///
    /// Returns `Some(vec![])` when the caller declared a filter
    /// (non-empty string or non-empty array) but every token was
    /// unknown (Cluster E audit COR-4 #767: an explicit zero-match
    /// filter must NOT silently collapse into "match all").
    #[must_use]
    pub fn parse(&self) -> Option<Vec<MemoryKind>> {
        match self {
            Self::Csv(s) => {
                if s.trim().eq_ignore_ascii_case("all") {
                    return None;
                }
                MemoryKind::parse_csv(s)
            }
            Self::Array(arr) => {
                if arr.is_empty() {
                    return None;
                }
                let mut out: Vec<MemoryKind> = Vec::new();
                for raw in arr {
                    if let Some(k) = MemoryKind::from_str(raw.trim())
                        && !out.contains(&k)
                    {
                        out.push(k);
                    }
                }
                Some(out)
            }
        }
    }
}

/// v0.7.0 #972 D1.3 (#984) / #967 — canonical recall-request DTO.
///
/// Marshalled once per surface (HTTP / MCP / CLI), then handed to the
/// downstream recall pipeline. Adding a new field (Form 6 `kinds`,
/// Form 4 `has_citations`, `confidence_tier`, etc.) lands in one place
/// instead of four positional-arg lists.
///
/// **Schemars contract.** Every doc-comment description and field
/// attribute is byte-equal to the legacy hand-coded entry in
/// [`crate::mcp::registry::tool_definitions`] — see the
/// `d1_3_984_tests::recall_parity_984` parity test which asserts the
/// derived schema matches byte-for-byte.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RecallRequest {
    /// What to recall
    pub context: String,

    /// Namespace filter
    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,

    /// Tag filter
    #[serde(default)]
    pub tags: Option<String>,

    /// RFC3339 lower bound on created_at
    #[serde(default)]
    pub since: Option<String>,

    /// RFC3339 upper bound on created_at
    #[serde(default)]
    pub until: Option<String>,

    #[serde(default)]
    #[schemars(description = "#151 scope-visibility agent.")]
    pub as_agent: Option<String>,

    /// P6/R1 cl100k content cap. 0=empty; top kept (meta.budget_overflow=true).
    #[serde(default)]
    pub budget_tokens: Option<i64>,

    /// Recent conversation tokens; biases query embedding 70/30 (v0.6.0.0).
    #[serde(default)]
    pub context_tokens: Option<Vec<String>>,

    /// Splice [agents.defaults.recall_scope]. explicit > scope > defaults.
    #[serde(default)]
    pub session_default: Option<bool>,

    #[serde(default)]
    #[schemars(description = "#518 session id; +0.05 rerank boost for in-session ring (cap 50).")]
    pub session_id: Option<String>,

    /// WT-1-E: include atomised sources alongside atoms.
    #[serde(default)]
    pub include_archived: Option<bool>,

    /// Form 4 (#757): require non-empty citations array.
    #[serde(default)]
    pub has_citations: Option<bool>,

    /// Form 4 (#757): restrict by source_uri prefix (e.g. 'doc:', 'uri:https://').
    #[serde(default)]
    pub source_uri_prefix: Option<String>,

    /// Form 6 (#759) kind filter. Array/CSV. OR within; AND across.
    #[serde(default)]
    pub kinds: Option<KindsFilter>,

    /// Gap 4 (#887) tier filter.
    #[serde(default)]
    pub confidence_tier: Option<String>,

    /// Gap 7 (#890): per-row provenance decoration.
    #[serde(default)]
    pub verbose_provenance: Option<bool>,

    /// Response format. toon_compact saves 79% vs json.
    #[serde(default)]
    pub format: Option<String>,
}

impl RecallRequest {
    /// MCP surface: marshal a `params` JSON bag (the `arguments` field
    /// of a `tools/call` request) into a typed [`RecallRequest`].
    ///
    /// Returns `Err` when `context` is missing — every other field is
    /// optional and defaults via `#[serde(default)]`. The legacy
    /// `handle_recall` body used `params["context"].as_str().ok_or(...)`
    /// to enforce the same invariant; this constructor preserves the
    /// exact error string for callers that match on it.
    ///
    /// On a deserialise failure (e.g. caller passes `limit: "ten"`),
    /// returns the serde error rendered as a string so the MCP
    /// dispatcher can return the corresponding `-32602 Invalid params`.
    ///
    /// # Errors
    /// Returns `Err` when:
    /// * `context` is missing or not a string ("context is required")
    /// * a typed field receives the wrong JSON shape
    ///
    /// **Saturation semantics.** Pre-#967 the legacy code used
    /// `params["limit"].as_u64()` + `usize::try_from(v).unwrap_or(usize::MAX)`,
    /// which silently saturated `u64::MAX` rather than erroring. The
    /// DTO's `limit: Option<i64>` would refuse to deserialize a value
    /// beyond `i64::MAX`, so the constructor clamps `limit` (and
    /// `budget_tokens`) values that exceed the signed range to
    /// `i64::MAX` BEFORE handing the bag to serde. This preserves the
    /// `limit_overflow_saturates` regression test contract.
    pub fn from_mcp_params(params: &Value) -> Result<Self, String> {
        // Pre-flight: legacy callers (and #984 parity tests) expect the
        // exact "context is required" error when the field is missing.
        // serde would surface "missing field `context`" instead; pin the
        // legacy wording here so the wire-level error envelope is stable.
        if params.get("context").and_then(Value::as_str).is_none() {
            return Err("context is required".to_string());
        }
        // Clamp `limit` / `budget_tokens` so an unsigned overflow value
        // (e.g. `u64::MAX` per `limit_overflow_saturates`) doesn't
        // collapse the constructor into a deserialise error. The recall
        // pipeline caps `limit` at `min(50)` downstream anyway, so the
        // precise value above `i64::MAX` is irrelevant to observable
        // behaviour — only that it doesn't crash.
        let mut owned = params.clone();
        if let Some(obj) = owned.as_object_mut() {
            for key in ["limit", "budget_tokens"] {
                if let Some(v) = obj.get(key)
                    && let Some(n) = v.as_u64()
                    && n > i64::MAX as u64
                {
                    obj.insert(key.to_string(), Value::from(i64::MAX));
                }
            }
        }
        serde_json::from_value::<Self>(owned).map_err(|e| e.to_string())
    }

    /// HTTP GET surface: marshal a [`crate::models::RecallQuery`] into
    /// the canonical DTO. `context` resolution honours the
    /// `context > query > q` precedence the HTTP handler enforces;
    /// callers must reject the empty result before recall.
    #[must_use]
    pub fn from_http_query(q: &crate::models::RecallQuery) -> Self {
        let context = q
            .context
            .as_deref()
            .or(q.query.as_deref())
            .or(q.q.as_deref())
            .unwrap_or("")
            .to_string();
        Self {
            context,
            namespace: q.namespace.clone(),
            limit: q.limit.and_then(|v| i64::try_from(v).ok()),
            tags: q.tags.clone(),
            since: q.since.clone(),
            until: q.until.clone(),
            as_agent: q.as_agent.clone(),
            budget_tokens: q.budget_tokens.and_then(|v| i64::try_from(v).ok()),
            context_tokens: None,
            session_default: q.session_default,
            session_id: q.session_id.clone(),
            // v0.7.0 #1098 — wired through from RecallQuery; pre-
            // #1098 these were hard-coded to `None` so HTTP callers
            // could not reach the toon_compact format selection,
            // verbose-provenance decoration, confidence-tier filter,
            // or include-archived widening even though MCP callers
            // could.
            include_archived: q.include_archived,
            has_citations: q.has_citations,
            source_uri_prefix: q.source_uri_prefix.clone(),
            kinds: q.kinds.as_deref().map(|s| KindsFilter::Csv(s.to_string())),
            confidence_tier: q.confidence_tier.clone(),
            verbose_provenance: q.verbose_provenance,
            format: q.format.clone(),
        }
    }

    /// HTTP POST surface: marshal a [`crate::models::RecallBody`] into
    /// the canonical DTO. `context` resolution honours the
    /// `context > query > q` precedence the HTTP handler enforces.
    #[must_use]
    pub fn from_http_body(body: &crate::models::RecallBody) -> Self {
        let kinds = body.kinds.as_ref().and_then(|raw| {
            if let Some(s) = raw.as_str() {
                Some(KindsFilter::Csv(s.to_string()))
            } else if let Some(arr) = raw.as_array() {
                let strs: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                Some(KindsFilter::Array(strs))
            } else {
                None
            }
        });
        Self {
            context: body.resolved_query(),
            namespace: body.namespace.clone(),
            limit: body.limit.and_then(|v| i64::try_from(v).ok()),
            tags: body.tags.clone(),
            since: body.since.clone(),
            until: body.until.clone(),
            as_agent: body.as_agent.clone(),
            budget_tokens: body.budget_tokens.and_then(|v| i64::try_from(v).ok()),
            context_tokens: None,
            session_default: body.session_default,
            session_id: body.session_id.clone(),
            // v0.7.0 #1098 — wired through from RecallBody; pre-#1098
            // these were hard-coded to `None`.
            include_archived: body.include_archived,
            has_citations: body.has_citations,
            source_uri_prefix: body.source_uri_prefix.clone(),
            kinds,
            confidence_tier: body.confidence_tier.clone(),
            verbose_provenance: body.verbose_provenance,
            format: body.format.clone(),
        }
    }

    /// CLI surface: marshal a [`crate::cli::recall::RecallArgs`] (clap-
    /// derived) into the canonical DTO.
    #[must_use]
    pub fn from_cli_args(args: &crate::cli::recall::RecallArgs) -> Self {
        Self {
            context: args.context.clone(),
            namespace: args.namespace.clone(),
            limit: i64::try_from(args.limit).ok(),
            tags: args.tags.clone(),
            since: args.since.clone(),
            until: args.until.clone(),
            as_agent: args.as_agent.clone(),
            budget_tokens: args.budget_tokens.and_then(|v| i64::try_from(v).ok()),
            context_tokens: args.context_tokens.clone(),
            session_default: Some(args.session_default),
            session_id: None,
            include_archived: Some(args.include_archived),
            has_citations: Some(args.has_citations),
            source_uri_prefix: args.source_uri_prefix.clone(),
            kinds: args
                .kind
                .as_deref()
                .map(|s| KindsFilter::Csv(s.to_string())),
            confidence_tier: None,
            verbose_provenance: None,
            format: None,
        }
    }

    /// Resolved limit clamped to `usize`. The recall pipeline caps the
    /// returned set at `min(50)` downstream; this constructor just
    /// converts the wire `Option<i64>` into a usable size with a
    /// default of 10 when the caller omitted the field.
    #[must_use]
    pub fn resolved_limit(&self) -> usize {
        match self.limit {
            Some(v) if v > 0 => usize::try_from(v).unwrap_or(usize::MAX),
            _ => 10,
        }
    }

    /// Resolved budget-tokens limit clamped to `usize`. `None` when the
    /// caller did not request a budget cap; `Some(0)` is preserved per
    /// the P6/R1 semantics (zero is a legitimate "return nothing"
    /// request distinct from "no budget set").
    #[must_use]
    pub fn resolved_budget_tokens(&self) -> Option<usize> {
        self.budget_tokens.and_then(|v| {
            if v < 0 {
                None
            } else {
                Some(usize::try_from(v).unwrap_or(usize::MAX))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_mcp_params_requires_context() {
        let err = RecallRequest::from_mcp_params(&json!({})).unwrap_err();
        assert!(
            err.contains("context"),
            "missing context must surface 'context' in the error: {err}"
        );
    }

    #[test]
    fn from_mcp_params_happy_path_minimal() {
        let req = RecallRequest::from_mcp_params(&json!({"context": "hello"})).unwrap();
        assert_eq!(req.context, "hello");
        assert!(req.namespace.is_none());
        assert!(req.limit.is_none());
    }

    #[test]
    fn from_mcp_params_full_field_set() {
        let req = RecallRequest::from_mcp_params(&json!({
            "context": "q",
            "namespace": "ns",
            "limit": 25,
            "tags": "a,b",
            "since": "2026-01-01T00:00:00Z",
            "until": "2026-12-31T00:00:00Z",
            "as_agent": "ai:viewer",
            "budget_tokens": 100,
            "context_tokens": ["alpha", "beta"],
            "session_default": true,
            "session_id": "sess-1",
            "include_archived": true,
            "has_citations": true,
            "source_uri_prefix": "doc:",
            "kinds": "concept,claim",
            "confidence_tier": "confirmed",
            "verbose_provenance": false,
            "format": "toon_compact"
        }))
        .unwrap();
        assert_eq!(req.context, "q");
        assert_eq!(req.namespace.as_deref(), Some("ns"));
        assert_eq!(req.limit, Some(25));
        assert_eq!(req.tags.as_deref(), Some("a,b"));
        assert_eq!(req.budget_tokens, Some(100));
        assert_eq!(
            req.context_tokens.as_deref(),
            Some(&["alpha".to_string(), "beta".to_string()][..])
        );
        assert_eq!(req.session_id.as_deref(), Some("sess-1"));
        assert!(matches!(req.kinds, Some(KindsFilter::Csv(ref s)) if s == "concept,claim"));
        assert_eq!(req.confidence_tier.as_deref(), Some("confirmed"));
        assert_eq!(req.verbose_provenance, Some(false));
    }

    #[test]
    fn from_mcp_params_limit_u64_max_saturates() {
        // Pre-#967 the legacy code used `params["limit"].as_u64()` +
        // `usize::try_from(v).unwrap_or(usize::MAX)`, which silently
        // saturated `u64::MAX`. The DTO field is `Option<i64>`, so
        // the constructor must clamp `u64::MAX` to `i64::MAX` before
        // serde-deserialising; otherwise the existing
        // `mcp::recall::tests::limit_overflow_saturates` regression
        // test would surface a `Result::Err` instead of a successful
        // recall response.
        let req = RecallRequest::from_mcp_params(&json!({
            "context": "q",
            "limit": u64::MAX,
        }))
        .expect("u64::MAX limit must saturate, not error");
        assert_eq!(req.limit, Some(i64::MAX));
    }

    #[test]
    fn from_mcp_params_budget_tokens_u64_max_saturates() {
        // Same saturation contract for budget_tokens.
        let req = RecallRequest::from_mcp_params(&json!({
            "context": "q",
            "budget_tokens": u64::MAX,
        }))
        .expect("u64::MAX budget_tokens must saturate, not error");
        assert_eq!(req.budget_tokens, Some(i64::MAX));
    }

    #[test]
    fn from_mcp_params_unknown_field_tolerated_at_runtime() {
        // v0.7.0 #1052 (Agent-4 F2) — pre-#1052 the struct carried
        // `#[schemars(deny_unknown_fields)]` so the WIRE schema
        // advertised `additionalProperties: false`, but
        // `#[serde(deny_unknown_fields)]` was intentionally omitted so
        // the RUNTIME silently tolerated unknowns. That asymmetry was
        // the bug: clients OBEYING the wire schema rejected inputs the
        // server happily accepted, and clients sending typos (e.g.
        // `"namespce"` for `"namespace"`) had them silently dropped
        // (no -32602) and observed surprising "no filter applied"
        // behaviour.
        //
        // The #1052 fix removes `schemars(deny_unknown_fields)` from
        // every tool-request struct so the wire schema becomes
        // truthful (no `additionalProperties: false` claim). The
        // runtime continues to tolerate unknowns — wider compat for
        // v0.6.x clients with newer field sets — but the schema no
        // longer lies about it. The corollary contract is pinned by
        // `tests/mcp_input_schema_no_false_strict_1052.rs`: the
        // canonical `tool_definitions()` payload must NOT advertise
        // `additionalProperties: false` on any tool's inputSchema.
        //
        // Pinned here so a future re-introduction of the attribute is
        // a visible, intentional change.
        let req = RecallRequest::from_mcp_params(&json!({
            "context": "q",
            "completely_unknown_field": true
        }))
        .expect("unknown fields are tolerated at runtime (post-#1052 contract is wire-truthful)");
        assert_eq!(req.context, "q");
    }

    #[test]
    fn from_mcp_params_kinds_array_shape() {
        let req = RecallRequest::from_mcp_params(&json!({
            "context": "q",
            "kinds": ["concept", "claim"]
        }))
        .unwrap();
        let kinds = req.kinds.expect("kinds present");
        match &kinds {
            KindsFilter::Array(v) => {
                assert_eq!(v, &vec!["concept".to_string(), "claim".to_string()]);
            }
            _ => panic!("expected Array variant: {kinds:?}"),
        }
        let parsed = kinds.parse().expect("parses to Some");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn kinds_filter_all_treated_as_no_filter() {
        let csv = KindsFilter::Csv("all".to_string());
        assert!(csv.parse().is_none());
        let csv_upper = KindsFilter::Csv("ALL".to_string());
        assert!(csv_upper.parse().is_none());
    }

    #[test]
    fn kinds_filter_empty_array_is_no_filter() {
        let arr = KindsFilter::Array(vec![]);
        assert!(arr.parse().is_none());
    }

    #[test]
    fn kinds_filter_typo_array_returns_empty_some_cor4() {
        // Cluster E audit COR-4 #767: declared filter with only-unknown
        // tokens must NOT collapse into None ("match all"). It returns
        // Some(vec![]) so the downstream filter applies and matches
        // zero rows.
        let arr = KindsFilter::Array(vec!["reflektion".to_string()]);
        let parsed = arr.parse().expect("declared filter returns Some");
        assert!(parsed.is_empty(), "typo'd kinds must return empty Some");
    }

    #[test]
    fn resolved_limit_default_is_ten() {
        let req = RecallRequest {
            context: "q".to_string(),
            ..Default::default()
        };
        assert_eq!(req.resolved_limit(), 10);
    }

    #[test]
    fn resolved_limit_uses_explicit_value() {
        let req = RecallRequest {
            context: "q".to_string(),
            limit: Some(25),
            ..Default::default()
        };
        assert_eq!(req.resolved_limit(), 25);
    }

    #[test]
    fn resolved_budget_tokens_zero_preserved() {
        // P6/R1 — `budget_tokens: 0` is a legitimate request meaning
        // "return zero memories", distinct from `None` ("no cap").
        let req = RecallRequest {
            context: "q".to_string(),
            budget_tokens: Some(0),
            ..Default::default()
        };
        assert_eq!(req.resolved_budget_tokens(), Some(0));
    }

    #[test]
    fn resolved_budget_tokens_none_when_negative() {
        let req = RecallRequest {
            context: "q".to_string(),
            budget_tokens: Some(-1),
            ..Default::default()
        };
        assert!(req.resolved_budget_tokens().is_none());
    }

    #[test]
    fn from_cli_args_round_trips_all_fields() {
        // Pin the CLI surface: clap-derived `RecallArgs` collapses
        // into the canonical DTO via `from_cli_args`. Adding a new
        // CLI flag means extending this round-trip.
        let cli_args = crate::cli::recall::RecallArgs {
            context: "hello".to_string(),
            namespace: Some("ns".to_string()),
            limit: 7,
            tags: Some("rust".to_string()),
            since: Some("2026-01-01T00:00:00Z".to_string()),
            until: Some("2026-12-31T00:00:00Z".to_string()),
            tier: Some("keyword".to_string()),
            as_agent: Some("ai:viewer".to_string()),
            budget_tokens: Some(50),
            context_tokens: Some(vec!["alpha".to_string()]),
            session_default: true,
            include_archived: true,
            has_citations: true,
            source_uri_prefix: Some("doc:".to_string()),
            kind: Some("concept,claim".to_string()),
        };
        let req = RecallRequest::from_cli_args(&cli_args);
        assert_eq!(req.context, "hello");
        assert_eq!(req.namespace.as_deref(), Some("ns"));
        assert_eq!(req.limit, Some(7));
        assert_eq!(req.tags.as_deref(), Some("rust"));
        assert_eq!(req.budget_tokens, Some(50));
        assert_eq!(req.session_default, Some(true));
        assert_eq!(req.include_archived, Some(true));
        assert_eq!(req.has_citations, Some(true));
        assert_eq!(req.source_uri_prefix.as_deref(), Some("doc:"));
        assert!(matches!(req.kinds, Some(KindsFilter::Csv(ref s)) if s == "concept,claim"));
        // CLI `tier` and `format` have no DTO field — they're CLI-only
        // knobs that drive embedder construction / output formatting,
        // not wire-level filters.
    }

    #[test]
    fn from_http_query_minimal() {
        let q = crate::models::RecallQuery {
            context: Some("hello".to_string()),
            query: None,
            q: None,
            namespace: None,
            limit: Some(15),
            tags: None,
            since: None,
            until: None,
            as_agent: None,
            budget_tokens: None,
            session_default: None,
            has_citations: None,
            source_uri_prefix: None,
            kinds: None,
            session_id: None,
        };
        let req = RecallRequest::from_http_query(&q);
        assert_eq!(req.context, "hello");
        assert_eq!(req.limit, Some(15));
    }

    #[test]
    fn from_http_query_aliases() {
        // `q` → `context` fallback honoured.
        let q = crate::models::RecallQuery {
            context: None,
            query: None,
            q: Some("via-q".to_string()),
            namespace: None,
            limit: None,
            tags: None,
            since: None,
            until: None,
            as_agent: None,
            budget_tokens: None,
            session_default: None,
            has_citations: None,
            source_uri_prefix: None,
            kinds: None,
            session_id: None,
        };
        let req = RecallRequest::from_http_query(&q);
        assert_eq!(req.context, "via-q");
    }

    #[test]
    fn round_trip_serialize_deserialize() {
        let req = RecallRequest {
            context: "q".to_string(),
            namespace: Some("ns".to_string()),
            limit: Some(5),
            kinds: Some(KindsFilter::Csv("concept".to_string())),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RecallRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.context, req.context);
        assert_eq!(back.namespace, req.namespace);
        assert_eq!(back.limit, req.limit);
    }
}
