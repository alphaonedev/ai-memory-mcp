// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8760 — a K9 `[[permissions.rules]]` Deny must apply to EVERY agent id
//! form the validator accepts.
//!
//! Defect class: a rule's `agent_pattern` was matched with the namespace
//! glob, whose `*` stops at `/`, so a Deny written as `*` (the default) or
//! `ai:*` refused `ai:plain` but let `ai:team/a` and SPIFFE ids through.
//! Mixed case was a second escape (`AI:PLAIN` against a Deny on
//! `ai:plain`).
//!
//! Invariant pinned here, for every accepted id form (enumerated from the
//! validator alphabet `[A-Za-z0-9_\-:@./]`, 1..=128 bytes, no `..`, no
//! leading `/`):
//!
//! * a Deny / Ask rule whose pattern is derived from the id (exact,
//!   wildcard, prefix) matches the id in any letter case;
//! * an Allow rule matches only in exact case;
//! * an id or a pattern the matcher cannot classify matches every Deny /
//!   Ask rule and no Allow rule (fail-closed);
//! * the result is the same through `Permissions::evaluate_with`, the MCP
//!   stdio `memory_store` tool and the HTTP `POST /api/v1/capture_turn`
//!   route on SQLite and on PostgreSQL (the PG cell is `#[ignore]`d and
//!   runs with `--include-ignored` against a minted database).

#![allow(clippy::doc_markdown, clippy::expect_used, clippy::too_many_lines)]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ai_memory::config::{FeatureTier, PermissionsMode, ResolvedScoring, ResolvedTtl};
use ai_memory::governance::{
    Decision, Op, PermissionContext, PermissionRule, Permissions, RuleDecision,
    clear_active_permission_rules_for_test, set_active_permission_rules,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

#[path = "common/child_stdin_report.rs"]
mod child_stdin_report;
mod common;
#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

/// Number of generated ids drawn from the validator alphabet.
const GENERATED_ID_CORPUS: usize = 2_048;
/// Upper bound on draws while filling the corpus (a draw the shape
/// validator rejects, e.g. one containing `..`, is discarded).
const GENERATED_ID_MAX_DRAWS: usize = GENERATED_ID_CORPUS * 8;
/// Deterministic seed so a red cell reproduces byte for byte.
const GENERATED_ID_SEED: u64 = 0x8760_8760_8760_8760;
/// The validator's documented maximum agent id length.
const AGENT_ID_MAX_BYTES: usize = 128;
/// Validator alphabet (`src/validate.rs::validate_agent_id_shape`).
const AGENT_ID_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-:@./";
/// Rules in the bound test (the matcher scans every rule).
const BOUND_RULE_COUNT: usize = 100_000;
/// Wall-clock ceiling for one evaluation over `BOUND_RULE_COUNT` rules
/// (debug build, loaded CI host).
const BOUND_WALL_CLOCK_CEILING: Duration = Duration::from_secs(20);
/// Longest agent pattern the matcher classifies (mirrors
/// `governance::agent_match::MAX_AGENT_PATTERN_LEN`).
const AGENT_PATTERN_MAX_BYTES: usize = 1_024;
/// Evaluations of the worst-case long pattern against the longest id.
const LONG_PATTERN_ROUNDS: usize = 1_000;
/// Prefix length used by the prefix-pattern column.
const PREFIX_PATTERN_BYTES: usize = 3;
/// Enforce-mode prefix of an escalated Ask (`governance::evaluate_with`).
const ASK_ESCALATED: &str = "permission ask escalated to deny under enforce mode: ";

/// Serialises the process-wide permission registry and the env mutation.
fn registry_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Every id form the validator accepts, by name.
fn id_forms() -> Vec<(&'static str, String)> {
    let mut max_len = String::from("ai:");
    while max_len.len() < AGENT_ID_MAX_BYTES {
        max_len.push(if max_len.len() % 2 == 0 { '/' } else { 'q' });
    }
    max_len.truncate(AGENT_ID_MAX_BYTES);
    vec![
        ("plain", "ai:plain".to_string()),
        ("bare", "alice".to_string()),
        ("slash", "ai:team/a".to_string()),
        ("nested_slash", "ai:team/a/b/c".to_string()),
        ("trailing_slash", "ai:team/".to_string()),
        ("double_slash", "ai:a//b".to_string()),
        ("spiffe", "spiffe://example.org/ns/a/sa/b".to_string()),
        ("email", "alice@example.org".to_string()),
        ("at_scoped", "ai:alice@team/x".to_string()),
        ("dotted", "ai:a.b.c".to_string()),
        ("underscore_hyphen", "ai:a_b-c".to_string()),
        ("colon_heavy", "urn:x:y:z".to_string()),
        ("mixed_case", "AI:Team/Mixed".to_string()),
        ("digits", "0123456789".to_string()),
        ("single_byte", "q".to_string()),
        ("max_len", max_len),
    ]
}

/// Ids the shape validator REJECTS; the matcher must fail closed on them.
fn unclassifiable_ids() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("space", "ai:a b".to_string()),
        ("percent", "ai:%2Fteam".to_string()),
        ("non_ascii", "ai:\u{e9}quipe".to_string()),
        ("newline", "ai:a\nb".to_string()),
        ("nul", "ai:a\0b".to_string()),
        ("star", "ai:*".to_string()),
        ("dotdot", "ai:../x".to_string()),
        ("leading_slash", "/ai:x".to_string()),
        ("too_long", "q".repeat(AGENT_ID_MAX_BYTES + 1)),
    ]
}

/// Patterns the matcher cannot classify; a Deny with one must still apply.
fn unclassifiable_patterns() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("percent", "ai:%".to_string()),
        ("space", "ai: *".to_string()),
        ("bracket", "ai:[ab]*".to_string()),
        ("question", "ai:?".to_string()),
        ("non_ascii", "ai:\u{e9}*".to_string()),
        ("too_long", "*".repeat(AGENT_PATTERN_MAX_BYTES + 1)),
    ]
}

#[derive(Clone, Copy, Debug)]
enum PatternKind {
    Exact,
    Wildcard,
    Prefix,
}

const PATTERN_KINDS: [PatternKind; 3] = [
    PatternKind::Exact,
    PatternKind::Wildcard,
    PatternKind::Prefix,
];

impl PatternKind {
    fn label(self) -> &'static str {
        match self {
            PatternKind::Exact => "exact",
            PatternKind::Wildcard => "wildcard",
            PatternKind::Prefix => "prefix",
        }
    }

    fn pattern_for(self, rule_id: &str) -> String {
        match self {
            PatternKind::Exact => rule_id.to_string(),
            PatternKind::Wildcard => "*".to_string(),
            PatternKind::Prefix => {
                let cut = rule_id.len().min(PREFIX_PATTERN_BYTES);
                format!("{}*", rule_id.get(..cut).expect("ASCII id"))
            }
        }
    }
}

/// What a surface must return for one cell.
#[derive(Clone, Debug, PartialEq)]
enum Expect {
    /// Refused with exactly this K9 reason.
    Denied(String),
    Allowed,
}

/// One (namespace, expected outcome) cell of the matrix.
#[derive(Clone, Debug)]
struct Cell {
    label: String,
    namespace: String,
    expect: Expect,
}

fn rule(ns: &str, agent: &str, decision: RuleDecision, reason: &str) -> PermissionRule {
    PermissionRule {
        namespace_pattern: ns.to_string(),
        op: Op::MemoryStore.as_str().to_string(),
        agent_pattern: agent.to_string(),
        decision,
        reason: Some(reason.to_string()),
    }
}

fn swap_ascii_case(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Rules written for `rule_id`, and the cells a caller named `caller`
/// must see. `tag` keeps namespaces unique per row.
fn matrix(tag: &str, rule_id: &str, caller: &str) -> (Vec<PermissionRule>, Vec<Cell>) {
    let mut rules = Vec::new();
    let mut cells = Vec::new();
    for kind in PATTERN_KINDS {
        let pattern = kind.pattern_for(rule_id);
        let k = kind.label();

        let deny_reason = format!("deny8760-{tag}-{k}");
        let deny_ns = format!("g8760-{tag}-deny-{k}");
        rules.push(rule(
            &format!("{deny_ns}/*"),
            &pattern,
            RuleDecision::Deny,
            &deny_reason,
        ));
        cells.push(Cell {
            label: format!("{tag} deny {k} pattern={pattern:?} caller={caller:?}"),
            namespace: format!("{deny_ns}/n"),
            expect: Expect::Denied(deny_reason),
        });

        let ask_reason = format!("ask8760-{tag}-{k}");
        let allow_ns = format!("g8760-{tag}-allow-{k}");
        rules.push(rule(
            &format!("{allow_ns}/*"),
            &pattern,
            RuleDecision::Allow,
            "allow8760",
        ));
        rules.push(rule(
            &format!("{allow_ns}/*"),
            "*",
            RuleDecision::Ask,
            &ask_reason,
        ));
        let allow_matches = match kind {
            PatternKind::Exact => caller == rule_id,
            PatternKind::Wildcard => true,
            PatternKind::Prefix => caller.starts_with(pattern.trim_end_matches('*')),
        };
        cells.push(Cell {
            label: format!("{tag} allow {k} pattern={pattern:?} caller={caller:?}"),
            namespace: format!("{allow_ns}/n"),
            expect: if allow_matches {
                Expect::Allowed
            } else {
                Expect::Denied(format!("{ASK_ESCALATED}{ask_reason}"))
            },
        });
    }
    (rules, cells)
}

fn evaluate(rules: &[PermissionRule], namespace: &str, caller: &str) -> Decision {
    let ctx = PermissionContext {
        op: Op::MemoryStore,
        namespace: namespace.to_string(),
        agent_id: caller.to_string(),
        payload: json!({}),
    };
    Permissions::evaluate_with(&ctx, &[], rules, PermissionsMode::Enforce)
}

fn assert_cell(rules: &[PermissionRule], cell: &Cell, caller: &str) {
    let got = evaluate(rules, &cell.namespace, caller);
    let want = match &cell.expect {
        Expect::Denied(reason) => Decision::Deny(reason.clone()),
        Expect::Allowed => Decision::Allow,
    };
    assert_eq!(got, want, "#8760 evaluator cell {}", cell.label);
}

// ---------------------------------------------------------------------------
// Evaluator matrix (the one matcher, no surface in between)
// ---------------------------------------------------------------------------

#[test]
fn every_id_form_by_every_pattern_kind_by_decision() {
    for (name, id) in id_forms() {
        ai_memory::validate::validate_agent_id_shape(&id)
            .unwrap_or_else(|e| panic!("fixture {name} must be a valid id: {e}"));
        let (rules, cells) = matrix(name, &id, &id);
        for cell in &cells {
            assert_cell(&rules, cell, &id);
        }
    }
}

#[test]
fn mixed_case_caller_cannot_escape_a_deny_and_gains_no_allow() {
    for (name, id) in id_forms() {
        let caller = swap_ascii_case(&id);
        if caller == id {
            continue;
        }
        let (rules, cells) = matrix(&format!("{name}-case"), &id, &caller);
        for cell in &cells {
            assert_cell(&rules, cell, &caller);
        }
    }
}

/// xorshift64*; deterministic and dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound64 = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.next() % bound64).expect("index fits usize")
    }
}

fn generated_ids() -> Vec<String> {
    let mut rng = Rng(GENERATED_ID_SEED);
    let mut out = Vec::with_capacity(GENERATED_ID_CORPUS);
    let mut draws = 0usize;
    while out.len() < GENERATED_ID_CORPUS && draws < GENERATED_ID_MAX_DRAWS {
        draws += 1;
        let len = 1 + rng.below(AGENT_ID_MAX_BYTES);
        let id: String = (0..len)
            .map(|_| char::from(AGENT_ID_ALPHABET[rng.below(AGENT_ID_ALPHABET.len())]))
            .collect();
        if ai_memory::validate::validate_agent_id_shape(&id).is_ok() {
            out.push(id);
        }
    }
    assert!(
        out.len() == GENERATED_ID_CORPUS,
        "corpus underfilled after {draws} draws"
    );
    out
}

#[test]
fn generated_ids_from_the_validator_alphabet_never_escape_a_deny() {
    for (i, id) in generated_ids().iter().enumerate() {
        let tag = format!("gen{i}");
        let (rules, cells) = matrix(&tag, id, id);
        for cell in &cells {
            assert_cell(&rules, cell, id);
        }
        let caller = swap_ascii_case(id);
        let (rules, cells) = matrix(&format!("{tag}-case"), id, &caller);
        for cell in &cells {
            assert_cell(&rules, cell, &caller);
        }
    }
}

// ---------------------------------------------------------------------------
// Fail-closed on what the matcher cannot classify
// ---------------------------------------------------------------------------

#[test]
fn unclassifiable_id_matches_every_deny_and_no_allow() {
    for (name, id) in unclassifiable_ids() {
        let rules = vec![
            rule(
                "u8760-deny/*",
                "zz-never-matches",
                RuleDecision::Deny,
                "deny8760-u",
            ),
            rule("u8760-allow/*", "*", RuleDecision::Allow, "allow8760"),
            rule(
                "u8760-allow/*",
                "zz-never-matches",
                RuleDecision::Ask,
                "ask8760-u",
            ),
        ];
        assert_eq!(
            evaluate(&rules, "u8760-deny/n", &id),
            Decision::Deny("deny8760-u".to_string()),
            "#8760 unclassifiable id {name} must match a Deny"
        );
        assert_eq!(
            evaluate(&rules, "u8760-allow/n", &id),
            Decision::Deny(format!("{ASK_ESCALATED}ask8760-u")),
            "#8760 unclassifiable id {name} must not match an Allow"
        );
    }
}

#[test]
fn unclassifiable_pattern_matches_as_deny_and_never_as_allow() {
    for (name, pattern) in unclassifiable_patterns() {
        let rules = vec![
            rule("p8760-deny/*", &pattern, RuleDecision::Deny, "deny8760-p"),
            rule("p8760-allow/*", &pattern, RuleDecision::Allow, "allow8760"),
            rule("p8760-allow/*", "*", RuleDecision::Ask, "ask8760-p"),
        ];
        assert_eq!(
            evaluate(&rules, "p8760-deny/n", "ai:plain"),
            Decision::Deny("deny8760-p".to_string()),
            "#8760 unclassifiable pattern {name} must still deny"
        );
        assert_eq!(
            evaluate(&rules, "p8760-allow/n", "ai:plain"),
            Decision::Deny(format!("{ASK_ESCALATED}ask8760-p")),
            "#8760 unclassifiable pattern {name} must not allow"
        );
    }
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[test]
fn one_hundred_thousand_rules_evaluate_under_the_ceiling() {
    let mut rules: Vec<PermissionRule> = (0..BOUND_RULE_COUNT)
        .map(|i| rule("b8760/*", &format!("zz{i}*"), RuleDecision::Deny, "never"))
        .collect();
    rules.push(rule(
        "b8760/*",
        "ai:*",
        RuleDecision::Deny,
        "deny8760-bound",
    ));
    let caller = "ai:team/a/b/c";
    let started = Instant::now();
    let got = evaluate(&rules, "b8760/n", caller);
    let elapsed = started.elapsed();
    assert_eq!(got, Decision::Deny("deny8760-bound".to_string()));
    assert!(
        elapsed < BOUND_WALL_CLOCK_CEILING,
        "#8760 {BOUND_RULE_COUNT} rules took {elapsed:?} (ceiling {BOUND_WALL_CLOCK_CEILING:?})"
    );
}

#[test]
fn worst_case_long_pattern_against_the_longest_id_is_bounded() {
    // `*a*a*a…` against `aaa…ab`: every star stays live, the classic
    // backtracking blow-up. The matcher is a DP, so this is
    // `O(|pattern| * |id|)` per evaluation.
    let pattern: String = "*a".repeat(AGENT_PATTERN_MAX_BYTES / 2);
    assert!(pattern.len() <= AGENT_PATTERN_MAX_BYTES);
    let mut id = "a".repeat(AGENT_ID_MAX_BYTES - 1);
    id.push('b');
    let rules = vec![
        rule("w8760/*", &pattern, RuleDecision::Deny, "never"),
        rule("w8760/*", "*", RuleDecision::Deny, "deny8760-long"),
    ];
    let started = Instant::now();
    for _ in 0..LONG_PATTERN_ROUNDS {
        assert_eq!(
            evaluate(&rules, "w8760/n", &id),
            Decision::Deny("deny8760-long".to_string())
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < BOUND_WALL_CLOCK_CEILING,
        "#8760 {LONG_PATTERN_ROUNDS} long-pattern rounds took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// SSE approval visibility (the second agent-pattern match site)
// ---------------------------------------------------------------------------

#[test]
fn sse_visibility_uses_the_same_agent_matcher() {
    let _g = registry_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_active_permission_rules_for_test();
    set_active_permission_rules(vec![PermissionRule {
        namespace_pattern: "sse8760/*".to_string(),
        op: Op::MemoryStore.as_str().to_string(),
        agent_pattern: "ai:*".to_string(),
        decision: RuleDecision::Allow,
        reason: None,
    }]);
    let event = ai_memory::approvals::ApprovalEvent::ApprovalRequested {
        pending_id: "p8760".to_string(),
        action_type: "store".to_string(),
        namespace: "sse8760/x".to_string(),
        requested_by: "ai:someone-else".to_string(),
        requested_at: "2026-11-10T00:00:00Z".to_string(),
    };
    let slash_visible = ai_memory::handlers::approvals::sse_event_visible_to("ai:team/a", &event);
    let unclassifiable_visible =
        ai_memory::handlers::approvals::sse_event_visible_to("ai:a b", &event);
    clear_active_permission_rules_for_test();
    assert!(slash_visible, "#8760 Allow `ai:*` must cover `ai:team/a`");
    assert!(
        !unclassifiable_visible,
        "#8760 an unclassifiable subscriber must not match an Allow"
    );
}

// ---------------------------------------------------------------------------
// MCP stdio surface (SQLite; the MCP server has no PostgreSQL mode)
// ---------------------------------------------------------------------------

fn toml_str(s: &str) -> String {
    serde_json::to_string(s).expect("toml basic string")
}

fn rules_toml(rules: &[PermissionRule]) -> String {
    let mut out = String::from("tier = \"keyword\"\n\n[permissions]\nmode = \"enforce\"\n\n");
    for r in rules {
        let decision = match r.decision {
            RuleDecision::Allow => "allow",
            RuleDecision::Deny => "deny",
            RuleDecision::Ask => "ask",
        };
        out.push_str("[[permissions.rules]]\n");
        out.push_str(&format!(
            "namespace_pattern = {}\n",
            toml_str(&r.namespace_pattern)
        ));
        out.push_str(&format!("op = {}\n", toml_str(&r.op)));
        out.push_str(&format!("agent_pattern = {}\n", toml_str(&r.agent_pattern)));
        out.push_str(&format!("decision = \"{decision}\"\n"));
        if let Some(reason) = &r.reason {
            out.push_str(&format!("reason = {}\n\n", toml_str(reason)));
        }
    }
    out
}

fn mcp_rows(rule_id: &str, caller: &str, tag: &str) {
    let (rules, cells) = matrix(tag, rule_id, caller);
    let fixture = mcp_stdio_child::Fixture::new();
    // XDG path (Linux: `dirs::config_dir()` honours `XDG_CONFIG_HOME`) and the
    // documented `$HOME/.config` path (macOS, #3329), so the child reads the
    // rules on either host.
    let body = rules_toml(&rules);
    for config_dir in [
        fixture.dir.path().join("config").join("ai-memory"),
        fixture
            .dir
            .path()
            .join("home")
            .join(".config")
            .join("ai-memory"),
    ] {
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::write(config_dir.join("config.toml"), &body).expect("config.toml");
    }
    let mut mcp = mcp_stdio_child::Mcp::start_with_config(&fixture, Some(caller));
    for (i, cell) in cells.iter().enumerate() {
        let result = mcp.call(
            "memory_store",
            &json!({
                "title": format!("t8760 {tag} {i}"),
                "content": "governance id-form probe",
                "namespace": cell.namespace,
                "format": "json",
            }),
        );
        let text = mcp_stdio_child::Mcp::text(&result).to_string();
        match &cell.expect {
            Expect::Denied(reason) => {
                assert_eq!(
                    result["isError"], true,
                    "#8760 MCP {}: {result}",
                    cell.label
                );
                assert_eq!(
                    text,
                    format!("store denied by permission rule: {reason}"),
                    "#8760 MCP refusal text {}",
                    cell.label
                );
            }
            Expect::Allowed => {
                assert_ne!(
                    result["isError"], true,
                    "#8760 MCP {}: {result}",
                    cell.label
                );
            }
        }
    }
}

#[test]
fn mcp_stdio_store_refuses_every_id_form() {
    for (name, id) in id_forms() {
        if ai_memory::validate::validate_agent_id(&id).is_err() {
            continue;
        }
        mcp_rows(&id, &id, &format!("mcp-{name}"));
        let swapped = swap_ascii_case(&id);
        if swapped != id && ai_memory::validate::validate_agent_id(&swapped).is_ok() {
            mcp_rows(&id, &swapped, &format!("mcp-{name}-case"));
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP surface, SQLite and PostgreSQL routers
// ---------------------------------------------------------------------------

fn app_state(
    db: Db,
    store: Arc<dyn ai_memory::store::MemoryStore>,
    backend: StorageBackend,
) -> AppState {
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::config::override_active_permissions_mode_for_test(PermissionsMode::Enforce);
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app)
}

fn sqlite_router(db_path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("open sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore"));
    router(app_state(db, store, StorageBackend::Sqlite))
}

async fn http_capture(
    router: &axum::Router,
    caller: &str,
    namespace: &str,
    turn: u64,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/capture_turn")
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "host_session_id": format!("sess-8760-{}", uuid::Uuid::new_v4()),
                "host_turn_index": turn,
                "role": "user",
                "content": "governance id-form probe",
                "namespace": namespace,
            }))
            .expect("body"),
        ))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({})))
}

/// Drive every id form (and its case swap) through `router`.
async fn http_matrix(router: &axum::Router, backend: &str) {
    for (name, id) in id_forms() {
        if ai_memory::validate::validate_agent_id(&id).is_err() {
            continue;
        }
        let mut callers = vec![id.clone()];
        let swapped = swap_ascii_case(&id);
        if swapped != id && ai_memory::validate::validate_agent_id(&swapped).is_ok() {
            callers.push(swapped);
        }
        for (ci, caller) in callers.iter().enumerate() {
            let tag = format!("http-{backend}-{name}-{ci}");
            let (rules, cells) = matrix(&tag, &id, caller);
            clear_active_permission_rules_for_test();
            set_active_permission_rules(rules);
            for (turn, cell) in (0u64..).zip(cells.iter()) {
                let (status, body) = http_capture(router, caller, &cell.namespace, turn).await;
                match &cell.expect {
                    Expect::Denied(reason) => {
                        assert_eq!(
                            status,
                            StatusCode::FORBIDDEN,
                            "#8760 HTTP {backend} {}: {body}",
                            cell.label
                        );
                        assert_eq!(
                            body["error"].as_str(),
                            Some(
                                format!("capture_turn denied by permission rule: {reason}")
                                    .as_str()
                            ),
                            "#8760 HTTP {backend} refusal text {}",
                            cell.label
                        );
                    }
                    Expect::Allowed => {
                        assert!(
                            status.is_success() && status != StatusCode::ACCEPTED,
                            "#8760 HTTP {backend} {} must be allowed, got {status}: {body}",
                            cell.label
                        );
                    }
                }
            }
        }
    }
    clear_active_permission_rules_for_test();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_capture_turn_refuses_every_id_form_sqlite() {
    let _g = registry_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _attestation =
        common::EnvVarGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0".to_string());
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("http8760.db");
    let router = sqlite_router(&db_path);
    http_matrix(&router, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
async fn http_capture_turn_refuses_every_id_form_postgres() {
    let _g = registry_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _attestation =
        common::EnvVarGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0".to_string());
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .expect("AI_MEMORY_TEST_POSTGRES_URL unset: cannot run the live-pg #8760 cell");
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    );
    let router = router(app_state(db, store, StorageBackend::Postgres));
    http_matrix(&router, "postgres").await;
}
