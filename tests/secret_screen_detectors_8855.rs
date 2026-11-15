// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8855 — secret-screen detector coverage for the four most common
//! credential forms that matched no detector and persisted verbatim:
//!
//! 1. URL userinfo password (`scheme://user:pass@host`) for the database and
//!    broker schemes;
//! 2. a `password` / `passwd` / `pwd` key followed by `:` or `=` and a value;
//! 3. Slack tokens (`xox[abprs]-…`);
//! 4. Stripe live keys (`sk_live_…`, `rk_live_…`).
//!
//! Invariant pinned here, for every form: refused on the caller validate
//! funnel (MCP store / HTTP / CLI store + update / capture-turn all reach
//! `validate::validate_*`) and by the real CLI binary with the EXACT reason
//! naming the detector, the secret value never echoed, masked (never refused)
//! on the storage and federation-receive / import funnels, the named doc
//! placeholders and benign shapes accepted, and every detector linear on a
//! 100K-character adversarial input.
//!
//! Every credential-shaped fixture is assembled with `concat!` so no
//! contiguous token of a live vendor format sits in the repository.

use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::models::Memory;
use ai_memory::secret_screen::{
    REDACTION_PLACEHOLDER, ScreenOutcome, SecretScreenMode, redact_memory_for_receive,
    redact_memory_for_storage, screen, set_screen_mode,
};
use ai_memory::validate;

// ── Detector kind tags (the exact names the refusal reason carries) ──────
const KIND_URL: &str = "url_userinfo_password";
const KIND_PASSWORD: &str = "password_assignment";
const KIND_SLACK: &str = "slack_token";
const KIND_STRIPE: &str = "stripe_live_key";

/// Generous wall-clock ceiling for one `screen` over a 100K adversarial
/// input. A linear scan needs milliseconds even in a debug build on a loaded
/// host; a quadratic one needs billions of byte steps.
const LINEAR_SCAN_CEILING: Duration = Duration::from_secs(2);
/// Size of every adversarial bound input.
const BOUND_INPUT_CHARS: usize = 100_000;

// ── Secret values (split so no live-format token is a source literal) ────
const URL_PW: &str = concat!("Zq8v", "T2kLw9");
const ASSIGN_PW: &str = concat!("Hn4r", "Xp7Qs2");
const SLACK_BODY: &str = concat!("1234567890", "-", "AbCdEfGhIjKlMnOp");
const STRIPE_BODY: &str = concat!("4eC39Hq", "LyjWDarjtT1zdp7dc");

/// One positive row: the content, the detector kind it must trip, and the
/// secret substring that must never survive redaction or reach an error.
struct Positive {
    content: String,
    kind: &'static str,
    secret: String,
}

fn url_positives() -> Vec<Positive> {
    let mut rows: Vec<Positive> = [
        "postgres",
        "postgresql",
        "mysql",
        "redis",
        "rediss",
        "amqp",
        "amqps",
        "mongodb",
        "mongodb+srv",
        "POSTGRES",
        "MongoDB+SRV",
    ]
    .iter()
    .map(|scheme| Positive {
        content: format!("connect with {scheme}://svc:{URL_PW}@db.internal:5432/mem today"),
        kind: KIND_URL,
        secret: URL_PW.to_string(),
    })
    .collect();
    // Percent-encoded password.
    let encoded = format!("p%40ss%2F{URL_PW}");
    rows.push(Positive {
        content: format!("postgresql://svc:{encoded}@db.internal/mem"),
        kind: KIND_URL,
        secret: encoded,
    });
    // Empty user.
    rows.push(Positive {
        content: format!("redis://:{URL_PW}@cache.internal:6379/0"),
        kind: KIND_URL,
        secret: URL_PW.to_string(),
    });
    // A JDBC-wrapped URL still names the scheme right before `://`.
    rows.push(Positive {
        content: format!("jdbc:mysql://svc:{URL_PW}@db.internal/app"),
        kind: KIND_URL,
        secret: URL_PW.to_string(),
    });
    rows
}

fn password_positives() -> Vec<Positive> {
    [
        format!("export PGPASSWORD={ASSIGN_PW}"),
        format!("db_password: {ASSIGN_PW}"),
        format!("{{\"password\": \"{ASSIGN_PW}\"}}"),
        format!("Passwd = {ASSIGN_PW}"),
        format!("pwd='{ASSIGN_PW}'"),
        format!("PASSWORD:{ASSIGN_PW}"),
    ]
    .into_iter()
    .map(|content| Positive {
        content,
        kind: KIND_PASSWORD,
        secret: ASSIGN_PW.to_string(),
    })
    .collect()
}

fn slack_positives() -> Vec<Positive> {
    ["a", "b", "p", "r", "s"]
        .iter()
        .map(|t| {
            let token = format!("{}{t}-{SLACK_BODY}", concat!("xo", "x"));
            Positive {
                content: format!("slack bot token {token} for the alerts channel"),
                kind: KIND_SLACK,
                secret: SLACK_BODY.to_string(),
            }
        })
        .collect()
}

fn stripe_positives() -> Vec<Positive> {
    [concat!("sk", "_live_"), concat!("rk", "_live_")]
        .iter()
        .map(|prefix| Positive {
            content: format!("stripe key {prefix}{STRIPE_BODY} in prod"),
            kind: KIND_STRIPE,
            secret: STRIPE_BODY.to_string(),
        })
        .collect()
}

fn all_positives() -> Vec<Positive> {
    let mut v = url_positives();
    v.extend(password_positives());
    v.extend(slack_positives());
    v.extend(stripe_positives());
    v
}

fn kinds_of(content: &str) -> Vec<&'static str> {
    match screen(content) {
        ScreenOutcome::Clean => vec![],
        ScreenOutcome::Hit { kinds, .. } => kinds,
    }
}

fn redacted_of(content: &str) -> String {
    match screen(content) {
        ScreenOutcome::Clean => content.to_string(),
        ScreenOutcome::Hit { redacted, .. } => redacted,
    }
}

/// The exact caller-refusal reason for one detector kind.
fn expected_reason(kind: &str) -> String {
    format!(
        "content rejected: appears to contain credential material ({kind}); \
         set AI_MEMORY_SECRET_SCREEN_MODE=redact to store a masked copy, \
         or =off to disable screening"
    )
}

fn assert_detects(rows: &[Positive]) {
    for row in rows {
        assert_eq!(
            kinds_of(&row.content),
            vec![row.kind],
            "8855: {:?} must trip exactly {}",
            row.content,
            row.kind
        );
        let r = redacted_of(&row.content);
        assert!(
            !r.contains(&row.secret),
            "8855: secret survived redaction: {r}"
        );
        assert!(
            r.contains(REDACTION_PLACEHOLDER),
            "8855: no placeholder: {r}"
        );
    }
}

// ── Positives, one cell per detector ──────────────────────────────────────

#[test]
fn url_userinfo_password_detected_8855() {
    assert_detects(&url_positives());
}

#[test]
fn password_assignment_detected_8855() {
    assert_detects(&password_positives());
}

#[test]
fn slack_token_detected_8855() {
    assert_detects(&slack_positives());
}

#[test]
fn stripe_live_key_detected_8855() {
    assert_detects(&stripe_positives());
}

/// Redaction keeps the surrounding context and is idempotent: a stored
/// redacted row re-screened (update, federation re-receive) trips none of
/// the four new detectors again.
#[test]
fn redaction_keeps_context_and_is_idempotent_8855() {
    let c = format!("postgres://svc:{URL_PW}@db.internal/mem");
    assert_eq!(
        redacted_of(&c),
        format!("postgres://svc:{REDACTION_PLACEHOLDER}@db.internal/mem")
    );
    let c = format!("export PGPASSWORD={ASSIGN_PW} && psql");
    assert_eq!(
        redacted_of(&c),
        format!("export PGPASSWORD={REDACTION_PLACEHOLDER} && psql")
    );
    for row in all_positives() {
        let once = redacted_of(&row.content);
        assert_eq!(
            kinds_of(&once),
            Vec::<&str>::new(),
            "8855: re-screen of {once:?} must be clean"
        );
    }
}

// ── Named negatives: one cell each, exact Clean ───────────────────────────

macro_rules! negative_cell {
    ($name:ident, $input:expr) => {
        #[test]
        fn $name() {
            let input: String = $input.to_string();
            assert_eq!(
                screen(&input),
                ScreenOutcome::Clean,
                "8855: {input:?} must stay accepted"
            );
        }
    };
}

negative_cell!(
    neg_uuid_8855,
    "id 550e8400-e29b-41d4-a716-446655440000 noted"
);
negative_cell!(
    neg_sha256_hex_8855,
    "digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
);
negative_cell!(
    neg_doc_user_password_at_host_8855,
    "use user:password@host to log in"
);
negative_cell!(
    neg_doc_postgres_user_password_url_8855,
    "set the url to postgres://user:password@host/db first"
);
negative_cell!(
    neg_angle_password_placeholder_8855,
    "postgres://admin:<password>@host/db and <password>"
);
negative_cell!(neg_password_your_password_8855, "password: <your-password>");
negative_cell!(neg_password_masked_8855, "password=********");
negative_cell!(
    neg_env_brace_reference_8855,
    "password=${DB_PASSWORD} or ${DB_PASSWORD}"
);
negative_cell!(
    neg_env_dollar_reference_8855,
    "password=$PASSWORD or $PASSWORD"
);
negative_cell!(
    neg_stripe_test_key_8855,
    format!("{}{STRIPE_BODY}", concat!("sk", "_test_"))
);
negative_cell!(
    neg_bare_word_password_in_prose_8855,
    "reset the password before the passwords are rotated"
);
negative_cell!(
    neg_redis_url_with_port_no_userinfo_8855,
    "redis://host:6379"
);
negative_cell!(neg_ipv6_url_8855, "http://[::1]:8080/a@b");
negative_cell!(
    neg_stripe_prefix_inside_word_8855,
    format!("risk{}{STRIPE_BODY}", concat!("_live_"))
);
negative_cell!(
    neg_password_comparison_8855,
    "if password == expected { ok }"
);

// ── Linear-time bound, adversarial per detector (100K chars) ──────────────

/// Screen `input` on a worker thread; the outcome must arrive within
/// [`LINEAR_SCAN_CEILING`].
fn screen_bounded(input: String) -> ScreenOutcome {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(screen(&input));
    });
    rx.recv_timeout(LINEAR_SCAN_CEILING)
        .unwrap_or_else(|_| panic!("8855: screen exceeded {LINEAR_SCAN_CEILING:?} on a 100K input"))
}

fn repeat_to(unit: &str) -> String {
    unit.repeat(BOUND_INPUT_CHARS / unit.len())
}

fn hit_kinds(o: &ScreenOutcome) -> Vec<&'static str> {
    match o {
        ScreenOutcome::Clean => vec![],
        ScreenOutcome::Hit { kinds, .. } => kinds.clone(),
    }
}

#[test]
fn bound_100k_colons_and_ats_8855() {
    let bare = repeat_to(":@");
    assert_eq!(screen_bounded(bare.clone()), ScreenOutcome::Clean);
    let o = screen_bounded(format!("redis://{bare}"));
    assert_eq!(hit_kinds(&o), vec![KIND_URL]);
}

#[test]
fn bound_100k_password_assignments_8855() {
    let o = screen_bounded(repeat_to("password="));
    assert_eq!(hit_kinds(&o), vec![KIND_PASSWORD]);
    let o = screen_bounded(repeat_to("password "));
    assert_eq!(o, ScreenOutcome::Clean);
}

#[test]
fn bound_100k_slack_prefixes_8855() {
    let o = screen_bounded(repeat_to(concat!("xo", "x")));
    assert_eq!(o, ScreenOutcome::Clean);
    let o = screen_bounded(repeat_to(concat!("xo", "xb-")));
    assert_eq!(hit_kinds(&o), vec![KIND_SLACK]);
}

#[test]
fn bound_100k_stripe_prefixes_8855() {
    let o = screen_bounded(repeat_to(concat!("sk", "_live_")));
    assert_eq!(hit_kinds(&o), vec![KIND_STRIPE]);
}

// ── Char boundaries on multi-byte input ───────────────────────────────────

#[test]
fn multibyte_input_is_char_boundary_safe_8855() {
    let v = "日本語の値";
    let c = format!("pässwörd 密码 password={v} postgres://ü:{v}@höst/db");
    let k = kinds_of(&c);
    assert_eq!(k, vec![KIND_PASSWORD, KIND_URL]);
    assert!(
        !redacted_of(&c).contains(v),
        "8855: multi-byte secret survived"
    );
    // Noise interleaving every trigger byte with multi-byte code points.
    let noise = "é:@=ü".repeat(2_000);
    for prefix in [
        "redis://",
        "password=",
        concat!("xo", "xb-"),
        concat!("sk", "_live_"),
        "",
    ] {
        let _ = screen(&format!("{prefix}{noise}"));
    }
}

// ── Entry-path families ───────────────────────────────────────────────────

/// Caller funnel (MCP `memory_store` / `memory_update`, HTTP create +
/// update, CLI store + update, capture-turn all call these validators):
/// refused with the exact reason, value never in the error.
#[test]
fn caller_validators_refuse_each_form_with_exact_reason_8855() {
    set_screen_mode(SecretScreenMode::Refuse);
    for row in all_positives() {
        let want = expected_reason(row.kind);
        let errs = [
            validate::validate_content(&row.content)
                .unwrap_err()
                .to_string(),
            validate::validate_title(&row.content)
                .unwrap_err()
                .to_string(),
            validate::validate_tags(std::slice::from_ref(&row.content))
                .unwrap_err()
                .to_string(),
            validate::validate_metadata(&serde_json::json!({ "note": row.content }))
                .unwrap_err()
                .to_string(),
        ];
        for err in errs {
            assert!(err.contains(&want), "8855: want {want:?}, got {err:?}");
            assert!(
                !err.contains(&row.secret),
                "8855: refusal echoed the secret: {err}"
            );
        }
    }
}

/// Storage funnel (`db::insert`, postgres store, import) and the
/// federation-receive funnel mask the value and never refuse.
#[test]
fn storage_and_receive_funnels_mask_each_form_8855() {
    set_screen_mode(SecretScreenMode::Refuse);
    for row in all_positives() {
        let mem = Memory {
            namespace: "ns-8855".to_string(),
            title: "a clean title".to_string(),
            content: row.content.clone(),
            ..Memory::default()
        };
        for (path, out) in [
            ("storage", redact_memory_for_storage(&mem)),
            ("receive", redact_memory_for_receive(&mem)),
        ] {
            let m = out.unwrap_or_else(|| panic!("8855 {path}: {:?} must be masked", row.content));
            assert!(
                !m.content.contains(&row.secret),
                "8855 {path}: secret persisted: {}",
                m.content
            );
            assert!(
                m.content.contains(REDACTION_PLACEHOLDER),
                "8855 {path}: {}",
                m.content
            );
        }
    }
}

/// The real CLI binary (`ai-memory store`): non-zero exit, the exact reason
/// on stderr, the secret in neither stream (tracing logs go to stderr), and
/// nothing persisted.
#[test]
fn cli_store_refuses_each_form_with_exact_reason_8855() {
    let dir = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-8855-secret-screen");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let rows = [
        url_positives().remove(0),
        password_positives().remove(0),
        slack_positives().remove(0),
        stripe_positives().remove(0),
    ];
    for row in rows {
        let db_path = dir.join(format!("cli-{}.db", uuid::Uuid::new_v4()));
        let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_SECRET_SCREEN_MODE", "refuse")
            .args([
                "--db",
                db_path.to_str().expect("utf-8 path"),
                "store",
                "--title",
                "cli-8855",
            ])
            .args(["--content", &row.content])
            .output()
            .expect("run ai-memory store");
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !out.status.success(),
            "8855 CLI: {} must be refused",
            row.kind
        );
        assert!(
            stderr.contains(&expected_reason(row.kind)),
            "8855 CLI: exact reason for {} missing; stderr: {stderr}",
            row.kind
        );
        assert!(
            !stderr.contains(&row.secret) && !stdout.contains(&row.secret),
            "8855 CLI: the secret reached an output stream"
        );
        if db_path.exists() {
            let conn = rusqlite::Connection::open(&db_path).expect("open db");
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
                .unwrap_or(0);
            assert_eq!(n, 0, "8855 CLI: a refused write persisted");
        }
    }
}
