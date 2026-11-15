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
        // Assignment operators beyond `:` / `=` (Go, Ruby/PHP, Python
        // subscript): the whole value is masked, not the operator's tail.
        format!("password := \"{ASSIGN_PW}\""),
        format!(":password => '{ASSIGN_PW}'"),
        format!("config['password'] = '{ASSIGN_PW}'"),
        // A type annotation followed by an initializer is an assignment.
        format!("const DB_PASSWORD: &str = \"{ASSIGN_PW}\";"),
        format!("password: String = \"{ASSIGN_PW}\""),
        format!("password: &'static str = \"{ASSIGN_PW}\";"),
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
    format!("risk_live_{STRIPE_BODY}")
);
negative_cell!(
    neg_password_comparison_8855,
    "if password == expected { ok }"
);
// The false-positive class (r2): stored memories carry source code and docs.
negative_cell!(
    neg_password_not_equal_comparison_8855,
    "if password != expected && pwd === other { ok }"
);
negative_cell!(
    neg_type_annotation_8855,
    "struct Login { password: String, pwd: Option<SecretString> }\nfn f(password: &str, passwd: &'a str) {}"
);
negative_cell!(
    neg_env_lookup_8855,
    "password = os.environ[\"DB_PASSWORD\"]\npassword = os.getenv('DB_PASSWORD')\nlet password = std::env::var(\"DB_PASSWORD\")?;\nconst password = process.env.DB_PASSWORD;\npassword: ${DB_PASSWORD}"
);
negative_cell!(
    neg_empty_value_8855,
    "password=\npwd=''\n{\"password\": \"\"}\nPrompted for the password:\n"
);
negative_cell!(
    neg_null_value_8855,
    "password: null, pwd = None, passwd: nil"
);
negative_cell!(
    neg_prose_mention_8855,
    "the query string (it is where `password=` lives) and `?sslpassword=` are dropped"
);
negative_cell!(
    neg_format_and_ellipsis_placeholder_8855,
    "refusal must redact the DSN password: {msg}\nuse `?sslpassword=…` or host=db password=... sslmode"
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

// ── r3 host probes P1 (leading `&` after `:`) and P2 (backtick in value) ──

/// Assert that each `(input, expected redaction)` pair trips exactly `kind`
/// and that the redacted copy is exactly the expected string (no byte of
/// the value survives).
fn assert_redacts_exactly(kind: &'static str, rows: &[(String, String)]) {
    for (input, expected) in rows {
        assert_eq!(
            kinds_of(input),
            vec![kind],
            "8855: {input:?} must trip {kind}"
        );
        assert_eq!(
            &redacted_of(input),
            expected,
            "8855: redaction of {input:?}"
        );
    }
}

/// P1: a leading `&` after `:` is a type annotation only when a named type
/// follows (after an optional `'lifetime ` and `mut `); anything else is a
/// value and refuses, and a YAML anchor masks the anchored value too.
#[test]
fn ampersand_value_after_colon_refuses_8855() {
    let ph = REDACTION_PLACEHOLDER;
    assert_redacts_exactly(
        KIND_PASSWORD,
        &[
            ("password: &S3cr3tValue99".into(), format!("password: {ph}")),
            (
                "password: &hunter2hunter2 ".into(),
                format!("password: {ph} "),
            ),
            (
                "PASSWORD: &'static-looking-secret".into(),
                format!("PASSWORD: {ph}"),
            ),
            (
                "password: &anchor Wq7sV2nB9x\nuser: bob".into(),
                format!("password: {ph}\nuser: bob"),
            ),
            (
                "db_password: &'a mut Hn4rXp7Qs2".into(),
                format!("db_password: {ph}"),
            ),
        ],
    );
}

negative_cell!(
    neg_reference_type_annotation_forms_8855,
    "fn f(password: &mut String, pwd: &'static str, passwd: &Option<Secret>) {}"
);

/// P2: a backtick inside an unquoted value (or a URL password) is part of
/// the value; the whole value is masked, never only the part before it.
#[test]
fn backtick_inside_value_is_masked_whole_8855() {
    let ph = REDACTION_PLACEHOLDER;
    assert_redacts_exactly(
        KIND_PASSWORD,
        &[
            ("password=abc`def123456".into(), format!("password={ph}")),
            ("password: abc`def123456".into(), format!("password: {ph}")),
        ],
    );
    assert_redacts_exactly(
        KIND_URL,
        &[(
            "postgres://svc:ab`cd1234@db.internal/x".into(),
            format!("postgres://svc:{ph}@db.internal/x"),
        )],
    );
}

negative_cell!(
    neg_prose_mention_backtick_empty_value_8855,
    "Set `password=` and `pwd:` in the file; see `redis://host:6379`."
);

// ── r4 class invariant: no byte inside a value ends it early ──────────────
//
// For EVERY printable ASCII byte b (and one multi-byte character) a value
// `abc<b>def123456` in the `=` form, the `:` form and as a URL password is
// refused, and the redacted copy holds no byte of the value. A value ends
// only at whitespace, the end of the line, or the closing quote of a value
// that opened with that same quote.

/// Every printable non-blank ASCII byte (0x21 `!` through 0x7E `~`).
const INNER_BYTE_RANGE: std::ops::RangeInclusive<u8> = 0x21..=0x7E;
/// The value bytes before the probed byte.
const VALUE_HEAD: &str = "abc";
/// The value bytes after the probed byte (the secret tail).
const VALUE_TAIL: &str = "def123456";
/// Context after the value, separated by a blank: it must survive.
const AFTER_VALUE: &str = " tail";
/// The multi-byte probe (3-byte UTF-8 code point).
const MULTIBYTE_INNER: char = '密';

/// The three value forms: `(name, kind, content for value v, expected
/// redaction)`.
fn value_forms(v: &str) -> [(&'static str, &'static str, String, String); 3] {
    let ph = REDACTION_PLACEHOLDER;
    [
        (
            "equals",
            KIND_PASSWORD,
            format!("password={v}{AFTER_VALUE}"),
            format!("password={ph}{AFTER_VALUE}"),
        ),
        (
            "colon",
            KIND_PASSWORD,
            format!("password: {v}{AFTER_VALUE}"),
            format!("password: {ph}{AFTER_VALUE}"),
        ),
        (
            "url_password",
            KIND_URL,
            format!("postgres://svc:{v}@db.internal/x{AFTER_VALUE}"),
            format!("postgres://svc:{ph}@db.internal/x{AFTER_VALUE}"),
        ),
    ]
}

/// Run one form over every byte of [`INNER_BYTE_RANGE`]; return the bytes
/// (as chars) whose refusal kind or exact redaction is wrong.
fn failing_inner_bytes(form: &str) -> Vec<char> {
    let mut failing = Vec::new();
    for b in INNER_BYTE_RANGE {
        let v = format!("{VALUE_HEAD}{}{VALUE_TAIL}", char::from(b));
        for (name, kind, input, expected) in value_forms(&v) {
            if name != form {
                continue;
            }
            if kinds_of(&input) != vec![kind] || redacted_of(&input) != expected {
                failing.push(char::from(b));
            }
        }
    }
    failing
}

#[test]
fn inner_byte_class_equals_form_masked_whole_8855() {
    let failing = failing_inner_bytes("equals");
    assert!(
        failing.is_empty(),
        "8855: `password=abc<b>def123456` cut early for bytes {failing:?}"
    );
}

#[test]
fn inner_byte_class_colon_form_masked_whole_8855() {
    let failing = failing_inner_bytes("colon");
    assert!(
        failing.is_empty(),
        "8855: `password: abc<b>def123456` cut early for bytes {failing:?}"
    );
}

#[test]
fn inner_byte_class_url_password_masked_whole_8855() {
    let failing = failing_inner_bytes("url_password");
    assert!(
        failing.is_empty(),
        "8855: URL password `abc<b>def123456` cut early for bytes {failing:?}"
    );
}

/// Char boundary: a multi-byte code point inside the value never panics a
/// slice and never ends the value.
#[test]
fn inner_multibyte_char_masked_whole_8855() {
    let v = format!("{VALUE_HEAD}{MULTIBYTE_INNER}{VALUE_TAIL}");
    for (name, kind, input, expected) in value_forms(&v) {
        assert_eq!(kinds_of(&input), vec![kind], "8855 {name}: {input:?}");
        assert_eq!(redacted_of(&input), expected, "8855 {name}: {input:?}");
    }
}

/// The whitespace end is honoured: the token after a blank is context, not
/// value (every form above asserts [`AFTER_VALUE`] survives), and a value
/// that OPENED with a quote still ends at that same quote.
#[test]
fn quoted_value_ends_at_its_own_quote_8855() {
    let ph = REDACTION_PLACEHOLDER;
    assert_redacts_exactly(
        KIND_PASSWORD,
        &[
            (
                "password=\"abc'def,123\" user=bob".into(),
                format!("password=\"{ph}\" user=bob"),
            ),
            (
                "password: 'abc\"def;123' user=bob".into(),
                format!("password: '{ph}' user=bob"),
            ),
        ],
    );
}

/// `unit` repeated until the result is longer than [`BOUND_INPUT_CHARS`].
fn repeat_past(unit: &str) -> String {
    unit.repeat(BOUND_INPUT_CHARS / unit.len() + 1)
}

/// Linear bound for the whitespace-ended value scans: one 100K value made
/// of every former terminator byte, and one 100K URL authority made of the
/// bytes that used to end it.
#[test]
fn bound_100k_inner_terminator_bytes_8855() {
    let ph = REDACTION_PLACEHOLDER;
    let body = repeat_past("a,b;c&d\"e'f`g/h?i#j");
    let o = screen_bounded(format!("password={body}"));
    assert_eq!(hit_kinds(&o), vec![KIND_PASSWORD]);
    match o {
        ScreenOutcome::Hit { redacted, .. } => assert_eq!(redacted, format!("password={ph}")),
        ScreenOutcome::Clean => panic!("8855: 100K value must be refused"),
    }
    let authority = repeat_past("u:/?#'\"@");
    let o = screen_bounded(format!("postgres://{authority}h"));
    assert_eq!(hit_kinds(&o), vec![KIND_URL]);
}

/// Sibling (parent `Bearer` detector): an RFC 6750 token68 value may hold
/// `~`; the token must be masked whole, never cut at it.
#[test]
fn bearer_token68_tilde_masked_whole_8855() {
    let token = concat!("Qm9vX2FiY2RlZjEy", "~", "MzQ1Njc4OTBhYmNk", "~", "ZWZnaGk");
    let input = format!("Authorization: Bearer {token} sent");
    assert_eq!(kinds_of(&input), vec!["bearer_token"], "8855: {input:?}");
    assert_eq!(
        redacted_of(&input),
        format!("Authorization: {REDACTION_PLACEHOLDER} sent")
    );
}

// ── r4 ruling eeda8423: quotes, terminators, callers, bounds ──────────────
//
// (a) a quoted value ends only at the quote it opened with: an escaped
//     quote (`\"`, `\'`) or a doubled quote (`""`, `''`) is part of the
//     value, and a value with no closing quote is masked to the line end;
// (b) the only terminators are ASCII whitespace (CR and LF included);
//     U+00A0 and U+2028 are value bytes, and every cut is on a char
//     boundary;
// (c) every caller of the value scans keeps its refusal (no verdict flips
//     from refuse to pass);
// (d) one 100K+ whitespace-free line per form under LINEAR_SCAN_CEILING;
// (e) an accepted shape (env lookup, `<…>`, `${…}`, a type annotation)
//     never swallows a password assignment in the same token.

/// The two quote characters a value may open with.
const QUOTE_CHARS: [char; 2] = ['"', '\''];
/// The non-ASCII blanks that must NOT end a value (NBSP, LINE SEPARATOR).
const NON_ASCII_BLANKS: [char; 2] = ['\u{00A0}', '\u{2028}'];
/// The plain secret used by the caller-class and boundary cells.
const PLAIN_VALUE: &str = concat!("abcdef", "123456");
/// One unit of a whitespace-free 100K value (no key, no `@`).
const BOUND_VALUE_UNIT: &str = "Ab9!x";

/// (a) For each quote q, `password=q abc<esc>def123456 q tail` with an
/// escaped (`\q`) and a doubled (`qq`) quote inside is masked whole, in the
/// `=` and the `:` form; an escaped backslash (`\\`) still lets the quote
/// after it close the value.
#[test]
fn quoted_value_escaped_and_doubled_quote_masked_whole_8855() {
    let ph = REDACTION_PLACEHOLDER;
    let mut rows = Vec::new();
    for q in QUOTE_CHARS {
        for inner in [format!("\\{q}"), format!("{q}{q}")] {
            for op in ["=", ": "] {
                rows.push((
                    format!("password{op}{q}abc{inner}def123456{q} tail"),
                    format!("password{op}{q}{ph}{q} tail"),
                ));
            }
        }
        rows.push((
            format!("password={q}abc\\\\{q} tail"),
            format!("password={q}{ph}{q} tail"),
        ));
    }
    assert_redacts_exactly(KIND_PASSWORD, &rows);
}

/// (a) A quoted value that never closes is masked to the end of its line
/// (LF or CRLF), never passed and never cut at an inner byte; the next line
/// survives.
#[test]
fn unterminated_quoted_value_masked_to_line_end_8855() {
    let ph = REDACTION_PLACEHOLDER;
    let mut rows = Vec::new();
    for q in QUOTE_CHARS {
        rows.push((
            format!("password={q}abc def,123 x\nnext line"),
            format!("password={q}{ph}\nnext line"),
        ));
        rows.push((
            format!("password: {q}abc\\{q}\r\nnext line"),
            format!("password: {q}{ph}\r\nnext line"),
        ));
        rows.push((
            format!("password={q}abc;def123456"),
            format!("password={q}{ph}"),
        ));
    }
    assert_redacts_exactly(KIND_PASSWORD, &rows);
}

/// (b) U+00A0 and U+2028 inside a value are value bytes in all three forms.
#[test]
fn non_ascii_blank_inside_value_masked_whole_8855() {
    for blank in NON_ASCII_BLANKS {
        let v = format!("{VALUE_HEAD}{blank}{VALUE_TAIL}");
        for (name, kind, input, expected) in value_forms(&v) {
            assert_eq!(kinds_of(&input), vec![kind], "8855 {name}: {input:?}");
            assert_eq!(redacted_of(&input), expected, "8855 {name}: {input:?}");
        }
    }
}

/// (b) CR and LF end an unquoted value (and the URL token): the next line
/// survives.
#[test]
fn cr_and_lf_end_an_unquoted_value_8855() {
    let ph = REDACTION_PLACEHOLDER;
    assert_redacts_exactly(
        KIND_PASSWORD,
        &[
            (
                format!("password={PLAIN_VALUE}\r\nuser bob"),
                format!("password={ph}\r\nuser bob"),
            ),
            (
                format!("password: {PLAIN_VALUE}\ruser bob"),
                format!("password: {ph}\ruser bob"),
            ),
        ],
    );
    assert_redacts_exactly(
        KIND_URL,
        &[(
            format!("postgres://svc:{PLAIN_VALUE}@db/x\r\nuser bob"),
            format!("postgres://svc:{ph}@db/x\r\nuser bob"),
        )],
    );
}

/// (b) A multi-byte character directly BEFORE the terminator is masked with
/// the value; one directly AFTER it survives. Neither slices mid-char.
#[test]
fn multibyte_char_at_the_cut_is_on_a_char_boundary_8855() {
    let ph = REDACTION_PLACEHOLDER;
    let before = format!("{PLAIN_VALUE}{MULTIBYTE_INNER}");
    for (name, kind, input, expected) in value_forms(&before) {
        assert_eq!(kinds_of(&input), vec![kind], "8855 {name}: {input:?}");
        assert_eq!(redacted_of(&input), expected, "8855 {name}: {input:?}");
    }
    let m = MULTIBYTE_INNER;
    assert_redacts_exactly(
        KIND_PASSWORD,
        &[
            (
                format!("password={PLAIN_VALUE} {m}tail"),
                format!("password={ph} {m}tail"),
            ),
            (
                format!("password: {PLAIN_VALUE}\n{m}tail"),
                format!("password: {ph}\n{m}tail"),
            ),
            (
                format!("password=\"{PLAIN_VALUE}{m}\"{m}tail"),
                format!("password=\"{ph}\"{m}tail"),
            ),
        ],
    );
    assert_redacts_exactly(
        KIND_URL,
        &[(
            format!("postgres://svc:{PLAIN_VALUE}{m}@db/x {m}tail"),
            format!("postgres://svc:{ph}@db/x {m}tail"),
        )],
    );
}

/// (c) One row per caller class of the value scans: `value_at` after `=`,
/// after `:`, after a type annotation's initializer (plain and `&`-led), the
/// `&`-led credential path, and `authority_end` for a URL password. Each is
/// refused on the caller funnel with the exact reason and masked exactly on
/// the receive funnel.
#[test]
fn every_value_scan_caller_keeps_its_refusal_8855() {
    set_screen_mode(SecretScreenMode::Refuse);
    let ph = REDACTION_PLACEHOLDER;
    let v = PLAIN_VALUE;
    let rows: [(&str, &str, String, String); 6] = [
        (
            "value_at =",
            KIND_PASSWORD,
            format!("password={v} tail"),
            format!("password={ph} tail"),
        ),
        (
            "value_at :",
            KIND_PASSWORD,
            format!("password: {v} tail"),
            format!("password: {ph} tail"),
        ),
        (
            "value_at initializer",
            KIND_PASSWORD,
            format!("password: String = \"{v}\";"),
            format!("password: String = \"{ph}\";"),
        ),
        (
            "value_at ref initializer",
            KIND_PASSWORD,
            format!("pwd: &'static str = \"{v}\";"),
            format!("pwd: &'static str = \"{ph}\";"),
        ),
        (
            "ref-led credential",
            KIND_PASSWORD,
            format!("password: &{v}"),
            format!("password: {ph}"),
        ),
        (
            "authority_end",
            KIND_URL,
            format!("postgres://svc:{v}@db.internal/x tail"),
            format!("postgres://svc:{ph}@db.internal/x tail"),
        ),
    ];
    for (class, kind, input, expected) in rows {
        assert_eq!(kinds_of(&input), vec![kind], "8855 {class}: {input:?}");
        assert_eq!(redacted_of(&input), expected, "8855 {class}: {input:?}");
        let err = validate::validate_content(&input)
            .map_err(|e| e.to_string())
            .expect_err("8855: caller funnel must refuse");
        assert!(
            err.contains(&expected_reason(kind)),
            "8855 {class}: want {kind} refusal, got {err:?}"
        );
        assert!(!err.contains(v), "8855 {class}: refusal echoed the value");
        let mem = Memory {
            namespace: "ns-8855".to_string(),
            title: "a clean title".to_string(),
            content: input.clone(),
            ..Memory::default()
        };
        let masked = redact_memory_for_receive(&mem)
            .unwrap_or_else(|| panic!("8855 {class}: receive must mask {input:?}"));
        assert_eq!(masked.content, expected, "8855 {class}: receive mask");
    }
}

/// Screen a 100K+ input under the ceiling and return its redacted copy.
fn bounded_redaction(input: String, kind: &'static str) -> String {
    let o = screen_bounded(input);
    assert_eq!(
        hit_kinds(&o),
        vec![kind],
        "8855: 100K input must trip {kind}"
    );
    match o {
        ScreenOutcome::Hit { redacted, .. } => redacted,
        ScreenOutcome::Clean => panic!("8855: 100K input must be refused"),
    }
}

/// (d) One 100K+ whitespace-free line per form (`=`, `:`, URL password),
/// plus a 100K quoted value full of escaped and doubled quotes, each under
/// [`LINEAR_SCAN_CEILING`] and masked whole.
#[test]
fn bound_100k_whitespace_free_line_per_form_8855() {
    let ph = REDACTION_PLACEHOLDER;
    let body = repeat_past(BOUND_VALUE_UNIT);
    assert_eq!(
        bounded_redaction(format!("password={body}"), KIND_PASSWORD),
        format!("password={ph}")
    );
    assert_eq!(
        bounded_redaction(format!("password:{body}"), KIND_PASSWORD),
        format!("password:{ph}")
    );
    assert_eq!(
        bounded_redaction(format!("postgres://svc:{body}@db.internal/x"), KIND_URL),
        format!("postgres://svc:{ph}@db.internal/x")
    );
    let quoted = repeat_past("a\\\"b\"\"c");
    assert_eq!(
        bounded_redaction(format!("password=\"{quoted}\""), KIND_PASSWORD),
        format!("password=\"{ph}\"")
    );
}

/// (d) A URL password holding `@`, a quote, a slash and percent-encoding is
/// masked whole.
#[test]
fn url_password_with_at_quote_slash_percent_masked_whole_8855() {
    let ph = REDACTION_PLACEHOLDER;
    assert_redacts_exactly(
        KIND_URL,
        &[
            (
                "postgres://svc:p@ss'w/rd%40x9\"q@db.internal/x tail".into(),
                format!("postgres://svc:{ph}@db.internal/x tail"),
            ),
            (
                "redis://:a%2Fb@c/d'e@cache:6379/0".into(),
                format!("redis://:{ph}@cache:6379/0"),
            ),
        ],
    );
}

/// (e) An accepted shape that holds a password assignment in the same token
/// is not accepted: the whole value is masked, never the nested secret left.
#[test]
fn accepted_shape_never_swallows_a_nested_assignment_8855() {
    let ph = REDACTION_PLACEHOLDER;
    let s = ASSIGN_PW;
    let heads_and_tails: [(&str, &str); 6] = [
        ("os.environ", ""),
        ("os.getenv(\"X\")", ""),
        ("process.env.X", ""),
        ("<a", ">"),
        ("${A", "}"),
        ("Option<", ">"),
    ];
    let mut rows = Vec::new();
    for (head, tail) in heads_and_tails {
        for sep in ["&", ",", ";"] {
            for op in ["=", ": "] {
                rows.push((
                    format!("password{op}{head}{sep}pwd={s}{tail} rest"),
                    format!("password{op}{ph} rest"),
                ));
            }
        }
    }
    rows.push((
        format!("password=\"<x&passwd:{s}>\" rest"),
        format!("password=\"{ph}\" rest"),
    ));
    assert_redacts_exactly(KIND_PASSWORD, &rows);
}

/// (e) Bound: one 100K accepted-shape token chained with nested assignments
/// is scanned once and masked whole.
#[test]
fn bound_100k_nested_assignment_chain_8855() {
    let chain = repeat_past("&pwd=os.environ");
    assert_eq!(
        bounded_redaction(format!("password=os.environ{chain}"), KIND_PASSWORD),
        format!("password={REDACTION_PLACEHOLDER}")
    );
}

// ── r4c: every env-lookup prefix ends in its delimiter (ruling e50aed97) ──
//
// An env-lookup prefix is matched with `starts_with`. An entry that ends in
// an identifier byte accepts any unquoted value that merely extends it
// (`os.environ_<secret>`), so each entry must end in the delimiter its lookup
// grammar requires. The table invariant itself is the lib cell
// `no_env_lookup_prefix_ends_in_an_identifier_character_8855`.

/// The identifier byte that extends a bare env-lookup head.
const IDENT_EXTENSION: &str = "_";
/// The two assignment forms each env-lookup cell runs.
const ENV_CELL_OPERATORS: [&str; 2] = ["=", ": "];

/// One `ENV_LOOKUP_PREFIXES` entry: its head without the delimiter, and the
/// delimited lookups that must stay accepted.
struct EnvLookupEntry {
    head: &'static str,
    delimited: &'static [&'static str],
}

const ENV_OS_ENVIRON: EnvLookupEntry = EnvLookupEntry {
    head: "os.environ",
    delimited: &["os.environ[\"X\"]", "os.environ.get(\"X\")"],
};
const ENV_OS_GETENV: EnvLookupEntry = EnvLookupEntry {
    head: "os.getenv",
    delimited: &["os.getenv(\"X\")"],
};
const ENV_GETENV: EnvLookupEntry = EnvLookupEntry {
    head: "getenv",
    delimited: &["getenv(\"X\")"],
};
const ENV_RUST_VAR: EnvLookupEntry = EnvLookupEntry {
    head: "env::var",
    delimited: &["env::var(\"X\")"],
};
const ENV_RUST_STD_VAR: EnvLookupEntry = EnvLookupEntry {
    head: "std::env::var",
    delimited: &["std::env::var(\"X\")"],
};
const ENV_NODE_PROCESS: EnvLookupEntry = EnvLookupEntry {
    head: "process.env",
    delimited: &["process.env.X"],
};
const ENV_RUBY_INDEX: EnvLookupEntry = EnvLookupEntry {
    head: "ENV",
    delimited: &["ENV[\"X\"]"],
};
const ENV_RUBY_FETCH: EnvLookupEntry = EnvLookupEntry {
    head: "ENV.fetch",
    delimited: &["ENV.fetch(\"X\")"],
};
const ENV_JAVA_GETENV: EnvLookupEntry = EnvLookupEntry {
    head: "System.getenv",
    delimited: &["System.getenv(\"X\")"],
};
const ENV_DOTNET_GET: EnvLookupEntry = EnvLookupEntry {
    head: "Environment.GetEnvironmentVariable",
    delimited: &["Environment.GetEnvironmentVariable(\"X\")"],
};
/// The Perl `%ENV` hash. Its bare head extended with identifier bytes
/// (`$ENV_<x>`) is the `$IDENT` shell-reference placeholder, a separate named
/// shape, so this entry gets a pin cell only.
const ENV_PERL_HASH: EnvLookupEntry = EnvLookupEntry {
    head: "$ENV",
    delimited: &["$ENV{X}"],
};

/// The head extended with identifier bytes is masked whole and refused with
/// the exact reason; every delimited lookup of the entry stays accepted.
fn assert_env_lookup_cell(entry: &EnvLookupEntry) {
    set_screen_mode(SecretScreenMode::Refuse);
    let ph = REDACTION_PLACEHOLDER;
    let s = ASSIGN_PW;
    let head = entry.head;
    for op in ENV_CELL_OPERATORS {
        let input = format!("password{op}{head}{IDENT_EXTENSION}{s} tail");
        assert_eq!(
            kinds_of(&input),
            vec![KIND_PASSWORD],
            "8855 r4c: {input:?} must trip {KIND_PASSWORD}"
        );
        assert_eq!(
            redacted_of(&input),
            format!("password{op}{ph} tail"),
            "8855 r4c: redaction of {input:?}"
        );
        let err = validate::validate_content(&input)
            .map_err(|e| e.to_string())
            .expect_err("8855 r4c: caller funnel must refuse");
        assert!(
            err.contains(&expected_reason(KIND_PASSWORD)),
            "8855 r4c: want {KIND_PASSWORD} refusal for {input:?}, got {err:?}"
        );
        assert!(!err.contains(s), "8855 r4c: refusal echoed the value");
        assert_delimited_lookups_accepted(entry, op);
    }
}

fn assert_delimited_lookups_accepted(entry: &EnvLookupEntry, op: &str) {
    for lookup in entry.delimited {
        let ok = format!("password{op}{lookup} tail");
        assert_eq!(
            kinds_of(&ok),
            Vec::<&str>::new(),
            "8855 r4c: delimited lookup {ok:?} stays accepted"
        );
    }
}

macro_rules! env_lookup_cell {
    ($name:ident, $entry:expr) => {
        #[test]
        fn $name() {
            assert_env_lookup_cell(&$entry);
        }
    };
}

env_lookup_cell!(
    env_lookup_os_environ_needs_its_delimiter_8855,
    ENV_OS_ENVIRON
);
env_lookup_cell!(env_lookup_os_getenv_needs_its_delimiter_8855, ENV_OS_GETENV);
env_lookup_cell!(env_lookup_getenv_needs_its_delimiter_8855, ENV_GETENV);
env_lookup_cell!(env_lookup_env_var_needs_its_delimiter_8855, ENV_RUST_VAR);
env_lookup_cell!(
    env_lookup_std_env_var_needs_its_delimiter_8855,
    ENV_RUST_STD_VAR
);
env_lookup_cell!(
    env_lookup_process_env_needs_its_delimiter_8855,
    ENV_NODE_PROCESS
);
env_lookup_cell!(
    env_lookup_ruby_env_index_needs_its_delimiter_8855,
    ENV_RUBY_INDEX
);
env_lookup_cell!(
    env_lookup_ruby_env_fetch_needs_its_delimiter_8855,
    ENV_RUBY_FETCH
);
env_lookup_cell!(
    env_lookup_java_getenv_needs_its_delimiter_8855,
    ENV_JAVA_GETENV
);
env_lookup_cell!(
    env_lookup_dotnet_getenv_needs_its_delimiter_8855,
    ENV_DOTNET_GET
);

/// Pin: the Perl hash lookup stays accepted; `$ENV_<x>` is the `$IDENT`
/// placeholder shape, not this entry, and stays accepted as that shape.
#[test]
fn env_lookup_perl_env_hash_delimited_form_pinned_8855() {
    for op in ENV_CELL_OPERATORS {
        assert_delimited_lookups_accepted(&ENV_PERL_HASH, op);
        let shell_ref = format!("password{op}{}{IDENT_EXTENSION}X tail", ENV_PERL_HASH.head);
        assert_eq!(
            kinds_of(&shell_ref),
            Vec::<&str>::new(),
            "8855 r4c: {shell_ref:?} is the $IDENT shape"
        );
    }
}
