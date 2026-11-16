// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8855 round 2 (conductor ruling a339bd79): the credential screen fails
//! closed by construction.
//!
//! - the reviewers' round-1 attack table (security and code lenses), one
//!   cell per row;
//! - the invariant cells for (a) key affixes, (b) the pure-reference value
//!   proof, (c) the RFC 3986 scheme grammar, (d) the nesting depth and size
//!   bounds and (e) the re-screen that refuses a still-hit copy;
//! - a generative table over key affixes x value forms x container forms;
//! - 100K-input wall-clock ceilings for the screen and for the funnel
//!   (redaction plus re-screen plus store);
//! - the SQLite write funnel and the federation receive funnel refuse a
//!   residual with the exact reason and store no row.
//!
//! Every secret is a synthetic constant split with `concat!`. No failure
//! message prints an input or an output: each names a cell id and the first
//! bytes of the input's SHA-256 (engineering-standards, secrets in output).
#![allow(clippy::too_many_lines)]

use std::time::{Duration, Instant};

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::secret_screen::{
    KIND_DEPTH_BOUND, KIND_RESIDUAL, KIND_SIZE_BOUND, MAX_NESTED_SCREEN_DEPTH,
    MAX_VIEW_SCREEN_BYTES, REDACTION_PLACEHOLDER, ScreenOutcome, SecretScreenMode, screen,
    set_screen_mode,
};
use sha2::{Digest, Sha256};

/// Security-lens synthetic password.
const PW: &str = concat!("Xk9m", "Q2vLp7Rw");
/// Code-lens synthetic password.
const PW_CODE: &str = concat!("Zq8", "vN2pL7xR4t");
const SLACK_BODY: &str = concat!("1234567890", "-", "AbCdEfGhIjKlMnOp");
const STRIPE_BODY: &str = concat!("4eC39Hq", "LyjWDarjtT1zdp7dc");
const WEBHOOK_BODY: &str = concat!("Xk9mQ2vL", "p7RwAbCdEfGh");
/// `PW` base64-encoded (the reviewer's base64 row).
const PW_B64: &str = concat!("WGs5bVEy", "dkxwN1J3");

/// Wall-clock ceiling for one screen of a [`BOUND_INPUT_CHARS`] input.
const LINEAR_SCAN_CEILING: Duration = Duration::from_secs(2);
/// Wall-clock ceiling for one funnel write (screen, redaction, re-screen and
/// the SQLite insert) of a [`BOUND_INPUT_CHARS`] input.
const FUNNEL_WRITE_CEILING: Duration = Duration::from_secs(4);
/// The size of the bound inputs.
const BOUND_INPUT_CHARS: usize = 100_000;

const KIND_PASSWORD: &str = "password_assignment";

/// The exact refusal reason a write funnel returns for a residual.
fn residual_reason(kinds: &[&str]) -> String {
    format!(
        "content rejected: credential material remains after redaction ({}); \
         the write is refused and no row is stored",
        kinds.join(", ")
    )
}

/// `cell=<id> sha256=<first 12 hex>`: the only identification a failure
/// message carries.
fn tag(cell: &str, input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let hex = hex::encode(&digest[..6]);
    format!("cell={cell} sha256={hex}")
}

/// What a cell expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// A hit whose redacted copy no longer holds the named secret.
    Masked(&'static str),
    /// No hit.
    Clean,
}

struct Cell {
    id: String,
    input: String,
    want: Want,
}

fn cell(id: &str, input: String, want: Want) -> Cell {
    Cell {
        id: id.to_string(),
        input,
        want,
    }
}

/// `None` when the cell holds; otherwise the failure line (no secret).
fn check(c: &Cell) -> Option<String> {
    match (screen(&c.input), c.want) {
        (ScreenOutcome::Clean, Want::Clean) => None,
        (ScreenOutcome::Clean, Want::Masked(_)) => Some(format!(
            "{}: expected a hit, got Clean",
            tag(&c.id, &c.input)
        )),
        (ScreenOutcome::Hit { kinds, .. }, Want::Clean) => Some(format!(
            "{}: expected Clean, got kinds {kinds:?}",
            tag(&c.id, &c.input)
        )),
        (ScreenOutcome::Hit { kinds, redacted }, Want::Masked(secret)) => {
            redacted.contains(secret).then(|| {
                format!(
                    "{}: kinds {kinds:?} but the secret survives the redacted copy",
                    tag(&c.id, &c.input)
                )
            })
        }
    }
}

fn assert_cells(table: &str, cells: &[Cell]) {
    let failures: Vec<String> = cells.iter().filter_map(check).collect();
    assert!(
        failures.is_empty(),
        "{table}: {} of {} cells failed:\n{}",
        failures.len(),
        cells.len(),
        failures.join("\n")
    );
}

/// The security lens's round-1 table (REVIEW-9363-sec-r1, H1-H8, M1-M5,
/// L1-L3), every row.
fn security_attack_table() -> Vec<Cell> {
    use Want::{Clean, Masked};
    let m = Masked(PW);
    let xb = concat!("xo", "xb-");
    let skl = concat!("sk", "_live_");
    let mut v = Vec::new();
    let mut p = |id: &str, input: String, want: Want| v.push(cell(id, input, want));
    // URL userinfo (#9368, #9373).
    p(
        "url.control.postgres",
        format!("postgres://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.sqlalchemy.psycopg2",
        format!("postgresql+psycopg2://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.sqlalchemy.pymysql",
        format!("mysql+pymysql://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.sqlalchemy.asyncpg",
        format!("postgresql+asyncpg://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.jdbc.postgresql",
        format!("jdbc:postgresql://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.mariadb",
        format!("mariadb://svc:{PW}@db.internal/x"),
        m,
    );
    p("url.mssql", format!("mssql://svc:{PW}@db.internal/x"), m);
    p(
        "url.sqlserver",
        format!("sqlserver://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.cockroachdb",
        format!("cockroachdb://svc:{PW}@db.internal/x"),
        m,
    );
    p("url.nats", format!("nats://svc:{PW}@mq.internal:4222"), m);
    p("url.mqtt", format!("mqtt://svc:{PW}@mq.internal:1883"), m);
    p(
        "url.https.basic",
        format!("https://svc:{PW}@api.internal/v1"),
        m,
    );
    p("url.ftp", format!("ftp://svc:{PW}@files.internal/"), m);
    p("url.ldap", format!("ldap://cn=svc:{PW}@dir.internal/"), m);
    p(
        "url.pw.with.at",
        format!("postgres://svc:{PW}@x@db.internal/x"),
        m,
    );
    p(
        "url.pw.unicode",
        format!("postgres://svc:P\u{e4}ss{PW}\u{f6}@db.internal/x"),
        m,
    );
    p(
        "url.percent.whole",
        format!("postgres%3A%2F%2Fsvc%3A{PW}%40db.internal%2Fx"),
        m,
    );
    p(
        "url.zw.in.scheme",
        format!("post\u{200b}gres://svc:{PW}@db.internal/x"),
        m,
    );
    p(
        "url.quoted.json",
        format!("{{\"dsn\":\"redis://:{PW}@cache:6379/0\"}}"),
        m,
    );
    p(
        "url.env.line",
        format!("DATABASE_URL=postgres://svc:{PW}@db/x"),
        m,
    );
    p(
        "url.neg.no.pw",
        "postgres://svc@db.internal/x".to_string(),
        Clean,
    );
    // Password assignment (#9369, #9370, #9371, #9373).
    p("pw.control.eq", format!("password={PW}"), m);
    p(
        "pw.json.escaped",
        format!("{{\\\"password\\\":\\\"{PW}\\\"}}"),
        m,
    );
    p(
        "pw.odbc.brace",
        format!("Driver={{ODBC}};Server=db;PWD={{{PW}}};"),
        m,
    );
    p("pw.odbc.plain", format!("Server=db;Uid=svc;Pwd={PW};"), m);
    p(
        "pw.shell.default",
        format!("password: ${{DB_PASS:-{PW}}}"),
        m,
    );
    p(
        "pw.dollar.brace.sandwich",
        format!("password=${{A}}{PW}${{B}}"),
        m,
    );
    p(
        "pw.yaml.nextline",
        format!("db:\n  password:\n    {PW}\n"),
        m,
    );
    p("pw.yaml.block", format!("password: |\n  {PW}\n"), m);
    p("pw.yaml.folded", format!("password: >-\n  {PW}\n"), m);
    p(
        "pw.py.getenv.fallback",
        format!("password = os.getenv(\"DB_PASS\", \"{PW}\")"),
        m,
    );
    p(
        "pw.py.environ.get.fallback",
        format!("password = os.environ.get(\"DB_PASS\", \"{PW}\")"),
        m,
    );
    p(
        "pw.py.environ.or",
        format!("password = os.environ[\"DB_PASS\"] or \"{PW}\""),
        m,
    );
    p(
        "pw.js.env.or",
        format!("password: process.env.DB_PASS || \"{PW}\""),
        m,
    );
    p(
        "pw.js.env.nullish",
        format!("const password = process.env.DB_PASS ?? '{PW}';"),
        m,
    );
    p(
        "pw.rust.unwrap_or",
        format!("let password = std::env::var(\"P\").unwrap_or(\"{PW}\".into());"),
        m,
    );
    p(
        "pw.annot.then.second",
        format!("password: String pwd: {PW}"),
        m,
    );
    p(
        "pw.annot.then.second.eq",
        format!("password: String, pwd={PW}"),
        m,
    );
    p(
        "pw.fn.arg",
        format!("props.setProperty(\"password\", \"{PW}\");"),
        m,
    );
    p("pw.xml", format!("<password>{PW}</password>"), m);
    p("pw.xml.attr", format!("<db password=\"{PW}\"/>"), m);
    p("pw.cli.flag", format!("mysql --password {PW} -h db"), m);
    p("pw.cli.flag.eq", format!("mysql --password={PW} -h db"), m);
    p("pw.netrc", format!("machine db login svc password {PW}"), m);
    p("pw.suffix.2", format!("password2={PW}"), m);
    p("pw.suffix.prod", format!("DB_PASSWORD_PROD={PW}"), m);
    p("pw.suffix.camel", format!("passwordConfirm: {PW}"), m);
    p("pw.ps.env", format!("$env:DB_PASSWORD = \"{PW}\""), m);
    p(
        "pw.export.quoted",
        format!("export DB_PASSWORD=\"{PW}\""),
        m,
    );
    p("pw.cmd.set", format!("set PASSWORD={PW}"), m);
    p("pw.toml", format!("[db]\npassword = \"{PW}\""), m);
    p("pw.tabs", format!("password\t=\t{PW}"), m);
    p("pw.nospace.colon", format!("pwd:{PW}"), m);
    p("pw.line.cont", format!("password = \\\n    {PW}"), m);
    p("pw.crlf", format!("password =\r\n{PW}"), m);
    p("pw.eq.newline", format!("password =\n{PW}"), m);
    p("pw.zw.in.key", format!("pass\u{200b}word={PW}"), m);
    p("pw.bom.before", format!("\u{feff}password={PW}"), m);
    p("pw.zw.before.value", format!("password=\u{200b}{PW}"), m);
    p("pw.bidi.before.value", format!("password=\u{202e}{PW}"), m);
    p("pw.zw.before.op", format!("password\u{200b}={PW}"), m);
    p(
        "pw.fullwidth.key",
        format!("\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff4f}\u{ff52}\u{ff44}={PW}"),
        m,
    );
    p("pw.fullwidth.eq", format!("password\u{ff1d}{PW}"), m);
    p("pw.fullwidth.colon", format!("password\u{ff1a}{PW}"), m);
    p("pw.cyrillic.a", format!("p\u{430}ssword={PW}"), m);
    p("pw.angle.wrapped", format!("password=<{PW}>"), m);
    p("pw.unterminated.dq", format!("password: \"{PW}"), m);
    p("pw.mixed.quotes", format!("password='{PW}\""), m);
    p("pw.backtick", format!("password=`{PW}`"), m);
    p("pw.py.dict", format!("{{'password': '{PW}'}}"), m);
    p(
        "pw.py.kwarg",
        format!("connect(host='db', password='{PW}')"),
        m,
    );
    p("pw.go.struct", format!("Password: \"{PW}\","), m);
    p("pw.rust.let", format!("let password = \"{PW}\";"), m);
    p("pw.compare", format!("if password == \"{PW}\" {{"), m);
    p(
        "pw.query.string",
        format!("https://h/login?user=svc&password={PW}&x=1"),
        m,
    );
    p(
        "pw.query.percent",
        format!("user%3Dsvc%26password%3D{PW}"),
        m,
    );
    p(
        "pw.base64.value",
        format!("password={PW_B64}"),
        Masked(PW_B64),
    );
    p("pw.hex.value", format!("password=0x58{PW}"), m);
    p(
        "pw.fstring.hole.then.secret",
        format!("password={{pw}}{PW}"),
        m,
    );
    p(
        "pw.neg.env.lookup",
        "password = os.environ[\"DB_PASS\"]".to_string(),
        Clean,
    );
    p("pw.neg.dollar", "password=$DB_PASS".to_string(), Clean);
    p("pw.neg.stars", "password: ********".to_string(), Clean);
    // Slack (#9372).
    let ms = Masked(SLACK_BODY);
    p("slack.control", format!("token {xb}{SLACK_BODY}"), ms);
    p(
        "slack.after.eq",
        format!("SLACK_TOKEN={xb}{SLACK_BODY}"),
        ms,
    );
    p("slack.quoted", format!("\"{xb}{SLACK_BODY}\""), ms);
    p(
        "slack.upper",
        format!("token {}{SLACK_BODY}", concat!("XO", "XB-")),
        ms,
    );
    p(
        "slack.xoxe",
        format!("token {}{SLACK_BODY}", concat!("xo", "xe-")),
        ms,
    );
    p(
        "slack.xoxe.xoxp",
        format!("token {}{SLACK_BODY}", concat!("xo", "xe.xo", "xp-")),
        ms,
    );
    p(
        "slack.xapp",
        format!("token {}1-A0123456789-{SLACK_BODY}", concat!("xa", "pp-")),
        ms,
    );
    p(
        "slack.webhook",
        format!("https://hooks.slack.com/services/T0123ABCD/B0123ABCD/{WEBHOOK_BODY}"),
        Masked(WEBHOOK_BODY),
    );
    p("slack.neg.wordtwin", format!("abc{xb}{SLACK_BODY}"), Clean);
    // Stripe (#9372).
    let mk = Masked(STRIPE_BODY);
    p("stripe.control", format!("key {skl}{STRIPE_BODY}"), mk);
    p(
        "stripe.rk",
        format!("key {}{STRIPE_BODY}", concat!("rk", "_live_")),
        mk,
    );
    p(
        "stripe.upper",
        format!("key {}{STRIPE_BODY}", concat!("SK", "_LIVE_")),
        mk,
    );
    p(
        "stripe.whsec",
        format!("key {}{STRIPE_BODY}", concat!("wh", "sec_")),
        mk,
    );
    p(
        "stripe.test",
        format!("key {}{STRIPE_BODY}", concat!("sk", "_test_")),
        mk,
    );
    p(
        "stripe.quoted.json",
        format!("{{\"k\":\"{skl}{STRIPE_BODY}\"}}"),
        mk,
    );
    p(
        "stripe.neg.pk",
        format!("key {}{STRIPE_BODY}", concat!("pk", "_live_")),
        Clean,
    );
    v
}

/// The code lens's round-1 probe cells (REVIEW-9363-code-r1, H1 and the
/// controls), plus the RFC 3986 scheme grammar cells of invariant (c).
fn code_probe_and_scheme_table() -> Vec<Cell> {
    use Want::{Clean, Masked};
    let m = Masked(PW_CODE);
    let mut v = Vec::new();
    for scheme in [
        "postgresql+psycopg2",
        "mysql+pymysql",
        "postgresql+asyncpg",
        "mongodb+srv",
        "POSTGRES",
        "svn+ssh",
        "coap+tcp",
        "x-custom.v2",
        "z39.50r",
        "a",
    ] {
        v.push(cell(
            &format!("scheme.{scheme}"),
            format!("{scheme}://svc:{PW_CODE}@db.internal/app"),
            m,
        ));
    }
    v.push(cell(
        "scheme.redis.empty.user",
        format!("redis://:{PW_CODE}@cache.internal:6379"),
        m,
    ));
    // A very long valid scheme: ALPHA then 4096 scheme bytes.
    let long_scheme = format!("a{}", "b+.-9".repeat(4096 / 5));
    v.push(cell(
        "scheme.very.long.valid",
        format!("{long_scheme}://svc:{PW_CODE}@h/x"),
        m,
    ));
    // Not a scheme: a scheme must start with ALPHA, so the run before
    // `://` that starts with a digit has no scheme; the userinfo is then
    // judged as text after `://`, which still carries a password.
    v.push(cell(
        "scheme.digit.start",
        format!("9db://svc:{PW_CODE}@h/x"),
        m,
    ));
    v.push(cell(
        "scheme.neg.no.password",
        "postgresql+psycopg2://svc@h/x".to_string(),
        Clean,
    ));
    v.push(cell(
        "scheme.neg.prose",
        "see https://example.com/docs for more".to_string(),
        Clean,
    ));
    v
}

/// Invariant (b): the values that ARE proven pure references (or carry no
/// information) stay clean; every value with a literal part is a finding.
fn value_proof_table() -> Vec<Cell> {
    use Want::{Clean, Masked};
    let m = Masked(PW);
    let mut v = Vec::new();
    for (id, value) in [
        ("dollar", "$DB_PASS"),
        ("brace", "${DB_PASS}"),
        ("quoted.brace", "\"${DB_PASS}\""),
        ("env.lookup", "os.environ[\"DB_PASS\"]"),
        ("process.env", "process.env.DB_PASS"),
        ("stars", "********"),
        ("placeholder", REDACTION_PLACEHOLDER),
        ("quoted.placeholder", "\"[REDACTED:secret]\""),
        ("null", "null"),
        ("none", "None"),
        ("ellipsis", "..."),
    ] {
        v.push(cell(
            &format!("b.clean.{id}"),
            format!("password = {value}"),
            Clean,
        ));
    }
    v.push(cell(
        "b.clean.annotation",
        "struct Db { password: String }".to_string(),
        Clean,
    ));
    v.push(cell(
        "b.clean.fn.param",
        "fn connect(pwd: &str) -> Conn".to_string(),
        Clean,
    ));
    v.push(cell(
        "b.clean.key.only.prose",
        "rotate the password_hash column".to_string(),
        Clean,
    ));
    for (id, value) in [
        ("angle", format!("<{PW}>")),
        ("format.hole", format!("{{{PW}}}")),
        ("brace.default", format!("${{X:-{PW}}}")),
        ("brace.alt", format!("${{X:={PW}}}")),
        ("brace.sandwich", format!("${{A}}{PW}")),
        ("literal.beside.ref", format!("$A{PW}")),
        ("or", format!("$A or {PW}")),
        ("pipe.pipe", format!("$A || {PW}")),
        ("nullish", format!("$A ?? {PW}")),
        ("stars.then.literal", format!("***{PW}")),
        ("quoted", format!("\"{PW}\"")),
        ("annotation.initializer", format!("String = \"{PW}\"")),
    ] {
        v.push(cell(
            &format!("b.finding.{id}"),
            format!("password = {value}"),
            m,
        ));
    }
    v
}

// ── Generative table (key affixes x value forms x container forms) ────────

/// Credential-named keys: the word with prefixes, suffixes, case and
/// separators (invariant (a)).
const KEY_AFFIXES: [&str; 12] = [
    "password",
    "Password",
    "PASSWORD",
    "db_password",
    "DB_PASSWORD_PROD",
    "password2",
    "passwordConfirm",
    "pwd",
    "PWD",
    "passwd",
    "user-password",
    "app.password",
];

/// Value forms that carry the literal `PW` (each is a finding, invariant
/// (b)); `{PW}` is substituted.
const LITERAL_VALUE_FORMS: [&str; 11] = [
    "{PW}",
    "\"{PW}\"",
    "'{PW}'",
    "${X:-{PW}}",
    "${A}{PW}",
    "{{PW}}",
    "<{PW}>",
    "os.getenv(\"X\", \"{PW}\")",
    "$X || \"{PW}\"",
    "process.env.X ?? \"{PW}\"",
    "os.environ[\"X\"] or \"{PW}\"",
];

/// Value forms that are pure references (each is clean).
const PURE_REFERENCE_FORMS: [&str; 4] = [
    "$DB_PASS",
    "${DB_PASS}",
    "os.environ[\"DB_PASS\"]",
    "process.env.DB_PASS",
];

/// Containers a key and value appear in.
#[derive(Debug, Clone, Copy)]
enum Container {
    Env,
    Yaml,
    YamlBlock,
    YamlNextLine,
    Json,
    NestedJson,
    Toml,
    ShellExport,
    UrlQuery,
}

const LITERAL_CONTAINERS: [Container; 9] = [
    Container::Env,
    Container::Yaml,
    Container::YamlBlock,
    Container::YamlNextLine,
    Container::Json,
    Container::NestedJson,
    Container::Toml,
    Container::ShellExport,
    Container::UrlQuery,
];

/// Containers whose syntax holds a bare reference.
const REFERENCE_CONTAINERS: [Container; 4] = [
    Container::Env,
    Container::Yaml,
    Container::Toml,
    Container::ShellExport,
];

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

fn contain(container: Container, key: &str, value: &str) -> String {
    match container {
        Container::Env => format!("{key}={value}\n"),
        Container::Yaml => format!("db:\n  {key}: {value}\n"),
        Container::YamlBlock => format!("db:\n  {key}: |\n    {value}\n  host: h\n"),
        Container::YamlNextLine => format!("db:\n  {key}:\n    {value}\n"),
        Container::Json => format!("{{\"{key}\": {}}}", json_string(value)),
        Container::NestedJson => {
            let inner = format!("{{\"{key}\": {}}}", json_string(value));
            format!("{{\"cfg\": {}}}", json_string(&inner))
        }
        Container::Toml => format!("[db]\n{key} = {value}\n"),
        Container::ShellExport => format!("export {key}={value}\n"),
        Container::UrlQuery => format!("https://h/login?user=svc&{key}={value}&x=1"),
    }
}

fn generative_positive_table() -> Vec<Cell> {
    let mut v = Vec::new();
    for key in KEY_AFFIXES {
        for (fi, form) in LITERAL_VALUE_FORMS.iter().enumerate() {
            let value = form.replace("{PW}", PW);
            for container in LITERAL_CONTAINERS {
                v.push(cell(
                    &format!("gen.{key}.form{fi}.{container:?}"),
                    contain(container, key, &value),
                    Want::Masked(PW),
                ));
            }
        }
    }
    v
}

fn generative_negative_table() -> Vec<Cell> {
    let mut v = Vec::new();
    for key in KEY_AFFIXES {
        for (fi, form) in PURE_REFERENCE_FORMS.iter().enumerate() {
            for container in REFERENCE_CONTAINERS {
                v.push(cell(
                    &format!("gen.neg.{key}.ref{fi}.{container:?}"),
                    contain(container, key, form),
                    Want::Clean,
                ));
            }
        }
    }
    v
}

#[test]
fn security_attack_table_round2_8855() {
    assert_cells("security attack table", &security_attack_table());
}

#[test]
fn code_probe_and_scheme_grammar_round2_8855() {
    assert_cells(
        "code probe and scheme grammar",
        &code_probe_and_scheme_table(),
    );
}

#[test]
fn value_side_pure_reference_proof_round2_8855() {
    assert_cells("value proof", &value_proof_table());
}

#[test]
fn generative_key_value_container_positive_round2_8855() {
    let cells = generative_positive_table();
    assert_eq!(
        cells.len(),
        KEY_AFFIXES.len() * LITERAL_VALUE_FORMS.len() * LITERAL_CONTAINERS.len()
    );
    assert_cells("generative positive", &cells);
}

#[test]
fn generative_key_value_container_negative_round2_8855() {
    let cells = generative_negative_table();
    assert_eq!(
        cells.len(),
        KEY_AFFIXES.len() * PURE_REFERENCE_FORMS.len() * REFERENCE_CONTAINERS.len()
    );
    assert_cells("generative negative", &cells);
}

// ── (d) nesting bounds ─────────────────────────────────────────────────────

/// A JSON document whose password key is spelled with a JSON unicode escape
/// (so only the unescaped view shows the key), wrapped `levels` times in a
/// JSON string value.
fn nested_unicode_key(levels: usize) -> String {
    let mut doc = format!("{{\"\\u0070assword\": \"{PW}\"}}");
    for _ in 0..levels {
        doc = format!("{{\"cfg\": {}}}", json_string(&doc));
    }
    doc
}

fn kinds_and_redacted(input: &str) -> (Vec<&'static str>, String) {
    match screen(input) {
        ScreenOutcome::Clean => (Vec::new(), input.to_string()),
        ScreenOutcome::Hit { kinds, redacted } => (kinds, redacted),
    }
}

#[test]
fn nested_depth_bound_at_and_past_round2_8855() {
    // Level 0 is the raw text; the unicode escape is resolved by the first
    // unescape, so `levels` wrappers need `levels + 1` unescapes.
    let at = nested_unicode_key(MAX_NESTED_SCREEN_DEPTH - 1);
    let (kinds, redacted) = kinds_and_redacted(&at);
    assert!(
        kinds.contains(&KIND_PASSWORD) && kinds.contains(&KIND_RESIDUAL),
        "{}: kinds {kinds:?}",
        tag("d.depth.at.bound", &at)
    );
    assert_eq!(
        redacted,
        REDACTION_PLACEHOLDER,
        "{}",
        tag("d.depth.at.bound", &at)
    );

    let past = nested_unicode_key(MAX_NESTED_SCREEN_DEPTH);
    let (kinds, redacted) = kinds_and_redacted(&past);
    assert!(
        kinds.contains(&KIND_DEPTH_BOUND) && kinds.contains(&KIND_RESIDUAL),
        "{}: kinds {kinds:?}",
        tag("d.depth.past.bound", &past)
    );
    assert_eq!(
        redacted,
        REDACTION_PLACEHOLDER,
        "{}",
        tag("d.depth.past.bound", &past)
    );
}

#[test]
fn nested_size_bound_at_and_past_round2_8855() {
    let core = nested_unicode_key(1);
    let pad = |total: usize| format!("{core}{}", " ".repeat(total.saturating_sub(core.len())));
    let at = pad(MAX_VIEW_SCREEN_BYTES);
    assert_eq!(at.len(), MAX_VIEW_SCREEN_BYTES);
    let (kinds, _) = kinds_and_redacted(&at);
    assert!(
        kinds.contains(&KIND_PASSWORD) && kinds.contains(&KIND_RESIDUAL),
        "{}: kinds {kinds:?}",
        tag("d.size.at.bound", "size-at")
    );
    let past = pad(MAX_VIEW_SCREEN_BYTES + 1);
    let (kinds, redacted) = kinds_and_redacted(&past);
    assert!(
        kinds.contains(&KIND_SIZE_BOUND) && kinds.contains(&KIND_RESIDUAL),
        "{}: kinds {kinds:?}",
        tag("d.size.past.bound", "size-past")
    );
    assert_eq!(
        redacted,
        REDACTION_PLACEHOLDER,
        "{}",
        tag("d.size.past.bound", "size-past")
    );
}

// ── 100K bounds ────────────────────────────────────────────────────────────

/// Adversarial shapes at [`BOUND_INPUT_CHARS`] (the security lens's cost
/// table plus the new grammar's worst cases).
fn bound_shapes() -> Vec<(&'static str, String)> {
    let n = BOUND_INPUT_CHARS;
    let rep = |unit: &str| unit.repeat(n / unit.len().max(1));
    vec![
        ("password.noop", rep("password ")),
        ("password.eq", rep("password=")),
        ("password.colon.newline", rep("password:\n")),
        ("password.block", rep("password: |\n")),
        ("password.cont", rep("password = \\\n")),
        ("pwd.run", rep("pwd")),
        ("password.annot", rep("password: String ")),
        (
            "password.dq.escapes",
            format!("password=\"{}", "\\\\".repeat(n / 2)),
        ),
        ("password.backslash.quotes", rep("password\\\"")),
        ("password.quotes", rep("password='\"")),
        (
            "dollar.brace",
            format!("password=${{{}", "${".repeat(n / 2)),
        ),
        ("scheme.noat", rep("postgres://")),
        (
            "scheme.colons",
            format!("postgres://{}", "a:".repeat(n / 2)),
        ),
        (
            "scheme.colons.ats",
            format!("postgres://{}{}", ":".repeat(n / 2), "@".repeat(n / 2)),
        ),
        ("scheme.plus.run", format!("{}://a:b@h", "+".repeat(n))),
        ("scheme.alpha.run", format!("{}://a:b@h", "a".repeat(n))),
        ("scheme.many.short", rep("a://")),
        ("nested.escapes", rep("\\\\\\\"password")),
        ("percent.run", rep("%3D%26")),
        ("zero.width.run", rep("p\u{200b}assword=")),
        ("fullwidth.run", rep("\u{ff50}\u{ff1d}")),
        ("slack.prefix", rep("xoxb-")),
        ("stripe.prefix", rep("sk_live_")),
        ("mixed", rep("postgres://a:password=xoxb-sk_live_\"'${<")),
        ("multibyte", rep("p\u{e4}ssword=\u{1f600}")),
    ]
}

#[test]
fn screen_is_linear_on_100k_inputs_round2_8855() {
    let mut slow = Vec::new();
    for (id, input) in bound_shapes() {
        assert!(
            input.len() >= BOUND_INPUT_CHARS / 2,
            "cell={id}: shape too small"
        );
        let start = Instant::now();
        let _ = screen(&input);
        let took = start.elapsed();
        if took > LINEAR_SCAN_CEILING {
            slow.push(format!(
                "{}: {took:?} > {LINEAR_SCAN_CEILING:?}",
                tag(id, &input)
            ));
        }
    }
    assert!(
        slow.is_empty(),
        "screen over the ceiling:\n{}",
        slow.join("\n")
    );
}

// ── (e) the write funnels refuse a residual and store no row ──────────────

fn mem(namespace: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: "round2 funnel cell".to_string(),
        content: content.to_string(),
        tags: vec!["round2-8855".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Inputs whose redacted copy still screens as a hit, with the exact kinds
/// the refusal names.
fn residual_cells() -> Vec<(&'static str, String, Vec<&'static str>)> {
    vec![
        (
            "e.zw.in.key",
            format!("pass\u{200b}word={PW}"),
            vec![KIND_PASSWORD, KIND_RESIDUAL],
        ),
        (
            "e.fullwidth.key",
            format!("\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff4f}\u{ff52}\u{ff44}={PW}"),
            vec![KIND_PASSWORD, KIND_RESIDUAL],
        ),
        (
            "e.percent.url",
            format!("postgres%3A%2F%2Fsvc%3A{PW}%40db.internal%2Fx"),
            vec![KIND_RESIDUAL, "url_userinfo_password"],
        ),
        (
            "e.nested.unicode.key",
            nested_unicode_key(1),
            vec![KIND_PASSWORD, KIND_RESIDUAL],
        ),
        (
            "e.depth.past.bound",
            nested_unicode_key(MAX_NESTED_SCREEN_DEPTH),
            vec![KIND_DEPTH_BOUND, KIND_RESIDUAL],
        ),
    ]
}

#[test]
fn sqlite_write_and_receive_funnels_refuse_residual_round2_8855() {
    set_screen_mode(SecretScreenMode::Redact);
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("round2.db")).expect("open db");
    let mut failures = Vec::new();
    for (id, input, kinds) in residual_cells() {
        let want = residual_reason(&kinds);
        for (funnel, result) in [
            ("insert", db::insert(&conn, &mem("round2-insert", &input))),
            (
                "insert_if_newer",
                db::insert_if_newer(&conn, &mem("round2-receive", &input)),
            ),
        ] {
            match result {
                Ok(stored_id) => {
                    let row = db::get(&conn, &stored_id).ok().flatten();
                    failures.push(format!(
                        "{} via {funnel}: stored (row present: {}), expected refusal",
                        tag(id, &input),
                        row.is_some()
                    ));
                }
                Err(e) if e.to_string() == want => {}
                Err(e) => failures.push(format!(
                    "{} via {funnel}: refused with a different reason (len {})",
                    tag(id, &input),
                    e.to_string().len()
                )),
            }
        }
    }
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace LIKE 'round2-%'",
            [],
            |r| r.get(0),
        )
        .expect("count rows");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(rows, 0, "cell=e.no.row: a refused write left a row");
}

#[test]
fn sqlite_funnel_100k_redaction_and_rescreen_ceiling_round2_8855() {
    set_screen_mode(SecretScreenMode::Redact);
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("round2-bound.db")).expect("open db");
    let filler = "lorem ipsum ".repeat(BOUND_INPUT_CHARS / 12);
    let input = format!("{filler}\npassword: |\n  {PW}\n{filler}");
    assert!(input.len() >= BOUND_INPUT_CHARS);
    let start = Instant::now();
    let id = db::insert(&conn, &mem("round2-bound", &input));
    let took = start.elapsed();
    let id = id.unwrap_or_else(|e| {
        panic!(
            "{}: refused (reason len {})",
            tag("e.bound.100k.masked", &input),
            e.to_string().len()
        )
    });
    assert!(
        took <= FUNNEL_WRITE_CEILING,
        "{}: {took:?} > {FUNNEL_WRITE_CEILING:?}",
        tag("e.bound.100k.masked", &input)
    );
    let row = db::get(&conn, &id).ok().flatten();
    let stored = row.map(|m| m.content).unwrap_or_default();
    assert!(
        !stored.contains(PW) && stored.contains(REDACTION_PLACEHOLDER),
        "{}: the stored copy is not masked",
        tag("e.bound.100k.masked", &input)
    );
}
