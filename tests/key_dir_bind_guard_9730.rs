//! #9730 - class guard for `src/cli/store.rs`: in the test code of that file the
//! key-dir variable is set only inside `bind_key_dir` and
//! `env_var_guard_restores_previous_value_on_drop`, whatever the spelling, and an
//! env-setter the scanner cannot classify is a violation. A new sign test that
//! skips the helper fails here in every run.
//!
//! This is its own test binary (own process) on purpose: the guard's fixtures
//! spell the setter forms as text, and `scripts/check-test-env-lock.sh` arm (d)
//! counts that text per file in the lib test binary (#3475). Nothing here
//! mutates the process environment.

/// #9730 — the pure guard: every violation found in `src`, as exact reasons.
///
/// Decision (fail closed by construction): the text is whitespace
/// normalised, then EVERY env-setter call (`set_var(` and
/// `EnvVarGuard::set(`) is classified by its first argument. The key-dir
/// variable (literal or `KEY_DIR_ENV` constant) is allowed only inside the
/// two named sites; a first argument that is neither a plain string
/// literal nor a name in [`KNOWN_NAME_ARGS`] is a violation, never a pass.
fn key_dir_guard_violations(src: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for setter in scan_env_setters(src) {
        match classify_arg(&setter.arg) {
            ArgKind::KeyDir => {
                let site = setter.fn_name.as_deref().unwrap_or(NO_ENCLOSING_FN);
                if !KEY_DIR_ALLOWED_FNS.contains(&site) {
                    violations.push(format!(
                        "key-dir variable set in `{site}` via `{}` with `{}`; go through bind_key_dir (#9730)",
                        setter.form, setter.arg
                    ));
                }
            }
            ArgKind::OtherLiteral | ArgKind::KnownName => {}
            ArgKind::Unknown => violations.push(format!(
                "unrecognised first argument `{}` to `{}`; use a string literal, a table name or bind_key_dir (#9730)",
                setter.arg, setter.form
            )),
        }
    }
    violations
}

/// Names of the functions that set the key-dir variable (sorted, unique).
fn key_dir_setter_fns(src: &str) -> Vec<String> {
    let mut fns: Vec<String> = scan_env_setters(src)
        .into_iter()
        .filter(|s| matches!(classify_arg(&s.arg), ArgKind::KeyDir))
        .map(|s| s.fn_name.unwrap_or_else(|| NO_ENCLOSING_FN.to_owned()))
        .collect();
    fns.sort();
    fns.dedup();
    fns
}

/// Env-setter call forms the guard scans for.
const SETTER_FORMS: [&str; 2] = ["set_var(", "EnvVarGuard::set("];
/// The key-dir variable as a string literal.
const KEY_DIR_LITERAL: &str = "\"AI_MEMORY_KEY_DIR\"";
/// The key-dir variable as the production constant's last path segment.
const KEY_DIR_CONST_NAME: &str = "KEY_DIR_ENV";
/// Non-literal first arguments that are known not to be the key-dir
/// variable: the parameters inside `EnvVarGuard`'s own `set` and `drop`.
const KNOWN_NAME_ARGS: [&str; 2] = ["key", "self.key"];
/// The only two sites allowed to set the key-dir variable.
const KEY_DIR_ALLOWED_FNS: [&str; 2] = [
    "bind_key_dir",
    "env_var_guard_restores_previous_value_on_drop",
];
/// Site label when a setter sits outside every `fn`.
const NO_ENCLOSING_FN: &str = "<no enclosing fn>";

struct Setter {
    fn_name: Option<String>,
    form: &'static str,
    arg: String,
}

enum ArgKind {
    KeyDir,
    OtherLiteral,
    KnownName,
    Unknown,
}

/// Collapse whitespace runs to one space, then drop spaces next to `(`,
/// `)`, `,` and `:` so a call split over lines or padded with spaces
/// matches the same needle as the one-line form.
fn normalise_ws(src: &str) -> String {
    let mut collapsed: Vec<char> = Vec::with_capacity(src.len());
    let mut pending = false;
    for c in src.chars() {
        if c.is_whitespace() {
            pending = true;
            continue;
        }
        if pending && !collapsed.is_empty() {
            collapsed.push(' ');
        }
        pending = false;
        collapsed.push(c);
    }
    let mut out = String::with_capacity(collapsed.len());
    for (i, &c) in collapsed.iter().enumerate() {
        if c == ' ' {
            let prev = i.checked_sub(1).map(|j| collapsed[j]);
            let next = collapsed.get(i + 1).copied();
            if matches!(prev, Some('(' | ':')) || matches!(next, Some('(' | ')' | ',' | ':')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Every `fn <name>` in `text` as (byte offset, name), in text order.
fn collect_fns(text: &str) -> Vec<(usize, String)> {
    text.match_indices("fn ")
        .filter(|(i, _)| !text[..*i].chars().next_back().is_some_and(is_ident_char))
        .filter_map(|(i, _)| {
            let name: String = text[i + 3..]
                .chars()
                .take_while(|c| is_ident_char(*c))
                .collect();
            (!name.is_empty()).then_some((i, name))
        })
        .collect()
}

/// The text up to the first top-level `,` or the closing `)`.
fn first_arg(args: &str) -> String {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    let mut end = args.len();
    for (i, c) in args.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' | ',' if depth == 0 => {
                end = i;
                break;
            }
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    args[..end].to_owned()
}

/// Every env-setter call in `src`, with its enclosing fn and first argument.
/// Linear in the input apart from a binary search per setter.
fn scan_env_setters(src: &str) -> Vec<Setter> {
    let text = normalise_ws(src);
    let fns = collect_fns(&text);
    let mut out = Vec::new();
    for form in SETTER_FORMS {
        for (pos, _) in text.match_indices(form) {
            if text[..pos].chars().next_back().is_some_and(is_ident_char) {
                continue;
            }
            let idx = fns.partition_point(|(p, _)| *p < pos);
            out.push(Setter {
                fn_name: idx.checked_sub(1).map(|i| fns[i].1.clone()),
                form,
                arg: first_arg(&text[pos + form.len()..]),
            });
        }
    }
    out
}

/// A single string literal: opens and closes with `"`, no unescaped `"` inside.
fn is_plain_literal(arg: &str) -> bool {
    let Some(inner) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) else {
        return false;
    };
    let mut esc = false;
    for c in inner.chars() {
        if esc {
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            return false;
        }
    }
    !esc
}

fn classify_arg(arg: &str) -> ArgKind {
    if arg == KEY_DIR_LITERAL {
        ArgKind::KeyDir
    } else if is_plain_literal(arg) {
        ArgKind::OtherLiteral
    } else if arg.rsplit("::").next() == Some(KEY_DIR_CONST_NAME)
        && arg.chars().all(|c| is_ident_char(c) || c == ':')
    {
        ArgKind::KeyDir
    } else if KNOWN_NAME_ARGS.contains(&arg) {
        ArgKind::KnownName
    } else {
        ArgKind::Unknown
    }
}

/// The test module of `src/cli/store.rs`: from its `mod tests {` header to the
/// end of the file (the module is the last item of that file).
const STORE_SRC: &str = include_str!("../src/cli/store.rs");
const TESTS_MODULE_HEADER: &str = "mod tests {";

/// #9730 — class guard: in the test code of `src/cli/store.rs` the key-dir
/// variable is set only inside `bind_key_dir` and
/// `env_var_guard_restores_previous_value_on_drop` (which tests the guard
/// itself), whatever the spelling; an env-setter the scanner cannot
/// classify is a violation. A new sign test that skips the helper fails
/// here in every run.
#[test]
fn key_dir_override_goes_through_bind_key_dir_9730() {
    let start = STORE_SRC
        .find(TESTS_MODULE_HEADER)
        .expect("tests module header in src/cli/store.rs");
    let region = &STORE_SRC[start..];
    let violations = key_dir_guard_violations(region);
    assert!(violations.is_empty(), "{violations:#?}");
    assert_eq!(
        key_dir_setter_fns(region),
        KEY_DIR_ALLOWED_FNS.map(str::to_owned).to_vec(),
        "both allowed sites must still set the key-dir variable (stale allow-list)"
    );
}

/// #9730 — the scanner is linear: 100K+ of setter-dense text stays fast.
#[test]
fn key_dir_guard_scan_is_bounded_9730() {
    const REPEATS: usize = 6_000;
    const CEILING: std::time::Duration = std::time::Duration::from_secs(5);
    let unit = "fn f() { unsafe { std::env::set_var(KEY_DIR_ENV, p) }; }\n";
    let big = unit.repeat(REPEATS);
    assert!(big.len() >= 100_000);
    let started = std::time::Instant::now();
    let violations = key_dir_guard_violations(&big);
    assert_eq!(violations.len(), REPEATS);
    assert!(
        started.elapsed() < CEILING,
        "scan took {:?}",
        started.elapsed()
    );
}

/// One table row: label, module text, expected violations.
type GuardRow = (&'static str, &'static str, Vec<String>);

fn guard_rows() -> Vec<GuardRow> {
    let raw = |f: &str, form: &str, arg: &str| {
        format!(
            "key-dir variable set in `{f}` via `{form}` with `{arg}`; go through bind_key_dir (#9730)"
        )
    };
    let unknown = |form: &str, arg: &str| {
        format!(
            "unrecognised first argument `{arg}` to `{form}`; use a string literal, a table name or bind_key_dir (#9730)"
        )
    };
    vec![
        (
            "literal through EnvVarGuard::set",
            r#"fn sign_a() { let _g = EnvVarGuard::set("AI_MEMORY_KEY_DIR", p); }"#,
            vec![raw("sign_a", "EnvVarGuard::set(", "\"AI_MEMORY_KEY_DIR\"")],
        ),
        (
            "constant path through EnvVarGuard::set",
            r"fn sign_b() { let _g = EnvVarGuard::set(crate::identity::keypair::KEY_DIR_ENV, p); }",
            vec![raw(
                "sign_b",
                "EnvVarGuard::set(",
                "crate::identity::keypair::KEY_DIR_ENV",
            )],
        ),
        (
            "bare constant through std::env::set_var",
            r"fn sign_c() { unsafe { std::env::set_var(KEY_DIR_ENV, p) }; }",
            vec![raw("sign_c", "set_var(", "KEY_DIR_ENV")],
        ),
        (
            "literal through env::set_var",
            r#"fn sign_d() { unsafe { env::set_var("AI_MEMORY_KEY_DIR", p) }; }"#,
            vec![raw("sign_d", "set_var(", "\"AI_MEMORY_KEY_DIR\"")],
        ),
        (
            "call split over lines with extra whitespace",
            "fn sign_e() {\n  let _g = EnvVarGuard  ::\n   set (\n      KEY_DIR_ENV ,\n   p );\n}",
            vec![raw("sign_e", "EnvVarGuard::set(", "KEY_DIR_ENV")],
        ),
        (
            "unknown expression as first argument",
            r"fn sign_f() { unsafe { std::env::set_var(name_from(x), p) }; }",
            vec![unknown("set_var(", "name_from(x)")],
        ),
        (
            "alias of the variable name",
            r#"fn sign_g() { let k = "AI_MEMORY_KEY_DIR"; unsafe { std::env::set_var(k, p) }; }"#,
            vec![unknown("set_var(", "k")],
        ),
        (
            "key-dir setter outside any fn",
            r"static X: () = set_var(KEY_DIR_ENV, p);",
            vec![raw("<no enclosing fn>", "set_var(", "KEY_DIR_ENV")],
        ),
        (
            "allowed: the helper, literal form",
            r#"fn bind_key_dir(d: &Path) -> G { EnvVarGuard::set("AI_MEMORY_KEY_DIR", d) }"#,
            vec![],
        ),
        (
            "allowed: the guard's own test, constant form",
            r"fn env_var_guard_restores_previous_value_on_drop() { set_var(KEY_DIR_ENV, p); }",
            vec![],
        ),
        (
            "allowed: other variable by literal and by table names",
            r#"fn t() { EnvVarGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", v); set_var(key, val); set_var(self.key, v); }"#,
            vec![],
        ),
        (
            "unknown stays red inside an allowed site",
            r"fn bind_key_dir(d: &Path) { set_var(pick(), d); }",
            vec![unknown("set_var(", "pick()")],
        ),
    ]
}

/// #9730 — table over setter spellings: the guard must report each exactly.
#[test]
fn key_dir_guard_reports_every_setter_spelling_9730() {
    for (label, src, expected) in guard_rows() {
        assert_eq!(key_dir_guard_violations(src), expected, "row: {label}");
    }
}
