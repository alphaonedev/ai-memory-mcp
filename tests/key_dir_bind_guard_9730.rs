//! Key-dir bind guard (#9730, #9803).
//!
//! What the checks do:
//! - Every tracked `.rs` file is lexed: comments are skipped; string, raw,
//!   byte and C string literals are decoded; delimiters are matched. Each token
//!   gets a site: the `fn`, `mod`, `trait`, `struct`, `enum`, `impl` and
//!   `macro_rules!` items around it and the `const`, `static` or `use`
//!   statement it is in, joined with `::` (`<file root>` when there is none).
//! - An identifier equal to the key-dir variable name, its constant or the
//!   bind helper, and a string literal that holds one of them as a name, is
//!   refused unless `ALLOWED_SITES` has a row with that exact file and site.
//!   A string literal that names one in prose (it has whitespace, is not
//!   only the name, and the name is not after `$` or `{` or before `=`) is not
//!   refused.
//! - A string literal or identifier that holds a piece of the variable name is
//!   refused unless `ALLOWED_FRAGMENTS` has a row with that file, site and text.
//! - A file is refused as unclassifiable when it is not UTF-8, is over
//!   `MAX_SOURCE_BYTES`, has an unterminated literal or comment, an unbalanced,
//!   mismatched or unclosed delimiter, nesting over `MAX_NESTING`, an impl
//!   header over `MAX_HEADER_CHARS`, an invalid escape or a stray quote, or
//!   needs more lexer steps than its step ceiling.
//! - A tracked file that is not `.rs` and holds one of the three names is
//!   refused unless its kind is a row of `LEFT_OUT`.
//! - A row of any table that matches nothing is a failure.
//!
//! siblings: src/identity/keypair.rs:173 (the constant), src/identity/keypair.rs:181
//! (its reader), src/identity/test_key_dir.rs:179-193 (`bind_key_dir_env`,
//! `set_key_dir_env`, callers `install` at :108 and the #3584 test at :329),
//! src/cli/store.rs:1280 (the bind helper and its callers in `mod tests`).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

/// The synthetic file name the allow and deny tables are checked under.
const SYN_FILE: &str = "src/synthetic_9730.rs";
/// Lines in the size-bound input.
const SIZE_LINES: usize = 100_000;
/// Wall-clock ceiling for one check of the size-bound input.
const SIZE_WALL_CLOCK_CEILING: Duration = Duration::from_secs(30);
/// A step ceiling far below what any input needs.
const TINY_STEP_CEILING: u64 = 8;

/// The key-dir variable name, built so this file does not spell it.
fn var_token() -> String {
    ["AI", "MEMORY", "KEY", "DIR"].join("_")
}

/// The name of the constant that holds the variable name.
fn const_token() -> String {
    ["KEY", "DIR", "ENV"].join("_")
}

/// The name of the test bind helper.
fn call_token() -> String {
    ["bind", "key", "dir"].join("_")
}

/// The variable name without its `AI_MEMORY_` prefix.
fn frag_token() -> String {
    ["KEY", "DIR"].join("_")
}

/// The variable name without its `_DIR` suffix.
fn prefix_token() -> String {
    ["AI", "MEMORY", "KEY"].join("_")
}

/// Expands the placeholders used in the tables below.
fn expand(template: &str) -> String {
    template
        .replace("@F@", &format!("#9730 guard: {SYN_FILE}"))
        .replace("@V@", &var_token())
        .replace("@C@", &const_token())
        .replace("@B@", &call_token())
        .replace("@K@", &frag_token())
        .replace("@P@", &prefix_token())
}

/// One allowed site: a file and the exact site path inside it.
struct SiteRow {
    file: &'static str,
    site: &'static str,
    reason: &'static str,
}

/// One allowed fragment: a file, a site and the exact literal text.
struct FragmentRow {
    file: &'static str,
    site: &'static str,
    text: &'static str,
    reason: &'static str,
}

/// One kind of non-Rust tracked file that may hold the names.
struct LeftOutRow {
    kind: &'static str,
    reason: &'static str,
}

const ALLOWED_SITES: &[SiteRow] = &[];

const ALLOWED_FRAGMENTS: &[FragmentRow] = &[];

const LEFT_OUT: &[LeftOutRow] = &[];

/// The expanded tables the scanner reads.
#[derive(Default)]
pub struct Tables {
    pub sites: Vec<(String, String)>,
    pub fragments: Vec<(String, String, String)>,
    pub left_out: Vec<String>,
}

/// The rows a run matched, by index into `Tables`.
#[derive(Default)]
pub struct Used {
    pub sites: BTreeSet<usize>,
    pub fragments: BTreeSet<usize>,
    pub left_out: BTreeSet<usize>,
}

fn tree_tables() -> Tables {
    Tables {
        sites: ALLOWED_SITES
            .iter()
            .map(|r| (r.file.to_owned(), expand(r.site)))
            .collect(),
        fragments: ALLOWED_FRAGMENTS
            .iter()
            .map(|r| (r.file.to_owned(), expand(r.site), expand(r.text)))
            .collect(),
        left_out: LEFT_OUT.iter().map(|r| r.kind.to_owned()).collect(),
    }
}

/// The allowed sites of the synthetic file the allow and deny rows use.
fn syn_tables() -> Tables {
    Tables {
        sites: [
            "fn allowed_reader",
            "fn allowed_caller",
            "fn @B@",
            "const @C@",
        ]
        .iter()
        .map(|s| (SYN_FILE.to_owned(), expand(s)))
        .collect(),
        ..Tables::default()
    }
}

mod scan {
    use std::path::Path;

    use super::{Tables, Used};

    /// Largest source file the lexer reads.
    pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
    /// Deepest delimiter nesting the lexer follows.
    pub const MAX_NESTING: usize = 256;
    /// Longest impl header the site path takes.
    pub const MAX_HEADER_CHARS: usize = 256;
    /// Lexer steps allowed per source byte.
    pub const STEPS_PER_BYTE: u64 = 4;
    /// Lexer steps allowed on top of the per-byte budget.
    pub const STEP_SLACK: u64 = 1024;

    /// The step ceiling for a source of `len` bytes.
    pub fn step_ceiling(len: usize) -> u64 {
        u64::try_from(len)
            .unwrap_or(u64::MAX)
            .saturating_mul(STEPS_PER_BYTE)
            .saturating_add(STEP_SLACK)
    }

    /// Red commit: no guard exists yet, so nothing is refused.
    pub fn check_file(
        _file: &str,
        _bytes: &[u8],
        _tables: &Tables,
        _ceiling: u64,
        _used: &mut Used,
    ) -> Vec<String> {
        Vec::new()
    }

    /// Red commit: no guard exists yet, so nothing is refused.
    pub fn check_other(
        _file: &str,
        _bytes: &[u8],
        _tables: &Tables,
        _used: &mut Used,
    ) -> Vec<String> {
        Vec::new()
    }

    /// Red commit: no guard exists yet, so no row is reported.
    pub fn unused_rows(_tables: &Tables, _used: &Used) -> Vec<String> {
        Vec::new()
    }

    /// Red commit: no guard exists yet, so nothing is refused.
    pub fn check_tree(_root: &Path, _tables: &Tables) -> Vec<String> {
        Vec::new()
    }
}

/// One row of the allow or deny table.
struct Case {
    name: &'static str,
    source: Vec<u8>,
    expected: Vec<String>,
}

fn case(name: &'static str, source: &str, expected: &[&str]) -> Case {
    Case {
        name,
        source: expand(source).into_bytes(),
        expected: expected.iter().map(|e| expand(e)).collect(),
    }
}

fn run_case(c: &Case) -> Vec<String> {
    scan::check_file(
        SYN_FILE,
        &c.source,
        &syn_tables(),
        scan::step_ceiling(c.source.len()),
        &mut Used::default(),
    )
}

/// Every spelling the guard must refuse, one row each, with the whole message.
#[allow(clippy::too_many_lines)]
fn deny_rows() -> Vec<Case> {
    let mut rows = vec![
        case(
            "direct read",
            r#"fn forbidden() { let _ = std::env::var("@V@"); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "alias constant in a forbidden fn",
            r#"fn forbidden() { const K: &str = "@V@"; let _ = std::env::var(K); }"#,
            &["@F@:1: `@V@` string at `fn forbidden::const K` is outside the allowed sites"],
        ),
        case(
            "alias constant in an allowed fn",
            r#"fn allowed_reader() { const K: &str = "@V@"; let _ = std::env::var(K); }"#,
            &["@F@:1: `@V@` string at `fn allowed_reader::const K` is outside the allowed sites"],
        ),
        case(
            "alias of the constant",
            "const K: &str = @C@;",
            &["@F@:1: `@C@` identifier at `const K` is outside the allowed sites"],
        ),
        case(
            "alias static",
            r#"static K: &str = "@V@";"#,
            &["@F@:1: `@V@` string at `static K` is outside the allowed sites"],
        ),
        case(
            "re-export of the constant",
            "pub use crate::identity::keypair::@C@;",
            &["@F@:1: `@C@` identifier at `use` is outside the allowed sites"],
        ),
        case(
            "re-export of the constant under another name",
            "pub use crate::identity::keypair::@C@ as K;",
            &["@F@:1: `@C@` identifier at `use` is outside the allowed sites"],
        ),
        case(
            "use alias of the helper",
            "use super::@B@ as kd;",
            &["@F@:1: `@B@` identifier at `use` is outside the allowed sites"],
        ),
        case(
            "call moved to a forbidden fn",
            "fn forbidden(p: &Path) { let _g = @B@(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "path-qualified call",
            "fn forbidden(p: &Path) { let _g = crate::cli::store::tests::@B@(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "path-qualified constant",
            "fn forbidden() { let _ = std::env::var(crate::identity::keypair::@C@); }",
            &["@F@:1: `@C@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "call split across lines",
            "fn forbidden(p: &Path) {\n    let _g = @B@\n        (p);\n}\n",
            &["@F@:2: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "string continued across lines",
            "fn forbidden() {\n    let _ = std::env::var(\"AI_MEMORY_\\\n        @K@\");\n}\n",
            &["@F@:2: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "hex escape",
            r#"fn forbidden() { let _ = std::env::var("\x41I_MEMORY_@K@"); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "unicode escape",
            r#"fn forbidden() { let _ = std::env::var("\u{41}I_MEMORY_@K@"); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "concat! of two pieces",
            r#"fn forbidden() { let _ = std::env::var(concat!("AI_MEMORY_", "@K@")); }"#,
            &[
                "@F@:1: a string literal holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "two pieces joined with +",
            r#"fn forbidden() { let k = "@P@".to_owned() + "_DIR"; let _ = std::env::var(k); }"#,
            &[
                "@F@:1: a string literal holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "format! of two pieces",
            r#"fn forbidden() { let _ = std::env::var(format!("{}{}", "@P@_D", "IR")); }"#,
            &[
                "@F@:1: a string literal holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "stringify! of a piece",
            r#"fn forbidden() { let _ = std::env::var(concat!("AI_MEMORY_", stringify!(@K@))); }"#,
            &[
                "@F@:1: an identifier holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "stringify! of the whole name",
            "fn forbidden() { let _ = std::env::var(stringify!(@V@)); }",
            &["@F@:1: `@V@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "let alias",
            r#"fn forbidden() { let k = "@V@"; let _ = std::env::var(k); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "fn pointer to the helper",
            "fn forbidden(p: &Path) { let f = @B@; let _g = f(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "env guard set with the name",
            r#"fn forbidden(p: &Path) { let _g = <EnvVarGuard>::set("@V@", p); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "macro_rules body",
            "macro_rules! m { ($p:expr) => { @B@($p) }; }",
            &["@F@:1: `@B@` identifier at `macro_rules! m` is outside the allowed sites"],
        ),
        case(
            "raw identifier",
            "fn forbidden(p: &Path) { let _g = r#@B@(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "raw string",
            "fn forbidden() { let _ = std::env::var(r#\"@V@\"#); }",
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "byte string",
            r#"fn forbidden() { let _ = b"@V@"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "C string",
            r#"fn forbidden() { let _ = c"@V@"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "constant name in a string",
            r#"fn forbidden() { let _ = "@C@"; }"#,
            &["@F@:1: `@C@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "shell expansion",
            r#"fn forbidden() { let _ = "echo $@V@ now"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "braced shell expansion",
            r#"fn forbidden() { let _ = "${@V@}"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "shell assignment",
            r#"fn forbidden() { let _ = "@V@=/x cmd"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "name with trailing blank",
            r#"fn forbidden() { let _ = "@V@ "; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "fn nested in an allowed fn",
            r#"fn allowed_reader() { fn inner() { let _ = std::env::var("@V@"); } }"#,
            &["@F@:1: `@V@` string at `fn allowed_reader::fn inner` is outside the allowed sites"],
        ),
        case(
            "impl method with an allowed name",
            r#"struct Holder; impl Holder { fn allowed_reader() { let _ = std::env::var("@V@"); } }"#,
            &[
                "@F@:1: `@V@` string at `impl Holder::fn allowed_reader` is outside the allowed sites",
            ],
        ),
        case(
            "trait default method with an allowed name",
            r#"trait T { fn allowed_reader() { let _ = std::env::var("@V@"); } }"#,
            &["@F@:1: `@V@` string at `trait T::fn allowed_reader` is outside the allowed sites"],
        ),
        case(
            "mod nest with an allowed name",
            r#"mod m { fn allowed_reader() { let _ = std::env::var("@V@"); } }"#,
            &["@F@:1: `@V@` string at `mod m::fn allowed_reader` is outside the allowed sites"],
        ),
        case(
            "unterminated string",
            r#"fn f() { let s = "abc; }"#,
            &["@F@:1: unterminated string literal; the guard cannot classify this file"],
        ),
        case(
            "unterminated block comment",
            "fn f() {}\n/* abc",
            &["@F@:2: unterminated block comment; the guard cannot classify this file"],
        ),
        case(
            "unterminated raw string",
            "fn f() { let s = r#\"abc; }",
            &["@F@:1: unterminated raw string literal; the guard cannot classify this file"],
        ),
        case(
            "malformed raw string",
            "fn f() { let s = r#!; }",
            &["@F@:1: malformed raw string literal; the guard cannot classify this file"],
        ),
        case(
            "unterminated character literal",
            r"fn f() { let c = '\n; }",
            &["@F@:1: unterminated character literal; the guard cannot classify this file"],
        ),
        case(
            "unbalanced closer",
            "fn f() {}\n}",
            &["@F@:2: unbalanced `}`; the guard cannot classify this file"],
        ),
        case(
            "mismatched delimiter",
            "fn f() { (] }",
            &[
                "@F@:1: mismatched delimiter: `(` closed by `]`; the guard cannot classify this file",
            ],
        ),
        case(
            "unclosed delimiter",
            "fn f() {\n",
            &["@F@:1: unclosed `{`; the guard cannot classify this file"],
        ),
        case(
            "invalid escape",
            r#"fn f() { let s = "\q"; }"#,
            &["@F@:1: invalid escape `\\q`; the guard cannot classify this file"],
        ),
        case(
            "stray quote",
            "fn f() { let c = ' ; }",
            &["@F@:1: stray `'`; the guard cannot classify this file"],
        ),
    ];
    rows.push(Case {
        name: "nesting over the ceiling",
        source: format!(
            "{}{}",
            "{".repeat(scan::MAX_NESTING + 1),
            "}".repeat(scan::MAX_NESTING + 1)
        )
        .into_bytes(),
        expected: vec![expand(&format!(
            "@F@:1: nesting deeper than {} delimiters; the guard cannot classify this file",
            scan::MAX_NESTING
        ))],
    });
    rows.push(Case {
        name: "impl header over the ceiling",
        source: format!("impl {} {{}}", "A".repeat(scan::MAX_HEADER_CHARS)).into_bytes(),
        expected: vec![expand(&format!(
            "@F@:1: impl header longer than {} characters; the guard cannot classify this file",
            scan::MAX_HEADER_CHARS
        ))],
    });
    rows.push(Case {
        name: "not UTF-8",
        source: vec![b'f', b'n', 0xff],
        expected: vec![expand("@F@ is not UTF-8; the guard cannot classify it")],
    });
    let over = scan::MAX_SOURCE_BYTES + 1;
    rows.push(Case {
        name: "over the byte cap",
        source: vec![b' '; over],
        expected: vec![expand(&format!(
            "@F@ is {over} bytes, over the {} byte cap; the guard cannot classify it",
            scan::MAX_SOURCE_BYTES
        ))],
    });
    rows
}

/// Spellings the guard must let through, one row each.
fn allow_rows() -> Vec<Case> {
    vec![
        case(
            "allowed reader",
            r#"fn allowed_reader() -> Option<String> { std::env::var("@V@").ok() }"#,
            &[],
        ),
        case(
            "allowed caller",
            "fn allowed_caller(p: &Path) { let _g = @B@(p); }",
            &[],
        ),
        case(
            "helper definition",
            r#"fn @B@(p: &Path) -> EnvVarGuard { EnvVarGuard::set("@V@", p.as_os_str()) }"#,
            &[],
        ),
        case(
            "constant definition",
            r#"pub const @C@: &str = "@V@";"#,
            &[],
        ),
        case("line comment", "// @V@ @C@ @B@\nfn forbidden() {}", &[]),
        case(
            "nested block comment",
            "/* a /* @V@ */ @B@ */ fn forbidden() {}",
            &[],
        ),
        case("doc comment", "/// reads @V@\nfn forbidden() {}", &[]),
        case(
            "prose panic string",
            r#"fn forbidden() { panic!("set @V@ to a directory first"); }"#,
            &[],
        ),
        case(
            "prose string",
            r#"fn forbidden() { let _ = "the @V@ variable is read by default_key_dir"; }"#,
            &[],
        ),
        case(
            "closure in an allowed fn",
            r#"fn allowed_reader() { let f = || std::env::var("@V@"); let _ = f(); }"#,
            &[],
        ),
        case(
            "longer variable with the same prefix",
            r#"fn forbidden() { let _ = std::env::var("@P@_PASSPHRASE"); }"#,
            &[],
        ),
        case(
            "identifier with the piece inside a longer name",
            "fn forbidden() { let @K@_BIND = 1; let _ = @K@_BIND; }",
            &[],
        ),
        case(
            "lifetimes and a quote character",
            "fn forbidden<'a>(x: &'a str) -> char { let _ = x; '\"' }",
            &[],
        ),
    ]
}

fn report(failures: &[String]) -> String {
    failures.join("\n")
}

#[test]
fn deny_rows_are_refused_with_their_exact_message_9730() {
    let mut failures = Vec::new();
    for c in deny_rows() {
        let got = run_case(&c);
        if got != c.expected {
            failures.push(format!(
                "deny row `{}`: expected {:?}, got {:?}",
                c.name, c.expected, got
            ));
        }
    }
    assert!(failures.is_empty(), "{}", report(&failures));
}

#[test]
fn allow_rows_pass_9730() {
    let mut failures = Vec::new();
    for c in allow_rows() {
        let got = run_case(&c);
        if got != c.expected {
            failures.push(format!("allow row `{}`: got {:?}", c.name, got));
        }
    }
    assert!(failures.is_empty(), "{}", report(&failures));
}

/// Round-3 finding 2: an alias constant is a route with no built name.
#[test]
fn alias_constant_route_is_refused_9730() {
    let source = expand(r#"fn forbidden() { const K: &str = "@V@"; let _ = std::env::var(K); }"#);
    let got = scan::check_file(
        "src/cli/store.rs",
        source.as_bytes(),
        &tree_tables(),
        scan::step_ceiling(source.len()),
        &mut Used::default(),
    );
    assert_eq!(
        got,
        vec![expand(
            "#9730 guard: src/cli/store.rs:1: `@V@` string at `fn forbidden::const K` is outside the allowed sites"
        )]
    );
}

/// Round-3 finding 1: a call moved from an allowed fn to a forbidden fn in the
/// same file keeps every per-file count; the guard refuses it by location.
#[test]
fn count_preserving_swap_is_refused_9730() {
    let file = "src/cli/store.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    let text = std::fs::read_to_string(&path).expect("read src/cli/store.rs");
    let moved = expand("        let _kd = @B@(key_dir.path());");
    let anchor = "    fn read_back_persisted_errors_when_row_is_missing_3025() {";
    let mut lines: Vec<&str> = text.lines().collect();
    let from = lines
        .iter()
        .position(|l| *l == moved)
        .expect("the first bound call in src/cli/store.rs");
    lines.remove(from);
    let to = lines
        .iter()
        .position(|l| *l == anchor)
        .expect("the anchor fn in src/cli/store.rs")
        + 1;
    lines.insert(to, &moved);
    let mutated = lines.join("\n");
    let tables = tree_tables();
    let before = scan::check_file(
        file,
        text.as_bytes(),
        &tables,
        scan::step_ceiling(text.len()),
        &mut Used::default(),
    );
    assert!(before.is_empty(), "{}", report(&before));
    let got = scan::check_file(
        file,
        mutated.as_bytes(),
        &tables,
        scan::step_ceiling(mutated.len()),
        &mut Used::default(),
    );
    let line = to + 1;
    assert_eq!(
        got,
        vec![expand(&format!(
            "#9730 guard: {file}:{line}: `@B@` identifier at `mod tests::fn read_back_persisted_errors_when_row_is_missing_3025` is outside the allowed sites"
        ))]
    );
}

#[test]
fn size_bound_holds_on_100k_lines_9730() {
    let mut source = String::new();
    for n in 0..SIZE_LINES {
        let _ = writeln!(
            source,
            "fn prose_{n}() {{ let _ = \"where the key directory is bound, line {n}\"; }}"
        );
    }
    source.push_str(&expand(
        r#"fn forbidden() { let _ = std::env::var("@V@"); }"#,
    ));
    let start = Instant::now();
    let got = scan::check_file(
        SYN_FILE,
        source.as_bytes(),
        &syn_tables(),
        scan::step_ceiling(source.len()),
        &mut Used::default(),
    );
    let took = start.elapsed();
    let line = SIZE_LINES + 1;
    assert_eq!(
        got,
        vec![expand(&format!(
            "@F@:{line}: `@V@` string at `fn forbidden` is outside the allowed sites"
        ))]
    );
    assert!(
        took <= SIZE_WALL_CLOCK_CEILING,
        "#9730 guard: {SIZE_LINES} lines took {took:?}, over {SIZE_WALL_CLOCK_CEILING:?}"
    );
}

#[test]
fn step_ceiling_is_a_finding_9730() {
    let source = expand(r#"fn forbidden() { let _ = std::env::var("@V@"); }"#);
    let got = scan::check_file(
        SYN_FILE,
        source.as_bytes(),
        &syn_tables(),
        TINY_STEP_CEILING,
        &mut Used::default(),
    );
    assert_eq!(
        got,
        vec![expand(&format!(
            "@F@: step ceiling {TINY_STEP_CEILING} exceeded; the guard cannot classify it"
        ))]
    );
}

#[test]
fn stale_rows_are_failures_9730() {
    let tables = Tables {
        sites: vec![(SYN_FILE.to_owned(), "fn nowhere".to_owned())],
        fragments: vec![(SYN_FILE.to_owned(), "fn nowhere".to_owned(), prefix_token())],
        left_out: vec!["md".to_owned()],
    };
    let mut used = Used::default();
    let source = b"fn nowhere() {}";
    let mut got = scan::check_file(
        SYN_FILE,
        source,
        &tables,
        scan::step_ceiling(source.len()),
        &mut used,
    );
    got.extend(scan::unused_rows(&tables, &used));
    assert_eq!(
        got,
        vec![
            format!(
                "#9730 guard: allowed site {SYN_FILE} `fn nowhere` matches nothing; remove the row"
            ),
            format!(
                "#9730 guard: allowed fragment {SYN_FILE} `fn nowhere` matches nothing; remove the row"
            ),
            "#9730 guard: left-out kind md matches no tracked file; remove the row".to_owned(),
        ]
    );
}

#[test]
fn other_kinds_need_a_left_out_row_9730() {
    let text = expand("set @V@ before the run\n");
    let none = Tables::default();
    let got = scan::check_other(
        "docs/notes.md",
        text.as_bytes(),
        &none,
        &mut Used::default(),
    );
    assert_eq!(
        got,
        vec![
            "#9730 guard: docs/notes.md holds a key-dir spelling and its kind md is not in LEFT_OUT"
                .to_owned()
        ]
    );
    let md = Tables {
        left_out: vec!["md".to_owned()],
        ..Tables::default()
    };
    let mut used = Used::default();
    let got = scan::check_other("docs/notes.md", text.as_bytes(), &md, &mut used);
    assert!(got.is_empty(), "{}", report(&got));
    assert!(scan::unused_rows(&md, &used).is_empty());
}

#[test]
fn every_row_has_a_reason_9730() {
    let mut missing: Vec<String> = Vec::new();
    for r in ALLOWED_SITES {
        if r.reason.trim().is_empty() {
            missing.push(format!("{} `{}`", r.file, expand(r.site)));
        }
    }
    for r in ALLOWED_FRAGMENTS {
        if r.reason.trim().is_empty() || r.text.is_empty() {
            missing.push(format!("{} `{}`", r.file, expand(r.site)));
        }
    }
    for r in LEFT_OUT {
        if r.reason.trim().is_empty() {
            missing.push(r.kind.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "rows without a reason: {}",
        report(&missing)
    );
}

#[test]
fn tracked_tree_holds_no_key_dir_route_outside_the_allowed_sites_9730() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let got = scan::check_tree(root, &tree_tables());
    assert!(got.is_empty(), "{}", report(&got));
}
