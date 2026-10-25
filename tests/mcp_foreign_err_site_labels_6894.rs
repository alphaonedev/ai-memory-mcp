//! #6894 - the context label passed to `mcp_foreign_err` / `log_foreign` is the
//! operator-log line's only statement of WHICH operation failed. A Rust method
//! name left behind by a codemod (`as_deref`, `as_ref`, ...) names no
//! operation. This source scan walks `src/mcp/tools` and fails on any such
//! label, printing every offending `file:line`.

use std::fs;
use std::path::{Path, PathBuf};

const CODEMOD_NAMES: &[&str] = &[
    "as_deref",
    "as_ref",
    "as_str",
    "unwrap_or_default",
    "to_string",
];
const CALLEES: &[&str] = &["mcp_foreign_err(", "log_foreign("];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.unwrap_or_else(|e| panic!("dir entry: {e}")).path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The string literal that is the first argument of a call starting at `rest`
/// (just after the opening paren), if the first argument is a plain literal.
fn first_literal(rest: &str) -> Option<&str> {
    let body = rest.trim_start().strip_prefix('"')?;
    Some(&body[..body.find('"')?])
}

#[test]
fn no_foreign_err_label_is_a_codemod_method_name_6894() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp/tools");
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "scanned no files under {}",
        root.display()
    );

    let mut offenders = Vec::new();
    for file in &files {
        let text =
            fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (idx, line) in text.lines().enumerate() {
            for callee in CALLEES {
                let mut from = 0;
                while let Some(pos) = line[from..].find(callee) {
                    let after = from + pos + callee.len();
                    if let Some(label) = first_literal(&line[after..])
                        && CODEMOD_NAMES.contains(&label)
                    {
                        let rel = file
                            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                            .unwrap_or(file);
                        offenders.push(format!(
                            "{}:{}: {callee}\"{label}\"",
                            rel.display(),
                            idx + 1
                        ));
                    }
                    from = after;
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "#6894: context labels that name no operation:\n{}",
        offenders.join("\n")
    );
}
