//! #7776 guard (rust-1.98 ERRORS-19): a bare discard of `gc_if_needed(..)`
//! silently drops sweep errors. Every call under `src/` must either be
//! observed (`if let Err(e) = ...` / `match`) or carry a comment within two
//! lines above.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Sites fixed by PR #7775 (#3566), which owns them: one allowed offender per
/// file (by count, so a NEW bare discard in these files still fails). Remove
/// each entry when that PR lands on the chain.
const FIXED_BY_PR_7775: [(&str, usize); 2] =
    [("src/cli/recall.rs", 1), ("src/mcp/tools/recall.rs", 1)];

const CALL: &str = "gc_if_needed(";
const OBSERVED: [&str; 3] = ["if let Err(", "match ", "pub fn gc_if_needed("];

fn walk(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    let entries = fs::read_dir(dir).expect("read_dir src");
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

/// Offending 1-based line numbers of one source text.
fn offenders_in(text: &str) -> Vec<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        // A line ending in `=` (e.g. `let _ =`) continues on the next line.
        let joined = if t.trim_end().ends_with('=') {
            format!("{t} {}", lines.get(idx + 1).map_or("", |l| l.trim()))
        } else {
            t.to_string()
        };
        let code = joined.split("//").next().unwrap_or_default();
        if !joined.contains(CALL) || OBSERVED.iter().any(|o| code.contains(o)) {
            continue;
        }
        let lo = idx.saturating_sub(2);
        let commented = lines[lo..idx]
            .iter()
            .any(|l| l.trim_start().starts_with("//"));
        if !commented {
            out.push(idx + 1);
        }
    }
    out
}

#[test]
fn no_uncommented_gc_if_needed_discard_7776() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    files.sort();
    let allowance: BTreeMap<&str, usize> = FIXED_BY_PR_7775.iter().copied().collect();
    let mut offenders = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(root)
            .expect("under manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(file).expect("read source");
        let found = offenders_in(&text);
        let allowed = allowance.get(rel.as_str()).copied().unwrap_or(0);
        if found.len() > allowed {
            offenders.extend(found.iter().map(|n| format!("{rel}:{n}")));
        }
    }
    assert!(
        offenders.is_empty(),
        "uncommented discard of `gc_if_needed(..)` (ERRORS-19, #7776): {}",
        offenders.join(", ")
    );
}
