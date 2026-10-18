//! #7776 guard (rust-1.98 ERRORS-19): a bare `let _ = db::gc_if_needed(..)`
//! silently drops sweep errors. Every discard under `src/` must either be
//! observed (`if let Err(e) = ...`) or carry a comment within two lines above.

use std::fs;
use std::path::Path;

/// Sites fixed by PR #7775 (#3566), which owns them; remove each entry when
/// that PR lands on the chain.
const FIXED_BY_PR_7775: [&str; 2] = ["src/cli/recall.rs", "src/mcp/tools/recall.rs"];

const NEEDLES: [&str; 2] = ["let _ = db::gc_if_needed(", "let _ = gc_if_needed("];

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

#[test]
fn no_uncommented_gc_if_needed_discard_7776() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    files.sort();
    let mut offenders = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(root)
            .expect("under manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        if FIXED_BY_PR_7775.contains(&rel.as_str()) {
            continue;
        }
        let text = fs::read_to_string(file).expect("read source");
        let lines: Vec<&str> = text.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") || !NEEDLES.iter().any(|n| t.contains(n)) {
                continue;
            }
            let lo = idx.saturating_sub(2);
            let commented = lines[lo..idx]
                .iter()
                .any(|l| l.trim_start().starts_with("//"));
            if !commented {
                offenders.push(format!("{rel}:{}", idx + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "uncommented `let _ = gc_if_needed(..)` discards (ERRORS-19, #7776): {}",
        offenders.join(", ")
    );
}
