//! #3713 — an own refusal in an MCP tool must have a TYPED root.
//!
//! The MCP funnel renders from a closed vocabulary: an `anyhow` chain whose
//! root is not one of ours classifies as `DatabaseError` and reaches the
//! caller as "internal storage error". That is correct for a driver fault and
//! wrong for our own text — and the day the funnel landed, fourteen bare
//! `anyhow!("…")` / `bail!("…")` / `map_err(anyhow::Error::msg)` refusals in
//! `src/mcp/tools` went opaque, five of them pinned by message
//! (`skill_promote_test`), nine of them not. This scan is the gate: every
//! string carrier in `src/mcp/tools` is a violation unless it is listed
//! below with its exact line text and the reason it is NOT own text. A line
//! that ends with the macro opener (`anyhow!(` / `bail!(`) carries its literal
//! on the next line and counts too — three promote refusals had that shape.

use std::path::Path;

/// (file, exact trimmed line, reason). Every entry must still exist — a
/// stale allowance is a failure, so the list cannot rot into a blanket.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "skill_promote.rs",
        r#".map_err(|e| anyhow::anyhow!("parameters_schema serialize: {e}"))?;"#,
        "serde_json error text is foreign; opaque is correct",
    ),
    (
        "skill_promote.rs",
        ".map_err(anyhow::Error::msg)?;",
        "register_core returns a MIXED population (own refusals + serde/std::io text); \
         a typed root here would leak paths — type register_core's error (follow-up)",
    ),
    (
        "capture_turn.rs",
        ".map_err(anyhow::Error::msg)?",
        "capture_turn_idempotent_auto returns Result<_, String> built by idempotent_err(ERR_*, e) with \
         the driver error inside; opaque is correct — type the storage error (follow-up)",
    ),
    (
        "capture_turn.rs",
        "crate::storage::capture_turn_idempotent(conn, &write, false).map_err(anyhow::Error::msg)?",
        "same population as the _auto twin above",
    ),
    (
        "capture_turn.rs",
        r#".map_err(|e| anyhow::anyhow!("{e}"))?"#,
        "pre-existing flatten of enforce_governance's error; classify in v1.0.1",
    ),
    (
        "recall.rs",
        r#"anyhow::bail!("FailEmbedder: synthetic failure on call {n}");"#,
        "cfg(test) synthetic embedder inside the file's test module",
    ),
];

const CARRIERS: &[&str] = &[
    "anyhow::anyhow!(\"",
    " anyhow!(\"",
    "anyhow::bail!(\"",
    " bail!(\"",
    ".map_err(anyhow::Error::msg)",
];

#[test]
fn every_string_carrier_in_mcp_tools_is_a_typed_root_or_an_allowed_foreign_wrap_3713() {
    let dir = Path::new("src/mcp/tools");
    let mut violations = Vec::new();
    let mut seen_allowed = vec![0usize; ALLOWED.len()];
    let mut files = 0;
    for entry in std::fs::read_dir(dir).expect("src/mcp/tools exists") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        files += 1;
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let src = std::fs::read_to_string(&path).expect("read tool source");
        for (i, line) in src.lines().enumerate() {
            let opener_only = {
                let t = line.trim_end();
                t.ends_with("anyhow::anyhow!(") || t.ends_with(" anyhow!(") || t.ends_with("bail!(")
            };
            if !opener_only && !CARRIERS.iter().any(|c| line.contains(c)) {
                continue;
            }
            let t = line.trim();
            if let Some(k) = ALLOWED.iter().position(|(f, l, _)| *f == name && *l == t) {
                seen_allowed[k] += 1;
                continue;
            }
            violations.push(format!("{name}:{}: {t}", i + 1));
        }
    }
    assert!(
        files > 10,
        "parser drift: only {files} files under src/mcp/tools"
    );
    for (k, (f, l, _)) in ALLOWED.iter().enumerate() {
        assert_eq!(
            seen_allowed[k], 1,
            "#3713: allowed entry {f} `{l}` must match exactly ONE line (matched {}); a stale or \
             duplicated allowance is a hole in the gate",
            seen_allowed[k]
        );
    }
    assert!(
        violations.is_empty(),
        "#3713: these MCP-tool refusals are bare string carriers — the funnel will render \
         them as \"internal storage error\". Plant `crate::errors::invalid_input(..)` / \
         `refusal(..)`, or list the line here with the reason it is foreign text:\n  {}",
        violations.join("\n  ")
    );
}
