// #1885 (critical) — END-TO-END regression: an ACTUAL `memory_store` under
// `[hooks].enforce_mode = enforce` with `pre_store` in `required_events` and NO
// configured pre_store hook must be DENIED at the real MCP store handler — not
// merely that the in-hooks pure helpers (`enforce_required_event_presence` /
// `dispatch_pre_event_enforced`) return the right value in isolation (cluster A
// already pinned those). This closes the silent-bypass gap where every write
// resolved an empty `HookChain` whose `fire` returned `Allow` while the boot
// banner / `doctor --hooks` only warned "WILL DENY".
//
// This lives in its OWN integration binary so the process-global enforcement
// gate installed here cannot leak into any other test binary, and the single
// sequential test avoids intra-file races on the set-once gate.

use ai_memory::config::ResolvedTtl;
use ai_memory::hooks::{HookEnforceMode, HookEvent};
use serde_json::{Value, json};
use std::path::PathBuf;

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("hooks-enforce-store-deny-1885")
}

/// v0.9 store-path default is REQUIRED agent attestation, which would reject
/// this suite's unsigned store fixtures; opt out (mirrors the other MCP-store
/// integration suites).
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before any gated store call.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn fresh_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    permissive_attestation_for_tests();
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("store.db");
    let conn = ai_memory::storage::open(&db_path).expect("open");
    (dir, db_path, conn)
}

fn call_store(
    conn: &rusqlite::Connection,
    db_path: &std::path::Path,
    params: &Value,
) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_for_tests(
        conn, db_path, params, None, None, None, &ttl, false, None, None,
    )
}

#[test]
fn enforce_required_pre_store_with_no_hook_denies_actual_memory_store_1885() {
    let (_dir, db_path, conn) = fresh_db();
    let params = json!({
        "title": "e2e-1885",
        "content": "hooks.enforce gate end-to-end regression body",
        "namespace": "ns-1885",
    });

    // Control — with NO enforcement gate installed (the default, enforce-off
    // deployment), the real store commits: proof the deny below is the gate's
    // doing, not an unrelated store failure.
    let ok = call_store(&conn, &db_path, &params)
        .expect("baseline store must succeed while the enforcement gate is uninstalled");
    assert!(
        ok.get("id").and_then(Value::as_str).is_some(),
        "baseline store returns an id: {ok}"
    );

    // Install the gate exactly as `run_mcp_server` would for
    // `enforce_mode = enforce` + `required_events = ["pre_store"]` with an EMPTY
    // hook set (no enabled pre_store hook) — the mandatory-presence check must
    // fail closed.
    ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
        vec![],
        HookEnforceMode::Enforce,
        vec![HookEvent::PreStore],
    );

    // The SAME store call is now refused by the REAL `handle_store` path with a
    // 503 Deny, before any row is built or committed.
    let err = call_store(&conn, &db_path, &params).expect_err(
        "memory_store MUST be denied under enforce_mode=enforce + required pre_store + no hook",
    );
    assert!(
        err.contains("hooks.enforce") && err.contains("pre_store"),
        "deny reason names the enforce gate and the required event: {err}"
    );
    assert!(
        err.contains("503"),
        "deny surfaces the 503 refusal code: {err}"
    );
}
