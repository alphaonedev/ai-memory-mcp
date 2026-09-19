//! #3708 — a hook subprocess is FOREIGN TEXT BY DEFINITION, and
//! `ChainResult::Deny.reason` crosses to the JSON-RPC / HTTP caller.
//!
//! The hook's stdout (its decision line), its stderr, and the operator's
//! configured command PATH must none of them ride out on that string. These
//! pins go RED on the pre-fix tree: the old arm was
//! `format!("hook {} errored under fail_mode=closed: {e}", cfg.command.display())`,
//! which interpolated BOTH the path and the executor error whose `Decode`
//! variant embeds the hook's own stdout verbatim.

use std::path::PathBuf;

use ai_memory::hooks::{
    ChainResult, ExecutorRegistry, FailMode, HookChain, HookConfig, HookEvent, HookMode,
};
use serde_json::json;
use tempfile::TempDir;

fn write_script(dir: &TempDir, name: &str, body: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let path = dir.path().join(name);
    {
        let mut f = std::fs::File::create(&path).expect("create script");
        f.write_all(body.as_bytes()).expect("write script");
        f.sync_all().expect("sync script");
    }
    let mut perms = std::fs::metadata(&path).expect("stat").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    path
}

fn cfg_for(script: PathBuf) -> HookConfig {
    HookConfig {
        event: HookEvent::PostRecall,
        command: script,
        priority: 0,
        timeout_ms: 5_000,
        mode: HookMode::Exec,
        enabled: true,
        namespace: "*".into(),
        fail_mode: FailMode::Closed,
    }
}

/// The hook prints an unrecognised action carrying a credential-shaped
/// sentinel. Pre-fix that text reached the caller through `Decode.reason`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_reason_carries_neither_hook_stdout_nor_the_command_path_3708() {
    const SENTINEL: &str = "sk-SENTINEL-must-not-reach-the-caller";
    let dir = tempfile::tempdir().expect("tempdir");
    let script = write_script(
        &dir,
        "unknown_action_with_secret.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' '{{\"action\":\"{SENTINEL}\"}}'\n"),
    );
    let script_name = script
        .file_name()
        .expect("file name")
        .to_string_lossy()
        .to_string();

    let chain = HookChain::new(vec![cfg_for(script)]);
    let mut registry = ExecutorRegistry::new();
    let result = chain
        .fire(HookEvent::PostRecall, json!({}), &mut registry)
        .await;

    match result {
        ChainResult::Deny { reason, code } => {
            assert_eq!(code, 503, "#3708: fail-closed hook error is a 503");
            // ABSENCE — the hook's own stdout must not cross.
            assert!(
                !reason.contains(SENTINEL),
                "#3708: the hook's stdout reached the caller: {reason}"
            );
            // ABSENCE — the operator's command path must not cross.
            assert!(
                !reason.contains(&script_name),
                "#3708: the operator's command path reached the caller: {reason}"
            );
            // PRESENCE ON THE SAME SINK — pairing the two absence assertions,
            // so this cannot pass by `reason` silently becoming empty or by
            // the Deny arm ceasing to produce a usable message at all.
            assert!(
                reason.contains("fail_mode=closed"),
                "#3708: the caller must still be told WHY it was denied: {reason}"
            );
            assert!(
                reason.contains("undecodable"),
                "#3708: the closed vocabulary must name the failure kind: {reason}"
            );
        }
        other => panic!("#3708: expected Deny under FailMode::Closed, got {other:?}"),
    }
}

/// ALLOWED-PATH CONTROL — a well-formed hook still runs to a normal verdict.
/// Without this, the assertions above would pass just as happily if every hook
/// began failing for an unrelated reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_well_formed_hook_is_unaffected_by_the_closed_vocabulary_3708() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = write_script(
        &dir,
        "well_formed_allow.sh",
        "#!/bin/sh\nprintf '%s\\n' '{\"action\":\"allow\"}'\n",
    );
    let chain = HookChain::new(vec![cfg_for(script)]);
    let mut registry = ExecutorRegistry::new();
    let result = chain
        .fire(HookEvent::PostRecall, json!({}), &mut registry)
        .await;
    assert!(
        !matches!(result, ChainResult::Deny { .. }),
        "#3708: a well-formed allow hook must NOT be denied, got {result:?}"
    );
}
