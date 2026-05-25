// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! V-1 — structural-integrity pin for the `wire_check` sole-path claim
//! (issue #698 commercial-claim validation pass).
//!
//! Claim being validated: "the `wire_check` helper (and
//! `GOVERNANCE_PRE_WRITE` for the `storage::insert` path) is the ONLY
//! path through which a hook-installed daemon's agent-driven
//! mutations may reach the host."
//!
//! This test is a structural-integrity PIN, not a behavioural test.
//! It reads the source of each load-bearing wire-point and verifies:
//!
//!   1. `GOVERNANCE_PRE_ACTION: OnceLock<WireCheckHook>` is declared
//!      in `src/governance/wire_check.rs`.
//!   2. `GOVERNANCE_PRE_WRITE: OnceLock<...>` is declared in
//!      `src/storage/mod.rs`.
//!   3. `src/hooks/executor.rs` calls `wire_check::check(...)` before
//!      `Command::new(...).spawn()`.
//!   4. `src/federation/sync.rs` calls `wire_check::check(...)` before
//!      the outbound peer POST.
//!   5. `src/llm.rs` calls `wire_check::check_anyhow(...)` before the
//!      Ollama HTTP request.
//!   6. `src/mcp/tools/skill_export.rs` calls `wire_check::check(...)`
//!      before each filesystem write.
//!
//! A future refactor that REMOVES a wire-point call without
//! consciously updating this test will fail at PR time, surfacing
//! the regression before merge. This is intentionally a textual /
//! structural check — runtime tests for the SAME invariants live in
//! `tests/governance_wire_points.rs` (refuse path) and
//! `tests/governance_storage_insert_hook.rs` (`PRE_WRITE` path).

use std::path::PathBuf;

fn src(file: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path: PathBuf = [manifest_dir, file].iter().collect();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "wire_check_sole_path_pin: failed to read {}: {}",
            path.display(),
            e
        )
    });
    // Normalise CRLF -> LF: Windows git checkouts can convert .rs to
    // CRLF; the literal-string searches below contain bare `\n` so the
    // CRLF form misses every match. Normalising here keeps the test
    // platform-independent without changing the production source.
    raw.replace("\r\n", "\n")
}

#[test]
fn governance_pre_action_oncelock_present_in_wire_check() {
    let body = src("src/governance/wire_check.rs");
    assert!(
        body.contains("pub static GOVERNANCE_PRE_ACTION"),
        "expected `pub static GOVERNANCE_PRE_ACTION` in src/governance/wire_check.rs"
    );
    assert!(
        body.contains("OnceLock"),
        "expected OnceLock declaration adjacent to GOVERNANCE_PRE_ACTION"
    );
    assert!(
        body.contains("pub fn check"),
        "expected `pub fn check` helper in src/governance/wire_check.rs"
    );
}

#[test]
fn governance_pre_write_oncelock_present_in_storage() {
    let body = src("src/storage/mod.rs");
    assert!(
        body.contains("pub static GOVERNANCE_PRE_WRITE"),
        "expected `pub static GOVERNANCE_PRE_WRITE` in src/storage/mod.rs"
    );
    assert!(
        body.contains("OnceLock"),
        "expected OnceLock declaration adjacent to GOVERNANCE_PRE_WRITE"
    );
}

#[test]
fn hooks_executor_invokes_wire_check_before_command_spawn() {
    let body = src("src/hooks/executor.rs");
    // wire_check::check call present, with the ProcessSpawn action shape
    assert!(
        body.contains("wire_check::check(&spawn_action)"),
        "src/hooks/executor.rs must call wire_check::check(&spawn_action) before Command::spawn"
    );
    // Validate textual ordering: wire_check::check appears before the
    // subsequent Command::new(&self.config.command).spawn().
    let wire_idx = body
        .find("wire_check::check(&spawn_action)")
        .expect("wire_check::check call must exist");
    // The CODE spawn() (vs. the doc-comment mention) is a multi-line
    // chain ending in `.spawn()\n` at the indentation of the chain. We
    // match `.kill_on_drop(true)\n` `.spawn()` shape that's stable
    // across rustfmt; the first such hit is the production call.
    let spawn_idx = body
        .find(".kill_on_drop(true)\n                .spawn()")
        .expect("Command::spawn (code) must exist");
    assert!(
        wire_idx < spawn_idx,
        "wire_check::check must precede Command::spawn in src/hooks/executor.rs"
    );
}

#[test]
fn federation_sync_invokes_wire_check_before_peer_post() {
    let body = src("src/federation/sync.rs");
    assert!(
        body.contains("wire_check::check(&net_action)"),
        "src/federation/sync.rs must call wire_check::check(&net_action) before peer POST"
    );
    // wire_check::check appears before the req.send() that drives the POST
    let wire_idx = body
        .find("wire_check::check(&net_action)")
        .expect("wire_check::check call must exist");
    let post_idx = body.find("req.send()").expect("req.send() must exist");
    assert!(
        wire_idx < post_idx,
        "wire_check::check must precede req.send() in src/federation/sync.rs"
    );
}

#[test]
fn llm_invokes_wire_check_before_ollama_request() {
    let body = src("src/llm.rs");
    // The LLM client uses check_anyhow to wrap the refusal into the
    // anyhow-chain expected by the Ollama caller.
    assert!(
        body.contains("wire_check::check_anyhow(&action)"),
        "src/llm.rs must call wire_check::check_anyhow(&action) before the Ollama HTTP request"
    );
    // check_outbound() is invoked before the post(...) in generate_with_body.
    let check_idx = body
        .find("self.check_outbound()")
        .expect("self.check_outbound() must exist");
    // Look for the first .post( call that follows the check_outbound call.
    let post_idx = body[check_idx..]
        .find(".post(")
        .map(|i| check_idx + i)
        .expect(".client.post(...) must follow check_outbound");
    assert!(
        check_idx < post_idx,
        "check_outbound must precede .client.post(...) in src/llm.rs"
    );
}

/// v0.7.0 (issue #1237) — extend the wire-point pin to cover the
/// post-#1067 production chat surfaces. Both `OllamaClient::generate`
/// and `OllamaClient::generate_with_model_override` MUST invoke
/// `self.check_outbound()` immediately after the `breaker_is_open()`
/// short-circuit and BEFORE the outbound `reqwest::post`. The
/// pre-#1237 code shipped both fns without the gate, so an operator
/// `refuse` rule against the LLM host was silently ignored on every
/// vendor (Ollama + OpenAI-compatible) — a governance bypass.
#[test]
fn llm_generate_invokes_wire_check_before_post_1237() {
    let body = src("src/llm.rs");

    // Locate the body of `pub fn generate(`. The function spans from
    // its signature through the next `fn ` that starts a SIBLING fn
    // at the impl-block indentation. Approximating with a bounded
    // window (up to the next `fn generate_with_model_override`).
    let fn_start = body
        .find("pub fn generate(&self, prompt: &str, system: Option<&str>)")
        .expect("OllamaClient::generate signature must exist in src/llm.rs");
    // Bound the search to the start of the next chat fn so we don't
    // bleed into generate_with_model_override.
    let fn_end = body[fn_start..]
        .find("fn generate_with_model_override")
        .map(|i| fn_start + i)
        .expect("generate_with_model_override must follow generate");
    let generate_body = &body[fn_start..fn_end];

    let check_idx = generate_body.find("self.check_outbound()").expect(
        "OllamaClient::generate must call self.check_outbound() before the outbound HTTP \
         (#1237 fix)",
    );
    let post_idx = generate_body
        .find(".post(")
        .expect(".client.post(...) must exist in OllamaClient::generate");
    assert!(
        check_idx < post_idx,
        "check_outbound must precede .client.post(...) in OllamaClient::generate \
         (#1237)"
    );
}

#[test]
fn llm_generate_with_model_override_invokes_wire_check_before_post_1237() {
    let body = src("src/llm.rs");
    let fn_start = body
        .find("fn generate_with_model_override(")
        .expect("OllamaClient::generate_with_model_override signature must exist");
    // Bound by the next fn in the impl (check_outbound is the next one).
    let fn_end = body[fn_start..]
        .find("fn check_outbound")
        .map(|i| fn_start + i)
        .expect("check_outbound must follow generate_with_model_override in source order");
    let fn_body = &body[fn_start..fn_end];

    let check_idx = fn_body.find("self.check_outbound()").expect(
        "OllamaClient::generate_with_model_override must call self.check_outbound() before \
         the outbound HTTP (#1237 fix)",
    );
    let post_idx = fn_body
        .find(".post(")
        .expect(".client.post(...) must exist in generate_with_model_override");
    assert!(
        check_idx < post_idx,
        "check_outbound must precede .client.post(...) in \
         OllamaClient::generate_with_model_override (#1237)"
    );
}

#[test]
fn skill_export_invokes_wire_check_before_each_filesystem_write() {
    let body = src("src/mcp/tools/skill_export.rs");
    assert!(
        body.contains("wire_check::check(&skill_md_action)"),
        "src/mcp/tools/skill_export.rs must call wire_check::check(&skill_md_action) before SKILL.md write"
    );
    assert!(
        body.contains("wire_check::check(&res_action)"),
        "src/mcp/tools/skill_export.rs must call wire_check::check(&res_action) before each resource write"
    );
    // Ordering: SKILL.md gate precedes the SKILL.md write
    let skill_gate_idx = body
        .find("wire_check::check(&skill_md_action)")
        .expect("SKILL.md gate must exist");
    let skill_write_idx = body
        .find("std::fs::write(&skill_md_path")
        .expect("SKILL.md std::fs::write must exist");
    assert!(
        skill_gate_idx < skill_write_idx,
        "wire_check::check(&skill_md_action) must precede the SKILL.md write"
    );
    // Ordering: per-resource gate precedes the per-resource write
    let res_gate_idx = body
        .find("wire_check::check(&res_action)")
        .expect("resource gate must exist");
    let res_write_idx = body
        .find("std::fs::write(&res_file")
        .expect("resource std::fs::write must exist");
    assert!(
        res_gate_idx < res_write_idx,
        "wire_check::check(&res_action) must precede the resource write"
    );
}

#[test]
fn bootstrap_serve_installs_governance_pre_action_hook_exactly_once() {
    let body = src("src/daemon_runtime.rs");
    // The OnceLock is set inside bootstrap_serve. We pin the exact
    // call shape — a future refactor that moves the install elsewhere
    // (or installs it twice) trips this assertion.
    assert!(
        body.contains("GOVERNANCE_PRE_ACTION.set(Box::new("),
        "src/daemon_runtime.rs must call GOVERNANCE_PRE_ACTION.set in bootstrap_serve"
    );
    // .set() is the only mutation API on OnceLock (there is no take/replace
    // in std). Asserting `.set(` is sufficient to pin the immutability —
    // a subsequent call would unconditionally return Err per std semantics.
    let installs: Vec<_> = body.match_indices("GOVERNANCE_PRE_ACTION.set(").collect();
    assert_eq!(
        installs.len(),
        1,
        "expected exactly one GOVERNANCE_PRE_ACTION.set call in daemon_runtime.rs (found {})",
        installs.len()
    );
}
