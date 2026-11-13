// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4059 — `memory_skill_compositional_context` must render only the
//! reflections the CALLER may read.
//!
//! Pre-fix the handler selected reflection rows straight from `memories`
//! (namespace / kind / depth / expiry only) and returned their `title` and
//! `content`, with no caller-visibility predicate — and the #3549 structural
//! read guard exempted the tool as "not memory rows". A per-agent read
//! posture therefore did not hold across this tool: one agent's private
//! reflection was rendered to another agent composing a skill that declares
//! the namespace.
//!
//! Driven through real `ai-memory mcp` children bound (`AI_MEMORY_AGENT_ID`)
//! as each agent; every row is authored through the supported
//! `memory_store` → `memory_reflect` path.
//!
//! Cells:
//!   * RED on the untouched tip — each agent composes and receives its OWN
//!     private reflection plus the collective one, never the other agent's
//!     private reflection.
//!   * control — the no-identity local-operator posture (the documented
//!     single-tenant trust-all read) still composes every reflection.
//!   * structural — the tool is no longer allowlisted by the #3549 read
//!     guard, and its handler calls the canonical read funnel.

use serde_json::json;

#[path = "common/child_stdin_report.rs"]
mod child_stdin_report;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::{Fixture, Mcp};

const NS: &str = "refl4059";
const ALICE: &str = "ai:alice-4059";
const BOB: &str = "ai:bob-4059";
const ALICE_SECRET: &str = "ALICE-PRIVATE-4059";
const BOB_SECRET: &str = "BOB-PRIVATE-4059";
const SHARED: &str = "COLLECTIVE-4059";

/// Author one observation + one reflection on it as `agent`, with the
/// reflection's `scope` set to `scope`.
fn author_reflection(fixture: &Fixture, agent: &str, marker: &str, scope: &str) {
    let mut mcp = Mcp::start(fixture, Some(agent));
    let stored = mcp.call_ok(
        "memory_store",
        &json!({
            "title": format!("source for {marker}"),
            "content": format!("observation behind {marker}"),
            "namespace": NS,
            "tier": "long",
        }),
    );
    let source = stored["id"]
        .as_str()
        .unwrap_or_else(|| panic!("memory_store id: {stored}"))
        .to_string();
    let reflected = mcp.call_ok(
        "memory_reflect",
        &json!({
            "source_ids": [source],
            "title": format!("reflection {marker}"),
            "content": marker,
            "namespace": NS,
            "metadata": {"scope": scope},
        }),
    );
    assert!(reflected.is_object(), "memory_reflect: {reflected}");
}

fn register_composing_skill(fixture: &Fixture) -> String {
    let mut mcp = Mcp::start(fixture, None);
    let md = format!(
        "---\nnamespace: skills4059\nname: composer-4059\ndescription: Composes {NS}.\n\
         composes_with_reflections:\n  - namespace: {NS}\n    min_depth: 0\n---\n\nCompose.\n"
    );
    let reg = mcp.call_ok("memory_skill_register", &json!({"inline_skill": md}));
    reg["id"]
        .as_str()
        .unwrap_or_else(|| panic!("skill_id: {reg}"))
        .to_string()
}

/// The reflection contents the `agent`-bound (or identity-less) caller
/// receives from the composition.
fn composed_contents(fixture: &Fixture, agent: Option<&str>, skill_id: &str) -> Vec<String> {
    let mut mcp = Mcp::start(fixture, agent);
    let out = mcp.call_ok(
        "memory_skill_compositional_context",
        &json!({"skill_id": skill_id}),
    );
    out["reflections"]
        .as_array()
        .unwrap_or_else(|| panic!("reflections array: {out}"))
        .iter()
        .map(|r| r["content"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn seeded() -> (Fixture, String) {
    let fixture = Fixture::new();
    author_reflection(&fixture, ALICE, ALICE_SECRET, "private");
    author_reflection(&fixture, BOB, BOB_SECRET, "private");
    author_reflection(&fixture, ALICE, SHARED, "collective");
    let skill_id = register_composing_skill(&fixture);
    (fixture, skill_id)
}

fn has(contents: &[String], marker: &str) -> bool {
    contents.iter().any(|c| c.contains(marker))
}

#[test]
fn each_agent_composes_only_the_reflections_it_may_read_4059() {
    let (fixture, skill_id) = seeded();

    let alice = composed_contents(&fixture, Some(ALICE), &skill_id);
    assert!(has(&alice, ALICE_SECRET), "alice sees her own: {alice:?}");
    assert!(
        has(&alice, SHARED),
        "alice sees the collective one: {alice:?}"
    );
    assert!(
        !has(&alice, BOB_SECRET),
        "alice must NOT receive bob's private reflection: {alice:?}"
    );

    let bob = composed_contents(&fixture, Some(BOB), &skill_id);
    assert!(has(&bob, BOB_SECRET), "bob sees his own: {bob:?}");
    assert!(has(&bob, SHARED), "bob sees the collective one: {bob:?}");
    assert!(
        !has(&bob, ALICE_SECRET),
        "bob must NOT receive alice's private reflection: {bob:?}"
    );

    let outsider = composed_contents(&fixture, Some("ai:mallory-4059"), &skill_id);
    assert!(
        !has(&outsider, ALICE_SECRET) && !has(&outsider, BOB_SECRET),
        "a third agent receives no private reflection: {outsider:?}"
    );
}

#[test]
fn local_operator_posture_is_unchanged_4059() {
    let (fixture, skill_id) = seeded();
    let operator = composed_contents(&fixture, None, &skill_id);
    for marker in [ALICE_SECRET, BOB_SECRET, SHARED] {
        assert!(
            has(&operator, marker),
            "the single-tenant trust-all posture composes {marker}: {operator:?}"
        );
    }
}

#[test]
fn compositional_context_is_funnelled_not_allowlisted_4059() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let allowlist =
        std::fs::read_to_string(root.join("tests/authority_boundary_3549_allowlist.txt"))
            .expect("read allowlist");
    let exempt = allowlist.lines().any(|l| {
        let mut cols = l.split('\t');
        cols.next() == Some("read") && cols.next() == Some("memory_skill_compositional_context")
    });
    assert!(
        !exempt,
        "memory_skill_compositional_context reads memory rows and must not be \
         exempted from the #3549 read funnel"
    );
    let handler =
        std::fs::read_to_string(root.join("src/mcp/tools/skill_compositional_context.rs"))
            .expect("read handler");
    let production = handler
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        production.contains("crate::visibility::is_readable_on_query("),
        "the compositional handler must call the canonical read funnel"
    );
    // The MCP dispatch must hand the resolved read caller to the handler. Since
    // #9174 (vote C1c) the four skill read verbs reach their handlers through
    // ONE funnel, `skill_read`, which passes the dispatch-resolved read caller
    // and the node's signing state; `check_read_funnel` pins both hops.
    let mcp = std::fs::read_to_string(root.join("src/mcp/mod.rs")).expect("read mcp");
    assert_eq!(
        check_read_funnel(&mcp),
        Ok(()),
        "the compositional-context handler must receive the resolved read caller \
         through the skill_read funnel"
    );
}

/// Header of the compositional-context MCP dispatch arm in `src/mcp/mod.rs`.
const ARM_HEADER: &str = "fn dispatch_memory_skill_compositional_context(";
/// Header of the skill read funnel (a top-level `fn`, so it starts a line).
const FUNNEL_HEADER: &str = "\nfn skill_read(";
/// The one handler the arm must route through the funnel.
const HANDLER: &str = "handle_skill_compositional_context";
/// The arm's only legal call: the handler handed to the funnel.
const ARM_CALL: &str = "skill_read(ctx, handle_skill_compositional_context)";
/// The funnel's handler parameter: a read verb with a read-caller slot.
const FUNNEL_SLOT: &str =
    "read: fn(&rusqlite::Connection, &Value, Option<&str>, NodeSigning) -> Result<Value, String>,";
/// The funnel's only legal handler call: the dispatch-resolved read caller.
const FUNNEL_CALL: &str = "read(ctx.conn, ctx.arguments, ctx.authority.read_caller(), node)";

/// Why a source text breaks the #4059 invariant "the resolved read caller
/// reaches the compositional-context handler through the read funnel".
#[derive(Debug, PartialEq, Eq)]
enum FunnelBreach {
    ArmMissing,
    ArmBypassesFunnel,
    ArmCallsHandlerOutsideFunnel,
    FunnelMissing,
    FunnelNoCallerSlot,
    FunnelUnresolvedCaller,
    FunnelCallsHandlerMoreThanOnce,
}

/// The #4059 / #9174 invariant over the text of `src/mcp/mod.rs`. Comment
/// lines are removed first, so a commented-out call never satisfies it.
fn check_read_funnel(mcp: &str) -> Result<(), FunnelBreach> {
    let arm = fn_body(mcp, ARM_HEADER).ok_or(FunnelBreach::ArmMissing)?;
    if !arm.contains(ARM_CALL) {
        return Err(FunnelBreach::ArmBypassesFunnel);
    }
    if arm.matches(HANDLER).count() != 1 {
        return Err(FunnelBreach::ArmCallsHandlerOutsideFunnel);
    }
    let funnel = fn_body(mcp, FUNNEL_HEADER).ok_or(FunnelBreach::FunnelMissing)?;
    if !funnel.contains(FUNNEL_SLOT) {
        return Err(FunnelBreach::FunnelNoCallerSlot);
    }
    if !funnel.contains(FUNNEL_CALL) {
        return Err(FunnelBreach::FunnelUnresolvedCaller);
    }
    if funnel.matches("read(").count() != 1 {
        return Err(FunnelBreach::FunnelCallsHandlerMoreThanOnce);
    }
    Ok(())
}

/// The body of the first `fn` whose header starts with `header` in `src`, up to
/// its closing top-level `}`, without `//` comment lines.
fn fn_body(src: &str, header: &str) -> Option<String> {
    let body = src.split(header).nth(1)?.split("\n}\n").next()?;
    Some(
        body.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// A well-formed funnel and arm, the shape the real source has.
const GOOD_FUNNEL: &str = "\nfn skill_read(
    ctx: &ToolDispatchCtx<'_>,
    read: fn(&rusqlite::Connection, &Value, Option<&str>, NodeSigning) -> Result<Value, String>,
) -> Result<Value, String> {
    let node = NodeSigning::of(ctx.active_keypair);
    read(ctx.conn, ctx.arguments, ctx.authority.read_caller(), node)
}
";
const GOOD_ARM: &str = "
fn dispatch_memory_skill_compositional_context(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> {
    skill_read(ctx, handle_skill_compositional_context)
}
";

#[test]
fn read_funnel_check_accepts_the_well_formed_shape_4059() {
    assert_eq!(
        check_read_funnel(&format!("{GOOD_FUNNEL}{GOOD_ARM}")),
        Ok(())
    );
}

/// Broken copy (a): the arm calls the handler directly, bypassing `skill_read`.
#[test]
fn read_funnel_check_rejects_an_arm_that_bypasses_the_funnel_4059() {
    let arm = GOOD_ARM.replace(
        ARM_CALL,
        "handle_skill_compositional_context(ctx.conn, ctx.arguments, \
         ctx.authority.read_caller(), NodeSigning::of(ctx.active_keypair))",
    );
    assert_eq!(
        check_read_funnel(&format!("{GOOD_FUNNEL}{arm}")),
        Err(FunnelBreach::ArmBypassesFunnel)
    );
}

/// Broken copy (a'): the arm calls the funnel AND the handler directly.
#[test]
fn read_funnel_check_rejects_a_second_direct_handler_call_4059() {
    let arm = GOOD_ARM.replace(
        ARM_CALL,
        "let _ = handle_skill_compositional_context(ctx.conn, ctx.arguments, None, \
         NodeSigning::NonSigning);\n    skill_read(ctx, handle_skill_compositional_context)",
    );
    assert_eq!(
        check_read_funnel(&format!("{GOOD_FUNNEL}{arm}")),
        Err(FunnelBreach::ArmCallsHandlerOutsideFunnel)
    );
}

/// Broken copy (b): `skill_read` hands a caller other than the resolved one.
#[test]
fn read_funnel_check_rejects_an_unresolved_caller_4059() {
    for caller in ["None", "Some(\"operator\")", "ctx.mcp_client"] {
        let funnel = GOOD_FUNNEL.replace("ctx.authority.read_caller()", caller);
        assert_eq!(
            check_read_funnel(&format!("{funnel}{GOOD_ARM}")),
            Err(FunnelBreach::FunnelUnresolvedCaller),
            "caller {caller}"
        );
    }
}

/// Broken copy (b'): `skill_read` calls the handler a second time with another caller.
#[test]
fn read_funnel_check_rejects_a_second_funnel_call_4059() {
    let funnel = GOOD_FUNNEL.replace(
        &format!("    {FUNNEL_CALL}\n"),
        &format!("    let _ = read(ctx.conn, ctx.arguments, None, node);\n    {FUNNEL_CALL}\n"),
    );
    assert_eq!(
        check_read_funnel(&format!("{funnel}{GOOD_ARM}")),
        Err(FunnelBreach::FunnelCallsHandlerMoreThanOnce)
    );
}

/// Broken copy (b''): the funnel's handler takes no read-caller slot.
#[test]
fn read_funnel_check_rejects_a_funnel_without_a_caller_slot_4059() {
    let funnel = GOOD_FUNNEL.replace("Option<&str>, ", "");
    assert_eq!(
        check_read_funnel(&format!("{funnel}{GOOD_ARM}")),
        Err(FunnelBreach::FunnelNoCallerSlot)
    );
}

/// Broken copy (c): the required call appears only inside a comment.
#[test]
fn read_funnel_check_rejects_a_call_only_in_a_comment_4059() {
    let arm = GOOD_ARM.replace(ARM_CALL, &format!("// {ARM_CALL}\n    todo!()"));
    assert_eq!(
        check_read_funnel(&format!("{GOOD_FUNNEL}{arm}")),
        Err(FunnelBreach::ArmBypassesFunnel)
    );
    let funnel = GOOD_FUNNEL.replace(
        &format!("    {FUNNEL_CALL}\n"),
        &format!("    // {FUNNEL_CALL}\n    todo!()\n"),
    );
    assert_eq!(
        check_read_funnel(&format!("{funnel}{GOOD_ARM}")),
        Err(FunnelBreach::FunnelUnresolvedCaller)
    );
}

/// Missing functions are breaches, never a silent pass.
#[test]
fn read_funnel_check_rejects_missing_functions_4059() {
    assert_eq!(
        check_read_funnel(GOOD_FUNNEL),
        Err(FunnelBreach::ArmMissing)
    );
    assert_eq!(
        check_read_funnel(GOOD_ARM),
        Err(FunnelBreach::FunnelMissing)
    );
}

/// #4059 (R10b retest gap) — ONE candidate reflection whose at-rest envelope
/// cannot be decrypted must not deny the composition to every caller. Pre-fix
/// the per-candidate fail-closed `db::get` propagated the decode error and
/// the whole tool answered "internal storage error". Now the poisoned
/// candidate is OMITTED (its content never returned) and the healthy sibling
/// is still composed.
#[test]
fn poisoned_candidate_is_omitted_not_fatal_4059() {
    const HEALTHY: &str = "HEALTHY-4059";
    const POISON: &str = "POISON-4059";
    let fixture = Fixture::new();
    author_reflection(&fixture, ALICE, HEALTHY, "collective");
    author_reflection(&fixture, ALICE, POISON, "collective");
    let skill_id = register_composing_skill(&fixture);
    {
        // Every MCP child above has exited (dropped); poison one row.
        let conn = rusqlite::Connection::open(&fixture.db).expect("open");
        let poisoned = conn
            .execute(
                "UPDATE memories SET encrypted_envelope = zeroblob(96) \
                 WHERE namespace = ?1 AND memory_kind = 'reflection' AND content = ?2",
                rusqlite::params![NS, POISON],
            )
            .expect("poison envelope");
        assert_eq!(poisoned, 1, "fixture: exactly one reflection poisoned");
    }
    for caller in [Some(BOB), Some(ALICE), None] {
        let mut mcp = Mcp::start(&fixture, caller);
        let result = mcp.call(
            "memory_skill_compositional_context",
            &json!({"skill_id": skill_id}),
        );
        assert_ne!(
            result["isError"], true,
            "{caller:?}: one undecryptable candidate must not fail the composition: {result}"
        );
        let text = Mcp::text(&result);
        assert!(
            text.contains(HEALTHY),
            "{caller:?}: healthy sibling composed: {text}"
        );
        assert!(
            !text.contains(POISON),
            "{caller:?}: the poisoned candidate is omitted, never rendered: {text}"
        );
    }
}
