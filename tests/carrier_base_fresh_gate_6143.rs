// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6143 -- `chain/**` and `rehearsal/**` PR bases have no required status checks
//! and no up-to-date-head rule, so a green gate on a stale head can be merged.
//!
//! Repo-side fix pinned here: (1) `scripts/check_carrier_base_fresh.py` fails
//! closed when the merge ref a `pull_request` job judged is not built on the LIVE
//! tip of a carrier base; (2) `c8-precheck.yml` runs it on every PR into a carrier
//! base; (3) the carrier ruleset the repository settings must carry is declared
//! in `docs/ci/CARRIER-BRANCH-GATES.md` so a removed rule is a reviewable diff.
//! Fail closed (per ERRORS-01, ERRORS-02): every assertion returns a `Result`.

use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult = Result<(), String>;

const JOB_NAME: &str = "Carrier-base freshness gate (#6143)";
const SCRIPT: &str = "scripts/check_carrier_base_fresh.py";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root().join(rel)).map_err(|e| format!("read {rel}: {e}"))
}

fn workflow() -> Result<serde_yaml_ng::Value, String> {
    serde_yaml_ng::from_str(&read(".github/workflows/c8-precheck.yml")?)
        .map_err(|e| format!("parse c8-precheck.yml: {e}"))
}

fn on_block(wf: &serde_yaml_ng::Value) -> Result<&serde_yaml_ng::Value, String> {
    wf.get("on")
        .or_else(|| wf.get(serde_yaml_ng::Value::Bool(true)))
        .ok_or_else(|| "workflow has no `on:` block".to_string())
}

fn branch_list(on: &serde_yaml_ng::Value, event: &str) -> Result<Vec<String>, String> {
    let seq = on
        .get(event)
        .and_then(|e| e.get("branches"))
        .and_then(serde_yaml_ng::Value::as_sequence)
        .ok_or_else(|| format!("on.{event}.branches missing"))?;
    Ok(seq
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect())
}

#[test]
fn carrier_base_fresh_script_self_test_passes_6143() -> TestResult {
    let script = root().join(SCRIPT);
    if !Path::new(&script).is_file() {
        return Err(format!("{SCRIPT} is missing (#6143)"));
    }
    let scratch = root().join(".local-runs");
    std::fs::create_dir_all(&scratch).map_err(|e| format!("mkdir .local-runs: {e}"))?;
    let out = Command::new("python3")
        .args(["-I"])
        .arg(&script)
        .arg("--self-test")
        .env("TMPDIR", &scratch)
        .output()
        .map_err(|e| format!("spawn python3: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "self-test failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[test]
fn workflow_runs_freshness_gate_on_carrier_pr_bases_6143() -> TestResult {
    let wf = workflow()?;
    let on = on_block(&wf)?;
    let pr = branch_list(on, "pull_request")?;
    for base in ["chain/**", "rehearsal/**"] {
        if !pr.iter().any(|b| b == base) {
            return Err(format!("pull_request.branches must include {base}"));
        }
    }
    // #2523/#2508: carrier branches are PR heads too; never in push.branches.
    let push = branch_list(on, "push")?;
    if push
        .iter()
        .any(|b| b.starts_with("chain/") || b.starts_with("rehearsal/"))
    {
        return Err(format!(
            "push.branches must not overlap carrier PR heads: {push:?}"
        ));
    }
    let jobs = wf
        .get("jobs")
        .and_then(serde_yaml_ng::Value::as_mapping)
        .ok_or("no jobs")?;
    let job = jobs
        .values()
        .find(|j| j.get("name").and_then(|n| n.as_str()) == Some(JOB_NAME))
        .ok_or_else(|| format!("no job named {JOB_NAME:?} in c8-precheck.yml"))?;
    if job.get("if").is_some() || job.get("needs").is_some() {
        return Err("the freshness job must have no job-level `if:`/`needs:`".into());
    }
    let steps = job
        .get("steps")
        .and_then(serde_yaml_ng::Value::as_sequence)
        .ok_or("job has no steps")?;
    let checkout_full = steps.iter().any(|s| {
        s.get("with")
            .and_then(|w| w.get("fetch-depth"))
            .is_some_and(|d| d.as_u64() == Some(0) || d.as_str() == Some("0"))
    });
    if !checkout_full {
        return Err("checkout must use fetch-depth: 0".into());
    }
    let gate_step = steps
        .iter()
        .find(|s| {
            s.get("run")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.contains(SCRIPT) && !r.contains("--self-test"))
        })
        .ok_or("no step runs the gate")?;
    let env = gate_step.get("env").ok_or("gate step has no env")?;
    for key in ["GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "PR_HEAD_SHA"] {
        if env.get(key).is_none() {
            return Err(format!("gate step env missing {key}"));
        }
    }
    let selftest = steps.iter().any(|s| {
        s.get("run")
            .and_then(|r| r.as_str())
            .is_some_and(|r| r.contains(SCRIPT) && r.contains("--self-test"))
    });
    if !selftest {
        return Err("workflow must also run the gate's --self-test".into());
    }
    Ok(())
}

#[test]
fn freshness_job_is_declared_in_required_context_ledger_6143() -> TestResult {
    let ledger = read("scripts/qc-allowlists/required-contexts-not-required.txt")?;
    if !ledger.contains("carrier-base-fresh-gate") {
        return Err(
            "rule (f): job id carrier-base-fresh-gate not declared (required or ledger)".into(),
        );
    }
    Ok(())
}

#[test]
fn carrier_ruleset_is_documented_for_relay_6143() -> TestResult {
    let doc = read("docs/ci/CARRIER-BRANCH-GATES.md")?;
    for needle in [
        "refs/heads/chain/**",
        "refs/heads/rehearsal/**",
        "strict_required_status_checks_policy",
        JOB_NAME,
        "Enterprise-federation cert-expiry gate (cert §7 / F7)",
        "#6143",
    ] {
        if !doc.contains(needle) {
            return Err(format!(
                "docs/ci/CARRIER-BRANCH-GATES.md must mention {needle:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn carrier_ruleset_live_checker_self_test_passes_6143() -> TestResult {
    let out = Command::new("python3")
        .args(["-I", "scripts/check_carrier_ruleset_live.py", "--self-test"])
        .current_dir(root())
        .output()
        .map_err(|e| format!("spawn python3: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ruleset checker self-test failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 2 (#6143 review F1-F7 + security F1-F4). Decision for the pre-apply
// behaviour: 5-agent vote (4d3ea1c5), memory a03dd15d: a committed state
// marker (`pending-apply` | `applied`) tied to OPEN tracking issue #6182.
// ---------------------------------------------------------------------------

const VERIFIER: &str = "scripts/check_carrier_ruleset_live.py";
const PAYLOAD: &str = "docs/ci/carrier-ruleset.json";
const CARRIER_DECL: &str = "scripts/qc-allowlists/required-contexts-carrier.txt";
const RELEASE_DECL: &str = "scripts/qc-allowlists/required-contexts-release.txt";
const STATE_FILE: &str = "scripts/qc-allowlists/carrier-ruleset-state.json";
const VERIFIER_JOB: &str = "Carrier-ruleset live verifier (#6143)";
const TRACKING_ISSUE: u64 = 6182;
const ACTIONS_APP_ID: u64 = 15368;
const POST_CMD: &str =
    "gh api -X POST repos/alphaonedev/ai-memory-mcp/rulesets --input docs/ci/carrier-ruleset.json";

fn decl_lines(rel: &str) -> Result<Vec<String>, String> {
    Ok(read(rel)?
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

fn payload() -> Result<serde_json::Value, String> {
    serde_json::from_str(&read(PAYLOAD)?).map_err(|e| format!("parse {PAYLOAD}: {e}"))
}

fn scratch(name: &str) -> Result<PathBuf, String> {
    let dir = root().join(".local-runs").join(format!("t6143-{name}"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    Ok(dir)
}

fn write_json(dir: &Path, file: &str, v: &serde_json::Value) -> Result<PathBuf, String> {
    let p = dir.join(file);
    std::fs::write(&p, v.to_string()).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

/// The payload as GitHub would return it for an admin reader (id + visible
/// `bypass_actors`).
fn live_from_payload() -> Result<serde_json::Value, String> {
    let mut rs = payload()?;
    let obj = rs.as_object_mut().ok_or("payload is not an object")?;
    obj.insert("id".into(), serde_json::json!(424_242));
    Ok(rs)
}

fn run_verifier(
    name: &str,
    rulesets: &serde_json::Value,
    state: &str,
    issue: &str,
    extra: &[&str],
) -> Result<(i32, String), String> {
    let dir = scratch(name)?;
    let rs_file = write_json(&dir, "rulesets.json", rulesets)?;
    let st_file = write_json(
        &dir,
        "state.json",
        &serde_json::json!({"state": state, "tracking_issue": TRACKING_ISSUE}),
    )?;
    let out = Command::new("python3")
        .arg("-I")
        .arg(root().join(VERIFIER))
        .arg("--rulesets-file")
        .arg(&rs_file)
        .arg("--state-file")
        .arg(&st_file)
        .args(["--tracking-issue-state", issue])
        .args(extra)
        .current_dir(root())
        .output()
        .map_err(|e| format!("spawn python3: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.code().unwrap_or(-1), text))
}

fn expect(name: &str, got: &(i32, String), rc: i32, needle: &str) -> TestResult {
    let (got_rc, got_text) = got;
    if *got_rc != rc || !got_text.contains(needle) {
        return Err(format!(
            "{name}: rc={got_rc} (want {rc}), output must contain {needle:?}; got:\n{got_text}"
        ));
    }
    Ok(())
}

fn rsc_params(rs: &mut serde_json::Value) -> Result<&mut serde_json::Value, String> {
    rs.get_mut("rules")
        .and_then(|r| r.get_mut(0))
        .and_then(|r| r.get_mut("parameters"))
        .ok_or_else(|| "payload rules[0].parameters missing".to_string())
}

/// F2/F4 + security F3: the exact POST body is committed, executable and
/// carries every setting the carriers need.
#[test]
fn carrier_ruleset_payload_is_exact_and_matches_declaration_6143() -> TestResult {
    let p = payload()?;
    let want = |k: &str, v: serde_json::Value| -> TestResult {
        if p.get(k) == Some(&v) {
            Ok(())
        } else {
            Err(format!("{PAYLOAD}: {k} must be {v}, got {:?}", p.get(k)))
        }
    };
    want("target", serde_json::json!("branch"))?;
    want("enforcement", serde_json::json!("active"))?;
    want("bypass_actors", serde_json::json!([]))?;
    let cond = p
        .pointer("/conditions/ref_name")
        .ok_or("no conditions.ref_name")?;
    if cond.get("include")
        != Some(&serde_json::json!([
            "refs/heads/chain/**",
            "refs/heads/rehearsal/**"
        ]))
        || cond.get("exclude") != Some(&serde_json::json!([]))
    {
        return Err(format!("{PAYLOAD}: include/exclude wrong: {cond}"));
    }
    let rules = p
        .get("rules")
        .and_then(|r| r.as_array())
        .ok_or("no rules")?;
    if rules.len() != 1
        || rules[0].get("type") != Some(&serde_json::json!("required_status_checks"))
    {
        return Err("exactly one required_status_checks rule expected".into());
    }
    let params = &rules[0]["parameters"];
    for key in [
        "strict_required_status_checks_policy",
        "do_not_enforce_on_create",
    ] {
        if params.get(key) != Some(&serde_json::json!(true)) {
            return Err(format!("{PAYLOAD}: {key} must be true"));
        }
    }
    let checks = params["required_status_checks"]
        .as_array()
        .ok_or("required_status_checks not an array")?;
    let mut ctx = Vec::new();
    for c in checks {
        if c.get("integration_id") != Some(&serde_json::json!(ACTIONS_APP_ID)) {
            return Err(format!(
                "context {c} must pin integration_id {ACTIONS_APP_ID}"
            ));
        }
        ctx.push(
            c["context"]
                .as_str()
                .ok_or("context not a string")?
                .to_owned(),
        );
    }
    let mut decl = decl_lines(CARRIER_DECL)?;
    let mut sorted_ctx = ctx.clone();
    sorted_ctx.sort();
    decl.sort();
    if sorted_ctx != decl {
        return Err(format!("{PAYLOAD} contexts != {CARRIER_DECL}"));
    }
    if !decl.iter().any(|d| d == JOB_NAME) {
        return Err(format!("{CARRIER_DECL} must declare {JOB_NAME:?}"));
    }
    // F1: every release-required context also guards the carriers.
    for r in decl_lines(RELEASE_DECL)? {
        if !decl.contains(&r) {
            return Err(format!("{CARRIER_DECL} is missing release context {r:?}"));
        }
    }
    Ok(())
}

/// F1: the freshness job is carrier-only; it never enters the release
/// declaration (check-required-contexts-live pins release/v1.0.0 protection).
#[test]
fn freshness_job_stays_out_of_release_declaration_6143() -> TestResult {
    if decl_lines(RELEASE_DECL)?.iter().any(|l| l == JOB_NAME) {
        return Err(format!("{JOB_NAME:?} must not be in {RELEASE_DECL}"));
    }
    let ledger = read("scripts/qc-allowlists/required-contexts-not-required.txt")?;
    let fresh = ledger
        .lines()
        .find(|l| l.starts_with("c8-precheck.yml carrier-base-fresh-gate "))
        .ok_or("no ledger line for carrier-base-fresh-gate")?;
    if fresh.contains("required-contexts-release.txt line") || !fresh.contains(CARRIER_DECL) {
        return Err(format!(
            "ledger line must point at {CARRIER_DECL}, not the release declaration: {fresh}"
        ));
    }
    let live = ledger
        .lines()
        .find(|l| l.starts_with("c8-precheck.yml carrier-ruleset-live-gate "))
        .ok_or("no ledger line for carrier-ruleset-live-gate")?;
    if !live.contains(&format!("#{TRACKING_ISSUE}")) {
        return Err(format!(
            "verifier ledger line must name #{TRACKING_ISSUE}: {live}"
        ));
    }
    Ok(())
}

#[test]
fn carrier_state_marker_names_tracking_issue_6143() -> TestResult {
    let st: serde_json::Value =
        serde_json::from_str(&read(STATE_FILE)?).map_err(|e| format!("parse {STATE_FILE}: {e}"))?;
    let state = st.get("state").and_then(|s| s.as_str()).unwrap_or("");
    if state != "pending-apply" && state != "applied" {
        return Err(format!(
            "{STATE_FILE}: state must be pending-apply|applied, got {state:?}"
        ));
    }
    if st.get("tracking_issue") != Some(&serde_json::json!(TRACKING_ISSUE)) {
        return Err(format!(
            "{STATE_FILE}: tracking_issue must be {TRACKING_ISSUE}"
        ));
    }
    Ok(())
}

/// F2: a c8 job runs the verifier on every PR (ledgered, `GH_TOKEN` plumbed).
#[test]
fn workflow_runs_carrier_ruleset_verifier_6143() -> TestResult {
    let wf = workflow()?;
    let jobs = wf
        .get("jobs")
        .and_then(serde_yaml_ng::Value::as_mapping)
        .ok_or("no jobs")?;
    let job = jobs
        .get("carrier-ruleset-live-gate")
        .ok_or("no job carrier-ruleset-live-gate in c8-precheck.yml")?;
    if job.get("name").and_then(|n| n.as_str()) != Some(VERIFIER_JOB) {
        return Err(format!("job name must be {VERIFIER_JOB:?}"));
    }
    if job.get("if").is_some() || job.get("needs").is_some() {
        return Err("verifier job must have no job-level if:/needs:".into());
    }
    let steps = job
        .get("steps")
        .and_then(serde_yaml_ng::Value::as_sequence)
        .ok_or("no steps")?;
    let run = steps
        .iter()
        .find(|s| {
            s.get("run")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.contains(VERIFIER) && !r.contains("--self-test"))
        })
        .ok_or("no step runs the verifier")?;
    if run.get("env").and_then(|e| e.get("GH_TOKEN")).is_none() {
        return Err("verifier step must set GH_TOKEN".into());
    }
    if !steps.iter().any(|s| {
        s.get("run")
            .and_then(|r| r.as_str())
            .is_some_and(|r| r.contains(VERIFIER) && r.contains("--self-test"))
    }) {
        return Err("workflow must run the verifier --self-test".into());
    }
    Ok(())
}

/// F3 + security F4: a ruleset that does not really protect the carriers fails.
#[test]
fn verifier_rejects_weakened_carrier_rulesets_6143() -> TestResult {
    let good = live_from_payload()?;
    expect(
        "applied+good",
        &run_verifier("good", &serde_json::json!([good]), "applied", "open", &[])?,
        0,
        "carrier-ruleset-live: OK",
    )?;

    let mut v = good.clone();
    v["conditions"]["ref_name"]["exclude"] = serde_json::json!(["refs/heads/chain/promo6-ssh"]);
    expect(
        "exclude",
        &run_verifier("exclude", &serde_json::json!([v]), "applied", "open", &[])?,
        1,
        "exclude",
    )?;

    let mut v = good.clone();
    v["bypass_actors"] = serde_json::json!([{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]);
    expect(
        "bypass",
        &run_verifier("bypass", &serde_json::json!([v]), "applied", "open", &[])?,
        1,
        "bypass_actors",
    )?;

    let mut v = good.clone();
    rsc_params(&mut v)?["required_status_checks"][0]["integration_id"] = serde_json::json!(999);
    expect(
        "integration",
        &run_verifier(
            "integration",
            &serde_json::json!([v]),
            "applied",
            "open",
            &[],
        )?,
        1,
        "integration_id",
    )?;

    let mut v = good.clone();
    rsc_params(&mut v)?
        .as_object_mut()
        .ok_or("params not an object")?
        .remove("do_not_enforce_on_create");
    expect(
        "create",
        &run_verifier("create", &serde_json::json!([v]), "applied", "open", &[])?,
        1,
        "do_not_enforce_on_create",
    )?;

    let mut v = good.clone();
    rsc_params(&mut v)?["strict_required_status_checks_policy"] = serde_json::json!(false);
    expect(
        "strict",
        &run_verifier("strict", &serde_json::json!([v]), "applied", "open", &[])?,
        1,
        "strict_required_status_checks_policy",
    )?;

    let mut v = good.clone();
    rsc_params(&mut v)?["required_status_checks"]
        .as_array_mut()
        .ok_or("checks not an array")?
        .pop();
    expect(
        "missing ctx",
        &run_verifier("missing", &serde_json::json!([v]), "applied", "open", &[])?,
        1,
        "contexts",
    )?;

    let mut v = good.clone();
    v.as_object_mut()
        .ok_or("not an object")?
        .remove("bypass_actors");
    expect(
        "hidden bypass",
        &run_verifier(
            "hidden",
            &serde_json::json!([v.clone()]),
            "applied",
            "open",
            &[],
        )?,
        0,
        "UNVERIFIED",
    )?;
    expect(
        "hidden bypass strict",
        &run_verifier(
            "hidden-strict",
            &serde_json::json!([v]),
            "applied",
            "open",
            &["--require-full-view"],
        )?,
        1,
        "UNVERIFIED",
    )
}

/// Vote (4d3ea1c5): the pending marker only skips while the carriers are
/// genuinely unprotected AND the tracking issue is open.
#[test]
fn verifier_pending_state_machine_6143() -> TestResult {
    let good = live_from_payload()?;
    let none = serde_json::json!([]);
    expect(
        "pending+absent+open",
        &run_verifier("p-open", &none, "pending-apply", "open", &[])?,
        0,
        "UNPROTECTED",
    )?;
    expect(
        "pending+absent+closed",
        &run_verifier("p-closed", &none, "pending-apply", "closed", &[])?,
        1,
        &format!("#{TRACKING_ISSUE}"),
    )?;
    expect(
        "pending+live",
        &run_verifier(
            "p-live",
            &serde_json::json!([good.clone()]),
            "pending-apply",
            "open",
            &[],
        )?,
        1,
        "applied",
    )?;
    let mut renamed = good.clone();
    renamed["name"] = serde_json::json!("something-else");
    rsc_params(&mut renamed)?["strict_required_status_checks_policy"] = serde_json::json!(false);
    expect(
        "pending+weak renamed",
        &run_verifier(
            "p-weak",
            &serde_json::json!([renamed]),
            "pending-apply",
            "open",
            &[],
        )?,
        1,
        "strict_required_status_checks_policy",
    )?;
    expect(
        "applied+absent",
        &run_verifier("a-absent", &none, "applied", "open", &[])?,
        1,
        "no carrier ruleset",
    )?;
    expect(
        "bogus state",
        &run_verifier("bogus", &none, "later", "open", &[])?,
        1,
        "state",
    )
}

/// F3: the listing is paginated and every gh call is bounded.
#[test]
fn verifier_paginates_and_bounds_gh_calls_6143() -> TestResult {
    let src = read(VERIFIER)?;
    for needle in ["--paginate", "timeout="] {
        if !src.contains(needle) {
            return Err(format!("{VERIFIER} must use {needle:?}"));
        }
    }
    Ok(())
}

/// F7: the self-test scratch is always REPO_ROOT/.local-runs, never TMPDIR.
#[test]
fn freshness_self_test_ignores_inherited_tmpdir_6143() -> TestResult {
    let dir = scratch("tmpdir-decoy")?;
    let decoy = dir.join("not-a-directory");
    std::fs::write(&decoy, b"decoy").map_err(|e| format!("write decoy: {e}"))?;
    let out = Command::new("python3")
        .arg("-I")
        .arg(root().join(SCRIPT))
        .arg("--self-test")
        .env("TMPDIR", &decoy)
        .output()
        .map_err(|e| format!("spawn python3: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "self-test must not use TMPDIR: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// F6 + security F1/F3: no enforcement overclaim; one-command GOD path.
#[test]
fn docs_and_changelog_do_not_overclaim_6143() -> TestResult {
    let doc = read("docs/ci/CARRIER-BRANCH-GATES.md")?;
    for needle in [
        POST_CMD,
        "--require-full-view",
        "## Limits",
        "#6140",
        "#6182",
        "do_not_enforce_on_create",
        "24733250",
        CARRIER_DECL,
    ] {
        if !doc.contains(needle) {
            return Err(format!(
                "docs/ci/CARRIER-BRANCH-GATES.md must mention {needle:?}"
            ));
        }
    }
    let frag = read("changelog.d/6143.fixed.md")?;
    if frag.contains("refuses a merge ref") || !frag.contains("advisory") || !frag.contains("#6182")
    {
        return Err("changelog.d/6143.fixed.md must state the job is advisory until #6182 applies the ruleset".into());
    }
    let ledger = read("scripts/qc-allowlists/required-contexts-not-required.txt")?;
    if ledger
        .lines()
        .filter(|l| l.contains("#6143"))
        .any(|l| l.contains("hard-fails on every PR"))
    {
        return Err("#6143 ledger lines must not claim the job hard-fails merges".into());
    }
    Ok(())
}
