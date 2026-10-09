// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6143 -- `chain/**` and `rehearsal/**` PR bases have no required status checks
//! and no up-to-date-head rule, so a green gate on a stale head can be merged.
//!
//! Repo-side fix pinned here: (1) `scripts/check_carrier_base_fresh.py` fails
//! closed when the merge ref a pull_request job judged is not built on the LIVE
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
