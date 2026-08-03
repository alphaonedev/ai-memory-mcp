let meta = #{
    name: "v1-ga-land-pr-beat",
    description: "Land one PR beat: verify CLEAN checks, review reminder, merge readiness report (orchestrator merges)",
    phases: [
        #{ title: "Inspect", detail: "PR status + check-runs" },
        #{ title: "Review gate", detail: "code + security audit checklist" },
    ],
    when_to_use: "Before merging any PR into release/v1.0.0 under the GA graph epic",
};

let pr = if args == () { () } else { args.pr };
if pr == () {
    pause("verification", "Pass args.pr — the pull request number to inspect.");
}

phase("Inspect");

let insp = agent(
    "Inspect GitHub PR #" + pr.to_string() + " on alphaonedev/ai-memory-mcp targeting release/v1.0.0. "
    + "Use gh: pr view JSON (state, mergeStateStatus, mergeable, headRefOid, baseRefName, title); "
    + "check-runs API for head SHA — pending must be 0, no failed conclusions (success/skipped/neutral only). "
    + "Report: clean_or_not, head_sha, failed_checks, behind_or_dirty, files_changed_summary. "
    + "Do not merge. Do not edit.",
    #{
        label: "pr-inspect",
        capability_mode: "read-only",
        agent_type: "explore",
    },
);

phase("Review gate");

let rev = agent(
    "You are the pre-merge CODE REVIEW + SECURITY AUDIT gate for PR #" + pr.to_string() + ". "
    + "Repo /home/fate_two/v07/v09-dev. Fetch PR head if needed via gh. "
    + "Audit the CONTROL not the diff summary: fail-open vs fail-closed, silent data loss, false-success, "
    + "namespace confinement, credential redaction, feature gates. "
    + "Return: verdict APPROVE|BLOCK, findings[], security_findings[], merge_conditions[]. "
    + "BLOCK if any unresolved high severity. Do not merge.",
    #{
        label: "pr-review-security",
        capability_mode: "read-only",
        agent_type: "explore",
    },
);

complete(#{
    summary: "PR beat inspection complete — orchestrator merges only if CLEAN and APPROVE",
    pr: pr,
    inspect: if insp != () && insp.success { insp.output } else { () },
    review: if rev != () && rev.success { rev.output } else { () },
    epic_issue: 2682,
});
