let meta = #{
    name: "v1-ga-session-boot",
    description: "Session boot for v1.0.0 GA graph epic: recall SSOT paths, disk, tip, next node",
    phases: [
        #{ title: "Boot", detail: "read-only session state snapshot for orchestrator" },
    ],
    when_to_use: "Start of a GA campaign session or after TMUX reconnect before /goal resume",
};

phase("Boot");

let r = agent(
    "You are the v1.0.0 GA session boot scout (read-only). "
    + "Working tree MUST be /home/fate_two/v07/v09-dev on release/v1.0.0. "
    + "1) Run: df -h / ; git fetch origin ; git status -sb ; git rev-parse HEAD ; git log -3 --oneline. "
    + "2) Confirm .codegraph exists at repo root (codegraph pin is this path only). "
    + "3) List open PRs to release/v1.0.0 via gh pr list --base release/v1.0.0 --state open. "
    + "4) Read docs/handoff/GRAPH-ENGINEERING-V1-GA-PROCESS.md and cite epic issue #2682. "
    + "5) Return a structured summary: tip_sha, free_disk_g, next_graph_node (Gate1|Gate2|capacity|2676|Gate3|Gate4), "
    + "open_pr_numbers, blockers. Use shell tools; do not edit files.",
    #{
        label: "ga-session-boot",
        capability_mode: "read-only",
        agent_type: "explore",
    },
);

if r == () || !r.success {
    pause("infra", "Session boot agent failed — fix environment then resume.");
}

complete(#{
    summary: "session boot complete — orchestrator must dual-checkpoint and continue graph node",
    boot: r.output,
    epic_issue: 2682,
});
