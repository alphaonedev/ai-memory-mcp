# Developer setup notes

How-to and setup text relocated verbatim from the tracked `CLAUDE.md` so the always-read rules stay small (operator efficiency order E5, 2026-10-10). These are procedures, not rules; the rules that point here are in `CLAUDE.md`. Base text: `CLAUDE.md` at `9019c504d` (branch `fix/crossroads-1x3-promo6-ssh`).

## LSP setup (v0.7.0 — Claude Code rust-analyzer plugin)

Per the v0.7.0 SHIP campaign retrospective (Anthropic's "How Claude Code
works in large codebases" article, 2026-05-14): LSP is one of the
highest-leverage Claude Code investments for multi-language codebases.
It gives Claude symbol-precision navigation (`go-to-definition`,
`find-all-references`, `incoming-calls`, `workspace-symbol`) rather
than grep-and-read on ambiguous text matches.

Configured in [`.claude/settings.json`](.claude/settings.json) at v0.7.0
ship.

**One-time per-developer setup:**

```bash
rustup component add rust-analyzer
```

**Verification:**

Open this repo in Claude Code and ask: *"find all callers of
`forensic_sink_test_lock` in src/governance/audit.rs"*. The LSP path
returns the 4 indirect-caller test modules in milliseconds via
`findReferences`; the grep-and-read fallback walks 200k+ LOC reading
files until it finds them. Both work; the LSP path is ~50x faster and
symbol-precise (no false hits on identically-named items in different
crates).

**Caveats:**

- Initial workspace indexing on this 200k+ LOC + 600+ dep codebase
  takes 2-5 min; subsequent same-day sessions are warm.
- rust-analyzer can take 2-4 GB resident memory. On hosts with <16 GB
  free, expect indexing to fail under concurrent `cargo` + `llvm-cov`
  load (the v0.7.0 SHIP commit cycle exercised this — see #898 for the
  parallel sal-postgres llvm-cov OOM that documented the same memory
  ceiling).
- LSP is *complementary* to the ai-memory substrate, not redundant.
  LSP answers "where is this symbol used in the codebase as it exists
  right now?" — ai-memory answers "what did the prior session learn
  about this symbol's behavior?" Both are needed for engineering work
  that crosses time + space.

`rust-analyzer` is treated as a build-time tool, not a runtime
dependency of ai-memory itself. CI doesn't require it.

## CodeGraph setup (v0.7.0 — Claude Code MCP server)

Per the 2026-05-19/20 v0.7.0 ship-hardening cycle retrospective (issue #923):
**CodeGraph is the L1 structural-safety tool** in the AI-NHI development
workflow. It is **complementary to** rust-analyzer LSP (above), NOT a
replacement.

| Question shape | Tool |
|---|---|
| "Where is this exact symbol used right now?" | LSP (`findReferences`, ~50× faster than grep) |
| "What's the shape of the code? What calls what? What would break if I changed Z?" | CodeGraph (`codegraph_callers`, `codegraph_impact`, `codegraph_context`) |
| "What did the prior session learn about this symbol's behavior?" | ai-memory (`memory_recall`) |

**One-time per-developer setup:**

```bash
npm install -g @colbymchenry/codegraph
codegraph install   # writes ~/.claude.json + ~/.claude/CLAUDE.md + ~/.claude/settings.json
cd /path/to/ai-memory-mcp
codegraph init -i   # indexes into .codegraph/codegraph.db (~63 MB for v0.7.0)
```

The installer auto-writes a global `~/.claude/CLAUDE.md` instructing every
future Claude Code session to use the `codegraph_*` MCP tools by default;
no project-side changes are needed for the runtime priors.

**When CodeGraph would have saved cycles (v0.7.0 cases):**

- The 10-site `CallerContext::for_agent("<literal>")` hardcode sweep
  across `handlers/{recall,memories,links,memories_query,power,power_consolidation,kg,archive,admin,hook_subscribers,http}.rs` —
  one `codegraph_search` query vs. hours of iterative greps.
- Impact analysis when adding `headers: HeaderMap` to 8 handler entry
  points — `codegraph callers <fn>` would have confirmed every call
  site got the matching update.
- Handler-chain tracing for the `bucket_c_namespace_standards_enforce`
  and `pending_approve_missing_id_returns_404` test failures —
  `codegraph context` surfaced the route → handler → SAL → error-mapping
  chain in one query.

**What CodeGraph does NOT replace:**

- Semantic correctness review (e.g., "is this use of `for_admin`
  appropriate here?") — that's L2, a code-reviewer subagent invocation.
- Security review of business logic — also L2.
- Runtime / behavioral correctness — L3, `cargo test` against the
  scoped Docker stack at `infra/lan-parity-test/`.

**Caveats:**

- Index lag: the file watcher debounces ~500ms behind writes. Don't
  re-query immediately after editing a file in the same turn.
- Trust codegraph results: do NOT re-verify symbol lookups with grep.
  Grep is slower, less accurate, and wastes context.
- The `.codegraph/` directory is `.gitignore`'d (per-developer index;
  not committed).

**Allowlist-gated structural checks** (tracked under #923 D2):
`scripts/qc-codegraph-precheck.sh` will run pre-PR + in CI to block
new `CallerContext::for_agent("<literal>")` sites outside the
allowlist + new `for_admin` privacy-bypass sites outside the allowlist
+ dangling callers after symbol removal. This is the **C8** orchestrator
safeguard (added to the C1–C7 set in §"Enforceable Orchestrator
Safeguards"); HARD-BLOCK on any violation.


## Local coverage (matching CI's `coverage.yml`)

```bash
scripts/coverage.sh
```

Runs `cargo llvm-cov --features sal,sal-postgres --lib --tests --workspace
-- --test-threads=1` (byte-for-byte the same invocation as the "Generate
coverage JSON" step in `.github/workflows/coverage.yml`) followed by
`coverage/check-thresholds.sh`. The trailing `-- --test-threads=1` is
**required, not optional** (v0.8.0 #1709 SHIP-HARDEN): the `sal-postgres`
suite shares one `ai_memory_test` database with no per-test schema
isolation, so running it under llvm-cov WITHOUT serialising threads lets
two postgres-backed tests race on shared table/index locks and produces a
spurious local-only failure that never reproduces in CI (which already
serialises). Before `scripts/coverage.sh` existed this was a recurring
trap for anyone running `cargo llvm-cov` locally by hand and omitting the
flag. Point `AI_MEMORY_TEST_POSTGRES_URL` at a live PG16 instance (+ `age`
+ `vector` extensions) to exercise the postgres backend instead of having
those tests self-skip; pass `--no-threshold-check` to generate
`coverage/current.json` only.


## Self-hosted runner disk cap (#7160)

Self-hosted jobs reuse the checkout's persistent `target/`, so `target/debug/deps` grows without bound. The `check` job of `ci.yml` (every self-hosted leg: linux-fed and both macos-fed legs), `cert-postgres-age.yml` and `postgres-ignored.yml` therefore end with a step guarded by `if: always() && runner.environment == 'self-hosted'` (in `ci.yml` also `needs.classify.outputs.docs_only != 'true'`, so docs-only changes skip it) that runs `python3 scripts/ci-sweep-target.py --target target --max-bytes ${{ env.SELF_HOSTED_TARGET_CAP_BYTES }}`. The `shared_target` leg of `check` (linux-fed enterprise-fed, #7188) builds into its own per-runner `CARGO_TARGET_DIR` (`~/.cache/ai-memory-ci/cargo-target/<runner>`, outside the workspace, never touched by the #7188 prune step), so it runs `python3 scripts/ci-sweep-target.py --target "$CARGO_TARGET_DIR" --allow-root --within "$AI_MEMORY_CI_TARGET_ROOT" --max-bytes ...` instead (the leg's own directory, never the whole cache root, which is only the `--within` containment root; the step fails closed when either variable is unset). The leg sweeps its RESOLVED per-runner directory inside the RESOLVED cache root: the script resolves both with `realpath`, so a symlinked cache parent (on f2 `~/.cache/ai-memory-ci` is a symlink to `/mnt/t9/ai-memory-ci`) is accepted by containment alone; the workspace `target` step runs on the legs that build in the workspace. `scripts/test/test_workflow_sweep_7160.py` pins both shapes, and the `classify` job of `ci.yml` runs it together with `scripts/test/test_ci_sweep_target.py` (step `Target sweep unit tests (#7160)`, ubuntu-latest, so the Linux-only `O_PATH` test executes). The script deletes the oldest-mtime top-level entries of `target/debug/{deps,incremental,build,.fingerprint}` until they total under the cap, refuses a target outside `$GITHUB_WORKSPACE` (exit 2, unless `--allow-root` for a node cron), and never follows symlinks. The cap is the workflow-level `env: SELF_HOSTED_TARGET_CAP_BYTES` (40 GiB = `42949672960`) at the top of each of the three workflows; raise or lower it there, in all three. The target is opened by one descriptor walk from `/` (each component, `debug` and each swept directory with `O_NOFOLLOW | O_DIRECTORY`, relative to its parent) and every scan and delete is relative to those handles, so a component swapped for a symlink before the open, after the scan or during removal is refused, not followed; every parent of the target must be searchable by the sweeping account (on Linux the parents are opened with `O_PATH`, so no read permission is needed; on macOS, which has no `O_PATH`, every parent of the target must also be readable, else nothing is swept and the exit is 4); `--allow-root` requires `--within <root>` (exit 5 without it, and `--within` alone is exit 5): the script resolves the target and the root and refuses (exit 2, naming both resolved paths) unless the resolved target is strictly inside the resolved root (not equal to it, never `/`), then walks the RESOLVED path with the descriptor walk above, so a symlink swapped in after the resolution still fails closed and a target that resolves outside the root (for example a symlink to a sibling directory) is refused. An unreadable directory or entry at any depth prints `warning: cannot read <path>` (or `cannot size` / `cannot remove`) on stderr and is skipped; the sweep continues and exits 0. A top-level entry that holds a directory the account cannot empty (unreadable, or read-only so its files cannot be unlinked) is detected during the sizing walk, before anything is deleted: it is kept whole, one `warning: cannot remove <entry>: ... entry kept whole` names it, and its bytes stay in `before=` and `after=`. The summary line is `before= after= removed= freed=` with `removed` the entries fully deleted and `freed` the bytes really unlinked (also when a removal fails midway). A top-level entry whose tree is deeper than 300 levels (`MAX_TREE_DEPTH`) is skipped whole: one `warning: cannot size <entry>: too deep to walk ... entry skipped` names it, it is never on the delete list, and none of it is deleted (a partly deleted cargo output is worse than an oversized one). Exit codes: 0 success, 2 refused path (target outside the workspace, symlinked `debug` or swept directory, a swept directory or any parent of it replaced before or after the scan, a target path component that is not a directory (`refused: <path> is not a directory`), or an `--allow-root` target not strictly inside `--within`), 3 `--max-bytes` zero or negative, 4 nothing could be sized because every swept directory or entry was unreadable (this turns the always-run step red), 5 usage error (`EXIT_USAGE`: a missing, unknown or unparsable argument such as `--max-bytes abc` or an empty `--max-bytes`, or `--allow-root` without `--within`), distinct from the exit-2 refusal. Preview a sweep with `--dry-run`.


## Dogfooding release branches

Every `release/v0.6.x.y` branch should be dogfooded by the maintainer for at least 24h before tag-cut so any migration / capability / wire-format regression surfaces in real use, not just CI. The script that does this on this node:

```bash
scripts/dogfood-rebuild.sh
```

What it does (idempotent — safe to re-run after every commit):
1. `cargo build --release`
2. Backs up the live MCP DB to `.local-runs/ai-memory-dogfood-test-<ts>.db`
3. Dry-runs migrations against the backup (proves v17→v18→v19 etc. round-trip cleanly on real data)
4. Re-points `/opt/homebrew/bin/ai-memory` → `target/release/ai-memory` (via `brew unlink` + symlink)
5. Lists running MCP processes that need a Claude Code restart to pick up the new binary

What it does NOT do:
- Touch the live DB (migrations only run when an actual ai-memory process opens it on the next MCP restart)
- Kill the running MCP (would self-DOS the in-flight Claude Code session)
- Bump `Cargo.toml` version (that's a tag-cut concern)

Reverting to the brew-managed binary: `brew link --overwrite ai-memory`.

## Reproducing the v0.7.0 recursive-learning primitive

`scripts/reproduce-recursive-learning.sh` is the self-contained end-to-end
demo for the v0.7.0 recursive-learning add-on (issue #655, Tasks 1-4
landed; Tasks 5-8 in flight on `feat/v0.7.0-recursive-learning`). It
builds the release binary, creates a fresh sqlite DB under
`.local-runs/repro-recursive-learning-<timestamp>/` (honoring the
project no-`/tmp` HARD RULE), inserts 3 sample memories, drives
`memory_reflect` over MCP stdio JSON-RPC up to the default depth cap
(3), and demonstrates the refusal at depth=4 with a clearly-formatted
`REFLECTION_DEPTH_EXCEEDED` verdict block. Idempotent (each run uses
a fresh timestamped subdir).

```bash
scripts/reproduce-recursive-learning.sh
# Set REPRO_KEEP_DB=1 to retain the demo DB for inspection after the run.
```

The full conceptual primer lives at `docs/RECURSIVE_LEARNING.md`; the
release-notes intro lives under `docs/v0.7.0/release-notes.md`
§"Substrate-native recursive refinement".

## Self-hosted runner host budget (#7188)

The `Check (linux-fed,enterprise-fed)` job compiles every integration test binary with
`--features sal-postgres`; an unshared per-checkout `target/` measured ~166 GiB. Each
labelled linux-fed runner now builds into its OWN `CARGO_TARGET_DIR`,
`~/.cache/ai-memory-ci/cargo-target/<runner name>` (root defined once in
`scripts/ci/shared_cargo_target.py`, which takes the name from `runner.name` and fails
closed on a missing or unsafe name). A target has exactly one writer, so one PR's build
can never replace a test binary another PR's job is about to run (cargo releases its
build lock before it executes test binaries; decided by 3-agent vote 6def5ab6, memory
023ed7e7-8650-424b-a5f7-2eb48573aa5f), and the runner reuses its target for its later
jobs, capped (#7160): the last step of the leg (`Sweep per-runner cargo target to the size
cap`) runs `scripts/ci-sweep-target.py` on that runner's directory after each job and
deletes the oldest-mtime build state until the target is under
`SELF_HOSTED_TARGET_CAP_BYTES` (40 GiB = `42949672960`, the workflow-level `env:` literal
of `ci.yml`), so later jobs rebuild whatever the sweep removed. The sweep targets the
RESOLVED per-runner directory and requires it strictly inside the RESOLVED cache root
(`--within "$AI_MEMORY_CI_TARGET_ROOT"`); this matters on f2, where `~/.cache/ai-memory-ci`
is a symlink to `/mnt/t9/ai-memory-ci`. Jobs on different runners do not share compiled
output: each runner pays one cold build, and two runners hold two targets.

Size the host with:

    footprint = labelled-runners x (cap + one build's peak above the cap)
    labelled runners per host = floor((disk - fixed - lanes - headroom) / that per-runner footprint)

where `disk` is the root disk, `fixed` the non-CI usage (databases, services), `lanes`
the agent-lane cargo targets and `headroom` the free-space floor. The cap is 40 GiB; one
build can exceed it while it runs (~158 GiB measured after the debuginfo strip, a lower
bound: the unstripped comparison build was stopped past 215 GiB before it finished), and
the sweep brings the target back under the cap after the job.
Example, f2: 912 GiB disk - ~400 GiB fixed leaves ~512 GiB before lanes and headroom,
which holds about two per-runner targets; runners 3 and 4 stay unlabelled for that reason
(tracked in #7199, which also covers sccache or a larger disk). After each job
`scripts/ci/prune_runner_artifacts.py --protected-root` prunes stale scratch and never
touches the target root, so a prune on one runner cannot delete a sibling runner's target.
