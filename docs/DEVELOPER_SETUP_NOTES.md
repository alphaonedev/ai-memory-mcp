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
