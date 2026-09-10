# 1x3 audit of #3587 (swarm anti-drift, v1.0.0 GA) — common brief

You are ONE of three independent auditors. Do not coordinate. Read-only: no source edits, no commits, no cargo builds or tests (the host is running a release push gate). Write ONLY to your assigned output file under <vote-dir>/ (never /tmp).

Repo: <tree> (release checkout, Rust 1.98 / edition 2024). Read the proposal in issue-3587.md next to this file.

Tooling rules (operator-set): use CodeGraph 1.6.0 BEFORE grep for every code question:
  cd <tree> && codegraph explore "<symbols or question>"
  cd <tree> && codegraph impact <symbol>     (blast radius)
  cd <tree> && codegraph callers <symbol>
grep only for literal strings (test names, messages). Cite rule IDs from the project Rust skill <rust-1.98 skill> for every Rust-level finding (e.g. ERRORS-09, CONCURRENCY-20).

Product facts already established (verify, do not re-derive from scratch):
- `ai-memory resolve` marks one memory as superseding another (archives the old row with archive_reason='superseded').
- `autonomous_hooks` (config / AI_MEMORY_AUTONOMOUS_HOOKS=1) fires auto_tag + detect_contradiction synchronously post-store; LLM-backed; off by default.
- `ai-memory watch` (src/watcher, src/cli/watch*) polls claude-code | codex | gemini transcript hosts and atomises lines into memories.
- `ai-memory curator` has --once / --daemon / --reflect; `[curator]` config section exists.
- `ai-memory install claude-code` writes a SessionStart hook into ~/.claude/settings.json.
- MCP tool memory_capture_turn exists; there is NO `capture-turn` CLI twin.
- GA authority boundary: #3578 / #3549 / #3581 / #3582 — every new write path is reviewed as a boundary change; QUAL-6 legacy Result<Value,String> ceiling is 132 (no bumps); C5 tools/list ceiling 8110; no new env knobs without a ruling; SQLite + Postgres twin tests for every store-path change; MCP/HTTP/CLI parity.

Output format (markdown), max ~250 lines:
1. VERDICT per unit U1..U6: SHIP-AS-SPECIFIED / SHIP-WITH-CHANGES / DO-NOT-SHIP-IN-v1.0.0, one line of reason each.
2. FINDINGS: numbered, each with severity (blocker / major / minor), the exact file:symbol it concerns (from codegraph), what is wrong or missing in the proposal, and the concrete amendment. Include the codegraph command you ran.
3. BLAST RADIUS: for the symbols each unit will touch, list callers/tests that must be updated or re-pinned (rule (e): old-contract pins across src/ AND tests/).
4. TEST PLAN GAPS: DENIED/ALLOWED pairs the proposal is missing.
5. EFFORT: your own estimate per unit in deputy-days, and the ordering you would use.
