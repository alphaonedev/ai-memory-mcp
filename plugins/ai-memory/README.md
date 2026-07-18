# ai-memory — Claude Code plugin

Persistent, tier-aware memory for Claude Code. This plugin wires up the three
integration surfaces ai-memory already ships, so a fresh Claude Code session is
memory-aware out of the box:

| Surface | What it does | Command |
|---|---|---|
| **MCP server** | the full memory-tool surface at `--profile full` (`memory_store`, `memory_recall`, …) + the `recall-first` / `memory-workflow` prompts | `ai-memory mcp --profile full` |
| **SessionStart hook** | Boots each session memory-aware — injects a short recall digest | `ai-memory boot --quiet --limit 10 --budget-tokens 4096` |
| **PreToolUse hook** (opt-in) | Governance gate: maps a proposed Bash/Edit/Write to a substrate action and enforces signed rules | `ai-memory governance check-action --from-pretool-stdin` |

## Prerequisite — install the `ai-memory` binary

**This plugin wires configuration; it does not ship the `ai-memory` binary.**
A git-based plugin marketplace cannot carry a platform-specific compiled
binary, so install it first and make sure it is on your `PATH`:

```bash
# one of:
brew install alphaonedev/tap/ai-memory
cargo install ai-memory
# or download a release binary from
# https://github.com/alphaonedev/ai-memory-mcp/releases

command -v ai-memory   # must print a path before the plugin is useful
```

If `ai-memory` is not on `PATH`, the plugin still installs, but the hooks
no-op **gracefully** — a Claude Code `SessionStart` hook that exits non-zero is
non-fatal, so your session is never blocked; you simply get no memory context
until the binary is present.

## Install

```bash
claude plugin marketplace add alphaonedev/ai-memory-mcp
claude plugin install ai-memory@ai-memory
```

Then restart Claude Code. `claude plugin details ai-memory` shows the wired
component inventory (MCP server + hooks).

## The PreToolUse governance hook is opt-in

The bundled `PreToolUse` hook calls `ai-memory governance check-action`. With
**no signed governance rules configured, it is inert** — it allows every action
(the seed rules ship disabled and require an operator's Ed25519 signature to
activate). It is bundled so the enforcement surface is one signing step away,
not so it blocks tools by default. If you do not want the per-tool
`check-action` shell-out at all, remove the `PreToolUse` block from the plugin's
`hooks/hooks.json` (or disable the plugin's hooks). See
[`docs/integrations/claude-code.md`](../../docs/integrations/claude-code.md)
§"PreToolUse governance" for the rule-signing workflow.

## What this plugin does NOT add

No net-new slash-commands or skills — ai-memory's workflow guidance ships as the
two MCP prompts (`recall-first`, `memory-workflow`) surfaced by the MCP server
above. The plugin bundles exactly the existing, documented assets.

## License

Apache-2.0
