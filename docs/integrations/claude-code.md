---
layout: doc
---
# Claude Code — SessionStart hook (reference recipe)

**Category 1 (hook-capable). 100% reliable.** This is the load-bearing
remediation for issue [#487](https://github.com/alphaonedev/ai-memory-mcp/issues/487).

> ### ℹ️ v1.0.0 — attestation is surface-scoped; MCP needs no opt-out
> **This note previously told you to set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`. Do not do
> that.** It described the v0.9.0 posture (#1751), which required attestation on *every*
> surface. Claude Code's MCP client sends `memory_store` **without a signature** and no MCP
> host can construct the canonical `SignableWrite` envelope, which made that default
> unsatisfiable on MCP ([#1981](https://github.com/alphaonedev/ai-memory-mcp/issues/1981)).
>
> **v1.0.0 ([#1985](https://github.com/alphaonedev/ai-memory-mcp/issues/1985)) fixed it in the
> substrate, not in your config:** with `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` **unset**, the
> fail-closed `403 ATTESTATION_FAILED` applies to the **HTTP direct-write surface only**
> (`POST /api/v1/memories` + `/bulk`). The MCP `memory_store` and CLI `store` surfaces are the
> operator-as-actor path: an unsigned write is accepted and lands `attest_level="claimed"`.
> **A stock Claude Code setup works out of the box with no `env` override.**
>
> Setting `=0` is a **global** override — it also disables the one surface where the gate is
> genuinely load-bearing (HTTP direct-write, the network surface). Leave it unset. Use `=1`
> only if you want strict on every surface and your clients can sign; attested writes remain
> available on the CLI via `ai-memory store --sign`.
> Full guide: **[Attestation setup](../attestation.html)**.

## Quick install

```text
# Preview the change (dry-run is the default -- writes nothing):
ai-memory install claude-code

# Commit the change:
ai-memory install claude-code --apply

# Remove later:
ai-memory install claude-code --uninstall --apply
```

The installer writes the SessionStart hook block into `~/.claude/settings.json`
inside a clearly-marked managed block, backs up the original to
`<config>.bak.<timestamp>` first, and is idempotent — re-running `--apply`
with no upstream changes is a no-op. Pass `--config <path>` to target a
non-default settings file (project-scoped or test fixture).

## What it does

Claude Code supports a `SessionStart` hook in `~/.claude/settings.json` (or
the project's `.claude/settings.json`) that runs a shell command at session
boot. The hook's stdout is injected into the conversation as additional
context, **before the model processes the first user message**. We point
that hook at `ai-memory boot` so every fresh session starts memory-aware
with no prompt from the user.

## One-time install

Edit `~/.claude/settings.json` (create it if missing) and add a `hooks`
block. If you already have other hooks, append the entry inside the
existing `SessionStart` array.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-memory boot --quiet --limit 10 --budget-tokens 4096"
          }
        ]
      }
    ]
  }
}
```

That's it. Restart Claude Code. The next session will see your most-recent
memory context as part of its system prompt.

> **Running ai-memory's `--tier smart` or `--tier autonomous` with a non-default LLM backend?** Post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) (v0.7.0) the **recommended** path is a `[llm]` section in `~/.config/ai-memory/config.toml` — every surface (the MCP server, the boot banner this hook prints, the `ai-memory doctor` reachability probe) reads the same file, so the boot banner here and the live MCP server agree on the backend. Example for xAI Grok 4.3:
>
> ```toml
> # ~/.config/ai-memory/config.toml
> schema_version = 2
>
> [llm]
> backend     = "xai"
> model       = "grok-4.3"
> base_url    = "https://api.x.ai/v1"
> api_key_env = "XAI_API_KEY"            # process-env-var name (NOT the literal key)
> ```
>
> Export `XAI_API_KEY` in your shell rc; restart Claude Code. The SessionStart hook's boot banner should now report `llm=xai:grok-4.3`.
>
> The **override** path is an `env:` block in the MCP server entry in `~/.claude.json` with `AI_MEMORY_LLM_BACKEND` / `_API_KEY` / `_MODEL` — still works and takes precedence over `config.toml`. Shell exports do not reach Claude Code's MCP-spawned subprocess ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144) → [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)). Full recipes: [`llm-backends.md`](llm-backends.html).

## Why these flags

- `--quiet`: a DB-unavailable failure becomes silent on stderr (so it
  doesn't pollute the agent log) but the **diagnostic header still
  appears on stdout** so the agent and the human running it always know
  whether boot fired and why context might be missing.
- `--limit 10` + `--budget-tokens 4096`: bounds the cost of every session.
  Tune up if you want richer context, down if your first turns are
  latency-sensitive.

**Do not** add `--no-header` to a hook command. The header is the
end-user-visible signal that ai-memory ran. Suppressing it makes silent
failure indistinguishable from "no memories yet" — exactly the failure
mode issue #487 is fixing.

## Privacy / disable (v0.6.3.1, PR-9h)

Two operator-controlled knobs gate what boot emits, for hosts where
memory titles must never enter CI logs or where compliance contexts
need an audit-trail signal without exposing memory subjects:

| Knob | Effect | Use case |
|---|---|---|
| `[boot] enabled = false` (in `~/.config/ai-memory/config.toml`) or `AI_MEMORY_BOOT_ENABLED=0` | `ai-memory boot` exits 0 with **empty stdout AND empty stderr** — true silence. The hook injects nothing. | Privacy-sensitive hosts where memory titles must not enter CI logs. |
| `[boot] redact_titles = true` | The manifest header still appears (so the agent + human still see boot fired) but every body row's `title` field is replaced with `<redacted>`. Namespace, tier, id_short, priority, and age still surface. | Compliance contexts that need an audit-trail signal of "boot ran with N memories" without exposing memory subjects. |

Both default to the historical (pre-v0.6.3.1) behaviour — omit the
`[boot]` section entirely to preserve existing behaviour.

The env var `AI_MEMORY_BOOT_ENABLED=0` takes precedence over the
config file (same precedence pattern as PR-5's log-dir resolution),
so a CI runner can force-disable boot for one job without editing
the host config.

**Schema-drift detection.** From v0.6.3.1, boot also surfaces a
`# ai-memory boot: warn` header when the DB's `schema_version` lies
outside the binary's supported range. The canonical
schema is **v78** (verified via `CURRENT_SCHEMA_VERSION` in
`src/storage/migrations.rs`); an older DB is brought up to v78
via the in-process migration ladder applied on first daemon start. An agent or
human running an older `ai-memory` binary against a newer DB (or
vice versa) sees the drift directly in their session log instead of
having boot silently degrade. The JSON variant carries
`schema_supported: bool` as a top-level key for SIEM /
fleet-dashboard ingest.

## End-user diagnostic — how to know boot fired

Every boot invocation emits a transparent multi-field manifest. Agents
and humans always see exactly what version ran, which DB / schema it
opened, the configured tier and models, and the wall-clock latency —
no black-box behaviour:

```text
# ai-memory boot: ok
#   version:    0.8.1
#   db:         /home/u/.claude/ai-memory.db (schema=v78, 161 memories)
#   tier:       autonomous (embedder=nomic-embed-text-v1.5, reranker=ms-marco-MiniLM-L-6-v2, llm=xai:grok-4.3)
#   latency:    12ms
#   namespace:  ai-memory-mcp (loaded 10 memories)
```

Post-#1146, the `llm=` field uses the `<backend>:<model>` display
format produced by `ResolvedLlm::display_label()` for any
non-Ollama backend (e.g. `llm=xai:grok-4.3`, `llm=openai:gpt-5`,
`llm=anthropic:claude-opus-4.7`). For the Ollama backend the bare
model name continues to display (`llm=gemma3:4b`).

The first line's status word is one of `ok` / `info` / `warn`; the
`namespace:` line's parenthetical varies by status. The four variants:

| Status | First line | `namespace:` line |
|---|---|---|
| Happy path | `# ai-memory boot: ok` | `(loaded N memories)` |
| Namespace empty, fell back | `# ai-memory boot: info` | `(fallback: loaded N memories from global Long tier)` |
| First-run / greenfield | `# ai-memory boot: info` | `(empty — nothing to load; this is normal on a fresh install)` |
| DB unavailable | `# ai-memory boot: warn` | `(db unavailable — see `ai-memory doctor`)` |

The manifest is *never* a black box: the warn variant still surfaces
`version`, `tier`, and `latency`, with `<unavailable>` standing in for
the live-DB-only fields (`schema`, `total memories`). Common causes for
the warn variant: wrong `AI_MEMORY_DB` path, permission denied,
brand-new install before first `ai-memory store`.

If you see **no manifest at all** in your session log, the hook never
fired. Run the diagnostic from the same shell Claude Code launched from:

```text
ai-memory boot --limit 1

# Should emit the manifest with one of the four status words above.
# If it errors instead, the binary or DB is misconfigured.
# If it works but Claude Code never sees a manifest, the SessionStart
#   hook isn't installed correctly — re-check ~/.claude/settings.json.
```

## Project-scoped namespace override

If you want a specific project to load from a sub-namespace (e.g.
`ai-memory-mcp/v0631-release` instead of the default `ai-memory-mcp`), put
a project-level `.claude/settings.json` at the repo root with:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-memory boot --quiet --no-header --namespace ai-memory-mcp/v0631-release --limit 10"
          }
        ]
      }
    ]
  }
}
```

Project-level hooks merge with user-level hooks; both fire. Best practice:
keep user-level hook generic (let `auto_namespace` infer from cwd) and use
project-level hooks only when you need a non-default namespace.

## Verifying

Cold-start test (the issue #487 acceptance criterion):

```text
# 1. Quit Claude Code entirely.
# 2. From a fresh shell, anywhere on the filesystem:
cd /tmp
claude

# 3. First message:
#    > what do you remember?
# 4. Expected: Claude responds with recalled titles, namespaces, ages,
#    no "I do not have context to continue this", no need to type
#    "access your memories".
```

If the cold-start fails, check:

1. `which ai-memory` returns a path (the binary is on `$PATH`).
2. `ai-memory boot --quiet --no-header --limit 3` from your shell returns
   memory rows.
3. `cat ~/.claude/settings.json | jq .hooks.SessionStart` shows the hook
   block.
4. The hook command is on a single line (Claude Code's `command` field is
   a single string, not an array).

## Uninstall

```text
ai-memory install claude-code --uninstall   # see PR-2 (issue #487 item E)
```

Or remove the entry by hand from `~/.claude/settings.json`.

## Substrate rules enforcement on every tool call (v0.7.0)

**OPT-IN. RESTRICTED ACTION.** Issue [#691](https://github.com/alphaonedev/ai-memory-mcp/issues/691)
lands the substrate-level **agent-action rules engine**: every Bash / Edit /
Write tool call Claude Code wants to dispatch can be routed through
`memory_check_agent_action` before it fires. The engine returns one of
`allow` / `refuse` / `warn`; the harness honours the verdict.

The MCP tool itself is registered unconditionally — but the
**PreToolUse hook that turns the engine into harness-enforced reality is
opt-in**. Sessions without the hook installed behave exactly as
v0.7.0-pre-hook: the engine never gets consulted, no rules fire, all
proposed actions dispatch as Claude Code normally would.

### What the hook does

Claude Code's [`PreToolUse`](https://docs.claude.com/en/docs/claude-code/hooks)
hook fires before a matching tool dispatch and can BLOCK it. The installer
scopes the managed entry with `matcher: "Bash|Edit|Write"` — the
agent-external action surface the rule engine models (the Claude Code
`matcher` is a regex over the tool name, so `Edit` also covers
`MultiEdit` / `NotebookEdit`). The managed entry is a **`type:command`**
hook that runs `ai-memory governance check-action --from-pretool-stdin`:
the wrapper reads the PreToolUse event off stdin, maps the proposed tool
to a substrate action (kind=`bash`/`command` for the Bash tool,
kind=`filesystem_write`/`path` for Edit / Write / MultiEdit /
NotebookEdit), evaluates the rules engine, and emits the Claude Code
decision contract (`hookSpecificOutput.permissionDecision`) so a Refuse
actually blocks:

> **Why `type:command`, not `type:mcp_tool` ([#1811](https://github.com/alphaonedev/ai-memory-mcp/issues/1811)).**
> A `type:mcp_tool` hook *cannot enforce*. Per the Claude Code hooks
> contract, an mcp_tool hook whose tool returns `isError:true` (e.g. the
> old "kind is required" failure) "produces a non-blocking error and
> execution continues", and a tool response that is not the harness
> decision JSON is "shown as plain text" — so the substrate
> `{"decision":{"decision":"refuse"}}` never blocked the tool. The
> `--from-pretool-stdin` wrapper owns the contract translation in-binary
> (it emits `permissionDecision:"deny"` on a Refuse), restoring real
> enforcement. The cost is a shell fork + a PATH dependence on
> `ai-memory`. Decision recorded via the 5-agent crossroads vote
> (`4d3ea1c5`).

The wrapper honours the returned `decision`:

| `decision` | Harness behaviour |
|---|---|
| `allow` | Wrapper emits nothing (exit 0). Tool dispatches normally. |
| `warn` | Wrapper emits `permissionDecision:"ask"` (+ `reason`/`rule_id`) — the harness surfaces the warning to the human for confirmation. The warning row also lands in `signed_events` (audit chain). |
| `refuse` / `escalate` | Wrapper emits `permissionDecision:"deny"` (+ `reason`/`rule_id`). Tool dispatch is BLOCKED; the agent must reroute (operator-approval workflow lives in K10, separate surface). |

Because the managed matcher is scoped to `Bash|Edit|Write`, the `Read`
tool, `WebFetch`, and `mcp__`-prefixed tools are NOT gated by the managed
entry — the harness builds no `AgentAction` (hence no `kind`) for them, so
gating them via `matcher: "*"` only produced a spurious `kind is required`
rejection on every such call (fixed in
[#1667](https://github.com/alphaonedev/ai-memory-mcp/issues/1667)). An
operator who wants to gate additional tools can widen the matcher by hand;
the action-kind translation is documented in
[`docs/governance/agent-action-rules.md`](../governance/agent-action-rules.html).

### How to install

```text
# Preview (dry-run is the default — writes nothing):
ai-memory install claude-code --hook pretool

# Commit:
ai-memory install claude-code --hook pretool --apply
```

On success the installer prints `installed PreToolUse hook -> <path>`
and (if the file already existed) writes a backup at
`settings.json.bak.<timestamp>`. The hook is added under the same
managed-block sentinel as the SessionStart hook, so the two install
verbs are orthogonal — you can install / uninstall PreToolUse
independently of SessionStart.

If your `settings.json` already has a `PreToolUse` array, the installer
APPENDS our entry rather than replacing the operator's entries. Order
is preserved (operator entries first, our managed entry last). If an
existing entry already names `memory_check_agent_action` with a
DIFFERENT `matcher` (e.g. you previously scoped the hook to `Bash`
only), the installer refuses without `--force`:

```text
# Conflict warning on stderr → installer exits non-zero
ai-memory install claude-code --hook pretool --apply
# error: refusing to overwrite a differing-but-similar PreToolUse hook
#        without --force; existing matcher(s): ["Bash"]

# Either keep the scoped entry by hand or:
ai-memory install claude-code --hook pretool --apply --force
```

### What rules govern

The substrate ships four seed rules (`R001`-`R004`) that land **inert
(`enabled = 0`)** at migration time, by design. The operator activates
them after auditing the test fleet (`/tmp` usage, `cargo` invocations
on low-disk hosts, etc.) and signing each one with the operator key:

| Rule | Kind | Refuses |
|---|---|---|
| `R001` | `filesystem_write` | Writes to `/tmp/**` |
| `R002` | `filesystem_write` | Writes to `/var/tmp/**` |
| `R003` | `filesystem_write` | Writes to `/private/tmp/**` (macOS realpath of `/tmp`) |
| `R004` | `process_spawn` | `cargo` spawn when free disk on `/` is below 20 GiB |

Full schema + matcher vocabulary lives in
[`migrations/sqlite/0024_v07_governance_rules.sql`](../../migrations/sqlite/0024_v07_governance_rules.sql).
Operators inspect / mutate rules via:

```text
ai-memory rules list                          # read-only, no signature
ai-memory rules enable R001 --sign            # activate; requires operator.priv
ai-memory rules add ...   --sign              # author a new rule
```

Mutation over MCP is **explicitly disabled** — a compromised agent
must not be able to weaken its own constraints. See
[`docs/governance/agent-action-rules.md`](../governance/agent-action-rules.html)
§"Operator-mutation gating".

### Operator workflow (end-to-end)

1. **Keygen** — `ai-memory rules keygen --out operator` writes `operator.priv` +
   `operator.pub` (the operator's signing keypair).
2. **Sign-seed** — `ai-memory rules sign-seed --key operator.priv` signs
   the four seed rules (they ship unsigned + disabled by design).
3. **Enable** — `ai-memory rules enable R001 --sign` (and R002/R003/R004
   as the audit clears each one).
4. **Install hook** — `ai-memory install claude-code --hook pretool
   --apply`. Restart Claude Code.
5. **Smoke test** — open a session, ask the model to write to `/tmp/foo`.
   Expected: the Edit tool dispatch is refused with `rule_id: R001` and
   `reason: "no /tmp"`. The audit row lands in `signed_events` with
   `event_type = 'governance.check'`.

### Backwards compatibility

The hook is **strictly opt-in**. Sessions without
`~/.claude/settings.json` PreToolUse entries pointing at
`memory_check_agent_action` behave exactly as v0.6.x: no engine, no
rules, no refusals. The substrate-side rules table can be populated
and signed independently of any hook install — the engine remains
inert until the harness wires in.

To uninstall the hook (e.g. before downgrading to a pre-v0.7.0
binary):

```text
ai-memory install claude-code --hook pretool --uninstall --apply
```

This removes only our managed entry; operator-authored PreToolUse
entries (under different markers) are left untouched.

## What this does NOT solve

- **Long-running sessions**: the hook only fires at session start. If you
  store new memories mid-session, they don't get pulled in until the next
  session. Use `memory_recall` directly when you need fresh context.
- **Tool deferral**: Claude Code may still defer the `mcp__memory__*` tool
  schemas, requiring a `ToolSearch` round-trip the first time the model
  wants to call them. The hook injects context as text — the model has it
  even before tools resolve. This is the right architectural separation.

## Related

- [`README.md`](README.html) — integration matrix and the `ai-memory boot` primitive.
- Issue #487 — the RCA and full remediation plan.
- Issue F (cross-filed at `anthropics/claude-code`) — request that MCP
  servers can mark tools as boot-priority so deferred-tool round-trips
  don't matter even for the second turn.
