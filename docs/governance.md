---
layout: doc
---
# Governance + permissions (operator index)

v0.7.0 refactors the v0.6.x governance subsystem into **rules + modes
+ hooks** that resolve to a single `Decision`. This page is the
operator-facing index — the deep docs live under
[`docs/governance/`](governance/) and the linked design + migration
docs below.

> **Default change at v0.7.0:** `permissions.mode` flips from
> `"advisory"` (v0.6.4) to `"enforce"` (v0.7.0). Operators who rely
> on the old default-permissive behavior must opt back in via
> `[permissions] mode = "advisory"` in `config.toml`.

## Where to read what

| Topic | Doc |
|---|---|
| **Operator how-to: activate Batman Mode end-to-end** | [`docs/batman-active-mode.md`](batman-active-mode.html) |
| Migration path v0.6.4 → v0.7.0 permissions | [`docs/MIGRATION_v0.7.md` §"Permissions migration"](MIGRATION_v0.7.html#permissions-migration) |
| 7th-form policy engine (substrate-authoritative rules) | [`docs/policy-engine.md`](policy-engine.html) |
| Agent-action rule catalogue | [`docs/governance/agent-action-rules.md`](governance/agent-action-rules.html) |
| SSE approval channel + HMAC binding | [`docs/k10-sse-approvals.md`](k10-sse-approvals.html) |
| Per-agent daily quotas (K8) | [`docs/k8-quotas.md`](k8-quotas.html) |
| Audit-trail coverage map | [`docs/security/audit-trail-coverage.md`](security/audit-trail-coverage.html) |
| Federation hardening (peer auth) | [`docs/federation.md`](federation.html) |
| Signed-events V-4 chain (substrate audit) | [`docs/signed-events-v4.md`](signed-events-v4.html) |
| Programmable lifecycle hooks | [`docs/hook-pipeline.md`](hook-pipeline.html) |

## Three modes

- **`enforce`** (v0.7.0 default) — every gated write is checked
  against the active rules; refusal returns `Decision::Deny`.
- **`advisory`** (v0.6.4 default) — gated writes are logged but not
  refused.
- **`off`** — pipeline disabled; substrate writes are accepted
  without consulting the rule corpus.

Rule-consultation failure is **fail-CLOSED** at v0.7.0
([#1455](https://github.com/alphaonedev/ai-memory-mcp/issues/1455)
secure default): when the rules DB cannot be consulted, the gated
action is refused and a synthetic
`governance:consultation_unavailable` refusal is chain-logged.
`AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1` reverts to the legacy
permissive posture (UNSAFE; the degraded-ALLOW path is WARN-logged).

## Namespace-standard defaults (allow-on-silence)

Per-namespace access control is carried by a **namespace standard**
(a standard memory whose `metadata.governance` holds the
`CorePolicy` knobs — `src/models/namespace.rs`). The defaults are
deliberately permissive
([#1569](https://github.com/alphaonedev/ai-memory-mcp/issues/1569)
documented posture):

> **Absent an explicit namespace standard, `write` and `promote` are
> ungated by design at v0.7.0.** `CorePolicy::default()` is
> `write: GovernanceLevel::Any`, `promote: GovernanceLevel::Any`,
> `delete: GovernanceLevel::Owner`. The governance pipeline gates
> only what operators configure — `resolve_governance_policy`
> returns `None` for a namespace with no standard (and no inheriting
> parent standard), and callers fall through to the permissive
> `CorePolicy::default()`.

The hardening knob is the namespace-standard surface: attach a
standard via the `memory_namespace_set_standard` MCP tool (companions
`memory_namespace_get_standard` / `memory_namespace_clear_standard`)
with a `metadata.governance` policy, e.g.
`{"write": "registered", "promote": "owner", "delete": "owner"}`.
**Production namespaces should carry an explicit standard** — the
allow-on-silence default is appropriate for single-operator local
substrates, not for shared or federated deployments. Child
namespaces inherit the parent's policy by default (`inherit: true`),
so one standard at `org/` governs the subtree until a child opts out.

### Corrupt standards resolve as SEVERED ([#4285](https://github.com/alphaonedev/ai-memory-mcp/issues/4285))

A namespace standard whose `metadata.governance` does not deserialize (a
typo'd enum variant, an out-of-band edit, an older binary) is handled exactly
like a severed standard ([#2503](https://github.com/alphaonedev/ai-memory-mcp/issues/2503))
**at every level of the chain, on both backends**: the walk continues (an
intact ancestor policy is still honoured) and the resolved `write` / `promote`
/ `delete` are raised to **at least Owner**. It is never a hard refusal (a
corrupt `*` would otherwise be a substrate-wide write outage) and never
"no policy" (the pre-#4285 behaviour silently fell through to
allow-on-silence). The owner of the corrupt standard is still the namespace
owner, so an owner write is not locked out; a non-owner write is refused.

- **Signal.** `ai-memory doctor` reports every corrupt standard as
  **Critical** ("Corrupt governance standards (#4285)", both backends) and the
  daemon / MCP server / postgres connect emit one boot `WARN` listing each
  namespace, standard id and a value-free reason (the error category and
  position; a stored value is never echoed into a log, the census or a
  response). Every resolve of a corrupt level also
  logs a `WARN` on target `ai_memory::governance::policy_read`.
- **What counts as corrupt.** A `metadata.governance` that fails the typed
  deserialise, **or** (sqlite) a whole `metadata` cell that is not a JSON object
  (invalid JSON, an array, a string, ...). A corrupt level contributes nothing
  to ANY governance reader: the sibling walkers
  (`require_approval_above_depth`, `skill_promotion_min_depth`) continue to the
  ancestor and never honour a raw key of an unparseable policy.
  `memory_namespace_get_standard` and the capabilities `rule_summary` report
  the effective severed (Owner-floored) policy with `corrupt: true`, not the
  permissive default. Whole-`metadata` corruption also loses the stored owner
  id: the corrupt level has no owner, so the nearest ancestor standard's owner (if any) is the namespace owner, otherwise nobody is until the binding is repaired (fail closed).
- **Documented limit (depth knobs).** A corrupt level also cannot state
  `require_approval_above_depth` / `skill_promotion_min_depth`: those walks
  continue to the ancestor (an ancestor's explicit value governs; with none,
  the documented default applies, i.e. no approval gate), while the Owner floor
  still gates WRITE at the corrupt level. A corrupt level that meant a stricter
  depth gate degrades to the inherited one until repaired. For the skill
  promotion floor only, a walk that passes a corrupt level and finds no explicit
  value fails closed to `u32::MAX` (no promotion) until the standard is
  repaired; an unconfigured chain keeps the default of 1.
- **Repair.** Re-run `memory_namespace_set_standard` for the namespace with a
  valid policy; the row is then read normally and no floor is applied.
- **Documented limit.** A corrupt policy that *meant* something stricter than
  Owner (`approve` / consensus) degrades to the Owner floor until repaired. The
  doctor Critical is the operator's signal; the floor only ever tightens.
- **Federation receive.** Measured by
  `tests/fed_owner_floor_4285.rs`: the Owner floor does **not** refuse a
  non-owner peer's relayed write on `/sync/push` (receive authorizes by peer
  attestation and namespace scope, not by the namespace write level — see
  *Enforcement scope* below). A corrupt standard therefore never turns
  federation receive into an outage, and receive behaviour is identical to an
  intact explicit Owner policy.

### Enforcement scope ([#1617](https://github.com/alphaonedev/ai-memory-mcp/issues/1617))

The namespace-standard `CorePolicy` gates the **direct write
surfaces** (MCP tools, HTTP `POST/PUT` routes, CLI under a daemon
context). It is **not** evaluated on the federation receive path:
`/sync/push` applies the signed L1-6 rule engine (on both backends)
but not the receiving node's namespace `CorePolicy`, because the
peer is mTLS-trusted + signature-verified and `CorePolicy` is an
authorship-time control. Operators configuring `write: owner` /
`approve` should understand the gate binds where memories are
*authored*, not where they replicate to. Receive-path hardening is
in scope for the
[#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464)
v0.8 work.

### `required_scope` — pin a namespace's memory scope ([#1720](https://github.com/alphaonedev/ai-memory-mcp/issues/1720) C)

An optional per-namespace `CorePolicy.required_scope`
(`private` | `team` | `unit` | `org` | `collective`) lets a namespace
standard pin the scope every stored memory must carry. When set, a
`Store` whose **effective scope** (`metadata.scope`; absent ⇒
`private`) does not match the pinned value is **REFUSED** at the
governance gate — **fail-closed, refuse-only**: the gate never
coerces the write to the required scope, it rejects it. The refusal
honors `permissions.mode` exactly like the other `CorePolicy` knobs —
`advisory` warns and lets the write through, `enforce` blocks it.

`required_scope` rides in the existing `metadata.governance` blob, so
there is **no schema migration** — set it alongside the other knobs:

```json
{"write": "registered", "promote": "owner", "required_scope": "collective"}
```

A `collective`-pinned namespace, for instance, refuses any
default-private write so nothing lands invisible to the rest of the
team. Enforced on **both** backends (sqlite `storage::enforce_governance`
+ postgres `PostgresStore::enforce_governance_action`). SDK parity: the
Python SDK `GovernancePolicy` gains a `required_scope: str | None`
field.

### Governance reach: memories writes only ([#1652](https://github.com/alphaonedev/ai-memory-mcp/issues/1652))

The L1-6 pre-write rule engine and the namespace `CorePolicy` govern
**memory and link writes**. Skill rows live in dedicated
`skills` / `skill_resources` tables that the `memory_write` gate does
not cover — skill registration/promotion/export are operator-surface
artifacts outside namespace-rule reach at v0.7.0. A `skill_write`
action kind for the rule engine is a v0.8 candidate; until then,
treat skill registration as an operator-trust surface.

## Commands

```bash
# Preview the v0.6.x → v0.7 permissions migration (dry-run by default)
ai-memory governance migrate-to-permissions

# Apply
ai-memory governance migrate-to-permissions --apply

# Install the operator-signed seed rules R001..R004
ai-memory governance install-defaults

# Sign a rule with the operator key (7th-form `attest_level = "signed"`)
# Seed-signing (v0.7.0): the verb is `rules sign-seed`, not `rules sign`.
# Per-rule signing is via --sign flag on `rules add/enable/disable/remove`.
ai-memory rules sign-seed rule-seed.json

# List the active rule corpus (CLI equivalent of memory_rule_list)
ai-memory rules list

# Wire the harness-side PreToolUse policy hook at install time
# (routes Bash / Edit / Write tool calls through memory_check_agent_action)
ai-memory install claude-code --hook pretool --apply
```

## Honest disclosures from v0.6.3.1 close out

- `permissions.mode = "advisory"` is now actually consulted by the
  gate (K3).
- `default_timeout_seconds` on `pending_actions` is now enforced by a
  60s sweeper (K2).
- `approval.subscribers` events are now actually published through
  the subscription system (K4).
- `rule_summary` is now populated with a real ordered list of active
  governance rules (K5).
- The 7th-form agent-EXTERNAL Layer-4 surface (`AgentAction::Bash` /
  `FilesystemWrite` / `NetworkRequest` / `ProcessSpawn`; wire kinds
  `bash` / `filesystem_write` / `network_request` / `process_spawn`)
  is **live at v0.7.0**: PE-1 wired `GOVERNANCE_PRE_ACTION` at four
  daemon-side boundaries (skill-manifest emission, federation peer
  POST, hooks subprocess spawn, LLM HTTP), PE-2 ships the Claude Code
  PreToolUse hook installer, and `memory_check_agent_action` is the
  harness-consulted read surface — see
  [`policy-engine.md`](policy-engine.html) §2 for the merged wire-point
  audit. **v0.8.0 update:** `AgentAction::Read` (wire `read_action`)
  shipped (#1730) and the mandatory-hook **presence** check shipped
  (#1734, `AI_MEMORY_HOOKS_ENFORCE_MODE` + `[hooks].required_events`);
  residual scope (subprocess-chain visibility, procurement-tier
  refuse-to-serve attestation / TPM binary integrity) is tracked under
  [#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697).
  Capabilities advertises the four wire kinds verbatim under
  `governance.enforced_actions`
  ([#1605](https://github.com/alphaonedev/ai-memory-mcp/issues/1605)).

See [`docs/internal/v070-feature-inventory.md` §"K1/G1
namespace-inheritance"](internal/v070-feature-inventory.html) for the
canonical track-K rollup.
