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
| **Operator how-to: activate Batman Mode end-to-end** | [`docs/batman-active-mode.md`](batman-active-mode.md) |
| Migration path v0.6.4 → v0.7.0 permissions | [`docs/MIGRATION_v0.7.md` §"Permissions migration"](MIGRATION_v0.7.md#permissions-migration) |
| 7th-form policy engine (substrate-authoritative rules) | [`docs/policy-engine.md`](policy-engine.md) |
| Agent-action rule catalogue | [`docs/governance/agent-action-rules.md`](governance/agent-action-rules.md) |
| SSE approval channel + HMAC binding | [`docs/k10-sse-approvals.md`](k10-sse-approvals.md) |
| Per-agent daily quotas (K8) | [`docs/k8-quotas.md`](k8-quotas.md) |
| Audit-trail coverage map | [`docs/security/audit-trail-coverage.md`](security/audit-trail-coverage.md) |
| Federation hardening (peer auth) | [`docs/federation.md`](federation.md) |
| Signed-events V-4 chain (substrate audit) | [`docs/signed-events-v4.md`](signed-events-v4.md) |
| Programmable lifecycle hooks | [`docs/hook-pipeline.md`](hook-pipeline.md) |

## Three modes

- **`enforce`** (v0.7.0 default) — every gated write is checked
  against the active rules; refusal returns `Decision::Deny`.
- **`advisory`** (v0.6.4 default) — gated writes are logged but not
  refused.
- **`off`** — pipeline disabled; substrate writes are accepted
  without consulting the rule corpus.

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
> returns the permissive default for a namespace with no standard
> (and no inheriting parent standard).

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

# Wire the policy file at install time on a harness
ai-memory install --harness claude-code --enforce-policy
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
- The 7th-form agent-EXTERNAL Layer-4 surface (Bash /
  FilesystemWrite / NetworkRequest / ProcessSpawn) is **Option-B
  foundation** at v0.7.0 (substrate-INTERNAL writes gated; agent
  contracts surface `callable_now=false`). Full cover lands in
  v0.8.0 per [#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697).

See [`docs/internal/v070-feature-inventory.md` §"K1/G1
namespace-inheritance"](internal/v070-feature-inventory.md) for the
canonical track-K rollup.
