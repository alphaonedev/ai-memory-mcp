# Agent Skills (v0.7.0)

> **Status (2026-05-14):** Agent Skills (Pillar 1.5) ships in v0.7.0
> as the substrate ingestion path for agentskills.io-compliant
> `SKILL.md` modules. The L2 wave adds reflection-as-skill promotion
> (#671) and the `composes_with_reflections` declaration (#672) — the
> two halves of the closing loop between the recursive-learning
> primitive and a runtime-portable skill artefact. Every claim on
> this page maps to shipped code at commit `c359e89`.

ai-memory v0.7.0 ships a **substrate-native ingestion path** for
[agentskills.io](https://agentskills.io/)-compliant skill manifests.
A skill is just a `SKILL.md` document with a YAML frontmatter block
plus an optional `resources/` sub-directory; the substrate persists
the manifest into a typed `skills` table, records its
content-addressed digest, signs the row with the operator's Ed25519
identity (when configured), and exposes a small set of MCP tools so
runtimes can register, list, get, fetch resources, export, promote
from a reflection, and compose with reflection memories.

This page is the engineering-precise primer. The narrative intro
sits in the v0.7.0 release notes
([`v0.7.0/release-notes.md`](v0.7.0/release-notes.md) §"Agent
Skills"). The reflection-to-skill bridge is documented from the
reflection side in
[`RECURSIVE_LEARNING.md` §Reflection-as-skill](RECURSIVE_LEARNING.md#reflection-as-skill-l2-6-closing-the-loop).

## What Agent Skills are

[Agent Skills](https://agentskills.io/) is an emerging community
specification for portable, machine-readable, runtime-agnostic
skill modules — a single `SKILL.md` file with a YAML frontmatter
header, a free-form markdown body, and an optional `resources/`
sub-directory holding any scripts, references, or assets the skill
activates against. Skills are designed to be moved across runtimes
without re-authoring: the manifest is the contract, the body is
the documentation, and the resources are the activation payload.

ai-memory does **not** ship a runtime that *executes* a skill — that
is the host agent's job. ai-memory ships the **substrate** that
makes a skill portable, audit-trail-attested, content-addressed,
and round-trip-stable across registration, export, and
re-registration on a different node.

## Substrate vs runtime relationship

| Layer | What ai-memory does | What the host agent does |
|---|---|---|
| **Substrate (this repo)** | Parses, validates, persists, content-addresses, signs, federates, exports, and round-trips the SKILL.md manifest. Provides MCP read APIs. | n/a |
| **Runtime (host agent)** | Reads the skill body, follows its instructions, activates resources by name. ai-memory is not in the call path. | Operates against the skill body returned by `memory_skill_get`. |

The split is deliberate. A skill is a **portable contract**, not a
function call. The substrate's job ends when it can hand a host
agent a content-addressed, signed, optionally-composed activation
payload. What the agent does with that payload is opaque to
ai-memory.

## MCP tools — the seven `memory_skill_*` verbs

The 7 MCP tools that make up the Agent Skills wire surface:

| Tool | Family | Wave | Purpose |
|---|---|---|---|
| `memory_skill_register` | `other` | L1-5 | Register a SKILL.md from a folder (with optional `resources/` sub-directory) or from inline text. Re-registering the same `(name, namespace)` creates a new version; the previous row is superseded. |
| `memory_skill_list` | `other` | L1-5 | List current (non-superseded) skills with `~100 tokens/skill`. Returns id, name, description, namespace, digest, metadata. **Body is NOT decompressed** — use `memory_skill_get` for activation. |
| `memory_skill_get` | `other` | L1-5 | Return the full activation payload: metadata + decompressed body. Old version ids remain addressable after supersession (durable history). |
| `memory_skill_resource` | `other` | L1-5 | Fetch a single resource by `(skill_id, resource_path)`, digest-verified against the row's SHA-256 before return. Errors on digest mismatch. |
| `memory_skill_export` | `other` | L1-5 | Write SKILL.md + `resources/` to a target folder. Re-registering from the exported folder produces the **identical SHA-256 digest** — the round-trip guarantee. Appends a `skill.exported` row to `signed_events`. |
| `memory_skill_promote_from_reflection` | `other` | L2-6 | Promote a `Reflection`-kind memory (depth ≥ 1, default floor `1`) to a SKILL.md-format skill. Each `reflects_on` source becomes a `references/source_{i}.md` resource. Frontmatter records `derived_from_reflection_id` + `original_reflection_depth`. The resulting digest is identical to a hand-authored SKILL.md with the same content. |
| `memory_skill_compositional_context` | `other` | L2-7 | Return a skill body + reflection memories from the namespaces declared in its `composes_with_reflections` frontmatter list, bounded by `max_reflection_depth` and a caller-supplied token budget (`budget_tokens`, default 4000, max 32000). |

(All seven report the `other` family in the MCP registry —
`crate::profile::Family::Other`; they ship in `--profile full`.)

Total: 7 MCP tools in the `memory_skill_*` family. The MCP tool
count grew from 60 → 63 across the L2 wave (L2-3 +
`memory_dependents_of_invalidated`; L2-6 +
`memory_skill_promote_from_reflection`; L2-7 +
`memory_skill_compositional_context`). The skill-family count alone
is 7 because the original L1-5 substrate landed 5 of the verbs
(`register`, `list`, `get`, `resource`, `export`) before L2-6 and
L2-7 added the closing-loop verbs.

## SKILL.md format + frontmatter

A `SKILL.md` file is a markdown document with a YAML frontmatter
block fenced by `---`:

```text
---
namespace: global
name: my-skill
description: "Does something useful."
license: Apache-2.0          # optional, SPDX expression or free-form
compatibility: ">=0.7.0"     # optional, 1-500 chars
allowed_tools:               # optional list of MCP tool names
  - memory_recall
  - memory_store
composes_with_reflections:   # v0.7.0 L2-7 — optional list
  - namespace: foo/observations
    min_depth: 1
---

Markdown body follows the closing fence.
```

Validation rules (per the agentskills.io spec, enforced in
[`src/parsing/skill_md.rs`](../src/parsing/skill_md.rs)):

| Field | Constraint |
|---|---|
| `name` | Regex `^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`, length 1-64. No consecutive hyphens. |
| `description` | 1-1024 chars, non-empty. |
| `compatibility` | 1-500 chars when present. |
| `namespace` | Required, non-empty. |
| `license` | SPDX expression or free-form. Optional. |
| `allowed_tools` | List of MCP tool names. Optional. |
| `composes_with_reflections` | List of `{namespace, min_depth}` entries. Optional. See L2-7 below. |

### `composes_with_reflections` (L2-7)

**Landed in v0.7.0 (L2-7, [commit `0966b57`](https://github.com/alphaonedev/ai-memory-mcp/commit/0966b57), [issue #672](https://github.com/alphaonedev/ai-memory-mcp/issues/672)).**

A skill declares *which reflection namespaces it should be composed
with at activation time* via the `composes_with_reflections`
frontmatter list. Each entry pins a `namespace` and a `min_depth`
floor:

- `namespace` — the reflection-bearing namespace (e.g.
  `"foo/observations"`).
- `min_depth` — minimum `reflection_depth` (inclusive) a memory must
  carry to be surfaced for this entry. `0` admits caller-minted
  observations (rare for a reflection-composition flow but legal);
  typical use is `1+` to require at least one reflection pass.

The substrate filters out reflections shallower than the per-entry
`min_depth`, then applies the per-namespace
`GovernancePolicy::effective_max_reflection_depth` as the
**authoritative ceiling**: composition cannot bypass the bounded-
recursion guarantee. Composition is a *filter*, not an *override*.

The list is round-trip-stable through JSON: registration parses it
out of the YAML, embeds it under
`metadata.composes_with_reflections` (so older clients that don't
know the field still see it as opaque metadata per the v0.7.0
backward-compat guarantee), and `memory_skill_compositional_context`
reads it back. v0.9.0 promotes this declaration to a first-class
composition manifest (cross-skill linkage + verifier tooling) — the
field name, type, and semantics carry forward across that promotion.

## Round-trip semantics

The substrate guarantees a **content-addressed round-trip identity**
between registration, export, and re-registration:

```text
register(folder_A) → skill_X with digest D
export(skill_X, folder_B)
register(folder_B) → skill_Y with digest D   (identical SHA-256)
```

The digest is over the canonical serialisation of the manifest plus
the canonicalised resource payloads. Every field is stable across
emit/parse cycles; resource order is normalised; whitespace is
preserved verbatim. The guarantee survives transport across hosts,
across operating systems, and across the v0.7.0 → v0.8.0 schema
revisions documented in
[`docs/MIGRATION_v0.7.md`](MIGRATION_v0.7.md).

`memory_skill_export` appends one `skill.exported` row to the
append-only `signed_events` audit table on every export, so a
downstream auditor can re-derive when and by whom a skill was
moved off the substrate.

## Cross-node interchange (export-folder round-trip)

At v0.7.0 the federation receive pipeline
([`src/federation/receive.rs`](../src/federation/receive.rs)) ferries
`memories` and `memory_links` between peers — it does **not** carry
the `skills` / `skill_resources` tables. The canonical cross-node
interchange shape for a skill is the **export folder**:
`memory_skill_export` on node A produces `SKILL.md + resources/`,
the operator ships the folder (e.g. `tar | curl | tar -x`), and
`memory_skill_register` on node B consumes it. Because the digest is
content-addressed over the canonical serialisation, node B's
registered row carries the **identical SHA-256 digest** — pinned
end-to-end by
[`tests/cov_17_skills_federation_roundtrip.rs`](../tests/cov_17_skills_federation_roundtrip.rs).

On the receiving node:

- the digest is re-derived from the imported content, so tampering
  in transit surfaces as a digest change;
- the same validation pipeline the local `memory_skill_register`
  handler runs refuses a malformed imported skill with the same
  structured error;
- re-registering on a node that already holds version N of the same
  `(name, namespace)` produces version N+1 and supersedes the older
  row, just as on a local-only deploy. Both versions remain
  addressable by id.

A wire-level federation fanout for skills rides on this folder
contract and is a future-release surface.

## Ed25519 attestation

Every `skills` row is **signable**. When the daemon has a signing
keypair on disk (under the key directory —
`AI_MEMORY_KEY_DIR`, default platform config dir +
`/ai-memory/keys`, layout `<key_dir>/<agent_id>.{pub,priv}` —
[`src/identity/keypair.rs`](../src/identity/keypair.rs)), the
registrar:

1. Computes the canonical-byte digest of the manifest + resources.
2. Signs the digest with the signing agent's Ed25519 private key.
3. Writes the signature plus the signing agent identity into the
   row; the companion `signed_events` row carries
   `attest_level = "self_signed"`
   (`crate::models::AttestLevel::SelfSigned`).

Unsigned skills (no keypair on disk, or an import with no inbound
signature) carry `attest_level = "unsigned"` and the signature
column is empty — verification surfaces this honestly rather than
silently passing.

Verification on read is **always-on**: `memory_skill_resource`
re-derives the resource's SHA-256 digest and compares to the
recorded value before returning the decompressed bytes. Mismatch is
an error, never a quiet fallback.

The skill-level signature complements (does not replace) the
forensic-bundle attestation described in
[`forensic-export.md`](forensic-export.md). A skill embedded in a
forensic bundle gets re-attested at the bundle level *too* so the
bundle itself is verifiable end-to-end.

## Operator references

- **MCP tool definitions:** [`src/mcp/registry.rs`](../src/mcp/registry.rs)
  (search for `memory_skill_`)
- **Parser + validator:** [`src/parsing/skill_md.rs`](../src/parsing/skill_md.rs)
- **Model:** [`src/models/skill.rs`](../src/models/skill.rs)
- **Tool implementations:** [`src/mcp/tools/skill_*.rs`](../src/mcp/tools/)
- **Integration tests:**
  - [`tests/skill_test.rs`](../tests/skill_test.rs) — register / list / get / resource / export round-trip
  - [`tests/skill_promote_test.rs`](../tests/skill_promote_test.rs) — reflection-to-skill promotion
  - [`tests/skill_composition_test.rs`](../tests/skill_composition_test.rs) — `composes_with_reflections`
- **Forensic-bundle integration:** [`forensic-export.md`](forensic-export.md)
- **Recursive-learning bridge:** [`RECURSIVE_LEARNING.md` §Reflection-as-skill](RECURSIVE_LEARNING.md#reflection-as-skill-l2-6-closing-the-loop)
- **Issues:**
  - [#665](https://github.com/alphaonedev/ai-memory-mcp/issues/665) — L1-5 Agent Skills ingestion substrate
  - [#671](https://github.com/alphaonedev/ai-memory-mcp/issues/671) — L2-6 reflection-as-skill promote
  - [#672](https://github.com/alphaonedev/ai-memory-mcp/issues/672) — L2-7 `composes_with_reflections`

## Forward roadmap

- **v0.8.0 (composition refinements).** Cross-skill linkage:
  `composes_with_reflections` extends to a `composes_with_skills`
  list so a skill can declare a dependency on another skill's
  activation payload, with the substrate composing the bundle.
- **v0.9.0 composition manifests.** Promote `composes_with_reflections`
  from a declaration to a first-class composition manifest —
  cross-skill linkage, verifier tooling, signed composition
  attestations. The v0.7.0 wire shape carries forward (additive
  backward-compat); the v0.9 epic adds enforcement and tooling.
