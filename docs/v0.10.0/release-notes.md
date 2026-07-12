---
layout: doc
---
{% raw %}
# ai-memory v0.10.0 — `warn-carrier` (release notes — SKELETON)

> **Status: DRAFT SKELETON (not yet cut).** v0.10.0 is the planned
> WARN-carrier release ([#1972](https://github.com/alphaonedev/ai-memory-mcp/issues/1972))
> ahead of the v1.0.0 secure-default flips. This file is the structural
> skeleton mirroring the v0.9.0 template; sections are filled in during the
> release-cut, which is a separate operator-gated step. **No manifest versions
> are bumped by the WARN-carrier work** — the version bump + channel publish
> is the release-cut concern.

## Release procedure (operator-gated)

v0.10.0 inherits the v0.9.0 separation of CI verification from publish.
`ci.yml` runs on every push + PR + tag; `release.yml` runs ONLY on explicit
`workflow_dispatch` and handles the multi-channel fanout. To publish a tag:

```bash
# 1. Create the signed tag locally
git tag -s v0.10.0 -m "..."

# 2. Push the tag — fires ci.yml verification only
git push origin v0.10.0

# 3. Wait for ci.yml to land GREEN (Check matrix is the release gate)

# 4. Manually trigger publish — operator-gated, intentional
gh workflow run release.yml \
  --repo alphaonedev/ai-memory-mcp \
  -f tag=v0.10.0
```

Pre-release tags (SemVer `-` suffix, e.g. `v0.10.0-rc.1`) auto-skip the
downstream stable channels so operator dry-runs are safe. The language SDKs
publish on their own `publish-sdks.yml` dispatch.

## Headline

**v0.10.0 is a WARN-carrier release. It flips NO fail-open → fail-closed
default.** It ships the one-cycle-deprecation WARN machinery and the
flip-ready code paths for every v1.0.0 secure-default flip, so operators get a
full soak cycle of loud, actionable WARNs before any behaviour changes in
v1.0.0. Every WARN is one-shot (fires once per process, not per call).

## The WARN carriers (this release's entire scope)

Each carrier below emits a one-shot WARN and changes NO runtime behaviour.
The actual flips land in the v0.10.0 → v1.0.0 window per each item's rule.

### 1. `AI_MEMORY_RECALL_TOUCH_SYNC` removal path ([#1953](https://github.com/alphaonedev/ai-memory-mcp/issues/1953))

- **What:** the legacy synchronous recall-time touch knob (env-table row 118)
  is deprecated at birth (v0.9.0, [#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869))
  and is **removed in v1.0.0**.
- **WARN:** a one-shot deprecation WARN fires at daemon boot AND on the first
  recall-path use when `AI_MEMORY_RECALL_TOUCH_SYNC=1` is set. Message:
  `RECALL_TOUCH_SYNC_DEPRECATION_WARNING` (`src/config.rs`).
- **Migration:** unset the knob and rely on the pure-recall fold ledger
  (`recall_observations` folded by the access-fold loop). The knob still works
  this release.

### 2. Federation write-sig + signal-sig flips ([#1954](https://github.com/alphaonedev/ai-memory-mcp/issues/1954))

- **What:** `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (row 94, [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464))
  and `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` (row 96, [#1843](https://github.com/alphaonedev/ai-memory-mcp/issues/1843))
  currently default permissive (accept-and-flag). In v1.0.0 the default flips
  to **required-per-surface** — federation inbound IS the network surface
  (ruling `9e9c3cf2` condition 7).
- **WARN:** a one-shot boot WARN per knob fires when the knob is **unset**
  (an explicit opt-in OR opt-out suppresses it — the operator has chosen).
  Messages: `FED_REQUIRE_WRITE_SIG_FLIP_WARNING` /
  `FED_REQUIRE_SIGNAL_SIG_FLIP_WARNING` (`src/federation/receive_auth.rs`).
- **Flip-ready:** both resolvers route through the single named
  `FED_REQUIRE_SIG_DEFAULT` const (currently `false`); the v1.0.0 flip is a
  one-line diff to that const. The `=0` opt-out keeps working past the flip.
- **Cross-link:** [#1801](https://github.com/alphaonedev/ai-memory-mcp/issues/1801)
  (sender-side EMIT + TOFU) is the R19 residue that makes the write-sig flip
  meaningful.

### 3. Decorrelation enforce-default advisory ([#1952](https://github.com/alphaonedev/ai-memory-mcp/issues/1952))

- **What:** when `AI_MEMORY_REFLECT_DECORRELATION_MODE` is unset/off, the
  `curator --reflect` run emits a one-shot advisory: v1.0.0 defaults the
  decorrelation probe to **advisory** (per D3-021), with enforce-as-default
  tracked for v1.x (D3-021 → D3-031 → D3-060).
- **WARN:** `REFLECT_DECORRELATION_ADVISORY_NOTICE` (`src/config.rs`). No
  behaviour change; the anti-theater refusal rules are unchanged.

## Honest scope

- **No default flips ship in v0.10.0.** The compiled defaults for rows 94, 96,
  and 118, and the decorrelation mode, are byte-unchanged. The flip-ready
  const `FED_REQUIRE_SIG_DEFAULT` is still `false`.
- **No manifest bumps** are part of the WARN-carrier work (the release cut is
  the sanctioned step that bumps versions + publishes channels).
- **No schema migration** — the WARN carriers are pure control-flow additions.

## Upgrade guidance

Run v0.10.0 for at least one soak cycle. Act on any WARN you see:
set `AI_MEMORY_FED_REQUIRE_WRITE_SIG` / `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`
explicitly (adopt `=1` early or keep `=0`), unset `AI_MEMORY_RECALL_TOUCH_SYNC`
and validate the fold ledger, and set
`AI_MEMORY_REFLECT_DECORRELATION_MODE=advisory` if you want the v1.0.0 default
early. A silent v0.10.0 run means you are already aligned with the v1.0.0
posture.

## Schema ladder

No schema changes in the WARN-carrier work (schema stays at the v0.9.0 tip).
{% endraw %}
