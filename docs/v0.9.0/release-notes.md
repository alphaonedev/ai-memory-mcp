---
layout: doc
---
{% raw %}
# ai-memory v0.9.0 — `security-hardening` (release notes)

## Release procedure (operator-gated)

v0.9.0 inherits the v0.8.0 separation of CI verification from publish.
`ci.yml` runs on every push + PR + tag (lint, check matrix, feature
gates, dockerfile-validate, coverage). `release.yml` runs ONLY on
explicit `workflow_dispatch` and handles the actual multi-channel
fanout (binary builds + GitHub Release + crates.io + Homebrew tap +
GHCR Docker + Fedora COPR).

To publish a tag:

```bash
# 1. Create the signed tag locally
git tag -s v0.9.0 -m "..."

# 2. Push the tag — fires ci.yml verification only
git push origin v0.9.0

# 3. Wait for ci.yml to land GREEN (Check matrix is the release gate)

# 4. Manually trigger publish — operator-gated, intentional
gh workflow run release.yml \
  --repo alphaonedev/ai-memory-mcp \
  -f tag=v0.9.0
```

Pre-release tags (SemVer `-` suffix, e.g. `v0.9.0-rc.1`) auto-skip the
downstream stable channels (crates.io, Homebrew, Docker, COPR) so
operator dry-runs are safe.

The language SDKs publish on their own dispatch — `publish-sdks.yml`
handles the npm (`@alphaone/ai-memory`) + PyPI (`ai-memory-mcp`) fanout,
distinct from the `release.yml` binary/crate channels.

The act of releasing is a deliberate, named action — not a side effect
of green tests.

> **Status: RELEASED — GA 2026-07-08.** v0.9.0 (`security-hardening`) is
> generally available. The full CI matrix is GREEN on the release commit; the
> post-feature multi-agent code-review and security-review loops are both
> closed (see §"Security review + code review" below). Published to every
> channel — GitHub Release, crates.io, Homebrew, Fedora COPR, GHCR, npm, and
> PyPI — with binaries for macOS / Linux / Windows / iOS / Android. The
> `v0.9.0` tag is signed and promoted to `main`. **SDK version nuance:** the
> SDK 0.9.0 slots were burned by a withdrawn 2026-07-06 build — PyPI and npm
> permanently reserve deleted / unpublished version slots — so the SDK
> packages ship the 0.9.0 line under fresh versions: **PyPI `ai-memory-mcp`
> `0.9.0.post1`** and **npm `@alphaone/ai-memory` `0.9.1`**, both wrapping the
> unchanged 0.9.0 core. The crates.io crate, the signed tag, the GitHub
> Release, the GHCR Docker image, the Homebrew formula, and the COPR package
> are all `0.9.0`.

## Headline

v0.9.0 is a **security-hardening + code-review release**: it turns
v0.8.0's *promises* into *enforcement*. Two secure-default flips make
agent attestation and mandatory-hook enforcement the on-by-default
posture, and a 5-lane adversarial review of the release branch produced
**49 fixes** across the code-review and security-review lanes — every one
triaged legit and fixed in-release per the prime directive.

The release advances the schema **v70 → v78** (all additive), separates
the governance signing layer into three keys (Recorder / Judge /
Stopper), wires macaroon capability tokens and a signed identity-lineage
succession chain end-to-end, and adds first-class skill memories, a
memory-derivation lineage-DAG, an opt-in vector-search slice, and a
pure-by-default recall path with a periodic fold job.

**Surface at v0.9.0** (SSOT: `src/lib.rs` `EXPECTED_*` consts +
`src/profile.rs`):

| Surface | v0.9.0 |
|---|---|
| MCP tools (`--profile full`) | **101 advertised** (100 callable + the always-on `memory_capabilities` bootstrap) |
| MCP tools (`--profile core`) | **7** (original 5 + `memory_load_family` + `memory_smart_load`) + the `memory_capabilities` bootstrap |
| HTTP routes | **92 production `.route(...)` registrations** / 78 unique URL paths |
| CLI subcommands | **87 default build** / **89 under `--features sal`** (the gap is `Migrate` + `SchemaInit`) |
| `Memory` struct | **28 fields** (adds `cid`) |
| Schema | **v78** (`CURRENT_SCHEMA_VERSION`, both adapters) |

## Two secure-default flips (breaking)

v0.9.0 flips two knobs that shipped OFF (or non-functional) at v0.8.0 to
their secure on-by-default posture. Both are the deliberate follow-through
on a v0.8.0 one-cycle deprecation.

- **Agent attestation REQUIRED by default on direct writes ([#1751](https://github.com/alphaonedev/ai-memory-mcp/issues/1751)).**
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` (env-table row #48) flipped its
  store-path default `false` → **`true`** — the flip promised by the
  v0.8.0 #1464 one-cycle deprecation WARN. Every direct-store surface
  (MCP `memory_store`, HTTP `POST /api/v1/memories`, CLI `store`) that
  receives a write WITHOUT a caller-presented Ed25519 `signature` is now
  rejected with **`403 ATTESTATION_FAILED`** instead of landing
  `attest_level = "claimed"`. When a `signature` IS presented it is
  verified against the agent's bound key regardless of the flag (valid →
  `agent_attested`; forged → `403`). **Migration:** operators with
  unsigned CLI `store` / MCP `memory_store` / HTTP `POST /api/v1/memories`
  workflows must either sign writes (`ai-memory store --sign` with a
  keypair bound via `ai-memory agents bind-key`) or opt out with
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`. Scope is the direct-write path
  ONLY — the federation receive boundary attests via the peer-authorship
  allowlist (`resolve_inbound_attribution`, #1464), not this flag, and
  curator / autonomy self-writes are exempt. **Setup — step-by-step key
  generation, register / bind, and signing on CLI / HTTP / MCP across
  Linux / macOS / Windows / iOS / Android: [Attestation setup guide](../attestation.html).**
- **Mandatory-hook enforcement wired LIVE on both write paths ([#1885](https://github.com/alphaonedev/ai-memory-mcp/issues/1885), [#1924](https://github.com/alphaonedev/ai-memory-mcp/issues/1924)).**
  At v0.8.0 the `AI_MEMORY_HOOKS_ENFORCE_MODE` (env-table row #83)
  `enforce` gate shipped **non-functional**: the enforce module carried
  the pure helpers (`enforce_required_event_presence`,
  `effective_fail_mode`) but nothing composed them into a real dispatch
  path, so every `memory_store` resolved an EMPTY `HookChain` whose `fire`
  returns `Allow` — a silent bypass. `#1885`
  (`src/hooks/chain.rs::dispatch_pre_event_enforced`) wired the gate onto
  the MCP write path and `#1924`
  (`src/handlers/create.rs::http_pre_event_gate`) wired the parallel
  consult onto the HTTP handler surface, so a required pre-* event with no
  enabled hook now returns `Deny{code:503}` on both direct write paths.
  **Migration:** the gate stays a no-op until an operator opts in with
  `AI_MEMORY_HOOKS_ENFORCE_MODE=enforce` AND a non-empty
  `[hooks].required_events` (default empty = hard no-op even under
  `enforce`, the self-DOS guard) — a deployment that never set enforce
  mode is byte-unchanged, but any deployment that DID set it at v0.8.0
  (expecting enforcement it never got) now actually blocks.

## The 5-lane code + security review — 49 fixes ([#1885](https://github.com/alphaonedev/ai-memory-mcp/issues/1885)–[#1935](https://github.com/alphaonedev/ai-memory-mcp/issues/1935))

The post-feature review of `release/v0.9.0` ran two adversarial lanes — a
codegraph multi-agent **code review** (32 findings under umbrella
[#1884](https://github.com/alphaonedev/ai-memory-mcp/issues/1884)) and a
multi-agent **security review** (17 findings under umbrella
[#1918](https://github.com/alphaonedev/ai-memory-mcp/issues/1918)) —
for a combined **49 fixes, all triaged legit and fixed in-release**.
Representative closures:

- **Bulk_create per-row attestation gating ([#1919](https://github.com/alphaonedev/ai-memory-mcp/issues/1919)).**
  The `#1751` attestation flip is now charged per-row across the
  `POST /api/v1/memories/bulk` batch path, so a bulk write cannot smuggle
  unsigned rows past the single-write gate.
- **Inbound federated PENDING approvals gated ([#1920](https://github.com/alphaonedev/ai-memory-mcp/issues/1920)).**
  Inbound federated PENDING-approval writes are routed through the
  registered-approver gate, closing an approval-injection path on the
  receive boundary.
- **Tightened team/unit/org visibility scope ([#1921](https://github.com/alphaonedev/ai-memory-mcp/issues/1921)).**
  The collective-visibility predicate is tightened so a `team` / `unit` /
  `org`-scoped row resolves to its intended audience only.
- **skill_register folder_path symlink jail ([#1923](https://github.com/alphaonedev/ai-memory-mcp/issues/1923)).**
  The `skill_register` `folder_path` resource root is jailed against
  symlink traversal so a registered skill cannot reach outside its
  declared folder.
- **Non-argv credential channel ([#1927](https://github.com/alphaonedev/ai-memory-mcp/issues/1927)).**
  `AI_MEMORY_STORE_URL` / `AI_MEMORY_STORE_URL_FILE` (env-table row #122)
  keep the Postgres DSN password off `--store-url` and out of
  `/proc/<pid>/cmdline`; the file channel enforces 0600-or-tighter
  permissions (escape hatch `AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS`).

## Governance signing-layer separation

The audit / governance signer is split into three physically-separable
roles so no single compromised key can both record and adjudicate.

- **Three-key Recorder / Judge / Stopper signing separation ([#1826](https://github.com/alphaonedev/ai-memory-mcp/issues/1826), G9).**
  Each role signs a domain-separated preimage under its own custody
  directory (`AI_MEMORY_{RECORDER,JUDGE,STOPPER}_KEY_DIR`, env-table rows
  #103/#105/#107) and pins against its own out-of-band pubkey (rows
  #104/#106/#108); `verify_audit_trail` demotes a daemon-signed governance
  row to `Forged` once a recorder key is enrolled, emits a judge-signed
  `governance_verdict` on every governed verdict (allow AND block), and
  emits a stopper-signed `governance_enforcement` anchor on a deny. The
  runtime `deny` is produced BEFORE and INDEPENDENT of any stopper
  signing, so an unsigned deny still blocks.
- **Macaroon capability tokens wired end-to-end ([#1827](https://github.com/alphaonedev/ai-memory-mcp/issues/1827), G10.1).**
  A stateless macaroon capability-token grant layer
  (`src/governance/capability.rs`) whose valid token — caveat chain +
  issuer ceiling covering an in-flight `(action, namespace)` — flips an
  otherwise-`Deny`/`Ask` coarse-gate decision to `Allow` (attenuation
  only). Master switch `[capabilities].enabled` /
  `AI_MEMORY_CAPABILITIES` (env-table row); GA-inert (byte-identical,
  zero new audit bytes) when off. Lifecycle via the new
  `ai-memory capability keygen|mint|attenuate|inspect|verify` CLI surface.
- **Signed identity-lineage key-succession chain ([#1828](https://github.com/alphaonedev/ai-memory-mcp/issues/1828), schema v76).**
  A dedicated `agent_lineage` table records one signed succession record
  per `(agent_id, epoch)` — the composite PRIMARY KEY is the DB-enforced
  anti-equivocation constraint — so a rotated daemon key survives a
  `verify_audit_trail` genesis→head walk. Scope is single-node key-ROTATION
  survival ONLY (NOT key-loss resilience; the recovery VERIFY path is v1.0)
  and is advisory/verdict-only. Fail-closed require-mode via
  `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` (env-table row).

## Additive surfaces

- **First-class skill memories (B7-SKILL, [#1865](https://github.com/alphaonedev/ai-memory-mcp/issues/1865)).**
  Skills become a first-class memory shape carrying a `parameters_schema`
  and an `invocation_record`, so a registered skill's callable contract
  and its usage history live in the substrate alongside memories.
- **recall_observations shadow-feedback loop ([#1706](https://github.com/alphaonedev/ai-memory-mcp/issues/1706)).**
  The `recall_observations` ledger feeds a shadow-feedback loop over the
  recall path.
- **Memory-derivation lineage-DAG ([#1859](https://github.com/alphaonedev/ai-memory-mcp/issues/1859)).**
  A three-surface derivation-lineage walk over the provenance subset
  `P = {derived_from, reflects_on, derives_from}`: the `memory_lineage`
  MCP tool, `GET /api/v1/memories/{id}/lineage`, and `ai-memory lineage`.
  Backed by the schema-v75 `memory_links.source_cid` / `target_cid`
  content-id mirror so lineage resolves stable node identity even after a
  source is tombstoned.
- **Opt-in vector-search minimal slice ([#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005)).**
  An opt-in ANN slice with capacity + dimension guards:
  `AI_MEMORY_VECTOR_INDEX_CAPACITY` (residency cap),
  `AI_MEMORY_VECTOR_INDEX_HARD_FAIL` (reject-at-cap vs evict-oldest),
  `AI_MEMORY_REQUIRE_DIM_MATCH` (strict dimension mode), and
  `AI_MEMORY_VECTOR_NAMESPACE_ALLOWLIST` (namespace-filtered ANN that
  closes small-namespace starvation).
- **Recall is pure-by-default with a periodic fold job ([#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869)).**
  Recall now mutates ZERO rows in `memories` on every path (the
  append-only `recall_observations` ledger is the only recall-time write);
  the access ladders (access_count, TTL floor-extend, tier promotion,
  priority decade) are batch-applied by a periodic FOLD job
  (`db::fold_recall_accesses` / `MemoryStore::fold_recall_accesses`,
  schema v77 `folded` column). The legacy synchronous touch is
  opt-back-in via `AI_MEMORY_RECALL_TOUCH_SYNC=1` (env-table row #118).

## Security review + code review

The post-feature work followed the v0.8.0 testing-loop discipline, run as
a five-step hardening program on `release/v0.9.0`:

1. **Codegraph multi-agent code review** — surfaced **32 findings**
   (umbrella [#1884](https://github.com/alphaonedev/ai-memory-mcp/issues/1884)).
2. **Fixed 100%** — every code-review finding closed in-release.
3. **Multi-agent security review** — surfaced **17 findings**
   ([#1919](https://github.com/alphaonedev/ai-memory-mcp/issues/1919)–[#1935](https://github.com/alphaonedev/ai-memory-mcp/issues/1935),
   umbrella [#1918](https://github.com/alphaonedev/ai-memory-mcp/issues/1918)).
4. **Fixed 100%** — every security finding closed in-release.
5. **DO crypto 3-green + dogfood 3-green** on the hardened binary, then a
   **docs-drift** sweep.

Each finding was fixed, retested, and closed in-release per the prime
directive (no deferrals). The review/validation loop closed green before
the (operator-gated) tag cut.

> The detailed per-issue write-ups for #1884–#1935 are tracked in the
> GitHub issues + the campaign memory rather than this CHANGELOG; they are
> summarized here for completeness and to record that both review lanes
> closed green.

## Schema ladder v72 → v78

All additive (CLAUDE.md §Database is the SSOT). Both adapters mirror via
`src/store/postgres.rs::{migrate_v72 … migrate_v78}`.

| Schema | Change |
|---|---|
| v72 | signed `memory_revisions` append-only spine ([#1823](https://github.com/alphaonedev/ai-memory-mcp/issues/1823), G6) |
| v73 | additive nullable `signed_events.cause_hash` audit cause-binding ([#1822](https://github.com/alphaonedev/ai-memory-mcp/issues/1822), G5a) |
| v74 | additive BLAKE3 `memories.cid` / `cid_genesis` content-id ([#1825](https://github.com/alphaonedev/ai-memory-mcp/issues/1825), G8) |
| v75 | `memory_links.source_cid` / `target_cid` lineage-DAG mirror ([#1859](https://github.com/alphaonedev/ai-memory-mcp/issues/1859), G13-mem) |
| v76 | signed `agent_lineage` succession table ([#1828](https://github.com/alphaonedev/ai-memory-mcp/issues/1828), G13) |
| v77 | `recall_observations.folded` recall-purity fold-state column ([#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869), P0-1) |
| v78 | `model_attestations` write-once TOFU table ([#1870](https://github.com/alphaonedev/ai-memory-mcp/issues/1870), §25.3 S1) |
{% endraw %}
