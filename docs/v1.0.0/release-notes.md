---
layout: doc
---
{% raw %}
# ai-memory v1.0.0 — GA (release notes)

## Release procedure (operator-gated)

v1.0.0 inherits the v0.8.0 separation of CI verification from publish.
`ci.yml` runs on every push + PR + tag (lint, check matrix, feature
gates, dockerfile-validate, coverage). `release.yml` runs ONLY on
explicit `workflow_dispatch` and handles the actual multi-channel
fanout (binary builds + GitHub Release + crates.io + Homebrew tap +
GHCR Docker + Fedora COPR).

To publish a tag:

```bash
# 1. Create the signed tag locally
git tag -s v1.0.0 -m "..."

# 2. Push the tag — fires ci.yml verification only
git push origin v1.0.0

# 3. Wait for ci.yml to land GREEN (Check matrix is the release gate)

# 4. Manually trigger publish — operator-gated, intentional
gh workflow run release.yml \
  --repo alphaonedev/ai-memory-mcp \
  -f tag=v1.0.0
```

Pre-release tags (SemVer `-` suffix, e.g. `v1.0.0-rc.1`) auto-skip the
downstream stable channels (crates.io, Homebrew, Docker, COPR) so
operator dry-runs are safe.

The language SDKs publish on their own dispatch — `publish-sdks.yml`
handles the npm (`@alphaone/ai-memory`) + PyPI (`ai-memory-mcp`) fanout,
distinct from the `release.yml` binary/crate channels.

The act of releasing is a deliberate, named action — not a side effect
of green tests.

> **Status: SHIP-RECOMMENDED — tag cut operator-gated.** The v1.0.0
> Program (ROADMAP §27, [#1939](https://github.com/alphaonedev/ai-memory-mcp/issues/1939))
> ran as gated work: Gate 0 (Sprint 0, [#1938](https://github.com/alphaonedev/ai-memory-mcp/issues/1938))
> → Gate 1 P0 freeze-critical formats → Gate 1′ "defaults stop lying" →
> Gate 2 P1 safety machinery → Gate 3 endgame. The Gate-3 loops
> (DigitalOcean full-spectrum testing + attestation, the multi-agent
> AI-NHI code review + security review, and the final AI-NHI dogfood)
> closed green (see §"Gate-3 evidence" and §"Security review + code
> review"). Per the standing v0.7.0 release gate the **tag cut itself is
> operator-gated** — no Cargo.toml / manifest is bumped in this document.
> The v0.10.0 `warn-carrier` release ([#1972](https://github.com/alphaonedev/ai-memory-mcp/issues/1972),
> GA 2026-07-12) shipped the one-cycle deprecation WARNs ahead of every
> secure-default flip below, so the flips are heads-up, not surprises.

## Headline

v1.0.0 is the **GA of the perfect-endpoint program** — it turns the
substrate's secure defaults from *opt-in* into *on*, lands the
crypto-core stage (SubkeyCert instance certification, epistemic memory
kinds, claim-bitemporal columns), and certifies the postgres + Apache
AGE + pgvector storage backend.

> **Certified-backend scope — read this before choosing Postgres.** The
> two backends are **not one identical API**: **59 of the 80 unique
> production HTTP paths are served on Postgres; the remaining 21 fail
> closed with a uniform `501 NOT IMPLEMENTED`** (the Agent Skills surface,
> `/api/v1/share`, the legacy `/api/v1/find_paths` alias, and the
> `memory_*` MCP-parity routes with no pg SAL trait method yet — pinned by
> `tests/pg_supported_route_inventory_gate_2799.rs`), and **MCP-stdio is
> structurally SQLite-only** ([#1675](https://github.com/alphaonedev/ai-memory-mcp/issues/1675)):
> a Postgres-backed deployment serves MCP clients through the HTTP daemon,
> not `ai-memory mcp`. The certified **PG 18.6 / AGE 1.8.0 / pgvector
> 0.8.6** stack is now exercised in-PR on every `release/**` PR by
> `.github/workflows/cert-postgres-age.yml`, which runs the pg-parity and
> AGE cells `--include-ignored` against the certified image CI builds from
> `deploy/docker-1461/Dockerfile.pg-age-vector` (SSOT-pinned PG 18.6 / AGE
> 1.8.0 / pgvector 0.8.6) and hard-fails on any drift from the exact pinned
> minors;
> the PG 16 / AGE 1.6.0 combination in `coverage.yml` is the documented
> **alternate** matrix (a line-coverage measurement). See §"Certified
> backend versions" for the exact versions and evidence basis.

The "defaults stop lying" lane (Gate 1′) is the centerpiece: six knobs
that shipped OFF (or non-functional) through v0.10.0 now resolve to their
secure posture by default, each riding the one-cycle deprecation-WARN
discipline the v0.10.0 `warn-carrier` release delivered. The release also
advances the schema **v78 → v89** — additive `ADD COLUMN` through v85,
then **two DATA-MUTATING rungs (v86, v87) that rewrite stored rows**, one
index-only rung (v88) and one derived-column-rebuild rung (v89, the
postgres FTS `tags` fold); see §"Schema ladder v78 → v89" — adds an M-of-N
threshold key-recovery lane, human-key-signed m-of-n approvals, an
open-time rollback-evidence check, an inference-plane egress gate, and a
named `asi-hard` no-disable security posture.

**Surface at v1.0.0** (SSOT: `src/lib.rs` `EXPECTED_*` consts +
`src/profile.rs`; v1.0.0's growth is primarily env-knob + schema surface,
with a small net increase in tool/route/CLI counts over v0.9.0 — e.g. the
`Stop` ([#1955](https://github.com/alphaonedev/ai-memory-mcp/issues/1955))
and `Watch` ([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978))
CLI subcommands):

| Surface | v1.0.0 |
|---|---|
| MCP tools (`--profile full`) | **103 advertised** (102 callable + the always-on `memory_capabilities` bootstrap) |
| MCP tools (`--profile core`) | **7** (original 5 + `memory_load_family` + `memory_smart_load`) + the `memory_capabilities` bootstrap |
| HTTP routes | **94 production `.route(...)` registrations** / 80 unique URL paths |
| CLI subcommands | **90 default build** / **92 under `--features sal`** (the `capability init` sub-verb rides the existing `Capability` command, so the top-level count is unchanged) |
| `MemoryKind` variants | **16** (adds v1.0.0 epistemic typing `Told` / `Instruction` / `Intervention`, [#1945](https://github.com/alphaonedev/ai-memory-mcp/issues/1945)) |
| Schema | **v89** (`CURRENT_SCHEMA_VERSION`, both adapters). Not uniformly additive: v79–v85 are additive, **v86 and v87 rewrite stored rows**, v88 is index-only, v89 redefines the postgres FTS `tsv` generated column (derived data, no stored-row rewrite). Per-rung detail + the true bound of the migration evidence: §"Schema ladder v78 → v89" |

## Secure-default flips (breaking)

v1.0.0 flips the Gate-1′ "defaults stop lying" knobs to their secure
posture. Every flip shipped its one-cycle deprecation WARN in v0.10.0
(`warn-carrier`), so an operator who set nothing is warned before the
behavior changes here.

- **Federation per-write content signature required by default ([#1801](https://github.com/alphaonedev/ai-memory-mcp/issues/1801) → [#1954](https://github.com/alphaonedev/ai-memory-mcp/issues/1954)).**
  `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (env-table row #94) flipped its
  compiled default `false` → **`true`**. Federation inbound IS the
  network surface (ruling `9e9c3cf2` condition 7), so a HONORED
  third-party relayed memory (`attribute_agent != sender`) without a
  valid `metadata.write_signature` over the #626 `SignableWrite` envelope
  is now refused. v1.0.0 also lands the **author-side EMIT**: the
  authoring node persists the detached Ed25519 signature at STORE time
  (`identity::attest::persist_write_signature`, wired into CLI `--sign` +
  MCP/HTTP signed-store paths) and it propagates verbatim across every
  relay hop (a relayer never re-signs a third-party attribution). The
  former single `FED_REQUIRE_SIG_DEFAULT` const split into
  `FED_REQUIRE_WRITE_SIG_DEFAULT` and `FED_REQUIRE_SIGNAL_SIG_DEFAULT` so
  the two lanes revert independently. **Migration:** unset now resolves
  STRICT; an explicit falsy token (`0`/`false`/`no`/`off`) is the
  staged-rollout bridge back to accept-and-flag during peer key
  enrollment. Multi-hop propagation of third-party content requires the
  ORIGIN author's key enrolled at EACH receiving node (a refused honored
  relay emits the distinguishable `missing-author-key` /
  `missing-signature` WARN + the `unenrolled_author_strict` DLQ cause;
  TOFU key distribution stays deferred to v1.x).
- **Federation per-signal author signature required by default ([#1801](https://github.com/alphaonedev/ai-memory-mcp/issues/1801) → [#1954](https://github.com/alphaonedev/ai-memory-mcp/issues/1954)).**
  `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` (env-table row #96, [#1843](https://github.com/alphaonedev/ai-memory-mcp/issues/1843))
  flipped `false` → **`true`** (compiled const
  `FED_REQUIRE_SIGNAL_SIG_DEFAULT = true`). An inbound relayed signal is
  now required to verify against `from_agent`'s locally-enrolled Ed25519
  key; an unenrolled / unverified author is skipped per-signal (never a
  batch drop). `=0` reverts to the permissive accept-and-flag posture.
- **Capabilities default-ON with a zero-config owner mint ([#1827](https://github.com/alphaonedev/ai-memory-mcp/issues/1827) → [#1960](https://github.com/alphaonedev/ai-memory-mcp/issues/1960), R9).**
  `[capabilities].enabled` / `AI_MEMORY_CAPABILITIES` (env-table row
  #110) compiled default flipped `false` → **`true`**. This is
  **ADDITIVE-ONLY** — the gate hook short-circuits `token.is_none() ||
  base==Allow` BEFORE it consults `enabled`, so a capability-LESS caller
  is byte-identical to the legacy inert posture and gains ZERO new
  denials; only a caller that actively presents a token pays extra work.
  R9 also adds the reserved zero-config `owner` issuer, auto-enrolled from
  on-disk custody (`owner.priv`/`.pub` + `owner.caproot`) with an Admin
  ceiling once `ai-memory capability init` has run. `AI_MEMORY_CAPABILITIES=off`
  restores the fully-inert posture.
- **Reflection decorrelation probe default `advisory` ([#1764](https://github.com/alphaonedev/ai-memory-mcp/issues/1764) → [#1952](https://github.com/alphaonedev/ai-memory-mcp/issues/1952), D3-021).**
  `AI_MEMORY_REFLECT_DECORRELATION_MODE` (env-table row #92) compiled
  default flipped `off` → **`advisory`** — the probe now runs and WARNs
  by default ("defaults stop lying"). After the reflection pass,
  `curator --reflect` computes single-producer CLAIMED dominance and
  emits a per-namespace advisory carrying the mandated caveat *"family
  attestation unavailable — diversity is CLAIMED not ATTESTED."* `enforce`
  remains reserved (it needs attested model-family provenance that would
  otherwise be security theater); the enforce-as-default flip is tracked
  for v1.x (D3-021 → D3-031 → D3-060). `off` opts out.
- **Agent-attestation default surface-scoped ([#1985](https://github.com/alphaonedev/ai-memory-mcp/issues/1985), resolving [#1981](https://github.com/alphaonedev/ai-memory-mcp/issues/1981)).**
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` (env-table row #48) is now
  tri-state with a per-surface compiled default. With the env unset, an
  unsigned direct-store write is fail-CLOSED (`403 ATTESTATION_FAILED`)
  ONLY on the HTTP direct-write surface (`POST /api/v1/memories` +
  `/memories/bulk`); the MCP `memory_store` and CLI `store` surfaces are
  the operator-as-actor path and stay permissive (unsigned →
  `attest_level="claimed"`). This CORRECTS the v0.9.0 #1751
  require-everywhere default, which was unsatisfiable on MCP (no MCP host
  can construct/sign the canonical `SignableWrite` envelope — the #1981
  external break). `=1` forces strict on every surface (the v0.9.0
  posture); `=0` forces permissive on every surface. A presented-but-forged
  signature is still rejected unconditionally on every surface. Scope is
  by API surface, NEVER transport/bind.
- **`AI_MEMORY_RECALL_TOUCH_SYNC` REMOVED ([#1953](https://github.com/alphaonedev/ai-memory-mcp/issues/1953)).**
  The legacy synchronous recall-time touch opt-back-in (env-table row
  #118) — deprecated at birth by the [#1869](https://github.com/alphaonedev/ai-memory-mcp/issues/1869)
  pure-recall vote, with its one-cycle v0.10.0 deprecation WARN already
  shipped — is gone: the env knob, `config::recall_touch_sync_enabled` /
  `ENV_RECALL_TOUCH_SYNC` / the deprecation-warning machinery, and every
  recall-path caller of the explicit touch verbs are removed. Recall is
  now **unconditionally pure** on every surface (both backends) — the
  periodic FOLD job (`db::fold_recall_accesses` /
  `MemoryStore::fold_recall_accesses`) is the sole applier of the access
  ladders from the `recall_observations` ledger. **Migration:** unset is
  byte-identical (no action); operators who had set the knob to `1` must
  remove it — the value is now silently ignored, not honored.

Two more knobs ship a secure default at v1.0.0 as net-new controls (they
had no prior WARN-carrier because there is nothing to break): the
per-checkpoint-resolution signature gate `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG`
(row #125, default `1`, [#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936))
and the cross-node governance `policy_version` refuse-stale gate
`AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` (row #132, default `1` for a
DETECTED-stale value, [#1947](https://github.com/alphaonedev/ai-memory-mcp/issues/1947)).
Both fail closed only on positive evidence (an absent/undeterminable
epoch is fail-OPEN, so existing federation is not hard-refused). See
§"Additive surfaces".

## Certified backend versions

The version story has two honest halves, and it matters which is which:

**Continuously + reproducibly CI-tested (every PR and push): PostgreSQL 16
+ Apache AGE 1.6.0.** The AGE-gated Cypher/KG suites
(`age_cte_equivalence`, `g2_postgres_find_paths_age_param_binding`,
`g4_postgres_link_projects_into_age_graph`, `cov_postgres_kg`,
`issue_1482_age_cypher_persistent`, `kg_age_fallback`) and the
pgvector-backed recall-purity suite (`recall_purity_p01_postgres`) run
green under `--features sal,sal-postgres --include-ignored` against the
`apache/age:release_PG16_1.6.0` service container in `coverage.yml`, with
pgvector layered in at service start via the `postgresql-16-pgvector` apt
package. This PG 16 / AGE 1.6.0 combination is the documented **alternate**
matrix — the stack `coverage.yml` measures line coverage against; the
certified PG 18.6 / AGE 1.8.0 / pgvector 0.8.6 stack is exercised in-PR
separately by `.github/workflows/cert-postgres-age.yml` (next paragraph).

**CI-asserted in-PR on `release/**` (SSOT-pinned): PostgreSQL 18.6 + Apache
AGE 1.8.0 + pgvector 0.8.6.** These are the pins
the deployment SSOT carries — `deploy/docker-1461/provision/lib.sh`
(`EXPECTED_PG_VERSION=18.6`, `EXPECTED_AGE_VERSION=1.8.0`,
`PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`,
`AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0` with AGE upgraded to 1.8.0
via a pinned pgdg apt install; the pgvector Rust binding
is the `pgvector` crate `0.4`, `features = ["sqlx"]`) — standardized to the
current-stable line by operator directive 2026-08-18. **Apache AGE 1.8.0 is
the newest RELEASED AGE for PG18** (tagged `PG18/v1.8.0-rc0` per Apache
AGE's release-vote convention; `CREATE EXTENSION age` reports extversion
1.8.0), installed via the pinned pgdg `postgresql-18-age` `.deb`. As of
[#2548](https://github.com/alphaonedev/ai-memory-mcp/issues/2548) /
[#2512](https://github.com/alphaonedev/ai-memory-mcp/issues/2512) the
AGE/KG + recall-purity suites run against this exact stack in-PR:
`.github/workflows/cert-postgres-age.yml` BUILDS
`deploy/docker-1461/Dockerfile.pg-age-vector` — the same recipe the
docker-1461 mesh ships — with build-args resolved straight from this SSOT
(`deploy/docker-1461/provision/lib.sh`), runs the resulting image as the
postgres under test, runs the pg-parity and AGE cells `--include-ignored`,
and version-asserts the EXACT pinned minors (PostgreSQL 18.6, Apache AGE
1.8.0, pgvector 0.8.6 — not merely "PG 18" or "pgvector >= 0.8.6") — so the
certified tier is proven by execution on the cert branch, not merely
claimed, and CI's build artifact is the SAME artifact the deploy SSOT
ships (zero drift by construction). The PG 16 / AGE 1.6.0 combination in
`coverage.yml` remains as the documented alternate matrix.

> **Cross-lane pgvector pin — reconciled ([#2872](https://github.com/alphaonedev/ai-memory-mcp/issues/2872)).**
> Both certified provisioning SSOTs now pin pgvector **0.8.6**:
> `deploy/docker-1461/provision/lib.sh` (`PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`,
> the container lane on Debian 13) and `deploy/do-1461/provision/lib.sh`
> (`PGVECTOR_APT_VERSION=0.8.6-1.pgdg24.04+1`,
> `EXPECTED_PGVECTOR_VERSION=0.8.6`, the NATIVE lane on Ubuntu 24.04). Only
> the pgdg distro suffix differs by lane (`pgdg13` vs `pgdg24.04`); the
> patch version is identical and both distro builds exist in the live pgdg
> apt repo. The earlier `do-1461` pin of `0.8.2` was accidental drift and
> was additionally no longer resolvable (pgdg keeps only a rolling window,
> so `0.8.2-1.pgdg24.04+1` is absent from noble-pgdg). Cross-lane parity is
> now asserted mechanically by `tests/provisioning_pgvector_pin_parity.rs`,
> so a future accidental divergence fails loudly. The former CI-vs-SSOT
> AGE drift (CI 1.6.0 vs SSOT 1.7.0) is **resolved** by
> [#2512](https://github.com/alphaonedev/ai-memory-mcp/issues/2512) /
> [#2548](https://github.com/alphaonedev/ai-memory-mcp/issues/2548): the
> certified AGE 1.8.0 / PG 18 canonical stack is now exercised in-PR by
> `.github/workflows/cert-postgres-age.yml`, while `coverage.yml`'s
> PG 16 / AGE 1.6.0 run is the documented alternate matrix.

### What those AGE greens attest — read this before relying on them

Until [#2511](https://github.com/alphaonedev/ai-memory-mcp/issues/2511)
(HIGH / data-honesty) landed, **every AGE-routed graph READ was rejected
by AGE at parse time and silently re-served from the relational
recursive CTE**, while `Capabilities.kg_backend` kept reporting `Age`.
There were **five independent causes, each sufficient on its own.** The
suites named above were green through that window, so **those greens
attest the relational CTE path, not the AGE engine** — they predate the
parse-time-fallback fix and were never evidence that AGE served a single
one of those reads.

#2511's own regression tests had to assert through DIRECT Cypher rather
than through `kg_query`, precisely because `kg_query` falls back — so a
`kg_query`-only assertion cannot tell the two engines apart
(`tests/age_cypher_param_binding_2511.rs`; both live tests FAIL at the
parent commit, and a DB-free source-inspection pin structurally rejects
the bad statement shape on hosts that never see AGE). #2511 is fixed and
closed.

**Residual, RESOLVED by [#2613](https://github.com/alphaonedev/ai-memory-mcp/issues/2613).**
The AGE `find_paths` reader (`find_paths_cypher`) and its
`build_find_paths_current_view_cypher` builder — which emitted an
`ALL(e IN relationships(p) …)` guard that the pinned AGE version rejects
at parse time — were unreachable from production ever since #2582 routed
`find_paths` to the relational recursive-CTE UNCONDITIONALLY on both
backends. #2613 DELETES that dead reader + builder rather than porting a
path the measurements prove can never win (5-agent vote `4d3ea1c5`,
unanimous), closing the "advertise a capability it cannot deliver" gap.
The reporting honesty gap is closed too: an AGE deployment now emits a
one-shot connect-time WARN stating `find_paths` is CTE-served (the
per-call fallback WARN that removal left silent). `find_paths` results
were and remain correct (the CTE reads the durable `memory_links`);
`kg_query` / `kg_timeline` / `lineage` still use AGE Cypher.

### CI posture for the SSOT-pinned (18.6) stack — exercised in-PR on `release/**`

**The certified PG 18.6 + AGE 1.8.0 + pgvector 0.8.6 stack is now
exercised in-PR.** `.github/workflows/cert-postgres-age.yml`
([#2548](https://github.com/alphaonedev/ai-memory-mcp/issues/2548))
triggers on `pull_request` + `push` to `release/**`, resolves every
version pin from the ONE declaration source
(`deploy/docker-1461/provision/lib.sh`), BUILDS
`deploy/docker-1461/Dockerfile.pg-age-vector` with those pins as
build-args (the same recipe the docker-1461 mesh ships — no second,
drift-prone copy of the pins), runs the resulting image as the postgres
under test, runs the `#[ignore]`-gated pg-parity binaries AND the
AGE-backed cells (`AI_MEMORY_TEST_AGE_URL` set, so they stop
self-skipping) under `--features sal-postgres --include-ignored`, and a
version-assert step hard-fails on ANY drift from the exact pinned minors
— PostgreSQL 18.6, Apache AGE 1.8.0, pgvector 0.8.6, not a looser "PG 18"
/ "pgvector >= 0.8.6" match. This is what makes the 2026-08-01 cutline
ruling §5.4(3) executable — the certified tier is proven by execution on
the cert branch, at the exact certified minors the docs cite.

The historical `postgres-age` nightly
([#2012](https://github.com/alphaonedev/ai-memory-mcp/issues/2012)) that
once rebuilt the stack from source every night was **deleted on
2026-07-31 by operator directive** (`2b85ba38`), and is NOT what
provides this coverage — the new in-PR job above does.
The former nightly cross-backend parity workflow (four parity binaries
against a `pgvector/pgvector:pg16` service container, no AGE) was
**removed in the v1.0.0 self-hosted CI rewrite**: the enterprise-fed
Check legs now run the sal-postgres parity suite in-PR on every push/PR
against the always-up native tier, so a separate nightly is redundant.
`coverage.yml`
continues to run the AGE-gated Cypher/KG suites on every PR and push
against an `apache/age:release_PG16_1.6.0` service container — **PG 16 +
AGE 1.6.0**, retained as the documented alternate matrix (a line-coverage
measurement, not the certified tier). The former CI-vs-SSOT AGE drift
([#2512](https://github.com/alphaonedev/ai-memory-mcp/issues/2512) defect
2) is **resolved**: CI now exercises the certified AGE 1.8.0 canonical
tier via `cert-postgres-age.yml` and honestly labels the PG 16 alternate.

## Additive surfaces

- **crypto-core stage 2 — SubkeyCert + epistemic kinds + claim-bitemporal columns ([#1942](https://github.com/alphaonedev/ai-memory-mcp/issues/1942) / [#1945](https://github.com/alphaonedev/ai-memory-mcp/issues/1945) / [#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834), schema v79).**
  A coordinated additive migration adds the `agent_subkey_certs` table
  backing the SubkeyCert instance-certification layer (spec §2.3 — a
  sub-key's raw Ed25519 verifying-key bytes + canonical signed CBOR +
  the principal root's Ed25519 signature + a revocation flag), the
  additive `memories.kind_provenance` column (HOW `memory_kind` was
  assigned — closed vocab `{declared, channel_derived, regex, llm}`;
  UNSIGNED metadata, not in the SignableWrite v2 envelope), and the
  claim-bitemporal `memories.valid_from` / `valid_until` columns (the
  interval a claim is asserted to hold, distinct from `created_at`). The
  `MemoryKind` vocabulary gains the epistemic-typing variants `Told` /
  `Instruction` / `Intervention` (#1945), bringing it to 16.
- **M-of-N threshold key recovery ([#1831](https://github.com/alphaonedev/ai-memory-mcp/issues/1831), G17, schema v81).**
  Two additive recovery-only `agent_lineage` columns — `guardian_set_id`
  (the committed SHA-256 over the sorted enrolled recovery-guardian
  pubkeys) + `recovery_threshold` (the committed M-of-N threshold) — both
  NULL on every non-recovery record and committed INSIDE the signed CBOR
  body, so a persisted recovery is re-verified against its mint-time trust
  bar (never the verifier's later env). This is the key-LOSS resilience
  path the v0.9.0 identity-lineage layer (single-node key-ROTATION only)
  explicitly deferred.
- **Human-key-signed m-of-n approvals ([#1957](https://github.com/alphaonedev/ai-memory-mcp/issues/1957), R40).**
  `AI_MEMORY_APPROVER_PUBKEYS` (env-table row #126) enrolls an approver
  key set in ADDITION to the governance operator key, and
  `AI_MEMORY_APPROVAL_THRESHOLD` (row #127, default `1`) sets the m-of-n
  threshold. `memory_pending_approve` accepts an `approvals` array of
  detached Ed25519 signatures over the domain-separated approval bytes;
  the gate counts DISTINCT valid enrolled signers. A pending action routed
  from a typed `Decision::Escalate` REQUIRES the signed quorum. The
  airgapped-operability model is single-call — an operator collects M
  signatures OFFLINE and submits them together, so no cross-call durable
  m-of-n state and no migration.
- **Open-time rollback-evidence check ([#1946](https://github.com/alphaonedev/ai-memory-mcp/issues/1946), A1).**
  `AI_MEMORY_REQUIRE_ROLLBACK_CHECK` (env-table row #124) gates a net-new
  `db::open`-time control that compares the surviving `signed_events` head
  against a witness-signed OFF-TABLE `head-anchor.log` high-water on the
  `AI_MEMORY_WITNESS_KEY_DIR` mount. Default `false` emits a signed
  `audit.rollback_evidence` forensic row + a loud WARN and CONTINUES the
  open (no self-DOS on a legitimate DR restore); truthy REFUSES the open
  fail-closed. Cleared by an operator-signed `audit restore-attest --sign`
  sanction — the only DR-vs-attack discriminator. Honest caveat: OSS build
  = tamper-EVIDENCE, not tamper-PROOF (an imaged-disk attacker who
  snapshots DB + anchor together wins; whole-host resistance needs TPM2
  NV / off-host anchor). Surfaced by `verify-audit-trail` on both backends.
  [#2370](https://github.com/alphaonedev/ai-memory-mcp/issues/2370) scoped
  the shared anchor log PER DATABASE via a signed v3 `db_id` (derived from
  the genesis `signed_events` row), so sibling databases on one witness
  mount no longer cross-refuse each other's opens under require-mode;
  legacy id-less v1/v2 anchor lines stay counted CONSERVATIVELY for one
  release, and the operator sanction record binds the database it clears.
  The open-time check + per-DB verdict filter are sqlite-side; the postgres
  `verify-audit-trail` check side keeps the conservative count-every-anchor
  posture pending [#2373](https://github.com/alphaonedev/ai-memory-mcp/issues/2373)
  (postgres EMISSION already stamps v3 `db_id` anchors).
- **Federated commit-checkpoint resolution signatures ([#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936), FED-RQ-01).**
  `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` (env-table row #125, default
  `1`) gates the inner per-resolution signature on inbound federated
  commit-checkpoint RESOLUTIONS — an authority-granting write (the
  separation-of-duties freeze anchor), so it shares the authority-lane
  fail-closed posture. An inbound resolution applies only when its
  Ed25519 signature verifies against the resolver's locally-enrolled key;
  application is idempotent under first-resolution-wins.
- **Cross-node governance policy-freshness gate ([#1947](https://github.com/alphaonedev/ai-memory-mcp/issues/1947), FED-RQ-03).**
  `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` (env-table row #132, default
  `1`) refuses an inbound federated push whose advertised
  `sender_policy_seq` is STRICTLY BEHIND the local committed governance
  policy with a typed `409 stale_policy_version` — a receive-path
  reject-before-apply that touches no `MemoryStore` checkpoint path
  (postgres-clean). Fail-closed means DETECTED-stale only: an absent /
  undeterminable epoch is fail-OPEN.
- **Route-IN quarantine of unattributed federated memories ([#1948](https://github.com/alphaonedev/ai-memory-mcp/issues/1948), R19/A3).**
  `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` (env-table row #123, default
  `false` / opt-in) stores an inbound relayed write that did not reach
  `attest_level=agent_attested` with the system-only
  `lifecycle_state=quarantined`, structurally hidden from every
  read/egress lane by the shared fail-CLOSED lifecycle allow-list. The
  bytes still converge (CRDT-safe) — only this node's LOCAL VIEW differs.
  Cleared via `dequarantine` (on-attest or operator).
- **Inference-plane egress gate ([#1963](https://github.com/alphaonedev/ai-memory-mcp/issues/1963), R68/D14).**
  `AI_MEMORY_INFERENCE_EGRESS` (env-table row #131, default `allow`) is a
  three-state egress class for LLM + API-embedder construction:
  `loopback-only` permits only localhost inference targets (local Ollama /
  self-hosted TEI) and refuses external-vendor egress; `deny` refuses ALL
  inference egress (keyword-only posture). Enforced at the boot
  chokepoints — on refuse the outbound client is not constructed, so no
  memory content can be POSTed to the refused vendor. A best-effort signed
  `egress.inference_refused` row records the class + non-secret target.
- **Power-loss durability knob + named `asi-hard` posture ([#1961](https://github.com/alphaonedev/ai-memory-mcp/issues/1961), R23/R7).**
  `AI_MEMORY_DB_SYNCHRONOUS` (env-table row #128, default `NORMAL`)
  exposes `PRAGMA synchronous` — `FULL`/`EXTRA` fsync the WAL at every
  commit so an acknowledged write survives a power cut. A fault-injection
  harness (`AI_MEMORY_TEST_ABORT_AFTER_COMMIT`, row #129) proves it.
  `AI_MEMORY_SECURITY_PROFILE=asi-hard` (env-table row #130) engages the
  hardened NO-DISABLE posture: at boot it PINS the fail-closed security
  knobs ON (including `DB_SYNCHRONOUS=FULL`) and REFUSES to boot if an
  operator set any pinned knob below its hard floor. An unrecognized token
  fails LOUD. The `asi-hard` config TEMPLATE (`docs/deploy/asi-hard.env`)
  sets `INFERENCE_EGRESS=loopback-only` explicitly; `asi-hard` never
  becomes a compiled default flip.
- **Erasure-coded archive cold tier ([#2064](https://github.com/alphaonedev/ai-memory-mcp/issues/2064), G16).**
  `AI_MEMORY_ERASURE_COLD_TIER` (env-table row #140, default `false` /
  opt-in) activates a redundancy layer for `archived_memories`: a
  paced sweep encodes each committed archived row into k data + m
  parity Reed-Solomon shards (`reed-solomon-simd`, operator-authorized
  per the #1830 vote), with per-shard + whole-payload SHA-256 gates.
  Any k of the k+m shards reconstruct the archived row; loss beyond
  the m budget FAILS LOUD, never silently returns wrong bytes. The
  archived DB row stays the durable source of truth — the shard
  bundles are DERIVED, regenerable redundancy, never the primary
  record. Purge/restore correctness rests on a durable write-ahead
  purge-intent journal written BEFORE each purge `DELETE`: a
  JOURNALED rowless bundle is confirmed-destroyed and reaped, while an
  UN-journaled rowless bundle (byte-indistinguishable from partial DB
  loss) is QUARANTINED — preserved and hidden from `get`/restore,
  NEVER destroyed, per the North Star "never cause unintentional data
  loss." Shard placement is SINGLE-NODE at v1.0.0 (see "Honest
  limits" below) — the no-primary multi-node placement is the tracked
  G16 residual.
- **Portability Spec v2 exporter + importer — SHIPPED ([#2006](https://github.com/alphaonedev/ai-memory-mcp/issues/2006)); `export` de-silenced ([#1944](https://github.com/alphaonedev/ai-memory-mcp/issues/1944)).**
  `ai-memory export --full` emits the full v2 envelope (`src/portability/emit.rs`):
  `spec_version="2"`, `db_schema_version`, and every §V2-2 signed array
  (`signed_events`, `memory_revisions`, `forget_tombstones`, `agent_lineage`,
  `model_attestations`, `governance_rules`, `trust_anchors`) byte-preserved,
  with a `conformance_level` (L1/L2/L3) COMPUTED from an in-export re-verify
  pass (a broken audit chain honestly downgrades to L1). A v2 envelope
  imports via `src/portability/import.rs::import_full_envelope`, which is
  **FAIL-CLOSED + ALL-OR-NOTHING** per PORTABILITY-V2 §V2-7: every class is
  staged inside ONE transaction, the imported audit spine is re-verified with
  `verify_audit_trail` BEFORE commit, and a malformed / tampered / truncated
  bundle (broken hash link, sequence gap, detected tail-truncation) is
  REJECTED with the transaction rolled back — a rejected bundle applies
  **ZERO rows** (never a partial apply); the importer NEVER re-signs.
  The **default** `ai-memory export` (no `--full`) remains the
  `memories + links` CONVENIENCE view and now announces that scope instead of
  silently omitting the tamper-evidence + governance spine: a stderr-only WARN
  (so a piped `export > corpus.json` stays valid JSON) plus additive in-band
  markers (`export_scope="memories+links"`, `portability_complete=false`,
  `excludes=[...]`). The standing forbidden-export-class discipline
  ([#1838](https://github.com/alphaonedev/ai-memory-mcp/issues/1838)) keeps
  signed classes out of the convenience view. The GA portability claim rests
  on Portability Spec v2 + `export --full` / the v2 importer + the CC0
  conformance corpus ([#1837](https://github.com/alphaonedev/ai-memory-mcp/issues/1837))
  + the two non-Rust readers + `ai-memory backup` (lossless SQLite
  `VACUUM INTO`, SQLite deployments only — it refuses a non-SQLite store
  rather than emitting an empty artifact,
  [#2444](https://github.com/alphaonedev/ai-memory-mcp/issues/2444))
  — NOT on the default `export`.

## Gate-3 evidence

Gate 3 is the endgame — ALL AI-NHI-conducted (operator correction
2026-07-09, memory `9a62049d`; there is NO third-party auditor, which
supersedes ROADMAP §11.6's "public security audit by named third-party
firm" line for this epic). ROADMAP §27 sequences it as a five-step
program:

1. **DigitalOcean full-spectrum testing + attestation.** The then-SSOT-pinned
   PG 18.4 + AGE 1.7.0 + pgvector 0.8.5 stack was exercised full-spectrum
   on DigitalOcean (the off-CI validation host — at the time this campaign
   ran, DO was the only place that exact triple had been exercised end to
   end; CI has since begun exercising the certified triple in-PR on
   `release/**` — now standardized to PG 18.6 / AGE 1.8.0 / pgvector 0.8.6
   (operator directive 2026-08-18) — runs `deploy/docker-1461/Dockerfile.pg-age-vector`
   built to the SSOT-pinned minors, and version-asserts the exact result — see
   §"Certified backend versions" for the current in-PR posture)
   and attested (this also covers the v0.9.0 4-phase
   ship-gate boundary per ROADMAP §17's recorded exception, ruling
   `wf_26d176ac` — the v0.9.0 record re-opens only if this campaign does
   not run).
2–3. **Multi-agent AI-NHI code review + security review.** A codegraph-anchored
   multi-agent code review and a multi-agent security review (security
   lenses) ran on the release branch under the 1:1-issue-per-finding
   discipline (every finding gets its own GitHub issue, never bundled;
   adversarially verified with retest + independent re-check, repeated
   until a round is clean). The round raised
   [#2014](https://github.com/alphaonedev/ai-memory-mcp/issues/2014)–[#2017](https://github.com/alphaonedev/ai-memory-mcp/issues/2017)
   and graded **none of them a GA-blocker**. Read the scope note below
   before treating that as a statement about the repository.
4. **100% fix + 100% track** (the ROADMAP §27 step this document
   previously skipped in its numbering). Every finding the two review
   lanes raised carried its own GitHub issue, was fixed, retested, and
   independently re-checked, with rounds repeated until one came back
   clean. **#2014–#2017 are all CLOSED** at the commit named below.
5. **Final AI-NHI dogfood — PASS.** The dogfood on the GA binary confirmed
   a **lossless v78 → v86 migration on a real corpus** (the additive
   crypto-core / lineage-custody / M-of-N-recovery ladder round-trips on
   live data), functional green, and a sound `verify-audit-trail` (the
   witness / cause-binding / role-separation / identity-lineage /
   rollback-evidence readouts resolve cleanly on both backends). **That
   dogfood covers v78 → v86 and nothing above it** — v87, v88 and v89
   landed afterwards on `release/v1.0.0` and are NOT covered by it. See
   §"Schema ladder v78 → v89".

### Scope of this attestation

As of commit **`0b5662ba`** on `release/v1.0.0`, the Gate-3 review round
described above closed with **0 GA-blockers in scope**, where *in scope*
means the findings raised by the two Gate-3 review lanes — the
multi-agent code review and the multi-agent security review — which are
enumerated as #2014–#2017 and are all closed.

**That is not a statement that the tracker is empty, and it must not be
read as one.** Counted on 2026-08-01 via
`gh api 'repos/alphaonedev/ai-memory-mcp/issues?state=open' --paginate`
with pull requests excluded: **175 open non-PR issues.** Open items
that touch claims in this document include
[#2613](https://github.com/alphaonedev/ai-memory-mcp/issues/2613) (the
AGE `find_paths` residual disclosed under §"Certified backend
versions"), plus
[#2400](https://github.com/alphaonedev/ai-memory-mcp/issues/2400),
[#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438),
[#2450](https://github.com/alphaonedev/ai-memory-mcp/issues/2450),
[#2492](https://github.com/alphaonedev/ai-memory-mcp/issues/2492) and
[#2629](https://github.com/alphaonedev/ai-memory-mcp/issues/2629). A
separate audit of this release's published claim surface is on the
branch at `docs/audit/3x7-claims-register-2026-08-01.md`; its
corrections are landing on the documents themselves, this one included.

**No tag has been cut.** `git tag -l 'v1.0.0*'` is empty at this commit
and the newest tag on the repository is `v0.10.0`. Nothing here
describes a completed release event; the tag cut remains
operator-gated, and the standing rule that it cannot cut with an open
Gate-3 finding is a rule about a future action, not a record of a past
one.

## Security review + code review

The post-feature work followed the established testing-loop discipline as
the Gate-3 endgame on the v1.0.0 release branch:

1. **Multi-agent codegraph-anchored code review (AI NHI)** — findings
   filed 1:1, no bundling.
2. **Every finding that round raised was closed in-release** — no
   deferrals, per the prime directive.
3. **Multi-agent security review (AI NHI, security lenses)** — findings
   filed 1:1, no bundling.
4. **Every finding that round raised was closed in-release.** The
   combined code + security findings are
   [#2014](https://github.com/alphaonedev/ai-memory-mcp/issues/2014)–[#2017](https://github.com/alphaonedev/ai-memory-mcp/issues/2017);
   all four are **CLOSED** at commit `0b5662ba`, and **none was graded a
   GA-blocker.**
5. **Final DO + AI-NHI dogfood 3-green**, then a **3×7 documentation
   drive** and a **docs-drift** sweep.

Each of those findings was fixed, retested, independently re-checked,
and closed in-release. The scope of that claim — and the count of what
is open on the tracker at this commit — is stated in §"Gate-3
evidence" → *Scope of this attestation*; it is bounded to the findings
those two review lanes raised, and no tag has been cut.

> The detailed per-issue write-ups for #2014–#2017 are tracked in the
> GitHub issues + the campaign memory rather than this document; they are
> summarized here for completeness and to record that both review lanes
> closed with zero GA-blockers among the findings they raised.

## Schema ladder v78 → v89

`CURRENT_SCHEMA_VERSION = 89` on both adapters
(`src/storage/migrations.rs:867`, `src/store/postgres.rs`); CLAUDE.md
§Database is the SSOT. Both adapters mirror via
`src/store/postgres.rs::{migrate_v79 … migrate_v89}`.

**The ladder is not uniformly additive, and this document previously
said it was.** v79–v85 are pure additive `ADD COLUMN` / `CREATE TABLE`
rungs. **v86 and v87 are DATA-MUTATING** — they issue `UPDATE`
statements against `memories` and `archived_memories`, rewriting the
stored rendering of existing rows. v88 is index-only (postgres-side
DDL; no row is touched). v89 redefines the postgres FTS `tsv` GENERATED
column (a `DROP COLUMN` + `ADD COLUMN` on a derived, regenerated column;
the durable `title`/`content`/`tags` TEXT is never touched). Both
mutating rungs are
instant/value-preserving, idempotent, and fail-safe on an unparseable
value (left byte-untouched rather than destroyed), but they are row
rewrites and are labelled as such below.

**Migration evidence, at its true bound.** The Gate-3 dogfood
(§"Gate-3 evidence" step 5) attested a lossless **v78 → v86**
round-trip on a real corpus. **v87, v88 and v89 are outside that
attestation** — all landed on `release/v1.0.0` after the dogfood ran.
They are covered by their own regression tests, not by a
real-corpus dogfood. Per the North Star, data-integrity evidence is
under-claimed rather than stretched: if you are upgrading a populated
database across v86 → v89, take a backup first (`ai-memory backup`).
The sqlite ladder additionally writes its own pre-migration
`VACUUM INTO` snapshot beside the database file on any `version > 0`
upgrade, before any schema mutation
(`src/storage/migrations.rs:1562`).

| Schema | Change |
|---|---|
| v79 | crypto-core stage 2 — additive `memories.kind_provenance` ([#1945](https://github.com/alphaonedev/ai-memory-mcp/issues/1945)) + claim-bitemporal `valid_from` / `valid_until` ([#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834)) + the `agent_subkey_certs` SubkeyCert table ([#1942](https://github.com/alphaonedev/ai-memory-mcp/issues/1942)); purely additive, no full-table rebuild |
| v80 | lineage-custody + revocation — additive `agent_lineage.custody_class` + `suspected_compromise_from_seq`, `reason` CHECK widened to admit `revocation` ([#1949](https://github.com/alphaonedev/ai-memory-mcp/issues/1949)) |
| v81 | M-of-N recovery-quorum — additive recovery-only `agent_lineage.guardian_set_id` + `recovery_threshold`, committed inside the signed CBOR body ([#1831](https://github.com/alphaonedev/ai-memory-mcp/issues/1831), G17) |
| v82 | operator-authorized skill retire/unretire — additive `skills.retired_at` / `retired_by` / `retire_reason` (sqlite-only; postgres ships no skills table so `migrate_v82` is a version-stamp no-op) ([#2024](https://github.com/alphaonedev/ai-memory-mcp/issues/2024)) |
| v83 | per-agent HTTP API-key principal binding — additive `agent_api_keys` table (`sha256(token) → agent_id`, both backends) backing the H1 IDOR + M1 admin-spoof fix ([#2044](https://github.com/alphaonedev/ai-memory-mcp/issues/2044) / #2032-A) |
| v84 | per-row embedding-space provenance — additive `embedding_space` column on `memories` + `archived_memories` (both backends) so recall never scores a vector from a different embedding space after a same-dim model swap ([#2167](https://github.com/alphaonedev/ai-memory-mcp/issues/2167)) |
| v85 | archive claim-validity parity — additive `valid_from` / `valid_until` on `archived_memories` (both backends), closing the archive→restore data-loss where the #1834 claim-validity interval was dropped on the round-trip ([#2035](https://github.com/alphaonedev/ai-memory-mcp/issues/2035)) |
| v86 | claim-bitemporal valid-time canonicalization — **DATA-MUTATING** (unlike every other v79-v85 rung, which is a pure additive `ADD COLUMN`): every stored `valid_from`/`valid_until` TEXT rendering on `memories` + `archived_memories` is REWRITTEN to the ONE fixed-UTC form `YYYY-MM-DDTHH:MM:SS.ffffffZ` (`validate::canonicalize_valid_time`), so the #1834 predicates' lexicographic TEXT comparison is exactly instant comparison — RFC3339's many equal-instant renderings (`Z` vs `+00:00`, variable fractional digits, non-UTC offsets) previously ordered WRONGLY as bytes, silently violating the start-inclusive/end-exclusive contract. The rewrite is INSTANT-PRESERVING (only the byte rendering changes, never the represented moment), idempotent (safe to re-run), and fail-safe (an unparseable value is left byte-untouched rather than destroyed) on both backends ([#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834) pre-ship 3x7) |
| v87 | archived `kind_provenance` parity + expiry-rendering heal — **DATA-MUTATING** (the second such rung; the first is v86). Additive half: `archived_memories.kind_provenance` on BOTH backends, the third v79/#1945 column finally mirrored onto the archive (its two siblings landed at v85), carried through every sqlite archive `INSERT…SELECT` + both `restore_archived*` lists, with legacy pre-v87 archive rows re-deriving it vocab-guarded from the metadata carrier ([#2333](https://github.com/alphaonedev/ai-memory-mcp/issues/2333), FBL-03). **Row-rewriting half (sqlite only):** `normalize_expiry_rows` applies the v86 canonicalization recipe to the expiry columns, whose predicates also compare lexicographically — `UPDATE memories SET expires_at = ?1 WHERE rowid = ?2` over every non-NULL `memories.expires_at`, plus the same over `archived_memories.expires_at` and, when the column is present, `archived_memories.original_expires_at` ([#2332](https://github.com/alphaonedev/ai-memory-mcp/issues/2332), FBL-02; `src/storage/migrations.rs`, the `if version < 87` arm). Postgres needs no heal — its `expires_at` is `TIMESTAMPTZ`, not TEXT — so `migrate_v87` is the additive half only. Same guarantees as v86: instant-preserving, idempotent, fail-safe on an unparseable value |
| v88 | postgres composite list/archive ordering indexes — **index-only, no row is read or rewritten** ([#2578](https://github.com/alphaonedev/ai-memory-mcp/issues/2578)). `migrate_v56()` had been recorded as a postgres version-stamp no-op, so the three composite ordering indexes SQLite has carried since v56 were never built on postgres and a namespace-scoped `list` read the whole namespace and sorted it. v88 is postgres catching up; the SQLite v88 arm is a version-stamp no-op so both adapters keep ONE logical schema number. The DDL runs `CREATE INDEX CONCURRENTLY` on a dedicated connection outside any transaction with `lock_timeout` cleared and a bounded `statement_timeout` — a plain in-transaction `CREATE INDEX` is a fleet-wide boot brick (reproduced live: `canceling statement due to lock timeout` at 5.002 s against a table with one ordinary uncommitted writer, on a small table as readily as a large one). It is **FAIL-OPEN**: these indexes are derived, disposable, non-UNIQUE artifacts regenerable from the durable text, so a build failure DEGRADES to today's query plan and the version stamps regardless — refusing to boot a fleet over a missing performance index would trade total availability for zero integrity. Because the stamp means the arm never re-runs, `connect_*` re-probes `indisvalid` on EVERY connect and rebuilds anything missing or left INVALID, so a node that lost one build self-heals instead of staying silently un-indexed |
| v89 | postgres FTS `tags` fold — cross-backend determinism fix ([#2392](https://github.com/alphaonedev/ai-memory-mcp/issues/2392); 5-agent vote `4d3ea1c5`). SQLite's `memories_fts` FTS5 table has always indexed `(title, content, tags)`, but the postgres stored generated `tsv` tsvector (v57) folded only `title + content`, so a tag-only-hit search / recall / contradiction returned the row on SQLite but ZERO rows on the enterprise (postgres) tier. `migrate_v89` redefines the generated column to fold `coalesce(tags::text, '')` — the generated-column-LEGAL fold (a GENERATED column bars `jsonb_array_elements_text`; the immutable `jsonb -> text` cast's JSON punctuation tokenizes away, leaving the array elements as lexemes under the same `'english'` config already applied to title + content) — and every `tsv`-reading path (search / recall / contradiction / list) is fixed uniformly. PG16 has no `ALTER COLUMN ... SET EXPRESSION`, so the arm is `DROP COLUMN IF EXISTS tsv` (cascades away `memories_tsv_gin`) + `ADD COLUMN tsv ... GENERATED ... STORED` + recreate the GIN, one transaction on the pooled connection retaining `lock_timeout` (the ACCESS EXCLUSIVE STORED-generated rewrite cannot be `CONCURRENTLY`, so it fails CLOSED under contention — DEGRADE to fewer tag results, never a wrong result). The SQLite v89 arm is a version-stamp no-op (FTS5 already indexes tags), so both adapters keep ONE logical schema number. `tsv` is derived data regenerated from the durable text |

## Honest limits

v1.0.0's tamper-evidence, attestation, and durability controls are
real but scoped — this section states the residual bounds honestly
rather than overclaiming, per the North Star (degrade, never corrupt
or overclaim).

- **Tamper-evidence bounds (interior-rewrite residual).** The
  `signed_events` cross-row hash chain plus the #1850 forensic
  watermark and the #1873/#2202 head-hash anchor detect **tail
  truncation** and a **same-length whole-suffix rewrite at or above
  the anchored sequence** on both backends. They do NOT bind an
  **interior / mid-suffix rewrite BELOW the anchored row** — the
  head-hash anchor's `canonical_chain_bytes` deliberately excludes
  `prev_hash`, so it commits only to the anchored row, not the whole
  prefix — nor the up-to-`WATERMARK_INTERVAL`−1 (=63) un-anchored
  rows above the last watermark. See `CLAUDE.md`'s `signed_events`
  paragraph for the full residual-2 scoping; the off-host
  `AI_MEMORY_LOG_SINK=syslog` tier (or a future rolling/accumulator
  hash committing the whole prefix) is the residual-closing control
  for a hostile host.
- **Rollback check is ESTIMABLE, not ATTESTABLE.** The open-time
  rollback-evidence check (`AI_MEMORY_REQUIRE_ROLLBACK_CHECK`, row
  #124) compares the surviving `signed_events` head against a
  witness-signed off-table high-water mark — tamper-EVIDENCE, not
  tamper-PROOF. An attacker who images the DB file and the anchor
  file TOGETHER (a whole-host snapshot-and-restore) evades detection;
  whole-host resistance needs a TPM2 NV counter or a genuinely
  off-host anchor, both out of scope for the OSS build at v1.0.0.
  Two [#2370](https://github.com/alphaonedev/ai-memory-mcp/issues/2370)
  per-database-scoping residuals share that boundary: (i)
  **wipe-and-reinit `db_id` rotation** — replacing the database with a
  re-initialised chain mints a NEW genesis identity that matches no
  existing anchor, resolving a clean `NotApplicable` open instead of
  `Evidence` (same imaged-disk-class attacker; a wipe-to-EMPTY without
  re-init is still caught as Evidence); (ii) **mixed-version fleet
  freeze** — a v3 anchor writer paired with a pre-#2370 reader (which
  hard-rejects `v: 3` resolutions) freezes that old reader's high-water
  at the last v1/v2 line, so it WITHHOLDS rather than detects newer
  rollbacks until upgraded (one-release conservatism: old readers never
  mint a FALSE verdict, and the new reader still counts legacy id-less
  lines toward Evidence).
- **Claimed-vs-attested identity and diversity.** `metadata.agent_id`
  and the reflection-decorrelation probe's model-family signal are
  CLAIMED (self-asserted by the caller) unless independently attested
  via the `model_attestations` substrate or an enrolled Ed25519 key.
  The decorrelation probe's `advisory` default (row #92) computes
  dominance over CLAIMED producer signals and says so explicitly in
  its WARN text; `enforce` stays RESERVED because a refusal on
  CLAIMED-only distinctness would be security theater — the
  write-time quorum gate (row #120) refuses ONLY on evidence-backed
  ATTESTED monoculture, never on a claimed-only corpus.
- **Loader-attestation coverage caps at ~40%.** The `model_attestations`
  table (schema v78) is TOFU write-once and populated at the LLM-client
  construction boundary (`loader_observed`) or by explicit operator
  enrollment (`operator_signed`); only substrate-invoked generation is
  attestable, so loader-observed coverage of a corpus's actual model
  provenance hard-caps at roughly 40% (ROADMAP.md §24) — external or
  pre-substrate content is never retroactively attested.
- **Erasure cold tier is single-node at v1.0.0.** The #2064 archive
  cold-tier redundancy layer places its Reed-Solomon shard bundles on
  the SAME host as the primary database (see the erasure cold-tier
  bullet under "Additive surfaces"); it protects against local
  disk/file corruption and partial data loss on that host, NOT against
  a whole-host loss. Multi-node shard placement is a tracked residual
  (`DurabilityModel::ErasureCodedColdTier.is_multi_node() == false`,
  G16 residual) deferred past v1.0.0.
{% endraw %}
