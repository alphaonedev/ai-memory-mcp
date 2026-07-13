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
AGE + pgvector storage backend on a pinned, live-tested stack.

The "defaults stop lying" lane (Gate 1′) is the centerpiece: six knobs
that shipped OFF (or non-functional) through v0.10.0 now resolve to their
secure posture by default, each riding the one-cycle deprecation-WARN
discipline the v0.10.0 `warn-carrier` release delivered. The release also
advances the schema **v78 → v81** (all additive), adds an M-of-N
threshold key-recovery lane, human-key-signed m-of-n approvals, an
open-time rollback-evidence check, an inference-plane egress gate, and a
named `asi-hard` no-disable security posture.

**Surface at v1.0.0** (SSOT: `src/lib.rs` `EXPECTED_*` consts +
`src/profile.rs`; the tool/route/CLI counts carry forward unchanged from
v0.9.0 — v1.0.0's growth is env-knob + schema surface, not new
tools/routes/subcommands):

| Surface | v1.0.0 |
|---|---|
| MCP tools (`--profile full`) | **101 advertised** (100 callable + the always-on `memory_capabilities` bootstrap) |
| MCP tools (`--profile core`) | **7** (original 5 + `memory_load_family` + `memory_smart_load`) + the `memory_capabilities` bootstrap |
| HTTP routes | **92 production `.route(...)` registrations** / 78 unique URL paths |
| CLI subcommands | **87 default build** / **89 under `--features sal`** (the `capability init` sub-verb rides the existing `Capability` command, so the top-level count is unchanged) |
| `MemoryKind` variants | **16** (adds v1.0.0 epistemic typing `Told` / `Instruction` / `Intervention`, [#1945](https://github.com/alphaonedev/ai-memory-mcp/issues/1945)) |
| Schema | **v81** (`CURRENT_SCHEMA_VERSION`, both adapters) |

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

v1.0.0 is **certified on PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector
0.8.5** (the pgvector Rust binding is the `pgvector` crate `0.4`,
`features = ["sqlx"]`). These are the current-stable upstream versions;
Apache AGE 1.8.0 exists only as `rc0` and is deliberately NOT shipped —
the certified stack pins the released `release_PG18_1.7.0` line.

The single source of truth for the pinned versions is
`deploy/docker-1461/provision/lib.sh` (`EXPECTED_PG_VERSION=18.4`,
`EXPECTED_AGE_VERSION=1.7.0`, `PGVECTOR_APT_VERSION=0.8.5-1.pgdg13+1`,
`AGE_BASE_IMAGE=apache/age:release_PG18_1.7.0`). The certified stack was
tested live: the AGE-gated Cypher/KG suites (`age_cte_equivalence`,
`g2_postgres_find_paths_age_param_binding`,
`g4_postgres_link_projects_into_age_graph`, `cov_postgres_kg`,
`issue_1482_age_cypher_persistent`, `kg_age_fallback`) and the
pgvector-backed recall-purity suite (`recall_purity_p01_postgres`) all
pass on it under `--features sal,sal-postgres --include-ignored`.

The stack is now gated **nightly** by the `postgres-age` CI job
(`.github/workflows/postgres-parity-nightly.yml`, [#2012](https://github.com/alphaonedev/ai-memory-mcp/issues/2012)),
which builds the SSOT-pinned image, **fail-closed asserts** the live
`server_version` / `age` extversion / `vector` extversion equal the pins
before any test runs, then runs the AGE + pgvector suites against the
live certified stack. This closes the gap that AGE-gated Cypher and the
vector path could only be exercised on an operator's own machine.

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
- **`ai-memory export` de-silenced — convenience view, not portability ([#1944](https://github.com/alphaonedev/ai-memory-mcp/issues/1944)).**
  The JSON `export` command now announces its `memories + links`
  convenience scope instead of silently omitting the tamper-evidence +
  governance spine: a stderr-only WARN (so a piped `export > corpus.json`
  stays valid JSON) plus additive in-band markers
  (`export_scope="memories+links"`, `portability_complete=false`,
  `excludes=[...]`). It directs to `ai-memory backup` (lossless SQLite
  `VACUUM INTO`) for integrity-preserving portability and
  `export-forensic-bundle` for the signed crypto spine; the standing
  forbidden-export-class discipline ([#1838](https://github.com/alphaonedev/ai-memory-mcp/issues/1838))
  keeps signed classes out of the convenience view. The GA portability
  claim rests on Portability Spec v2 + the CC0 conformance corpus
  ([#1837](https://github.com/alphaonedev/ai-memory-mcp/issues/1837)) +
  `ai-memory backup`, not on `export`.

## Gate-3 evidence

Gate 3 is the endgame — ALL AI-NHI-conducted (operator correction
2026-07-09, memory `9a62049d`; there is NO third-party auditor, which
supersedes ROADMAP §11.6's "public security audit by named third-party
firm" line for this epic). It ran as a five-step program:

1. **DigitalOcean full-spectrum testing + attestation.** The certified
   PG 18.4 + AGE 1.7.0 + pgvector 0.8.5 stack was exercised full-spectrum
   on DigitalOcean and attested (this also covers the v0.9.0 4-phase
   ship-gate boundary per ROADMAP §17's recorded exception, ruling
   `wf_26d176ac` — the v0.9.0 record re-opens only if this campaign does
   not run).
2–3. **Multi-agent AI-NHI code review + security review.** A codegraph-anchored
   multi-agent code review and a multi-agent security review (security
   lenses) ran on the release branch under the 1:1-issue-per-finding
   discipline (every finding gets its own GitHub issue, never bundled;
   adversarially verified with retest + independent re-check, repeated
   until a round is clean). The reviews surfaced **0 GA-blockers**; the
   findings raised ([#2014](https://github.com/alphaonedev/ai-memory-mcp/issues/2014)–[#2017](https://github.com/alphaonedev/ai-memory-mcp/issues/2017))
   were all fixed in-release per the prime directive (no deferrals).
5. **Final AI-NHI dogfood — PASS.** The dogfood on the GA binary confirmed
   a **lossless v78 → v81 migration on a real corpus** (the additive
   crypto-core / lineage-custody / M-of-N-recovery ladder round-trips on
   live data), functional green, and a sound `verify-audit-trail` (the
   witness / cause-binding / role-separation / identity-lineage /
   rollback-evidence readouts resolve cleanly on both backends).

The tag cannot cut with any Gate-3 finding open; the loop closed green
before the (operator-gated) tag cut.

## Security review + code review

The post-feature work followed the established testing-loop discipline as
the Gate-3 endgame on the v1.0.0 release branch:

1. **Multi-agent codegraph-anchored code review (AI NHI)** — findings
   filed 1:1, no bundling.
2. **Fixed 100%** — every code-review finding closed in-release.
3. **Multi-agent security review (AI NHI, security lenses)** — findings
   filed 1:1, no bundling.
4. **Fixed 100%** — every security finding closed in-release; the
   combined code + security findings ([#2014](https://github.com/alphaonedev/ai-memory-mcp/issues/2014)–[#2017](https://github.com/alphaonedev/ai-memory-mcp/issues/2017))
   produced **0 GA-blockers**, all triaged legit and fixed.
5. **Final DO + AI-NHI dogfood 3-green**, then a **3×7 documentation
   drive** and a **docs-drift** sweep.

Each finding was fixed, retested, independently re-checked, and closed
in-release per the prime directive. The review/validation loop closed
green before the (operator-gated) tag cut.

> The detailed per-issue write-ups for #2014–#2017 are tracked in the
> GitHub issues + the campaign memory rather than this document; they are
> summarized here for completeness and to record that both review lanes
> closed green with zero GA-blockers.

## Schema ladder v78 → v81

All additive (CLAUDE.md §Database is the SSOT). Both adapters mirror via
`src/store/postgres.rs::{migrate_v79 … migrate_v81}`; the v78→v81 ladder
round-trips losslessly on a real corpus (Gate-3 dogfood).

| Schema | Change |
|---|---|
| v79 | crypto-core stage 2 — additive `memories.kind_provenance` ([#1945](https://github.com/alphaonedev/ai-memory-mcp/issues/1945)) + claim-bitemporal `valid_from` / `valid_until` ([#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834)) + the `agent_subkey_certs` SubkeyCert table ([#1942](https://github.com/alphaonedev/ai-memory-mcp/issues/1942)); purely additive, no full-table rebuild |
| v80 | lineage-custody + revocation — additive `agent_lineage.custody_class` + `suspected_compromise_from_seq`, `reason` CHECK widened to admit `revocation` ([#1949](https://github.com/alphaonedev/ai-memory-mcp/issues/1949)) |
| v81 | M-of-N recovery-quorum — additive recovery-only `agent_lineage.guardian_set_id` + `recovery_threshold`, committed inside the signed CBOR body ([#1831](https://github.com/alphaonedev/ai-memory-mcp/issues/1831), G17) |
{% endraw %}
</content>
</invoke>
