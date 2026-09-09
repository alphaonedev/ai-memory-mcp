# ai-memory v1.0.0 — Mission-Critical Certification Standard (v1)

**Author:** Claude Fable 5.1 (Conductor, sole merger of `release/v1.0.0`)
**Date:** 2026-09-09 (revision 4.2: freeze line recorded in §6 and §7)
**Status:** NORMATIVE for the v1.0.0 certification decision. Supersedes Phase 6
("release and adoption decision") of `GPT-6-ASTRA-AI-NHI-TEST-PLAN-2026-09-05.md` and
prepends a scope-and-envelope section that plan lacked. Phases 1–5 of that plan remain
the execution method; this document is the standard the evidence must meet.
**Companion:** `FABLE-5.1-FULL-SPECTRUM-AUDIT-OF-GPT-6-ASTRA-2026-09-09.md` (the verified
findings this standard is built from; its N-/V- ids are the work-item ids used below).

## 0. What this standard certifies

A certificate under this standard says one thing: *inside the declared envelope, an
agent cluster, swarm or hive can bet a business-critical or mission-critical process on
ai-memory v1.0.0, and every published number behind that statement can be recomputed
from an immutable artifact bound to the exact binary that was tested.*

Binding means: the daemon reports `binary_sha256` (SHA-256 of its own executable,
computed at boot) and `source_commit` on `/api/v1/capabilities` (added under item 3b;
neither exists today), and the harness independently records the SHA-256 of the
executable of the process it addressed (`/proc/<pid>/exe` or the platform equivalent).
Harness-side and daemon-reported hashes must both equal the bundle's
`daemon_binary_sha256`, and `source_commit` must equal the bundle's. A hash typed by
hand is not a binding.

It does not say the product is good, fast or novel. Those are claims for benchmarks,
not certificates.

### 0.1 Declared envelope

A certificate is void outside its envelope. The envelope enumerates:

| Axis | Declared values (v1.0.0 candidate) |
|---|---|
| Backends | SQLite (bundled, WAL) with `PRAGMA synchronous=FULL` — **not the compiled default**, which is `NORMAL` (`src/storage/connection.rs:558`, the documented #1579 B7 posture); the certified posture requires `AI_MEMORY_DB_SYNCHRONOUS=FULL` or the `asi-hard` profile, `ai-memory doctor --posture` attests it (N26), and a `NORMAL` node is inside the envelope only under the `local-only` durability class with its RPO declared accordingly · PostgreSQL 18.6 + Apache AGE 1.8.0 (apt package `1.8.0~rc0`, extension version 1.8.0) + pgvector 0.8.6; pins are the package SHA-256s mirrored in the bundle, the apt strings are informational |
| Feature builds | exactly the Cargo feature sets certified: `default` (sqlite-bundled) · `sal` · `sal-postgres` (implies `sal`) · `vectorlite`. The CI lane named `enterprise-fed` is `sal-postgres` run against the certified PG/AGE/pgvector pins; it is not a Cargo feature |
| Transports and principals | HTTP with per-agent enrolled keys is the only **multi-principal** transport. MCP over stdio resolves its caller from the launcher's `AI_MEMORY_AGENT_ID` environment (`src/identity/mod.rs:470-497`; absent → single-tenant trust-all) and is certified as a **single trust domain**: one launcher, one principal. A swarm of N agents is certifiable only over HTTP, or over stdio when an orchestrator provably controls each child's environment and is itself the certified principal |
| Hosts / adapters | an adapter contract with a tested version **range** per host, recorded in the N4 matrix; `ai-memory doctor --host <name>` (new, item 21) runs the wrapper self-test on the installed node; a node outside the range is NOT CERTIFIED for that host |
| Topologies | `single` · `swarm(1 region, N agents, 1 data tier)` · `hive(K regions federated, W-of-N)` with measured K, N, W. A region is an independently failing power and network domain, declared with its blast radius; the region of every data tier is declared (data residency) |
| Postures | each hardening / at-rest profile with its generated allowed/refused operation matrix |
| External processors | every embedding and LLM provider in use, with region and data flow; a provider not listed is NOT CERTIFIED |
| SDKs in scope | Python (`sdk/python`) and the two Python shims. The Swift and Kotlin mobile SDKs are NOT CERTIFIED |

**NOT CERTIFIED (permanent for v1.0.0; the buyer accepts these):** FIPS 140-3 validated
cryptography (Rust `rustls` / `ed25519-dalek`-class crates are not validated) · exactly-once
external business effects · erasure from offline historical backups · multi-principal
identity on MCP stdio (above) · `ai-memory wrap codex` on Codex CLI ≥ 0.153 (use native
MCP; N4) · hook lifecycle events other than those with a production fire site (#3126:
11 of 22 advertised events never fire) · agent-action rule enforcement on the live hive
(#3032: advertised by `/capabilities`, inert) · `memory_load_family` / `memory_smart_load`
quality on an organically grown corpus (#3028) · a configuration-bounded recall p99 on
the local candle embedder (#3026: the embed latency budget is inert there) · complete
portable export (`PORTABILITY_COMPLETE = false`, `src/export_scope.rs:39`) · any
relevance or LongMemEval advantage claim until #2437 lands · cross-backend semantic
parity on `set_row_metadata`, `list_archived` tag shapes and tombstoned-root lineage
(#3187, #3186, #3305) · sustained single-author write rates above the
`AI_MEMORY_MAX_MEMORIES_PER_DAY` default (#2930; an envelope axis) · PostgreSQL routes that are fail-closed 501 by design (#2803: 21 paths including
`/api/v1/skill/*`, `share`, `atomise`, `smart_load`, `export_reflection`, `replay`) · CLI
write verbs and MCP stdio against a PostgreSQL store (#2803) · per-(agent, namespace)
quotas on PostgreSQL (#3209) · hosted MCP transport (#2788) · PostgreSQL row-level
tenant isolation (#2647) · mobile SDK surface · any "regression vs baseline" performance
claim until `performance/baseline.json` is regenerated (#3162).

**NOT YET EVIDENCED (blocks issuance while any gate depends on it):** 24 h / 72 h soak
(G5) · CONFIG-2 and E3 on the certified pins (G4) · real power-cut fsync honesty
(N20) · coordination-plane retention (#3011: signals, actions, checkpoints and routine
runs are never pruned, so G5's growth budget cannot be met for those tables) · catch-up
pacing and boot-path index builds (#2671, #2631; §0.5) · vendor-independent assessment
(§4).

### 0.2 Declared SLO / RPO / RTO

Declared before testing, in a file whose SHA-256 is the first record of every run; a run
whose `envelope_ref` hash differs from the pre-registered hash is `FAIL`. Never revised
after a miss.

| Field | How it is measured | Miss disposition |
|---|---|---|
| Read p50 / p95 / p99 per workload class and backend | pooled raw samples; never an average of per-run p99s | FAIL of G5 |
| Signed write-ack p99 (with embedding) | same | FAIL of G5 |
| RPO per durability class: `local-only` · `quorum W-of-N` · `replicated+backup` | every write receipt carries `durability_class` (N29; today no receipt does); loss = acknowledged op-ids missing from recovered state **inside the receipt's declared class**, verified by a harness-side digest of the bytes sent compared against a read through a different surface, never by HTTP 200 alone | any loss inside the declared class = CERT-VOID; loss outside it is published as exposure, never upgraded |
| RTO = clock 3 (mission hydrated into a NEW harness-owned reference agent) | five-clock table §0.3; clocks 4 and 5 are published with their `model_case` record and are not the RTO | FAIL of G2/G4 |
| Unauthorized effects | independent oracle whose diff set is every write funnel in the generated §2 inventory, not a hand list | any = CERT-VOID |
| Correction reachability (memory side): after a correction the corrected row is top-1 for the original query | held-out oracle | FAIL of G3 |
| Correction adoption (model side) | benchmark (V2); reported, not certified | — |
| Maintenance growth / cost ceiling per 24 h per 10⁶ rows | budget declared here before the first ramp | FAIL of G5 even when foreground passes |

### 0.3 The five clocks

1. daemon restarted to health `ok` · 2. storage and retrieval ready · 3. mission
hydrated into a NEW agent · 4. first correct resumed action · 5. mission complete with
external-effect reconciliation.

What the existing harness measures: `.local-runs/continuity-cycle.py` publishes
`resume_ms` = 500 ms deliberate sleep (`:91`) + loader drain + process start + time to
health 200; its `health_ok_ms` (329–382 ms in the 2026-09-01 artifact) is the honest
clock-1 number and the dashboard publishes the larger one. Its `embedder_ready` wait is
vacuous because the daemon's `embedder_ready` is a boot-time constant
(`src/handlers/transport.rs:1267`). Corrections: historical figures are relabelled
`clock_1_harness_restart_to_health_ok_ms`; clock 2 is `NOT_MEASURED` (the recall probe is
untimed); clocks 3–5 are measured with a harness-owned scripted reference agent and a
mock external-effect sink, without a real host; a real host is required only for G2's
per-host claim.

### 0.4 Data-integrity supremacy clause

Any observed unintentional data loss, corruption, silent mixed state (a single logical
request persisted partially and reported as an error or a success; #3152 is an open
instance and is pulled to GA as N28), irreversible destructive operation without a
fail-closed refusal or an explicit operator confirmation token, a receipt whose
durability class was silently upgraded, or a read surface that reports different
`version` / `cid` / `confidence_source` for the same row id on the same node than another
read surface (the #3404 class; the N2 parity test is the detector; share/import restamps
across nodes are legitimate per ADR-001) is a **CERT-VOID** event. It outranks a full
green board. Memory text, the audit/attestation spine, the governance sidecar, key
epochs and policy versions are the source-of-truth class; vectors, AGE projections and
indices are disposable and their loss is a repair item.

### 0.5 Fleet-manageability clause

For v1.0.0 the clause covers GC, consolidation and re-embed: each must be pace-able,
resumable and non-synchronised across the fleet. Federation catch-up pacing (#2671) and
boot-path index builds under a cluster-wide lock (#2631) are NOT YET EVIDENCED and are
listed in §0.1. A certificate may issue with them open only when the envelope declares
federation catch-up and boot-time migrations as operator-serialised (one node at a
time); a `hive(K)` envelope without that declaration fails G4.

### 0.6 Threat model

Every gate names which of these adversaries it covers: a malicious co-tenant agent
(HTTP with its own enrolled key; stdio within the single trust domain); a compromised
launcher process (stdio); a network adversary on the federation link; a writer with
access to the backup directory; a malicious or mistaken administrator; a poisoned or
stale memory acted on by a downstream agent. Adversaries outside this list (hypervisor,
hardware, supply chain below the SBOM) are out of scope and stated as such.

## 1. Evidence schema (normative)

One JSON-lines record per case per run.

```
artifact_kind (daemon | test_binary)
run_id, supersedes_run_id (nullable), started_at_utc, finished_at_utc
source_commit, source_tree_sha, dirty_patch_sha256 (nullable)
daemon_binary_sha256 | test_binary_sha256, daemon_features[], cargo_lock_sha256
adapter_version, host_version, sdk_version        # NOT_APPLICABLE for test_binary rows
config_redacted_sha256                            # from `ai-memory config show --redacted --canonical` (N7)
identity_posture, posture_profile
storage{backend, postgres, age, pgvector, schema_version}
workload{kind, concurrency, duration_seconds, corpus_rows, vector_dim}
clock_source{ntp_synced, offset_ms}               # per node
envelope_ref, envelope_sha256                     # the pre-registered §0 declaration
cell, principal, case_id, dimension, expected, observed   # NOT_APPLICABLE where the inventory says so
status, attempts, invocation_argv_sha256, evidence_refs[]
oracle_kind (independent | self-report | not-applicable)
declared_durability_class, verdict_signed_by      # for any PASS row a gate relies on: a key in reviewer_keys held by a
                                                  # principal independent of the vendor; the daemon identity key may sign
                                                  # only self-report rows; the bundle manifest is countersigned by the wave-3 reviewer
model_case{requested_model, served_model, provider_response_meta, system_prompt_sha256,
           tool_schema_sha256, token_budget, tool_call_budget, inference_ms, tool_call_trace}
                                                  # required when the case is agent-driven
```

Statuses form a closed set: `PASS` · `PASS_ON_RETRY` · `EXPECTED_REFUSAL` · `FAIL` ·
`BLOCKED{reason}` · `SKIPPED` · `NOT_APPLICABLE`.

* **Independent** means: the observation is made through a surface other than the one
  whose return value is under test (a second read path, a direct storage read, a
  filesystem or process observation) by code that does not share the mutation's success
  path. Suites are classified in a checked-in allowlist; a suite claimed independent must
  carry a G7-style mutation proof. Under this definition the existing guard suites are
  independent; a handler's own "updated" is not.
* `PASS` requires `oracle_kind == independent` and `attempts == 1`. A pass on a later
  attempt under a predeclared retry policy is `PASS_ON_RETRY`, in its own denominator.
* `EXPECTED_REFUSAL` requires an allow-listed status code AND a zero durable-mutation
  delta over the declared side-effect set (the documented read side effects of N10 are
  excluded), and is published in its own denominator.
* `BLOCKED{reason: infra}` is permitted for load-sensitive cases on a shared host; more
  than 2 % of required cases blocked-infra blocks issuance. `SKIPPED` and `BLOCKED` are
  published in their own denominator; any required case `BLOCKED` for a non-infra reason
  is not issuable.
* A leg's executed test count must equal `cargo test -- --list` under the claimed
  features and be no lower than the count at the previous certification (ratchet). A
  suite that reports `running 0 tests` is `NOT_APPLICABLE`, never `PASS`.
* The verdict is a schema-validated field, checked by `scripts/check-evidence-bundle.sh`
  (N7). Parsing prose for verdicts is prohibited. Disagreement between summary,
  denominator and raw case statuses is a `FAIL` of the bundle itself.

## 2. Surface inventory (generated, never hand-written)

Before Phase 1, one command emits, from the tested build: every MCP tool from
`tools/list` (the existing `tool-count-drift.yml` is a partial producer), every HTTP
route with its backend support, every CLI verb, every in-scope SDK method, every storage
write funnel (SQLite and PostgreSQL), each flagged `mutating` or not. Dimension
applicability derives from that flag. A gate fails the run if any entry lacks either a
case row or a declared unsupported boundary; boundary declarations are not permitted on
write funnels or destructive operations and their count is published as its own
denominator. `sdk/python/swarm/coverage.py` already performs the manifest × live
cross-check for MCP tools; the inventory extends it.

## 3. Gates that must be green per release artifact

Each gate binds to `daemon_binary_sha256` as defined in §0.

| # | Gate | Bound artifact |
|---|---|---|
| G1 | **Atomic conformance.** Principals A (owner), B (grantee), C (bystander), D (unenrolled), O (admin), revoked key, old key valid at historical write time, per-namespace peer — on the HTTP transport; on stdio the single-principal cases only. Identity, Scope, Revision and Replay on every mutating operation; the remaining six dimensions on every write funnel and destructive operation. | surface manifest + case ledger |
| G2 | **Real-agent continuation per advertised host.** Clock 3 (and 4 where the host exposes a first action) with a real host for every row of the N4 matrix; a host without a run moves to NOT CERTIFIED. | per-host trace bundle |
| G3 | **Correction reachability and poisoned memory** under the declared threat model, n ≥ 30 per mission with a preregistered pass threshold. Produced at GA by the two-mission subset (item 22a). | oracle results |
| G4 | **Native recovery and federation at the declared topology.** E1/E2 on the certified pins produced by extending `deploy/docker-1461/test/run.sh` (the tracked 2-peer PG/AGE mesh over TLS+mTLS) into the CONFIG-2 acceptance harness (N25); E3 cross-host f1↔f2 (N17); E4 only if `hive(K≥3)` is declared. | topology attestation |
| G5 | **Capacity envelope with soak.** Growth/cost budget pre-registered under §0.2; repeated short ramps with the load generator proven not to be the bottleneck; 24 h steady and 72 h qualification at declared size with maintenance concurrent; measured on hardware not weaker than the buyer's declared node, or after a site-acceptance ramp on the buyer's node. | raw samples + growth ledger |
| G6 | **Release provenance.** Annotated and signed tag verified; every job checks out the resolved immutable commit; that commit carries G1–G5; tools and archives pinned and digest-verified; four negative fixtures (lightweight/unsigned tag · tag moved between jobs · unqualified source · altered tool archive) each proven to REFUSE, under `act` for hosted jobs and on a fork with a mutable release asset for the self-hosted legs; no binary-changing merge after the soak (the tagged binary is the soaked binary). | release workflow evidence |
| G7 | **Integrity guards proven load-bearing.** `append_only_spine_guard_g6/g7`, `record_stop_structural_b7`, `spawn_audit_gate_1937` green; `scripts/check-cert-removal-proof.sh` green; every control cited by the certificate has a mutation row and the count is published (#2912 lists the open gaps). | removal-proof log |
| G8 | **Certificate current.** `scripts/check-cert-expiry.sh` widened to the §5 watch set with a banner-and-ancestor check (today it fires only on federation-path diffs and is green with a VOID certificate; N30), its context present in live branch protection (N27), and the certificate re-issued at the artifact SHA (VOID today, #3501). | cert document |

## 4. Review waves and independence

Three waves × seven distinct reviewers per major qualification, 21 recorded ballots:
W1 independent findings; W2 adversarial counterexamples against W1; W3 final artifact
adjudication. Distinct means distinct principals (a person or an organisation) recorded
as `reviewer_identity`; sessions of one model family within one organisation count once.
Every ballot and every rejected claim is preserved in the bundle
(`docs/reviews/gpt6-astra-20260905-evidence/` is the precedent). A wave with fewer than
seven ballots blocks issuance. Smaller 3×3 waves are permitted for intermediate
documents and are labelled as such (this standard and its companion audit were reviewed
3×3 by one principal, and therefore carry the VENDOR SELF-CERTIFIED label below).

At least one wave-3 ballot must come from a reviewer independent of the vendor and of the
model family that authored the artifact; otherwise the certificate carries the label
**VENDOR SELF-CERTIFIED**.

## 5. Issuance, expiry, re-issue, disconfirmation

One immutable bundle per artifact. The certificate expires on any change to the watched
surface set: `src/federation/**`, `src/handlers/federation_receive.rs`,
`src/handlers/federation_signing_check.rs`, the `AI_MEMORY_FED_*` name set, and, added by
this standard, `src/identity/**`, `src/storage/migrations.rs`, the write funnels in
`src/store/postgres.rs`, and `src/handlers/admin.rs`. The enforcer is the widened
`check-cert-expiry.sh` (N30). Historical certificates are retained with expiry banners
and never edited to look current. A passing older source SHA never certifies new
identity, migration or federation code.

Preconditions of issuance: the deployed node's `ai-memory doctor --posture` output is
attached and shows the certified posture (including `synchronous=FULL` for SQLite);
audit-spine retention declared (days) and exportable to an external log store; every
certified node NTP-disciplined to UTC with `clock_source` in the run record; a
documented key-management procedure (generation, rotation, compromise, revocation) for
agent keys, daemon keys and at-rest keys.

Disconfirmation clauses (any one voids the certificate): the four existing §7 clauses of
`docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md`; any `PASS` row with
`oracle_kind: self-report`; any published number not recomputable from a linked
immutable artifact; any dashboard observation whose freshness timestamp postdates its
source artifact's `finished_at_utc`.

## 6. Execution list

Two tracks. **Tag-blocking** items are defects that would ship or evidence without which
no "green" is recomputable; they precede the v1.0.0 tag. **Certificate-blocking** items
produce the G1–G8 evidence about the shipped binary; they precede issuance of the
certificate. **Operator decision (2026-09-09 17:05Z, final): v1.0.0 GA ships at the
freeze line — the tag track — and describes itself as production-supported inside the
published envelope, NOT CERTIFIED for mission-critical use; v1.1.0 is the certification
release that produces G1–G8 and issues the certificate. `v1.0.0-rc.N` pre-release tags
ship as the freeze list clears. Track column: `tag` = inside the v1.0.0 freeze
(`ga-freeze`), `cert` = v1.1.0.**

| # | Item | Work | Track | Effort | Type |
|---|---|---|---|---|---|
| 0a | N22 | Pre-register the §0.2 declaration (SLO/RPO/RTO, growth budget) and its hash; adopt this standard into `docs/compliance/`. Must precede every measurement. | tag | S | docs |
| 0b | lanes | Land the reviewed authority lanes (#3379 #3380 #3381 #3382, then #3383 #3455 #3499 #3364 #3386 #3506, then N23); #3383 retires the #936 pin `mcp_as_admin_true_purges_cross_tenant_936`. | tag | L | code |
| 0c | N11 | One shared authority resolver invoked at dispatch for every mutating handler and visibility-gated read; structural guard test over the N14 inventory; rulings on #3125 (enforce-mode default) and on stdio as a single trust domain (F13), recorded in `SECURITY.md`. | tag | M | code + ruling |
| 1 | N2 (#3404) | Canonical row projection on every SQLite read path (search, recall FTS, hybrid FTS, semantic scan with its 13 missing columns); parity test get vs search vs recall on one row, both backends; #2431 validity metadata re-pinned. Touches `migrations.rs` (voids any earlier certificate). | tag | M | code |
| 1a | N26 | Durability posture honesty: `doctor --posture` attests `synchronous`; certified posture pins FULL; `NORMAL` declared `local-only` with its RPO. No default flip. | tag | S | code + docs |
| 1b | N28 (#3152) | SAL `update` commits content patch and lifecycle transition in one transaction on both backends. | tag | M | code |
| 1c | N29 | Every write receipt carries `durability_class`. Prerequisite of the §0.2 RPO row. | tag | M | code |
| 2 | N1 | Rewrite the false-green predicates: Big-10 plaintext (`!= 200`, add exit-code and other-port probe) and anonymous-write (`!= 201` → `401/403` + zero-mutation delta), continuity readiness (constant `embedder_ready`) and 200-only retention, `test-attestation.sh` INFO oracle, swarm `covered` semantics. | tag | S | harness |
| 3a | N7(a) | Track the harnesses and the dashboard publisher in git; fix `continuity-cycle.py:21`; find or retire the producer of `mcp-tools-state.json`. | tag | S | harness |
| 3b | N7(b) | Evidence writer for §1 with computed bindings; daemon-reported `binary_sha256` and `source_commit` on `/api/v1/capabilities`; `config show --redacted --canonical`; `check-evidence-bundle.sh --self-test`. | cert | M | harness + code |
| 4 | N14 | Generated surface manifest (§2) and its gate; the G1 case ledger and N11's matrix use it as the denominator. | cert | M | harness |
| 5 | N24 | Certified-pin evidence as a merge gate: `cert-postgres-age.yml` and `postgres-ignored.yml` become declared and live contexts; non-vacuity ratchet on executed test counts per leg. | tag | S | harness |
| 6 | N25 | Extend `deploy/docker-1461/test/run.sh` (D6) into the CONFIG-2 acceptance harness (NHI-style acceptance, at-rest leg) and wire it to a required context. Parent #3308 Config 2. | cert | L | harness |
| 7 | N17 | E3 cross-host f1↔f2 negative set (duplicate / stale-revision / reorder / wrong-peer-key / unauthorized-restore) on the certified pins. Child of #3308 Config 2. | cert | L | harness |
| 8 | #3501 | Re-issue the enterprise certificate at the artifact SHA with §0.1 prepended. Last: after every watched-surface merge. | cert | M | docs + harness |
| 9 | N16 | Mission ledger, clocks 1–5 relabelled, hydrate a NEW reference agent from receipts, digest + revision verification per acknowledged row. | cert | L | harness |
| 10 | N16 | Fault-boundary matrix: twelve declared; the after-commit boundary already exists (`AI_MEMORY_TEST_ABORT_AFTER_COMMIT`, #1961); the five remaining in-process boundaries (before-durable-store, mid-capture partial transcript, disk-full / IO refusal, embedding outage, wake-hub kill) with seeded randomised timing; PG crash rides item 6, power rides item 17, external-effect-receipt-lost rides V10. | cert | L | harness |
| 11a | N6 | Release workflow: verify annotated + signed tag in preflight, use `needs.preflight.outputs.sha` for all eight checkouts, pin `cbindgen` and digest-verify `nfpm`, bind the resolved commit to a successful qualification run, tag ruleset, `cargo audit` / `cargo deny` with zero un-VEX'd advisories. | tag | S | harness |
| 11b | N6 | Four negative release fixtures (G6) and the reproducible-build provision (`SOURCE_DATE_EPOCH`, two-build byte identity) so the soaked binary is the tagged binary. | cert | M | harness |
| 12a | N27 | Enforce the two claim gates (#2879, #2869) and N24's certified-pin contexts in live branch protection; a declared-vs-live drift check (`check-required-contexts-live.sh`); ruling that admin-lift merges over red required checks stop. | tag | S | infra (operator) + harness + ruling |
| 12b | N27 | Enforce the Enterprise-federation cert-expiry context, after item 8 (else every PR is red while the certificate is VOID). | cert | S | infra (operator) |
| 13 | N3 | Shims: read `status` and `memory_id`; `ask` is a false acknowledgment, `pending` is durable-but-deferred and must be reported as such (S); the seven-receipt-class conformance harness (M). Shims ship via `publish-sdk-shims.yml`, outside the tag artifact. | tag (S) / cert (M) | M | code + harness |
| 14 | N14 | Posture × operation matrix (cell P) generated from the same manifest as item 4. | cert | M | harness |
| 15 | N12 | Backup/restore (#3199 follow-up): signed manifests, name-or-manifest selection, directory-fsync failure surfaced, unlink sidecars before publish (today after, `backup.rs:1121→1135`) and fatal on failure (retires the #3131 pin), writer during restore; restore into a fresh environment and resume a mission. Native PostgreSQL recovery orchestration is v1.1 (the CLI refuses backup on a pg store by design); document the operator procedure. | tag (fixes) / cert (battery) | L | code + harness |
| 16 | N20 | Soak host and 24 h / 72 h qualification soak with the growth ledger. Last binary-changing step precedes it. Child of #3308 Config 3. | cert | L | infra (operator) + harness |
| 17 | N20 | Power-interruption VM for the persistence boundary named in `tests/power_loss_durability.rs` (carried inside N20). | cert | M | infra (operator) |
| 18 | N22(b) | Procurement appendix (§8) and the ballot procedure into `docs/compliance/` (N22's certificate half; 0a is its tag half). | cert | S | docs |
| 19 | N15 | AGE claim labelling into #3297's truthfulness pass; re-verify the `find_paths` relational-only rationale on AGE 1.8.0 with an EXPLAIN capture. Differential relational↔AGE suite is v1.1. | tag (docs) | S | docs + harness |
| 21 | N4 | `wrap codex` fails closed outside the tested version range (Codex ≥ 0.153 rejects `--system`; `--system-flag` overrides exist); boot sentinel; `ai-memory doctor --host <name>` wrapper self-test; docs rewritten. Matrix generation from acceptance runs is certificate work (G2). | tag (S) / cert (M) | M | code + docs |
| 22 | N8 | Trust signals as distinct machine-readable claims; stop deriving `provenance_tier` from the incident edge; stop bucketing caller 1.0 as `confirmed`. | tag | M | code |
| 22a | N31 | GA subset of the mission suite: correction reachability and poisoned memory with the harness-owned reference agent, n ≥ 30, preregistered threshold. Produces G3. | cert | M | harness |
| 22b | N21 | On-call rehearsal on the campaign infrastructure, before any customer mission. | cert | M | docs + harness |
| 22c | N10 | Comment the deliberate `gc_if_needed` discard on the recall path (ERRORS-19); document the declared read side-effect set (`gc_if_needed` probe, `recall_observations` ledger, `fold_recall_accesses`) that §1's EXPECTED_REFUSAL delta excludes. Prerequisite of §1 for any recall case. | cert | S | code + docs |
| 22d | N13 | pg export contract (amendment on #3288): declare snapshot-vs-live-scan semantics, return withheld/redacted counts on every path. | tag | S | code |
| 22g | N9 | Recall budget accounting (candidate / emitted / dropped tokens with reasons). | v1.0 | S | code |
| 22h | N30 | Widen `check-cert-expiry.sh` to the §5 watch set with a banner-and-ancestor check. | tag | S | harness |
| 23 | V8 | E4 three failure domains. Track `infra/do-hive/HIVE-TEST-PLAN.md` first. | v1.1 | L | infra + harness |
| 24 | V3 / V2 | Full 12-mission suite with arms A–E; workload-advantage benchmark. | v1.1 | L | harness |
| 25 | V6 | Embedding-evolution suite (comment on #2169). | v1.1 | M | harness |
| 25a | V9 | Overload knee / admission control / fairness (comment on #2623); differential relational↔AGE suite. | v1.1 | M | harness |
| 25b | V10 | Lease fencing at the external side effect (new lease token; exactly-once is NOT CERTIFIED for v1.0). | v1.1 | M | code |
| 26 | V7 | Roadmap w1–w8 reconciliation (comment on #2440). | v1.1 | L | docs |
| 27 | V1 / V4 / V5 | Recall abstention signal; MemTrapBench methodological guards; compact TOON measurement. Audit-only carriers, no certificate dependency. | v1.1 | M | code + harness |

**Tag-blocking critical path:** 0a → 0b / 0c → 1 / 1a / 1b / 1c → 2 / 3a / 5 / 22h
(parallel, harness) → 11a / 12a → 13 (S) / 21 (S) / 22 / 22d / 15 (fixes) / 19 → tag.

**Certificate critical path:** 3b → 11b → 4 → 6 → 7 → 9 → 10 → 15 (battery) → 13 (M) /
21 (M) / 14 / 22c → 22a → 16 / 17 → 22b → 8 → 12b → 18 → issue. Pre-tag execution is
permitted only for 4, 6, 7 and 14; 3b requires 3a, 9 requires 1c and 13 (S), and 16
requires every tag-track code item, so those three cannot precede the tag.

## 7. Adoption statement a buyer may rely on

A Fortune 500, federal, state or municipal adopter may rely on a certificate only when:
G1–G8 are green for the artifact they deploy; the envelope in §0.1 contains their
backend, transport model, host range, topology, posture and external processors; their
declared SLO/RPO/RTO in §0.2 are inside the measured values on hardware not weaker than
theirs; the certificate is not expired; and the certificate is not labelled VENDOR
SELF-CERTIFIED unless their procurement rules allow it.

**v1.0.0 GA without a certificate** is production-supported inside its published
envelope for business processes whose owner accepts the published NOT-CERTIFIED list and
the absence of G1–G8 evidence; it is not certified for mission-critical use, and the
vendor says so in the release note, the README and `/capabilities`. The certificate is
the v1.1.0 deliverable.

## 8. Procurement appendix (what a public-sector reviewer will ask for)

None of it is certified today.

| Area | Status | Where it lands |
|---|---|---|
| Control mapping (NIST SP 800-53 Rev 5 / 800-171; FedRAMP Moderate, StateRAMP, TX-RAMP baselines) | not written | appendix mapping G1–G8 to AC-3/AC-6, AU-2/AU-8/AU-9/AU-11, IA-2/IA-5, SC-8/SC-12/SC-13/SC-28, SI-7, CP-9/CP-10, CM-6/CM-14, IR-4/IR-6, RA-5, SA-11, SR-3/SR-4/SR-11 |
| Cryptographic module validation (FIPS 140-3) | not validated; NOT CERTIFIED | scope an `aws-lc-fips`-class build or state the exclusion |
| Audit-log retention, tamper evidence, SIEM export, clock source (AU-8) | spine exists (G7); retention and export undeclared | §5 preconditions |
| Data residency / region pinning for `hive(K)` | envelope axis in §0.1 | per-certificate declaration |
| Incident response, vulnerability disclosure SLA, CVE/KEV cadence, breach notification | rehearsal only (item 22b) | policy document alongside the certificate |
| Supply chain: SBOM exists (CycloneDX, `release.yml:435`); SLSA provenance level, VEX, CISA Secure Software Development Attestation (OMB M-22-18 / M-23-16) | not stated | G6 evidence bundle |
| Assessor independence (3PAO-style) | all waves one principal | §4 VENDOR SELF-CERTIFIED until met |
| Data classification, PII/PHI handling, records retention, right-to-erasure boundary | NOT CERTIFIED beyond the erasure line | envelope declaration |
| Key management (KMS/HSM, rotation, compromise) | tested by Astra; procedure undocumented | §5 preconditions |
| Sub-processors (embedding and LLM providers) | envelope axis in §0.1 | per-certificate declaration |
| Accessibility (Section 508) of dashboards | out of scope | stated |
