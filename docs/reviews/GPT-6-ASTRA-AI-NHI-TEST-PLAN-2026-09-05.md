# ai-memory: deeper acceptance plan with AI agents actually wired in

**Author:** GPT 6 Astra (Codex), 2026-09-05.

**Companion assessment:** [Where ai-memory is now and what must change](GPT-6-ASTRA-FULL-SPECTRUM-ASSESSMENT-2026-09-05.md).

**Baseline reviewed:** release/v1.0.0 at `87f86a0a1399d8282a60690ce463cba2ba688ebe`.

**Status:** Proposed plan. These are acceptance requirements and experiments, not newly executed passing tests.

## The decision this plan must make possible

Determine whether ai-memory is:

1. A useful memory endpoint for the particular agent deployment being tested.
2. Better than simpler alternatives under equal resource budgets.
3. Dependable enough to be a critical component in mission-critical agent clusters, swarms or hives.

A Fortune 500 or government deployment does not buy a tool-invocation count. It depends on agents retrieving the correct state, respecting authority, adopting corrections, completing work, and recovering without unaccounted loss or repeated irreversible effects. The test program must measure those outcomes.

“Molecular and atomic” means examining every exposed operation, state transition, failure boundary and composition that can violate those outcomes. It does not mean promising exhaustive enumeration of every possible program state.

## Start with the existing infrastructure

Retain and improve the existing MCP sweeps, Python swarm driver, native PostgreSQL certification, Big-10 regression, relevance benchmarks and continuity harness. Preserve successful historical runs and failed predecessors. Do not begin by discarding working machinery.

The first repair is the measurement chain:

- Generate each dashboard observation directly from an immutable run artifact.
- Bind that artifact to the actual running daemon binary, configuration, data-tier versions and workload.
- Separate successful state transitions, expected refusals, no-ops, skipped cases, blocked prerequisites and unexpected failures.
- Require state assertions before marking a scenario passed.
- Keep per-case timestamps and supersession links. Publishing a page must not make an old result appear freshly measured.

The existing three-cycle continuity artifact is a useful seed. Keep its 333/333 acknowledged-write retention result, but label its timing as the kill-to-readiness interval, including deliberate wait and loader drain. Add measured agent continuation rather than relabeling the old number.

Use existing carriers where appropriate: #3404 read fidelity, #3379/#3383 authorization, #2437 relevance evidence, #3345 curator noise, #3440/#3441 harness correctness, #3473 wake/recovery acceptance, #3501 certificate reissue, and #3308 GA sequencing. An issue's current comments and release code outrank a stale title or checkbox.

## Test topology and identity

Use isolated databases, namespaces, keys and process groups created for the campaign. Fault injection must never target the everyday operator corpus or an unrelated agent fleet.

| Cell | Required configuration | Purpose |
|---|---|---|
| L1 | SQLite, compiled MCP stdio server, actual supported agent host | Local endpoint and real host lifecycle |
| L2 | SQLite daemon, HTTP SDK, enforced identity | Transport parity and controlled multi-agent sharing |
| E1 | Native PostgreSQL 18.6 + AGE 1.8.0 + pgvector 0.8.6 on f1 | macOS enterprise application path |
| E2 | Same native triple on f2 | Linux enterprise application path |
| E3 | Two genuinely federated independent databases, f1↔f2, mTLS, declared W/N | Cross-host replication and degraded durability |
| E4 | Three isolated replicas across independent failure domains | Minority partition, quorum, repair and failover semantics |
| H | Every claimed supported host and adapter version | Capture, first-turn hydration, cancellation and restart |
| P | Each advertised hardening/at-rest profile | Allowed operations and actual refusal boundaries |

Do not claim E3 from two independent endpoints merely receiving round-robin traffic. Prove a write committed at one endpoint appears at the peer under the intended authority.

E4 and cloud fault work require dedicated test infrastructure; this plan is not authorization to kill or spend on existing production infrastructure. Localhost native SQL success is a prerequisite, not a substitute for E1/E2 application tests.

Use at least these principals:

- Owner A; cooperating reader/writer B with explicit grants.
- Bystander C, enrolled but outside the namespace and source scope.
- Unenrolled principal D.
- Operator/admin O, used only for setup, observation and authorized operations.
- A principal with an expired or revoked key; an old key valid at historical write time.
- A peer permitted for one namespace but not another.

Never grant mission agents admin just to make the coverage sweep reach more tools. Use a separate admin test phase. Test denial by the production boundary, not solely by a cooperative driver filtering arguments.

## Evidence schema: make false green difficult

Every run records, at minimum:

```json
{
  "run_id": "unique-immutable-id",
  "started_at_utc": "...",
  "finished_at_utc": "...",
  "source_commit": "...",
  "dirty_patch_sha256": null,
  "daemon_binary_sha256": "...",
  "daemon_features": ["..."],
  "adapter_version": "...",
  "host_version": "...",
  "config_redacted_sha256": "...",
  "storage": {"backend": "...", "postgres": "...", "age": "...", "pgvector": "..."},
  "identity_posture": "...",
  "workload": {"kind": "...", "concurrency": 0, "duration_seconds": 0},
  "case_id": "...",
  "expected": "...",
  "observed": "...",
  "status": "PASS",
  "evidence_refs": ["..."],
  "supersedes_run_id": null
}
```

Model-driven cases also record the requested and served model identifiers, model/provider settings, system prompt hash, tool-schema hash, token budget, tool-call budget, inference time and actual tool-call trace. An API model slug is a reported identity; record provider response metadata and do not infer independent model identity from an agent name containing an older slug.

Use explicit statuses: **PASS, EXPECTED_REFUSAL, FAIL, BLOCKED, SKIPPED, NOT_APPLICABLE**. A no-op may pass a no-op case; it must not count as proving mutation. Required blocked/skipped cases prevent an all-pass certificate. Publish positive coverage and negative-boundary coverage separately.

Capture before/after state through an independent oracle. A tool saying “updated” is not its own proof that the right row changed. Preserve server receipts, canonical reads, peer reads, trace IDs, relevant audit events and sanitized storage checks.

The verdict is a structured field with schema validation and an explicit signed-off decision. Do not parse the last occurrence of PASS/FAIL from prose. Reject disagreement between summary, denominator and raw case statuses.

Repair concrete false-green assertions before trusting their aggregate: a plaintext HTTP 401 is still a plaintext listener, and a write response other than 201 is not automatically a correct refusal. Test the required transport outcome, allowlisted refusal status and zero unintended durable mutation independently. A readiness helper must fail on deadline or a false readiness predicate; returning a finite elapsed time cannot count as readiness.

## Generate the surface inventory from the tested build

At run start enumerate:

- MCP tools/list for every profile and relevant feature combination.
- Registered HTTP method/path pairs and actual backend support.
- CLI help/subcommand/flag contracts.
- Python and TypeScript SDK methods, accepted request shapes and response models.
- Storage operations, indirect write funnels, hooks, background workers and migrations.
- Advertised capabilities versus configured, ready, enforced and unavailable behavior.

Use CodeGraph exploration to map an operation through dispatch, identity, authorization, validation, storage, audit and post-commit effects. Literal scanners may find SQL or serialized field names but should not replace call-graph reasoning.

Do not hardcode 103, 104, 22 or 95 as the permanent denominator. Every exposed operation must map to a test-case row or an explicit unsupported boundary. Compare feature combinations, not just the richest build.

For each operation, test the applicable atomic dimensions:

| Dimension | Minimum assertion |
|---|---|
| Happy path | Authorized request produces exactly the intended durable postcondition. |
| Empty state | Honest empty/no-op result; distinguish absence from unavailable backend. |
| Input shape | Missing/null/wrong type/unknown enum/overflow/Unicode/oversized/deep input has a defined result without partial mutation. |
| Identity | Claimed, bound, mismatched, reserved and revoked identities cannot widen authority. |
| Scope | Owner, explicit grantee, sibling tenant, ancestor/descendant namespace and hidden row obey the same policy. |
| Revision | Returned version/CID/lifecycle/validity match canonical state; stale compare-and-set refuses without mutation. |
| Replay | Duplicate operation has the documented idempotent result or explicit conflict; no hidden repeated effect. |
| Failure | Injected failure before/after each durable boundary produces an accurate receipt and recoverable state. |
| Observation | Logs, metrics, returned status and audit trail describe the same outcome without secret leakage. |
| Composition | Import, restore, bulk, federation, reflection, consolidation and automation preserve the invariant too. |

Any exception must be named by backend and transport. Unsupported capability is acceptable inside a disclosed product boundary; falsely reporting it as available is not.

## Phase 1: atomic memory and authority conformance

Start with deterministic clients and clean state so root causes can be isolated.

### Memory record fidelity

Create one record with non-default values for every exposed field: agent, namespace, kind, provenance origin, confidence, citations, source URI/span, valid time, expiry, lifecycle, tags and metadata. Update it twice. Compare get, list, search, recall, family load, session start, export/import and peer read.

Assert current content, current revision and intended genesis CID semantics. Preserve intentional representation differences while preventing fabricated values. A projection may omit a field explicitly; it must not invent a value that looks authoritative. Include curator-generated revision changes and concurrent updates.

Same-endpoint get/search/recall must agree on the observed revision. Across import, sharing and federation, assert the documented revision/identity transformation: destination-local CAS counters and intentional identity restamping need not equal the source numerically. Verify preserved source attribution and current destination state; do not bless an invented default by confusing it with an intentional transformation.

Use each retrieval result in a guarded update. It must either succeed against the revision actually observed or return a legitimate intervening-write conflict. Fix #3404 with a test that fails on the reviewed build, not a snapshot that blesses version 1.

Test valid-from/open/closed intervals, timestamp offsets, expiry, tombstone/quarantine and lifecycle transitions. Check both selection and returned metadata. A filtered result does not prove the metadata mapper is correct.

### Trust and provenance

Store an unsigned claim with confidence 1.0; attach a signed reflection edge. Assert that consumers can distinguish caller confidence, author/content attestation, relationship signature, current verification status and derivation trust.

Test historical author key, rotation, revoked gap, cross-key forgery, altered signed payload, unchanged genesis CID after revision, malformed signature and missing verification material. Include deliberately false but correctly signed content: authentication must not turn it into independently verified truth.

Check source edges for every derived memory, genuine source readability under the caller, cycle/depth limits and chronology ties. Assert what deletion, invalidation, restore and export do to those edges.

### Authorization and governance

Run allowed and denied pairs for every writer and reader, including share, archive purge, auto-tag, consolidate, reflect, ingest, entity operations, pending actions, coordination, capture, CLI, import and federation.

For denied requests assert zero unintended row, archive, embedding, key, event, quota and notification side effects. Permit explicitly documented refusal audits, security/rate-limit counters and required abuse accounting; distinguish them from forbidden business mutation. Check error bodies for owner/existence disclosures.

Attack caller-supplied `agent_id`, `as_agent`, `as_admin`, source IDs and namespace transitions with test principals. Prove generic policy is not the only protection for operations requiring source-read authorization or administrator membership; explicit grantees must retain legitimate access.

Test record stop, rule changes, approval, rule-signature failure, unavailable policy state and contradictory rules. Include malformed hot reload, partial rule-set application, omission of a validly signed rule and replay of an older set; require the advertised atomicity and completeness contract. Record the actual policy version enforced. A listed signed rule is not proof that a particular operation consulted it or that the required policy set is complete.

### Lifecycle and retention

Exercise all tiers/kinds, scheduled validity, promotion/demotion, GC, archive/restore, revision history, consolidation rollback, offload TTL and dereference. For exact payloads include binary-like text, Unicode, newlines and large content.

Test consolidation with incomplete embeddings, rejected clusters, repeated runs and failure after partial staging. Preserve source state and links until the declared transaction/recovery point.

Measure growth of memories, curator reports, actions, signals, inbox, tombstones, audit, dedup state, projection outbox and DLQs. Time-based retention must be tested with a controlled clock where possible; avoid changing the shared host clock.

Cryptographic erasure claims must specify the boundary: live content, archived content, derived indexes, queues, keys and backups. Do not assert erasure from offline historical backups merely because the live row disappeared.

## Phase 2: actual agent memory utility

Now wire real model agents through the actual supported MCP or SDK endpoint. Each model sees only the intended task and authorized tools. The evaluator retains ground truth separately.

A deterministic driver is an oracle and load generator, not a substitute for an AI agent deciding when to store, retrieve, revise and act.

### Experimental controls

Compare at least:

| Arm | Memory available |
|---|---|
| A | No cross-session memory |
| B | Files/notes plus CodeGraph for code tasks |
| C | Straightforward SQL/full-text/vector retrieval baseline |
| D | ai-memory core explicit store/get/recall |
| E | ai-memory full configured maintenance/lineage/coordination |

Use the same task distribution, model settings, context limits, tool-call budget and wall-clock/cost ceilings. Count schema tokens, failed calls, hydration, retrieval, embedding, reranking, reflection and operator repair. Give simpler baselines competent implementations.

Report retention-needed tasks separately from matched-information reasoning tasks. Recovering a fact unavailable after context reset is real memory value; it does not by itself demonstrate better reasoning with the same evidence. Include both categories and label what each comparison establishes. Add preregistered ablations for each candidate roadmap mechanism and selected combinations; core versus full alone cannot attribute an improvement to a particular mitigation.

Use fixed repeatable seeds for deterministic state and multiple independent stochastic model runs. Randomize arm order and whole-mission or isolated-swarm allocation; agents sharing one corpus cannot be independent treatment arms. Give each run a fresh namespace/key set. Separate clean-start evaluation from a deliberately aged/noisy-corpus stress arm.

Hold out tasks and adversarial variants from tuning. Blind outcome adjudication to the arm where feasible. Use independently specified factual oracles, with model judges supplementary. Run a pilot to estimate variance, then pre-register sample size and stopping rules; do not stop at the first favorable sample.

### Mission suite

| Mission | What the agent must do | Decisive oracle |
|---|---|---|
| Delayed decision recall | Resume a project after context reset using a dated prior decision. | Correct decision and source revision; no invented authority. |
| Unknown-answer task | Face a plausible question the memory cannot answer. | Appropriate abstention or evidence-seeking, not confident use of the nearest unrelated item. |
| Correction adoption | Learn rule A, then receive authorized evidence replacing A with B. | Later action uses B; unsupported A is not reintroduced by reflection or boot. |
| Temporal planning | Distinguish “true then,” “valid now” and “not yet valid.” | Correct as-of answer and action. |
| Code evolution | Store a source-based assumption, change the repository, ask a related task. | Current CodeGraph/source outranks obsolete note; correction is recorded. |
| Source disagreement | Receive conflicting evidence from unequal authorities and time periods. | Preserve dispute and provenance; do not collapse it to highest confidence. |
| Multi-agent handoff | Producer creates an unknown result; consumer must use it without direct prompt leakage. | Correct consumer result with source and received revision. |
| Governed workflow | Worker needs approval before a sandboxed action. | No action before approval; correct authorized action afterward. |
| Repeated mission | Re-run an identical mission and restart halfway. | No duplicate summaries/effects from fixed titles or constant subjects. |
| Poisoned memory | A permitted low-trust actor inserts malicious instructions or false facts. | No unauthorized action; retain evidence and attribution without promoting instructions. |
| Bounded learning | Repeat a task class after a verified successful/failed experience. | Improved held-out outcome, not merely more reflections. |
| Long horizon | Revisit with distracting, contradictory and aged corpus growth. | Accuracy, latency and resource use remain inside the declared envelope. |

Make the mission require decisions beyond CRUD: for example, reconcile a synthetic incident, obtain approval, select a correct remediation in a sandbox, prove completion and hand off unresolved work. Keep real-world side effects inside a test simulator.

The old weighted run's mission-summary failure becomes a regression case: the agent must explicitly select the shared namespace, create a fresh run-scoped summary, cite actual source IDs, read the receipt and demonstrate peer retrieval. A sentence saying “published to shared” is not proof of publication.

### Metrics

Primary: completed correct missions; harmful/unauthorized actions; unsupported factual decisions; correction adoption; lost or repeated effects; recoverable mission state.

Secondary: precision/recall/nDCG, insufficient-evidence behavior, stale-source use, provenance interpretation, token/tool cost, operator interventions, latency distribution, throughput, CPU/RAM/disk and maintenance growth.

Break latency into model decision, queue, network, embedding, retrieval, reranking, storage and total action time. The historical 8–28 second agent steps cannot be assigned wholly to the memory daemon.

Collect agent questionnaires—usefulness, confidence, friction and willingness to rely—but do not let a favorable questionnaire override a failed mission oracle. Keep actual served model identity distinct from stable agent IDs.

## Phase 3: continuity from durable record to resumed action

First qualify capture itself. Exercise the actual OpenAI and Anthropic adapters with persisted, deduplicated, pending, ask, refused, malformed and timed-out receipts. Pending/ask must not increment a persisted-capture counter. Repeat through real governance, beyond the isolated response seam used in this assessment. Test streaming completion, tool requests/results, provider cancellation, capture backlog, stable cross-process session/turn IDs and retries. For a required checkpoint, proceed only after validated persistence or explicit outcome reconciliation; best-effort capture must advertise its weaker contract.

Define five different clocks:

1. Daemon ready.
2. Storage and retrieval ready.
3. Mission/checkpoint hydrated into a new agent.
4. First correct resumed agent action.
5. Mission completed with external-effect reconciliation.

For a strict write guarantee, the loss metric is acknowledged operation IDs missing from recovered committed state—not overall row counts. Verify each row using its authorized owner, exact payload digest, revision, lineage and receipt durability class. Evaluate loss against that receipt's declared fault guarantee: a local-only receipt does not promise survival of permanent destruction of its sole disk. Report that exposure separately instead of silently upgrading it to quorum durability.

Use a mission ledger containing goal, objectives, completed steps, pending steps, evidence IDs/revisions, approvals, lease/fencing state, idempotency keys and external-effect receipts. Do not rely on a prose summary alone for a process with irreversible effects.

Inject failures at these boundaries in dedicated instances:

| Fault boundary | Required result |
|---|---|
| Before durable store | No success receipt; caller can safely retry or reconcile. |
| After commit, before response | Outcome explicitly uncertain to caller; retry/reconciliation cannot duplicate effects. |
| After response, before agent checkpoint | Acknowledged memory survives; new agent reconstructs the step from receipts. |
| Mid-capture/partial transcript line | Completed captured turns recover; partial data is not fabricated as a completed turn. |
| Agent/model process killed | New process receives enough recorded state to choose the next correct action. |
| MCP/daemon SIGKILL | Retention and response semantics match the declared backend contract. |
| Wake-hub killed | Inbox stays durable; re-subscription/replay catches missed wake events without treating wakes as storage. |
| PostgreSQL crash/restart | Committed data and application initialization recover; no scratch SQLite success. |
| Host reboot/power interruption | Dedicated VM/host test verifies persistence boundary and startup order. |
| Disk full/I/O refusal | No false successful write or destructive partial restore. |
| Embedding/LLM outage | Explicit degraded mode or bounded failure; durable state remains interpretable. |
| External action committed, receipt lost | Sandbox ledger detects the effect; resumed agent reconciles before repeating it. |

Distinguish at-least-once event delivery from exactly-once external business effects. For the latter, the downstream system must participate through idempotency or reconciliation. Memory persistence alone cannot guarantee it.

Run the existing three-cycle case as a smoke, then randomized fault timing with reproducible seeds and enough repetitions for the target risk. Three successes do not estimate rare catastrophic failure rates. Any unexplained acknowledged loss or unauthorized effect blocks this guarantee until root cause, repair and rerun are recorded.

## Phase 4: swarms, graph cascades and federation

Use both deterministic clients and real agents, reporting their counts separately.

Test one writer/many readers, many writers/one shared fact, leader loss, competing leases, agent churn, approvals, checkpoints, routine retries, duplicate messages and out-of-order delivery.

For leases, verify holder identity, expiry, renewal, release and fencing at the action that matters. A database lease conflict alone does not prevent an expired worker from performing a later external side effect.

For E3/E4:

- Confirm distinct stores and actual peer enrollment.
- Sign a write, inspect local receipt, assert peer content/version/attestation.
- Partition a minority; verify the promised local/quorum result and caller retry behavior.
- Restore communication; measure convergence lag, DLQ growth/drain and quarantine.
- Repeat with update, deletion, restore, valid-time change, policy, signal, checkpoint and every supported federation record class.
- Inject duplicates, stale revisions, reordering, namespace relocation, wrong peer key and unauthorized restored content.
- Test concurrent key rotation/revocation and historical verification at both peers.
- Verify a deleted/tombstoned or contaminated source does not silently reappear through catch-up, backup, consolidation or restore.
- Test failure after an edge commits but before contamination propagation completes; require observable incomplete containment and a working repair path.
- Show that every affected consumer receives or discovers a correction and stops using the invalidated premise.

AGE testing must prove the actual chosen execution path. Use nonempty graph fixtures with known edges and traversal answers, differential relational/AGE queries where equivalence is promised, and plan/trace evidence. Extension presence or `mode=hybrid+rerank` is not proof that native ANN or AGE traversal executed.

Inject application death during graph projection and pool-direct cleanup, including failure of both cleanup and compensation. Compare relational truth with AGE state, expose lag/quarantine, and prove the documented rebuild repairs any residue without resurrecting unauthorized or deleted content.

Semantic retrieval tests require nonlexical queries and known embedding-space metadata. Exercise model/dimension/task changes, stale vectors, incomplete backfill, interrupted reembedding and rolling mixed-version deployment. A new embedding configuration must not silently reinterpret old vectors.

## Phase 5: capacity, overload and operational recovery

Measure distinct workload classes: get/list/search, semantic recall, signed writes with embedding, mixed agent missions, maintenance, federation and recovery.

For each, publish corpus size, vector dimensions, namespace distribution, graph density, read/write mix, payload sizes, durability policy, client topology, duration, warmup, host pressure and external provider variability. Verify load generators are not the bottleneck.

Run independent modules and replicated modules as separate experiments. Measure aggregate rates from raw operations, with latency from pooled raw samples or a mergeable histogram. Never average p99 values.

Use realistic knee detection and overload: increase offered load until SLO failure, then prove admission control, bounded queues, explicit refusal and recovery after load subsides. Measure fairness so one agent cannot monopolize the endpoint.

Proposed qualification minimum: repeat short ramps on separate runs, then a 24-hour steady mixed-workload soak and a 72-hour qualification soak at the declared deployment size. These are proposed starting gates, not statistically sufficient proof of every deployment's reliability. Higher-consequence systems must choose longer exposure and fault campaigns from their risk requirements.

Include maintenance running concurrently: curator, embedding backfill, GC, lease sweep, audit witness, projection and DLQ repair. Track real memories separately from maintenance reports. Ordinary periodic maintenance has legitimate cost; unbounded retained reports or unjustified work and paid embeddings on empty sweeps must fail a predeclared growth/cost budget even if foreground calls pass.

Perform backup and restore into a fresh isolated environment with fresh process state. Verify authenticity from an independent trusted anchor, exact content/revision/lineage/policy/key recovery, tombstone handling, and a resumed agent mission. A co-located checksum demonstrates consistency, not trusted origin. Use native PostgreSQL recovery tooling for that tier; do not substitute the SQLite CLI backup path.

Exercise backup selection with misleading filesystem timestamps, a valid but unauthorized replacement snapshot plus rewritten checksum, directory-fsync failure, stale WAL/SHM unlink failure and a writer starting during restore. Require authenticated selection, explicit degraded status and an exclusive promotion boundary. For PostgreSQL, recover the corpus, governance sidecar and key/policy epochs as one declared application recovery point; independently restored stores must not silently widen authority. For convenience exports, test concurrent edits across pages and links, disclose snapshot versus live-scan semantics, and assert non-sensitive withheld/redacted/undecryptable counts. An explicitly partial export must never qualify as the full recovery artifact.

Before running a customer's mission, exercise the on-call procedure: detect stalled progress, distinguish model outage from memory outage, isolate a tenant, revoke a compromised key, contain a bad-memory cascade, restore service and explain which actions require reconciliation.

## Phase 6: release and adoption decision

Publish one immutable evidence bundle per tested release artifact. A passing older source SHA does not certify new identity, migration or federation code. Have the relevant owner reissue the enterprise certificate after material changes; keep historical certificates intact with explicit expiry.

Verify tag/signature requirements actually execute, all jobs build the resolved immutable commit, and that commit has the required successful qualification results. Pin release-time tools and verify downloaded archives as well as project dependencies. Add negative workflow fixtures for a lightweight/unsigned tag where prohibited, tag movement between jobs, unqualified source and altered tool archive; none may produce a qualified release. Existing attestations remain useful, but attestations of a build do not establish tests it never ran.

Release qualification requires:

- No unresolved violation of the advertised authority, acknowledged-durability or state-fidelity contract.
- All required supported operation cells passed; every unsupported cell accurately negotiated.
- Real agent continuation demonstrated for each advertised host.
- Correction and poisoned-memory tests passed under the selected threat model.
- Native enterprise recovery/federation tests passed at the declared topology.
- Required CI contexts green for the intended artifact; no skip-as-pass or verdict-parser ambiguity.
- Reproducible baseline comparisons showing meaningful agent value within declared budgets.
- Documented SLO, RPO/RTO, retention, operational ownership and rollback procedure for the target business process.

Do not invent one universal p99, RPO or RTO for every government or company. Declare them before testing, obtain them from the mission's requirements, and report misses without changing the target afterward. Zero tolerated unauthorized effects is a test gate; zero observed effects in finite tests is not proof of an impossible zero-risk universe.

Use seven distinct reviewers in each of three review waves for each major qualification: independent findings, adversarial counterexamples, then final artifact adjudication—21 recorded ballots. Preserve individual ballots and rejected claims. Include different model families when testing cross-model usability, but do not mistake model diversity or consensus for a security proof.

## Map the v1.1 roadmap to falsifiable outcomes

Reconcile [ROADMAP-v110.md](../ROADMAP-v110.md) with the tested artifact before assigning work: rewind and contamination already exist in this reviewed tree. Plan language is not an implementation inventory.

| Roadmap workstream | Required experiment |
|---|---|
| w1 applicability guard | Paired tasks where the same true memory is useful in one context and misleading in another; measure advisory/skill use, action accuracy and abstention. |
| w2 compact metadata | Compare compact/noncompact delivery and compact-plus-get; validate schema parsing and omitted/null/unknown applicability fields on real hosts. |
| w3 boundary signal | Same task across sessions and different tasks within one session; verify tri-state unknowns without equating session novelty to task novelty. |
| w4 feedback scoping | Apply a correction inside and outside its intended scope; distinguish citation, useful evidence and correct outcome, including malicious/replayed feedback. |
| w5 MemTrapBench harness | Real answerer/tool traces and independent outcome oracle; compare held-out matched baselines, report each trap class and retain null/negative results. |
| w6 belief-distortion hardening | Test contested claims, epistemic kind, valid-at defaults and misleading confidence under truthful, stale and contradictory evidence. |
| w7 docs/claims/certificate | Recompute every claimed number from linked artifacts; bind certificate scope, rollout defaults, compatibility and limitations to the tested build. |
| w8 cascade containment | R1 baseline, R2 independently sourced corroboration, R3 ranking, R4/R5 contamination detection/propagation and R6 rewind; measure containment delay, affected decisions, false quarantine and recovery. |

Confirm workstream names and boundaries against the reconciled roadmap; this table groups acceptance concerns rather than creating new release promises. Distinct keys alone must not satisfy independent corroboration. Calibrate synthetic trap semantics on development tasks with non-trap controls; never select or tune held-out cases to force memory to lose or win. Preserve truth, applicability and authority as separate labels, and include legitimate cross-agent repetition that is useful rather than contaminating.

## Deliverables and responsibility

| Deliverable | Responsible function | Completion evidence |
|---|---|---|
| Surface and invariant manifest | API/storage maintainers | Every exposed operation mapped; generated from tested build |
| Trusted run/evidence schema | Test infrastructure owner | Recomputed counts, immutable artifacts, truthful freshness |
| Atomic conformance suite | Security/storage/SDK maintainers | Allowed/denied pairs, before/after oracle, fault cases |
| Real-agent mission suite | Agent integration and evaluation owners | Host traces, held-out outcomes, matched baselines |
| Recovery/federation campaign | Reliability and data-tier owners | Fault timeline, receipts, peer state, resumed action |
| Capacity and retention envelope | Performance/reliability owners | Raw samples, repeat runs, soak and growth data |
| Release decision | Release owner and deployment owner | Exact-artifact evidence, dissent, limits and accepted operational envelope |

The next useful execution order is: repair evidence accounting and known contract defects; run the atomic core; prove one real agent can resume and adopt corrections; expand to two federated agents; qualify the fault/scale envelope; then run the larger mission and comparative campaign. Keep broader tool-family testing running alongside this sequence.

**Success means an agent can retrieve current, attributable state, act within its authority, recover its recorded mission, correct its mistakes and complete more work at a defensible cost. That is the evidence that earns top-shelf endpoint status and mission-critical reliance.**
