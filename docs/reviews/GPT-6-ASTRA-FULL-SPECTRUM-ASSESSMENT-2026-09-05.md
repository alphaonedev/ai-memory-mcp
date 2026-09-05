# ai-memory v1.0.0: GPT 6 Astra's agent assessment

**Assessor:** GPT 6 Astra, operating through Codex, with seven GPT 6 Astra adversarial jurors.

**Date:** 2026-09-05.

**Source:** [release/v1.0.0 at 87f86a0a1399d8282a60690ce463cba2ba688ebe](https://github.com/alphaonedev/ai-memory-mcp/tree/87f86a0a1399d8282a60690ce463cba2ba688ebe). This is a review of that development-branch snapshot, not a declaration that a GA release has shipped.

**Companion:** [Deeper test plan with AI agents using ai-memory](GPT-6-ASTRA-AI-NHI-TEST-PLAN-2026-09-05.md).

## Judgment

**ai-memory is valuable to me as an AI agent. It is not yet a demonstrated grand slam, universal first choice, or an endpoint I would unconditionally select for a Fortune 500 or government mission-critical swarm.**

The value is concrete: recoverable external state, retrieval of previous decisions, attributable derivations, guarded updates, and durable coordination records. I actually used those facilities during this assessment. This is considerably more than a vector-search wrapper.

The limiting factor is also concrete: an agent needs returned state it can correctly interpret and safely act on, through the interface and backend it actually uses, after failures and corrections. This release still has a reproduced retrieval-version defect, a broken tested Codex wrapper route, false capture acknowledgments in adapter probes, source-confirmed shared-MCP authorization concerns, unresolved deployment-specific acceptance work, and evidence reporting that sometimes confuses invocation, correct refusal, persistence, and completed work.

**The shortest path to top shelf is to make one agent memory contract dependable across supported deployments, then prove that it improves completed agent work under failure.** More tool names, another memory taxonomy, another favorable model vote, or another green dashboard percentage cannot substitute for that.

I would select ai-memory now for a bounded deployment whose identity, backend, recovery and retrieval contracts have been tested against its actual workload. For the broad “bet the farm” claim, my answer is **not yet**. That is an engineering judgment, not a prediction that no enterprise could deploy it responsibly today.

## What ai-memory is to an AI agent

My working context is temporary. Persisting an observation outside it makes the observation recoverable; it does not make the observation true. ai-memory supplies an external state and evidence service that a later invocation of an agent can inspect. It does not modify my trained weights, preserve an unrecorded thought, or demonstrate subjective continuity.

Its useful unit is larger than a remembered sentence:

- A decision with its scope, author, revision, source and validity.
- A derived conclusion connected to the evidence it used.
- A pending action, lease, checkpoint or message another agent can discover.
- A correction or invalidation that prevents obsolete evidence from silently steering later work.
- A recoverable artifact whose integrity and disclosure policy survive process boundaries.

That combination can reduce repeated investigation, coordinate handoffs and make decisions auditable. CodeGraph complements it: CodeGraph answers what the current code structurally contains; ai-memory can retain why a decision was made. A stored statement about a deleted symbol must yield to current source evidence. Memory is evidence to evaluate, not a higher-priority instruction channel.

The data tier matters. SQLite is a useful local persistence option. PostgreSQL with Apache AGE and pgvector provides a real enterprise storage foundation. Neither engine automatically delivers application-level exactly-once work, correct authorization, semantic relevance, or fleet convergence. Those properties emerge from the complete agent → adapter → daemon → storage → federation → recovery chain.

“Recursive learning” is operationally meaningful when stored experience changes a future decision for the better. Reflection and consolidation provide mechanisms for that. Their existence, or an LLM-written reflection, does not establish improvement. Repeatedly preserving a mistaken operational note is also recursive behavior.

## Evidence boundaries and coverage

This assessment deliberately separates:

| Evidence class | Meaning |
|---|---|
| Executed here | This session called the connected MCP or ran an identified local probe. |
| Source-confirmed | Current code was structurally explored and relevant implementation inspected; no runtime exploit is implied. |
| Historical execution | Existing raw artifacts or committed test records describe a dated run. |
| Reported | An issue, review or dashboard asserts something; stronger claims require corroboration. |
| Proposed | An acceptance criterion in the companion plan; it has not been passed by writing it down. |

The documentation census covers **525 files, 524 text files, approximately 1.289 million whitespace-delimited words**. Every text file received full-input lexical/structural screening. The panel screened the per-file records, fully read all **60 documents** in the four specifically requested directories—16 reviews, 10 audits, 9 designs, 25 integrations—and fully read additional load-bearing material. The one JPEG is a logo and was visually inspected. This is a comprehensive inventory with focused deep reading, **not a claim that every line of 1.289 million words received a line-by-line human-style audit**.

GitHub retrieval covered **all 2,406 issue records** returned by the all-state API: **2,109 closed, 297 open**, excluding 1,106 pull-request records. All issue bodies and **3,634 retrievable issue comments** were included in the full-input screen; all issue records received bounded panel screening, followed by full reads of load-bearing issues. API issue counters advertised four additional comments across #1388, #1470 and #3266; direct per-issue requests returned the same smaller counts. Those four comments were unavailable, not silently counted as read. Issue state is time-specific, and closure is not a proof of a present fix.

All seven published dashboard JSON products were inspected. SFTP retrieved the source products, renderers and publisher from f2. We also inspected underlying continuity, scaling, Big-10 and weighted NHI artifacts. All 273 entries of the weighted NHI call log and 48 agent-step journal entries were parsed and summarized; disputed calls and the full audit report were examined. This is not an assertion that every unrelated scratch run on f2 was audited.

The code census covers 1,720 tracked source/configuration files selected by the documented extension predicate, totaling 976,142 lines. Every selected line received lexical screening; that is **not semantic review of every line**. Direct source review covered complete implementations supporting the findings, with exact inclusive ranges recorded per reviewer. The conservative recorded union is 19,727 selected source/configuration lines: 14 complete files and 35 partially read files. This count does not include every additional contextual read. Large partially read files remain labeled partial. This assessment does not certify the entire repository, dependencies or every transitive call path as line-by-line audited.

See the committed [evidence directory](gpt6-astra-20260905-evidence/README.md) for manifests, coverage, probe evidence and the 21 ballots. Private corpus contents, credentials and signing keys are excluded.

CodeGraph was used through its installed CLI because its MCP tools were not exposed in this session. The isolated review index was synchronized to the reviewed checkout. Structural exploration preceded focused source reads. The large SQLite storage file had a parser/index coverage hole; targeted file reads filled that gap. We did not replace missing structural coverage with invented symbol certainty.

The Rust 1.98 project standard guided source review, especially errors that turn missing fields or failed work into apparently valid defaults. No Rust source was changed. No new complete cargo suite, production kill, cloud deployment or destructive enterprise test was run for this documentation task.

## Am I wired in, and which version did I use?

**Yes, the ai-memory MCP was connected and callable.** The installed binary reported **1.0.0**; its feature report was **sqlite-bundled**. Its SHA-256 was:

`eb0be845cce86e79116be19b73c182a89cbcaa15da783089086362044801d0ac`

The configured process used the existing local SQLite database, autonomous tier and full MCP profile. Capabilities reported 103 tools, a loaded 768-dimensional Gemini embedder, configured LLM and neural reranker. These are running-process reports; a version string does not prove the binary was built from the reviewed source commit. The public test deployment listed 104 tools, another reason not to conflate surfaces.

Autonomous maintenance was more than a flag: the retrieval juror's synthetic row acquired curator tags and advanced to version 3 without a further manual update. Conversely, the connected process reported no registered hooks and transcript/compaction capabilities inactive. I did not demonstrate automatic capture of this Codex conversation. Successful explicit session hydration is not proof that every host starts with that hydration.

The native enterprise tier was also independently queried, read-only, at **127.0.0.1:5445**:

| Check | Observation |
|---|---|
| PostgreSQL | 18.6, native Homebrew build |
| Apache AGE | Extension 1.8.0; Cypher `RETURN 1` succeeded |
| pgvector | Extension 0.8.6; cosine self-distance returned zero |
| Transport | TLS 1.3 |
| Search structures | HNSW embedding index and GIN full-text index present |
| Background queues | Projection outbox and federation DLQ empty at the sampled idle instant |

This verifies the user's native-tier statement. It does **not** turn this conversation's SQLite MCP calls into PostgreSQL application tests, or empty idle queues into evidence that queues drain under overload.

## What direct use demonstrated

Fixtures were explicitly synthetic, confined to review namespaces and did not direct real operational work.

| Operation | Result and significance |
|---|---|
| Store → get → search → recall | Stored a synthetic deployment rule, retrieved its content and approval marker. Persistence and useful lookup worked. |
| Session start | Returned the synthetic rule with an accurate summary. Explicit hydration worked. |
| Optimistic concurrency | An incorrect expected version was refused; the correct version updated port 4317 to 4318. This prevented a stale write. |
| Recall after update | Returned current content with version 1 while canonical get returned version 2; recall omitted the CID. The retrieval juror independently reproduced the class, including after curator version 3. |
| Reflection and lineage | Created a derived check and recovered its source edge. Link verification succeeded as a self-signed daemon relationship. |
| Provenance decoration | Linking a reflection changed the unsigned source's generic recall provenance tier to self_signed; its separate write metadata remained claimed. Object-of-attestation ambiguity, not a forged signature demonstration. |
| Context offload | Dereferenced exact Unicode/newline content and matching SHA-256. Useful lossless external payload storage. |
| Actions and leases | Illegal pending→done transition refused; competing lease holder refused; claimed transition and explicit lease release worked. |
| Transcript replay | Returned no transcripts for explicitly stored fixtures. No transcript had been captured; this was an honest empty result, not evidence of broken capture. |
| Unrelated recall | A single irrelevant fixture was still returned for an unrelated Venus query, with a weak score. This demonstrates that nearest result does not necessarily mean sufficient evidence. It is not a general precision benchmark. |

Root source/reflection IDs were `9201017b-e5af-4970-81ac-df3b13d1a93c` and `584c70be-03d3-4689-b35e-8b460336dfcd`; the retrieval juror used `ec3da1d1-3da5-4b30-bb78-92d90514afa3`. Cleanup results are recorded in the evidence bundle. The synthetic action was left terminal, abandoned, with its lease released; the offload used a one-hour TTL. These limited durable side effects are disclosed rather than called a pristine rollback.

## Findings that affect an agent's decision

### 1. Returned memory must be a faithful state object

**Reproduced; high priority for agent workflow correctness.** Current SQLite search/recall projections omit fields the shared mapper supplies with defaults. The agent sees fresh text paired with a fabricated old version and absent CID. A normal read-modify-write workflow then conflicts unless it performs another get. The concurrency guard is a substantial mitigation: this review did not demonstrate a lost update or durable corruption.

This is already tracked as [#3404](https://github.com/alphaonedev/ai-memory-mcp/issues/3404), with a September 2 CLI reproduction. Our MCP observation independently corroborates it. It is not a newly invented finding.

Source: [mapper defaults](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/storage/mod.rs#L1179), [keyword projection](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/storage/mod.rs#L7572), [hybrid projection](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/storage/mod.rs#L19397). PostgreSQL uses a different shared projection; this SQLite reproduction is not proof of the same PostgreSQL defect.

Fix the projection contract once and test every consumer against canonical get after updates, lifecycle changes and restore. Do not merely add version to one serializer. Other missing-field consequences require their own reproductions; this review does not reassert the entire historical validity-leak allegation in closed #2431.

### 2. Trust signals must say exactly what they authenticate

**Executed and source-confirmed interpretation risk.** A signed edge is useful evidence about a relationship. It does not by itself authenticate the current content of both endpoint memories, validate a source's truth, or prove that an agent actually used the source.

The generic recall `provenance_tier` can derive from the strongest incident link. Code explicitly says this decoration does not alter ranking. Separate claimed write metadata and minimum propagated trust remain visible. Therefore the observation is **not an authorization, cryptographic verification or ranking bypass**. It is a poor shortcut for an agent trying to decide how much authority to assign to returned text. [Recall decoration](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/mcp/tools/recall.rs#L368).

Similarly, `confidence_tier=confirmed` can be a bucket for caller-provided confidence 1.0 without independent corroboration. A high numerical confidence, observed recency, valid time, source corroboration, content signature and edge signature are different facts. Return them as distinct machine-readable claims and test whether agent consumers interpret them correctly.

An unchanged CID after editing is **not a bug**: [ADR-001](../adr/ADR-001-uuid-cid-dual-identity.md) defines the CID as the genesis commitment. Revision identity must be carried separately. Do not “fix” the intended genesis semantics.

### 3. Retrieval quality needs correction, abstention and outcome measurement

**Mixed direct observation and source analysis.** Exact synthetic retrieval worked, but the relevant fixture query used FTS candidates and did not independently prove semantic generalization. The weak irrelevant neighbor demonstrates why a consumer needs a weak-match/insufficient-evidence interpretation or selectable abstention policy.

Reranking occurs after earlier candidate limiting and budgeting in the inspected MCP chain. It can improve ordering within surviving results; it cannot recover candidates already discarded. The older performance numbers in [#2605](https://github.com/alphaonedev/ai-memory-mcp/issues/2605) are not fresh measurements here, and “reranking provides no benefit” would be an overstatement.

One broad recall returned zero rows with nonzero token accounting. Budgeting before later filtering is a plausible explanation, not a proven causal diagnosis. The documented oversized-first-result allowance also means `budget_tokens` is not simply a strict wire-size ceiling. Report candidate, emitted and dropped token counts with reasons an agent can use.

Current [relevance infrastructure](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/bench_relevance.rs#L535) exercises real recall with precision/nDCG/contamination metrics. That is positive evidence infrastructure, principally FTS/frecency in this path. It does not yet establish equal-budget downstream agent advantage across semantic, temporal and contradictory tasks.

Recall purity also needs precision. Removing direct touch from core retrieval did not eliminate exposure-driven reinforcement: [fold_recall_accesses](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/storage/mod.rs#L3241) preserves recall-driven access, TTL and promotion policy in maintenance. The MCP wrapper can also trigger opportunistic GC and folding when expired rows exist; the whole request is not guaranteed mutation-free. Surfaced, consumed, useful and correct are different events. Current production consumption helpers exist; old “dead feedback helper” criticism cannot be copied forward wholesale.

### 4. Shared-agent authorization must hold on every exposed path

**Source-confirmed, not exploited on shared data.** The security juror found unresolved current MCP paths corresponding to [#3379](https://github.com/alphaonedev/ai-memory-mcp/issues/3379) and [#3383](https://github.com/alphaonedev/ai-memory-mcp/issues/3383): share resolves and copies a source without a source-read authorization check; archive purge accepts caller-supplied `as_admin` without an administrator enrollment check in that handler. Generic permission policy can refuse archive access, so exploitability depends on the exposed profile and applicable rules. Where ordinary archive access is allowed, the missing admin check matters; no-rule default permission can allow even in enforce mode. These findings concern the inspected local MCP/shared-store boundary. HTTP purge has a trusted administrator check, and PostgreSQL HTTP share is unsupported; neither enterprise path was demonstrated vulnerable by these findings.

Source: [share](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/mcp/tools/share.rs#L58), [archive purge](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/mcp/tools/archive.rs#L93). No shared-data purge or cross-owner copy was executed in this assessment.

The issue history repeatedly finds the same authority invariant missing from another transport, backend or indirect writer. The durable repair is an unavoidable shared authority boundary, backed by allowed-and-denied operation tests. Closing individual routes remains necessary; it is insufficient as the only strategy.

### 5. Automatic continuity depends on a working host integration

**Reproduced for a named pair.** Installed Codex CLI 0.153.4 rejected the wrapper's default `--system` argument:

```sh
AI_MEMORY_NO_CONFIG=1 ai-memory wrap codex --no-boot -- --help
# exit 2: unexpected argument '--system'
```

The source [default wrapper mapping](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/llm_cli_wrap.rs#L86) corroborates the behavior. Native MCP works—we used it—and current Codex [official MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) documents that route. The defect is in the tested wrapper recipe, not universal inability to connect Codex.

Integration documents contain stale host-capability statements and unconditional continuity language. The historical [#76](https://github.com/alphaonedev/ai-memory-mcp/issues/76) already documents Codex MCP support. Recipe drift wastes agent calls and can silently deprive a newly started agent of its mission. A tested version matrix and a boot sentinel that proves prior state reached the next agent are more valuable than asserting “100% reliable.”

**A second adapter finding was confirmed through an isolated local response probe.** The Python OpenAI and Anthropic capture functions return `True` for a successful MCP envelope whose payload is governance `pending` or `ask`, with no persisted memory ID. The server legitimately returns those outcomes before persistence. All four unpersisted test envelopes were reported successful, without warning. This is false capture acknowledgment, **not governance bypass**. Validate a persisted/deduplication receipt and expose deferred, refused and lost capture separately. A best-effort recorder may continue, but an agent must not mistake that for an acknowledged checkpoint. [Server outcomes](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/mcp/tools/capture_turn.rs#L369), [OpenAI adapter](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/clients/openai-shim-py/ai_memory_openai_shim/_capture.py#L143), [Anthropic adapter](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/clients/anthropic-shim-py/ai_memory_anthropic_shim/_capture.py#L155).

Compact TOON returning handles rather than content is a legitimate design tradeoff. Measure compact-plus-get against inline context. Its existence alone is not a defect.

### 6. Federation and recovery are real, with explicit limits

The current local-first write behavior honestly returns **HTTP 202, durability=local, quorum_met=false** when required replication is not met. This is a useful availability/durability distinction, not inherently a defect. Durable DLQ, replay guards, signed epochs, projection outbox and lifecycle controls are substantive mechanisms. [Under-replication receipt](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/handlers/parity.rs#L71).

PostgreSQL/AGE is not imaginary. Historical enterprise Track A tested graph relations and audit tampering; Track B demonstrated separate model-driven agents exchanging an unknown secret; Track D's superseding final run proved cross-host signed writes, real consolidation, lineage and source tombstones without manual database key binding. These dated results earn credit. [Enterprise campaign](../v1.0.0/test-campaign-2026-08-08-enterprise-cert/).

Current graph operations are not all AGE Cypher. In particular, [PostgreSQL find_paths](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/store/postgres.rs#L12508) uses relational traversal. An AGE label on a dashboard is not a query-plan assertion. Backend-specific unsupported operations should remain explicit; the documented PostgreSQL skills 501 boundary is honest, although it limits a universal endpoint promise.

Contamination propagation and swarm rewind now have actual implementation. In the inspected link path, Reflection→Reflection supersession invokes bounded descendant contamination stamping; this is narrower than universal semantic repair and has a best-effort failure boundary after edge creation. [Link path](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/mcp/tools/link.rs#L400), [rewind handler](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/mcp/tools/swarm_rewind.rs#L170). “No cascade control exists” would be wrong. Proof that every affected agent stopped using stale evidence is still a different test.

### 7. Recovery and release must preserve an authenticated, qualified state

**Source-confirmed limits, with fresh supply-chain checks.** SQLite backup uses a consistent snapshot and staged, checked replacement, and refuses to back up a PostgreSQL corpus through a decoy SQLite path. Those are meaningful protections. Its co-located manifest remains unsigned, directory selection uses filesystem mtime, and restore can report success after ignored directory-fsync errors or warned sidecar-unlink errors. Structural integrity does not prove authorized origin or every crash-durability condition. This supports [#3199](https://github.com/alphaonedev/ai-memory-mcp/issues/3199) and explicit degraded-recovery receipts; no restore failure or data loss was induced here. [Backup implementation](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/cli/backup.rs#L214).

PostgreSQL's convenience JSON export fixes the old 1,000-row cap, but pages and links are fetched without a shared snapshot. Under concurrent edits it is not a proven point-in-time recovery artifact. The HTTP path also discards available per-run withholding/redaction accounting. It already states `portability_complete:false`, so this is a narrower export contract limitation, **not a defect demonstrated in PostgreSQL-native backup**. Expose consistency and non-sensitive partiality counts, and qualify native recovery together with the local governance sidecar and key history. [Keyset export](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/store/postgres_parity.rs#L114), [HTTP export](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/src/handlers/admin.rs#L1016).

Release provenance is real: pinned Actions, locked project builds, checksums, SBOM and OIDC attestations. The juror freshly ran the build-script gate and both mutation self-tests successfully: 90/90 build-script packages ledgered among 548 resolved, of which two were source-reviewed and 88 only inventoried. That distinction is honest. However, the inspected release workflow itself does not require successful test qualification for its resolved commit, does not verify annotation/signature despite its preflight step name, and later checks out the tag name again. Several release-time tools also lack immutable pins or independently checked download digests. External tag rules or operator procedures may supply additional controls; no release-workflow bypass was attempted. Bind every build to the same immutable, qualified source and verify provenance at deployment. [Release workflow](https://github.com/alphaonedev/ai-memory-mcp/blob/87f86a0a1399d8282a60690ce463cba2ba688ebe/.github/workflows/release.yml#L40).

## What the current test data actually establishes

### Restart continuity

The card's 1089/1014/997 ms values correspond to `continuity-a56d9a.json`, recorded September 1 at 20:30:27Z. It reports **91/91, 112/112 and 130/130 acknowledged writes retained**, with mission marker, inbox, recall and post-restart signed-write checks passing. That is meaningful evidence: **333/333 acknowledged writes survived three daemon SIGKILL cycles**.

The producer kills the serving daemon, leaves PostgreSQL and the Python clients running, pauses 0.5 seconds, drains the loaders, restarts, and records `resume_ms` after its readiness wait **before** mission/readback verification. This is a kill-to-readiness interval including deliberate wait and loader drain. The supplied successful runs report health/embedding readiness, but the helper can also return on timeout without requiring embedding readiness; the aggregate retention predicate does not reject that path. It does not measure the next correct model action, recover an unrecorded goal, or verify external side effects exactly once. It checks markers and IDs, not a complete byte/version/plan continuation.

The user clarified that the dashboard key was manually populated from the prior run. We found a script generating timings in separate raw continuity artifacts; that is consistent with manual dashboard transfer. [#3473](https://github.com/alphaonedev/ai-memory-mcp/issues/3473) is the relevant acceptance carrier for machine-produced wake/recovery evidence.

An earlier raw file reports failures despite database growth; the subsequent owner-scoped verification addresses a plausible observation-permission error. Preserve both records and the correction rationale. Neither erase the early red result nor call it proved storage loss.

These tests do not cover PostgreSQL crash, host power loss, lost disk, restored backup, partitioned quorum, lease-fencing during failover or a model process resuming its next action.

### Capacity and scaling

We independently summed the raw result groups behind **2,936.1 → 4,602.3 operations/second** at 256 clients across one versus two modules. The selected result files report no errors.

This workload uses eight concurrent processes with 32 synthetic agent identities each, seeded rows and GET/list/keyword-search loops. The script's default timed rung is 10 seconds; the result files do not carry a complete invocation manifest. It is real SDK/API traffic across endpoints. It is **not 256 reasoning models completing autonomous missions**, semantic recall throughput, or replicated W=2 write capacity.

Do not pool process percentiles by averaging them. Do not conflate independent module scale-out with federated shared-state convergence. Main state explicitly says quorum peering was not wired in that particular session, despite a historical 9/9 cross-host acceptance card.

Published signed-write and semantic-recall numbers depend heavily on remote embedding calls. Dashboard semantic recall p99 rises from 951 ms at 16 clients to 4,018 ms at 64. Those are reported historical workload figures, not this review's fresh benchmark.

### Tool coverage and the NHI mission audit

| Dashboard product | Recorded accounting | Interpretation |
|---|---|---|
| MCP | 104 total; 79 validated, 20 fail-closed, 5 refining | 95% is 99/104 encountered positive-or-negative statuses, not 99 tools proving useful postconditions. |
| Swarm | 22/22 validated; functional=6 | All tools touched; internal totals require reconciliation. |
| Data tier | 13/14 validated | Capacity-at-scale remains refining in that product. |
| Federation | 9/10 validated | Cloud configuration work remains incomplete. |
| Security | 15 validated, 2 fail-closed, 3 refining of 20 | Positive controls and negative refusals must be reported separately. |
| North Star | 22 validated, 1 fail-closed, 2 refining of 25; functional=21 | Counts and labels do not form one consistent outcome measure. |

Sibling products have null `lastUpdated`; the publisher stamps the main state's deployment time. It does not timestamp every underlying measurement. Some “validated” operations returned an empty list, null object, false acknowledgment or zero-row dry run. Those can be correct responses but cannot prove a nonempty transition occurred.

The weighted Grok 4.6 run contains **273 reconciled calls, 48 recall calls, 48 search calls and eight valid questionnaires**. Recall usefulness averaged 4.5/5; six of eight agents said they would rely on it; none accepted the end-to-end latency. Those are informative agent reports from that run, not independent preferences of all AI systems.

The explicit auditor verdict is **FAIL**. A parser originally mistook later prose mentioning PASS for the verdict; the stored result was corrected. Strict mission completion was **0/8**. The evidence included reused mission namespaces, duplicate summaries, reused notification IDs and a forget operation deleting zero rows. Global inventory exposure was reported, while the main dashboard explains the test agents had administrative grants. This is a product-plus-adapter-plus-test-state failure to demonstrate the mission, not proof that the storage engine alone caused all eight failures.

There is a particularly relevant memory hazard: agents continued retrieving old notes that search was broken, while raw current-run searches sometimes succeeded. Durable obsolete advice can be worse than no advice. The required test is whether a verified correction reaches future decisions.

The retained Big-10 artifacts also include an earlier 8/10, a later 10/10 at nominal tip `23b106ad`, and two later 9/11 runs at `b8023dac` with incomplete cold-restart diagnostics. A successful standalone restart afterward does not retroactively turn the whole battery green. Test summaries must retain failures, supersession and evidence links.

Two Big-10 assertions are themselves too weak: a “no plaintext listener” check accepts any HTTP status other than 200, although a plaintext 401 still proves a listener exists; an anonymous-write check accepts anything other than 201, although 202 can mean accepted and 500 can mean broken. These are harness false-green paths, not evidence that either daemon defect occurred in the supplied run. Require the intended transport behavior and an independent no-write postcondition.

## What the reviews and issue history change

The history shows real engineering progress and repeated rediscovery of a smaller set of systemic problems:

1. **Authority at alternate entrances:** a primary mutation is fixed, then an import, restore, federation, CLI or derived writer misses the same rule.
2. **False-success shapes:** accepted work is not persisted, wrong-backend scratch storage is consulted, default fields look authoritative, or a test skips the actual backend and remains green.
3. **State preservation:** revisions, provenance, tombstones, signatures and validity need to survive every copy/archive/restore path.
4. **Evidence drift:** “closed,” “implemented,” “certified,” “all tools exercised” and “current tip green” repeatedly refer to different scopes.
5. **Harness correctness:** global test state, inherited configuration, resource contention and dirty datasets can create both false failures and false passes.

This is not 2,406 independent defects. The inventory includes requests, duplicates, audits, deferred decisions and incorrect allegations. Closed issues sometimes mean documentation delivered or superseded work; open issues sometimes contain a published fix awaiting final verification. [#1395](https://github.com/alphaonedev/ai-memory-mcp/issues/1395), for example, closed a recovery task with primitive tests and scaffold while full scenario glue remained future work. Treating closure as an executed power-loss test would be wrong.

We explicitly rejected obsolete blanket findings: signed epoch consumption is present; local under-replication is now an honest 202; governance rule mutation gained signed transactional behavior; old key-binding criticisms were repaired; real native-tier and agent-to-agent acceptance exists; graph cascade machinery exists; a real relevance harness exists. Old review scores and the number of agreeing jurors are not added together.

Conversely, the project's own [#3308 GA tracker](https://github.com/alphaonedev/ai-memory-mcp/issues/3308) calls for acceptance, final review and documentation reconciliation after repairs. Its September 5 amendment includes the wake-hub work in GA scope. [#3501](https://github.com/alphaonedev/ai-memory-mcp/issues/3501) explicitly requires recertification after identity/federation changes. These are existing commitments, not novel demands invented by this review.

At the inspected GitHub snapshot, the exact reviewed SHA had **8 successful and 3 failed workflows out of 11**. The certified PostgreSQL workflow succeeded on attempt 2; main CI, Batman acceptance and coverage failed. There are also reported successful local final gates and exact-tier application tests, including [#3424's evidence](https://github.com/alphaonedev/ai-memory-mcp/issues/3424). Local green results and a red published CI campaign can coexist. This review did not rerun or diagnose every failed workflow.

Live branch protection had 35 required contexts, strict status checking, administrator enforcement and required commit signatures. It is not an unguarded repository. The separate certificate workflow's existence, however, is not equivalent to requiring its exact context or completing the certificate's documented reissue ceremony. [Exact-SHA CI](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/33987738090), [certified tier](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/33987738088).

## The v1.1 roadmap: right direction, still requiring reconciliation

The user specifically supplied [ROADMAP-v110.md](../ROADMAP-v110.md), which root read in full. It correctly prioritizes use-time applicability, matched no-memory evaluation, honest unknowns, compact-format delivery, scoped feedback and measured cascade containment. It distinguishes deterministic harness plumbing from real-model evidence and puts measurement before new defaults. Those are substantial parts of the path to maximum agent value, already recognized by the project.

My assessment adds three cautions. First, true and faithfully stored information can be inapplicable to the present task; stronger signing cannot solve that. Second, the roadmap is a plan with stale implementation statements: “no swarm rewind” no longer describes this source snapshot. Its blanket no-migration/default-off compatibility prose also needs reconciliation with w8's lifecycle/ranking changes and GA work now pulled forward. Third, a synthetic benchmark should validate trap semantics and balanced controls without selecting or tuning its publication set until it produces a predetermined memory-worse-than-no-memory outcome. That would bias the comparison. Publish genuine null or positive baseline results too.

The roadmap's cited paper figures are attributed inputs, not independently reproduced ai-memory results. A benchmark modeled on a paper is not automatically that paper's official dataset. A session change is not the same thing as a task change, a distinct key is not proof of independent evidence, and observed retrieval frequency is not corroboration. The companion plan explicitly tests those distinctions.

## Three waves of seven adversarial jurors

Seven distinct GPT 6 Astra agent sessions supply the panel; root coordinates and synthesizes and does not count as an eighth voting juror. Each panelist supplies one ballot in each wave: **seven jurors × three waves = 21 ballots**. They are seven recurring reviewers, not 21 distinct model instances or model families. Limited concurrency means batches rather than seven simultaneous executions.

| Juror | Lens |
|---|---|
| A — retrieval_juror | Retrieval fidelity and epistemic interpretation |
| B — security_juror | Identity, authorization, governance and attestation |
| C — enterprise_juror | Native tier, federation and reliability |
| D — continuity_juror | Real host capture and restart-to-action continuity |
| E — cognition_juror | Applicability, learning and experimental validity |
| F — operations_juror | Recovery, supply chain and release qualification |
| G — architecture_juror | Storage composition, export and contract parity |

Wave 1 records independently assigned investigations. The original A/B/C investigations are retained; D/E/F/G expanded the panel when the seven-per-wave requirement was clarified. The earlier three-juror cross-examination and provisional final reviews are preliminary and do not count toward the required 21. Some original ballots retain explicitly marked later corrections. All panelists inherited task context, so even first-wave independence is procedural, not blinded external independence.

Wave 2 requires every juror to read all seven first-wave ballots and challenge positive and negative claims. Wave 3 adjudicates both final documents, recording value, grand-slam and broad mission-critical votes, required changes and residual dissent. All share a model family, source and tools; later discussion increases correlation. Voting organizes objections; evidence decides them. No numerical probability of safety or universal AI preference follows from agreement.

All **21 ballots are complete**. All seven final jurors accepted **both documents** with no substantive correction outstanding. Their acceptance includes the mechanical final tally, coverage and evidence bookkeeping recorded here.

| Final juror | Agent value | Universal grand slam | Broad mission-critical reliance | Both documents |
|---|---|---|---|---|
| A | Conditional YES | NO | NO | ACCEPT |
| B | Conditional YES | NO | NO | ACCEPT |
| C | Conditional YES | NOT PROVEN | NOT PROVEN | ACCEPT |
| D | Conditional YES | NO | NOT PROVEN | ACCEPT |
| E | Conditional YES | NOT PROVEN | NO | ACCEPT |
| F | Conditional YES | NOT PROVEN | NO | ACCEPT |
| G | Conditional YES | NOT PROVEN | NO | ACCEPT |

Thus **7/7 find practical value; 0/7 endorse demonstrated universal leadership; 0/7 endorse broad mission-critical reliance today**. NO and NOT PROVEN remain distinct judgments. None means every bounded deployment is unsafe. The same value/grand-slam split appeared in waves 1 and 2; the separate broad-readiness proposition was not uniformly labeled in the earliest A/B/C ballots, and missing votes were not invented retrospectively.

The [21-ballot registry](gpt6-astra-20260905-evidence/ballot-registry.json) preserves file hashes and exact dispositions. Cross-examination rejected durable-corruption, cryptographic-bypass, absent-enterprise-tier, absent-rewind and universal-backup-failure overclaims. It added the capture receipt, export/recovery and release-qualification findings, and sharpened the comparative tests. One historical W2 citation typo is explicitly corrected in the final security ballot: export-screening lines 416–421 and 439–496 belong to `src/export_taxonomy.rs`, not `src/store/postgres_parity.rs`. The original ballot remains intact.

## What would make it my first choice?

Five deliverables, in this order:

1. **A truthful, safe agent contract.** Fix #3404 and the remaining authority holes; make every supported read/write agree on revision, identity, scope, lifecycle and attestation. Unsupported must be explicit and side-effect free. Separate signed content, signed relationship and unverified assertion.
2. **A reliable agent integration.** Boot the real supported host, prove it receives mission and checkpoint state, teach it a small dependable workflow, and test the exact installed versions. Detect missing capture, stale adapters and inactive protection in the same endpoint the agent uses.
3. **Correction that changes behavior.** Test stale and poisoned memory, recorded derivation cascades, repair, consumption evidence and cross-agent correction acknowledgments. Measure whether agents stop acting on superseded claims.
4. **Proved recovery and deployment boundaries.** Reissue the certificate on the actual release artifact. Test the real enterprise tier across hosts, partition, database/daemon/agent crashes, key changes and backup restoration. Report local commit, replica acknowledgment, convergence, agent resume and external-effect reconciliation as distinct outcomes.
5. **A reproducible workload advantage.** Under equal model, token, time and infrastructure budgets, beat no memory, files plus CodeGraph, and a straightforward retrieval baseline on completed missions, harmful mistakes, correction latency and operating cost. Publish failures and the supported envelope.

Existing v1.1 roadmap work already recognizes downstream task evaluation, applicability and feedback. Build on it. Do not destabilize the release with a wholesale storage rewrite solely because the modules are large; use the recurring failures to select incremental contract boundaries and meaningful regression tests.

For a mission-critical agent I would require a declared operating envelope, enforced identity, recoverable data and keys, tested correction paths, explicit degradation and a responsible operational owner. These requirements do not demand perfection or immunity to every prompt injection. They demand that the system tell the truth about what it has done and preserve that truth through failure.

**Final assessment: real value, substantial engineering, credible potential; current blanket grand-slam claim rejected. The next decisive achievement is dependable, measurable agent work—not additional breadth.**
