# Boids emergence and ai-memory — 3x7 adversarial assessment (enterprise federation, PostgreSQL + Apache AGE + pgvector)

**Question.** Where does ai-memory sit in the Boids model of emergence as it applies to AI agent clusters, swarms and hives? The scope is the v1.0.0 GA **enterprise federation configuration** (PostgreSQL + Apache AGE + pgvector). Agents use ai-memory as their **endpoint memory** and coordinate over the **rust-a2a wake plane**. Tracking issue: #3922.

**Code under review:** `release/v1.0.0` at `c926f059b` (promotion 3), read-only checkout.

**Sources.**
1. Grokipedia, *Boids* (<https://grokipedia.com/page/Boids>), and Reynolds (1987).
2. A Google AI Mode answer. The share link could not be fetched; the operator supplied its text afterwards. It is quoted in the appendix and treated as **claims to test**, not as evidence.
3. **#3266**, *agent swarm / hive groupthink cascades and memory contamination*. The operator made it a required input. It is the Boids problem viewed from the failure side.

## Verdict

**ai-memory is the flock's environment, not a boid and not a controller.** It is the shared field that agents sense and deposit into (stigmergy). On the PG enterprise configuration that field carries the **messages** a steering rule could use. It computes none of the three Boids rules itself. Its one built-in steering term makes a same-DNA swarm *more* likely to turn together: recall ranking rewards popularity. And the swarm cannot yet sense or stop a contaminated turn on PG.

| # | Topic | Pass-1 majority | Final | Decision |
|---|---|---|---|---|
| T1 | Position of ai-memory in the scheme | ENVIRONMENT 7/7 | ENVIRONMENT 7/7 | **ENVIRONMENT** (a stigmergic field) |
| T2 | Separation | PARTIAL 7/7 | PARTIAL 7/7; call paths show it is *weak* on PG | **PARTIAL (weak on PG)** |
| T3 | Alignment | PARTIAL 7/7 | PARTIAL 7/7; carriers narrowed | **PARTIAL**: the substrate carries messages and computes no alignment |
| T4 | Cohesion | PARTIAL 7/7 | PARTIAL 7/7 | **PARTIAL**: structural, not dynamic |
| T5 | Perception neighbourhood | HYBRID 7/7 | HYBRID 7/7 | **HYBRID** (metric + lexical + nominal-k + scope mask) |
| T6 | Decentralisation | HYBRID 7/7 | HYBRID 7/7 | **HYBRID**: central cells, leaderless eventual replication between them |
| T7 | Failure modes (predator) | PARTIAL 7/7 | **UNCONTROLLED 7/7** after #3266 was factored in | **UNCONTROLLED on PG** (supersedes PARTIAL) |
| T8 | Recommendation | WATCH 5/7 → 6/7 | **V1.1-FEATURE 7/7** after #3266 was factored in | **V1.1-FEATURE**, plus unanimous v1.0.x asks (below) |
| T9 | Endpoint memory | BOTH 7/7 | BOTH 7/7 | **BOTH**, split by transport (below) |
| T10 | rust-a2a wake plane as the perception channel | HINT-ONLY 7/7 | HINT-ONLY 7/7 | **HINT-ONLY**: it tells an agent to read the field; it is not a way of sensing it |
| T11 | #3266 stages on PG at `c926f059b` | mean 11/27/28 | mean **12/29/32** (range 11-12 / 28-30 / 31-32) | **12 / 29 / 32** (prior: 12/32/36 at `19892abf`) |

The tally rule was fixed in advance: **5/7 decides**, and 3-4/7 goes to the Conductor. Every categorical topic was decided 7/7. Only T11 went to adjudication, because its ballots are numeric. Its final ballots spread by at most two points per stage, so the arithmetic mean is adopted, following the #3266 precedent of averaging per-stage percentages.

## Where ai-memory sits (T1), and what "emergence" means here

Boids has three parts: the **agents** (boids), their **local rules**, and the **space** they move through. ai-memory is the third. Agents write memories, signals and inbox rows, and other agents later sense those rows through recall. Recall is filtered by scope and ranked by text match, similarity, confidence, recency and popularity. That is **stigmergy**: coordination through modifications to a shared medium, as in termite nest-building or ant pheromone trails, and not flocking by direct observation.

Three consequences follow, and every lens accepted them:
- **The rules live in the agents.** Whether a swarm separates, aligns or coheres is decided by the harness and the model. ai-memory makes the field richer or poorer, and it makes some deposits louder than others.
- **The field is not neutral.** Ranking decides which deposits an agent senses first. On PG, ranking includes a popularity term (see T7/T11), so the field **amplifies** whatever many agents have already read. In Boids terms, this is an alignment force added by the environment. It is also exactly the mechanism of #3266's groupthink cascade.
- **"Emergence" is not a product claim.** Nothing in v1.0.0 measures, bounds or certifies emergent swarm behaviour. This document is a mapping, and it makes no performance or capacity claim.

## Findings by topic

Each finding is labelled with its evidence class. **CODEGRAPH-PATH** means the call path was traced with codegraph and then confirmed at `path:line`. **GREP-CONFIRMED** means the hop was confirmed by line in the tree. The codegraph index never surfaced `PostgresStore` methods, so **every PG hop below is GREP-CONFIRMED**. Codegraph established the SQLite and trait-side paths.

**T2 Separation: PARTIAL, weak on PG.** Nothing in the substrate repels agents from each other on PG:
- **Leases** are the single-holder action grant. They are SQLite-only in practice: MCP `memory_lease_acquire` → `mcp/tools/action.rs:468` (rusqlite) → `actions/mod.rs:637`. `PostgresStore` has lease methods, but they have no production caller (`store/mod.rs:3731-3759` says so). The HTTP action transition reads a PG lease table that nothing writes.
- **The near-duplicate ≥0.95 refusal and the contradiction hint** run only on the SQLite create path (`handlers/create.rs:1872`, `:1880-1890`). The PG create returns early at `:1669` into `create_memory_postgres`, which has no such probe.
- **What does reach PG:** the exact `(title, namespace)` 409 (`create.rs:1163-1167`, with a race backstop at `:1413`), the `scope=private`/namespace SQL predicates (`postgres.rs:24089`, `:25799`), and TTL/size bounds on the HTTP signal lane.
- **Opt-in sensing** also reaches PG: `POST /api/v1/check_duplicate` (`power.rs:797` → `postgres.rs:34116`) and `GET /api/v1/contradictions` (`power.rs:116`). An agent has to call these itself, so they are collision *detection*, not repulsion.

**T3 Alignment: PARTIAL.** Two carriers reach PG. The first is HTTP notify, which writes an inbox row plus a digest-only wake doorbell and re-wakes on peers. The second is shared recall within one scope and embedding space. Signals are Ed25519-signed, federated and verified on receive, **but no agent-facing entry point reads the PG signals table**. Namespace standards on PG are per cell and are **not federated on write**. Both are recorded as parity defects, not swarm features. The wording that survived every attack is the adversary's: *ai-memory carries the messages an agent-side alignment rule could use; no alignment is computed.* The one exception runs the wrong way: the popularity term (T7).

**T4 Cohesion: PARTIAL, structural rather than dynamic.** The shared centre is the namespace/scope hierarchy plus a hop-capped `memory_links` walk, and an agent must fetch it. With AGE installed, current-view `kg_query` and lineage are answered by AGE Cypher over a projection of `memory_links`, with parity enforced. `find_paths`, historical queries and fallbacks are answered by a recursive CTE (`kg.rs:1163` → `postgres.rs:12731`). So *graph = memory_links, with AGE as an optional accelerator.* Two unanimous round-1 claims were wrong and are corrected here:
- AGE does answer the current view. It is not the case that every PG neighbourhood result comes from the CTE.
- Cosine consolidation is not SQLite-only. The SAL `ConsolidationPass` runs against PG through `ai-memory curator --store-url postgres://`. It is off by default and operator-driven, and it has no centroid.

Nothing pulls an agent toward a centre.

**T5 Perception neighbourhood: HYBRID.** On the PG recall path (`handlers/recall.rs:414` → `:556` → `postgres.rs:25734`) the neighbourhood has four parts:
- **Metric:** a hard cosine > 0.2 radius on the semantic pool, written as an SQL literal rather than the `RECALL_COSINE_GATE` constant, with a length-adaptive 0.50-0.15 similarity weight.
- **Lexical:** an ungated FTS union pool.
- **Topological:** a nominal k of at most 50 on HTTP (`recall.rs:436`). Its ANN candidate pool depends on HNSW `ef_search`, **which the product never sets**. So the perceived neighbourhood is **not** a fixed k-nearest set under selective filters. This is recorded as a documented limit.
- **Scope:** a mask applied to recall and to every KG hop. KG hops are capped at 5 (`kg_query`) and 7 (`find_paths`).

**T6 Decentralisation: HYBRID.** Each site is a **central, single-primary** PG + AGE + pgvector cell. Between cells, replication is **leaderless and eventual**:
- **Push-receive** field-merges same-id rows: `sync_push` → `sync_push_via_store` → `PostgresStore::merge_inbound` (`postgres.rs:25284`) → `merge_memory`. It falls back to last-writer-wins for absent or cross-id rows.
- **Pull/catch-up** uses whole-row LWW.
- **W-of-N quorum** is an advisory ack SLA on the HTTP create path. The local commit is never rolled back.
- `src/sequencer.rs` has **no production caller**, so there is **no leader and no total order**.

In Boids terms, the federation is a set of flocks that couple only through eventual copying (the distsys dissent), not one flock with global perception.

**T9 Endpoint memory: BOTH, split by transport.**
- **INTERNAL-STATE (the boid's own memory):** only the local SQLite store of an MCP-stdio endpoint. Its notify and inbox tools never forward, even when a forward URL is set (`mcp/mod.rs:2801`, `:2824`).
- **SHARED-FIELD:** every PG row, **including `scope=private` rows**. A private row is shared-field matter with a per-reader mask. It is hidden from other readers but not encapsulated: it is stored in plaintext and replicated to peers (see *Private rows on the push lane*).

"Private" on PG means *only the depositor may sense it*. It does not mean *it lives only in the depositor*.

**T10 rust-a2a wake plane: HINT-ONLY.**
- The frame is `WakeMeta`: ids, sender, namespace, an unkeyed sha256 digest and a sequence number, with **no body** and at most 256 B. The durable `_inbox` row is the record, and a poll of at most 60 s is the guarantee (`docs/a2a-integration.md`).
- The hub sink is **off by default**: `[wake_hub].sink_socket` is unset.
- Wakes fire only for notify rows, never for ordinary field writes.
- There is no cross-host hop of its own. Federation is the only cross-host path.

The plane is a **trigger to read the field**, not a perception channel.

Two misuse notes were recorded:
- The unkeyed digest can act as a confirmation oracle for low-entropy vocabularies.
- A namespace-topic wake could carry about 248 B that nobody validates.

Millisecond wake latency is a design target and is not measured (#3473), so no Boids-speed claim is made.

## #3266 factored in: the predator the flock cannot see (T7, T11)

#3266's two failure classes run through the field:
- **(A) groupthink cascade:** same-DNA agents align on one agent's error.
- **(B) contamination:** bad state that every agent sensing it inherits.

The codegraph verification of every #3266 mechanism on the PG path at `c926f059b`:

| #3266 mechanism | On PG at `c926f059b` | Evidence |
|---|---|---|
| `DEFAULT_CONFIDENCE = 1.0` | **Present.** A bare HTTP write lands at 1.0 and gets the maximum +2.0 rank. Only `confidence_source='default'` is now recorded, and ranking does not read it | `models/memory.rs:1898`, `:1996`; `create.rs:421`; `postgres.rs:9465`, `:25778` |
| Popularity amplifier in ranking | **Present, and stronger than #3266 scored it.** `LEAST(access_count,50)*0.1` is in both PG lanes. The always-on PG fold loop also raises priority (cap 7) and promotes mid→long at 5 accesses, so popularity can add about **+8** of rank against a +2 maximum for confidence. It counts served results, not distinct readers. There is no trust or provenance term | `postgres.rs:9464`, `:25777`; `daemon_runtime.rs:4289-4306` → `postgres.rs:29060-29080` |
| Contradiction down-weight | **Missing from PG `recall_hybrid`**, which drops the soft-loser factor that `search_with_source_uri` applies. PG also has no contradiction producer | `postgres.rs:9488` vs `:25734ff`; `cli/curator.rs:346-354` |
| #3322 `memory_swarm_rewind` | **SQLite-only.** No HTTP route, no `PostgresStore` or trait method. The CLI verb on a PG node opens the local placeholder SQLite and lacks the `refuse_pg_store` guard its siblings have | `mcp/mod.rs:2403` → `swarm_rewind.rs:180`; `cli/commands/swarm_rewind.rs:71`; compare `calibrate_confidence.rs:123` |
| #3323 cost accounting | **Write-only on PG.** Accrual happens, but the rollup readers have zero non-test callers. It meters content tokens, not LLM spend | `cost/postgres.rs:42`; readers `:184`, `:225`, `:281` |
| #3324 `Contaminated` propagation | **SQLite-only, and narrow even there** (MCP `supersedes` where both ends are reflections). PG hides rows that are already contaminated but never writes the state | `mcp/tools/link.rs:457` → `storage/mod.rs:13592`; PG read side `postgres.rs:25808`, `:25926` |
| Model-family decorrelation gate | Reaches PG, but is **inert by default**: Advisory, reflect writes only, and silent when no attestations exist | reflection lane (PG and SQLite parity) |
| Record-stop | A real **per-cell** brake on every PG write funnel. It is global per cell, not per namespace, **not fanned out** to other cells, and reads stay live | `postgres.rs:3470`; `federation_signing_check.rs:289` |
| Cascade / burst / storm detector | **Absent** on both backends (deferred to v1.1 by #3266) | none |

**T7: UNCONTROLLED on PG, 7/7.** On PG the flock has a brake (record-stop) and a filter that hides tainted rows on read, **but no sensor and no dampener**. Nothing detects a cascade, nothing writes the taint, and the ranking feedback loop amplifies what spreads.

**T11: #3266 stages on PG, 12 / 29 / 32** (prior 12/32/36 at `19892abf`). Stage 1 is unchanged: a memory layer cannot stop an idea forming in a model. Stage 2 falls, because the popularity ladder via the PG fold loop and the missing PG soft-loser make propagation easier than the prior vote credited. Stage 3 falls, because the prior figure assumed Stage-3 primitives that, on this configuration, do not reach PG.

Several judges dissented from reading this as regression. The MVG shipped **after** the prior vote, and it adds **nothing** on PG, so part of the drop comes from scoring the enterprise configuration specifically, not from code getting worse. The adopter's summary: *a buyer should not read 12/29/32 as "stable"; it holds only because the fix marketed as the #3266 answer adds zero on the enterprise configuration.*

**Private rows on the push lane.** Four round-3 dissents in pass 2 claimed a cross-peer scope leak. A dedicated codegraph verifier ruled it **BY-DESIGN-REPLICATION**, severity MEDIUM, as a custody/residency issue.
- The push lane (`federation/sync.rs:651`; PG create `create.rs:1451`) ships **every** row, including `scope=private` and private-by-default inbox rows, to every configured peer.
- The pull lane withholds the same rows (`federation_sync_since.rs:195-250`).
- Transit is TLS-only and signed (`tls.rs:183`).
- On the peer the owner predicate is re-applied (`postgres.rs:24089`), so **no other agent can read the row there**. But the row is stored in plaintext at rest, where the peer's operator can read it.

This is recorded here and was raised separately. It is not a visibility breach.

## Recommendation (T8: V1.1-FEATURE, 7/7)

**Unanimous v1.0.x asks.** These are documentation and a guard, not features:
1. State in the GA notes that #3322 and #3324 are **SQLite-only** and that the #3323 PG rollup readers are absent.
2. Correct the false-parity comment at `src/store/postgres.rs:8211-8214`. It says the supersedes path stamps dependents `contaminated`, and on PG nothing writes that state.
3. Add `refuse_pg_store` to the `swarm-rewind` CLI (`cli/commands/swarm_rewind.rs:71-77`) and a PG refusal to the MCP dispatch (`mcp/mod.rs:2403`).
4. *(SRE, CISO, adopter)* Wire readers for the PG #3323 cost rollups, so the cost of a cascade is visible on the enterprise path.

**v1.1, in Boids order: cut the alignment gain, then add the sensor, then the actuator.** Six of seven lenses back this order.
1. **A trust term in ranking.** Count popularity per distinct reader, and stop recall-driven priority, tier and `updated_at` escalation. This removes the environment's own alignment force.
2. **Change `DEFAULT_CONFIDENCE`**, or have ranking read `confidence_source='default'`.
3. **Cascade detection (the sensor).** Port the contradiction pass and soft-loser producer to PG, and scope record-stop by namespace or lineage with fan-out to other cells.
4. **PG parity for rewind and the `Contaminated` stamp (the actuator).** One recursive-CTE update over `derives_from`, plus a merge rule that keeps taint monotone, because `lifecycle_state` currently merges by last-writer-wins (`crdt_merge.rs:955-985`).
5. **The corroboration gate, last.** Sybil-correct "independent writer" is the hard part.

Minority (vector): put item 4 first. The PG read side already hides contaminated rows in both pools, so one writer gives real containment even with a manual trigger.

## Source 2 (operator-supplied summary), claim by claim

| Claim | Status | Why |
|---|---|---|
| Endpoint memory is one bird: local, private, fast | **PARTIAL** | True only for the MCP-stdio local SQLite. On PG a "private" row is shared-field matter with a per-reader mask, replicated to peers (T9) |
| Collective memory is the overlap, copies, votes, last-write-wins and gossip; no agent owns it | **SUPPORTED** | Push/pull replication, LWW fallback, eventual consistency, no leader (T6) |
| Flip the coupling rules (who reads or writes whom, how often, with what quorum) and the same agents produce a different hive | **SUPPORTED** | Scope, peer lists and the advisory W-of-N are exactly those parameters |
| Separate = don't overwrite your neighbour's local truth | **PARTIAL** | Exact-key 409 and same-id field merge on PG; leases and near-dup refusal are SQLite-only (T2) |
| Align = match the heading of nearby memories | **PARTIAL, and inverted by ranking** | The substrate computes no alignment, but its popularity term aligns agents on whatever spreads (T3, T7) |
| Cohere = drift toward the cluster's centre (the quorum, the shared store) | **NOT-SUPPORTED** | Nothing pulls agents anywhere. W-of-N is an ack SLA, not an attractor. Cohesion is structural (T4) |
| You cannot inspect one agent's memory and know what the swarm believes; safety lives in the coupling | **SUPPORTED** | T7: the risk sits in ranking and replication, not in any endpoint |
| Treat federation, quorum and write visibility as the three rules | **PARTIAL** | Those are the **coupling parameters**. The force that actually steers a same-DNA swarm through this substrate is **recall ranking**, which the summary omits |

The two framings can be reconciled. Source 2 says "the product is the flock those rules emit". The vote says ai-memory is the environment. **The field is where the coupling rules are enforced**, so ai-memory does not *emit* the flock, but it sets how strongly agents are coupled. That makes it responsible for the gain in the feedback loop.

## Corrections the attack rounds forced

Seventy-one agents cast votes across the three passes. The attack rounds checked 52 call paths on T9/T10 (38 held) and 89 citations and call paths in pass 3 (80 held). In pass 1 there were 14 failed citation checks. The load-bearing corrections:
- **"Total ordering uses a leader elected by quorum" is false.** `src/sequencer.rs` has no production caller.
- **"The CRDT merge is not wired" is stale.** `merge_inbound` → `merge_memory` is wired on PG via `federation_signing_check.rs:678`.
- **"k is capped at 1000" misread `lib.rs:97`**, which is the 0.2 cosine gate. The HTTP recall cap is 50 (`handlers/recall.rs:436`).
- **"A fixed 0.7 blend" was wrong.** 0.7 is the primary-context blend. The FTS/cosine blend is adaptive, 0.50→0.15.
- **The hop ceiling of 16 (`kg/cycle_check.rs:26`) bounds write-side cycle detection**, not perception.
- **Autonomy cosine clustering (0.75) runs on SQLite.** The PG consolidation path is the SAL `ConsolidationPass` via the curator.
- **Tags on same-id merges are unioned, not replaced.**
- **"swarm_rewind contains the PG cascade" was withdrawn** once the call path showed it is SQLite-only.

## Recorded dissent

- **distsys:** In the Boids sense the federation is not one flock. It is a set of flocks that do not sense each other. PG parity for rewind will not fix a federated fleet while `lifecycle_state` merges last-writer-wins.
- **graph:** Credit AGE only as an accelerator of the current view. Every neighbourhood result an agent depends on is also reachable via the CTE.
- **vector:** The perceived neighbourhood is not a fixed k-nearest set, because `ef_search` is never set. Fix the actuator before the sensor.
- **ciso:** Semantic-poisoning containment on PG is uncontrolled. Every PG control proves authorship, form or freshness, never truth.
- **sre:** The measurable swarm risk is crowding in the shared field: one un-partitioned wake ring per node, a 32-permit webhook lane, a 1000-row PG prefix-scan cliff and an unset `ef_search`.
- **adopter:** For a buyer, the Boids framing misleads more than it helps unless it carries the disclaimers in this document.
- **adversary:** Applied to v1.0.0, the Boids framing is mostly marketing. None of the three steering rules lives in the substrate on PG.

## Method and provenance

Seven lenses (distsys, graph, vector, ciso, sre, adopter, adversary) voted across three rounds per pass: an independent ballot, an attack on the majorities with citation re-checks, then a final vote with changes flagged and dissent recorded. The tally was mechanical and computed in code: 5/7 decides, and 3-4/7 goes to the Conductor.

| Pass | Workflow | Topics | Agents | Codegraph |
|---|---|---|---|---|
| 1 | `wf_3b6a85a9-56b` | T1-T8 | 21 | **0 calls.** Grep-based; recorded as a method gap on #3922 |
| 2 | `wf_78510597-da3` | call-path verification of T2-T7, then T9-T10 | 6 + 21 | 31 verifier calls plus 3-7 per ballot |
| 3 | `wf_544b528b-6a8` | #3266 verification and private-push verification, then T7r, T8r, T11 | 2 + 21 | 7 verifier calls plus about 1 per ballot |

Every ballot was cast against the same read-only tree at `c926f059b`. Codegraph (`codegraph_explore`, pinned to the release-dev index) was the only codegraph tool available to the agents. Its line numbers lagged the release tree by 10-194 lines, so every hop was confirmed at `path:line` in the tree. The index never surfaced `PostgresStore` methods, so every PG hop is GREP-CONFIRMED. The raw ballots, attacks and tallies are in the deputy session's archive and the workflow journals.

This is a decision document only. It changes no product code and triggers no release. It makes no performance, capacity or certification claim.

## Appendix: Source 2 (operator-supplied text, verbatim)

> **Executive summary.** Emergence in an agent swarm means the hive does things no single agent was told to do. Each agent only sees neighbors and its own memory. The flock — consensus, drift, silence, a shared "truth," a collapse — appears from the *rules between* them.
>
> **How memory splits.** *Endpoint / individual memory:* what one agent actually knows. Local, private, fast. Like one bird's three neighbors. It cannot see the hive's shape. *Collective memory:* what the swarm *behaves as if* it knows. Not one file. It is the overlap, the copies, the votes, the last-write-wins, the gossip that stuck. No agent owns it. Flip the coupling rules (who can read/write whom, how often, with what quorum) and the same agents produce a different hive-mind.
>
> **What actually happens.** Agents don't "share a brain." They couple memories: copy, cite, contradict, forget, federate. Separate = don't overwrite your neighbor's local truth. Align = match the heading of nearby memories (same facts, same policy). Cohere = drift toward the cluster's center (the quorum, the shared store). Those three, running locally, *are* the collective memory.
>
> **Why it matters.** You cannot inspect one agent's memory and know what the swarm believes. Safety, governance, and "what did we decide?" live in the coupling, not in any endpoint. Change who syncs with whom and the hive changes; the agents can stay the same.
>
> **Design rule.** Treat endpoint memory as a bird. Treat federation, quorum, and write visibility as the three rules. The product is the flock those rules emit — not the sum of the notebooks.

*Prepared by the deputy session (Claude Opus 5.5) from three 3x7 passes on 2026-09-23. Operator-approved for merge under `release/v1.0.0` `docs/reviews/`. Related: #3922, #3266.*
