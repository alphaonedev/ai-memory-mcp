# Graph Engineering — ai-memory development process & standard

**Status:** active — governs AI-NHI development on this repository
**Adopted:** 2026-07-27 (v1.0.0 GA campaign)
**Supersedes:** the loop-in-head orchestration described in `.local-runs/HANDOFF-NEW-ACCOUNT.md`

---

## 0. The principle everything follows from

> **You do not fix the code. You fix the process that produced the code.**

When a reviewer catches the same mistake in a third file, the wrong move is to fix three
files. The right move is to add one sentence to the rulebook and regenerate the batch.
Individual failures are the loop's job. Attention belongs on the patterns.

Corollary: **if you are hand-patching agent output, you are working inside the agent's job
instead of building the thing that does it.**

Two standards sit alongside it:

> **Data tier: absolute perfection.** A fix is not done when its own test passes. It is done
> when the full data-tier matrix passes against it. (Operator standard, 2026-07-26 —
> enterprise customers are the bar.)

> **A self-skipping test is NOT a pass.** A test that skips because an extension or feature
> is absent is an untested surface, not coverage.

---

## 1. Loops vs graphs, and why this repo uses a graph

Most agents are **loops**: the model thinks, calls a tool, reads the result, thinks again,
until it decides it is done. Control lives inside the model. You see the input and the
output and almost nothing in between — so when it fails at minute forty, you do not know
which minute went wrong.

A **graph** moves control outside the model. Steps are named, edges are declared, state
lives on disk. The model still does the thinking, but inside nodes that were drawn in
advance. Some nodes use no model at all — a script, a compiler, a test suite.

Four properties follow:

| Property | Why it matters here |
|---|---|
| **Failure is located** | it happens at a named node, not "somewhere in a long run" |
| **Runs are resumable** | state is on disk, so a killed run restarts where it stopped |
| **Branches parallelise** | independent nodes run concurrently, conflict-checked by computation |
| **Boring parts are deterministic** | a script decides, instead of paying a model to guess |

### When NOT to use a graph

A graph requires knowing the shape of the work in advance. That is the whole trade.
Skip it when:

- **The task runs once.** Setup cost amortises across repetitions; building a judge and a
  rulebook to process eleven files is slower than doing the eleven files.
- **The steps are unknown.** Research, unfamiliar debugging, exploring a new codebase.
  A loop will find a path you would not have drawn; locking topology early locks in a wrong
  guess.
- **No mechanical judge exists and none can.** If correctness genuinely needs human taste on
  every item, reviewer nodes become theatre.

**Middle path:** run a loop first to learn the shape, keep notes on every correction, and
those notes become the first rulebook. Build the graph for the second run.

**This repo qualifies** because the v1.0.0 fix campaign is ~30 lanes of repeating shape
(find defect → fix → test → review → merge → close) with a mechanical judge available (CI,
plus the checks below).

---

## 2. The eight steps

### Step 1 — Build the judge before anything else

An agent without an exit condition never finishes. It stops when it *feels* done, which is
a mood, not a condition.

Before writing any instruction about the work itself, decide **how a machine tells you the
work is correct**. Not a human reading the output. A machine.

**Artefact:** `scripts/judge.sh <pr-number>` → exit `0` pass / `1` fail, printing why.

Six mechanical checks, each citing a rulebook ID:

| ID | Check | Rule |
|---|---|---|
| J1 | 0 *genuine* CI failures on a settled head | R-403 |
| J2 | src changed ⇒ a test file was touched | R-203 |
| J3 | sqlite changed ⇒ postgres twin, or a stated reason | R-303 |
| J4 | size-ceilinged file grew ⇒ ceiling re-measured | R-401/402 |
| J5 | no `/tmp` path introduced | HARD-RULE |
| J6 | PR body cites `Closes #N` | R-502 |

J1 is deliberately not "did `gh pr checks` say pass" — it queries the check-runs API for
`conclusion=="failure"`, because the rendered label reports a *cancelled* concurrency-twin
as `fail`.

### Step 2 — Break the judge on purpose

A judge that never fails is decoration, and every green result downstream of a blind judge
is meaningless.

**Artefact:** `scripts/judge-selftest.sh` — validates in **both** directions:

- **Positive:** three real merged PRs must PASS. A judge that rejects known-good work is too
  strict and will block real progress.
- **Negative:** four synthetic breakages must FAIL, **and must trip the correct rule**. A
  check that fires accidentally is not a check.
- **Control:** the sqlite-only-*with-rationale* case must be **allowed** — this distinguishes
  a working judge from one that rejects everything.

Run this before generating anything at scale.

### Step 3 — Write the rulebook, and never patch around it

**Artefact:** `rules/rulebook.md` — read by every lane before it touches anything.

Two properties make it work:

1. **It grows.** Every reviewer catch the rules did not cover becomes a new sentence.
2. **Nothing bypasses it.** The moment output is hand-edited to match what the rulebook
   *should* have said, there are two sources of truth and one is in someone's head.

Every rule has a **stable ID** so reviewers can cite it. Rules are grouped:

| Series | Concern | Examples |
|---|---|---|
| R-100 | build & resources | R-101 never compile in a lane · R-103 `cargo clean`, not `rm -rf` |
| R-200 | verification | R-202 self-skip ≠ pass · R-203 prove tests load-bearing · R-204 `contains` cannot detect drift |
| R-300 | completeness | R-301 footprint from codegraph not grep · R-303 both backends |
| R-400 | measurement | R-401 measure, never inherit a number · R-402 max-wins insufficient when changes stack |
| R-500 | process | R-501 check backlog before filing · R-502 close the audit trail |

Every rule carries **provenance** — the specific incident that produced it. These are not
generic best practices; they are the recorded ways this campaign broke.

### Step 4 — Stress-test the rules on three items, then delete the work

**Artefact:** `scripts/rule-stresstest.sh <task1> <task2> <task3>`

Run three items twice — **with** the rulebook and **without** it — and diff. Every
difference is a place where the rules are missing, wrong, or *worse than the model's
default*. Fix the rulebook, not the files.

Then **delete everything produced**. The goal was never the three artefacts; it was the
rules. Keeping the output is how the first three items follow one convention and everything
after follows another.

### Step 5 — Put state on disk, not in the context window

**Artefact:** the ai-memory coordination substrate itself (`actions`, `action_edges`,
`leases` — schema v59), namespace `campaign/v1.0.0-ga`.

The work queue is **rebuilt from durable state on every run**. Nothing about it lives in a
conversation. The consequence: the process is **resumable by construction** — kill it at 60%,
restart, and it resumes at 60% because the substrate remembers.

This is also deliberate dogfooding: the campaign's control graph runs on the product's own
coordination primitives.

### Step 6 — Two reviewers who cannot see each other, citing rule IDs

One reviewer sharing context with the worker will agree with the worker — it has seen the
reasoning and is primed to accept it.

**Artefact:** `scripts/review.sh <pr-number>` — two fresh sessions, each seeing **only** the
diff and the rulebook.

Required output shape:

```
RULE: <rule-id> | ISSUE: <what is wrong, with file:line>
RULE: GAP | ISSUE: <problem> | SUGGESTED-RULE: <the sentence that should be added>
PASS
```

The **citation is what closes the loop**:

- A citation turns a vague complaint into a queue item.
- **A rule cited three times across different lanes is not three problems — it is one badly
  written rule.** Rewrite that line and re-run the affected batch.
- A `GAP` finding makes a rulebook hole as reportable as a code defect.
- **Reviewer disagreement usually means the rulebook is ambiguous at that spot.** That is an
  edit, not a coin flip.

The script rolls up citation frequency across *all* reviews so patterns are visible.

### Step 7 — Make the boring checks deterministic, and place them by cost

Anything a script can verify must never be verified by a model — faster, cheaper, no
opinions.

**The rule is not "check often". It is: match check frequency to check cost.**

**Artefact:** `scripts/checks.sh fast|slow`

| Placement | Contents | Cost |
|---|---|---|
| **FAST — in-loop** | `cargo fmt --check`, six shell gates (hardcoded-literals, vendor-literals, docs-vs-SSOT, l3-boundary, cloud-init-ascii, migration-ladder), implicated static-guard enumeration, `/tmp` scan | seconds |
| **SLOW — batched** | full `cargo test --features sal-postgres` compile + suite | ~40 min, 180–200 GB |

The slow path **categorises** its errors rather than listing them:

```bash
grep -oE '^error(\[E[0-9]+\])?' build.log | sort | uniq -c | sort -rn | head
```

Thousands of individual errors are usually one classification problem. A category is fixable
with one rule; instances are not.

### Step 8 — Serialize the expensive operation

If one operation dominates cost or time, do not let every agent trigger it.

**Artefact:** `scripts/build-daemon.sh` (systemd user unit `campaign-build-daemon.service`)

- Lanes **append a request** to `queue/build_requests` — they never invoke a heavy build.
- The daemon drains the queue, builds **once** into **one shared `CARGO_TARGET_DIR`**, runs
  the affected tests, and fans results back to `logs/build_results/<lane>`.
- A **120 GB disk floor** is enforced before every build; below it the daemon reclaims by
  `cargo clean` on worktrees whose HEAD is safely on a remote, and **refuses to build** if it
  still cannot clear the floor.

N agents each triggering a rebuild pays N times for work that batches into one.

---

## 3. The control graph

### Typed state

Mirrors `src/models/action.rs::ActionState`:

```
pending ──► claimed ──► in_progress ──► done | failed | abandoned
   │           │
   │           └──► pending          (claim release)
   └──► abandoned                    (early abandon)
```

Terminal states accept no outbound transition. **`claimed → done` is illegal** — the legal
route is `claimed → in_progress → done`. Callers request a destination and the executor walks
the legal path.

The mirror is **verified against the Rust source** at preflight, parsing the actual enum. A
mirror that drifts silently is worse than no mirror.

### Routing (deterministic, no model)

A node is dispatchable **only if** all hold:

1. state is `pending`
2. no `blocks` predecessor is un-`done`
3. its file footprint does not intersect any node currently held

An **undeclared footprint is treated as conflicting** — unproven-safe is not safe.

### Gates — BLOCK stops routing

| Gate | Blocks when |
|---|---|
| `state-mirror` | the typed mirror has drifted from `action.rs` |
| `disk` | ≥90% used or <120 GB free |
| `codegraph-id` | the index is not the canonical repo on `release/v1.0.0` |
| `codegraph` | the index is older than HEAD |
| `pg-substrate` | the PG+AGE test stack is not healthy |
| `stale-holds` | a node has been held with no progress beyond the threshold |

**The executor never "proceeds anyway."** That judgement is precisely what is being removed
from the loop.

---

## 3.5 Node contracts — output is DATA, not a message

**Every node's output is validated against a JSON schema at the tool boundary.**
A shape mismatch is rejected and re-asked; it never reaches the orchestrator as
prose to be mined by hand.

This is not a style preference. For most of this campaign exactly ONE edge had a
contract — `scripts/review.sh`, which requires

```
RULE: <rule-id> | ISSUE: <what is wrong, specifically, with file:line>
```

and then does `grep -oE '^RULE: [A-Z0-9-]+' | sort | uniq -c | sort -rn`. That
roll-up — the one that turns *a rule cited three times* into *one badly-written
rule* — is only possible **because the edge has a shape**. Every other edge
returned a fenced `Q1:/Q2:/Q3:` prose block that the orchestrator read and
re-typed.

The cost was not hypothetical. Issue #2436 was filed with the **wrong line
numbers** because its citations were transcribed out of a paragraph instead of
consumed from a field. Three of the four R-405 violations in this campaign
happened inside a parse-and-hope step.

`executor/contracts.py` now defines the shapes and enforces them:

| contract | required fields | what it makes impossible |
|---|---|---|
| `finding` | `claim`, `citation`, `evidence`, `severity` | a citation that does not resolve |
| `vote` | `verdict`, `confidence`, `findings`, `killer_objection` | a refutation buried in a paragraph — `refutes` is a **field** |
| `lane` | `landed`, `test_fails_before_fix`, `cross_backend`, `footprint` | claiming a fix landed without a load-bearing test |

Two rules are enforced mechanically rather than by reading:

- **Citations must match `file:line`.** `src/store/postgres.rs:5677` passes;
  *"around line 5677 in the postgres store"* is rejected. A citation the
  orchestrator has to interpret is a citation it will eventually retype wrong.
- **R-203 is a boolean.** `landed: true` with `test_fails_before_fix: false`
  raises `ContractViolation`. A test that passes against unfixed code proves
  nothing, and a bool cannot be hedged the way a sentence can.

The contract travels **with** the dispatch (`contracts.prompt_suffix(kind)`) —
a contract the node never sees is a contract the node cannot meet.

---

## 3.6 Pipeline by default; a barrier must earn its wait

A **barrier** holds every item to the pace of the slowest one. It is correct in
exactly three cases:

1. a stage genuinely needs the **whole set** (cross-set dedupe, ranking a
   complete list),
2. an early exit on the total ("zero findings → skip verification entirely"),
3. a stage whose prompt compares against *the other findings*.

*"It reads more cleanly"* is not one of them — and it was the actual reason this
campaign used barriers everywhere. Wave 1 was drained in full before Wave 2
started; the 1×5 was drained to the last voter before anything was acted on. The
framing voter returned in ~7 minutes and the data-tier voter in ~12, so a
**total-data-loss finding** (`ai-memory backup` fails open on postgres, #2444)
sat idle behind voters that had nothing to do with it.

`executor/dispatch.py` provides both, named for what they cost:

- `pipeline(items, *stages)` — each item flows through **every** stage
  independently, no synchronization point. Wall-clock is the slowest single-item
  *chain*, not the sum of slowest-per-stage. A stage that raises drops that item
  to `None` and skips its remaining stages, so one bad item never sinks the
  batch.
- `barrier(thunks)` — awaits all. Deliberately separate and deliberately named,
  so reaching for it is a decision rather than a default.

---

## 3.7 Loop until dry, and dedupe against everything ever seen

Fixed `2×N` waves stop because the count says so, not because the work is done.

`loop_until_dry(round_fn, seen, dry_rounds=2)` runs until **K consecutive rounds
surface nothing new**. Two properties are load-bearing:

- **Dedupe against everything ever seen — never against what was confirmed.**
  Deduping against confirmed-only is the classic non-convergence bug: a
  judge-rejected finding reappears every round and the loop pays forever to
  rediscover the same dead end.
- **A loop that hits `max_rounds` without converging says so, loudly.** Reporting
  a capped loop as exhaustive is the same silent-truncation class this campaign
  spent the week filing issues about.

The `SeenSet` is **durable** (`state/seen-*.jsonl`) — an in-memory set dies with
the process, and this campaign has already lost work to a killed lane.

Identity is semantic, not textual. Citation is the bucket; within a bucket a
Jaccard overlap ≥ 0.6 over content words decides sameness. **The first cut of
this class was wrong and its own self-test caught it**: an exact hash over the
first twelve words minted two entries for *"…never fires"* and *"…never fires at
all"*. A dedupe that does not dedupe is worse than none — the loop never goes
dry and the roll-up double-counts. The fix is pinned in both directions:

| case | second occurrence is new? |
|---|---|
| exact repeat | no |
| reworded tail | no |
| reordered clause | no |
| **different defect, same line** | **yes** |
| **same claim, different line** | **yes** |

---

## 3.8 R-207 — the Rust standard is a gate, not a prompt

Every lane that touches `.rs` is held to **rust-skills**: 265 rules across 26
categories, sourced from the Rust API Guidelines, the Performance Book, the 2024
Edition Guide, the Rustonomicon, and the ripgrep / tokio / serde / polars / axum
/ cargo codebases.

Two lanes in this campaign were dispatched **without** it, because the standard
lived only in an orchestrator's memory of the standard. That is precisely how a
standard erodes — the same failure shape as the eleven Python files that
accumulated because nobody ever wrote the language rule down (#2451).

So `checks.sh fast` now enumerates the implicated categories from the changed
files, deterministically:

| changed path matches | categories raised |
|---|---|
| `federation` · `sync` · `receive` | `async-` `conc-` `err-` `obs-` |
| `storage` · `store` · `migrat` | `perf-` `opt-` `mem-` `err-` `serde-` |
| `sweep` · `background` · `daemon` | `async-` `conc-` `err-` `obs-` |
| `handlers` · `mcp` · `cli` | `api-` `err-` `type-` `doc-` |
| *(always)* | `test-` `anti-` |

A federation + storage + sweeper change raises **121 of the 265 rules** — named
by category, with counts, at dispatch time rather than at review time. If
rust-skills is not installed the gate says so: *"standard unenforceable"*, rather
than passing silently.

---

## 4. Codegraph — integral, not incidental

Codegraph is wired as three gates the process cannot route around.

| Gate | Purpose |
|---|---|
| **G1 identity** | the index must belong to the **canonical** codebase. Verified by resolved path **and** git branch **and** index presence — not a path string. Codegraph resolves the nearest `.codegraph` at or *above* a query path, so a worktree can silently resolve into a different repo's index. A fresh index of the *wrong* codebase is more dangerous than a stale index of the right one, so identity gates **before** freshness. |
| **G2 footprint** | a node's file footprint is **derived from its symbols**, never trusted from a hand-written list. |
| **G3 completeness** | after a change, every caller of a changed symbol must be touched or explicitly excluded with a reason. |

**Freshness is automated**, not remembered: a systemd timer runs every 15 minutes —
`git fetch` → `merge --ff-only` → `codegraph sync`, at `Nice=10` with idle I/O.

**Caveat encoded in the tooling:** codegraph caller lists on common symbol names
(`resolve`, `get`, `new`, `insert`, `validate`, …) collide across modules. Results for those
names are returned **flagged for verification** — they are leads, not facts.

---

## 5. Verification substrate

A permanent local stack, because the shipped CI cannot exercise these surfaces.

| Component | Version |
|---|---|
| PostgreSQL | **18.4** |
| Apache AGE | **1.7.0** |
| pgvector | **0.8.5** |

- **TLS 1.3 enforced** — `pg_hba.conf` contains **no plain `host` lines**, so a cleartext
  connection is refused rather than silently downgraded. A client cert exists for mTLS work.
- **Two instances:** a working instance, and a deliberately **bare** instance whose only
  purpose is migration rehearsal — it must be able to start from an empty database so an
  upgrade run creates the extensions itself, as a real upgrade would.
- Extensions are **built from pinned commit SHAs** against the official PG image, because the
  upstream AGE image ships a different PostgreSQL patch level. The SHAs are baked into the
  image so a rebuild is reproducible.

**Why this exists:** the CI postgres service carries pgvector but **no AGE**. Every AGE-gated
test detects the missing extension, logs a skip, and exits 0. Those tests had never executed
anywhere. Their green was the absence of evidence.

---

## 6. Data-tier matrix

Eighteen lanes, run in full after **every** merged data-tier fix — not just the touched lane.

Ladder (forward + bootstrap-replay + idempotence) · archive round-trip losslessness ·
encryption at rest · concurrency & isolation · crash/power-loss durability · AGE projection
consistency · AGE deferred drain · pgvector correctness · cross-backend parity · federation
convergence · collation & encoding · FK/cascade integrity · quota enforcement · audit-chain
tamper evidence · backup/restore · TLS enforcement.

**Protocol:** baseline → fix → **retest the FULL matrix** → compare. Any lane that changed
state, *including `PASS → SKIPPED`*, is a finding.

Results are reported `PASS / FAIL / **SKIPPED**` separately. A `SKIPPED` lane blocks any
"full spectrum" claim.

---

## 7. Post-fix dogfood install

Each fixed iteration is installed on the development node and exercised against the real
memory substrate — a migration rehearsal on production data, which the synthetic stack
cannot provide.

Order is deliberate; do not reorder:

1. build release from HEAD
2. **snapshot** the live DB (sqlite backup API — consistent under concurrent readers)
3. run the ladder against the **snapshot** with the new binary
4. assert: **no rows lost**, `integrity_check = ok`, version **monotonic**
5. only then install (symlink-versioned, so rollback is a symlink flip)
6. report what must restart — never kill a live MCP, which would self-DOS the session

If step 3 or 4 fails, nothing is installed and the live database was never exposed.

---

## 8. Crossroads protocol

Genuine architecture inflection points (`T1`–`T6`: public-contract shape change · sync↔async
boundary · security posture · hard-to-reverse representation · spec deviation · ≥2
mutually-exclusive paths with no precedent) require an **adversarial vote before building**,
with the verdict cited in the commit.

**Lessons learned about running votes:**

- **Lenses must be genuinely distinct**, or five voters produce one argument in five
  vocabularies. Measure effective panel size, not headcount.
- **Do not instruct a default.** A brief that says "default to REJECT if uncertain"
  manufactures the consensus it then reports.
- **Do not forbid re-derivation.** A brief that says "do not re-derive, vote on it" prevents
  voters from catching an error in the brief itself.
- **Shared evidence correlates voters.** Independence in *reasoning* is not independence in
  *evidence* — if a fact in the brief is wrong, every voter inherits it.
- **Unanimity is where groupthink hides.** Point a second wave at the consensus, not at the
  rejected options.

---

## 9. Non-negotiables

- **No agent scratch under `/tmp`** — use the project-local scratch directory.
- **`cargo clean`, never `rm -rf`** (operator hard rule R005).
- **Measure, never inherit a number** — ceilings, sizes, counts are read from the artefact,
  not copied from a brief, an issue body, or another branch.
- **MAX-WINS is insufficient when changes stack.** Two lanes editing one file produce a
  combined size above *both* candidate ceilings. Re-measure after rebase.
- **Verify a red before believing it** — genuine failure vs cancelled concurrency-twin vs
  watchdog timeout. Query the API, not the rendered label.
- **Never blame a red on the most recent merge** without reverting to base and re-running.
- **Close the audit trail** — merged work closes its issues with evidence and transitions its
  node. Stale-open issues and merged-but-held nodes are process defects.
- **A deferral needs a tracked carrier.** Silence is not a disposition.

---

## 9.1 R-405 — absence of evidence is not evidence of absence

A **negative** claim ("never decrements", "unreachable", "has never executed",
"zero callers", "no such rule exists") requires a **positive demonstration of
the negative** — an exhaustive enumeration, a compiler error, an execution
trace. A search that came back empty is not that demonstration.

This rule was violated **four times in one campaign, by the reviewer, including
inside the document that proposed it**. Four different tools produced the same
error: a `grep` for a Rust const that could never match the SQL string literal
the code actually used; reading §17's prose without grepping `tests/`; a
`head -25` that truncated a check-run list read as absence; and a `cargo tree`
edge filter that returned empty for a dependency plainly present in
`Cargo.lock`.

Four occurrences across four tools is not a discipline failure correctable by
intent. **It requires a mechanical gate** — which is why `codegraph.py` now
unions grep results into every caller set rather than trusting an empty index
response, and why node contracts (§3.5) force citations into fields the
orchestrator does not retype.

---

## 10. Provenance

Every rule above was produced by a specific failure. A partial record, because rules without
provenance decay into folklore:

| Rule | Incident |
|---|---|
| R-101 build daemon | fourteen concurrent lane target trees filled a 912 GB volume to 1.4 GB free |
| R-202 self-skip ≠ pass | the PR-gating postgres job runs an AGE-less image, so AGE-gated tests self-skip to exit 0 on that gate (the coverage job does run a live AGE service) |
| R-203 prove load-bearing | a ghost-node test used a query path that silently falls back, so it passed against unfixed code |
| R-204 `contains` blind to drift | a span guard passed while broken — `contains` cannot detect a one-byte offset at any distance |
| R-206 static-guard sweep | five CI jobs lost to a single static guard that targeted test selection could not see |
| R-207 rust standard is a gate | two lanes dispatched without the 265-rule Rust standard because it lived only in an orchestrator's memory of it |
| R-405 absence ≠ evidence | **four** violations by the reviewer — a const-name grep that could not match a SQL string literal, prose read without grepping `tests/`, a `head -25` truncation, and a `cargo tree` query artifact |
| R-301 codegraph footprint | an issue was filed with a 2-funnel scope; codegraph showed 14 call sites |
| R-401/402 measure | an orchestrator brief carried three wrong ceiling numbers; a lane caught them by measuring |
| R-403 classify the red | a rendered `fail` was a cancelled concurrency twin; a separate red was a watchdog timeout on a passing run |
| R-404 revert before blaming | fixture residue produced failures that pointed convincingly at a just-merged PR |
| R-501 check the backlog | an issue was filed as a duplicate of an existing one |
| R-502 close the trail | three stale-open issues and two merged-but-held nodes found in one session |
| state mirror | nodes were transitioned to a state named `fixing`, which does not exist — the handoff doc said so in prose and nothing caught it |

---

## 11. The actual shift

The question was never whether the model is smart enough. It is **who decides what happens
next.**

In a loop, the model decides and you find out at the end. In a graph, you decided in advance
and the model executes inside the boundaries you drew.

What remains model work is what is irreducibly judgement: reading a codebase, writing a fix,
adversarial review. Everything around it — precondition checking, routing, conflict
detection, footprint derivation, completeness verification, build serialisation, merge and
close-out — is deterministic, inspectable, and outside the prompt.
