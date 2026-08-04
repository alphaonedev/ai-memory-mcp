<!-- Bet-the-farm claims audit, 2026-08-01. 7 published surfaces, 265 falsifiable claims -->
<!-- adjudicated against the code at release/v1.0.0 HEAD. Read-only; no execution. -->

# CLAIMS REGISTER — ai-memory v1.0.0 GA

**Repo:** `/home/fate_two/v07/v09-dev` · **Branch:** `release/v1.0.0` · **HEAD:** `e31dea74` (was `5449b6da` when the seven surface passes began; re-verified at `e31dea74`)
**Standard applied (operator, verbatim):** *"enterprise ready means a fortune 500 company would bet their entire business in integrating all their AI Agents with ai-memory v1.0.0 GA release — they would bet the entire farm analogy on ai-memory doing everything it CLAIMS it can reliably, consistently, without error"*
**Binding surface:** the published claims, not the code.
**Scope:** 7 published surfaces — README, capabilities API, security/compliance docs, federation docs, performance claims, API contract + SDK READMEs, roadmap/release-notes/changelog.
**Method:** 265 falsifiable claims harvested and adjudicated against code at HEAD. Read-only: `rg` / `git` / `gh` / file reads. No `cargo`, no daemons, no docker, no benchmarks.
**Result:** 71 claims adjudicated **FALSE** or **OVERCLAIMED**. 5 **UNVERIFIABLE** without execution. The remainder verified.

---

## 1. Can a Fortune 500 bet their business on the claims this product currently makes?

**No — not yet.** And the reason is specific enough to be fixable in days, not quarters.

The engineering is, in the large, **more conservative than the prose that describes it.** Repeatedly in this audit the code contains an accurate, unflattering statement about its own limits — and the published document forty lines away, or in another file, asserts the opposite:

- `src/audit.rs:913` says the `CHECKPOINT.sig` anti-truncation marker "is **NOT** yet implemented ... Rather than silently advertise anti-truncation attestation an audit-enabled daemon does not get, emit a one-shot operator WARN." `docs/security/audit-trail.md` publishes that same marker as the threat-model mitigation for tail-truncation of the audit log.
- `src/governance/rules_store.rs:203-210` warns: "Substrate is in **FAIL-OPEN** posture: every enabled rule passes through without signature verification." `src/config.rs:1527` reports `rules_engine: "operator_signed"` on that same daemon.
- `benchmarks/longmemeval/results.md:24-29` states that conflating the Python shadow harness with the shipped binary path "**would be dishonest**" and publishes the binary-faithful keyword number as **96.4%**. `README.md:770` publishes **97.0%** from the shadow harness, undisclosed.

That is the shape of this release: **a sound substrate wearing a claim surface that was written for a different, larger, more-enforced product.** Ninety percent of the failures below are corrected by editing a sentence. That is the good news, and it is genuinely good news — an enterprise integrating on the *actual* behaviour of this daemon would mostly find it safer than advertised.

But three things are **not** documentation drift, and they are why the answer is "no" rather than "yes with a doc pass":

1. **The federation trust boundary the documents sell is not the boundary the code enforces.** `docs/federation.md:97-104` says namespace scoping is applied on "every lane that can reach a write." Three write lanes never consult it — `links[]` (`src/handlers/federation_receive.rs:2359`), `signals[]` (`:2734`), and the entire pull-accept path (`src/federation/receive.rs:346`, which runs as `CallerContext::for_admin`). The documents simultaneously offer "one cluster **per tenant**" (`docs/enterprise-deployment.md:1238`) and "**multi-tenant isolation**" (`docs/federation-identity.md:58`). A compromised or hostile tenant peer can write graph edges into a namespace it is denied — and `contradicts`/`supersedes` edges feed the recall down-weight, so that is a **read-path influence primitive against data the peer cannot read.**
2. **The capability envelope is a build manifest wearing a capability report's schema.** `memory_capabilities` reports `compaction: {planned: true, enabled: false}` (`src/config.rs:467`) unconditionally — `rg 'caps.compaction' src/` returns **zero writers** — while a hard-DELETE merge consolidator ships and is switchable via `resolve_compaction_enabled()` (`src/config.rs:8322`). Fleet tooling that polls capabilities to answer *"is a destructive merge running on this node?"* gets an unconditional **no**, and the merge's rollback is separately documented as **not** restoring `memory_links` provenance (`src/curator/compaction.rs:41-47`). That is unrecoverable graph deletion behind a capability bit that says the feature does not exist.
3. **Verification integrity.** The flagship retrieval number, the enterprise capacity table, and the Batman latency decomposition are each attributed to a harness that **structurally cannot produce them.** 11 of the 14 ops/s cells in `docs/enterprise-deployment.md:1389-1409` have no producer in `benches/` at all, and the entire Postgres+AGE column comes from a bench that `exit 0`s unless `AI_MEMORY_TEST_AGE_URL` is exported. This is the #2450 class, three more times.

**What must change before a Fortune 500 can rely on this claim surface:** close C-01 through C-09 below (nine items), then execute the doc-correction list in §3.2. The code work in §3.1 is four defects. Everything else is prose.

**The honest one-line summary:** *the product is substantially sound; its documentation overclaims — and in federation scoping, capability reporting, and benchmark provenance, the overclaim is load-bearing enough that the documentation is not merely stale, it is wrong about the security model.*

---

## 2. FALSE and OVERCLAIMED claims, ranked by blast radius

### Tier 1 — BET-THE-FARM (9)
*A false security, durability, or verification-integrity guarantee. An enterprise would build on these.*

---

**C-01 · FALSE · Retrieval quality headline**
📍 `README.md:770`, `:809`, `:815`; `ROADMAP.md:320-334`
> **Claim:** "**97.0% R@5** pure FTS5 keyword (LLM-independent, 2.2 seconds, 232 q/s, zero API costs)"; ROADMAP: "Recall@5 (keyword, LLM-independent) **97.0%** (485/500) ... pure SQLite FTS5+BM25."
> **Code/repo:** `benchmarks/longmemeval/results.md:41` — binary-faithful keyword R@5 = **96.4%**. `benchmarks/longmemeval/README.md:39` attributes 97.0% / 232 q/s to `harness_fast.py` — "Native Python+SQLite, zero subprocesses." `results.md:24-29`: the shadow harness "re-implements scoring outside the binary", is "**not** the shipped code path", and conflating them "would be dishonest."

This is the one number an evaluator treats as the **floor guarantee**, because it has no LLM dependency. It is published from a Python reimplementation, against a repo document written specifically to prevent that. Open as **#2450**; this pass confirms it reaches the keyword row, not only the expansion headline.

---

**C-02 · FALSE · Audit-log tail-truncation is bounded by signed checkpoints**
📍 `docs/security/audit-trail.md` (threat-model row "Local attacker truncates the tail"); `docs/security/audit-schema.md`
> **Claim:** "Periodic `CHECKPOINT.sig` markers (cadence `attestation_cadence_minutes`) bound how much history can be silently discarded ... v1 emits the marker shape."
> **Code:** `src/audit.rs:912-925` — "the periodic `CHECKPOINT.sig` attestation marker is **NOT** yet implemented: no emission code exists and `effective_attestation_cadence_minutes` ... has no production consumer."

Its only runtime effect is `warn_attestation_reserved_once()` (`src/audit.rs:935-947`) — a `tracing::warn!`. Verified at HEAD: three `CHECKPOINT.sig` hits in `src/audit.rs`, all in comments/WARN text, zero emission sites. **The daemon warns the operator that the published threat model is wrong.**

---

**C-03 · FALSE · Namespace scoping covers "every lane that can reach a write"**
📍 `docs/federation.md:97-104`
> **Claim:** `allowed_namespaces` globs are "matched against `Memory::namespace` on **every lane that can reach a write**."
> **Code:** `src/handlers/federation_receive.rs:2359` — `for link in &body.links` → `db::create_link_inbound` at `:2424`; no scope check. `:2734` — `for sig in &body.signals`; `sig.namespace` is read only at the quota call (`:2786`) and never compared to `allowed_namespaces`. `src/federation/receive.rs:346` — builds `CallerContext::for_admin(sentinels::FEDERATION_CATCHUP)` (`bypass_visibility=true`) then inserts; `rg 'PeerAttestationConfig|namespace_allowed' src/federation/receive.rs` → **zero hits**.

Contrast the lanes that *do* gate — `archives[]` (`:2226`) and `deletions[]` (`:2185`) both call `receive_auth::inbound_by_id_namespace_authorized`. Open: **#2489**, **#2480**. This is a universal quantifier over the exact mechanism an enterprise builds tenant isolation on.

---

**C-04 · FALSE · Sync daemon refuses to start without mTLS**
📍 `docs/compliance/honest-limitations.md` §4 mitigation 6; `docs/compliance/nsa-csi-mcp-security-mapping.md` §3.4
> **Claim:** "The sync daemon **refuses to start without mTLS** unless an explicit insecure flag is set; an empty peer allowlist refuses every peer."
> **Code:** `src/cli/sync.rs:476-484` implements the **inverse** — `if args.insecure_skip_server_verify && (args.client_cert.is_none() || args.client_key.is_none()) { bail!("--insecure-skip-server-verify requires both --client-cert and --client-key as a compensating mTLS control") }`. With neither flag set, `:529-540` takes the `SyncTlsMode::CaValidated` arm and `sync_client_identity()` returns `Option` — **the daemon starts with no client certificate and no insecure flag.** Server side: `src/daemon_runtime.rs:829 pub mtls_allowlist: Option<PathBuf>` — mTLS is entirely opt-in. The empty-allowlist refusal (`src/tls.rs:217-223`) only fires once the operator has already chosen mTLS.

Federation ships **plaintext** memory content (`src/encryption/mod.rs:11-16`). This is the guarantee tenant isolation rests on.

---

**C-05 · FALSE · Capabilities reports destructive compaction as not-in-this-build**
📍 `src/config.rs:467` → emitted on every v2/v3 envelope via `to_v3` (`src/config.rs:1924`)
> **Claim (on the wire):** `compaction: {planned: true, version: "v0.8+", enabled: false}`, where the type doc defines `planned=true` as "the feature exists only on the roadmap."
> **Code:** `src/curator/compaction.rs:20-25` — "the **LIVE** consolidator (#1746 cutover)"; `:316` — "Persist the consolidated memory and **hard-delete the sources**." Activation knob at `src/config.rs:8322 resolve_compaction_enabled()`. `rg 'caps.compaction' src/` → **zero writers**; `build_capabilities_overlay` (`src/mcp/tools/capabilities.rs:337-470`) overlays hnsw, hooks, permissions, approval, transcripts — never compaction.

An operator who sets `compaction.enabled = true` still gets `{planned:true, enabled:false}` on the wire. Rollback does **not** restore `memory_links` (`src/curator/compaction.rs:41-47`). Open: **#2400** — confirmed and sharpened: the real defect is that the resolver exists and the capability surface never calls it.

---

**C-06 · FALSE · Enterprise capacity table attributed to the in-tree bench suite**
📍 `docs/enterprise-deployment.md:1389-1409`
> **Claim:** 14 ops/s cells across 7 workloads × 2 backends, "Reference numbers from the in-tree benchmark suite (`benches/recall.rs`, `reflect.rs`, `reranker_throughput.rs`, `hnsw_rebuild_async.rs`, `age_vs_cte.rs`, `longmemeval_reflection.rs`, `harness_bench.rs`)."
> **Repo:** `grep -ln 'postgres|sqlx' benches/*.rs` → `age_vs_cte.rs` only, which measures `kg_query` depth=5 exclusively and **self-skips with exit 0** unless `AI_MEMORY_TEST_AGE_URL` is set (`benches/age_vs_cte.rs:16-40`). `grep -ln 'sync_push' benches/*.rs` → no hits. No bench emits `memory_store` ops/s, `memory_recall` cold ops/s, or `/sync/push` ops/s on any backend.

**11 of 14 cells have no producer; the entire Postgres+AGE column has no runnable harness.** This is the section a Fortune 500 capacity-plans from.

---

**C-07 · OVERCLAIMED · Blast radius of a compromised federation peer**
📍 `docs/federation.md:582-586`
> **Claim:** "The **blast radius of a single compromised peer** scales with what the operator wired into its `PeerScope`; default-deny on both `allowed_namespaces` and `allowed_sender_agent_ids` keeps a compromised peer from authoring as other agents or pulling unrelated namespaces."
> **Code:** True on the two verbs named. Silent on the reach that is not contained — per C-03, a peer scoped `public/*` can still write graph edges into a denied namespace, deliver signals into a denied inbox, and inject rows into any namespace on a node that pulls from it.

#2480's own body states the accepted threat model is "a configured peer turns hostile / is compromised" — exactly the case this sentence claims to bound.

---

**C-08 · OVERCLAIMED · Gate-3 closed green / zero GA blockers**
📍 `docs/v1.0.0/release-notes.md:399-437`
> **Claim:** "The reviews surfaced **0 GA-blockers**"; "Fixed 100% — every code-review finding closed in-release"; "The tag cannot cut with any Gate-3 finding open; the loop closed green before the (operator-gated) tag cut."
> **Repo:** `git tag -l 'v1.0.0*'` → **empty** (only `v0.10.0` exists). `gh api .../issues?state=open` → **169 open non-PR issues**, including #2450, #2438, #2613, #2400, #2492, #2629 — all confirmed open. The document also promises "a five-step program" and enumerates steps 1, 2–3, and 5; **step 4 is absent from the text.**

This is the release's own readiness attestation — the single claim an enterprise would use to skip its own diligence.

---

**C-09 · OVERCLAIMED · Certified Postgres+AGE stack "tested live"**
📍 `docs/v1.0.0/release-notes.md:190-199`
> **Claim:** "The certified stack was tested live: the AGE-gated Cypher/KG suites (`age_cte_equivalence`, `g2_postgres_find_paths_age_param_binding`, `g4_postgres_link_projects_into_age_graph`, `cov_postgres_kg`, `issue_1482_age_cypher_persistent`, `kg_age_fallback`) ... all pass on it."
> **Code/CHANGELOG:** `CHANGELOG.md:171` records **#2511 (HIGH / data-honesty)**: "Every AGE-routed graph READ was rejected by AGE at parse time and **silently re-served from the relational recursive CTE**, while `Capabilities.kg_backend` kept reporting `Age` ... **FIVE INDEPENDENT causes, each sufficient on its own.**" `CHANGELOG.md:179`: the fix's own regression tests had to avoid `kg_query` because "it falls back, so a `kg_query`-only assertion cannot tell the two engines apart."

**Those suites passed against the relational fallback, not against AGE.** The certification evidence was green for the wrong reason. Residual #2613 is open. The release notes mention neither #2511 nor #2613.

---

### Tier 2 — HIGH (30)

**C-10 · FALSE · "Three concurrent auth layers enforced together" / "`/health` is the only exempt endpoint"**
📍 `docs/enterprise-deployment.md:44-47`, `:1633` — vs `src/handlers/transport.rs:852`
> Claim: "a peer that satisfies two but not the third **cannot push or fan-out** into the local store."
> Code: `if auth.mtls_enforced && path.starts_with("/api/v1/sync/") { return next.run(req).await.into_response(); }` — under the mTLS posture the **same checklist mandates one line earlier (`:1630`)**, the api-key layer is bypassed on every federation endpoint. `docs/federation.md:66-72` documents this bypass correctly (#702). **The two documents in one surface contradict each other.**

**C-11 · FALSE · The prescribed auth-stack verification command**
📍 `docs/federation.md:396-399`; `docs/enterprise-deployment.md:1150-1154`
> Claim: `curl --cert peer.crt --key peer.key -H "x-peer-id: peer-node-1" .../api/v1/health` — "a 200 ... means TLS + mTLS + API key all aligned" / "+ attestation."
> Code: `src/handlers/transport.rs:801-804` exempts `HEALTH` from the api key entirely; `pub async fn health(State(app): State<AppState>)` (`:1035`) **takes no `HeaderMap`** — `x-peer-id` is never read. A 200 proves TLS + mTLS only. An operator following the runbook gets a green light for an auth stack that was never tested.

**C-12 · FALSE · "1 to ~1,000,000 agents"**
📍 `docs/federation.md:9-12`; `docs/federation-identity.md:9-10`
> Contradicted inside the same surface: `docs/federation.md:575-578` ("50+ peers ... the substrate's peer-to-peer mesh model is the **wrong shape**"); `docs/enterprise-deployment.md:78` (top tier T6 = **1000+** agents); `:1269-1277` ("Agent counts are **PROVISIONAL** ... not benchmarked guarantees"). Open: **#2438**. ~3 orders of magnitude, both numbers public.

**C-13 · FALSE · HTTP body limit 50 MB**
📍 `README.md:1220` — vs `src/lib.rs:87 pub const HTTP_BODY_LIMIT_BYTES: usize = 2 * MIB;` applied at `src/lib.rs:1317`. **25× smaller than published.** An integrator sizing bulk ingest against 50 MB gets 413s at 2 MiB.

**C-14 · FALSE · README declares v0.9.0 as the current release, with six stale surface numbers**
📍 `README.md:43`, `:1235`
> Claim: "**v0.9.0 — current release**" · schema **v78** · **101** MCP tools · **92** HTTP routes · **89/87** CLI subcommands · **28-field** `Memory`.
> Code: `Cargo.toml:3 version = "1.0.0"`; `CURRENT_SCHEMA_VERSION = 88`; `tool_names::ALL` = **103**; `EXPECTED_PRODUCTION_ROUTES_COUNT = 94` (`src/lib.rs:345`); `EXPECTED_CLI_SUBCOMMANDS_DEFAULT = 89` / `_SAL = 91`; `Memory::FIELD_COUNT = 30`. README says "v1.0.0" exactly once, in a parenthetical at line 152. **All six are wrong, in the first screen of the document.**

**C-15 · FALSE · Semantic tier 97.4% R@5 / 45 q/s**
📍 `README.md:816` — binary-faithful semantic R@5 = **96.8%** (`benchmarks/longmemeval/results.md:122`). `grep -rn "97.4" benchmarks/` returns only a per-category R@1 cell. The table also **silently omits the `autonomous` tier**, the only tier measured *worse* than baseline (95.8%, `results.md:135`).

**C-16 · FALSE · `?api_key=` query credential still accepted**
📍 `docs/API_REFERENCE.md:26-31` — "Still accepted at v0.7.0 for back-compat ... slated for rejection at v0.8."
> Code: `src/handlers/transport.rs` (`api_key_auth`) — "#2032 L1 (v1.0.0) — the legacy `?api_key=` QUERY-STRING credential is **NO LONGER accepted** (header-only)." Every integrator on the documented path gets a silent 401, with no advertised remediation because the doc says removal is still in the future.

**C-17 · FALSE · HTTP admission control is opt-in / default 0**
📍 `docs/API_REFERENCE.md:164-185` — "**opt-in** ... compiled default `0` = disabled ... behaviour is byte-identical to a build without admission control."
> Code: `src/config.rs:8712-8717` — unset resolves to `resolve_default_max_inflight_requests()` = `clamp(parallelism*64, 256, 4096)`. Only an **explicit** `0` disables (`src/lib.rs:1366-1368`). #2032 M3 flipped this fail-open→fail-closed; the doc describes the pre-flip posture. Operators get 503 + Retry-After under a load level they were told needs no configuration.

**C-18 · FALSE · `GET /api/v1/links/{id}` returns `signature`, `attest_level`, `signed_at`**
📍 `docs/API_REFERENCE.md:499` — vs `src/storage/mod.rs:7996-7999`, whose projection is `source_id, target_id, relation, created_at, valid_from, valid_until, observed_by, attest_level`. `:7993` states `signature` is **intentionally not surfaced**; `signed_at` **is not a column on `memory_links`** at all. An integrator building link-attestation verification over HTTP is pointed at a surface that isn't there.

**C-19 · FALSE · SDK `grant()` / `revoke()` / `cluster()`**
📍 `sdk/python/README.md:143-144`, `sdk/typescript/README.md:104-106` (impl `sdk/python/ai_memory/client.py:466-487`)
> `rg '"/api/v1/cluster"|/grant"|/revoke"' src/handlers/routes.rs` → **zero hits** (re-verified at HEAD). Three shipped SDK methods 404 at runtime.

**C-20 · FALSE · TypeScript `unsubscribe(id)` → `DELETE /api/v1/subscriptions/:id`**
📍 `sdk/typescript/README.md:101` (impl `src/client.ts:580-587`) — `src/lib.rs:1177-1183` registers delete on `"/api/v1/subscriptions"` only; the id rides the **query string** (`src/handlers/subscriptions.rs:587-591`). **The worst of the four:** webhook teardown appears to fail-safe but leaves a decommissioned endpoint receiving signed deliveries indefinitely.

**C-21 · FALSE · "≥30% AGE-over-CTE speedup, bench-gated in CI"**
📍 `PERFORMANCE.md:556-560`; `README.md:140`; `docs/enterprise-deployment.md:1405`
> `.github/workflows/bench.yml` declares exactly two jobs (`bench:`, `regenerate-baseline:`). `grep -rni 'age' .github/workflows/bench.yml` → **zero hits**. `grep -rn 'age_vs_cte' .github/` → **zero hits**. The published exit criterion — "if AGE ever fails to clear that bar, the AGE backend is dropped" — **can never fire.**

**C-22 · FALSE · Bench baseline compare "blocks merge" / is "pulled from the previous release tag"**
📍 `docs/performance.html:321`, `:280`
> `bench.yml:116-147` labels the step "Baseline regression (**advisory**, #1987)" and prints "**ADVISORY — never fails the build**"; `:124-134` **self-skips the compare entirely** because `performance/baseline.json:4` carries `"bootstrap": true`; the baseline is a committed file, not pulled from a tag. `PERFORMANCE.md:164-172` states the correct posture — **two published surfaces directly contradict each other.**

**C-23 · FALSE · `postgres-age` nightly CI job gates the certified stack**
📍 `docs/v1.0.0/release-notes.md:205-212` — "gated **nightly** ... **fail-closed asserts** the live server_version / age extversion / vector extversion equal the pins before any test runs ... This closes the gap that AGE-gated Cypher ... could only be exercised on an operator's own machine."
> `.github/workflows/postgres-parity-nightly.yml:16-29` — "**REMOVED 2026-07-31 (operator directive)**: the `postgres-age` job (#2012) ... is **gone rather than repaired**"; deleted in `da3fb9cc`. The surviving job uses `pgvector/pgvector:pg16` — **not** the certified PG 18.4 — and runs 4 non-AGE binaries. The exact disclaimer the sentence claims to retire is the current state **by design**.

**C-24 · FALSE · "Two independent CI jobs" enforce coverage + a `.coverage-baseline` ratchet**
📍 `ROADMAP.md:284`, `:993-996`
> `.github/workflows/ci.yml:1237-1246` — "the former `Code Coverage` job ... was **REMOVED** here (#1993)." `rg 'coverage-baseline' .` hits **prose only** — no workflow, no script reads it. `scripts/coverage.sh:86` invokes only `coverage/check-thresholds.sh`; no ratchet, no slack. The sole live floor is `min_line_coverage = 90.0` (`coverage/thresholds.toml:70`) — **~2.6pp of undetected regression headroom versus the published control.** Aggravating: this ROADMAP entry was itself authored to correct a stale coverage claim (#1970).

**C-25 · FALSE · `kg_backend` reports which traversal engine is serving**
📍 `src/config.rs:555-571` — "Operators consult this through `ai-memory doctor` and `memory_capabilities` to **verify which traversal path their daemon actually runs**."
> `rg 'kg_backend = ' --include=*.rs src/` at HEAD → `src/config.rs:9333` and `:9337`, **both inside `#[cfg(test)]`**. No production writer. The field is `skip_serializing_if = Option::is_none`, so it is **always omitted**, and its documented meaning of absence ("no SAL adapter is wired") is false on every SAL deployment. `PostgresStore::kg_backend()` exists (`src/store/postgres.rs:1478`) and is never threaded into the envelope. **Whoever fixes #2613 must be told the field needs to be WIRED, not corrected.**

**C-26 · FALSE · `memory_kinds: ["observation", "reflection"]`**
📍 `src/config.rs:487`, doc at `:2113-2124` — "the `MemoryKind` enum in this binary **only carries** `Observation` and `Reflection`."
> `MemoryKind::all()` returns **16** variants at HEAD. A single v3 payload carries **two mutually contradictory machine-readable enumerations of the same vocabulary** — `memory_kinds` (2) and `memory_kind_vocab.vocabulary` (16, `src/config.rs:1707`). A v2-pinned client rejects `intervention` / `told` / `instruction` — the epistemic kinds the provenance layer cites as the do-calculus enforcement layer.

**C-27 · OVERCLAIMED · `reflection.attestation: "Ed25519"`**
📍 `src/config.rs:1311` — hardcoded, no runtime keypair check.
> `src/storage/mod.rs:7509-7530` — "When `keypair` is `None` ... the row is written with `signature = NULL` and `attest_level = \"unsigned\"`." `ReflectHooks::empty()` defaults to `None` (`src/storage/reflect.rs:187-196`). On a daemon with no generated keypair — **the default after `cargo install`** — reflections and their `reflects_on` edges are unsigned while capabilities asserts Ed25519. Contrast `governance.l1_6_attest`, which *does* report live key state.

**C-28 · OVERCLAIMED · `governance.rules_engine: "operator_signed"`**
📍 `src/config.rs:1527` — hardcoded regardless of posture.
> `src/governance/rules_store.rs:234-244` — `(None, _) => { ... true }` "No operator pubkey configured — substrate is in pre-L1-6 mode. Every `enabled = 1` row passes through unchanged." `:203-210`: "Substrate is in **FAIL-OPEN** posture ... a SQL-write gadget that can mutate `governance_rules` can install or flip rules **without operator consent**." Fleet tooling keying on `rules_engine` concludes rules are tamper-proof when they are not.

**C-29 · OVERCLAIMED · NSA CSI concern (a) Access control "structurally addressed" / 10-of-10**
📍 `docs/compliance/nsa-csi-mcp-security-mapping.md` §1 row a; `docs/compliance/index.html`
> The **same landing page** publishes `v1.0.0-security-assessment.html` finding **H1 = HIGH**, OWASP A01/A07, "Cross-tenant IDOR/BOLA on read+mutate via spoofable `X-Agent-Id`." `CHANGELOG.md:460` verbatim: "Out of the box (`advisory` default + zero per-agent keys enrolled) H1/M1 behave **EXACTLY as pre-#2044** — the gate is **fully inert** until an operator enrolls per-agent keys AND sets `enforce`." Concern (a) is claimed closed while the shipped default posture is the one the project itself rates HIGH. (The assessment page is also stale the *other* way — it still lists H1 as unremediated.)

**C-30 · OVERCLAIMED · Semantic-recall sizing at 1M / 5M memories**
📍 `docs/enterprise-deployment.md:1412-1424`
> `src/hnsw.rs:80 pub const DEFAULT_MAX_ENTRIES: usize = 100_000;` — the shipped in-memory vector index holds 100k and **evicts oldest past the cap**. `grep -rn 'VECTOR_INDEX_CAPACITY' docs/enterprise-deployment.md docs/production-deployment.md` → **zero hits**: neither capacity doc names the knob. An enterprise sized at 1M–5M gets semantic recall **silently truncated to the newest 100k rows** — a guarantee that holds only under an unstated configuration.

**C-31 · OVERCLAIMED · "A CI gate that fails any PR whose measured p95 exceeds the budget by more than 10%"**
📍 `README.md:821-825`; `PERFORMANCE.md:9-14`, `:437-444`; `ROADMAP.md:354` ("the Bench workflow **gates** every PR/push ... these budgets are the **latency contract**")
> `.github/workflows/bench.yml:18` verbatim: "**Bench is advisory (not in required-status-checks).**" Re-verified at HEAD: `grep -ic bench scripts/qc-allowlists/required-contexts-release.txt` → **0**. The job exits non-zero; it cannot block a merge.

**C-32 · OVERCLAIMED · Federation push DLQ — "not lost"**
📍 `docs/enterprise-deployment.md:868-877`
> The durable DLQ key is a **positional index**: `src/federation/peer.rs:107-109 PeerEndpoint { id: format!("peer-{i}"), ... }` (URL dropped from identity); replay does `config.peers.iter().find(|p| p.id == row.peer_id)` (`src/federation/push_dlq.rs:488`) and POSTs the stored payload. **Removing one peer from `--quorum-peers` reindexes every id above it**, so `find()` succeeds against the **wrong host**: the queued full memory payload is delivered to an unintended peer and the intended peer never receives it — no counter, no error (**#2442**). In the documented "one cluster per tenant" hive this is **cross-tenant content disclosure**.

**C-33 · OVERCLAIMED · `trust_domain` = "multi-tenant isolation"**
📍 `docs/federation-identity.md:58`, `:87`, `:394`; composed with `docs/enterprise-deployment.md:1238-1243` ("one per region **or per tenant**", "**Strict trust gates**") and `:1638`
> `trust_domain` is a **credential-replay scope only** (`src/federation/identity/trust_bundle.rs`): it rejects a credential minted for another fleet and enforces nothing between tenants **inside** one domain. The stated in-domain confinement primitive is `PeerScope.allowed_namespaces` — which per C-03 three write lanes never consult. **Delivered boundary: separately-administered peers in one org. Documented boundary: mutually distrusting tenants.**

**C-34 · OVERCLAIMED · At-rest encryption for regulated workloads**
📍 `docs/enterprise-deployment.md:1653-1658` (§14.6), `:971-998` (§7.4 "The substrate enforces the policy")
> `src/encryption/mod.rs:11-16` — "**NOT end-to-end across federation (#1809)** ... federation catch-up decrypts content and the receiving peer re-seals under its own per-node key, so a federated peer holds **plaintext** transiently at apply time." `docs/federation.md:337-339` discloses this honestly. **The 1694-line enterprise document — the one an architect reads as their compliance gate, and the one recommending a cluster per tenant — never says it.**

**C-35 · OVERCLAIMED · "Two production backends behind one identical API"**
📍 `README.md:43`, `:45`, `:36`
> `src/handlers/postgres_gate.rs:97 postgres_endpoint_supported()` is an explicit **allowlist — 56 `=> true` arms out of 94 route registrations**; everything else gets a "uniform 501 NOT IMPLEMENTED" (`:29`, `:68`). Additionally, `CLAUDE.md` §Architecture: "MCP stdio is structurally **sqlite-only** (#1675/n24)." A Postgres deployment gets a materially smaller HTTP API **and cannot use the stdio MCP path the README's entire integration story is built on.**

**C-36 · OVERCLAIMED · 232 q/s throughput**
📍 `README.md:770`, `:815`; `ROADMAP.md:328-329`
> `docs/DEVELOPER_GUIDE.md:1098-1101` reveals 232 q/s is `harness_99.py --no-expand` = "**Parallel FTS5, 10 cores**" (`harness_99.py:244`, `mp.Pool` at `:296`) — a Python harness. The **same table** measures the shipped binary path at **1.2 q/s** and single-process native SQLite at 57 q/s. The benchmark's own metric definition (`methodology.md:179`): "q/s: ... **SINGLE-THREADED** recall path (parallel runs annotated separately)." Published without the mandated annotation. Throughput sibling of #2450.

**C-37 · OVERCLAIMED · "Schema ladder v78 → v86 — all additive" + "lossless v78→v86 migration on a real corpus"**
📍 `docs/v1.0.0/release-notes.md:68`, `:440-452`, `:413`
> `CURRENT_SCHEMA_VERSION = 88` on both adapters. **v87 is data-mutating** — `src/storage/migrations.rs:3790-3805` runs `normalize_expiry_rows(...)` with `UPDATE memories SET expires_at = ?1 WHERE rowid = ?2` plus the same over `archived_memories` — and has **no row in the ladder table at all**, while the v86 row asserts it is data-mutating "(unlike every other v79-v85 rung...)". **Two rungs that rewrite rows on a real corpus ship with no lossless-migration evidence on this surface.**

**C-38 · OVERCLAIMED · SOC2 CC7.2 / FedRAMP AU-11/AU-12 attestation cadence**
📍 `docs/security/audit-trail.md` (regulatory mapping); `docs/security/audit-schema.md` (compliance presets)
> The resolver exists (`src/config.rs:6360`) but `src/audit.rs:912-925` records it "**has no production consumer**"; its only caller feeds the reserved-WARN. Setting `fedramp.applied = true` yields a 30-minute figure **no code acts on** — and `audit-trail.md`'s threat model then reuses that dead cadence as the truncation defense (C-02). A FedRAMP reviewer reads a named control citation resolving to a no-op.

**C-39 · OVERCLAIMED · `POST /api/v1/memories/bulk` outcomes**
📍 `docs/API_REFERENCE.md:376-385`, `:135` (400 = "validation, parse, or limit error")
> Terminal response is a bare `Json(json!({"created": …, "errors": […]}))` with **no `StatusCode`** (`src/handlers/memories_query.rs` ~`:1090-1140`; `rg 'StatusCode::(OK|CREATED|MULTI_STATUS)' src/handlers/memories_query.rs` → no hits). A batch in which **every** row was rejected by the per-agent quota answers **HTTP 200 with `created: 0`** (#2588). The doc gives an integrator no way to learn that.

---

### Tier 3 — MEDIUM (28)

| # | Verdict | Claim → Code | Location |
|---|---|---|---|
| **C-40** | FALSE | "Recall **mutates the database** (touches, auto-promotes)" / "each recall extends expiry (short +1h, mid +1d)" / CLI "auto-touch" → `src/handlers/recall.rs:581` "recall is now **UNCONDITIONALLY pure**" (#1953); `rg '\.touch_after_recall\(' src/` → **zero production call sites**; ladders applied only by the periodic fold job (`src/storage/mod.rs:2596`), which on the README's own headline MCP-stdio deployment never runs until a gc chokepoint | `docs/API_REFERENCE.md:391`; `README.md:716,731,1058,1138`; `sdk/typescript/README.md:62` |
| **C-41** | FALSE | `format` is "MCP-only; HTTP responses are always JSON" → `src/handlers/recall.rs:143,236` call `toon::WireFormat::parse_http(...)`; the **same document** says the opposite at `:396-399` and `:441-446` | `docs/API_REFERENCE.md:933-936` |
| **C-42** | FALSE | "the Bench workflow gates every PR/push against the ABSOLUTE p95 budgets above" over a 15-row table → gated budgets are `src/bench.rs:1337-1347` (store **20 ms**, not 5; search 100 ms, not 8); **9 of the 15 rows have no `Operation` variant at all** | `ROADMAP.md:336-354` |
| **C-43** | FALSE | Per-Form Batman p50/p95/p99 + a 5-row p99 contributor ranking "measured on `scripts/batman-bench.sh`" → that script times **end-to-end `ai-memory store` subprocess wall clock** across four content-size buckets and emits four stat lines (`:69-93`, `:116-121`, `:150-157`). No per-Form, LLM-cold-start, JSON-re-extract or dedup instrumentation exists. #2450 shape | `PERFORMANCE.md:344-355`, `:402-414` |
| **C-44** | FALSE | "`cargo bench --bench kg_bench --features=age`" → **no such bench target** (`rg kg_bench` hits `PERFORMANCE.md` only; real target is `age_vs_cte`) and **no `age` cargo feature** exists (`Cargo.toml:275-330`). Both halves of the command fail | `PERFORMANCE.md:571`, `:574` |
| **C-45** | FALSE | `memory_session_start < 100 ms` published under "a CI gate that fails any PR" → no `Operation` variant in `src/bench.rs`; `PERFORMANCE.md:29` itself marks the row `*[advisory]*`. README **strips the advisory marker**. Section header also reads "(v0.6.4)" on a v1.0.0 branch | `README.md:819-835` |
| **C-46** | FALSE | `## [1.0.0] — 2026-07-21` as a released, dated heading in a "Keep a Changelog" file → no tag exists; `release-notes.md:45` says "tag cut operator-gated"; ~328 lines of `[Unreleased]` incl. HIGH fixes sit **above** the dated heading; entries inside it are labelled "v1.0.0 pre-ship" | `CHANGELOG.md:336`, `:5` |
| **C-47** | FALSE | Audit action vocabulary "recall / search / list / get / session_boot" and a 13-value enum → `src/audit.rs:143-163` has **no `Search`/`List`/`Get`** variants and **has a 14th**, `CaptureLag` (wire `"capture_lag"`, `:183`), which a SIEM built to the published enum will meet on the wire | `docs/security/audit-trail.md`, `audit-schema.md` |
| **C-48** | FALSE | Procurement pair stamped "v0.7.0 (sqlite + postgres schema **v57**, lockstep)"; "Cargo.lock (~5,479 lines)" → schema is **88**; `wc -l Cargo.lock` = **5747**. Stale by 31 schema versions — on the version stamp a reviewer uses to decide whether the assessment applies | `honest-limitations.md:6`, `nsa-csi-mcp-security-mapping.md:6` |
| **C-49** | FALSE | "93 REST route registrations (80 unique URL paths)" (7 sites) and "**92** HTTP routes (**78** unique paths)" → `EXPECTED_PRODUCTION_ROUTES_COUNT = 94`, `EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT = 80`. Wrong on **both axes**; the unique-path axis is a second stale value beyond #2492 | `README.md:153,216,600,718,749,871,1015` |
| **C-50** | FALSE | One paragraph asserts **80** unique paths in prose, **78** as its own "authoritative" command output, and cites a const that says **80** — three values, one self-labelled authoritative. (Command run at HEAD returns 80.) | `docs/API_REFERENCE.md:974-983` |
| **C-51** | FALSE | "101 entries advertised at `--profile full` ... the command returns 101" → returns **103**; the same document says 103 fourteen lines earlier (`:972`) | `docs/API_REFERENCE.md:1013` |
| **C-52** | FALSE | Feature-tier table: smart/autonomous give the "full **101-entry** surface" → `tool_names::ALL` = 103, pinned `== Profile::full().expected_tool_count()` (`src/mcp/registry.rs:295`); **the same table says 103 three lines above** (`README.md:892`) | `README.md:893-895` |
| **C-53** | FALSE | "In the current table: **7 of 14** rows are bench-verified; the remaining 7 are advisory" → the table has **17** rows and **8** advisory markers; two rows are in neither bucket. This is the sentence that tells operators how much of the latency contract is measured | `PERFORMANCE.md:24-25` |
| **C-54** | FALSE | "the baseline-COMPARE guard ... is **not yet a CI job** — **no committed `performance/baseline.json` exists**" → the file exists at HEAD (10 rows, `"bootstrap": true`) and the compare **is** a CI step (`bench.yml:116-147`, advisory) | `ROADMAP.md:354` |
| **C-55** | OVERCLAIMED | "Every claim traces to a `capability_id` ... the inventory traces every claim to a **file path + line number** ... all verified via codegraph" → **6/6 sampled anchors miss at HEAD**, including a symbol that no longer exists (`decorate_memory` → `decorate_memory_many`, `src/mcp/tools/recall.rs:610`) and one (`clientInfo.name` capture at `src/mcp/mod.rs:1607-1611`) pointing at nothing. `index.html` carries a currency note; **the two `.md` files that ARE the cited procurement pair carry none** | `nsa-csi-mcp-security-mapping.md` §7 + §§3.2,3.6,3.9,3.10,4.3,4.5-4.7 |
| **C-56** | OVERCLAIMED | Layer-3 code citations all drifted (`PeerScope` :107→:110, `attest_sender` :257→:259, `namespace_allowed` :348→:357, consts :75-88→:77/:83/:90) — and `namespace_allowed` is named as **the outbound `/sync/since` gate** but is never called from that handler (it inlines `namespace_allowed_test_glob` at `:232`). Behaviour equivalent; the map is wrong | `docs/federation.md:92,155,157,178,186` |
| **C-57** | OVERCLAIMED | GA enterprise guide titled "for ai-memory **v0.7.0**" — `grep -c 'v0\.7\.0'` → **38**. §14.3's "v0.7.0 secure defaults" omits `FED_REQUIRE_WRITE_SIG` / `_SIGNAL_SIG` / `_CHECKPOINT_SIG` / `_PUSH_NAMESPACE_SCOPE` / `_REQUIRE_SERVER_VERIFY`, all of which became fail-closed defaults at v1.0.0. §9.3 offers a **v0.7.0 gap list** as the hive-planning basis | `docs/enterprise-deployment.md:4,1200,1219,1246` |
| **C-58** | OVERCLAIMED | "Data-residency policy is enforced ... at the `namespace_allowed` gate ... before any row crosses the wire" → true on the **serve** direction (`federation_sync_since.rs:196-234`, default-deny, `scope_status="no_allowlist_default_deny"`); the **accept** direction is ungated (`src/federation/receive.rs:346`, `for_admin`, incl. `(title,namespace)` dedup-overwrites) — **#2480**. Residency has two directions | `docs/enterprise-deployment.md:948-969` |
| **C-59** | OVERCLAIMED | "Revocation is stop renewing ... its credential simply expires; **no peer visit required**" → true only for the credential lane, after up to 3600 s. Silent that the legacy `.pub` lane and the mTLS fingerprint allowlist — **the only lane in the shipped runbooks** — have **no expiry** and require an allowlist edit **plus a full daemon restart** (no hot-reload, verified) | `docs/federation-identity.md:324-326` |
| **C-60** | OVERCLAIMED | macOS operators "held to the published budgets with the published 10% tolerance — the same binary the CI guard runs" → `src/bench.rs:94-97 MACOS_BUDGET_MULT: f64 = 3.0`, applied at `:988`. On macOS the real pass bar is **3.3×** published (recall PASSes at 165 ms against `<50 ms`). Undisclosed — on the platform `PERFORMANCE.md:457` names as **the reference baseline** | `PERFORMANCE.md:485-492` |
| **C-61** | OVERCLAIMED | "recall during HNSW rebuild < 35 ms — bench-verified ... **2k-vector fixture**" asserted against a stated **100k-vector** rebuild → `benches/hnsw_rebuild_async.rs:29 DEFAULT_FIXTURE_SIZE = 5_000` (2k reachable only via an undocumented env var). A **50× scale extrapolation presented as bench-verification** | `PERFORMANCE.md:44` |
| **C-62** | OVERCLAIMED | Three different reference machines for the same budgets: Apple **M4/32 GB** (`PERFORMANCE.md:457`, `performance.html:269`), Apple **M2/16 GB** (`ROADMAP.md:335`, `production-deployment.md:154`, `enterprise-deployment.md:1399`), plus "M2 thermal throttling" as the variance source (`methodology.md:213`). An operator cannot tell which machine any number belongs to | multiple |
| **C-63** | OVERCLAIMED | "`/health` — **Deep health check** — verifies DB accessibility and **FTS5 integrity**" → since #2579 the check runs on a background connection every `AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS` (**default 21600 = 6 h**) and `/health` renders a **cached** verdict that can be `pending`/`stale`/`disabled` (`src/handlers/transport.rs:1029-1054`); `:983` says the live part is "REACHABLE, not VERIFIED". An operator wiring `/health` as a corruption detector gets evidence up to 6 h old | `README.md:761,1021` |
| **C-64** | OVERCLAIMED | `/health` documented response is `{status, service}` → body also carries `version, embedder_ready, federation_enabled, checks{...}, fts_integrity{...}`, and the endpoint returns **503** whenever `!live || verdict.is_unhealthy()` (`health_status_code`, `src/handlers/transport.rs:1001-1010`). **The doc omits the only way the probe fails** — orchestrator probe configs are written against it | `docs/API_REFERENCE.md:224-236` |
| **C-65** | OVERCLAIMED | Status table lists 200/201/202/400/401/403/404/409/500/503 + "No per-client rate limiting at the HTTP layer" → **429** is produced at ≥9 sites incl. both primary write surfaces (`src/handlers/create.rs:591`, `src/handlers/links.rs:653`). The Python SDK's own error table lists `RateLimitError | 429` — **the SDK knows what the reference does not** | `docs/API_REFERENCE.md:128-141,161-162` |
| **C-66** | OVERCLAIMED | `atomisation: {tool/curator/auto/... = "implemented"}` doc: "`\"implemented\"` **only when** the engine, hook, and wrapper code are all wired" → all six are hardcoded with no tier/LLM check; `src/mcp/mod.rs:3748-3760` returns `None` with no LLM, and `src/mcp/tools/atomise.rs:189` short-circuits on keyword tier. **The file's own precedent** gates `curator_mode` on `cfg!(feature = "sal")` because reporting "implemented" "over-reports the surface" (`src/config.rs:1313-1320`) | `src/config.rs:1630`, `:1635` |
| **C-67** | OVERCLAIMED | "`ai-memory bench --scale 10000` runs ... on **every** PR + trunk push" → both triggers carry `paths-ignore: ['docs/**','**/*.md']` (`bench.yml:20-28`), and per C-31 the job is not required, so a failure blocks nothing | `PERFORMANCE.md:156-162` |

---

### Tier 4 — LOW (4)

| # | Verdict | Claim → Code | Location |
|---|---|---|---|
| **C-68** | OVERCLAIMED | Badge "≥92% cov" / "held above the **≥92% project bar**" → enforced workspace floor is `min_line_coverage = 90.0` (`coverage/thresholds.toml:70`, re-verified). `README.md:777` states 90% correctly — the badge and the prose assert a bar that is not the gate | `README.md:14`, `:769` |
| **C-69** | FALSE | "Both SDKs are versioned with the server (`0.9.0` matches `ai-memory 0.9.0`)" → `sdk/typescript/package.json:3` = `1.0.0`; `Cargo.toml:3` = `1.0.0`. The **rule** holds; the **stated pair** is stale, and an integrator pinning `@alphaone/ai-memory@0.9.0` is following the README literally | `README.md:702` |
| **C-70** | FALSE | "~10,000 tests — 6,712 under `src/` (5,759 + 953) plus ~3,362 under `tests/` (2,138 + 1,224)" → measured: src/ **7,446** (6,443 + 1,003); tests/ **4,047** (2,567 + 1,480); total **≈11,493**. Every sub-figure wrong; direction is conservative | `README.md:769` |
| **C-71** | OVERCLAIMED | "Default `--profile core` advertises **7**" (+ badge `MCP-7_default`) vs the same page's footnote "advertises **8** at boot ... the 7 Core-family tools plus the always-on `memory_capabilities`" → both defensible; the page states both without reconciling, and the badge picks one. Same disambiguation hazard #862 was opened to close | `README.md:17,152,926` |

**Two claims are true but cite the wrong evidence** (not counted as failures, but they will mislead a reviewer who follows the pointer): `skills.round_trip: "verified"` cites `tests/skill_test.rs` (whose `export_roundtrip_identical_digest` at `:295` hand-writes both digests and never calls the handlers) when the real end-to-end pin is `tests/cov_17_skills_federation_roundtrip.rs:109-218`; and `capabilities.permissions.mode` computes the live value correctly while its doc comment at `src/config.rs:939` still reads "`\"advisory\"` until P4 ships the gate."

---

## 3. Remedy: fix the CODE vs correct the CLAIM

This is the operative section. **The distinction is: would we still want to make this claim if it were free?** If yes, the code must change. If the claim was never going to be true for this architecture — or the code's current behaviour is a deliberate, better design — the honest fix is to stop making the claim.

### 3.1 — REMEDY BY FIXING THE CODE
*These claims are the right claims. The product is supposed to do this. Narrowing the documentation would ship a weaker product under an honest label — which is worse than fixing four defects.*

| Claim | Fix | Why code, not prose |
|---|---|---|
| **C-03 / C-07 / C-33 / C-58** — namespace scoping on `links[]`, `signals[]`, pull-accept (#2489, #2480) | Apply `receive_auth::inbound_by_id_namespace_authorized` under `ns_gate_enrolled` to the `links` and `signals` loops (`federation_receive.rs:2359`, `:2734`); construct a `PeerScope` on the pull-accept path instead of `CallerContext::for_admin` (`receive.rs:346`) | **The documents sell multi-tenant peer isolation and the product is architected for it.** Narrowing the doc to "we scope 5 of 8 lanes" makes federation unsellable to the segment it was built for. The gate mechanism already exists and is already applied on the sibling lanes — this is **wiring, not design**. Interim: ship the narrowed doc *today* (§3.2) so nobody integrates on the false version while the code lands. |
| **C-05 / C-25 / C-27 / C-28 / C-66** — capability envelope is a compile-time build manifest | Extend `build_capabilities_overlay` (`src/mcp/tools/capabilities.rs:337-470`): overlay `compaction` from `resolve_compaction_enabled()` + the curator's last-run stats (the `interval_minutes` / `last_run_at` / `last_run_stats` fields **already exist and are already `Option`**); thread `PostgresStore::kg_backend()` (`src/store/postgres.rs:1478`) into `AppState`; gate `reflection.attestation` on live keypair presence exactly as `governance.l1_6_attest` already gates itself; derive `rules_engine` from `l1_6_attest` (`"operator_signed"` vs `"fail_open_unsigned"`); gate `atomisation.*` on tier + LLM presence | **A capability API whose answer does not depend on the running deployment has no reason to exist.** "Correcting" these to honest constants would produce an API that tells every daemon the same thing — that is not a capability report. The in-repo pattern is already correct twice: `transcripts` flips `enabled` off a live `COUNT(*)` (`src/config.rs:1155-1230`), and `cross_encoder_reranking` is force-`false`d when no reranker is live (`capabilities.rs:349-378`). **Reuse the overlay; do not invent a mechanism.** |
| **C-32** — DLQ positional peer identity (#2442) | Key `federation_push_dlq.peer_id` on a **stable** identity (URL hash or configured name), not `format!("peer-{i}")` (`src/federation/peer.rs:107-109`) | This is a **straight misdelivery bug with cross-tenant content-disclosure consequences**. There is no version of this that gets documented away. The code already handles peer *removal* (`push_dlq.rs:488-497`); it does not handle *reindexing*. |
| **C-19 / C-20** — SDK methods against unregistered routes | `unsubscribe`: fix the TS client to use `DELETE /api/v1/subscriptions?id=<id>` (`src/handlers/subscriptions.rs:587-591`). `grant`/`revoke`/`cluster`: **delete** from both SDKs and both READMEs | Split verdict. `unsubscribe` is a real, registered capability the SDK calls wrong — **fix it**, and it is urgent because the failure mode is a decommissioned webhook that keeps receiving signed deliveries. `grant`/`revoke`/`cluster` are routes that **never existed** — that is §3.2 territory. |
| **C-39** — bulk returns 200 with `created: 0` (#2588) | Return `207 Multi-Status` (or 400 on total rejection) from the bulk terminal path (`memories_query.rs` ~`:1090-1140`) | A write endpoint that reports HTTP success for a batch in which **every row was rejected** is a durability-adjacent correctness defect, not a documentation gap. No wording makes 200/`created:0` a safe contract for a retrying client. |
| **C-31 / C-21 / C-24 / C-23** — enforcement claimed, advisory in fact | **Decide, per gate, then make the docs match the decision.** Bench: either add `ai-memory bench (ubuntu-latest)` to `scripts/qc-allowlists/required-contexts-release.txt`, or restate as advisory. Coverage ratchet: either wire `.coverage-baseline` into `coverage/check-thresholds.sh`, or delete the file and the claim. AGE: either add an AGE job to `bench.yml` + restore a `postgres-age` nightly, or delete the J8 gate claim from all three locations | These are the only items where **both** remedies are legitimate and the choice is a product decision. What is **not** legitimate is the current state: a published enforcement guarantee backed by a workflow whose own header says "advisory (not in required-status-checks)". Note the coverage gap is quantified: **~2.6pp of undetected regression headroom** between the claimed 92.59 ratchet and the live 90.0 floor. |
| **C-02** — `CHECKPOINT.sig` (if the control is wanted) | Implement emission on the `effective_attestation_cadence_minutes` cadence and give `verify` a checkpoint-aware mode | Listed here **only if** the anti-truncation property is a v1.0 requirement. If it is not — and `src/audit.rs:912` implies it is not — this belongs entirely to §3.2. **Until it is implemented, the claim must go; there is no third option.** |

### 3.2 — REMEDY BY CORRECTING THE CLAIM
*These were never going to be true in this release, or the code's behaviour is deliberate and correct and the prose simply describes an older/other product. Making the claim true would mean building something we did not choose to build. Stop saying it.*

**A. Numbers that were measured by something other than the shipped product.** *Publish what the binary does.*
- **C-01 / C-15 / C-36** — replace `97.0%` → **96.4%**, `97.4%` → **96.8%**, and either drop `232 q/s` or publish it as "`harness_99.py`, 10-way parallel Python harness — the shipped binary path measures 1.2 q/s via CLI subprocess / 57 q/s single-process native." **Restore the `autonomous` row (95.8%)** that the tier table drops. *Why claim-side:* the Rust ranker's real numbers are excellent and the repo already computes them. The 97.0% was never this product's number, and `benchmarks/longmemeval/results.md:24-29` says so in the repo's own words.
- **C-06 / C-43** — relabel `docs/enterprise-deployment.md` §11.1 and the `PERFORMANCE.md` Batman stage tables **"estimated design figures — not measured"**, or delete them. *Why claim-side:* producing them honestly requires building harnesses that do not exist (a Postgres+AGE throughput rig, per-Form instrumentation). That is a project, not a fix. An explicit "estimated" label is instantly true and costs nothing.
- **C-61 / C-60 / C-62** — state the actual bench fixture (5,000, not 2k) and stop extrapolating it to 100k; **disclose `MACOS_BUDGET_MULT = 3.0`** at the point the budgets are published; pick one reference machine and use it everywhere.

**B. Claims describing a product one to three versions old.** *Mechanical; the SSOT already holds the right value.*
- **C-14 / C-48 / C-57 / C-37 / C-46 / C-69 / C-70 / C-49 / C-50 / C-51 / C-52 / C-53 / C-54 / C-68 / C-71** — restamp README to v1.0.0 and re-derive its six surface numbers from `src/lib.rs` / `registry.rs` / `migrations.rs`; restamp the compliance procurement pair (or apply `index.html`'s currency note to both `.md` files); restamp `docs/enterprise-deployment.md` (38 × `v0.7.0`); extend the release-notes ladder to **v88 with v87 flagged DATA-MUTATING** and restate the dogfood attestation at its true bound (v78→v86); move the `CHANGELOG` `[1.0.0]` heading to undated-pending until the tag cuts; fix coverage badge 92→90; reconcile the 7-vs-8 core default in one direction.

**C. Security and compliance properties that are not implemented.** *These are the ones that must not survive to GA under any wording short of deletion.*
- **C-02** — **delete** the tail-truncation mitigation row from `audit-trail.md` and the "v1 emits the marker shape" line from `audit-schema.md`; mark `CHECKPOINT.sig` **RESERVED**, matching `src/audit.rs:912` verbatim.
- **C-38** — **delete** the SOC2 CC7.2 / FedRAMP AU-11/AU-12 cadence mapping until the cadence drives something. A named control citation resolving to a value nothing reads is worse than no mapping.
- **C-04 / C-10 / C-11** — rewrite the mTLS sentence in both procurement documents to describe the **actual** control (`--insecure-skip-server-verify` requires a client cert; mTLS itself is opt-in on both ends). Correct the "three layers enforced together" checkbox to state the **#702 `/api/v1/sync/*` api-key bypass under mTLS** — `docs/federation.md:66-72` already has the correct wording; copy it. **Delete both `/health` verification runbook steps** or repoint them at a gated endpoint. *Why claim-side:* opt-in mTLS is a deliberate deployment choice, and `/health` is deliberately unauthenticated so probes survive overload (`src/lib.rs:1382-1387`). The code is right; the runbook is wrong.
- **C-29** — restate NSA concern (a) as *"structurally addressed under `enforce` posture with per-agent keys enrolled; the shipped default (`advisory`, zero keys) is finding H1"*, quoting `CHANGELOG.md:460`. Also update the assessment page, which is stale in the *opposite* direction (still lists H1 as unremediated post-#2044/#2129/#2154). **One page or the other must move; they cannot both stand.**
- **C-34** — carry `docs/federation.md:337-339`'s plaintext-federation sentence (#1968) into `docs/enterprise-deployment.md` §14.6 **and** §7.4. One sentence, copied, closes a compliance-gate omission.
- **C-59** — state that credential expiry is the *credential* lane only, and that the mTLS fingerprint allowlist — the lane the runbooks actually use — has **no expiry and no hot-reload** (verified: `rg 'hot.?reload|reload_allowlist' src/tls.rs src/daemon_runtime.rs` → one hit, the `[llm]` SIGHUP path).

**D. Claims about behaviour the code deliberately removed or changed.** *The code is better than the doc. Update the doc to brag about it.*
- **C-40** — recall is **unconditionally pure** (#1953). That is a *stronger* property than "recall mutates the DB" — it makes recall safe on read replicas and idempotent under retry. Rewrite `README`, `docs/API_REFERENCE.md:391` and the TS SDK to say so, and describe the fold job as the ladder applier, **including** the caveat that on MCP-stdio with no `serve` daemon nothing folds until a gc chokepoint.
- **C-16** — `?api_key=` removal shipped at v1.0.0 (#2032 L1). Document it as a **breaking change with a migration note**, not as a future plan.
- **C-17** — admission control is **on by default** (#2032 M3), CPU-scaled. That is the safer posture. Document the default, the 503 + Retry-After behaviour, and that explicit `0` disables.
- **C-63 / C-64** — document `/health` honestly: liveness + **cached** FTS5 verdict (default 6 h), the `fts_integrity` fields, and **that it returns 503** on `!live || verdict.is_unhealthy()`. An orchestrator cannot write a probe config against a contract that omits the failure mode.
- **C-41 / C-65** — TOON `format` **is** supported on HTTP recall/search (`recall.rs:143,236`) — fix the coverage table so integrators get the ~79% payload reduction. Add **429** to the status table and delete "no per-client rate limiting at the HTTP layer."
- **C-18** — `signature` is withheld from `get_links` **by design** ("the verification surface owned by the `memory_verify` tool", `src/storage/mod.rs:7993`) and `signed_at` is not a column. Correct the doc and point integrators at `memory_verify`.
- **C-35** — replace "one identical API" with the truth: **56 of 94 routes** are Postgres-supported (`postgres_gate.rs:97`), the rest return a uniform 501, and **MCP stdio is sqlite-only**. This is a real limitation with a real workaround (HTTP); hiding it converts a supportable constraint into a production surprise.

**E. Claims that this architecture cannot support.**
- **C-12** — **delete the 1,000,000-agent figure** (#2438). The documents' own topology envelope is 1000+ agents/mesh with a ~50-peer ceiling and an explicit "at this scale the peer-to-peer mesh model is the wrong shape" (`docs/federation.md:575-578`). Three orders of magnitude is not a rounding posture. Publish the envelope; it is a good number.
- **C-08** — restate the Gate-3 attestation **scoped and dated**: "as of commit `<sha>`, the Gate-3 review round closed with 0 blockers **in scope**", plus the current open-issue count. Delete "the loop closed green before the tag cut" — no tag exists. Supply the missing **step 4**.
- **C-09** — add the **#2511 / #2613** disclosure to §Certified backend versions and state plainly that the AGE suite greens predate the parse-time-fallback fix and therefore attest the relational CTE.
- **C-44 / C-45 / C-42 / C-55 / C-56** — delete the dead reproduction command (`kg_bench` / `--features=age`), strip the CI-enforcement framing from `ROADMAP` §9.6 and the README budget table, and either regenerate the compliance/federation `file:line` anchors against HEAD or **remove the line numbers and cite symbols only**. Anchors that miss 6/6 are worse than no anchors — they cost the reviewer trust they cannot get back.
- **C-19** (`grant`/`revoke`/`cluster`) — delete from both SDKs and both READMEs. There is no server-side plan for these routes.
- **C-26 / C-47** — recompute `memory_kinds` from `MemoryKind::all()` (16) and delete the false "only carries Observation and Reflection" note (`src/config.rs:2118-2124`); correct the audit `action` enum to the shipped 14 (`Recall` only on the read side; add `CaptureLag`).

### 3.3 — The structural fix that prevents recurrence
Three of the twelve API-contract findings are **the same document disagreeing with itself** (92/80/78 paths; 103/101 tools; `format` MCP-only vs HTTP-supported). #2629 already records that `scripts/check-docs-vs-ssot.sh` pins **values, not symbols**. This audit shows two further gaps:

1. **It also misses values it nominally covers** — README currently carries 94→92/93, 88→78, 30→28, 103→101, 91/89→89/87 **with the gate green**. Either README is outside the file walk or those narrative patterns are outside the pattern set. A gate that greens a page carrying five stale SSOT values is the #2444 "reports success while doing nothing" shape.
2. **Nothing pins a doc against another paragraph of the same doc, and nothing pins the SDK READMEs or SDK client sources against `src/handlers/routes.rs`.** That check is mechanically trivial — extract every path literal from `sdk/*/README.md` + the client sources and assert membership in the `routes.rs` path set — and it catches **C-19 and C-20 at authoring time.**
3. **Add an existence rule for named CI jobs.** Every workflow/job name cited in `ROADMAP.md`, `PERFORMANCE.md`, `README.md` or `docs/v1.0.0/*.md` must resolve to a live job in `.github/workflows/`. This catches **C-21, C-23, C-24, C-31** mechanically — all four are "a control was removed and the prose was not."

Note the drift direction is **consistently toward more claimed enforcement than exists.** That is not random staleness; it is a systematic bias that a gate must be built to counter.

---

## 4. What this product CAN honestly say — VERIFIED and load-bearing

*Written for whoever drafts the release notes. Every line below was verified against code at HEAD by at least one of the seven passes. These are strong claims and they are true.*

### Security posture — the strongest part of the surface
- **Unsigned HTTP-direct writes fail closed by default.** `resolve_require_agent_attestation` falls through to `matches!(surface, WriteSurface::HttpDirect)` on unset **or typo** (`src/identity/attest.rs`); bulk enforces the same gate whole-batch (`memories_query.rs:768-790`). A **forged signature is rejected on every surface regardless of posture** (`src/identity/attest.rs:114-135`). ±300 s freshness window (`ATTEST_CREATED_AT_SKEW_SECS = 300`).
- **Six fail-closed secure defaults, all verified:** `FED_REQUIRE_SIG=1` and `FED_REQUIRE_NONCE=1` (`src/federation/signing.rs:240-247`, pinned by `require_sig_defaults_to_true` at `:335`); `GOVERNANCE_FAIL_OPEN_ON_ERROR=false`; `SSRF_GUARD_ALLOW_DNS_FAIL=false`; `PASSPHRASE_FILE_ALLOW_LAX_PERMS=false`; `permissions.mode` → `enforce` via `resolve_v07_default_mode(None)` for **both** "no `[permissions]` block" and "block with mode omitted" (`src/config.rs:7454-7456`). Plus `FED_REQUIRE_WRITE_SIG` / `_SIGNAL_SIG` default-true (`receive_auth.rs:236,242`) and `_CHECKPOINT_SIG` / `_POLICY_CURRENT` default-on with correctly-caveated fail-open-on-absent semantics (`:189-199`, `:465-497`).
- **Outbound TLS server verification is required unless explicitly disabled** — `server_verify_required()` = unset ⇒ required (`src/tls.rs:112-116`), pinned by `server_verify_required_default_on_grammar_2448` (`:1879-1891`).
- **mTLS Layer 1 is exactly as described:** `FingerprintAllowlistVerifier` with `client_auth_mandatory() -> true` (`src/tls.rs:917`), constant-time SHA-256(DER) allowlist check, rejection **inside the handshake** before any Axum layer (`:913-941`).
- **2 MiB global HTTP body cap** applied as a root-level layer, therefore covering bulk/import/sync (`src/lib.rs:87`, `:1317`); **16 MiB MCP stdio line cap** with `-32700` on overrun (`src/mcp/mod.rs:3727`, `:4358-4364`). **No request `DecompressionLayer`.**
- **Macaroon capability verify is safe-by-default and honestly scoped:** version-pinned, `verify_strict`, `subtle::ct_eq` HMAC chain, attenuation-only append-only fold, issuer ceiling clamp (`src/governance/capability.rs:388-390`, `:454-456`), and a **closed** issuer allowlist that "MUST NEVER consult the broad federation trust store" (`:20-24`, `:558-562`). Cryptographic language is applied only to the cryptographic part.
- **`asi-hard` no-disable posture is genuinely composed**, not helper-only: a 16-entry pin-and-refuse KNOBS table (`src/security_profile.rs:194-278`) including `ENV_DB_SYNCHRONOUS→FULL`, with `tests/security_profile_prerun_2386.rs` pinning **structurally** that `enforce_at_boot_pre_runtime` runs before file logging and before the tokio runtime builder, **and** behaviourally (subprocess) that a below-floor value aborts boot. Inference-egress gating is composed at **six** call sites.
- **Operational logs and the audit trail are both default-OFF** (`src/config.rs:6232`, `:6288`); the log-path resolver **refuses world-writable directories** (`src/log_paths.rs:319-323`); `ai-memory audit verify` **exits 2** on a broken chain; and the daemon **refuses `hash_chain = false` outright** rather than letting the knob lie (`src/audit.rs:903-911`) — stronger than documented.
- **Crypto-erase is real and honestly bounded:** `ERASED_ENVELOPE_VERSION = 0x04` tombstone, read of an erased envelope **fails closed** (`src/encryption/mod.rs:117-123`, `:684-731`), tests at `tests/crypto_erase_1956.rs`. `docs/security/crypto-erase.md` separates **ATTESTABLE from ESTIMABLE by name**, admits legacy `0x02` rows are not crypto-erasable, admits archive is not tombstoned, and admits pre-erasure backups are out of reach. **This document is the standard the rest of the surface should be held to.**
- **The rollback control downgrades itself correctly:** "tamper-**EVIDENCE**, not tamper-**PROOF** — an imaged-disk attacker who snapshots DB + anchor together wins" (`CLAUDE.md:527`), verdicts degrade to `Unknown`/`WITHHOLD` rather than a false all-clear, and TPM2 NV is disclosed as "reserved-when-present, format only." **No cryptographic language over an operational assurance was found in the CLAUDE.md guarantee rows.**
- **Build-script vetting is a real fail-closed ledger** with both checksums matching `Cargo.lock:3392` and `:3351`. (Disclosure: the gate is `python3 scripts/check-build-script-vetting.py` — a second Python CI gate under a "100% Rust" claim, #2451. The document names it as Python, so it is disclosed, not hidden.)
- **Portability v2 import is all-or-nothing:** `BEGIN IMMEDIATE`, `verify_audit_trail` run against staged state **inside** the transaction, `tx.commit()` last (`src/portability/import.rs:276-360`). `ai-memory backup` **refuses a non-SQLite store** (#2444).
- **Concern (j) coverage is exactly as published:** 20 module tests in `src/mcp/server_identity.rs` + 27 in `tests/mcp_initialize_server_signing.rs` = **47**, counted at HEAD.

### API and data model
- **94 production route registrations over 80 unique paths**, mechanically pinned (`src/lib.rs:345`, `:375`, `tests/route_count_invariant.rs:70`). **103 advertised MCP tools at `--profile full`** (102 callable + always-on `memory_capabilities`), pinned `tool_names::ALL == Profile::full().expected_tool_count()` (`src/mcp/registry.rs:295`). **89 CLI subcommands default / 91 under `sal`** (`src/lib.rs:415`, `:434`). **30-field `Memory`**, **16 `MemoryKind` variants**, **9 typed `MemoryLink` relations** (`src/models/link.rs:306`), **27 `HookEvent` variants**. Schema **v88**, lockstep across SQLite and Postgres.
- **`GET /api/v1/capabilities` returns `schema_version "3"` by default** with `Accept-Capabilities` negotiating v1/v2 (`src/handlers/system.rs:47-51`, `:93`).
- **Optimistic concurrency is real:** `If-Match` / 409 on stale ETag (`src/handlers/memories.rs:245-247`, #884); 409 on `(title, namespace)` collision (`:478,687,781,794`).
- **Federation under-replication is a 202, not a 5xx** — `{quorum_met:false, acks, needed, reason, durability:"local"}` (`src/handlers/parity.rs:71-80`). The doc is right and a stale *code comment* is wrong — the rarer and better direction.
- **Webhook signing is exactly as documented:** `HMAC-SHA256(SHA256(secret), "{ts}.{body}")`, `X-Ai-Memory-Signature: sha256=<hex>`, `X-Ai-Memory-Timestamp` (`src/subscriptions.rs:971-974`, `:1441`, `:1444`).
- Verified operational constants: recall cap 50; list default 20 capped at `max_page_size`, `LIST_MAX_LIMIT` 1000; `KG_QUERY_MAX_SUPPORTED_DEPTH = 5`; taxonomy depth clamped to `MAX_NAMESPACE_DEPTH` (8); tier TTLs 6h/7d/permanent; auto-promotion at 5 accesses; priority +1 per 10 accesses; 6-factor recall score with the access-count cap at 50; HTTP binds `127.0.0.1:9077` by default; GC every 30 min; MSRV 1.96.

### Capability surface — the parts that are honest
- **Every compile-anchored count and enumeration checked was exact:** `hook_events_count = 27`, `bypass_impossibility_tests = 6`, the four `enforced_actions` wire tags (routed through the #1558 SSOT so they cannot drift in spelling), the 7 `memory_skill_*` tool names, `max_default = 3` (single-sourced post-#1680), the confidence half-life const, the three forensic CLI verbs.
- **`permissions.mode` reports the live enforcement mode**, not a literal (`src/config.rs:441`, `:5920-5943`).
- **`transcripts.enabled` flips only off a live `COUNT(*)`**, and **`cross_encoder_reranking` is force-`false`d whenever no reranker is live** (`src/mcp/tools/capabilities.rs:349-378`) so an HTTP daemon can no longer advertise it beside `reranker_active="off"`. **These two are the pattern; they prove the four broken fields are fixable with the mechanism already in the tree.**

### Performance contract — the parts that are pinned
- **`P95_TOLERANCE = 1.10`** matches the published 10%; **`DEFAULT_REGRESSION_THRESHOLD_PCT = 10.0`** matches the docs.
- **Default and 10k-scale budget tables are mechanically pinned in both directions** (`src/bench.rs:1337-1347`, `:1385-1412`).
- **Verified-path crypto headroom is exact and scale-invariant:** +10 ms store / +20 ms recall (`src/bench.rs:51`, `:57`), applied identically at default and at scale, pinned at `:1669-1705`. `MAX_SCALE = 1_000_000`.
- **`PERFORMANCE.md` explicitly refuses to pin fabricated 1M budgets** and says so ("REPRODUCIBLE-METHODOLOGY, not pinned", `:231-252`). **That is the correct posture and is the template for the rest of the performance surface.** The power-loss durability section likewise draws an honest PROVEN / NOT-PROVEN boundary and correctly scopes the fsync-lie out of software test range.

### Documentation that is exemplary and should be the house style
`docs/security/crypto-erase.md` · `docs/security/audit-trail-coverage.md` (admits the read-gate audit availability gap, and that signature failures do not drive the chain-verify exit code) · `docs/compliance/nsa-control-test-matrix.html` (18/18 named binaries exist, 11/11 spot-checked test fns resolve, and it marks **7 controls "config-asserted — no harness PASS row" against its own interest**) · `docs/federation.md:335-358` (the plaintext-federation paragraph) · `ROADMAP.md §11.6` (four unshipped v1.0 items ruled DEFERRED with issue numbers and inline refutation evidence) · `ROADMAP.md §27` (self-corrects §24/§25.6/§26.2). **Six documents on this surface already meet the bet-the-farm standard. The fix for the rest is to write like these six.**

---

## 5. UNVERIFIABLE — one command each

| Claim | Settling command |
|---|---|
| **NSA CSI: 580 control tests green · 0 failed** (Part 1: 203 lib; Part 2: 377 across 18 integration binaries). *Structural preconditions hold: 18/18 binaries exist, 11/11 spot-checked test fns resolve at HEAD.* | `AI_MEMORY_NO_CONFIG=1 cargo test --features sal --test export_memories_admin_gate_957 --test capabilities_v3 … (all 18 named binaries) && cargo test --features sal --lib tls subscriptions signed_events verify_signed_events validate server_identity` |
| **`PERFORMANCE.md:148-154` measured `--scale 10000`** (store 0.45 ms / search 1.42 ms / recall 15.44 ms p95) — no CPU/RAM/disk, binary rev, date, or iteration count recorded, while the doc's own 1M methodology (`:246`) mandates exactly that | `cargo build --release && target/release/ai-memory bench --scale 10000 --json` **on a host whose CPU/RAM/disk is recorded alongside the output** |
| **TOON payload sizes** (3 memories: JSON 1,600 B → TOON 626 B → compact 336 B). No literal pin exists in `src/toon.rs` or any test | `cargo test --lib toon -- --nocapture` after adding a byte-length assertion — or `ai-memory recall <q> --json` vs default TOON byte-diff on a fixed 3-row fixture |
| **Badge "NSA CSI MCP — 10/10 concerns · 7/7 recs"** — links to a Pages artifact outside this tree; no in-repo mapping of the 10 concerns / 7 recommendations to code controls found under `docs/` | `rg -l 'NSA|CSI' docs/ && gh issue view 1153` to locate the audit's closure evidence, then re-derive the tally |
| **"Exercised at 50-peer cells without measurable handshake overhead"** + the T5 latency envelope table (local-DC read 22 ms, cross-DC write 50–100 ms, federation propagation 50–150 ms). The document concedes the class at `:1269-1277` | Land the measured envelope `X` the doc already promises: `cargo run --release -p <harness> -- --peers 50` against `infra/pillar4-envelope/`, then replace the table |

---

## 6. What this audit does NOT cover

Stated bluntly so nobody mistakes this register for a clean bill of health.

1. **Nothing was executed.** No `cargo build`, `test`, `clippy`, `bench`, no daemon, no docker, no live Postgres or AGE. Every verdict is static: source reads, `rg`, `git`, `gh`. **A claim marked VERIFIED means the code says what the doc says — not that the code works.**
2. **This is a claims audit, not a code audit.** Correctness, memory safety, concurrency, `unsafe` blocks, error handling, SQL injection surface, migration correctness — none of it was examined except where a published claim pointed at it. **A defect nobody published a claim about is invisible to this register.** In particular: the correctness of the **v87/v88 data-mutating migrations** was not assessed, only the absence of published evidence for them.
3. **The 169 open issues were not individually adjudicated.** Six were confirmed open as calibration (#2438, #2450, #2492, #2400, #2613, #2629) and several more confirmed at HEAD in passing (#2489, #2480, #2442, #1968, #2511, #2588). The other ~155 are unexamined and may contain GA blockers.
4. **Surfaces not in scope:** `docs/INSTALL.md`, `docs/DEVELOPER_GUIDE.md` (beyond incidental cross-checks — note it is already known internally inconsistent on tool count at lines 7/88 vs 423 vs 845), `docs/ARCHITECTURAL_LIMITS.md`, `docs/production-deployment.md` (beyond §7), MCP per-tool descriptions and JSON schemas as advertised on the wire, iOS/Android clients, SDK source beyond the READMEs and the specific methods named, the public website, GitHub Pages content outside `docs/compliance/`, marketing copy, licensing, and dependency CVE posture.
5. **Postgres + AGE behaviour is entirely unverified by execution here** — and per C-09 the project's own most recent live evidence (#2511) shows a five-cause silent fallback to the relational CTE that made prior AGE greens meaningless. **Treat every Postgres/AGE claim in this register as adjudicated-on-paper only.**
6. **Retrieval quality on anything other than LongMemEval is unmeasured**, and even there this register only adjudicates *which harness produced the published numbers* — it does not independently reproduce **96.4% / 96.8%**.
7. **Seven independent passes wrote the source findings; this register adjudicates and ranks them.** Cross-surface spot-checks re-verified at `e31dea74`: `HTTP_BODY_LIMIT_BYTES = 2 * MIB`, `EXPECTED_PRODUCTION_ROUTES_COUNT = 94`, `EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT = 80`, `CURRENT_SCHEMA_VERSION = 88`, `min_line_coverage = 90.0`, `bench.yml` self-declared advisory + 0 bench entries in `required-contexts-release.txt`, `src/audit.rs` CHECKPOINT.sig comment-only, `kg_backend =` assignments `#[cfg(test)]`-only, zero `caps.compaction` writers, `transport.rs:852` sync bypass, no `grant`/`revoke`/`cluster` in `routes.rs`, `git tag -l 'v1.0.0*'` empty. **Findings not on that list are carried at their source pass's stated evidence and were not independently re-derived.**
8. **HEAD moves.** This register is pinned to `e31dea74`. Every file:line will drift — which is, precisely, the #2629 failure class this register documents. **Re-derive before citing.**

---

## 7. ERRATA — errors found IN THIS REGISTER during remediation

*Added 2026-08-01 by the CERT GATE 2 remediation lanes (PRs #2651–#2661). Every item below was found by a lane implementing this register's own §3 remedy list, and each was verified against code at `03bbd556`/`cb09bb07` before being recorded here.*

**Why this section exists.** This register's standard is that a correct system which overclaims fails the bet-the-farm bar. **An audit that overclaims about claims fails its own standard.** The seven remediation lanes were instructed to verify every correction against the code rather than trust the register, and doing so surfaced ~20 defects in the register itself. They are recorded here rather than silently fixed, because §6.8 already warns that this document drifts — this is that warning coming true, measured.

**Materiality note.** None of these overturns a Tier-1 verdict. C-01 through C-09 stand. The errors are of three kinds: **stale anchors** (the #2629 class, self-predicted), **undercounts** (the register was conservative, so the real defect was larger), and **four substantive misreadings** (E-01, E-02, E-11, E-16) where the register asserted something the code contradicts.

### 7.1 — Substantive: the register was WRONG about the code

| # | Register claim | Verified reality | Found by |
|---|---|---|---|
| **E-01** | **C-35**: "`postgres_endpoint_supported()` is an explicit allowlist — **56** `=> true` arms out of 94 route registrations" | **56 is an ARM COUNT, not a ROUTE count.** One match arm can cover several routes and several arms cover none. The real supported-route figure is **73 of 94**. The register's own framing conflates two different units, understating Postgres coverage by 17 routes | README lane (#2654) |
| **E-02** | **C-23**: AGE-gated Cypher "could only be exercised on an operator's own machine" is "the current state **by design**" | **False at HEAD.** None of the six named AGE suites is `#[ignore]`-gated, and `.github/workflows/coverage.yml` sets `AI_MEMORY_TEST_AGE_URL` against an `apache/age:release_PG16_1.6.0` service container, running them on every PR and push to `release/**`. The true and narrower claim is: **no CI job builds or version-asserts the certified PG 18.4 + AGE 1.7.0 + pgvector 0.8.5 pins** (drift tracked as #2512 defect 2, behind #2548) | release-notes lane (#2651) |
| **E-11** | **C-24**: "`rg 'coverage-baseline' .` hits **prose only**" | Nothing *reads* it — correct. But **the file exists on disk** carrying `92.59`. It is dead config, not an absent file; the distinction matters because a reviewer greping for it finds it and assumes a live ratchet | performance lane (#2653) |
| **E-16** | **C-61**: the 2k HNSW fixture is "reachable only via an **undocumented** env var" | The var **is** documented — in `benches/hnsw_rebuild_async.rs` itself, just not in `PERFORMANCE.md`. Separately, the 43 µs / 56 µs figures **do** have a recorded producing run (`CHANGELOG.md`, `docs/v0.7.0/release-notes.md`), so they were kept at their true fixture size rather than deleted under rule 2 | performance lane (#2653) |

### 7.2 — Undercounts: the real defect was LARGER than recorded

| # | Register said | Actual | Found by |
|---|---|---|---|
| **E-03** | **C-20** is a TypeScript defect (`sdk/typescript/src/client.ts`) | **Three clients.** `sdk/python/ai_memory/client.py` and `sdk/python/ai_memory/async_client.py` carried the identical `/api/v1/subscriptions/{id}` bug. **`async_client.py` appears NOWHERE in this 429-line register** — the entire file was outside the audit's field of view, and it also carried all three C-19 dead methods | API lane (#2655) |
| **E-04** | **C-55**: 6 anchors sampled, 6 miss | **13 checked, 13 miss** — including `tests/validate.rs`, a cited test file that **has never existed**, and `src/mcp/mod.rs:1607-1611`, which the register called "pointing at nothing" but actually points at `build_mcp_signal_hooks` — **unrelated code that reads plausibly to a skimming reviewer**, which is worse than nothing | security lane (#2656) |
| **E-05** | **C-55** on the HTML procurement page: 5 tally sites | **8 sites** — the extras being `<meta name="description">` and `<meta property="og:description">`, which carry the retired "10 of 10" claim into **every shared link preview**. Also **34** `file:line` anchors on that page, all converted; and concern (d) carried an **independent instance of the C-04 false mTLS claim** that the register never located | NSA-HTML lane (#2660) |
| **E-06** | **C-42**: "9 of the 15 rows have no `Operation` variant" | **11 of 15.** Only `memory_store`, `memory_search`, `memory_recall` and `memory_kg_query` map by operation name | performance lane (#2653) |
| **E-07** | **C-47**: flags the missing `CaptureLag` and the phantom `Search`/`List`/`Get` | Also missed that **`Export` and `Import` have ZERO production emitters** — both variants appear only under `mod tests`. A documented "one summary event per bulk operation" that no bulk operation produces: a rule-2 no-producer claim sitting *inside* the enum the register was auditing. Separately, read-access audit events are **MCP-stdio-only** | security lane (#2656) |
| **E-08** | **C-70**: test-count figures | The register's counting regex drops `#[tokio::test(flavor = …)]` attributes. Direction is conservative, but every sub-figure is wrong | README lane (#2654) |
| **E-09** | **C-39**: bulk response is `{created, errors}` | The **Postgres** branch also returns `"pending": [...]`; the SQLite branch does not. The two backends return different response shapes | API lane (#2655) |
| **E-10** | **C-44**: the `kg_bench` / `--features=age` command is dead | Understated — the "CTE (default, no extra services)" half was **also** wrong: `age_vs_cte` needs `--features sal-postgres` and a Postgres URL for **either** half, and the doc's `PG_DSN` env var is never read by the bench | performance lane (#2653) |
| **E-17** | Two API-contract coverage rows the register did not examine | `memory_recall`/`context_tokens` published as MCP-only — it is on **both** transports; and the `memory_store`/`ttl_secs` note claimed "the MCP tool exposes `expires_at`" when MCP `StoreRequest` exposes **neither** | API lane (#2655) |

### 7.3 — Stale anchors and counts (the #2629 class this register predicted)

| # | Register anchor | Reality at HEAD | Found by |
|---|---|---|---|
| **E-12** | **C-17**: `src/config.rs:8712-8717` | Real resolver is `src/config.rs:4314-4321` — **stale by ~4,400 lines** | API lane (#2655) |
| **E-13** | **C-29**: `CHANGELOG.md:460` | Now `:475`. Quote verbatim and unchanged | security lane (#2656) |
| **E-14** | **C-09**: `CHANGELOG.md:171` / `:179`; **C-46**: `:336` | Now `:186` / `:194` / `:351`. Content matched in every case | release-notes lane (#2651) |
| **E-15** | **C-08**: "**169** open non-PR issues" | **175** on 2026-08-01. The `[Unreleased]` block is ~343 lines, not ~328 | release-notes lane (#2651) |
| **E-18** | **C-08**: the five-step program's step 4 "is absent from the text" | Correct, and now identified: step 4 is **"100% fix + 100% track"** (`ROADMAP.md` §27's canonical Gate-3 sequence). Never present in the file — absent from its first appearance onward | release-notes lane (#2651) |

### 7.4 — Errors in a SOURCE the register relied on

| # | Finding |
|---|---|
| **E-19** | **`benchmarks/longmemeval/README.md` shifted every harness throughput figure UP ONE ROW**, crediting `harness.py` with 57 q/s (which is `harness_fast.py`'s number) and `harness_fast.py` with 232 q/s (which is `harness_99.py --no-expand`'s). Settled by internal consistency — every `docs/DEVELOPER_GUIDE.md` row satisfies `published q/s == 500 questions / published elapsed`, and `benchmarks/README` carries no elapsed times so nothing cross-checked it. **Shipped-binary throughput is 1.2 q/s, not ~57.** C-36 cites DEVELOPER_GUIDE and is correct; the benchmark README was the drifted surface. Fixed at root, with elapsed times added so each figure is auditable |
| **E-20** | **`docs/benchmark.svg` rendered the retired headline as PIXELS** — `97.0%`, `R@5 (485/500)`, `232 q/s` — on the image `README.md` embeds. Not a `.md` file, so no prose correction and no text-matching gate would ever have touched it. Corrected to `96.4%` / `482/500` (the fraction resolves exactly) / `1.2 q/s`. **Generalisable lesson: a claims gate that scans only text cannot see a claim that has been rendered** |

### 7.5 — Process findings from remediation

| # | Finding |
|---|---|
| **E-21** | **A `CONFLICTING` pull request silently suppresses ALL CI dispatch in this repo.** GitHub cannot compute a merge ref for a conflicting PR, so `pull_request`-triggered workflows create **no check suite at all** — and `gh pr checks` then reports *"no checks reported on the branch"*, which reads almost identically to a pass. Four remediation lanes were in this state simultaneously; five successive pushes on one produced zero Actions runs while the last *green* run sat four commits back. Close/reopen does **not** clear it; merging the base does. Verify with `gh api ".../actions/runs?head_sha=<sha>" -q .total_count`, never `gh pr checks`. Filed as **#2665** together with its sibling trap (a PR displaying green checks belonging to a superseded head) |
| **E-22** | **The queue bottleneck across parallel doc lanes is `CHANGELOG.md` `[Unreleased]` contention**, producing genuine textual conflicts — not branch-protection strictness. Relaxing `strict` does not resolve a text conflict. **#2483 is the real fix and remains unowned.** Every conflict observed was both-added and resolvable by keeping both blocks |
